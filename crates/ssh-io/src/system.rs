//! [`SystemRunner`]: an [`ExecHandler`] that runs commands as real OS processes.
//!
//! This is the *only* thing that grants system access, and it is opt-in — register it
//! as a context's unmatched-exec and/or shell handler to allow it. A context without it
//! can never spawn a process.

use std::process::Stdio;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::exec::{ChannelSession, ExecHandler, HandlerFuture};

/// Runs the given command directly (or the platform shell when the command is empty) as
/// a child process, bridging its stdio to the channel.
pub struct SystemRunner;

impl ExecHandler for SystemRunner {
    fn run(self: Arc<Self>, command: Box<str>, session: ChannelSession) -> HandlerFuture {
        Box::pin(run_process(command, session))
    }
}

async fn run_process(command: Box<str>, session: ChannelSession) -> u32 {
    let mode = if command.is_empty() {
        ProcessMode::Shell
    } else {
        ProcessMode::Direct
    };
    let mut cmd = match build_command(if command.is_empty() {
        None
    } else {
        Some(&command)
    }) {
        Ok(c) => c,
        Err(e) => {
            let _ = session.write_stderr(format!("{e}\n").as_bytes()).await;
            return 127;
        }
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // If the handler future is dropped (e.g. the runtime tears it down), kill the
        // child rather than leaving it orphaned.
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = session
                .write_stderr(format!("failed to start process: {e}\n").as_bytes())
                .await;
            return 127;
        }
    };

    let mut child_stdin = child.stdin.take().expect("piped stdin");
    let mut child_stdout = child.stdout.take().expect("piped stdout");
    let mut child_stderr = child.stderr.take().expect("piped stderr");
    let (mut reader, writer) = session.split();

    // Pump channel stdin → child stdin (emulating a PTY's icrnl for shells).
    let stdin_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let data = if mode == ProcessMode::Shell {
                        cr_to_lf(&buf[..n])
                    } else {
                        buf[..n].to_vec()
                    };
                    if child_stdin.write_all(&data).await.is_err() {
                        break;
                    }
                    let _ = child_stdin.flush().await;
                }
            }
        }
    });

    // Pump child stdout/stderr → channel until both close (the process has finished
    // writing), so all output is delivered before the exit status. The budgeted writes
    // suspend the pumps when the client stops reading, which in turn backpressures the
    // child through its full pipe — output is bounded end to end.
    let out_writer = writer.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        while let Ok(n) = child_stdout.read(&mut buf).await {
            if n == 0 || out_writer.write_stdout(&buf[..n]).await.is_err() {
                break;
            }
        }
    });
    let err_writer = writer.clone();
    let stderr_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        while let Ok(n) = child_stderr.read(&mut buf).await {
            if n == 0 || err_writer.write_stderr(&buf[..n]).await.is_err() {
                break;
            }
        }
    });

    // Wait for the process to finish, OR for the channel to go away (client disconnect).
    // Without this, a long-running or silent process would keep running after the client
    // is gone, since the output pumps never notice the closed channel — an orphan leak.
    let pumps = async {
        let _ = tokio::join!(stdout_task, stderr_task);
    };
    tokio::pin!(pumps);
    tokio::select! {
        _ = &mut pumps => {} // process closed its stdout/stderr (it has finished writing)
        _ = writer.closed() => {
            // The client/channel is gone: kill the child, then let the pumps unwind.
            let _ = child.start_kill();
            pumps.await;
        }
    }
    stdin_task.abort(); // interactive stdin may have no EOF; stop pumping
    // `kill_on_drop` guarantees the process dies even if we bail before reaping it.
    child.wait().await.ok().and_then(|s| s.code()).unwrap_or(0) as u32
}

/// Map CR→LF (collapsing CRLF) to emulate a terminal's `icrnl` for a pipe-fed shell.
fn cr_to_lf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\r' => {
                out.push(b'\n');
                if data.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
            }
            b => out.push(b),
        }
        i += 1;
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProcessMode {
    Direct,
    Shell,
}

/// Build the platform shell/command invocation.
///
/// SSH `exec` carries a command line, not an argv vector. For non-interactive execs we
/// split it into a program plus whitespace-separated arguments and spawn that program
/// directly. This intentionally does not interpret shell metacharacters: an allowlisted
/// `SystemRunner` must not turn `git-upload-pack repo; sh` into arbitrary shell access.
fn build_command(command: Option<&str>) -> Result<Command, &'static str> {
    match command {
        Some(command) => {
            let mut parts = command.split_whitespace();
            let program = parts.next().ok_or("empty command")?;
            let mut c = Command::new(program);
            c.args(parts);
            Ok(c)
        }
        None if cfg!(windows) => {
            let mut c = Command::new("cmd.exe");
            c.arg("/Q");
            Ok(c)
        }
        None => {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
            let mut c = Command::new(shell);
            c.arg("-i");
            Ok(c)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use crate::exec::{ChannelSession, Outbound};

    #[test]
    fn maps_cr_and_crlf_to_lf() {
        assert_eq!(cr_to_lf(b"dir\r"), b"dir\n");
        assert_eq!(cr_to_lf(b"dir\r\n"), b"dir\n");
        assert_eq!(cr_to_lf(b"unix\n"), b"unix\n");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn exec_command_is_not_run_through_shell() {
        let out = build_command(Some("printf safe; printf pwned"))
            .unwrap()
            .output()
            .await
            .unwrap();

        assert!(out.status.success());
        assert_eq!(out.stdout, b"safe;");
    }

    /// A long-running child must be torn down promptly when the channel goes away (the
    /// serve loop dropped its receiver), rather than running to completion as an orphan.
    #[cfg(unix)]
    #[tokio::test]
    async fn child_is_killed_when_channel_closes() {
        use std::time::Duration;
        use tokio::sync::{Semaphore, mpsc, watch};

        let (out_tx, out_rx) = mpsc::unbounded_channel::<Outbound>();
        let (_stdin_tx, stdin_rx) = mpsc::unbounded_channel::<Box<[u8]>>();
        let session = ChannelSession::new(
            stdin_rx,
            out_tx,
            Arc::new(Semaphore::new(256 * 1024)),
            watch::channel(0).0,
            None,
            watch::channel((0, 0)).1,
        );

        let handle = tokio::spawn(Arc::new(SystemRunner).run("sleep 30".into(), session));

        // Give the child a moment to spawn, then simulate the client disconnecting.
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(out_rx);

        // The handler must finish far sooner than the 30s sleep would allow.
        let result = tokio::time::timeout(Duration::from_secs(5), handle).await;
        assert!(
            result.is_ok(),
            "handler should return promptly after the channel closes"
        );
    }
}
