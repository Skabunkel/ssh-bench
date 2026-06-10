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

/// Runs the given command (or the platform shell when the command is empty) as a child
/// process, bridging its stdio to the channel.
pub struct SystemRunner;

impl ExecHandler for SystemRunner {
    fn run(self: Arc<Self>, command: Box<str>, session: ChannelSession) -> HandlerFuture {
        Box::pin(run_process(command, session))
    }
}

async fn run_process(command: Box<str>, session: ChannelSession) -> u32 {
    let is_shell = command.is_empty();
    let mut cmd = build_command(if is_shell { None } else { Some(&command) });
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // If the handler future is dropped (e.g. the runtime tears it down), kill the
        // child rather than leaving it orphaned.
        .kill_on_drop(true);

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            session.write_stderr(format!("failed to start process: {e}\n").as_bytes());
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
                    let data = if is_shell { cr_to_lf(&buf[..n]) } else { buf[..n].to_vec() };
                    if child_stdin.write_all(&data).await.is_err() {
                        break;
                    }
                    let _ = child_stdin.flush().await;
                }
            }
        }
    });

    // Pump child stdout/stderr → channel until both close (the process has finished
    // writing), so all output is delivered before the exit status.
    let out_writer = writer.clone();
    let stdout_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        while let Ok(n) = child_stdout.read(&mut buf).await {
            if n == 0 {
                break;
            }
            out_writer.write_stdout(&buf[..n]);
        }
    });
    let err_writer = writer.clone();
    let stderr_task = tokio::spawn(async move {
        let mut buf = [0u8; 8192];
        while let Ok(n) = child_stderr.read(&mut buf).await {
            if n == 0 {
                break;
            }
            err_writer.write_stderr(&buf[..n]);
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

/// Build the platform shell/command invocation.
fn build_command(command: Option<&str>) -> Command {
    if cfg!(windows) {
        let mut c = Command::new("cmd.exe");
        match command {
            Some(cmd) => {
                c.arg("/C").arg(cmd);
            }
            None => {
                c.arg("/Q");
            }
        }
        c
    } else {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
        let mut c = Command::new(shell);
        match command {
            Some(cmd) => {
                c.arg("-c").arg(cmd);
            }
            None => {
                c.arg("-i");
            }
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exec::{ChannelSession, Outbound};

    #[test]
    fn maps_cr_and_crlf_to_lf() {
        assert_eq!(cr_to_lf(b"dir\r"), b"dir\n");
        assert_eq!(cr_to_lf(b"dir\r\n"), b"dir\n");
        assert_eq!(cr_to_lf(b"unix\n"), b"unix\n");
    }

    /// A long-running child must be torn down promptly when the channel goes away (the
    /// serve loop dropped its receiver), rather than running to completion as an orphan.
    #[cfg(unix)]
    #[tokio::test]
    async fn child_is_killed_when_channel_closes() {
        use std::time::Duration;
        use tokio::sync::mpsc;

        let (out_tx, out_rx) = mpsc::unbounded_channel::<Outbound>();
        let (_stdin_tx, stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let session = ChannelSession::new(stdin_rx, out_tx);

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
