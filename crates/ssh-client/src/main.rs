//! Minimal SSH client CLI: handshake, password auth, and `exec` or interactive `shell`.
//!
//! Usage: `ssh-client [host:port] [user] [password] [command]`
//! (defaults target the docker-compose demo server: 127.0.0.1:2222 / myuser).
//! With a `command`, it runs it remotely (`exec`); without one, it requests a `shell`.
//! Local stdin is forwarded to the remote side; remote stdout/stderr is printed; the
//! process exits with the remote exit status.

use std::io::Write;

use ssh_io::{Driver, KnownHosts};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostPublicKey, Password,
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

struct DemoClient {
    user: Box<str>,
    password: Option<Password>,
    known_hosts: Option<KnownHosts>,
}

impl ClientAuthHandler for DemoClient {
    fn username(&self) -> Box<str> {
        self.user.clone()
    }
    fn verify_host_key(&mut self, key: &HostPublicKey) -> bool {
        match &self.known_hosts {
            // Enforce known_hosts when provided.
            Some(kh) => {
                if kh.contains(key) {
                    true
                } else {
                    eprintln!("[client] host key {} not in known_hosts", fingerprint(key));
                    false
                }
            }
            // Trust-on-first-use otherwise.
            None => {
                eprintln!("[client] server host key fingerprint: {}", fingerprint(key));
                true
            }
        }
    }
    fn next_auth(&mut self, _can_continue: &[Box<str>]) -> Option<AuthAttempt> {
        self.password.take().map(AuthAttempt::Password)
    }
}

fn fingerprint(key: &HostPublicKey) -> String {
    key.blob()
        .iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect()
}

type Client = ClientConnection<OsRng, DemoClient>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let addr = args.next().unwrap_or_else(|| "127.0.0.1:2222".to_owned());
    let user = args.next().unwrap_or_else(|| "myuser".to_owned());
    let password = args.next().unwrap_or_else(|| "mysecretpassword".to_owned());
    let command = args.next();

    eprintln!("[client] connecting to {addr} as {user:?}");
    let stream = TcpStream::connect(&addr).await?;
    let demo = DemoClient {
        user: user.into(),
        password: Some(password.into()),
        known_hosts: std::env::var_os("SSH_KNOWN_HOSTS").and_then(|p| KnownHosts::load(p).ok()),
    };
    // Opt into delayed `zlib@openssh.com` compression with SSH_COMPRESSION=1.
    let session = if std::env::var_os("SSH_COMPRESSION").is_some() {
        eprintln!("[client] offering zlib@openssh.com compression");
        ClientConnection::with_compression_preference(OsRng, demo, &["zlib@openssh.com", "none"])
    } else {
        ClientConnection::new(OsRng, demo)
    };
    let mut driver = Driver::new(stream, session);

    // Phase 1: drive the handshake and authentication.
    if let Some(code) = authenticate(&mut driver).await? {
        std::process::exit(code);
    }
    eprintln!("[client] AUTHENTICATED");

    // Phase 2: request exec or shell.
    match &command {
        Some(cmd) => driver.session_mut().exec(cmd)?,
        None => driver.session_mut().shell()?,
    }
    // Optional: exercise a client-initiated re-key (testing hook).
    if std::env::var_os("SSH_REKEY").is_some() {
        driver.session_mut().initiate_rekey();
    }

    // Phase 3: forward stdin and stream output until the channel closes.
    let code = run_session(&mut driver).await?;
    std::process::exit(code);
}

/// Returns `Some(exit_code)` if the session ended before authentication, else `None`.
// Boxed error: a CLI entry point aggregating heterogeneous errors (`DriveError`,
// `io::Error`) for ergonomic propagation to `main`; no caller matches on the variant.
async fn authenticate(
    driver: &mut Driver<Client>,
) -> Result<Option<i32>, Box<dyn std::error::Error>> {
    loop {
        match driver.next_event().await? {
            Some(ClientEvent::Banner(msg)) => eprint!("[client] banner: {msg}"),
            Some(ClientEvent::Authenticated) => return Ok(None),
            Some(ClientEvent::AuthFailed { methods }) => {
                eprintln!("[client] AUTH FAILED (server offered: {methods:?})");
                return Ok(Some(1));
            }
            Some(ClientEvent::HostKeyRejected) => {
                eprintln!("[client] host key rejected");
                return Ok(Some(1));
            }
            Some(ClientEvent::Disconnect {
                reason,
                description,
            }) => {
                eprintln!("[client] disconnected reason={reason} {description:?}");
                return Ok(Some(1));
            }
            None => return Ok(Some(1)),
            _ => {}
        }
    }
}

// Boxed error: same rationale as `authenticate` — heterogeneous errors boxed for the CLI.
async fn run_session(driver: &mut Driver<Client>) -> Result<i32, Box<dyn std::error::Error>> {
    // Read stdin on a dedicated thread feeding an mpsc channel. `tokio::io::stdin()` is
    // not cancellation-safe and blocks on the real Windows console inside a `select!`
    // loop; a plain blocking thread + mpsc avoids that hang and is fully portable.
    // The channel closing (recv → None) signals EOF, ordered after all data chunks.
    let mut stdin_rx = spawn_stdin_reader();
    let mut stdin_open = true;
    let mut exit_status: Option<u32> = None;

    loop {
        driver.flush().await?;
        tokio::select! {
            read = driver.read_once() => {
                if !read? {
                    return Ok(exit_status.unwrap_or(0) as i32);
                }
                while let Some(event) = driver.session_mut().poll_event() {
                    match event {
                        ClientEvent::Stdout(data) => {
                            std::io::stdout().write_all(&data)?;
                            std::io::stdout().flush()?;
                        }
                        ClientEvent::Stderr(data) => {
                            std::io::stderr().write_all(&data)?;
                            std::io::stderr().flush()?;
                        }
                        ClientEvent::ExitStatus(status) => exit_status = Some(status),
                        ClientEvent::RequestFailed => {
                            eprintln!("[client] server refused the request");
                            exit_status = Some(1);
                        }
                        ClientEvent::ChannelClosed => {
                            return Ok(exit_status.unwrap_or(0) as i32);
                        }
                        ClientEvent::ChannelOpenFailure { reason, description } => {
                            eprintln!("[client] channel open failed reason={reason} {description:?}");
                            return Ok(1);
                        }
                        ClientEvent::Disconnect { reason, description } => {
                            eprintln!("[client] disconnected reason={reason} {description:?}");
                            return Ok(exit_status.unwrap_or(1) as i32);
                        }
                        _ => {}
                    }
                }
            }
            maybe = stdin_rx.recv(), if stdin_open => {
                match maybe {
                    // Normalize Windows CRLF to LF so a Windows client works with a
                    // remote shell that expects bare LF line endings.
                    Some(chunk) => driver.session_mut().write_stdin(&crlf_to_lf(&chunk))?,
                    // EOF (ordered after all data); signal it to the remote once.
                    None => {
                        stdin_open = false;
                        driver.session_mut().send_eof()?;
                    }
                }
            }
        }
    }
}

/// Spawn a blocking thread that reads stdin into an mpsc channel. The channel closes on
/// EOF, which `recv()` reports as `None` after all data has been delivered.
fn spawn_stdin_reader() -> mpsc::UnboundedReceiver<Vec<u8>> {
    use std::io::Read;
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 8192];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        return;
                    }
                }
            }
        }
    });
    rx
}

/// Convert `\r\n` to `\n`, leaving lone `\r`/`\n` untouched.
fn crlf_to_lf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\r' && data.get(i + 1) == Some(&b'\n') {
            // Skip the CR; the following LF is emitted on the next iteration.
        } else {
            out.push(data[i]);
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::crlf_to_lf;

    #[test]
    fn crlf_becomes_lf() {
        assert_eq!(crlf_to_lf(b"echo hi\r\n"), b"echo hi\n");
        assert_eq!(crlf_to_lf(b"a\r\nb\r\n"), b"a\nb\n");
    }

    #[test]
    fn lone_cr_and_lf_are_preserved() {
        assert_eq!(crlf_to_lf(b"lone\rcr"), b"lone\rcr");
        assert_eq!(crlf_to_lf(b"unix\nonly"), b"unix\nonly");
        assert_eq!(crlf_to_lf(b"plain"), b"plain");
    }
}
