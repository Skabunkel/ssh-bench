//! In-process full-screen TUI served over SSH — no PTY on the server, no spawned
//! process, no TUI framework: the handler owns the client's screen with raw ANSI.
//!
//! Run it:
//! ```text
//! cargo run -p ssh-io --example tui_demo
//! ssh -p 2222 demo@127.0.0.1        # password: demo
//! ```
//! A stock OpenSSH client requests a PTY for a shell session automatically, which puts
//! *its* terminal into raw mode once we grant it — keystrokes arrive raw, and every
//! escape sequence we write lands on the user's screen. Resize your terminal to watch
//! `window-change` flow through; press `q` (or Ctrl-C) to quit.

use std::sync::Arc;
use std::time::Duration;

use ssh_io::{
    ChannelSession, ExecContext, ExecHandler, HandlerFuture, ServeConfig, load_or_create_host_key,
    serve_with,
};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{ServerAuthHandler, ServerConnection, UserPublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct DemoAuth;
impl ServerAuthHandler for DemoAuth {
    fn verify_password(&mut self, user: &str, password: &str) -> bool {
        user == "demo" && password == "demo"
    }
    fn is_authorized_key(&mut self, _u: &str, _k: &UserPublicKey) -> bool {
        false
    }
}

/// The "app": a status panel that redraws on every keystroke, resize, and 1s tick.
struct Dashboard;

impl ExecHandler for Dashboard {
    fn run(self: Arc<Self>, _command: Box<str>, session: ChannelSession) -> HandlerFuture {
        Box::pin(async move {
            let Some(pty) = session.pty().cloned() else {
                // Cooked mode: full-screen drawing would be garbage. Bail with a hint.
                let _ = session
                    .write_stderr(b"this app needs a terminal (try: ssh -t ... )\r\n")
                    .await;
                return 1;
            };
            let mut resize = session.resize_events();
            let (mut reader, mut writer) = session.split();

            let mut size = (pty.cols, pty.rows);
            let mut ticks = 0u64;
            let mut last_key: Vec<u8> = Vec::new();
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            let mut buf = [0u8; 64];

            // Alternate screen + hidden cursor for the app's lifetime.
            if writer.write_all(b"\x1b[?1049h\x1b[?25l").await.is_err() {
                return 1;
            }
            loop {
                let frame = draw(&pty.term, size, ticks, &last_key);
                if writer.write_all(frame.as_bytes()).await.is_err() {
                    break; // client gone (or output budget closed): tear down
                }
                tokio::select! {
                    read = reader.read(&mut buf) => match read {
                        Ok(0) | Err(_) => break, // stdin EOF / channel gone
                        Ok(n) => {
                            last_key = buf[..n].to_vec();
                            if last_key.contains(&b'q') || last_key.contains(&0x03) {
                                break;
                            }
                        }
                    },
                    changed = resize.changed() => match changed {
                        Ok(()) => size = *resize.borrow_and_update(),
                        Err(_) => break,
                    },
                    _ = tick.tick() => ticks += 1,
                }
            }
            // Restore the client's screen and cursor.
            let _ = writer.write_all(b"\x1b[?1049l\x1b[?25h").await;
            0
        })
    }
}

/// Render one full frame (clear + box + status lines) as a single buffer, so each
/// frame is one atomic channel write.
fn draw(term: &str, (cols, rows): (u16, u16), ticks: u64, last_key: &[u8]) -> String {
    use std::fmt::Write;
    let (cols, rows) = (cols.max(20), rows.max(6));
    let mut f = String::with_capacity(4096);
    f.push_str("\x1b[2J\x1b[H"); // clear, home

    let w = (cols as usize).min(60);
    let top = format!("┌{}┐", "─".repeat(w - 2));
    let bot = format!("└{}┘", "─".repeat(w - 2));
    let line = |f: &mut String, row: u16, text: &str| {
        let text: String = text.chars().take(w - 4).collect();
        let _ = write!(
            f,
            "\x1b[{row};1H│ \x1b[36m{text:<pad$}\x1b[0m │",
            pad = w - 4
        );
    };

    let _ = write!(f, "\x1b[1;1H\x1b[1m{top}\x1b[0m");
    line(&mut f, 2, "ssh-bench in-process TUI (q quits)");
    line(&mut f, 3, &format!("TERM={term}  size={cols}x{rows}"));
    line(&mut f, 4, &format!("uptime: {ticks}s"));
    let printable: String = last_key
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                (b as char).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect();
    line(&mut f, 5, &format!("last input: {printable}"));
    let _ = write!(f, "\x1b[6;1H\x1b[1m{bot}\x1b[0m");
    f
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let host_key = load_or_create_host_key(".tui_demo_host_key", &mut OsRng)?;
    let listener = TcpListener::bind("127.0.0.1:2222").await?;
    eprintln!(
        "listening on 127.0.0.1:2222 — connect with: ssh -p 2222 demo@127.0.0.1 (password: demo)"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true)?; // keystroke latency matters for interactive sessions
        let host_key = host_key.clone();
        tokio::spawn(async move {
            let ctx = ExecContext::new().on_shell(Dashboard);
            let mut conn = ServerConnection::new(OsRng, host_key, DemoAuth);
            conn.set_allow_pty(true); // our handlers drive the screen themselves
            if let Err(e) = serve_with(
                stream,
                conn,
                ctx,
                ServeConfig::default(),
                Some(peer),
                &ssh_io::NoRetryReaction,
            )
            .await
            {
                eprintln!("[{peer}] connection ended with error: {e}");
            }
        });
    }
}
