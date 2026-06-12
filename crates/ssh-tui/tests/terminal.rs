//! End-to-end: a handler renders a ratatui frame through [`SshTerminal`] and reacts to
//! input parsed by [`InputParser`], driven by a real client session over an in-memory
//! pipe. Verifies the whole chain — pty-req grant, alternate screen, ANSI frame bytes,
//! keystroke decoding, resize repaint, screen restore.

use std::sync::Arc;
use std::time::Duration;

use ssh_io::{
    ChannelSession, Driver, ExecContext, ExecHandler, HandlerFuture, NoRetryReaction, ServeConfig,
    serve_with,
};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    ServerAuthHandler, ServerConnection, UserPublicKey,
};
use ssh_tui::ratatui::widgets::{Block, Paragraph};
use ssh_tui::{InputParser, KeyCode, SshTerminal};
use tokio::io::AsyncReadExt;

struct AllowPw;
impl ServerAuthHandler for AllowPw {
    fn verify_password(&mut self, _u: &str, p: &str) -> bool {
        p == "pw"
    }
    fn is_authorized_key(&mut self, _u: &str, _k: &UserPublicKey) -> bool {
        false
    }
}

struct TestClient;
impl ClientAuthHandler for TestClient {
    fn username(&self) -> Box<str> {
        "user".into()
    }
    fn verify_host_key(&mut self, _k: &HostPublicKey) -> bool {
        true
    }
    fn next_auth(&mut self, _c: &[Box<str>]) -> Option<AuthAttempt> {
        Some(AuthAttempt::Password("pw".into()))
    }
}

/// Draws a banner, redraws on resize, quits on `q` — the minimal ratatui app shape.
struct MiniApp;
impl ExecHandler for MiniApp {
    fn run(self: Arc<Self>, _command: Box<str>, session: ChannelSession) -> HandlerFuture {
        Box::pin(async move {
            let Some(pty) = session.pty().cloned() else {
                return 1;
            };
            let mut resize = session.resize_events();
            let (mut reader, writer) = session.split();
            let Ok(mut terminal) = SshTerminal::new(writer, (pty.cols, pty.rows)).await else {
                return 1;
            };
            let mut parser = InputParser::new();
            let mut buf = [0u8; 64];
            loop {
                let size = *resize.borrow_and_update();
                let banner = format!("HELLO CASINO {}x{}", size.0, size.1);
                let draw = terminal
                    .draw(|frame| {
                        let widget = Paragraph::new(banner.as_str()).block(Block::bordered());
                        frame.render_widget(widget, frame.area());
                    })
                    .await;
                if draw.is_err() {
                    return 1;
                }
                tokio::select! {
                    read = reader.read(&mut buf) => match read {
                        Ok(0) | Err(_) => return 1,
                        Ok(n) => {
                            if parser.feed(&buf[..n]).iter().any(|k| k.code == KeyCode::Char('q')) {
                                break;
                            }
                        }
                    },
                    changed = resize.changed() => {
                        if changed.is_err() {
                            return 1;
                        }
                        terminal.resize(*resize.borrow_and_update());
                    }
                }
            }
            if terminal.restore().await.is_err() {
                return 1;
            }
            0
        })
    }
}

#[tokio::test]
async fn ratatui_frames_flow_end_to_end() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = tokio::spawn(async move {
        let ctx = ExecContext::new().on_shell(MiniApp);
        let mut conn = ServerConnection::new(OsRng, HostKey::generate(&mut OsRng), AllowPw);
        conn.set_allow_pty(true);
        let _ = serve_with(
            server_io,
            conn,
            ctx,
            ServeConfig::default(),
            None,
            &NoRetryReaction,
        )
        .await;
    });

    let run = tokio::time::timeout(Duration::from_secs(30), async move {
        let session = ClientConnection::new(OsRng, TestClient);
        let mut driver = Driver::new(client_io, session);
        let mut stdout = Vec::new();
        let mut exit = None;
        let mut resized = false;
        let mut quit_sent = false;
        while let Some(event) = driver.next_event().await.unwrap() {
            match event {
                ClientEvent::Authenticated => {
                    driver.session_mut().request_pty("xterm-256color", 90, 30);
                    driver.session_mut().shell().unwrap();
                }
                ClientEvent::PtyRefused => panic!("PTY must be granted"),
                ClientEvent::Stdout(d) => {
                    stdout.extend_from_slice(&d);
                    let text = String::from_utf8_lossy(&stdout);
                    // The frame diff skips unchanged blank cells, so the banner's words
                    // arrive as separate runs with cursor moves between them — match on
                    // the size run, which has no spaces. First frame seen → resize once;
                    // resized frame seen → press q.
                    if !resized && text.contains("90x30") {
                        resized = true;
                        driver.session_mut().window_change(60, 20).unwrap();
                    } else if !quit_sent && text.contains("60x20") {
                        quit_sent = true;
                        driver.session_mut().write_stdin(b"q").unwrap();
                    }
                }
                ClientEvent::ExitStatus(s) => exit = Some(s),
                ClientEvent::ChannelClosed => break,
                ClientEvent::AuthFailed { .. } | ClientEvent::HostKeyRejected => {
                    panic!("setup failed")
                }
                _ => {}
            }
        }
        (stdout, exit)
    });

    let (stdout, exit) = run.await.expect("session must not stall");
    assert_eq!(exit, Some(0), "app must exit cleanly on q");
    let text = String::from_utf8_lossy(&stdout);
    assert!(
        text.contains("\x1b[?1049h"),
        "must enter the alternate screen"
    );
    assert!(
        text.contains("HELLO") && text.contains("90x30"),
        "first frame must render at the granted PTY size"
    );
    assert!(
        text.contains("60x20"),
        "resize must repaint at the new size"
    );
    assert!(
        text.contains("\x1b[?1049l"),
        "restore must leave the alternate screen"
    );
    server.await.unwrap();
}
