//! End-to-end PTY plumbing over an in-memory duplex pipe: a handler must see the
//! granted PTY (term + size) and receive `window-change` resizes through the watch,
//! all the way from a real client session.

use std::sync::Arc;
use std::time::Duration;

use ssh_io::{ChannelSession, Driver, ExecContext, ExecHandler, HandlerFuture, serve_with};
use ssh_io::{NoRetryReaction, ServeConfig};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    ServerAuthHandler, ServerConnection, UserPublicKey,
};
use tokio::io::AsyncWriteExt;

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

/// Reports its PTY, waits for one resize, reports it, and exits — a stand-in for a
/// TUI app's "initial draw, redraw on resize" loop.
struct TuiProbe;
impl ExecHandler for TuiProbe {
    fn run(self: Arc<Self>, _command: Box<str>, session: ChannelSession) -> HandlerFuture {
        Box::pin(async move {
            let Some(pty) = session.pty().cloned() else {
                return 1;
            };
            let mut resize = session.resize_events();
            let (_reader, mut writer) = session.split();
            let line = format!("pty {} {}x{}\n", pty.term, pty.cols, pty.rows);
            if writer.write_all(line.as_bytes()).await.is_err() {
                return 1;
            }
            if resize.changed().await.is_err() {
                return 1;
            }
            let (cols, rows) = *resize.borrow_and_update();
            let line = format!("resize {cols}x{rows}\n");
            if writer.write_all(line.as_bytes()).await.is_err() {
                return 1;
            }
            0
        })
    }
}

#[tokio::test]
async fn handler_sees_pty_and_resizes() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = tokio::spawn(async move {
        let ctx = ExecContext::new().on_shell(TuiProbe);
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
        let mut granted = false;
        let mut resized = false;
        while let Some(event) = driver.next_event().await.unwrap() {
            match event {
                ClientEvent::Authenticated => {
                    driver.session_mut().request_pty("xterm-256color", 120, 40);
                    driver.session_mut().shell().unwrap();
                }
                ClientEvent::PtyGranted => granted = true,
                ClientEvent::PtyRefused => panic!("PTY must be granted"),
                ClientEvent::Stdout(d) => {
                    stdout.extend_from_slice(&d);
                    // After the handler's first line, resize the "terminal" once.
                    if !resized {
                        resized = true;
                        driver.session_mut().window_change(80, 24).unwrap();
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
        (stdout, exit, granted)
    });

    let (stdout, exit, granted) = run.await.expect("session must not stall");
    assert!(granted, "client must observe the PTY grant");
    assert_eq!(exit, Some(0), "probe must see a PTY and a resize");
    let text = String::from_utf8(stdout).unwrap();
    assert!(
        text.contains("pty xterm-256color 120x40"),
        "handler must see the granted PTY: {text:?}"
    );
    assert!(
        text.contains("resize 80x24"),
        "handler must see the window-change: {text:?}"
    );
    server.await.unwrap();
}
