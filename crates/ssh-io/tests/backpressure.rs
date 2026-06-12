//! End-to-end flow-control tests over an in-memory duplex pipe.
//!
//! * A transfer several times larger than both the SSH window (1 MiB) and the handler
//!   output budget (256 KiB) must complete — this fails if window replenishment is not
//!   driven by actual handler consumption, or if the output budget is never released.
//! * A handler spewing output at a client that goes away must terminate promptly
//!   instead of buffering forever or leaking as a blocked task.

use std::sync::Arc;
use std::time::Duration;

use ssh_io::{ChannelSession, Driver, ExecContext, ExecHandler, HandlerFuture, serve};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    ServerAuthHandler, ServerConnection, UserPublicKey,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;

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

/// In-process echo handler.
struct Cat;
impl ExecHandler for Cat {
    fn run(self: Arc<Self>, _command: Box<str>, session: ChannelSession) -> HandlerFuture {
        Box::pin(async move {
            let (mut r, mut w) = session.split();
            let _ = tokio::io::copy(&mut r, &mut w).await;
            0
        })
    }
}

/// A transfer much larger than one flow-control window and many times the handler
/// output budget must still complete: window adjusts are granted as the handler reads,
/// and output budget is released as the client drains.
#[tokio::test]
async fn multi_window_transfer_completes() {
    const SIZE: usize = 3 * 1024 * 1024; // 3× the 1 MiB window, 12× the 256 KiB budget
    // A pipe comfortably larger than one flow-control window, so the client can dump
    // its entire initial window at once and genuinely exhaust it — progress past 1 MiB
    // then depends entirely on consumption-driven WINDOW_ADJUSTs.
    let (client_io, server_io) = tokio::io::duplex(8 * 1024 * 1024);

    let server = tokio::spawn(async move {
        let ctx = ExecContext::new().on_exec("cat", Cat);
        let conn = ServerConnection::new(OsRng, HostKey::generate(&mut OsRng), AllowPw);
        let _ = serve(server_io, conn, ctx).await;
    });

    let input: Vec<u8> = (0..SIZE).map(|i| (i % 251) as u8).collect();
    let expected = input.clone();

    let client = tokio::time::timeout(Duration::from_secs(120), async move {
        let session = ClientConnection::new(OsRng, TestClient);
        let mut driver = Driver::new(client_io, session);
        let mut stdout = Vec::new();
        let mut exit = None;
        while let Some(event) = driver.next_event().await.unwrap() {
            match event {
                ClientEvent::Authenticated => driver.session_mut().exec("cat").unwrap(),
                ClientEvent::ChannelReady { .. } => {
                    driver.session_mut().write_stdin(&input).unwrap();
                    driver.session_mut().send_eof().unwrap();
                }
                ClientEvent::Stdout(d) => stdout.extend_from_slice(&d),
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

    let (stdout, exit) = client.await.expect("transfer must not stall");
    assert_eq!(exit, Some(0));
    assert_eq!(stdout.len(), expected.len(), "echo must be complete");
    assert_eq!(stdout, expected, "echo must be intact");
    server.await.unwrap();
}

/// Writes output forever; reports (via the oneshot) when it is torn down — whether that
/// is its write loop ending (budget closed) or the serve loop aborting it on disconnect.
/// The signal rides a `Drop` guard so it fires on either path.
struct Spew {
    done: std::sync::Mutex<Option<oneshot::Sender<()>>>,
}
impl ExecHandler for Spew {
    fn run(self: Arc<Self>, _command: Box<str>, session: ChannelSession) -> HandlerFuture {
        let signal = self.done.lock().unwrap().take();
        Box::pin(async move {
            struct Signal(Option<oneshot::Sender<()>>);
            impl Drop for Signal {
                fn drop(&mut self) {
                    if let Some(tx) = self.0.take() {
                        let _ = tx.send(());
                    }
                }
            }
            let _signal = Signal(signal);
            let (_r, mut w) = session.split();
            let chunk = vec![0u8; 8 * 1024];
            // Suspends on the output budget (client stopped reading) until the budget
            // closes or the task is aborted on disconnect — either way, teardown.
            while w.write_all(&chunk).await.is_ok() {}
            1
        })
    }
}

/// A client that goes away mid-stream must terminate the handler promptly: the output
/// budget bounds what gets buffered, and closing it on teardown unblocks the writer.
#[tokio::test]
async fn spewing_handler_terminates_when_client_goes_away() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let (done_tx, done_rx) = oneshot::channel();

    let server = tokio::spawn(async move {
        let ctx = ExecContext::new().on_exec(
            "spew",
            Spew {
                done: std::sync::Mutex::new(Some(done_tx)),
            },
        );
        let conn = ServerConnection::new(OsRng, HostKey::generate(&mut OsRng), AllowPw);
        let _ = serve(server_io, conn, ctx).await;
    });

    // Authenticate, start the spewing command, read a little — then vanish.
    let session = ClientConnection::new(OsRng, TestClient);
    let mut driver = Driver::new(client_io, session);
    let mut received = 0usize;
    while let Some(event) = driver.next_event().await.unwrap() {
        match event {
            ClientEvent::Authenticated => driver.session_mut().exec("spew").unwrap(),
            ClientEvent::Stdout(d) => {
                received += d.len();
                if received >= 64 * 1024 {
                    break; // hang up mid-stream
                }
            }
            ClientEvent::AuthFailed { .. } | ClientEvent::HostKeyRejected => {
                panic!("setup failed")
            }
            _ => {}
        }
    }
    drop(driver);

    // The handler must notice (budget closed / writes failing) and finish promptly,
    // rather than buffering output forever for a client that is gone.
    tokio::time::timeout(Duration::from_secs(5), done_rx)
        .await
        .expect("spewing handler must terminate after the client disconnects")
        .expect("handler must report completion");
    server.await.unwrap();
}
