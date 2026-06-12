//! A handler that ignores its session and never returns must still be torn down when the
//! connection ends — otherwise an uncooperative handler (or its spawned child) leaks past
//! the client's disconnect. The serve loop's task guard aborts it; here we observe the
//! abort via a `Drop` flag inside the handler future.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use ssh_io::{ChannelSession, Driver, ExecContext, ExecHandler, HandlerFuture, serve};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    ServerAuthHandler, ServerConnection, UserPublicKey,
};

/// Announces that it started, then loops forever, ignoring the session entirely. A `Drop`
/// guard records when the future is finally dropped (i.e. aborted).
struct Forever(Arc<AtomicBool>);

impl ExecHandler for Forever {
    fn run(self: Arc<Self>, _command: Box<str>, session: ChannelSession) -> HandlerFuture {
        let dropped = Arc::clone(&self.0);
        Box::pin(async move {
            struct Guard(Arc<AtomicBool>);
            impl Drop for Guard {
                fn drop(&mut self) {
                    self.0.store(true, Ordering::SeqCst);
                }
            }
            let _guard = Guard(dropped);
            // Hold the writer so the channel stays "live", announce we're up, then spin
            // forever without ever polling the session — a handler that won't cooperate.
            let (_reader, writer) = session.split();
            let _ = writer.write_stdout(b"up\n").await;
            loop {
                tokio::time::sleep(Duration::from_secs(3600)).await;
            }
        })
    }
}

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

#[tokio::test]
async fn uncooperative_handler_is_aborted_when_client_disconnects() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let dropped = Arc::new(AtomicBool::new(false));

    let server_flag = Arc::clone(&dropped);
    let server = tokio::spawn(async move {
        let ctx = ExecContext::new().on_exec("run", Forever(server_flag));
        let conn = ServerConnection::new(OsRng, HostKey::generate(&mut OsRng), AllowPw);
        let _ = serve(server_io, conn, ctx).await;
    });

    // Authenticate, exec, wait until the handler is up, then disconnect by dropping the
    // client (and its half of the pipe).
    {
        let mut driver = Driver::new(client_io, ClientConnection::new(OsRng, TestClient));
        let run = tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(event) = driver.next_event().await.unwrap() {
                match event {
                    ClientEvent::Authenticated => driver.session_mut().exec("run").unwrap(),
                    ClientEvent::Stdout(_) => break, // handler announced it is running
                    ClientEvent::ChannelClosed => break,
                    ClientEvent::AuthFailed { .. } | ClientEvent::HostKeyRejected => {
                        panic!("setup failed")
                    }
                    _ => {}
                }
            }
        });
        run.await.expect("client must reach the running handler");
        // driver drops here → client_io closes → server sees EOF
    }

    // serve() returns on EOF, dropping the task guard, which aborts the handler; its Drop
    // guard then flips the flag. Wait for the server task, then observe the abort.
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("serve must return promptly after the client disconnects")
        .unwrap();

    let mut aborted = false;
    for _ in 0..200 {
        if dropped.load(Ordering::SeqCst) {
            aborted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        aborted,
        "the handler task must be aborted (and its future dropped) once the connection ends"
    );
}
