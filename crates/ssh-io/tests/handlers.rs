//! Integration test for the exec handler system over a loopback socket: a restricted
//! [`ExecContext`] runs an in-process `cat` handler and rejects everything else.

use std::sync::Arc;

use ssh_io::{ChannelSession, Driver, ExecContext, ExecHandler, HandlerFuture, serve};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    ServerAuthHandler, ServerConnection, UserPublicKey,
};
use tokio::net::{TcpListener, TcpStream};

/// In-process echo handler (stands in for sftp/git/etc.).
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

struct Outcome {
    stdout: Vec<u8>,
    exit: Option<u32>,
    rejected: bool,
}

async fn run_client(addr: std::net::SocketAddr, command: &str, input: &[u8]) -> Outcome {
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut driver = Driver::new(stream, ClientConnection::new(OsRng, TestClient));
    let mut out = Outcome { stdout: Vec::new(), exit: None, rejected: false };
    let command = command.to_owned();
    while let Some(event) = driver.next_event().await.unwrap() {
        match event {
            ClientEvent::Authenticated => driver.session_mut().exec(&command).unwrap(),
            ClientEvent::ChannelReady { .. } => {
                driver.session_mut().write_stdin(input).unwrap();
                driver.session_mut().send_eof().unwrap();
            }
            ClientEvent::Stdout(d) => out.stdout.extend_from_slice(&d),
            ClientEvent::ExitStatus(s) => out.exit = Some(s),
            ClientEvent::RequestFailed => out.rejected = true,
            ClientEvent::ChannelClosed => break,
            ClientEvent::AuthFailed { .. } | ClientEvent::HostKeyRejected => break,
            _ => {}
        }
    }
    out
}

#[tokio::test]
async fn restricted_context_runs_cat_and_rejects_others() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Restricted context: only `cat`. No shell, no system access.
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else { break };
            tokio::spawn(async move {
                let ctx = ExecContext::new().on_exec("cat", Cat);
                let conn = ServerConnection::new(OsRng, HostKey::generate(&mut OsRng), AllowPw);
                let _ = serve(stream, conn, ctx).await;
            });
        }
    });

    // Allowed command echoes its stdin and exits 0.
    let allowed = run_client(addr, "cat", b"hello-handler\n").await;
    assert_eq!(allowed.stdout, b"hello-handler\n");
    assert_eq!(allowed.exit, Some(0));
    assert!(!allowed.rejected);

    // Any other command is refused (no system access).
    let denied = run_client(addr, "rm -rf /", b"").await;
    assert!(denied.rejected, "unregistered command must be rejected");
    assert!(denied.stdout.is_empty());
}
