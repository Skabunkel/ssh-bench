//! Integration tests for the batteries-included [`serve_listener`] accept loop and the
//! defences it wires (rate limit, connection cap, peer policy) plus the default idle
//! slow-loris guard. All run over a real loopback `TcpListener`.

use std::sync::Arc;
use std::time::Duration;

use ssh_io::{
    ChannelSession, ConnectionLimiter, Defense, Driver, ExecContext, ExecHandler, HandlerFuture,
    RateLimiter, ServeConfig, serve_listener,
};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    ServerAuthHandler, ServerConnection, UserPublicKey,
};
use tokio::net::{TcpListener, TcpStream};

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

/// Spawn `serve_listener` with the given defences and a `cat`-only context; return the
/// bound address. The host key is generated once and cloned per connection.
fn spawn_listener<P, RP>(listener: TcpListener, defense: Defense<P, RP>)
where
    P: ssh_io::ConnectionPolicy,
    RP: ssh_io::RetryPolicy + Clone,
{
    let host_key = HostKey::generate(&mut OsRng);
    tokio::spawn(async move {
        let ctx = ExecContext::new().on_exec("cat", Cat);
        let _ = serve_listener(listener, defense, ctx, move |_peer| {
            ServerConnection::new(OsRng, host_key.clone(), AllowPw)
        })
        .await;
    });
}

/// Drive a fresh client through auth + one `cat` exec; return what came back.
async fn run_cat(addr: std::net::SocketAddr, input: &[u8]) -> (Vec<u8>, Option<u32>) {
    let stream = TcpStream::connect(addr).await.unwrap();
    let mut driver = Driver::new(stream, ClientConnection::new(OsRng, TestClient));
    let (mut stdout, mut exit) = (Vec::new(), None);
    while let Some(event) = driver.next_event().await.unwrap() {
        match event {
            ClientEvent::Authenticated => driver.session_mut().exec("cat").unwrap(),
            ClientEvent::ChannelReady { .. } => {
                driver.session_mut().write_stdin(input).unwrap();
                driver.session_mut().send_eof().unwrap();
            }
            ClientEvent::Stdout(d) => stdout.extend_from_slice(&d),
            ClientEvent::ExitStatus(s) => exit = Some(s),
            ClientEvent::ChannelClosed => break,
            ClientEvent::AuthFailed { .. } | ClientEvent::HostKeyRejected => break,
            _ => {}
        }
    }
    (stdout, exit)
}

#[tokio::test]
async fn serve_listener_runs_a_command() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let defense = Defense::new(ConnectionLimiter::new(256, Some(8)), RateLimiter::new(50.0, 100.0));
    spawn_listener(listener, defense);

    let (stdout, exit) = run_cat(addr, b"hello-listener\n").await;
    assert_eq!(stdout, b"hello-listener\n");
    assert_eq!(exit, Some(0));
}

#[tokio::test]
async fn serve_listener_rate_limit_drops_excess() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Burst 1, zero refill: exactly one connection is ever admitted.
    let defense = Defense::new(ConnectionLimiter::new(256, Some(8)), RateLimiter::new(0.0, 1.0));
    spawn_listener(listener, defense);

    // First connection consumes the only token; keep it open so it holds the slot.
    let stream1 = TcpStream::connect(addr).await.unwrap();
    let mut driver1 = Driver::new(stream1, ClientConnection::new(OsRng, TestClient));
    let mut first_authed = false;
    while let Some(event) = driver1.next_event().await.unwrap() {
        if matches!(event, ClientEvent::Authenticated) {
            first_authed = true;
            break;
        }
    }
    assert!(first_authed, "first connection should authenticate");

    // Second connection is dropped at accept time (no token left), so it never reaches
    // authentication — the server closes it during the handshake.
    let stream2 = TcpStream::connect(addr).await.unwrap();
    let mut driver2 = Driver::new(stream2, ClientConnection::new(OsRng, TestClient));
    let mut second_authed = false;
    let drained = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = driver2.next_event().await.unwrap() {
            if matches!(event, ClientEvent::Authenticated) {
                second_authed = true;
                break;
            }
        }
    })
    .await;
    assert!(drained.is_ok(), "rate-limited connection should close promptly, not hang");
    assert!(!second_authed, "second connection must be rate-limited, not served");

    drop(driver1);
}

#[tokio::test]
async fn serve_listener_idle_timeout_closes_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Short idle window so the test is fast; reuse the rest of the defaults.
    let serve_cfg = ServeConfig {
        idle_timeout: Some(Duration::from_millis(200)),
        ..ServeConfig::default()
    };
    let defense = Defense::new(ConnectionLimiter::new(256, Some(8)), RateLimiter::new(50.0, 100.0))
        .with_serve_config(serve_cfg);
    spawn_listener(listener, defense);

    let stream = TcpStream::connect(addr).await.unwrap();
    let mut driver = Driver::new(stream, ClientConnection::new(OsRng, TestClient));
    // Authenticate, then go silent: never exec, never send. The server must drop us once
    // the idle window elapses (we only read, which sends nothing inbound).
    let mut authed = false;
    while let Some(event) = driver.next_event().await.unwrap() {
        if matches!(event, ClientEvent::Authenticated) {
            authed = true;
            break;
        }
    }
    assert!(authed, "client should authenticate before idling");

    let closed = tokio::time::timeout(Duration::from_secs(3), async {
        // `next_event` returns `None` on EOF — i.e. the server closed the idle connection.
        while driver.next_event().await.unwrap().is_some() {}
    })
    .await;
    assert!(closed.is_ok(), "idle connection should be closed by the server, not left open");
}
