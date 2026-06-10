//! In-memory client↔server integration test over `tokio::io::duplex` — no sockets, no
//! docker. The generic [`Driver`]/[`serve`] accept any `AsyncRead + AsyncWrite`, so a
//! duplex pipe lets a real client session and a real server loop run in one process.
//!
//! This exercises a full handshake → auth → exec round-trip, and runs it for each cipher
//! suite by pinning the client's offered cipher (negotiation prefers the client's order).

use std::sync::Arc;

use ssh_io::{ChannelSession, Driver, ExecContext, ExecHandler, HandlerFuture, serve};
use ssh_transport::algo::{CIPHER_AES256_GCM, CIPHER_CHACHA20_POLY1305};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    ServerAuthHandler, ServerConnection, UserPublicKey,
};

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

/// Run a full client session over `client_io`, returning (stdout, exit, negotiated cipher).
async fn run_client(
    client_io: tokio::io::DuplexStream,
    ciphers: &[&str],
    command: &str,
    input: &[u8],
) -> (Vec<u8>, Option<u32>, Option<String>) {
    let session = ClientConnection::with_cipher_preference(OsRng, TestClient, ciphers);
    let mut driver = Driver::new(client_io, session);

    let mut stdout = Vec::new();
    let mut exit = None;
    let mut cipher = None;
    while let Some(event) = driver.next_event().await.unwrap() {
        match event {
            ClientEvent::Authenticated => {
                // The cipher is fixed by NEWKEYS, well before auth completes.
                cipher = driver.session_mut().negotiated_cipher().map(str::to_owned);
                driver.session_mut().exec(command).unwrap();
            }
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
    (stdout, exit, cipher)
}

/// Drive a handshake → auth → `cat` exec entirely in memory with the given cipher pinned.
async fn round_trip_with_cipher(expected: &str) {
    // 64 KiB pipe buffers in each direction — comfortably larger than a handshake.
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = tokio::spawn(async move {
        let ctx = ExecContext::new().on_exec("cat", Cat);
        let conn = ServerConnection::new(OsRng, HostKey::generate(&mut OsRng), AllowPw);
        let _ = serve(server_io, conn, ctx).await;
    });

    let (stdout, exit, cipher) =
        run_client(client_io, &[expected], "cat", b"in-memory-duplex\n").await;

    assert_eq!(stdout, b"in-memory-duplex\n", "echo round-trip failed");
    assert_eq!(exit, Some(0));
    assert_eq!(
        cipher.as_deref(),
        Some(expected),
        "expected the pinned cipher to be negotiated"
    );

    server.await.unwrap();
}

#[tokio::test]
async fn duplex_session_with_chacha20_poly1305() {
    round_trip_with_cipher(CIPHER_CHACHA20_POLY1305).await;
}

#[tokio::test]
async fn duplex_session_with_aes256_gcm() {
    round_trip_with_cipher(CIPHER_AES256_GCM).await;
}
