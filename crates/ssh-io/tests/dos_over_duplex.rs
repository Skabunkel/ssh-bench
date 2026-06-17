//! Over-allocation / decompression-bomb guards exercised *over a live connection* rather
//! than against the synchronous `on_input` entry point.
//!
//! The parser-level rejections are already proven directly in `ssh-transport`'s
//! `allocation_dos.rs` / `compress.rs`. These tests close the loop one layer out: they
//! run the real async [`serve`] loop ([`Driver`] pumping over a `tokio::io::duplex` pipe)
//! and assert the *connection* reacts correctly — the server returns a protocol error and
//! tears the connection down **promptly**, never hanging on, or allocating, the bytes the
//! attacker claims. A `tokio::time::timeout` around the server task is the teeth: a parser
//! that buffered the claimed/expanded size before checking it would blow the timeout (or
//! the process's memory) instead of returning a tidy `Err`.

use std::time::Duration;

use ssh_io::{DriveError, Driver, ExecContext, serve};
use ssh_transport::algo::{COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH};
use ssh_transport::packet::MAX_PACKET_LENGTH;
use ssh_transport::rand_core::OsRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    ServerAuthHandler, ServerConnection, SshError,
};
use tokio::io::AsyncWriteExt;

struct PwServer;
impl ServerAuthHandler for PwServer {
    fn verify_password(&mut self, _u: &str, p: &str) -> bool {
        p == "pw"
    }
}

struct PwClient;
impl ClientAuthHandler for PwClient {
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

/// A peer that completes the SSH identification exchange and then sends a binary-packet
/// header claiming a `packet_length` larger than [`MAX_PACKET_LENGTH`] must have its
/// connection torn down from the header alone — the server must not wait for (let alone
/// allocate) the ~gigabyte payload the header promises. Running this through the real
/// `serve` loop proves the async read path propagates the rejection as a clean
/// `DriveError::Protocol(BadPacket)` and returns, rather than parking on the socket
/// waiting for bytes that will never (and must never) be buffered.
#[tokio::test]
async fn oversized_packet_length_tears_down_the_live_connection() {
    let (mut attacker, server_io) = tokio::io::duplex(64 * 1024);

    let server = tokio::spawn(async move {
        let conn = ServerConnection::new(OsRng, HostKey::generate(&mut OsRng), PwServer);
        serve(server_io, conn, ExecContext::new()).await
    });

    // A well-formed identification, then ONLY a 4-byte length field claiming one byte past
    // the cap. No payload follows: the header alone must be enough to reject.
    attacker
        .write_all(b"SSH-2.0-attacker\r\n")
        .await
        .expect("write identification");
    let oversized = ((MAX_PACKET_LENGTH as u32) + 1).to_be_bytes();
    attacker.write_all(&oversized).await.expect("write header");
    attacker.flush().await.expect("flush");

    let result = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("server must reject from the header and return, not hang waiting for the payload")
        .expect("server task panicked");

    assert!(
        matches!(result, Err(DriveError::Protocol(SshError::BadPacket(_)))),
        "an oversized packet_length must tear the live connection down, got {result:?}"
    );
}

/// The decompression-bomb vector, end to end over a real session: a client negotiates
/// `zlib@openssh.com`, authenticates (delayed compression engages only here), and then
/// sends a single packet whose payload expands past [`MAX_PACKET_LENGTH`] on the server.
///
/// We build the bomb by handing a large, trivially-compressible payload to the *real*
/// outbound compressor (`send_raw_packet` compresses when active), so the bytes on the
/// wire are a genuine, tiny `zlib@openssh.com` frame — exactly what an attacker would
/// craft. The server must refuse it *during decompression*, before the expanded buffer is
/// realized, surfacing `DriveError::Protocol(Compression)` and ending the connection.
#[tokio::test]
async fn decompression_bomb_over_a_live_session_is_rejected() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);

    let server = tokio::spawn(async move {
        // Server offers zlib@openssh.com by default; an empty context means no handler is
        // ever reached — the bomb is rejected at the transport, below any dispatch.
        let conn = ServerConnection::new(OsRng, HostKey::generate(&mut OsRng), PwServer);
        serve(server_io, conn, ExecContext::new()).await
    });

    let session = ClientConnection::with_compression_preference(
        OsRng,
        PwClient,
        &[COMPRESSION_ZLIB_OPENSSH, COMPRESSION_NONE],
    );
    let mut driver = Driver::new(client_io, session);

    let mut sent = false;
    loop {
        match driver.next_event().await {
            Ok(Some(ClientEvent::Authenticated)) => {
                // Premise check: compression must be live, or `send_raw_packet` would emit
                // an oversized *plaintext* packet and we'd be exercising the packet-length
                // guard (BadPacket) instead of the decompression guard we mean to test.
                assert!(
                    driver.session_mut().is_compression_active(),
                    "delayed zlib must be active at auth so the bomb is sent compressed"
                );
                // 4 MiB of zeros compresses to a handful of bytes, then expands past the
                // 1 MiB cap on the receiver — the classic zip bomb.
                let bomb = vec![0u8; MAX_PACKET_LENGTH * 4];
                driver
                    .session_mut()
                    .send_raw_packet(&bomb)
                    .expect("queue the compressed bomb");
                // Push it to the wire; the server will reject and drop, so ignore the
                // result of this and any subsequent flush.
                let _ = driver.flush().await;
                sent = true;
            }
            Ok(Some(_)) => {}
            // Server tore the connection down (clean EOF) or surfaced the teardown to us —
            // either way the client side is done.
            Ok(None) | Err(_) => break,
        }
    }
    assert!(sent, "client must authenticate and send the bomb");

    let result = tokio::time::timeout(Duration::from_secs(10), server)
        .await
        .expect("server must reject the bomb during decompression and return, not hang/OOM")
        .expect("server task panicked");

    assert!(
        matches!(result, Err(DriveError::Protocol(SshError::Compression(_)))),
        "a decompression bomb must tear the live connection down, got {result:?}"
    );
}
