//! In-memory client ↔ server test for delayed `zlib@openssh.com` compression: the client
//! prefers compression, the server offers it, and a large repetitive payload round-trips
//! correctly through the compressed channel after authentication.

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use ssh_transport::algo::{COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH};
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    Password, ServerAuthHandler, ServerConnection, ServerEvent,
};

struct Server;
impl ServerAuthHandler for Server {
    fn verify_password(&mut self, _u: &str, p: &str) -> bool {
        p == "pw"
    }
}

struct Client {
    password: Option<Password>,
}
impl ClientAuthHandler for Client {
    fn username(&self) -> Box<str> {
        "user".into()
    }
    fn verify_host_key(&mut self, _k: &HostPublicKey) -> bool {
        true
    }
    fn next_auth(&mut self, _c: &[Box<str>]) -> Option<AuthAttempt> {
        self.password.take().map(AuthAttempt::Password)
    }
}

type C = ClientConnection<ChaCha8Rng, Client>;
type S = ServerConnection<ChaCha8Rng, Server>;

#[test]
fn delayed_zlib_compresses_and_round_trips() {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(1));
    let mut server = ServerConnection::new(ChaCha8Rng::seed_from_u64(2), host_key, Server);
    // Client prefers zlib@openssh.com; the server offers it by default.
    let mut client = ClientConnection::with_compression_preference(
        ChaCha8Rng::seed_from_u64(3),
        Client {
            password: Some("pw".into()),
        },
        &[COMPRESSION_ZLIB_OPENSSH, COMPRESSION_NONE],
    );

    // A large, highly compressible payload to exercise the compressed path end-to-end.
    let big: Vec<u8> = b"the quick brown fox jumps over the lazy dog\n"
        .iter()
        .cycle()
        .take(200_000)
        .copied()
        .collect();

    let mut stdout = Vec::new();
    let mut exit = None;
    let mut requested = false;
    let mut active_at_auth = false;

    for _ in 0..400 {
        let moved = pump(&mut client, &mut server);

        while let Some(e) = client.poll_event() {
            match e {
                ClientEvent::Authenticated => {
                    active_at_auth = client.is_compression_active();
                    client.exec("run").unwrap();
                }
                ClientEvent::Stdout(d) => stdout.extend_from_slice(&d),
                ClientEvent::ExitStatus(c) => exit = Some(c),
                _ => {}
            }
        }
        while let Some(e) = server.poll_event() {
            if let ServerEvent::ExecRequest { channel, .. } = e {
                requested = true;
                server.accept_channel(channel).unwrap();
                server.channel_stdout(channel, &big).unwrap();
                server.channel_exit(channel, 0).unwrap();
            }
        }

        if !moved && requested && exit.is_some() {
            break;
        }
    }

    // Compression was negotiated and engaged immediately on authentication.
    assert_eq!(
        client.negotiated_compression(),
        Some(COMPRESSION_ZLIB_OPENSSH)
    );
    assert!(
        active_at_auth,
        "compression should be active once authenticated"
    );
    assert!(client.is_compression_active());

    // The payload survived the compress → encrypt → decrypt → decompress round trip.
    assert_eq!(exit, Some(0));
    assert_eq!(stdout.len(), big.len());
    assert_eq!(stdout, big);
}

fn pump(client: &mut C, server: &mut S) -> bool {
    let mut moved = false;
    let c_out = client.take_output();
    if !c_out.is_empty() {
        server.on_input(&c_out).unwrap();
        moved = true;
    }
    let s_out = server.take_output();
    if !s_out.is_empty() {
        client.on_input(&s_out).unwrap();
        moved = true;
    }
    moved
}
