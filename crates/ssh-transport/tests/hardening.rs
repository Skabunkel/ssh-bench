//! End-to-end hardening tests: a real client ↔ server pair (over in-memory byte
//! shuttling) exercises the pre-auth and connection-layer DoS guards. Crafted packets
//! are injected through `send_raw_packet`, the same hook the fuzzers use to drive the
//! peer's parsers behind the crypto gate.

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use ssh_transport::auth::{self, SERVICE_CONNECTION};
use ssh_transport::connection as conn;
use ssh_transport::msg;
use ssh_transport::wire::Writer;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    ServerAuthHandler, ServerConnection, ServerEvent, UserKeypair, UserPublicKey,
};

const ED25519: &str = "ssh-ed25519";

struct Srv {
    password: Option<(String, String)>,
    authorized: Option<UserPublicKey>,
}

impl ServerAuthHandler for Srv {
    fn verify_password(&mut self, user: &str, password: &str) -> bool {
        self.password
            .as_ref()
            .is_some_and(|(u, p)| u == user && p == password)
    }
    fn is_authorized_key(&mut self, _user: &str, key: &UserPublicKey) -> bool {
        self.authorized.as_ref() == Some(key)
    }
}

struct Cli {
    attempts: Vec<AuthAttempt>,
}

impl ClientAuthHandler for Cli {
    fn username(&self) -> Box<str> {
        "user".into()
    }
    fn verify_host_key(&mut self, _key: &HostPublicKey) -> bool {
        true
    }
    fn next_auth(&mut self, _can_continue: &[Box<str>]) -> Option<AuthAttempt> {
        if self.attempts.is_empty() {
            None
        } else {
            Some(self.attempts.remove(0))
        }
    }
}

type Client = ClientConnection<ChaCha8Rng, Cli>;
type Server = ServerConnection<ChaCha8Rng, Srv>;

fn make_pair(srv: Srv, attempts: Vec<AuthAttempt>) -> (Client, Server) {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(100));
    let server = ServerConnection::new(ChaCha8Rng::seed_from_u64(101), host_key, srv);
    let client = ClientConnection::new(ChaCha8Rng::seed_from_u64(202), Cli { attempts });
    (client, server)
}

/// Shuttle one round of bytes each way. Returns whether anything moved.
fn pump(client: &mut Client, server: &mut Server) -> bool {
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

/// Pump to quiescence, collecting all events from both sides.
fn settle(client: &mut Client, server: &mut Server) -> (Vec<ClientEvent>, Vec<ServerEvent>) {
    let mut ce = Vec::new();
    let mut se = Vec::new();
    for _ in 0..128 {
        let moved = pump(client, server);
        while let Some(e) = client.poll_event() {
            ce.push(e);
        }
        while let Some(e) = server.poll_event() {
            se.push(e);
        }
        if !moved {
            break;
        }
    }
    (ce, se)
}

/// A peer that knows an authorized public key (public information) could send unbounded
/// no-signature `publickey` probes: each is answered with `PK_OK` and never counts as a
/// failure, so the brute-force cap never trips. The request cap must drop such a flood.
#[test]
fn publickey_probe_flood_is_capped() {
    let key = UserKeypair::generate(&mut ChaCha8Rng::seed_from_u64(303));
    let blob = key.public().blob();
    let (mut client, mut server) = make_pair(
        Srv {
            password: None,
            authorized: Some(key.public()), // probes will be answered with PK_OK
        },
        vec![], // the client makes no auth attempt of its own
    );

    // Complete the handshake so the transport is established (probes need it).
    settle(&mut client, &mut server);

    // The default request cap is 50; a probe carries no signature, so none of these
    // count as failures. Inject more than the cap.
    let probe = auth::publickey_request("user", SERVICE_CONNECTION, ED25519, &blob, None);
    let mut disconnected = false;
    let mut exhausted = false;
    for _ in 0..60 {
        let _ = client.send_raw_packet(&probe);
        let (ce, se) = settle(&mut client, &mut server);
        if se.iter().any(|e| matches!(e, ServerEvent::AuthExhausted)) {
            exhausted = true;
        }
        if ce
            .iter()
            .any(|e| matches!(e, ClientEvent::Disconnect { reason, .. } if *reason == 2))
        {
            disconnected = true;
        }
        if disconnected {
            break;
        }
    }

    assert!(
        exhausted,
        "the server must signal AuthExhausted on a probe flood"
    );
    assert!(
        disconnected,
        "the client must be disconnected (PROTOCOL_ERROR) once the request cap is hit"
    );
    assert!(
        server.is_closing(),
        "server must be closing after the flood"
    );
    assert!(!client.is_authenticated());
}

/// A `CHANNEL_OPEN` advertising a tiny maximum packet size would force per-byte framing
/// (an AEAD seal per byte) — an amplification/CPU vector. The server must refuse it.
#[test]
fn channel_open_with_tiny_max_packet_is_refused() {
    let (mut client, mut server) = make_pair(
        Srv {
            password: Some(("user".into(), "pw".into())),
            authorized: None,
        },
        vec![AuthAttempt::Password("pw".into())],
    );
    settle(&mut client, &mut server);
    assert!(client.is_authenticated(), "auth must succeed first");

    // Hand-roll a CHANNEL_OPEN with max_packet = 4 (far below the floor).
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_OPEN);
    w.string(b"session");
    w.u32(0); // sender channel
    w.u32(conn::DEFAULT_WINDOW); // initial window (fine)
    w.u32(4); // maximum packet size (abusive)
    client.send_raw_packet(&w.into_bytes()).unwrap();

    let (ce, _se) = settle(&mut client, &mut server);
    assert!(
        ce.iter().any(|e| matches!(
            e,
            ClientEvent::ChannelOpenFailure { reason, .. }
                if *reason == conn::open_failure::ADMINISTRATIVELY_PROHIBITED
        )),
        "a tiny max-packet channel open must be refused: {ce:?}"
    );
}

/// A session runs one program. A second exec/shell on a channel that already started one
/// must be refused (no second request event), so a peer can't churn handlers on one
/// session. Matches OpenSSH.
#[test]
fn second_exec_on_one_channel_is_refused() {
    let (mut client, mut server) = make_pair(
        Srv {
            password: Some(("user".into(), "pw".into())),
            authorized: None,
        },
        vec![AuthAttempt::Password("pw".into())],
    );
    settle(&mut client, &mut server);
    assert!(client.is_authenticated());

    // First exec: opens the channel and (on confirmation) sends the request.
    client.exec("first").unwrap();
    let (_ce, se1) = settle(&mut client, &mut server);
    let first_count = se1
        .iter()
        .filter(|e| matches!(e, ServerEvent::ExecRequest { .. }))
        .count();
    assert_eq!(first_count, 1, "the first exec must surface one request");

    // Second exec injected on the same (server) channel id 0 — must be refused outright.
    let dup = conn::channel_request_exec(0, true, "second");
    client.send_raw_packet(&dup).unwrap();
    let (_ce2, se2) = settle(&mut client, &mut server);
    let second_count = se2
        .iter()
        .filter(|e| matches!(e, ServerEvent::ExecRequest { .. }))
        .count();
    assert_eq!(
        second_count, 0,
        "a second program request on the same channel must not surface"
    );
}
