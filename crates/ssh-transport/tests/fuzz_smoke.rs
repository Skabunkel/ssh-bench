//! In-suite smoke + mutation fuzzing of the untrusted-input surface. The sans-IO design
//! funnels every attacker-controlled byte through a handful of pure entry points, and the
//! invariant we assert here is simple: arbitrary or corrupted input must only ever yield
//! `Ok`/`Err` — never a panic, overflow, or hang. (A panic or non-termination fails the
//! test; iteration counts are kept CI-friendly.)

use rand_chacha::ChaCha8Rng;
use rand_core::{RngCore, SeedableRng};
use ssh_transport::algo::{COMPRESSION_ZLIB_OPENSSH, KexInit};
use ssh_transport::auth::AuthRequest;
use ssh_transport::compress::Decompressor;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    Password, ServerAuthHandler, ServerConnection, ServerEvent, UserPublicKey,
};

// --- minimal handlers ---

struct NullServer;
impl ServerAuthHandler for NullServer {}

struct NullClient;
impl ClientAuthHandler for NullClient {
    fn username(&self) -> Box<str> {
        "u".into()
    }
    fn verify_host_key(&mut self, _k: &HostPublicKey) -> bool {
        true
    }
    fn next_auth(&mut self, _c: &[Box<str>]) -> Option<AuthAttempt> {
        None
    }
}

struct PwServer;
impl ServerAuthHandler for PwServer {
    fn verify_password(&mut self, _u: &str, p: &str) -> bool {
        p == "pw"
    }
}

struct PwClient {
    pw: Option<Password>,
}
impl ClientAuthHandler for PwClient {
    fn username(&self) -> Box<str> {
        "u".into()
    }
    fn verify_host_key(&mut self, _k: &HostPublicKey) -> bool {
        true
    }
    fn next_auth(&mut self, _c: &[Box<str>]) -> Option<AuthAttempt> {
        self.pw.take().map(AuthAttempt::Password)
    }
}

// --- helpers ---

fn rand_bytes(rng: &mut ChaCha8Rng, max: usize) -> Vec<u8> {
    let n = (rng.next_u32() as usize) % (max + 1);
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v);
    v
}

/// A fuzzed input stream: sometimes prefixed with a valid identification line so the
/// fuzzer reaches the binary-packet and KEXINIT parsers behind the version stage.
fn fuzz_stream(rng: &mut ChaCha8Rng) -> Vec<u8> {
    let mut v = Vec::new();
    if rng.next_u32() & 1 == 0 {
        v.extend_from_slice(b"SSH-2.0-fuzz\r\n");
    }
    v.extend_from_slice(&rand_bytes(rng, 2048));
    v
}

/// Apply a few random structural mutations (bit flips, truncation, insertions).
fn mutate(data: &mut Vec<u8>, rng: &mut ChaCha8Rng) {
    let ops = 1 + (rng.next_u32() as usize) % 8;
    for _ in 0..ops {
        if data.is_empty() {
            data.push(rng.next_u32() as u8);
            continue;
        }
        match rng.next_u32() % 3 {
            0 => {
                let i = (rng.next_u32() as usize) % data.len();
                data[i] ^= 1u8 << (rng.next_u32() % 8);
            }
            1 => {
                let i = (rng.next_u32() as usize) % data.len();
                data.truncate(i);
            }
            _ => {
                let i = (rng.next_u32() as usize) % (data.len() + 1);
                data.insert(i, rng.next_u32() as u8);
            }
        }
    }
}

fn feed_server(
    server: &mut ServerConnection<ChaCha8Rng, NullServer>,
    data: &[u8],
    rng: &mut ChaCha8Rng,
) {
    let mut i = 0;
    while i < data.len() {
        let step = 1 + (rng.next_u32() as usize) % 64;
        let end = (i + step).min(data.len());
        if server.on_input(&data[i..end]).is_err() {
            break; // an error is a valid outcome; stop feeding this stream
        }
        let _ = server.take_output();
        while server.poll_event().is_some() {}
        i = end;
    }
}

fn feed_client(
    client: &mut ClientConnection<ChaCha8Rng, NullClient>,
    data: &[u8],
    rng: &mut ChaCha8Rng,
) {
    let mut i = 0;
    while i < data.len() {
        let step = 1 + (rng.next_u32() as usize) % 64;
        let end = (i + step).min(data.len());
        if client.on_input(&data[i..end]).is_err() {
            break;
        }
        let _ = client.take_output();
        while client.poll_event().is_some() {}
        i = end;
    }
}

/// Record a complete, valid client→server byte stream (handshake + auth + exec) to use as
/// a corpus seed for mutation fuzzing.
fn record_valid_client_stream() -> Vec<u8> {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(1));
    let mut server = ServerConnection::new(ChaCha8Rng::seed_from_u64(2), host_key, PwServer);
    let mut client = ClientConnection::new(
        ChaCha8Rng::seed_from_u64(3),
        PwClient {
            pw: Some("pw".into()),
        },
    );
    let mut recorded = Vec::new();

    for _ in 0..200 {
        let c_out = client.take_output();
        let mut moved = false;
        if !c_out.is_empty() {
            recorded.extend_from_slice(&c_out);
            server.on_input(&c_out).unwrap();
            moved = true;
        }
        let s_out = server.take_output();
        if !s_out.is_empty() {
            client.on_input(&s_out).unwrap();
            moved = true;
        }
        while let Some(e) = client.poll_event() {
            if matches!(e, ClientEvent::Authenticated) {
                client.exec("x").unwrap();
            }
        }
        while let Some(e) = server.poll_event() {
            if let ServerEvent::ExecRequest { channel, .. } = e {
                server.accept_channel(channel).unwrap();
                server.channel_stdout(channel, b"out").unwrap();
                server.channel_exit(channel, 0).unwrap();
            }
        }
        if !moved {
            break;
        }
    }
    recorded
}

/// Build a client+server that have completed a real handshake + password auth + channel
/// open, so post-auth connection handlers are reachable. Used to fuzz *behind* the crypto
/// gate: the authenticated client transport encrypts arbitrary plaintext for the server.
fn authed_pair(
    seed: u64,
) -> (
    ClientConnection<ChaCha8Rng, PwClient>,
    ServerConnection<ChaCha8Rng, PwServer>,
) {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(seed));
    let mut server = ServerConnection::new(ChaCha8Rng::seed_from_u64(seed + 1), host_key, PwServer);
    let mut client = ClientConnection::new(
        ChaCha8Rng::seed_from_u64(seed + 2),
        PwClient {
            pw: Some("pw".into()),
        },
    );
    for _ in 0..60 {
        let co = client.take_output();
        let mut moved = false;
        if !co.is_empty() {
            server.on_input(&co).unwrap();
            moved = true;
        }
        let so = server.take_output();
        if !so.is_empty() {
            client.on_input(&so).unwrap();
            moved = true;
        }
        while let Some(e) = client.poll_event() {
            if matches!(e, ClientEvent::Authenticated) {
                client.exec("x").unwrap();
            }
        }
        while let Some(e) = server.poll_event() {
            if let ServerEvent::ExecRequest { channel, .. } = e {
                server.accept_channel(channel).unwrap();
            }
        }
        if server.is_authenticated() && !moved {
            break;
        }
    }
    (client, server)
}

// --- the fuzz tests ---

#[test]
fn parsers_never_panic_on_random_input() {
    for seed in 0..5000u64 {
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let bytes = rand_bytes(&mut rng, 512);
        let _ = KexInit::parse(&bytes);
        let _ = AuthRequest::parse(&bytes);
        let _ = HostPublicKey::parse_blob(&bytes);
        let _ = UserPublicKey::parse_blob(&bytes);
        let _ = Decompressor::new(COMPRESSION_ZLIB_OPENSSH).decompress(&bytes);
    }
}

#[test]
fn server_on_input_survives_random_bytes() {
    for seed in 0..1500u64 {
        let mut rng = ChaCha8Rng::seed_from_u64(seed ^ 0x5151);
        let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(seed));
        let mut server =
            ServerConnection::new(ChaCha8Rng::seed_from_u64(seed + 1), host_key, NullServer);
        let data = fuzz_stream(&mut rng);
        feed_server(&mut server, &data, &mut rng);
    }
}

#[test]
fn client_on_input_survives_random_bytes() {
    for seed in 0..1500u64 {
        let mut rng = ChaCha8Rng::seed_from_u64(seed ^ 0x6262);
        let mut client = ClientConnection::new(ChaCha8Rng::seed_from_u64(seed + 1), NullClient);
        let data = fuzz_stream(&mut rng);
        feed_client(&mut client, &data, &mut rng);
    }
}

#[test]
fn server_survives_fuzzed_post_auth_packets() {
    // Behind the crypto gate: drive the authenticated server's connection-protocol parsers
    // with arbitrary plaintext, validly encrypted by the real client transport. (A full
    // handshake per iteration is the cost of reaching past the gate, so keep the count
    // modest here — the cargo-fuzz `post_auth_server` target does the millions of runs.)
    for seed in 0..250u64 {
        let mut rng = ChaCha8Rng::seed_from_u64(seed ^ 0x9999);
        let (mut client, mut server) = authed_pair(seed);
        assert!(server.is_authenticated(), "auth setup should complete");
        let payload = rand_bytes(&mut rng, 256);
        if client.send_raw_packet(&payload).is_ok() {
            let co = client.take_output();
            let _ = server.on_input(&co);
            let _ = server.take_output();
            while server.poll_event().is_some() {}
        }
    }
}

#[test]
fn server_survives_mutated_valid_stream() {
    let base = record_valid_client_stream();
    assert!(!base.is_empty(), "should have recorded a handshake");
    for seed in 0..2000u64 {
        let mut rng = ChaCha8Rng::seed_from_u64(seed ^ 0x7373);
        let mut data = base.clone();
        mutate(&mut data, &mut rng);
        let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(seed));
        let mut server =
            ServerConnection::new(ChaCha8Rng::seed_from_u64(seed + 1), host_key, NullServer);
        feed_server(&mut server, &data, &mut rng);
    }
}
