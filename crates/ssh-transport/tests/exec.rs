//! In-memory client ↔ server exec test: open a session channel, run a command, stream
//! stdout/stderr and exit status. The "process" is simulated by the test harness
//! responding to the server's `ExecRequest` event (process spawning is Infrastructure's job).

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use ssh_transport::{
    AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent, HostKey, HostPublicKey,
    Obfuscation, Password, ServerAuthHandler, ServerConnection, ServerEvent,
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
fn exec_streams_output_and_exit_status() {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(1));
    let mut server = ServerConnection::new(ChaCha8Rng::seed_from_u64(2), host_key, Server);
    let mut client = ClientConnection::new(
        ChaCha8Rng::seed_from_u64(3),
        Client {
            password: Some("pw".into()),
        },
    );

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit = None;
    let mut exec_seen = false;
    let mut requested = false;

    for _ in 0..200 {
        let moved = pump(&mut client, &mut server);

        while let Some(e) = client.poll_event() {
            match e {
                ClientEvent::Authenticated => client.exec("run").unwrap(),
                ClientEvent::Stdout(d) => stdout.extend_from_slice(&d),
                ClientEvent::Stderr(d) => stderr.extend_from_slice(&d),
                ClientEvent::ExitStatus(c) => exit = Some(c),
                _ => {}
            }
        }
        while let Some(e) = server.poll_event() {
            if let ServerEvent::ExecRequest { channel, command } = e {
                assert_eq!(&*command, "run");
                exec_seen = true;
                requested = true;
                server.accept_channel(channel).unwrap();
                // Simulate a process: emit stdout + stderr, then exit 7.
                server.channel_stdout(channel, b"hello stdout").unwrap();
                server.channel_stderr(channel, b"warn stderr").unwrap();
                server.channel_exit(channel, 7).unwrap();
            }
        }

        if !moved && requested && exit.is_some() {
            break;
        }
    }

    assert!(exec_seen, "server never saw the exec request");
    assert_eq!(stdout, b"hello stdout");
    assert_eq!(stderr, b"warn stderr");
    assert_eq!(exit, Some(7));
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

/// With chunking + chaff enabled on both ends, a stream must still reassemble byte-for-byte
/// (chaff `SSH_MSG_IGNORE` packets are transparently dropped), and a payload larger than
/// `max_chunk` must arrive split across several real data packets.
#[test]
fn obfuscation_preserves_stream_integrity() {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(1));
    let mut server = ServerConnection::new(ChaCha8Rng::seed_from_u64(2), host_key, Server);
    let mut client = ClientConnection::new(
        ChaCha8Rng::seed_from_u64(3),
        Client {
            password: Some("pw".into()),
        },
    );
    server.set_obfuscation(Obfuscation::INTERACTIVE);
    client.set_obfuscation(Obfuscation::INTERACTIVE);

    let payload: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
    let mut stdout = Vec::new();
    let mut stdout_packets = 0usize;
    let mut exit = None;
    let mut requested = false;

    for _ in 0..400 {
        let moved = pump(&mut client, &mut server);
        while let Some(e) = client.poll_event() {
            match e {
                ClientEvent::Authenticated => client.exec("run").unwrap(),
                ClientEvent::Stdout(d) => {
                    stdout_packets += 1;
                    stdout.extend_from_slice(&d);
                }
                ClientEvent::ExitStatus(c) => exit = Some(c),
                _ => {}
            }
        }
        while let Some(e) = server.poll_event() {
            if let ServerEvent::ExecRequest { channel, command } = e {
                assert_eq!(&*command, "run");
                requested = true;
                server.accept_channel(channel).unwrap();
                server.channel_stdout(channel, &payload).unwrap();
                server.channel_exit(channel, 0).unwrap();
            }
        }
        if !moved && requested && exit.is_some() {
            break;
        }
    }

    assert_eq!(stdout, payload, "obfuscated stream must reassemble exactly");
    assert!(
        stdout_packets >= 4,
        "max_chunk=256 must split 1000 bytes across packets, got {stdout_packets}"
    );
    assert_eq!(exit, Some(0));
}
