//! In-memory client ↔ server shell test: the client requests a shell, the harness
//! (standing in for the process) echoes stdin back to stdout, and the client observes it.

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
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
fn shell_request_drives_an_interactive_session() {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(11));
    let mut server = ServerConnection::new(ChaCha8Rng::seed_from_u64(12), host_key, Server);
    let mut client = ClientConnection::new(
        ChaCha8Rng::seed_from_u64(13),
        Client {
            password: Some("pw".into()),
        },
    );

    let mut shell_seen = false;
    let mut got_prompt = false;
    let mut stdout = Vec::new();
    let mut done = false;

    for _ in 0..200 {
        let moved = pump(&mut client, &mut server);

        while let Some(e) = client.poll_event() {
            match e {
                ClientEvent::Authenticated => client.shell().unwrap(),
                ClientEvent::ChannelReady { .. } => {
                    // Once the shell is up, send a line of input.
                    client.write_stdin(b"hello\n").unwrap();
                }
                ClientEvent::Stdout(d) => stdout.extend_from_slice(&d),
                ClientEvent::ChannelClosed => done = true,
                _ => {}
            }
        }
        while let Some(e) = server.poll_event() {
            match e {
                ServerEvent::ShellRequest { channel } => {
                    shell_seen = true;
                    server.accept_channel(channel).unwrap();
                    server.channel_stdout(channel, b"$ ").unwrap();
                    got_prompt = true;
                }
                ServerEvent::ChannelData { channel, data } => {
                    // Echo received stdin back, then close.
                    server.channel_stdout(channel, &data).unwrap();
                    server.channel_exit(channel, 0).unwrap();
                }
                _ => {}
            }
        }

        if !moved && done {
            break;
        }
    }

    assert!(shell_seen, "server never saw the shell request");
    assert!(got_prompt);
    assert!(
        stdout.windows(6).any(|w| w == b"hello\n"),
        "echoed stdin not observed in stdout: {stdout:?}"
    );
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
