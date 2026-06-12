//! In-memory PTY negotiation tests: `pty-req` grant/refusal policy, `window-change`
//! propagation, and reply attribution on the client (a refused PTY must not read as a
//! failed session request).

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
    pw: Option<Password>,
}
impl ClientAuthHandler for Client {
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

type C = ClientConnection<ChaCha8Rng, Client>;
type S = ServerConnection<ChaCha8Rng, Server>;

fn pump(c: &mut C, s: &mut S) -> bool {
    let mut moved = false;
    let co = c.take_output();
    if !co.is_empty() {
        s.on_input(&co).unwrap();
        moved = true;
    }
    let so = s.take_output();
    if !so.is_empty() {
        c.on_input(&so).unwrap();
        moved = true;
    }
    moved
}

fn pair() -> (C, S) {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(7));
    let server = ServerConnection::new(ChaCha8Rng::seed_from_u64(2), host_key, Server);
    let client = ClientConnection::new(
        ChaCha8Rng::seed_from_u64(1),
        Client {
            pw: Some("pw".into()),
        },
    );
    (client, server)
}

/// Drive both sides until quiescent, collecting every event.
fn settle(c: &mut C, s: &mut S) -> (Vec<ClientEvent>, Vec<ServerEvent>) {
    let mut ce = Vec::new();
    let mut se = Vec::new();
    for _ in 0..64 {
        let moved = pump(c, s);
        while let Some(e) = c.poll_event() {
            if matches!(e, ClientEvent::Authenticated) {
                c.request_pty("xterm-256color", 120, 40);
                c.shell().unwrap();
            }
            ce.push(e);
        }
        while let Some(e) = s.poll_event() {
            if let ServerEvent::ShellRequest { channel } = e {
                s.accept_channel(channel).unwrap();
            }
            se.push(e);
        }
        if !moved {
            break;
        }
    }
    (ce, se)
}

#[test]
fn pty_is_granted_when_allowed_and_window_change_propagates() {
    let (mut client, mut server) = pair();
    server.set_allow_pty(true);

    let (ce, se) = settle(&mut client, &mut server);
    assert!(
        ce.iter().any(|e| matches!(e, ClientEvent::PtyGranted)),
        "client must learn the PTY was granted"
    );
    assert!(
        se.iter()
            .any(|e| matches!(e, ServerEvent::ShellRequest { .. })),
        "shell must still be requested after the pty-req"
    );

    let pty = server.channel_pty(0).expect("server must hold the PTY");
    assert_eq!(&*pty.term, "xterm-256color");
    assert_eq!((pty.cols, pty.rows), (120, 40));

    // Resize: the stored PTY updates and an event is emitted.
    client.window_change(80, 24).unwrap();
    let mut resized = None;
    for _ in 0..8 {
        if !pump(&mut client, &mut server) {
            break;
        }
        while let Some(e) = server.poll_event() {
            if let ServerEvent::WindowChange { cols, rows, .. } = e {
                resized = Some((cols, rows));
            }
        }
    }
    assert_eq!(resized, Some((80, 24)), "window-change must surface");
    let pty = server.channel_pty(0).unwrap();
    assert_eq!((pty.cols, pty.rows), (80, 24), "stored size must track");
}

#[test]
fn pty_is_refused_by_default_and_session_survives() {
    let (mut client, mut server) = pair();
    // allow_pty stays false (the default).

    let (ce, se) = settle(&mut client, &mut server);
    assert!(
        ce.iter().any(|e| matches!(e, ClientEvent::PtyRefused)),
        "client must learn the PTY was refused"
    );
    assert!(
        !ce.iter()
            .any(|e| matches!(e, ClientEvent::RequestFailed | ClientEvent::ChannelClosed)),
        "a refused PTY must not tear down the session"
    );
    assert!(
        se.iter()
            .any(|e| matches!(e, ServerEvent::ShellRequest { .. })),
        "the shell request must still go through"
    );
    assert!(server.channel_pty(0).is_none());

    // window-change without a granted PTY is ignored, not an error.
    client.window_change(80, 24).unwrap();
    for _ in 0..8 {
        if !pump(&mut client, &mut server) {
            break;
        }
        while let Some(e) = server.poll_event() {
            assert!(
                !matches!(e, ServerEvent::WindowChange { .. }),
                "no WindowChange without a granted PTY"
            );
        }
    }
}
