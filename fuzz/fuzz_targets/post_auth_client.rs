//! Fuzz the client's *post-authentication* parsers (channel open confirm/failure, data,
//! extended data, window-adjust, exit-status request, eof, close) behind the crypto gate.
//!
//! Symmetric to `post_auth_server`: after a real handshake + auth + channel open, the
//! authenticated server transport encrypts the fuzz bytes and feeds them to the client.
#![no_main]

use libfuzzer_sys::fuzz_target;
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

fn pump(c: &mut ClientConnection<ChaCha8Rng, Client>, s: &mut ServerConnection<ChaCha8Rng, Server>) -> bool {
    let mut moved = false;
    let co = c.take_output();
    if !co.is_empty() {
        let _ = s.on_input(&co);
        moved = true;
    }
    let so = s.take_output();
    if !so.is_empty() {
        let _ = c.on_input(&so);
        moved = true;
    }
    moved
}

fuzz_target!(|data: &[u8]| {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(0xF));
    let mut server = ServerConnection::new(ChaCha8Rng::seed_from_u64(0xE), host_key, Server);
    let mut client =
        ClientConnection::new(ChaCha8Rng::seed_from_u64(0xC), Client { pw: Some("pw".into()) });

    let mut opened = false;
    for _ in 0..60 {
        let moved = pump(&mut client, &mut server);
        while let Some(e) = client.poll_event() {
            if matches!(e, ClientEvent::Authenticated) {
                let _ = client.exec("x");
            }
        }
        while let Some(e) = server.poll_event() {
            if let ServerEvent::ExecRequest { channel, .. } = e {
                let _ = server.accept_channel(channel);
                opened = true;
            }
        }
        if opened && !moved {
            break;
        }
    }
    if !client.is_authenticated() {
        return;
    }

    // Inject the fuzz bytes as a decrypted application packet → the client's connection
    // parser, validly encrypted by the authenticated server transport.
    if server.send_raw_packet(data).is_err() {
        return;
    }
    let _ = pump(&mut client, &mut server);
    let _ = client.take_output();
    while client.poll_event().is_some() {}
});
