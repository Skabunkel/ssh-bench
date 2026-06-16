//! Generate seed corpus files for the cargo-fuzz targets in `fuzz/`. Each seed is a
//! structurally-valid byte stream so libFuzzer starts past the version/KEXINIT framing
//! (and, for the server, through the full key exchange) instead of from random bytes —
//! which lights up the pre-auth parsing paths far faster. The crypto gate still stops the
//! fuzzer at signature/MAC verification, so post-auth code stays the domain of the
//! integration tests.
//!
//! Run from anywhere in the repo: `cargo run -p ssh-transport --example gen_fuzz_corpus`.
//! The corpus directories are gitignored; this generator is the committed source of truth.

use std::fs;
use std::path::PathBuf;

use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use ssh_transport::algo::{COMPRESSION_ZLIB_OPENSSH, KexInit};
use ssh_transport::compress::Compressor;
use ssh_transport::connection;
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

/// Drive a full handshake + auth + exec, capturing every byte each side sent: the
/// client→server stream (seed for `server_on_input`) and server→client (`client_on_input`).
fn record_streams() -> (Vec<u8>, Vec<u8>) {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(1));
    let mut server = ServerConnection::new(ChaCha8Rng::seed_from_u64(2), host_key, Server);
    let mut client = ClientConnection::new(
        ChaCha8Rng::seed_from_u64(3),
        Client {
            pw: Some("pw".into()),
        },
    );

    let mut c2s = Vec::new();
    let mut s2c = Vec::new();
    for _ in 0..200 {
        let co = client.take_output();
        let mut moved = false;
        if !co.is_empty() {
            c2s.extend_from_slice(&co);
            server.on_input(&co).unwrap();
            moved = true;
        }
        let so = server.take_output();
        if !so.is_empty() {
            s2c.extend_from_slice(&so);
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
                server.channel_stdout(channel, b"out").unwrap();
                server.channel_exit(channel, 0).unwrap();
            }
        }
        if !moved {
            break;
        }
    }
    (c2s, s2c)
}

fn write_seed(target: &str, name: &str, data: &[u8]) {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/corpus")
        .join(target);
    fs::create_dir_all(&dir).expect("create corpus dir");
    let path = dir.join(name);
    fs::write(&path, data).expect("write seed");
    println!("wrote {} ({} bytes)", path.display(), data.len());
}

fn main() {
    let (c2s, s2c) = record_streams();
    // The server seed drives the full KEX (it fails only at the first encrypted packet,
    // since the fuzz server derives different keys); the client seed reaches the
    // KEX_ECDH_REPLY parse and host-key verify path.
    write_seed("server_on_input", "valid-handshake", &c2s);
    write_seed("client_on_input", "valid-handshake", &s2c);

    // A standalone valid KEXINIT payload for the parser target.
    let kexinit = KexInit::ours(&mut ChaCha8Rng::seed_from_u64(9), false).payload;
    write_seed("kexinit_parse", "valid-kexinit", &kexinit);

    // A valid zlib-compressed blob for the decompressor target.
    let blob = Compressor::new(COMPRESSION_ZLIB_OPENSSH)
        .compress(b"corpus seed payload\n".as_slice());
    write_seed("decompress", "valid-zlib", &blob);

    // Post-auth connection-protocol messages (already decrypted plaintext) — valid seeds
    // for the targets that fuzz behind the crypto gate.
    write_seed(
        "post_auth_server",
        "channel-data",
        &connection::channel_data(0, b"hello"),
    );
    write_seed(
        "post_auth_server",
        "exec-request",
        &connection::channel_request_exec(0, true, "ls -la"),
    );
    write_seed(
        "post_auth_server",
        "window-adjust",
        &connection::channel_window_adjust(0, 4096),
    );
    write_seed(
        "post_auth_server",
        "channel-close",
        &connection::channel_close(0),
    );
    write_seed(
        "post_auth_client",
        "channel-data",
        &connection::channel_data(0, b"out"),
    );
    write_seed(
        "post_auth_client",
        "extended-data",
        &connection::channel_extended_data(0, 1, b"err"),
    );
    write_seed(
        "post_auth_client",
        "exit-status",
        &connection::channel_request_exit_status(0, 0),
    );

    println!("done; now run e.g. `cargo +nightly fuzz run post_auth_server`");
}
