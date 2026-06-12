//! Fuzz the client's untrusted-input entry point: arbitrary server bytes into a fresh
//! `ClientConnection::on_input` must never panic, overflow, or hang.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use ssh_transport::{AuthAttempt, ClientAuthHandler, ClientConnection, HostPublicKey};

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

fuzz_target!(|data: &[u8]| {
    let mut client = ClientConnection::new(ChaCha8Rng::seed_from_u64(0xC), NullClient);
    let _ = client.on_input(data);
    let _ = client.take_output();
    while client.poll_event().is_some() {}
});
