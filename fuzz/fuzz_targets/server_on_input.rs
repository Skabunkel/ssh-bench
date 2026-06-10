//! Fuzz the server's untrusted-input entry point: arbitrary bytes into a fresh
//! `ServerConnection::on_input` must never panic, overflow, or hang.
#![no_main]

use libfuzzer_sys::fuzz_target;
use rand_chacha::ChaCha8Rng;
use rand_core::SeedableRng;
use ssh_transport::{HostKey, ServerAuthHandler, ServerConnection};

struct NullServer;
impl ServerAuthHandler for NullServer {}

fuzz_target!(|data: &[u8]| {
    // Fixed seeds keep a crash reproducible from the input bytes alone.
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(0xF));
    let mut server = ServerConnection::new(ChaCha8Rng::seed_from_u64(0xE), host_key, NullServer);
    let _ = server.on_input(data);
    let _ = server.take_output();
    while server.poll_event().is_some() {}
});
