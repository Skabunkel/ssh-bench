//! Send and receive hot paths measured **independently**.
//!
//! Over a real socket you cannot separate the two: a send only makes progress when a peer
//! drains the other end, and a receive only happens when a peer produces bytes — the byte
//! stream couples them, so any "over a connection" benchmark inevitably times both at once
//! (that is exactly what `transport.rs`'s `transport_roundtrip` does). The separation is
//! possible *because the transport is sans-IO*: the per-byte cost of each direction lives
//! entirely in the core (`send_packet` → compress → seal → tx buffer on the way out;
//! `on_input` → AEAD `open` → decompress → parse → event on the way in). The socket itself
//! is just `read`/`write_all` — an OS syscall, identical for both directions and not part
//! of "our" callstack — so dropping it loses nothing we want to measure and removes the
//! coupling that makes separation impossible.
//!
//! * **`send_only`** drives just the outbound stack: `send_packet` then `take_output` to
//!   drain. No receiver exists, so nothing receive-side is timed. Auto-rekey is disabled so
//!   the unbounded tx sequence never triggers a mid-run key exchange.
//!
//! * **`recv_only`** is the subtle one. AEAD binds the packet sequence number, so the
//!   receiver can only decrypt ciphertext fed in the exact order it was produced — we
//!   cannot replay one captured packet in a loop. `iter_batched` solves it: the **untimed**
//!   setup closure produces the next packet's wire bytes from the sender (advancing its tx
//!   sequence), and the **timed** routine feeds them to the receiver (advancing its rx
//!   sequence). The two advance in lockstep across the whole run, so sequence numbers always
//!   match, and the send cost lands in setup — outside the measurement. What's timed is
//!   purely the inbound stack.

use std::hint::black_box;

use criterion::{
    BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use rand_chacha::ChaCha8Rng;
use secrecy::ExposeSecret;
use ssh_transport::rand_core::SeedableRng;
use ssh_transport::{Event, HostKey, Transport};

const SIZES: &[usize] = &[64, 1024, 8192, 32768];

/// Drive a client/server pair through the handshake and return them established. Auto-rekey
/// is disabled so a long benchmark run is never perturbed by a mid-run key exchange.
fn establish() -> (Transport<ChaCha8Rng>, Transport<ChaCha8Rng>) {
    let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(7));
    let mut client = Transport::new_client(ChaCha8Rng::seed_from_u64(1));
    let mut server = Transport::new_server(ChaCha8Rng::seed_from_u64(2), host_key);
    client.set_rekey_limits(u64::MAX, u64::MAX);
    server.set_rekey_limits(u64::MAX, u64::MAX);

    for _ in 0..32 {
        let c = client.take_output();
        if !c.is_empty() {
            server.on_input(&c).unwrap();
        }
        let s = server.take_output();
        if !s.is_empty() {
            client.on_input(&s).unwrap();
        }
        if client.is_established() && server.is_established() {
            break;
        }
    }
    assert!(client.is_established() && server.is_established());
    while client.poll_event().is_some() {}
    while server.poll_event().is_some() {}
    (client, server)
}

/// Outbound stack only: encode → (compress) → seal → tx buffer → `take_output`. No peer.
fn bench_send(c: &mut Criterion) {
    let mut group = c.benchmark_group("send_only");
    for &size in SIZES {
        let payload = vec![0xCDu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, p| {
            let (mut client, _server) = establish();
            b.iter(|| {
                client.send_packet(black_box(p)).unwrap();
                // Drain so the tx buffer never grows; this is the byte handoff `Driver`
                // would write to the socket.
                black_box(client.take_output().len());
            });
        });
    }
    group.finish();
}

/// Inbound stack only: `on_input` → rx cursor/compaction → AEAD `open` → (decompress) →
/// parse → event delivery. The sender runs only in the untimed `setup` to produce
/// correctly-sequenced ciphertext.
fn bench_recv(c: &mut Criterion) {
    let mut group = c.benchmark_group("recv_only");
    for &size in SIZES {
        let payload = vec![0xCDu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, p| {
            let (mut client, mut server) = establish();
            b.iter_batched(
                // Untimed: produce the next packet's wire bytes (advances client tx seq).
                || {
                    client.send_packet(p).unwrap();
                    client.take_output()
                },
                // Timed: consume them (advances server rx seq, in lockstep with the above).
                |wire| {
                    server.on_input(&wire).unwrap();
                    while let Some(ev) = server.poll_event() {
                        if let Event::Packet(pkt) = ev {
                            black_box(pkt.expose_secret().len());
                        }
                    }
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, bench_send, bench_recv);
criterion_main!(benches);
