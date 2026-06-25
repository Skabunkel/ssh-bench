//! End-to-end post-handshake data path: one application packet from `send_packet` through
//! the wire and back out as an `Event::Packet`. This exercises the whole steady-state hot
//! path together — outbound sealing into the tx buffer, `take_output`, `on_input`'s rx
//! handling (read cursor + compaction), in-place AEAD `open`, and event delivery.

use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
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

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("transport_roundtrip");
    for &size in SIZES {
        let payload = vec![0xCDu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, p| {
            let (mut client, mut server) = establish();
            b.iter(|| {
                client.send_packet(black_box(p)).unwrap();
                let out = client.take_output();
                server.on_input(&out).unwrap();
                while let Some(ev) = server.poll_event() {
                    if let Event::Packet(pkt) = ev {
                        black_box(pkt.expose_secret().len());
                    }
                }
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_roundtrip);
criterion_main!(benches);
