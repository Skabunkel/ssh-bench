//! Key-exchange cost per method: a full exchange (client keygen → server encapsulate →
//! client agree), which is the expensive crypto that differentiates the classical and
//! post-quantum hybrid methods. Runs once per connection (and per rekey), so this is the
//! handshake-latency hot spot rather than a per-packet one.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use rand_chacha::ChaCha8Rng;
use ssh_transport::kex::EcdhKeypair;
use ssh_transport::rand_core::SeedableRng;
use ssh_transport::{mlkem, sntrup};

fn bench_kex(c: &mut Criterion) {
    let mut group = c.benchmark_group("kex_full_exchange");

    group.bench_function("curve25519-sha256", |b| {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        b.iter(|| {
            let client = EcdhKeypair::generate(&mut rng);
            let server = EcdhKeypair::generate(&mut rng);
            let client_pub = client.public();
            let server_pub = server.public();
            let ck = client.agree(&server_pub).unwrap();
            let sk = server.agree(&client_pub).unwrap();
            black_box((ck, sk));
        });
    });

    group.bench_function("mlkem768x25519-sha256", |b| {
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        b.iter(|| {
            let client = mlkem::HybridClient::generate(&mut rng);
            let (reply, sk) = mlkem::server_respond(&mut rng, client.init()).unwrap();
            let ck = client.agree(&reply).unwrap();
            black_box((ck, sk));
        });
    });

    group.bench_function("sntrup761x25519-sha512", |b| {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        b.iter(|| {
            let client = sntrup::HybridClient::generate(&mut rng);
            let (reply, sk) = sntrup::server_respond(&mut rng, client.init()).unwrap();
            let ck = client.agree(&reply).unwrap();
            black_box((ck, sk));
        });
    });

    group.finish();
}

criterion_group!(benches, bench_kex);
criterion_main!(benches);
