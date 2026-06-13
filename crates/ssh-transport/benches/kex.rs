//! Key-exchange cost per method: a full exchange (client keygen → server encapsulate →
//! client agree), which is the expensive crypto that differentiates the classical and
//! post-quantum hybrid methods. Runs once per connection (and per rekey), so this is the
//! handshake-latency hot spot rather than a per-packet one.

use std::hint::black_box;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use rand_chacha::ChaCha8Rng;
use ssh_transport::kex::EcdhKeypair;
use ssh_transport::rand_core::SeedableRng;
use ssh_transport::{mlkem, sntrup};

/// Benchmark the three stages of a hybrid KEM (`$kem` is the module: `mlkem` or `sntrup`):
/// client keygen, server encapsulation, and client decapsulation. `agree` consumes the
/// client, so decapsulation uses `iter_batched` with the keygen+encapsulate done untimed
/// in setup.
macro_rules! kem_stage_group {
    ($c:expr, $label:literal, $kem:path) => {{
        use $kem as kem;
        let mut group = $c.benchmark_group(concat!("kex_stage/", $label));
        group.bench_function("keygen", |b| {
            let mut rng = ChaCha8Rng::seed_from_u64(10);
            b.iter(|| black_box(kem::HybridClient::generate(&mut rng)));
        });
        group.bench_function("encapsulate", |b| {
            let mut rng = ChaCha8Rng::seed_from_u64(11);
            let init = kem::HybridClient::generate(&mut rng).init().to_vec();
            b.iter(|| black_box(kem::server_respond(&mut rng, &init).unwrap()));
        });
        group.bench_function("decapsulate", |b| {
            let mut rng = ChaCha8Rng::seed_from_u64(12);
            b.iter_batched(
                || {
                    let client = kem::HybridClient::generate(&mut rng);
                    let (reply, _sk) = kem::server_respond(&mut rng, client.init()).unwrap();
                    (client, reply)
                },
                |(client, reply)| black_box(client.agree(&reply).unwrap()),
                BatchSize::PerIteration,
            );
        });
        group.finish();
    }};
}

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

fn bench_kex_stages(c: &mut Criterion) {
    kem_stage_group!(c, "mlkem768x25519", ssh_transport::mlkem);
    kem_stage_group!(c, "sntrup761x25519", ssh_transport::sntrup);

    // Classical curve25519 is a symmetric DH: a keygen and an `agree` (no separate
    // encapsulate/decapsulate). Included for comparison against the hybrids' stages.
    let mut group = c.benchmark_group("kex_stage/curve25519");
    group.bench_function("keygen", |b| {
        let mut rng = ChaCha8Rng::seed_from_u64(20);
        b.iter(|| black_box(EcdhKeypair::generate(&mut rng)));
    });
    group.bench_function("agree", |b| {
        let mut rng = ChaCha8Rng::seed_from_u64(21);
        b.iter_batched(
            || {
                let local = EcdhKeypair::generate(&mut rng);
                let peer_pub = EcdhKeypair::generate(&mut rng).public();
                (local, peer_pub)
            },
            |(local, peer_pub)| black_box(local.agree(&peer_pub).unwrap()),
            BatchSize::PerIteration,
        );
    });
    group.finish();
}

criterion_group!(benches, bench_kex, bench_kex_stages);
criterion_main!(benches);
