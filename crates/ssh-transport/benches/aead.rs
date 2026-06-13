//! Per-packet AEAD hot path: `Cipher::seal_into` (outbound) and `Cipher::open` (inbound)
//! for both negotiated ciphers, across payload sizes from a tiny control packet to a
//! full max-size data packet. Throughput is reported per payload byte.

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand_chacha::ChaCha8Rng;
use ssh_transport::algo::{CIPHER_AES256_GCM, CIPHER_CHACHA20_POLY1305};
use ssh_transport::cipher::Cipher;
use ssh_transport::rand_core::SeedableRng;

const SIZES: &[usize] = &[64, 1024, 8192, 32768];

fn make_cipher(name: &str) -> Cipher {
    if name == CIPHER_CHACHA20_POLY1305 {
        let key: Vec<u8> = (0..64u8).collect();
        Cipher::new(name, &key, &[]).unwrap()
    } else {
        let key: Vec<u8> = (0..32u8).collect();
        let iv: Vec<u8> = (0..12u8).collect();
        Cipher::new(name, &key, &iv).unwrap()
    }
}

fn bench_seal(c: &mut Criterion) {
    for &name in &[CIPHER_CHACHA20_POLY1305, CIPHER_AES256_GCM] {
        let mut group = c.benchmark_group(format!("seal/{name}"));
        for &size in SIZES {
            let payload = vec![0xABu8; size];
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, p| {
                let mut rng = ChaCha8Rng::seed_from_u64(0x5EA1);
                let mut cipher = make_cipher(name);
                // Reused output buffer (retains capacity, like the transport's tx buffer),
                // so this measures steady-state sealing without a per-call allocation.
                let mut out = Vec::with_capacity(p.len() + 64);
                let mut seq = 0u32;
                b.iter(|| {
                    out.clear();
                    cipher.seal_into(seq, black_box(p), &mut rng, &mut out);
                    seq = seq.wrapping_add(1);
                    black_box(out.len());
                });
            });
        }
        group.finish();
    }
}

fn bench_open(c: &mut Criterion) {
    let mut rng = ChaCha8Rng::seed_from_u64(0xBEEF);
    for &name in &[CIPHER_CHACHA20_POLY1305, CIPHER_AES256_GCM] {
        let mut group = c.benchmark_group(format!("open/{name}"));
        for &size in SIZES {
            let payload = vec![0xABu8; size];
            // Seal one frame at sequence 0; each timed `open` runs on a fresh cipher (made
            // untimed in setup) so the matching keystream/IV state is reproduced exactly —
            // necessary for the stateful GCM IV counter.
            let mut sealer = make_cipher(name);
            let mut frame = Vec::new();
            sealer.seal_into(0, &payload, &mut rng, &mut frame);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(size), &frame, |b, frame| {
                b.iter_batched(
                    || make_cipher(name),
                    |mut cipher| {
                        let (payload, _consumed) = cipher.open(0, black_box(frame)).unwrap().unwrap();
                        black_box(payload.len());
                    },
                    BatchSize::SmallInput,
                );
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_seal, bench_open);
criterion_main!(benches);
