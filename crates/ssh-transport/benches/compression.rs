//! `zlib@openssh.com` compression hot path: `Compressor::compress` and
//! `Decompressor::decompress` on two payload profiles — compressible (text-like) and
//! incompressible (random) — across packet sizes. Each timed call runs on a freshly
//! constructed (de)compressor (built untimed in setup) so the zlib stream history does
//! not accumulate across iterations and skew the per-packet cost. Throughput is reported
//! per *original* (uncompressed) byte.

use std::hint::black_box;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rand_chacha::ChaCha8Rng;
use ssh_transport::algo::COMPRESSION_ZLIB_OPENSSH;
use ssh_transport::compress::{Compressor, Decompressor};
use ssh_transport::rand_core::{RngCore, SeedableRng};

const SIZES: &[usize] = &[1024, 8192, 32768];

/// Repetitive, text-like data (compresses well).
fn compressible(n: usize) -> Vec<u8> {
    let pat = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n";
    pat.iter().copied().cycle().take(n).collect()
}

/// Random data (does not compress).
fn incompressible(n: usize) -> Vec<u8> {
    let mut rng = ChaCha8Rng::seed_from_u64(0xC0FFEE);
    let mut v = vec![0u8; n];
    rng.fill_bytes(&mut v);
    v
}

/// A named payload generator: a label and a function producing `n` bytes.
type Profile = (&'static str, fn(usize) -> Vec<u8>);

const PROFILES: &[Profile] = &[("text", compressible), ("random", incompressible)];

fn bench_compress(c: &mut Criterion) {
    for &(profile, make) in PROFILES {
        let mut group = c.benchmark_group(format!("compress/{profile}"));
        for &size in SIZES {
            let payload = make(size);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(size), &payload, |b, p| {
                b.iter_batched_ref(
                    || Compressor::new(COMPRESSION_ZLIB_OPENSSH),
                    |comp| black_box(comp.compress(black_box(p))),
                    BatchSize::SmallInput,
                );
            });
        }
        group.finish();
    }
}

fn bench_decompress(c: &mut Criterion) {
    for &(profile, make) in PROFILES {
        let mut group = c.benchmark_group(format!("decompress/{profile}"));
        for &size in SIZES {
            let payload = make(size);
            // First-packet compressed form, decodable by a fresh decompressor.
            let compressed = Compressor::new(COMPRESSION_ZLIB_OPENSSH).compress(&payload);
            group.throughput(Throughput::Bytes(size as u64));
            group.bench_with_input(BenchmarkId::from_parameter(size), &compressed, |b, comp| {
                b.iter_batched_ref(
                    || Decompressor::new(COMPRESSION_ZLIB_OPENSSH),
                    |d| black_box(d.decompress(black_box(&comp[..])).unwrap()),
                    BatchSize::SmallInput,
                );
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench_compress, bench_decompress);
criterion_main!(benches);
