//! Fuzz zlib decompression: malformed/hostile compressed input must error or stay within
//! the size bound, never panic, hang, or allocate without limit (decompression bombs).
#![no_main]

use libfuzzer_sys::fuzz_target;
use ssh_transport::algo::COMPRESSION_ZLIB_OPENSSH;
use ssh_transport::compress::Decompressor;

fuzz_target!(|data: &[u8]| {
    let mut d = Decompressor::new(COMPRESSION_ZLIB_OPENSSH);
    let _ = d.decompress(data);
});
