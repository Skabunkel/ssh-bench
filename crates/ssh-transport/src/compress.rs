//! Payload compression (RFC 4253 §6.2). Only `zlib@openssh.com` is implemented: a
//! continuous zlib (RFC 1950) stream whose history carries across packets, with a sync
//! flush after each packet so the receiver can recover it immediately. The context is
//! reset on every key exchange (handled by the transport).
//!
//! `zlib@openssh.com` is *delayed*: compression engages only once authentication has
//! succeeded, so the auth exchange itself is never compressed (avoiding CRIME-style
//! length leaks). The activation point is driven by the transport.
//!
//! Decompression output is bounded to [`MAX_PACKET_LENGTH`] so a small compressed payload
//! cannot expand into a memory-exhausting "decompression bomb".

use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};

use crate::algo::COMPRESSION_ZLIB_OPENSSH;
use crate::packet::MAX_PACKET_LENGTH;
use crate::{Result, SshError};

/// Outbound compression state for one direction.
pub enum Compressor {
    /// No compression: payloads pass through unchanged.
    None,
    /// `zlib@openssh.com`: a continuous zlib deflate stream.
    Zlib(Box<Compress>),
}

/// Inbound decompression state for one direction.
pub enum Decompressor {
    None,
    Zlib(Box<Decompress>),
}

impl Compressor {
    /// Build from a negotiated compression name. Unknown names fall back to `None`.
    pub fn new(name: &str) -> Self {
        match name {
            COMPRESSION_ZLIB_OPENSSH => {
                Compressor::Zlib(Box::new(Compress::new(Compression::default(), true)))
            }
            _ => Compressor::None,
        }
    }

    /// Compress one packet payload, flushing so the peer can decompress it immediately.
    pub fn compress(&mut self, payload: &[u8]) -> Vec<u8> {
        match self {
            Compressor::None => payload.to_vec(),
            Compressor::Zlib(c) => {
                let start_in = c.total_in();
                let mut out = Vec::with_capacity(64 + payload.len());
                loop {
                    if out.len() == out.capacity() {
                        out.reserve(out.capacity().max(128));
                    }
                    let cap = out.capacity();
                    let in_before = c.total_in();
                    let out_before = c.total_out();
                    let consumed = (in_before - start_in) as usize;
                    // `compress_vec` writes into the Vec's spare capacity (ensured above)
                    // and never fails for in-memory buffers.
                    let _ = c
                        .compress_vec(&payload[consumed..], &mut out, FlushCompress::Sync)
                        .expect("zlib compress");
                    let consumed_all = (c.total_in() - start_in) as usize == payload.len();
                    let no_progress = c.total_in() == in_before && c.total_out() == out_before;
                    // A sync flush is complete once deflate leaves spare output room (it
                    // did not fill the whole buffer); calling again would emit a *new*
                    // redundant sync marker, so we must stop here. `no_progress` guards
                    // against any pathological stall.
                    if (consumed_all && out.len() < cap) || no_progress {
                        break;
                    }
                }
                out
            }
        }
    }
}

impl Decompressor {
    /// Build from a negotiated compression name. Unknown names fall back to `None`.
    pub fn new(name: &str) -> Self {
        match name {
            COMPRESSION_ZLIB_OPENSSH => Decompressor::Zlib(Box::new(Decompress::new(true))),
            _ => Decompressor::None,
        }
    }

    /// Decompress one packet payload, bounding the output to [`MAX_PACKET_LENGTH`].
    pub fn decompress(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        match self {
            Decompressor::None => Ok(payload.to_vec()),
            Decompressor::Zlib(d) => {
                let start_in = d.total_in();
                let mut out = Vec::with_capacity(64 + payload.len() * 2);
                loop {
                    if out.len() == out.capacity() {
                        out.reserve(out.capacity().max(64));
                    }
                    let out_before = d.total_out();
                    let consumed = (d.total_in() - start_in) as usize;
                    let status = d
                        .decompress_vec(&payload[consumed..], &mut out, FlushDecompress::Sync)
                        .map_err(|_| SshError::Compression("malformed compressed payload"))?;
                    if out.len() > MAX_PACKET_LENGTH {
                        return Err(SshError::Compression("decompressed payload too large"));
                    }
                    let consumed_all = (d.total_in() - start_in) as usize == payload.len();
                    let produced = d.total_out() - out_before;
                    if status == Status::StreamEnd || (consumed_all && produced == 0) {
                        break;
                    }
                }
                Ok(out)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::algo::COMPRESSION_NONE;

    #[test]
    fn roundtrip_across_packets_with_shared_history() {
        let mut c = Compressor::new(COMPRESSION_ZLIB_OPENSSH);
        let mut d = Decompressor::new(COMPRESSION_ZLIB_OPENSSH);
        // The stream history persists across packets, so repeated content in a later
        // packet should still decompress correctly.
        for payload in [
            b"GET /index.html HTTP/1.1\r\n".to_vec(),
            b"GET /index.html HTTP/1.1\r\n".to_vec(),
            vec![0xABu8; 4096],
            b"".to_vec(),
            b"final".to_vec(),
        ] {
            let comp = c.compress(&payload);
            let back = d.decompress(&comp).unwrap();
            assert_eq!(back, payload);
        }
    }

    #[test]
    fn compresses_repetitive_data() {
        let mut c = Compressor::new(COMPRESSION_ZLIB_OPENSSH);
        let payload = vec![0x5Au8; 8192];
        let comp = c.compress(&payload);
        assert!(comp.len() < payload.len() / 4, "repetitive data should shrink");
    }

    #[test]
    fn none_is_passthrough() {
        let mut c = Compressor::new(COMPRESSION_NONE);
        let mut d = Decompressor::new(COMPRESSION_NONE);
        let payload = b"unchanged".to_vec();
        assert_eq!(c.compress(&payload), payload);
        assert_eq!(d.decompress(&payload).unwrap(), payload);
    }

    #[test]
    fn rejects_garbage_compressed_input() {
        let mut d = Decompressor::new(COMPRESSION_ZLIB_OPENSSH);
        assert!(matches!(
            d.decompress(&[0xff, 0x00, 0x13, 0x37, 0x42]),
            Err(SshError::Compression(_))
        ));
    }

    #[test]
    fn decompression_bomb_is_rejected() {
        // A few KiB of compressed data that expands to many MiB is the classic zip-bomb.
        // Decompression must refuse it once the output passes MAX_PACKET_LENGTH instead of
        // allocating without bound.
        let mut c = Compressor::new(COMPRESSION_ZLIB_OPENSSH);
        let huge = vec![0u8; MAX_PACKET_LENGTH * 4]; // 4 MiB of zeros
        let bomb = c.compress(&huge);
        assert!(
            bomb.len() < 16 * 1024,
            "bomb should be tiny relative to its expansion ({} bytes)",
            bomb.len()
        );

        let mut d = Decompressor::new(COMPRESSION_ZLIB_OPENSSH);
        match d.decompress(&bomb) {
            Err(SshError::Compression(_)) => {}
            other => panic!("oversized decompression must be rejected, got {other:?}"),
        }
    }
}
