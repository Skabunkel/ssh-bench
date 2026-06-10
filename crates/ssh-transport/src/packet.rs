//! Binary Packet Protocol framing, RFC 4253 §6.
//!
//! ```text
//! uint32    packet_length   (length of the rest, excluding the MAC)
//! byte      padding_length
//! byte[n1]  payload         (n1 = packet_length - padding_length - 1)
//! byte[n2]  random padding  (n2 = padding_length)
//! byte[m]   mac             (only once a MAC/AEAD is in effect)
//! ```
//!
//! This module handles the unencrypted framing used before `NEWKEYS`. The encrypted
//! AEAD framing (chacha20-poly1305) is layered on top in the cipher module during M1.

use rand_core::RngCore;

use crate::{Result, SshError};

/// Minimum padding length (RFC 4253 §6).
pub const MIN_PADDING: usize = 4;
/// Minimum total packet size including the length field (RFC 4253 §6).
pub const MIN_PACKET: usize = 16;
/// Block size used to align unencrypted packets ("none" cipher): 8.
const BLOCK: usize = 8;
/// Defensive upper bound on `packet_length` to bound memory use.
pub const MAX_PACKET_LENGTH: usize = 1024 * 1024;

/// Compute the padding length for a payload so the whole packet is a multiple of
/// `block` (>= 8), padding is >= 4, and the total is >= 16.
pub(crate) fn padding_len(payload_len: usize, block: usize) -> usize {
    let block = block.max(BLOCK);
    let unpadded = 4 + 1 + payload_len;
    let mut pad = block - (unpadded % block);
    if pad < MIN_PADDING {
        pad += block;
    }
    while 4 + 1 + payload_len + pad < MIN_PACKET {
        pad += block;
    }
    pad
}

/// Encode `payload` into an unencrypted binary packet, drawing random padding from `rng`.
pub fn encode_plain(payload: &[u8], rng: &mut impl RngCore) -> Vec<u8> {
    let pad = padding_len(payload.len(), BLOCK);
    let packet_length = 1 + payload.len() + pad;
    let mut out = Vec::with_capacity(4 + packet_length);
    out.extend_from_slice(&(packet_length as u32).to_be_bytes());
    out.push(pad as u8);
    out.extend_from_slice(payload);
    let pad_start = out.len();
    out.resize(pad_start + pad, 0);
    rng.fill_bytes(&mut out[pad_start..]);
    out
}

/// Try to decode one unencrypted packet from the front of `buf`.
///
/// Returns `Ok(Some((payload, consumed)))` when a whole packet is present (drain
/// `consumed` bytes), `Ok(None)` when more bytes are required, or an error for a
/// malformed packet.
pub fn decode_plain(buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let packet_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if !(MIN_PACKET - 4..=MAX_PACKET_LENGTH).contains(&packet_length) {
        return Err(SshError::BadPacket("packet_length out of range"));
    }
    let total = 4 + packet_length;
    if buf.len() < total {
        return Ok(None);
    }
    let padding_length = buf[4] as usize;
    if padding_length < MIN_PADDING || padding_length + 1 > packet_length {
        return Err(SshError::BadPacket("invalid padding_length"));
    }
    let payload_len = packet_length - padding_length - 1;
    let payload = buf[5..5 + payload_len].to_vec();
    Ok(Some((payload, total)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(0xA5A5)
    }

    #[test]
    fn padding_keeps_packet_block_aligned_and_minimum() {
        for payload_len in 0..64usize {
            let pad = padding_len(payload_len, BLOCK);
            let total = 4 + 1 + payload_len + pad;
            assert_eq!(total % BLOCK, 0, "not block aligned for {payload_len}");
            assert!(pad >= MIN_PADDING);
            assert!(total >= MIN_PACKET);
        }
    }

    #[test]
    fn roundtrip_small_and_large() {
        let mut rng = rng();
        for payload in [
            vec![],
            vec![20u8],
            b"the quick brown fox".to_vec(),
            vec![7u8; 5000],
        ] {
            let frame = encode_plain(&payload, &mut rng);
            let (decoded, consumed) = decode_plain(&frame).unwrap().unwrap();
            assert_eq!(decoded, payload);
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn decode_needs_more_bytes() {
        let mut rng = rng();
        let frame = encode_plain(b"hello", &mut rng);
        assert_eq!(decode_plain(&frame[..3]).unwrap(), None);
        assert_eq!(decode_plain(&frame[..frame.len() - 1]).unwrap(), None);
    }

    #[test]
    fn decode_reports_trailing_bytes_via_consumed() {
        let mut rng = rng();
        let mut frame = encode_plain(b"hello", &mut rng);
        let original_len = frame.len();
        frame.extend_from_slice(b"next-packet-bytes");
        let (decoded, consumed) = decode_plain(&frame).unwrap().unwrap();
        assert_eq!(decoded, b"hello");
        assert_eq!(consumed, original_len);
    }

    #[test]
    fn rejects_bad_padding_length() {
        // packet_length = 12, padding_length = 1 (< MIN_PADDING)
        let mut buf = vec![0, 0, 0, 12, 1];
        buf.extend_from_slice(&[0u8; 11]);
        assert!(matches!(decode_plain(&buf), Err(SshError::BadPacket(_))));
    }

    #[test]
    fn rejects_oversize_packet_length() {
        let buf = (MAX_PACKET_LENGTH as u32 + 1).to_be_bytes().to_vec();
        assert!(matches!(decode_plain(&buf), Err(SshError::BadPacket(_))));
    }
}
