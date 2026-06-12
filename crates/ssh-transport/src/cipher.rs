//! Packet ciphers. The active cipher changes at `NEWKEYS`, so the set of ciphers is a
//! runtime [`Cipher`] enum (matched, never `dyn`) rather than a generic parameter.
//!
//! Before key exchange completes, [`Cipher::None`] performs the plaintext framing from
//! [`crate::packet`]. After `NEWKEYS`, [`Cipher::ChaCha20Poly1305`] implements
//! `chacha20-poly1305@openssh.com` (OpenSSH `PROTOCOL.chacha20poly1305`):
//!
//! * 64 bytes of key material: `K_2 = key[0..32]` (payload), `K_1 = key[32..64]` (length).
//! * The 4-byte packet length is encrypted with `K_1` (ChaCha20-Legacy, counter 0).
//! * The Poly1305 key is the first 32 bytes of the `K_2` keystream at counter 0; the
//!   payload is encrypted with `K_2` from counter 1 (byte offset 64).
//! * The Poly1305 tag authenticates `encrypted_length ‖ encrypted_payload` and is appended.

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit as _};
use chacha20::ChaCha20Legacy;
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use rand_core::RngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::algo::{CIPHER_AES256_GCM, CIPHER_CHACHA20_POLY1305};
use crate::packet::{self, MAX_PACKET_LENGTH, MIN_PADDING};
use crate::{Result, SshError};

/// Length of the AEAD authentication tag (both ciphers use 16).
const TAG_LEN: usize = 16;
/// Block-alignment size for chacha20-poly1305's padded region.
const CHACHA_BLOCK: usize = 8;
/// Block-alignment size for aes256-gcm's padded region.
const GCM_BLOCK: usize = 16;

/// Padding length for an AEAD packet: the 4-byte packet-length field is not part of the
/// block-aligned region, so `padding_length ‖ payload ‖ padding` (`packet_length`) must
/// be a multiple of `block`, with padding >= 4.
fn aead_padding_len(payload_len: usize, block: usize) -> usize {
    let unpadded = 1 + payload_len; // padding_length byte + payload
    let mut pad = block - (unpadded % block);
    if pad < MIN_PADDING {
        pad += block;
    }
    pad
}

/// An active packet cipher for one direction. The key material is scrubbed from memory
/// when the cipher is dropped (at `NEWKEYS`/rekey and when the connection ends).
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum Cipher {
    /// Plaintext framing used before `NEWKEYS`.
    None,
    /// `chacha20-poly1305@openssh.com`.
    ChaCha20Poly1305 { k2: [u8; 32], k1: [u8; 32] },
    /// `aes256-gcm@openssh.com`. `iv` holds the current 12-byte nonce whose trailing
    /// 8-byte invocation counter increments after each packet (OpenSSH `PROTOCOL`).
    Aes256Gcm { key: [u8; 32], iv: [u8; 12] },
}

impl Cipher {
    /// Bytes of encryption-key material a named cipher consumes from the KDF.
    pub fn key_len(name: &str) -> Result<usize> {
        match name {
            CIPHER_CHACHA20_POLY1305 => Ok(64),
            CIPHER_AES256_GCM => Ok(32),
            _ => Err(SshError::NoCommonAlgorithm("cipher")),
        }
    }

    /// Bytes of IV material a named cipher consumes from the KDF.
    pub fn iv_len(name: &str) -> Result<usize> {
        match name {
            CIPHER_CHACHA20_POLY1305 => Ok(0),
            CIPHER_AES256_GCM => Ok(12),
            _ => Err(SshError::NoCommonAlgorithm("cipher")),
        }
    }

    /// Construct a cipher from its negotiated name and derived key/IV material.
    pub fn new(name: &str, key: &[u8], iv: &[u8]) -> Result<Self> {
        match name {
            CIPHER_CHACHA20_POLY1305 => {
                if key.len() != 64 {
                    return Err(SshError::Kex("chacha20-poly1305 needs 64 key bytes"));
                }
                let mut k2 = [0u8; 32];
                let mut k1 = [0u8; 32];
                k2.copy_from_slice(&key[0..32]);
                k1.copy_from_slice(&key[32..64]);
                Ok(Cipher::ChaCha20Poly1305 { k2, k1 })
            }
            CIPHER_AES256_GCM => {
                if key.len() != 32 || iv.len() != 12 {
                    return Err(SshError::Kex("aes256-gcm needs 32 key + 12 IV bytes"));
                }
                let mut k = [0u8; 32];
                let mut v = [0u8; 12];
                k.copy_from_slice(key);
                v.copy_from_slice(iv);
                Ok(Cipher::Aes256Gcm { key: k, iv: v })
            }
            _ => Err(SshError::NoCommonAlgorithm("cipher")),
        }
    }

    /// Encrypt `payload` into a complete on-wire packet for sequence number `seqnr`.
    pub fn seal(&mut self, seqnr: u32, payload: &[u8], rng: &mut impl RngCore) -> Vec<u8> {
        match self {
            Cipher::None => packet::encode_plain(payload, rng),
            Cipher::Aes256Gcm { key, iv } => gcm_seal(key, iv, payload, rng),
            Cipher::ChaCha20Poly1305 { k2, k1 } => {
                let pad = aead_padding_len(payload.len(), CHACHA_BLOCK);
                let packet_length = (1 + payload.len() + pad) as u32;

                // payload region = padding_length ‖ payload ‖ random padding
                let mut region = Vec::with_capacity(packet_length as usize);
                region.push(pad as u8);
                region.extend_from_slice(payload);
                let pad_start = region.len();
                region.resize(pad_start + pad, 0);
                rng.fill_bytes(&mut region[pad_start..]);

                let mut out = Vec::with_capacity(4 + region.len() + TAG_LEN);

                // Encrypt the 4-byte length with K_1.
                let mut len_bytes = packet_length.to_be_bytes();
                length_cipher(k1, seqnr).apply_keystream(&mut len_bytes);
                out.extend_from_slice(&len_bytes);

                // Encrypt the payload region with K_2 (counter 1) and derive the poly key.
                let (poly_key, mut main) = payload_cipher(k2, seqnr);
                main.apply_keystream(&mut region);
                out.extend_from_slice(&region);

                let tag = poly1305_tag(&poly_key, &out);
                out.extend_from_slice(&tag);
                out
            }
        }
    }

    /// Try to decrypt one packet from the front of `buf`. The returned plaintext is held
    /// in a [`Zeroizing`] buffer so it is scrubbed from memory once dropped.
    pub fn open(&mut self, seqnr: u32, buf: &[u8]) -> Result<Option<(Zeroizing<Vec<u8>>, usize)>> {
        match self {
            // Pre-NEWKEYS framing carries no secrets, but wrap it for a uniform type.
            Cipher::None => Ok(packet::decode_plain(buf)?.map(|(p, n)| (Zeroizing::new(p), n))),
            Cipher::Aes256Gcm { key, iv } => gcm_open(key, iv, buf),
            Cipher::ChaCha20Poly1305 { k2, k1 } => {
                if buf.len() < 4 {
                    return Ok(None);
                }
                // Decrypt the length with K_1 to learn how many bytes to expect.
                let mut len_bytes = [buf[0], buf[1], buf[2], buf[3]];
                length_cipher(k1, seqnr).apply_keystream(&mut len_bytes);
                let packet_length = u32::from_be_bytes(len_bytes) as usize;
                // The AEAD region must be a positive multiple of the block size.
                if packet_length < CHACHA_BLOCK
                    || !packet_length.is_multiple_of(CHACHA_BLOCK)
                    || packet_length > MAX_PACKET_LENGTH
                {
                    return Err(SshError::BadPacket("packet_length out of range"));
                }

                let total = 4 + packet_length + TAG_LEN;
                if buf.len() < total {
                    return Ok(None);
                }

                // Authenticate encrypted_length ‖ encrypted_payload before decrypting.
                let (poly_key, mut main) = payload_cipher(k2, seqnr);
                let tag = poly1305_tag(&poly_key, &buf[..4 + packet_length]);
                let received = &buf[4 + packet_length..total];
                if tag.ct_eq(received).unwrap_u8() != 1 {
                    return Err(SshError::Integrity);
                }

                // Decrypt the payload region. Held in `Zeroizing` so the decrypted bytes
                // (which may include credentials) are wiped on every exit path.
                let mut region = Zeroizing::new(buf[4..4 + packet_length].to_vec());
                main.apply_keystream(region.as_mut_slice());

                let padding_length = region[0] as usize;
                if padding_length < MIN_PADDING || padding_length + 1 > packet_length {
                    return Err(SshError::BadPacket("invalid padding_length"));
                }
                let payload = region[1..packet_length - padding_length].to_vec();
                Ok(Some((Zeroizing::new(payload), total)))
            }
        }
    }
}

/// ChaCha20-Legacy instance keyed by `K_1` for the length field (counter 0).
fn length_cipher(k1: &[u8; 32], seqnr: u32) -> ChaCha20Legacy {
    ChaCha20Legacy::new(k1.into(), &nonce(seqnr).into())
}

/// Returns the Poly1305 key (block-0 keystream) and a `K_2` cipher positioned at
/// counter 1 (byte offset 64) ready to encrypt/decrypt the payload region. The one-time
/// MAC key is held in a [`Zeroizing`] buffer so it is scrubbed from memory on drop.
fn payload_cipher(k2: &[u8; 32], seqnr: u32) -> (Zeroizing<[u8; 32]>, ChaCha20Legacy) {
    let mut cipher = ChaCha20Legacy::new(k2.into(), &nonce(seqnr).into());
    let mut poly_key = Zeroizing::new([0u8; 32]);
    cipher.apply_keystream(poly_key.as_mut_slice());
    cipher.seek(64u64);
    (poly_key, cipher)
}

fn poly1305_tag(key: &[u8; 32], data: &[u8]) -> [u8; TAG_LEN] {
    let mac = Poly1305::new(key.into());
    mac.compute_unpadded(data).into()
}

/// The 8-byte nonce: the packet sequence number as a big-endian `uint64`.
fn nonce(seqnr: u32) -> [u8; 8] {
    (seqnr as u64).to_be_bytes()
}

// --- aes256-gcm@openssh.com (RFC 5647 framing) ---
//
// The 4-byte packet length is sent in cleartext and authenticated as AAD; the rest
// (padding_length ‖ payload ‖ padding) is encrypted. The 12-byte IV's trailing 8 bytes
// are an invocation counter incremented after every packet.

fn gcm_seal(key: &[u8; 32], iv: &mut [u8; 12], payload: &[u8], rng: &mut impl RngCore) -> Vec<u8> {
    let pad = aead_padding_len(payload.len(), GCM_BLOCK);
    let packet_length = (1 + payload.len() + pad) as u32;

    let mut region = Vec::with_capacity(packet_length as usize);
    region.push(pad as u8);
    region.extend_from_slice(payload);
    let pad_start = region.len();
    region.resize(pad_start + pad, 0);
    rng.fill_bytes(&mut region[pad_start..]);

    let aad = packet_length.to_be_bytes();
    let cipher = Aes256Gcm::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(iv.as_ref().into(), &aad, &mut region)
        .expect("aes-gcm encryption");

    gcm_increment(iv);

    let mut out = Vec::with_capacity(4 + region.len() + TAG_LEN);
    out.extend_from_slice(&aad);
    out.extend_from_slice(&region);
    out.extend_from_slice(&tag);
    out
}

fn gcm_open(
    key: &[u8; 32],
    iv: &mut [u8; 12],
    buf: &[u8],
) -> Result<Option<(Zeroizing<Vec<u8>>, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let packet_length = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if packet_length < GCM_BLOCK
        || !packet_length.is_multiple_of(GCM_BLOCK)
        || packet_length > MAX_PACKET_LENGTH
    {
        return Err(SshError::BadPacket("packet_length out of range"));
    }
    let total = 4 + packet_length + TAG_LEN;
    if buf.len() < total {
        return Ok(None);
    }

    let aad = &buf[0..4];
    // Held in `Zeroizing` so the decrypted plaintext is wiped on every exit path.
    let mut region = Zeroizing::new(buf[4..4 + packet_length].to_vec());
    let tag = &buf[4 + packet_length..total];

    let cipher = Aes256Gcm::new(key.into());
    cipher
        .decrypt_in_place_detached(iv.as_ref().into(), aad, region.as_mut_slice(), tag.into())
        .map_err(|_| SshError::Integrity)?;

    gcm_increment(iv);

    let padding_length = region[0] as usize;
    if padding_length < MIN_PADDING || padding_length + 1 > packet_length {
        return Err(SshError::BadPacket("invalid padding_length"));
    }
    let payload = region[1..packet_length - padding_length].to_vec();
    Ok(Some((Zeroizing::new(payload), total)))
}

/// Increment the trailing 8-byte big-endian invocation counter of a gcm IV.
fn gcm_increment(iv: &mut [u8; 12]) {
    let counter = u64::from_be_bytes(iv[4..12].try_into().unwrap()).wrapping_add(1);
    iv[4..12].copy_from_slice(&counter.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn cipher() -> Cipher {
        let key: Vec<u8> = (0..64u8).collect();
        Cipher::new(CIPHER_CHACHA20_POLY1305, &key, &[]).unwrap()
    }

    fn gcm() -> Cipher {
        let key: Vec<u8> = (0..32u8).collect();
        let iv: Vec<u8> = (0..12u8).collect();
        Cipher::new(CIPHER_AES256_GCM, &key, &iv).unwrap()
    }

    #[test]
    fn seal_open_roundtrip() {
        let mut rng = ChaCha8Rng::seed_from_u64(99);
        let mut c = cipher();
        for (seqnr, payload) in [
            (0u32, vec![]),
            (1, b"hello world".to_vec()),
            (2, vec![0xABu8; 3000]),
        ] {
            let frame = c.seal(seqnr, &payload, &mut rng);
            let (out, consumed) = c.open(seqnr, &frame).unwrap().unwrap();
            assert_eq!(*out, payload);
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn gcm_seal_open_roundtrip() {
        // Separate instances (like cipher_out/cipher_in) so their IV counters advance
        // in lockstep, matching how a real connection is keyed.
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let mut tx = gcm();
        let mut rx = gcm();
        for (seqnr, payload) in [
            (0u32, vec![]),
            (1, b"gcm payload".to_vec()),
            (2, vec![7u8; 5000]),
        ] {
            let frame = tx.seal(seqnr, &payload, &mut rng);
            let (out, consumed) = rx.open(seqnr, &frame).unwrap().unwrap();
            assert_eq!(*out, payload);
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn gcm_tampered_fails_integrity() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let mut tx = gcm();
        let mut rx = gcm();
        let mut frame = tx.seal(0, b"important", &mut rng);
        let i = frame.len() / 2;
        frame[i] ^= 0x01;
        assert!(matches!(rx.open(0, &frame), Err(SshError::Integrity)));
    }

    #[test]
    fn wrong_sequence_number_is_rejected() {
        // Opening with the wrong seqnr corrupts the length decryption (caught as a bad
        // packet) and/or fails the MAC — either way it must be rejected.
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let mut c = cipher();
        let frame = c.seal(5, b"data", &mut rng);
        assert!(c.open(6, &frame).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails_integrity() {
        let mut rng = ChaCha8Rng::seed_from_u64(8);
        let mut c = cipher();
        let mut frame = c.seal(0, b"important", &mut rng);
        let i = frame.len() / 2;
        frame[i] ^= 0x01;
        assert!(matches!(c.open(0, &frame), Err(SshError::Integrity)));
    }

    #[test]
    fn open_needs_more_bytes() {
        let mut rng = ChaCha8Rng::seed_from_u64(9);
        let mut c = cipher();
        let frame = c.seal(0, b"partial", &mut rng);
        assert_eq!(c.open(0, &frame[..2]).unwrap(), None);
        assert_eq!(c.open(0, &frame[..frame.len() - 1]).unwrap(), None);
    }
}
