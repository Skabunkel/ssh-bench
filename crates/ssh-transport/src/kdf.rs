//! Exchange-hash computation and key derivation for `curve25519-sha256`
//! (RFC 4253 §7.2, RFC 8731). The hash is SHA-256.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::wire::Writer;

/// Inputs to the exchange hash `H`.
pub struct ExchangeHashInput<'a> {
    /// `V_C` — client identification string (no CR LF).
    pub client_id: &'a [u8],
    /// `V_S` — server identification string (no CR LF).
    pub server_id: &'a [u8],
    /// `I_C` — client's KEXINIT payload.
    pub client_kexinit: &'a [u8],
    /// `I_S` — server's KEXINIT payload.
    pub server_kexinit: &'a [u8],
    /// `K_S` — server host key blob.
    pub host_key_blob: &'a [u8],
    /// `Q_C` — client ephemeral public value.
    pub client_ephemeral: &'a [u8],
    /// `Q_S` — server ephemeral public value.
    pub server_ephemeral: &'a [u8],
    /// `K` — shared secret, as unsigned big-endian magnitude.
    pub shared_secret: &'a [u8],
}

/// Compute the exchange hash `H = SHA256(V_C ‖ V_S ‖ I_C ‖ I_S ‖ K_S ‖ Q_C ‖ Q_S ‖ K)`
/// where every component is SSH-encoded (`string` for all but `K`, which is `mpint`).
pub fn exchange_hash(input: &ExchangeHashInput<'_>) -> [u8; 32] {
    let mut w = Writer::new();
    w.string(input.client_id);
    w.string(input.server_id);
    w.string(input.client_kexinit);
    w.string(input.server_kexinit);
    w.string(input.host_key_blob);
    w.string(input.client_ephemeral);
    w.string(input.server_ephemeral);
    w.mpint(input.shared_secret);
    let h = Sha256::digest(w.as_slice()).into();
    // The hash input ends with the shared secret K; scrub the buffer before it is freed.
    w.into_bytes().zeroize();
    h
}

/// The directional keys/IVs derived from a completed key exchange. `chacha20-poly1305`
/// uses only the encryption keys (IVs derived with length 0); `aes256-gcm` uses both.
/// The key bytes are scrubbed once the `Keys` are dropped (after the ciphers copy them).
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Keys {
    /// Initial IV, client-to-server (letter `A`).
    pub iv_c2s: Vec<u8>,
    /// Initial IV, server-to-client (letter `B`).
    pub iv_s2c: Vec<u8>,
    /// Encryption key, client-to-server (letter `C`).
    pub enc_c2s: Vec<u8>,
    /// Encryption key, server-to-client (letter `D`).
    pub enc_s2c: Vec<u8>,
}

impl Keys {
    /// Derive `key_len` encryption-key bytes and `iv_len` IV bytes per direction.
    pub fn derive(
        shared_secret: &[u8],
        h: &[u8; 32],
        session_id: &[u8],
        key_len: usize,
        iv_len: usize,
    ) -> Self {
        let mut k_mpint = mpint_bytes(shared_secret);
        let keys = Self {
            iv_c2s: derive_key(&k_mpint, h, b'A', session_id, iv_len),
            iv_s2c: derive_key(&k_mpint, h, b'B', session_id, iv_len),
            enc_c2s: derive_key(&k_mpint, h, b'C', session_id, key_len),
            enc_s2c: derive_key(&k_mpint, h, b'D', session_id, key_len),
        };
        // `k_mpint` holds the shared secret K; scrub it now that derivation is done.
        k_mpint.zeroize();
        keys
    }
}

/// `K1 = HASH(K ‖ H ‖ X ‖ session_id)`, then `K_{n+1} = HASH(K ‖ H ‖ K1 ‖ .. ‖ Kn)`,
/// concatenated and truncated to `out_len`.
fn derive_key(
    k_mpint: &[u8],
    h: &[u8; 32],
    letter: u8,
    session_id: &[u8],
    out_len: usize,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(out_len);

    let mut first = Sha256::new();
    first.update(k_mpint);
    first.update(h);
    first.update([letter]);
    first.update(session_id);
    out.extend_from_slice(&first.finalize());

    while out.len() < out_len {
        let mut next = Sha256::new();
        next.update(k_mpint);
        next.update(h);
        next.update(&out);
        out.extend_from_slice(&next.finalize());
    }
    out.truncate(out_len);
    out
}

/// Encode an unsigned big-endian magnitude as an SSH `mpint` (sign byte + trimmed).
fn mpint_bytes(magnitude: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.mpint(magnitude);
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_produces_requested_length_with_extension() {
        // 64 bytes needs the chained extension (two SHA-256 blocks).
        let keys = Keys::derive(&[0x42u8; 32], &[0x11u8; 32], &[0x33u8; 32], 64, 12);
        assert_eq!(keys.enc_c2s.len(), 64);
        assert_eq!(keys.enc_s2c.len(), 64);
        assert_eq!(keys.iv_c2s.len(), 12);
        // Different letters must give different material.
        assert_ne!(keys.enc_c2s, keys.enc_s2c);
        assert_ne!(keys.iv_c2s, keys.iv_s2c);
    }

    #[test]
    fn derive_is_deterministic() {
        let a = Keys::derive(&[1u8; 32], &[2u8; 32], &[3u8; 32], 64, 0);
        let b = Keys::derive(&[1u8; 32], &[2u8; 32], &[3u8; 32], 64, 0);
        assert_eq!(a.enc_c2s, b.enc_c2s);
    }

    #[test]
    fn exchange_hash_changes_with_inputs() {
        let base = ExchangeHashInput {
            client_id: b"SSH-2.0-a",
            server_id: b"SSH-2.0-b",
            client_kexinit: b"ic",
            server_kexinit: b"is",
            host_key_blob: b"ks",
            client_ephemeral: &[1u8; 32],
            server_ephemeral: &[2u8; 32],
            shared_secret: &[3u8; 32],
        };
        let h1 = exchange_hash(&base);
        let other = ExchangeHashInput {
            shared_secret: &[4u8; 32],
            ..base
        };
        let h2 = exchange_hash(&other);
        assert_ne!(h1, h2);
    }
}
