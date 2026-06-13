//! `sntrup761x25519-sha512@openssh.com` post-quantum / classical hybrid key exchange, as
//! deployed by OpenSSH ≥ 8.5 (its default before `mlkem768x25519-sha256`).
//!
//! Structurally identical to [`crate::mlkem`], but built on Streamlined NTRU Prime
//! (sntrup761) instead of ML-KEM-768 and bound with **SHA-512** rather than SHA-256:
//!
//! ```text
//! K = SHA512(K_pq ‖ K_x25519)
//! ```
//!
//! `K` (64 bytes) feeds the exchange hash and key derivation as an SSH `string` (see
//! [`crate::kdf::SharedSecret`] and [`crate::kdf::KexHash`]). The wire blobs reuse the
//! `SSH_MSG_KEX_ECDH_INIT` / `SSH_MSG_KEX_ECDH_REPLY` carriers:
//!
//! * client → server (`C_INIT`): sntrup761 public key ‖ client X25519 public value
//! * server → client (`S_REPLY`): sntrup761 ciphertext ‖ server X25519 public value
//!
//! sntrup761 randomness is supplied from the transport's own CSPRNG via the crate's
//! deterministic entry points (seed-based keygen and encapsulation), keeping a single RNG
//! source and avoiding a second `rand_core` major in the hot path — the same approach as
//! [`crate::mlkem`].

use sha2::{Digest, Sha512};
use sntrup761::{Ciphertext, DecapsulationKey, EncapsulationKey, generate_key_from_seed};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::kex::EcdhKeypair;
use crate::{Result, SshError};

/// Negotiated name for the hybrid method.
pub const KEX_SNTRUP761_X25519: &str = "sntrup761x25519-sha512@openssh.com";

/// sntrup761 public-key length.
const SNTRUP_PK_LEN: usize = 1158;
/// sntrup761 ciphertext length.
const SNTRUP_CT_LEN: usize = 1039;
/// X25519 public-value length.
const X25519_LEN: usize = 32;

/// Length of the client's `C_INIT` blob: sntrup761 public key followed by the client's
/// X25519 public value.
pub const CLIENT_INIT_LEN: usize = SNTRUP_PK_LEN + X25519_LEN;
/// Length of the server's `S_REPLY` blob: sntrup761 ciphertext followed by the server's
/// X25519 public value.
pub const SERVER_REPLY_LEN: usize = SNTRUP_CT_LEN + X25519_LEN;

/// `K = SHA512(K_pq ‖ K_x25519)`. The sntrup761 secret is hashed first, matching the
/// order fixed by OpenSSH. The inputs scrub themselves on drop (the sntrup761 shared
/// secret is `ZeroizeOnDrop`; the X25519 one is held in `Zeroizing`).
fn combine(k_pq: &[u8], k_x25519: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut h = Sha512::new();
    h.update(k_pq);
    h.update(k_x25519);
    Zeroizing::new(h.finalize().to_vec())
}

/// Client-side hybrid state, held between `C_INIT` and the server's `S_REPLY`. Owns the
/// sntrup761 decapsulation key (scrubbed on drop) and the X25519 ephemeral.
pub struct HybridClient {
    decap: DecapsulationKey,
    x25519: EcdhKeypair,
    /// The `C_INIT` blob to put on the wire (and feed verbatim into the exchange hash).
    init: Vec<u8>,
}

impl HybridClient {
    /// Generate a fresh sntrup761 key pair and X25519 ephemeral, assembling `C_INIT`.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // sntrup761 key generation is driven by a 32-byte seed; draw it from our CSPRNG.
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(&mut seed[..]);
        let (ek, decap) = generate_key_from_seed(*seed);

        let x25519 = EcdhKeypair::generate(rng);

        let mut init = Vec::with_capacity(CLIENT_INIT_LEN);
        init.extend_from_slice(ek.as_ref());
        init.extend_from_slice(&x25519.public());
        debug_assert_eq!(init.len(), CLIENT_INIT_LEN);

        Self {
            decap,
            x25519,
            init,
        }
    }

    /// The `C_INIT` blob (`SSH_MSG_KEX_ECDH_INIT` payload after the message id).
    pub fn init(&self) -> &[u8] {
        &self.init
    }

    /// Complete the exchange from the server's `S_REPLY`, returning `K`.
    pub fn agree(self, server_reply: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if server_reply.len() != SERVER_REPLY_LEN {
            return Err(SshError::Kex("sntrup761x25519 server reply has wrong length"));
        }
        let (ciphertext, server_x) = server_reply.split_at(SNTRUP_CT_LEN);

        let ciphertext = Ciphertext::try_from(ciphertext)
            .map_err(|_| SshError::Kex("sntrup761 ciphertext has wrong length"))?;
        // Decapsulation is infallible (implicit rejection); the shared secret is
        // ZeroizeOnDrop.
        let k_pq = self.decap.decapsulate(&ciphertext);
        let k_x25519 = self.x25519.agree(server_x)?;

        Ok(combine(k_pq.as_ref(), &k_x25519[..]))
    }
}

/// Server side, run in one shot on receipt of `C_INIT`: encapsulate to the client's
/// sntrup761 key and complete the X25519 half, returning `(S_REPLY, K)`.
pub fn server_respond<R: RngCore + CryptoRng>(
    rng: &mut R,
    client_init: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    if client_init.len() != CLIENT_INIT_LEN {
        return Err(SshError::Kex("sntrup761x25519 client init has wrong length"));
    }
    let (pk_bytes, client_x) = client_init.split_at(SNTRUP_PK_LEN);

    let ek = EncapsulationKey::try_from(pk_bytes)
        .map_err(|_| SshError::Kex("sntrup761 public key has wrong length"))?;

    // Encapsulation is driven by a 32-byte seed; draw it from our CSPRNG.
    let mut seed = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut seed[..]);
    let (ciphertext, k_pq) = ek.encapsulate_deterministic(*seed);

    let server_x = EcdhKeypair::generate(rng);
    let server_x_pub = server_x.public();
    let k_x25519 = server_x.agree(client_x)?;

    let mut reply = Vec::with_capacity(SERVER_REPLY_LEN);
    reply.extend_from_slice(ciphertext.as_ref());
    reply.extend_from_slice(&server_x_pub);
    debug_assert_eq!(reply.len(), SERVER_REPLY_LEN);

    Ok((reply, combine(k_pq.as_ref(), &k_x25519[..])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    /// A full client/server exchange must agree on the same 64-byte `K`, and the wire
    /// blobs must be the advertised sizes.
    #[test]
    fn client_and_server_agree() {
        let mut crng = ChaCha8Rng::seed_from_u64(1);
        let mut srng = ChaCha8Rng::seed_from_u64(2);

        let client = HybridClient::generate(&mut crng);
        assert_eq!(client.init().len(), CLIENT_INIT_LEN);

        let (reply, k_server) = server_respond(&mut srng, client.init()).unwrap();
        assert_eq!(reply.len(), SERVER_REPLY_LEN);

        let k_client = client.agree(&reply).unwrap();
        assert_eq!(k_client.len(), 64);
        assert_eq!(*k_client, *k_server);
    }

    #[test]
    fn rejects_wrong_length_client_init() {
        let mut rng = ChaCha8Rng::seed_from_u64(3);
        assert!(matches!(
            server_respond(&mut rng, &[0u8; CLIENT_INIT_LEN - 1]),
            Err(SshError::Kex(_))
        ));
    }

    #[test]
    fn rejects_wrong_length_server_reply() {
        let mut rng = ChaCha8Rng::seed_from_u64(4);
        let client = HybridClient::generate(&mut rng);
        assert!(matches!(
            client.agree(&[0u8; SERVER_REPLY_LEN + 1]),
            Err(SshError::Kex(_))
        ));
    }

    /// A tampered ciphertext must not yield the server's `K` (sntrup761 implicit rejection
    /// plus the X25519 binding), while decapsulation itself stays infallible.
    #[test]
    fn tampered_reply_diverges() {
        let mut crng = ChaCha8Rng::seed_from_u64(5);
        let mut srng = ChaCha8Rng::seed_from_u64(6);
        let client = HybridClient::generate(&mut crng);
        let (mut reply, k_server) = server_respond(&mut srng, client.init()).unwrap();
        reply[0] ^= 0xff;
        let k_client = client.agree(&reply).unwrap();
        assert_ne!(*k_client, *k_server);
    }
}
