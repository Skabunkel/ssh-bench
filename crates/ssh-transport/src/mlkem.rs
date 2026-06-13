//! `mlkem768x25519-sha256` post-quantum / classical hybrid key exchange
//! (draft-kampanakis-curdle-ssh-pq-ke, as deployed by OpenSSH ≥ 9.0).
//!
//! The method runs ML-KEM-768 (FIPS 203) and X25519 side by side and binds both shared
//! secrets together:
//!
//! ```text
//! K = SHA256(K_pq ‖ K_x25519)
//! ```
//!
//! where `K_pq` is the ML-KEM shared secret and `K_x25519` the classical one. Unlike the
//! plain `curve25519-sha256` method (whose `K` is an `mpint`), the hybrid feeds `K` into
//! the exchange hash and key derivation as an SSH `string` of the 32-byte hash — see
//! [`crate::kdf::SharedSecret`]. The wire blobs reuse the `SSH_MSG_KEX_ECDH_INIT` /
//! `SSH_MSG_KEX_ECDH_REPLY` carriers:
//!
//! * client → server (`C_INIT`): ML-KEM encapsulation key ‖ client X25519 public value
//! * server → client (`S_REPLY`): ML-KEM ciphertext ‖ server X25519 public value
//!
//! ML-KEM randomness is supplied from the transport's own CSPRNG via the deterministic
//! entry points, which is exactly what the RNG-based API does internally (it draws the
//! same bytes and calls the same routine); doing it here keeps a single RNG source and
//! avoids pulling a second `rand_core` major into the hot path.

use ml_kem::kem::{Decapsulate, KeyExport};
use ml_kem::{B32, DecapsulationKey, EncapsulationKey, Key, MlKem768, Seed};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::kex::EcdhKeypair;
use crate::{Result, SshError};

/// Negotiated name for the hybrid method.
pub const KEX_MLKEM768_X25519: &str = "mlkem768x25519-sha256";

/// ML-KEM-768 encapsulation-key length (FIPS 203).
const MLKEM_EK_LEN: usize = 1184;
/// ML-KEM-768 ciphertext length (FIPS 203).
const MLKEM_CT_LEN: usize = 1088;
/// X25519 public-value length.
const X25519_LEN: usize = 32;

/// Length of the client's `C_INIT` blob: ML-KEM encapsulation key followed by the client's
/// X25519 public value.
pub const CLIENT_INIT_LEN: usize = MLKEM_EK_LEN + X25519_LEN;
/// Length of the server's `S_REPLY` blob: ML-KEM ciphertext followed by the server's
/// X25519 public value.
pub const SERVER_REPLY_LEN: usize = MLKEM_CT_LEN + X25519_LEN;

/// `K = SHA256(K_pq ‖ K_x25519)`. The ML-KEM secret is hashed first, matching the order
/// fixed by the draft and by OpenSSH. The inputs are the callers' to scrub.
fn combine(k_pq: &[u8], k_x25519: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut h = Sha256::new();
    h.update(k_pq);
    h.update(k_x25519);
    Zeroizing::new(h.finalize().to_vec())
}

/// Client-side hybrid state, held between `C_INIT` and the server's `S_REPLY`. Owns the
/// ML-KEM decapsulation key (scrubbed on drop) and the X25519 ephemeral.
pub struct HybridClient {
    decap: DecapsulationKey<MlKem768>,
    x25519: EcdhKeypair,
    /// The `C_INIT` blob to put on the wire (and feed verbatim into the exchange hash).
    init: Vec<u8>,
}

impl HybridClient {
    /// Generate a fresh ML-KEM-768 key pair and X25519 ephemeral, assembling `C_INIT`.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        // ML-KEM key generation consumes a 64-byte seed (d ‖ z); draw it from our CSPRNG.
        let mut seed = Zeroizing::new([0u8; 64]);
        rng.fill_bytes(&mut seed[..]);
        let seed = Seed::try_from(&seed[..]).expect("64-byte ML-KEM seed");
        let decap = DecapsulationKey::<MlKem768>::from_seed(seed);
        let ek = decap.encapsulation_key().to_bytes();

        let x25519 = EcdhKeypair::generate(rng);

        let mut init = Vec::with_capacity(CLIENT_INIT_LEN);
        init.extend_from_slice(&ek);
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
            return Err(SshError::Kex("mlkem768x25519 server reply has wrong length"));
        }
        let (ciphertext, server_x) = server_reply.split_at(MLKEM_CT_LEN);

        // ML-KEM decapsulation is infallible (implicit rejection on a bad ciphertext).
        let mut k_pq = self
            .decap
            .decapsulate_slice(ciphertext)
            .map_err(|_| SshError::Kex("mlkem768 ciphertext has wrong length"))?;
        let k_x25519 = self.x25519.agree(server_x)?;

        let k = combine(&k_pq, &k_x25519[..]);
        k_pq.as_mut_slice().zeroize();
        Ok(k)
    }
}

/// Server side, run in one shot on receipt of `C_INIT`: encapsulate to the client's
/// ML-KEM key and complete the X25519 half, returning `(S_REPLY, K)`.
pub fn server_respond<R: RngCore + CryptoRng>(
    rng: &mut R,
    client_init: &[u8],
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>)> {
    if client_init.len() != CLIENT_INIT_LEN {
        return Err(SshError::Kex("mlkem768x25519 client init has wrong length"));
    }
    let (ek_bytes, client_x) = client_init.split_at(MLKEM_EK_LEN);

    let ek_bytes = Key::<EncapsulationKey<MlKem768>>::try_from(ek_bytes)
        .map_err(|_| SshError::Kex("mlkem768 encapsulation key has wrong length"))?;
    let ek = EncapsulationKey::<MlKem768>::new(&ek_bytes)
        .map_err(|_| SshError::Kex("invalid mlkem768 encapsulation key"))?;

    // Encapsulation consumes 32 bytes of randomness; draw them from our CSPRNG.
    let mut m = Zeroizing::new([0u8; 32]);
    rng.fill_bytes(&mut m[..]);
    let m = B32::try_from(&m[..]).expect("32-byte ML-KEM message");
    let (ciphertext, mut k_pq) = ek.encapsulate_deterministic(&m);

    let server_x = EcdhKeypair::generate(rng);
    let server_x_pub = server_x.public();
    let k_x25519 = server_x.agree(client_x)?;

    let mut reply = Vec::with_capacity(SERVER_REPLY_LEN);
    reply.extend_from_slice(&ciphertext);
    reply.extend_from_slice(&server_x_pub);
    debug_assert_eq!(reply.len(), SERVER_REPLY_LEN);

    let k = combine(&k_pq, &k_x25519[..]);
    k_pq.as_mut_slice().zeroize();
    Ok((reply, k))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    /// A full client/server exchange must agree on the same `K`, and the wire blobs must
    /// be the advertised sizes.
    #[test]
    fn client_and_server_agree() {
        let mut crng = ChaCha8Rng::seed_from_u64(1);
        let mut srng = ChaCha8Rng::seed_from_u64(2);

        let client = HybridClient::generate(&mut crng);
        assert_eq!(client.init().len(), CLIENT_INIT_LEN);

        let (reply, k_server) = server_respond(&mut srng, client.init()).unwrap();
        assert_eq!(reply.len(), SERVER_REPLY_LEN);

        let k_client = client.agree(&reply).unwrap();
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

    /// A tampered ciphertext must not yield the server's `K` (ML-KEM implicit rejection
    /// plus the X25519 binding), but decapsulation itself stays infallible.
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
