//! `curve25519-sha256` key exchange (RFC 8731) using X25519.

use rand_core::{CryptoRng, RngCore};
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::{Result, SshError};

/// An ephemeral X25519 key pair. The public value is the 32-byte `Q` sent on the wire.
pub struct EcdhKeypair {
    secret: EphemeralSecret,
    public: [u8; 32],
}

impl EcdhKeypair {
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let secret = EphemeralSecret::random_from_rng(rng);
        let public = PublicKey::from(&secret).to_bytes();
        Self { secret, public }
    }

    /// The 32-byte public value `Q` to send to the peer.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Complete the exchange with the peer's public value, returning the 32-byte shared
    /// secret. Rejects non-contributory (all-zero) results from low-order points.
    pub fn agree(self, peer_public: &[u8]) -> Result<[u8; 32]> {
        let peer: [u8; 32] = peer_public
            .try_into()
            .map_err(|_| SshError::Kex("peer public key is not 32 bytes"))?;
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer));
        if !shared.was_contributory() {
            return Err(SshError::Kex("non-contributory key exchange"));
        }
        Ok(shared.to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn both_sides_agree_on_shared_secret() {
        let mut rng = ChaCha8Rng::seed_from_u64(1);
        let client = EcdhKeypair::generate(&mut rng);
        let server = EcdhKeypair::generate(&mut rng);
        let cpub = client.public();
        let spub = server.public();
        let k_client = client.agree(&spub).unwrap();
        let k_server = server.agree(&cpub).unwrap();
        assert_eq!(k_client, k_server);
    }

    #[test]
    fn rejects_wrong_length_peer_key() {
        let mut rng = ChaCha8Rng::seed_from_u64(2);
        let kp = EcdhKeypair::generate(&mut rng);
        assert!(matches!(kp.agree(&[0u8; 31]), Err(SshError::Kex(_))));
    }
}
