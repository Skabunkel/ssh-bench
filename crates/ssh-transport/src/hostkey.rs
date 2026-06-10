//! `ssh-ed25519` host keys: signing the exchange hash (server) and verifying it
//! (client), plus the SSH wire blob formats from RFC 8709.
//!
//! Public key blob `K_S`:  `string "ssh-ed25519"` ‖ `string key[32]`
//! Signature blob:         `string "ssh-ed25519"` ‖ `string sig[64]`

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;
use ssh_key::private::{Ed25519Keypair, KeypairData};
use ssh_key::{LineEnding, PrivateKey};
use zeroize::Zeroizing;

use crate::algo::HOSTKEY_ED25519;
use crate::wire::{Reader, Writer};
use crate::{Result, SshError};

/// A private host key held by the server.
#[derive(Clone)]
pub struct HostKey {
    signing: SigningKey,
}

impl HostKey {
    /// Build from a 32-byte ed25519 seed (the private scalar seed).
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Generate a fresh host key.
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self {
            signing: SigningKey::generate(rng),
        }
    }

    /// Parse an unencrypted OpenSSH-format private key (the
    /// `-----BEGIN OPENSSH PRIVATE KEY-----` PEM written by `ssh-keygen -t ed25519`).
    /// Only `ssh-ed25519` keys are supported; encrypted keys are rejected.
    pub fn from_openssh(pem: &str) -> Result<Self> {
        let key = PrivateKey::from_openssh(pem)
            .map_err(|_| SshError::Key("invalid OpenSSH private key"))?;
        match key.key_data() {
            KeypairData::Ed25519(kp) => Ok(Self::from_seed(&kp.private.to_bytes())),
            _ => Err(SshError::Key(
                "host key is not ssh-ed25519 (or is encrypted)",
            )),
        }
    }

    /// Serialize to an unencrypted OpenSSH-format private key PEM, suitable for writing to
    /// a key file and reloading with [`HostKey::from_openssh`]. The PEM (and the transient
    /// seed used to build it) live in [`Zeroizing`] buffers so the private key text is
    /// scrubbed from memory once the returned value is dropped.
    pub fn to_openssh(&self) -> Result<Zeroizing<String>> {
        let seed = Zeroizing::new(self.signing.to_bytes());
        let kp = Ed25519Keypair::from_seed(&seed);
        PrivateKey::from(kp)
            .to_openssh(LineEnding::LF)
            .map_err(|_| SshError::Key("failed to encode host key"))
    }

    /// The public key blob `K_S` hashed into the exchange hash and sent to the client.
    pub fn public_blob(&self) -> Vec<u8> {
        public_blob(&self.signing.verifying_key())
    }

    /// The corresponding public key (for tests and known-host registration).
    pub fn public(&self) -> HostPublicKey {
        HostPublicKey {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Sign the 32-byte exchange hash `H`, returning the SSH signature blob.
    pub fn sign_exchange_hash(&self, h: &[u8]) -> Vec<u8> {
        let sig = self.signing.sign(h);
        let mut w = Writer::new();
        w.string(HOSTKEY_ED25519.as_bytes());
        w.string(&sig.to_bytes());
        w.into_bytes()
    }
}

/// A public host key held/seen by the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPublicKey {
    verifying: VerifyingKey,
}

impl HostPublicKey {
    /// Parse a `K_S` public key blob.
    pub fn parse_blob(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        if r.utf8()? != HOSTKEY_ED25519 {
            return Err(SshError::Kex("unsupported host key algorithm"));
        }
        let key = r.string()?;
        let key: [u8; 32] = key
            .try_into()
            .map_err(|_| SshError::Kex("ed25519 key is not 32 bytes"))?;
        let verifying =
            VerifyingKey::from_bytes(&key).map_err(|_| SshError::Kex("invalid ed25519 key"))?;
        Ok(Self { verifying })
    }

    /// Build from a raw 32-byte ed25519 public key.
    pub fn from_ed25519_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            verifying: VerifyingKey::from_bytes(bytes)
                .map_err(|_| SshError::Kex("invalid ed25519 key"))?,
        })
    }

    /// The `K_S` public key blob for this key.
    pub fn blob(&self) -> Vec<u8> {
        public_blob(&self.verifying)
    }

    /// Verify a signature blob over the exchange hash `H`.
    pub fn verify(&self, h: &[u8], sig_blob: &[u8]) -> Result<()> {
        let mut r = Reader::new(sig_blob);
        if r.utf8()? != HOSTKEY_ED25519 {
            return Err(SshError::Kex("unsupported signature algorithm"));
        }
        let sig = r.string()?;
        let sig: [u8; 64] = sig
            .try_into()
            .map_err(|_| SshError::Kex("ed25519 signature is not 64 bytes"))?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig);
        self.verifying
            .verify_strict(h, &signature)
            .map_err(|_| SshError::Kex("host key signature verification failed"))
    }
}

fn public_blob(vk: &VerifyingKey) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(HOSTKEY_ED25519.as_bytes());
    w.string(vk.as_bytes());
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn sign_then_verify_roundtrip() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let host = HostKey::generate(&mut rng);
        let h = [0x11u8; 32];
        let sig = host.sign_exchange_hash(&h);

        let pubkey = HostPublicKey::parse_blob(&host.public_blob()).unwrap();
        assert!(pubkey.verify(&h, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_tampered_hash() {
        let mut rng = ChaCha8Rng::seed_from_u64(43);
        let host = HostKey::generate(&mut rng);
        let sig = host.sign_exchange_hash(&[0x11u8; 32]);
        let pubkey = host.public();
        assert!(matches!(
            pubkey.verify(&[0x22u8; 32], &sig),
            Err(SshError::Kex(_))
        ));
    }

    #[test]
    fn openssh_pem_roundtrip_preserves_key() {
        let mut rng = ChaCha8Rng::seed_from_u64(7);
        let host = HostKey::generate(&mut rng);
        let pem = host.to_openssh().unwrap();
        assert!(pem.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));

        // Reloading yields the same public identity and a usable signing key.
        let reloaded = HostKey::from_openssh(&pem).unwrap();
        assert_eq!(reloaded.public(), host.public());
        let h = [0x33u8; 32];
        let sig = reloaded.sign_exchange_hash(&h);
        assert!(host.public().verify(&h, &sig).is_ok());
    }

    #[test]
    fn from_openssh_rejects_garbage() {
        assert!(matches!(
            HostKey::from_openssh("not a key"),
            Err(SshError::Key(_))
        ));
    }

    #[test]
    fn parse_blob_rejects_wrong_algorithm() {
        let mut w = Writer::new();
        w.string(b"ssh-rsa");
        w.string(&[0u8; 32]);
        assert!(matches!(
            HostPublicKey::parse_blob(&w.into_bytes()),
            Err(SshError::Kex(_))
        ));
    }
}
