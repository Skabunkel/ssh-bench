//! User authentication protocol (RFC 4252): service request/accept and the `none`,
//! `password`, and `publickey` methods. User public keys are `ssh-ed25519`.
//!
//! Message bodies are built/parsed here; the client and server session state machines
//! ([`crate::client`], [`crate::server`]) drive the exchange.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::CryptoRngCore;

use crate::algo::HOSTKEY_ED25519;
use crate::wire::{Reader, Writer};
use crate::{Result, SshError, msg};

/// The user-authentication service name.
pub const SERVICE_USERAUTH: &str = "ssh-userauth";
/// The connection-protocol service name (requested after authentication).
pub const SERVICE_CONNECTION: &str = "ssh-connection";

pub const METHOD_NONE: &str = "none";
pub const METHOD_PASSWORD: &str = "password";
pub const METHOD_PUBLICKEY: &str = "publickey";

/// A user's `ssh-ed25519` public key, used to authorize and verify `publickey` auth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserPublicKey {
    verifying: VerifyingKey,
}

impl UserPublicKey {
    /// Parse an `ssh-ed25519` public key blob.
    pub fn parse_blob(blob: &[u8]) -> Result<Self> {
        let mut r = Reader::new(blob);
        if r.utf8()? != HOSTKEY_ED25519 {
            return Err(SshError::Protocol("unsupported public key algorithm"));
        }
        let key: [u8; 32] = r
            .string()?
            .try_into()
            .map_err(|_| SshError::Protocol("ed25519 key is not 32 bytes"))?;
        Ok(Self {
            verifying: VerifyingKey::from_bytes(&key)
                .map_err(|_| SshError::Protocol("invalid ed25519 key"))?,
        })
    }

    /// Build from a raw 32-byte ed25519 public key.
    pub fn from_ed25519_bytes(bytes: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            verifying: VerifyingKey::from_bytes(bytes)
                .map_err(|_| SshError::Protocol("invalid ed25519 key"))?,
        })
    }

    pub fn blob(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.string(HOSTKEY_ED25519.as_bytes());
        w.string(self.verifying.as_bytes());
        w.into_bytes()
    }

    /// Verify a `publickey` signature blob over `signed_data`.
    pub fn verify(&self, signed_data: &[u8], sig_blob: &[u8]) -> Result<()> {
        let mut r = Reader::new(sig_blob);
        if r.utf8()? != HOSTKEY_ED25519 {
            return Err(SshError::Protocol("unsupported signature algorithm"));
        }
        let sig: [u8; 64] = r
            .string()?
            .try_into()
            .map_err(|_| SshError::Protocol("signature is not 64 bytes"))?;
        self.verifying
            .verify_strict(signed_data, &ed25519_dalek::Signature::from_bytes(&sig))
            .map_err(|_| SshError::AuthFailed)
    }
}

/// A user's `ssh-ed25519` private key, used by the client to sign `publickey` requests.
pub struct UserKeypair {
    signing: SigningKey,
}

impl UserKeypair {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            signing: SigningKey::from_bytes(seed),
        }
    }

    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Self {
        Self {
            signing: SigningKey::generate(rng),
        }
    }

    pub fn public(&self) -> UserPublicKey {
        UserPublicKey {
            verifying: self.signing.verifying_key(),
        }
    }

    /// Produce the signature blob over `signed_data`.
    pub fn sign(&self, signed_data: &[u8]) -> Vec<u8> {
        let sig = self.signing.sign(signed_data);
        let mut w = Writer::new();
        w.string(HOSTKEY_ED25519.as_bytes());
        w.string(&sig.to_bytes());
        w.into_bytes()
    }
}

/// The data signed for a `publickey` request (RFC 4252 §7): the session id followed by
/// the request up to but excluding the signature.
pub fn publickey_signed_data(
    session_id: &[u8],
    user: &str,
    service: &str,
    key_algo: &str,
    key_blob: &[u8],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(session_id);
    w.u8(msg::USERAUTH_REQUEST);
    w.string(user.as_bytes());
    w.string(service.as_bytes());
    w.string(METHOD_PUBLICKEY.as_bytes());
    w.boolean(true);
    w.string(key_algo.as_bytes());
    w.string(key_blob);
    w.into_bytes()
}

// --- message builders ---

pub fn service_request(service: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::SERVICE_REQUEST);
    w.string(service.as_bytes());
    w.into_bytes()
}

pub fn service_accept(service: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::SERVICE_ACCEPT);
    w.string(service.as_bytes());
    w.into_bytes()
}

pub fn userauth_failure(methods: &[&str], partial: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::USERAUTH_FAILURE);
    w.name_list(methods);
    w.boolean(partial);
    w.into_bytes()
}

pub fn userauth_success() -> Vec<u8> {
    vec![msg::USERAUTH_SUCCESS]
}

pub fn userauth_banner(message: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::USERAUTH_BANNER);
    w.string(message.as_bytes());
    w.string(b""); // language tag
    w.into_bytes()
}

pub fn userauth_pk_ok(key_algo: &str, key_blob: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::USERAUTH_PK_OK);
    w.string(key_algo.as_bytes());
    w.string(key_blob);
    w.into_bytes()
}

pub fn password_request(user: &str, service: &str, password: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::USERAUTH_REQUEST);
    w.string(user.as_bytes());
    w.string(service.as_bytes());
    w.string(METHOD_PASSWORD.as_bytes());
    w.boolean(false);
    w.string(password.as_bytes());
    w.into_bytes()
}

pub fn none_request(user: &str, service: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::USERAUTH_REQUEST);
    w.string(user.as_bytes());
    w.string(service.as_bytes());
    w.string(METHOD_NONE.as_bytes());
    w.into_bytes()
}

/// A `publickey` request, with or without a trailing signature.
pub fn publickey_request(
    user: &str,
    service: &str,
    key_algo: &str,
    key_blob: &[u8],
    signature: Option<&[u8]>,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::USERAUTH_REQUEST);
    w.string(user.as_bytes());
    w.string(service.as_bytes());
    w.string(METHOD_PUBLICKEY.as_bytes());
    w.boolean(signature.is_some());
    w.string(key_algo.as_bytes());
    w.string(key_blob);
    if let Some(sig) = signature {
        w.string(sig);
    }
    w.into_bytes()
}

/// A parsed `SSH_MSG_USERAUTH_REQUEST` (server side).
#[derive(Debug)]
pub struct AuthRequest {
    pub user: Box<str>,
    pub service: Box<str>,
    pub method: Method,
}

/// The method-specific part of an auth request.
#[derive(Debug)]
pub enum Method {
    None,
    Password { password: Box<str> },
    PublicKey {
        key_algo: Box<str>,
        key_blob: Vec<u8>,
        /// Present only when the client included a signature (vs. a probe).
        signature: Option<Vec<u8>>,
    },
    Unknown { name: Box<str> },
}

impl AuthRequest {
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.u8()? != msg::USERAUTH_REQUEST {
            return Err(SshError::Protocol("expected USERAUTH_REQUEST"));
        }
        let user = r.utf8()?.into();
        let service = r.utf8()?.into();
        let method_name = r.utf8()?;
        let method = match method_name {
            METHOD_NONE => Method::None,
            METHOD_PASSWORD => {
                let _change = r.boolean()?; // FALSE; password change not supported
                Method::Password {
                    password: r.utf8()?.into(),
                }
            }
            METHOD_PUBLICKEY => {
                let has_sig = r.boolean()?;
                let key_algo = r.utf8()?.into();
                let key_blob = r.string()?.to_vec();
                let signature = if has_sig { Some(r.string()?.to_vec()) } else { None };
                Method::PublicKey {
                    key_algo,
                    key_blob,
                    signature,
                }
            }
            other => Method::Unknown { name: other.into() },
        };
        Ok(Self {
            user,
            service,
            method,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    #[test]
    fn password_request_roundtrip() {
        let bytes = password_request("alice", SERVICE_CONNECTION, "hunter2");
        let req = AuthRequest::parse(&bytes).unwrap();
        assert_eq!(&*req.user, "alice");
        assert_eq!(&*req.service, SERVICE_CONNECTION);
        match req.method {
            Method::Password { password } => assert_eq!(&*password, "hunter2"),
            _ => panic!("expected password method"),
        }
    }

    #[test]
    fn publickey_probe_has_no_signature() {
        let kp = UserKeypair::generate(&mut ChaCha8Rng::seed_from_u64(1));
        let blob = kp.public().blob();
        let bytes = publickey_request("bob", SERVICE_CONNECTION, HOSTKEY_ED25519, &blob, None);
        let req = AuthRequest::parse(&bytes).unwrap();
        match req.method {
            Method::PublicKey { signature, .. } => assert!(signature.is_none()),
            _ => panic!("expected publickey method"),
        }
    }

    #[test]
    fn publickey_signature_roundtrips_and_verifies() {
        let kp = UserKeypair::generate(&mut ChaCha8Rng::seed_from_u64(2));
        let pubkey = kp.public();
        let session_id = [0x5au8; 32];
        let blob = pubkey.blob();
        let signed =
            publickey_signed_data(&session_id, "bob", SERVICE_CONNECTION, HOSTKEY_ED25519, &blob);
        let sig = kp.sign(&signed);
        assert!(pubkey.verify(&signed, &sig).is_ok());

        // A tampered signed-data must fail.
        let mut bad = signed.clone();
        bad[0] ^= 0xff;
        assert!(matches!(pubkey.verify(&bad, &sig), Err(SshError::AuthFailed)));
    }
}
