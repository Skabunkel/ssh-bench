//! Crate-wide error type. We deliberately avoid `anyhow`; every fallible path returns a
//! typed [`SshError`].

use core::fmt;

/// Result alias used throughout the engine.
pub type Result<T> = core::result::Result<T, SshError>;

/// All errors the protocol engine can produce.
#[derive(Debug)]
#[non_exhaustive]
pub enum SshError {
    /// The peer's identification string was missing, malformed, or an unsupported version.
    BadVersion(&'static str),
    /// A binary packet was malformed (bad length, padding, or truncated field).
    BadPacket(&'static str),
    /// Encoding or decoding of an SSH wire primitive failed.
    Encoding(&'static str),
    /// Algorithm negotiation found no algorithm in common for the named slot.
    NoCommonAlgorithm(&'static str),
    /// Key exchange failed (bad point, signature, or exchange-hash mismatch).
    Kex(&'static str),
    /// A key blob could not be parsed or encoded (e.g. an OpenSSH private key file).
    Key(&'static str),
    /// Message integrity / AEAD authentication-tag verification failed.
    Integrity,
    /// Received a message that is not valid in the current protocol state.
    Protocol(&'static str),
    /// Authentication did not succeed.
    AuthFailed,
}

impl fmt::Display for SshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SshError::BadVersion(s) => write!(f, "bad SSH identification string: {s}"),
            SshError::BadPacket(s) => write!(f, "malformed binary packet: {s}"),
            SshError::Encoding(s) => write!(f, "wire encoding error: {s}"),
            SshError::NoCommonAlgorithm(s) => write!(f, "no common algorithm for {s}"),
            SshError::Kex(s) => write!(f, "key exchange failed: {s}"),
            SshError::Key(s) => write!(f, "key error: {s}"),
            SshError::Integrity => write!(f, "message integrity check failed"),
            SshError::Protocol(s) => write!(f, "protocol violation: {s}"),
            SshError::AuthFailed => write!(f, "authentication failed"),
        }
    }
}

impl core::error::Error for SshError {}
