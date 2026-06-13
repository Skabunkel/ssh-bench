//! Pure-Rust, sans-IO SSH-2.0 protocol engine shared by the client and server.
//!
//! This crate is the **App** layer: it owns all protocol logic and crypto computation
//! and performs no I/O of its own. A driver (the `ssh-io` crate) feeds it bytes and
//! pumps the bytes/events it produces.
//!
//! ## Layout
//! - [`wire`] — RFC 4251 primitive reader/writer
//! - [`msg`] — SSH message-number constants
//! - [`version`] — identification-string exchange (RFC 4253 §4.2)
//! - [`packet`] — Binary Packet Protocol framing (RFC 4253 §6)

mod error;

pub mod algo;
pub mod auth;
pub mod cipher;
pub mod client;
pub mod compress;
pub mod connection;
pub mod hostkey;
pub mod kdf;
pub mod kex;
pub mod mlkem;
pub mod msg;
pub mod packet;
pub mod server;
pub mod transport;
pub mod version;
pub mod wire;

pub use error::{Result, SshError};
pub use hostkey::{HostKey, HostPublicKey};
pub use transport::{Event, Role, Transport};

pub use auth::{Password, UserKeypair, UserPublicKey};
pub use client::{AuthAttempt, ClientAuthHandler, ClientConnection, ClientEvent};
pub use connection::PtyInfo;
pub use server::{ServerAuthHandler, ServerConnection, ServerEvent};

/// Re-exported so downstream crates can name a matching-version RNG (e.g. `OsRng`)
/// without depending on `rand_core` directly.
pub use rand_core;
