//! SSH message-number constants (the first byte of every packet payload).
//! Numbers are from RFC 4250 §4.1 and the relevant protocol RFCs.

// Transport layer (RFC 4253)
pub const DISCONNECT: u8 = 1;
pub const IGNORE: u8 = 2;
pub const UNIMPLEMENTED: u8 = 3;
pub const DEBUG: u8 = 4;
pub const SERVICE_REQUEST: u8 = 5;
pub const SERVICE_ACCEPT: u8 = 6;
pub const KEXINIT: u8 = 20;
pub const NEWKEYS: u8 = 21;

// Key exchange method-specific (RFC 5656 / curve25519): ECDH init/reply.
pub const KEX_ECDH_INIT: u8 = 30;
pub const KEX_ECDH_REPLY: u8 = 31;

// User authentication (RFC 4252)
pub const USERAUTH_REQUEST: u8 = 50;
pub const USERAUTH_FAILURE: u8 = 51;
pub const USERAUTH_SUCCESS: u8 = 52;
pub const USERAUTH_BANNER: u8 = 53;
/// Method-specific (publickey): `SSH_MSG_USERAUTH_PK_OK`.
pub const USERAUTH_PK_OK: u8 = 60;

// Connection protocol (RFC 4254)
pub const GLOBAL_REQUEST: u8 = 80;
pub const REQUEST_SUCCESS: u8 = 81;
pub const REQUEST_FAILURE: u8 = 82;
pub const CHANNEL_OPEN: u8 = 90;
pub const CHANNEL_OPEN_CONFIRMATION: u8 = 91;
pub const CHANNEL_OPEN_FAILURE: u8 = 92;
pub const CHANNEL_WINDOW_ADJUST: u8 = 93;
pub const CHANNEL_DATA: u8 = 94;
pub const CHANNEL_EXTENDED_DATA: u8 = 95;
pub const CHANNEL_EOF: u8 = 96;
pub const CHANNEL_CLOSE: u8 = 97;
pub const CHANNEL_REQUEST: u8 = 98;
pub const CHANNEL_SUCCESS: u8 = 99;
pub const CHANNEL_FAILURE: u8 = 100;

/// `SSH_MSG_DISCONNECT` reason codes (RFC 4253 §11.1) used by this implementation.
pub mod disconnect {
    pub const PROTOCOL_ERROR: u32 = 2;
    pub const KEY_EXCHANGE_FAILED: u32 = 3;
    pub const MAC_ERROR: u32 = 5;
    pub const NO_MORE_AUTH_METHODS_AVAILABLE: u32 = 14;
}

/// `SSH_MSG_CHANNEL_EXTENDED_DATA` data-type codes (RFC 4254 §5.2).
pub mod extended_data {
    pub const STDERR: u32 = 1;
}
