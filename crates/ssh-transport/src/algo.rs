//! Algorithm negotiation and the `SSH_MSG_KEXINIT` message (RFC 4253 §7.1).
//!
//! We offer a deliberately small, modern set (see the crate plan). Because the only
//! cipher we offer is an AEAD (`chacha20-poly1305@openssh.com`), the negotiated MAC is
//! always implicit and the offered MAC name-list is a formality.

use rand_core::RngCore;

use crate::mlkem::KEX_MLKEM768_X25519;
#[cfg(feature = "sntrup761")]
use crate::sntrup::KEX_SNTRUP761_X25519;
use crate::wire::{Reader, Writer};
use crate::{Result, SshError, msg};

// Supported algorithm names, in preference order.
pub const KEX_CURVE25519: &str = "curve25519-sha256";
pub const KEX_CURVE25519_LIBSSH: &str = "curve25519-sha256@libssh.org";
pub const HOSTKEY_ED25519: &str = "ssh-ed25519";
pub const CIPHER_CHACHA20_POLY1305: &str = "chacha20-poly1305@openssh.com";
pub const CIPHER_AES256_GCM: &str = "aes256-gcm@openssh.com";

// Compression
pub const COMPRESSION_NONE: &str = "none";
/// Delayed zlib: compression engages only after authentication succeeds.
pub const COMPRESSION_ZLIB_OPENSSH: &str = "zlib@openssh.com";

/// Strict-KEX markers (OpenSSH `kex-strict-*`, the Terrapin mitigation). Advertised in
/// the KEX name-list but never selected as an algorithm; strict mode turns on only when
/// both sides advertise their respective marker.
pub const KEX_STRICT_CLIENT: &str = "kex-strict-c-v00@openssh.com";
pub const KEX_STRICT_SERVER: &str = "kex-strict-s-v00@openssh.com";

// The PQ-hybrid methods are offered first so one is selected against any peer that
// supports them (negotiation prefers the client's order), giving "store now, decrypt
// later" resistance. The order — ML-KEM first, then sntrup761 — matches modern OpenSSH's
// default preference. sntrup761 is only offered when the `sntrup761` crate feature is on
// (it pulls a non-Rust dependency; see the crate's Cargo.toml); ML-KEM covers PQ otherwise.
#[cfg(feature = "sntrup761")]
const KEX_ALGORITHMS: &[&str] = &[
    KEX_MLKEM768_X25519,
    KEX_SNTRUP761_X25519,
    KEX_CURVE25519,
    KEX_CURVE25519_LIBSSH,
];
#[cfg(not(feature = "sntrup761"))]
const KEX_ALGORITHMS: &[&str] = &[KEX_MLKEM768_X25519, KEX_CURVE25519, KEX_CURVE25519_LIBSSH];
const HOSTKEY_ALGORITHMS: &[&str] = &[HOSTKEY_ED25519];
const CIPHERS: &[&str] = &[CIPHER_CHACHA20_POLY1305, CIPHER_AES256_GCM];
// Offered but unused: an AEAD cipher is always selected, carrying its own integrity.
const MACS: &[&str] = &["hmac-sha2-256"];
// `none` is listed first, so compression is off unless a peer prefers `zlib@openssh.com`.
const COMPRESSIONS: &[&str] = &[COMPRESSION_NONE, COMPRESSION_ZLIB_OPENSSH];

/// A parsed/observed `SSH_MSG_KEXINIT`. The `payload` is the full message bytes
/// (starting with the message id) because both sides' KEXINIT payloads feed verbatim
/// into the exchange hash as `I_C` / `I_S`.
#[derive(Debug, Clone)]
pub struct KexInit {
    pub payload: Vec<u8>,
    pub kex: Vec<Box<str>>,
    pub host_key: Vec<Box<str>>,
    pub cipher_c2s: Vec<Box<str>>,
    pub cipher_s2c: Vec<Box<str>>,
    pub comp_c2s: Vec<Box<str>>,
    pub comp_s2c: Vec<Box<str>>,
    pub first_kex_packet_follows: bool,
}

impl KexInit {
    /// Build our KEXINIT with a fresh random cookie, advertising the strict-KEX marker
    /// for our role, offering the default cipher and compression sets.
    pub fn ours(rng: &mut impl RngCore, is_server: bool) -> Self {
        Self::ours_with(rng, is_server, CIPHERS, COMPRESSIONS)
    }

    /// Like [`KexInit::ours`] but offering `ciphers` and `compressions` (in preference
    /// order) for both directions. Every name must be one this crate implements;
    /// negotiation prefers the client's order, so a client uses this to pin selections.
    pub fn ours_with(
        rng: &mut impl RngCore,
        is_server: bool,
        ciphers: &[&str],
        compressions: &[&str],
    ) -> Self {
        let mut cookie = [0u8; 16];
        rng.fill_bytes(&mut cookie);

        let mut kex_algorithms = KEX_ALGORITHMS.to_vec();
        kex_algorithms.push(if is_server {
            KEX_STRICT_SERVER
        } else {
            KEX_STRICT_CLIENT
        });

        let mut w = Writer::new();
        w.u8(msg::KEXINIT);
        w.raw(&cookie);
        w.name_list(&kex_algorithms);
        w.name_list(HOSTKEY_ALGORITHMS);
        w.name_list(ciphers); // c2s
        w.name_list(ciphers); // s2c
        w.name_list(MACS); // c2s
        w.name_list(MACS); // s2c
        w.name_list(compressions); // c2s
        w.name_list(compressions); // s2c
        w.name_list(&[]); // languages c2s
        w.name_list(&[]); // languages s2c
        w.boolean(false); // first_kex_packet_follows
        w.u32(0); // reserved

        let payload = w.into_bytes();
        Self {
            kex: to_owned(&kex_algorithms),
            host_key: to_owned(HOSTKEY_ALGORITHMS),
            cipher_c2s: to_owned(ciphers),
            cipher_s2c: to_owned(ciphers),
            comp_c2s: to_owned(compressions),
            comp_s2c: to_owned(compressions),
            first_kex_packet_follows: false,
            payload,
        }
    }

    /// Parse a peer's KEXINIT payload (including the leading message id).
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut r = Reader::new(payload);
        if r.u8()? != msg::KEXINIT {
            return Err(SshError::Protocol("expected SSH_MSG_KEXINIT"));
        }
        let _cookie = r_take16(&mut r)?;
        let kex = r.name_list()?;
        let host_key = r.name_list()?;
        let cipher_c2s = r.name_list()?;
        let cipher_s2c = r.name_list()?;
        let _mac_c2s = r.name_list()?;
        let _mac_s2c = r.name_list()?;
        let comp_c2s = r.name_list()?;
        let comp_s2c = r.name_list()?;
        let _lang_c2s = r.name_list()?;
        let _lang_s2c = r.name_list()?;
        let first_kex_packet_follows = r.boolean()?;
        let _reserved = r.u32()?;
        Ok(Self {
            payload: payload.to_vec(),
            kex,
            host_key,
            cipher_c2s,
            cipher_s2c,
            comp_c2s,
            comp_s2c,
            first_kex_packet_follows,
        })
    }
}

/// The algorithms agreed by both sides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub kex: Box<str>,
    pub host_key: Box<str>,
    pub cipher_c2s: Box<str>,
    pub cipher_s2c: Box<str>,
    pub comp_c2s: Box<str>,
    pub comp_s2c: Box<str>,
}

/// Run RFC 4253 §7.1 negotiation. `client` and `server` are the two KEXINITs; the rule
/// is "the first algorithm on the client's list that the server also supports".
pub fn negotiate(client: &KexInit, server: &KexInit) -> Result<Negotiated> {
    Ok(Negotiated {
        kex: pick(&client.kex, &server.kex, "kex")?,
        host_key: pick(&client.host_key, &server.host_key, "host key")?,
        cipher_c2s: pick(&client.cipher_c2s, &server.cipher_c2s, "cipher c2s")?,
        cipher_s2c: pick(&client.cipher_s2c, &server.cipher_s2c, "cipher s2c")?,
        comp_c2s: pick(&client.comp_c2s, &server.comp_c2s, "compression c2s")?,
        comp_s2c: pick(&client.comp_s2c, &server.comp_s2c, "compression s2c")?,
    })
}

/// The default offered cipher list (preference order).
pub fn default_ciphers() -> &'static [&'static str] {
    CIPHERS
}

/// The default offered compression list (preference order; `none` first, so compression
/// is off unless a peer prefers it).
pub fn default_compressions() -> &'static [&'static str] {
    COMPRESSIONS
}

fn pick(client: &[Box<str>], server: &[Box<str>], slot: &'static str) -> Result<Box<str>> {
    client
        .iter()
        .find(|c| server.iter().any(|s| s == *c))
        .cloned()
        .ok_or(SshError::NoCommonAlgorithm(slot))
}

fn to_owned(names: &[&str]) -> Vec<Box<str>> {
    names.iter().map(|s| Box::from(*s)).collect()
}

fn r_take16(r: &mut Reader<'_>) -> Result<[u8; 16]> {
    let mut c = [0u8; 16];
    for b in &mut c {
        *b = r.u8()?;
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(7)
    }

    #[test]
    fn ours_roundtrips_through_parse() {
        let k = KexInit::ours(&mut rng(), false);
        let parsed = KexInit::parse(&k.payload).unwrap();
        assert_eq!(parsed.kex, k.kex);
        assert_eq!(parsed.host_key, k.host_key);
        assert_eq!(parsed.cipher_c2s, k.cipher_c2s);
        assert!(!parsed.first_kex_packet_follows);
    }

    #[test]
    fn negotiation_prefers_client_order() {
        let mut client = KexInit::ours(&mut rng(), false);
        let mut server = KexInit::ours(&mut rng(), false);
        client.kex = vec![KEX_CURVE25519_LIBSSH.into(), KEX_CURVE25519.into()];
        server.kex = vec![KEX_CURVE25519.into(), KEX_CURVE25519_LIBSSH.into()];
        // Client lists libssh first and the server supports it → libssh wins.
        let n = negotiate(&client, &server).unwrap();
        assert_eq!(&*n.kex, KEX_CURVE25519_LIBSSH);
    }

    #[test]
    fn negotiation_fails_with_no_overlap() {
        let mut client = KexInit::ours(&mut rng(), false);
        let server = KexInit::ours(&mut rng(), false);
        client.kex = vec!["diffie-hellman-group14-sha1".into()];
        assert!(matches!(
            negotiate(&client, &server),
            Err(SshError::NoCommonAlgorithm("kex"))
        ));
    }

    #[test]
    fn parse_rejects_wrong_message_id() {
        let mut bad = KexInit::ours(&mut rng(), false).payload;
        bad[0] = msg::NEWKEYS;
        assert!(matches!(KexInit::parse(&bad), Err(SshError::Protocol(_))));
    }
}
