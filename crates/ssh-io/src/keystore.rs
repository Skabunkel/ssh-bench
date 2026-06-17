//! Filesystem key stores: OpenSSH-format `authorized_keys` (server) and `known_hosts`
//! (client). Both parse `ssh-ed25519` entries via the `ssh-key` crate; entries in other
//! algorithms are skipped.

use std::io;
use std::path::Path;

use ssh_key::public::KeyData;
use ssh_transport::rand_core::{CryptoRng, RngCore};
use ssh_transport::{HostKey, HostPublicKey, UserPublicKey};

/// A set of user public keys permitted to authenticate (an `authorized_keys` file).
#[derive(Default, Clone)]
pub struct AuthorizedKeys {
    keys: Vec<UserPublicKey>,
}

impl AuthorizedKeys {
    /// Parse `authorized_keys` content, skipping blanks, comments, and unsupported keys.
    pub fn parse(contents: &str) -> Self {
        let mut keys = Vec::new();
        for line in contents.lines() {
            if let Some(key) = parse_user_key(line) {
                keys.push(key);
            }
        }
        Self { keys }
    }

    /// Load and parse an `authorized_keys` file.
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Ok(Self::parse(&std::fs::read_to_string(path)?))
    }

    /// Whether `key` is authorized.
    pub fn contains(&self, key: &UserPublicKey) -> bool {
        self.keys.iter().any(|k| k == key)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }
}

/// Trusted host keys parsed from a `known_hosts` file, keyed by the host field so a key
/// trusted for one host is not silently accepted for another. Matching is exact against
/// the comma-separated tokens of each line's first field (`host`, `host,host2`,
/// `[host]:port`); hashed (`|1|...`) and wildcard host patterns are not interpreted and
/// only match literally.
#[derive(Default, Clone)]
pub struct KnownHosts {
    /// `(host token, key)` pairs; a line listing several hosts expands to one pair each.
    entries: Vec<(Box<str>, HostPublicKey)>,
}

impl KnownHosts {
    /// Parse `known_hosts` content (`<host[,host...]> <algo> <base64> [comment]` per line).
    pub fn parse(contents: &str) -> Self {
        let mut entries = Vec::new();
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Split the host field from the `<algo> <base64> [comment]` key, keeping it so
            // the key stays bound to the host(s) it was recorded for.
            if let Some((hosts, key_part)) = trimmed.split_once(char::is_whitespace)
                && let Some(key) = host_key_from_openssh(key_part.trim())
            {
                for host in hosts.split(',').filter(|h| !h.is_empty()) {
                    entries.push((Box::from(host), key.clone()));
                }
            }
        }
        Self { entries }
    }

    /// Load and parse a `known_hosts` file.
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Ok(Self::parse(&std::fs::read_to_string(path)?))
    }

    /// Whether `key` is trusted *for `host`*: both the host token and the key must match.
    /// `host` must be the same string the client connects with (e.g. `127.0.0.1:2222` or
    /// `[host]:port`), since matching is literal.
    pub fn is_trusted(&self, host: &str, key: &HostPublicKey) -> bool {
        self.entries
            .iter()
            .any(|(h, k)| h.as_ref() == host && k == key)
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Load a server [`HostKey`] from an OpenSSH-format private key file at `path`.
pub fn load_host_key(path: impl AsRef<Path>) -> io::Result<HostKey> {
    let pem = std::fs::read_to_string(path)?;
    HostKey::from_openssh(&pem)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
}

/// Write `key` to `path` as an unencrypted OpenSSH-format private key. On Unix the file
/// is created with `0600` permissions so the private key is not world-readable.
pub fn save_host_key(key: &HostKey, path: impl AsRef<Path>) -> io::Result<()> {
    let pem = key
        .to_openssh()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    write_private(path.as_ref(), pem.as_bytes())
}

/// Load the host key at `path`, or — if the file does not exist — generate a fresh key,
/// persist it there, and return it. This gives a server a stable identity across runs
/// (so clients can pin it via `known_hosts`) without manual key generation.
pub fn load_or_create_host_key<R: RngCore + CryptoRng>(
    path: impl AsRef<Path>,
    rng: &mut R,
) -> io::Result<HostKey> {
    let path = path.as_ref();
    match std::fs::read_to_string(path) {
        Ok(pem) => HostKey::from_openssh(&pem)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let key = HostKey::generate(rng);
            save_host_key(&key, path)?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

/// Write private key bytes, restricting permissions to the owner where the platform
/// supports it.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        f.write_all(bytes)
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, bytes)
    }
}

fn parse_user_key(line: &str) -> Option<UserPublicKey> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let pk = ssh_key::PublicKey::from_openssh(trimmed).ok()?;
    match pk.key_data() {
        KeyData::Ed25519(ed) => UserPublicKey::from_ed25519_bytes(&ed.0).ok(),
        _ => None,
    }
}

fn host_key_from_openssh(key_part: &str) -> Option<HostPublicKey> {
    let pk = ssh_key::PublicKey::from_openssh(key_part).ok()?;
    match pk.key_data() {
        KeyData::Ed25519(ed) => HostPublicKey::from_ed25519_bytes(&ed.0).ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed ssh-ed25519 public key (generated by ssh-keygen) and its raw 32 bytes.
    const PUBKEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGNmmBF6bWlKOrl/hhf4v/+WQDISQW+PVVDAR0pQ5NHu test@example";

    #[test]
    fn authorized_keys_parses_and_matches() {
        let store = AuthorizedKeys::parse(&format!("# a comment\n\n{PUBKEY}\n"));
        assert_eq!(store.len(), 1);
        let parsed = ssh_key::PublicKey::from_openssh(PUBKEY).unwrap();
        let KeyData::Ed25519(ed) = parsed.key_data() else {
            panic!()
        };
        let key = UserPublicKey::from_ed25519_bytes(&ed.0).unwrap();
        assert!(store.contains(&key));
    }

    fn host_public_key_from_const() -> HostPublicKey {
        let parsed = ssh_key::PublicKey::from_openssh(PUBKEY).unwrap();
        let KeyData::Ed25519(ed) = parsed.key_data() else {
            panic!("test key is ed25519")
        };
        HostPublicKey::from_ed25519_bytes(&ed.0).unwrap()
    }

    #[test]
    fn known_hosts_binds_key_to_host() {
        let store = KnownHosts::parse(&format!("[127.0.0.1]:2222 {PUBKEY}\n"));
        let key = host_public_key_from_const();
        assert!(
            store.is_trusted("[127.0.0.1]:2222", &key),
            "key is trusted for the host it was recorded under"
        );
        assert!(
            !store.is_trusted("evil.example.com", &key),
            "the same key must NOT be trusted for a different host"
        );
    }

    #[test]
    fn known_hosts_supports_comma_separated_hosts() {
        let store = KnownHosts::parse(&format!("alias.local,10.0.0.5 {PUBKEY}\n"));
        let key = host_public_key_from_const();
        assert!(store.is_trusted("alias.local", &key));
        assert!(store.is_trusted("10.0.0.5", &key));
        assert!(!store.is_trusted("other.local", &key));
    }

    #[test]
    fn rejects_unparsable_lines() {
        let store = AuthorizedKeys::parse("not a key\nssh-rsa AAAAfake\n");
        assert!(store.is_empty());
    }
}
