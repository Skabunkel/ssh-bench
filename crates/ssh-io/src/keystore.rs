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

/// Trusted host keys (a `known_hosts` file). Host-pattern matching is not implemented;
/// any line's key is trusted, which suits a single-host client.
#[derive(Default, Clone)]
pub struct KnownHosts {
    keys: Vec<HostPublicKey>,
}

impl KnownHosts {
    /// Parse `known_hosts` content (`<host> <algo> <base64> [comment]` per line).
    pub fn parse(contents: &str) -> Self {
        let mut keys = Vec::new();
        for line in contents.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            // Drop the leading host field, leaving the `<algo> <base64> [comment]` key.
            if let Some((_host, key_part)) = trimmed.split_once(char::is_whitespace)
                && let Some(key) = host_key_from_openssh(key_part.trim())
            {
                keys.push(key);
            }
        }
        Self { keys }
    }

    /// Load and parse a `known_hosts` file.
    pub fn load(path: impl AsRef<Path>) -> std::io::Result<Self> {
        Ok(Self::parse(&std::fs::read_to_string(path)?))
    }

    /// Whether `key` is a trusted host key.
    pub fn contains(&self, key: &HostPublicKey) -> bool {
        self.keys.iter().any(|k| k == key)
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// Load a server [`HostKey`] from an OpenSSH-format private key file at `path`.
pub fn load_host_key(path: impl AsRef<Path>) -> io::Result<HostKey> {
    let pem = std::fs::read_to_string(path)?;
    HostKey::from_openssh(&pem).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
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
        Ok(pem) => {
            HostKey::from_openssh(&pem).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        }
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
        let KeyData::Ed25519(ed) = parsed.key_data() else { panic!() };
        let key = UserPublicKey::from_ed25519_bytes(&ed.0).unwrap();
        assert!(store.contains(&key));
    }

    #[test]
    fn known_hosts_strips_host_field() {
        let store = KnownHosts::parse(&format!("[127.0.0.1]:2222 {PUBKEY}\n"));
        assert!(!store.is_empty());
    }

    #[test]
    fn rejects_unparsable_lines() {
        let store = AuthorizedKeys::parse("not a key\nssh-rsa AAAAfake\n");
        assert!(store.is_empty());
    }
}
