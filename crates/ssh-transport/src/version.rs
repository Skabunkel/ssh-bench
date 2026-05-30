//! SSH protocol version (identification string) exchange, RFC 4253 §4.2.
//!
//! Each side sends a single line `SSH-2.0-<softwareversion>[ <comments>]` terminated
//! by CR LF. The server may precede it with arbitrary banner lines; the client must
//! tolerate and skip them. The identification line (without CR LF) is fed verbatim
//! into the key-exchange hash, so we preserve the exact bytes.

use crate::{Result, SshError};

/// Our software identification, without the trailing CR LF.
pub const LOCAL_ID: &str = "SSH-2.0-rust_ssh_0.1.0";

/// Maximum length of a single line including CR LF (RFC 4253 §4.2).
const MAX_LINE: usize = 255;

/// The peer's parsed identification line (the `SSH-2.0-...` bytes, no CR LF).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerId {
    pub raw: Vec<u8>,
}

/// Bytes to send for our identification line, including the terminating CR LF.
pub fn local_id_line() -> Vec<u8> {
    let mut v = Vec::with_capacity(LOCAL_ID.len() + 2);
    v.extend_from_slice(LOCAL_ID.as_bytes());
    v.extend_from_slice(b"\r\n");
    v
}

/// Attempt to parse the peer identification from a receive buffer.
///
/// Returns `Ok(Some((peer, consumed)))` once a full `SSH-2.0`/`SSH-1.99` line has
/// arrived (`consumed` bytes should be drained from the buffer), `Ok(None)` if more
/// bytes are needed, or an error for a malformed or over-long line.
///
/// `allow_banner` should be `true` for the client (servers may emit banner lines
/// before their identification) and `false` for the server.
pub fn parse_peer_id(buf: &[u8], allow_banner: bool) -> Result<Option<(PeerId, usize)>> {
    let mut start = 0;
    loop {
        let Some(rel_nl) = buf[start..].iter().position(|&b| b == b'\n') else {
            // No complete line yet; guard against an unbounded pre-identification flood.
            if buf.len() - start > MAX_LINE * 64 {
                return Err(SshError::BadVersion("banner too long"));
            }
            return Ok(None);
        };
        let nl = start + rel_nl;
        if nl - start + 1 > MAX_LINE {
            return Err(SshError::BadVersion("identification line too long"));
        }
        // Line content without the LF, and without a preceding CR if present.
        let mut line_end = nl;
        if line_end > start && buf[line_end - 1] == b'\r' {
            line_end -= 1;
        }
        let line = &buf[start..line_end];

        if line.starts_with(b"SSH-2.0-") || line.starts_with(b"SSH-1.99-") {
            return Ok(Some((PeerId { raw: line.to_vec() }, nl + 1)));
        }

        if !allow_banner {
            return Err(SshError::BadVersion("expected SSH identification string"));
        }
        // Skip this banner line and look for the next one.
        start = nl + 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_identification() {
        let buf = b"SSH-2.0-OpenSSH_9.6\r\n";
        let (peer, consumed) = parse_peer_id(buf, true).unwrap().unwrap();
        assert_eq!(peer.raw, b"SSH-2.0-OpenSSH_9.6");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn tolerates_lf_without_cr() {
        let buf = b"SSH-2.0-foo\n";
        let (peer, consumed) = parse_peer_id(buf, true).unwrap().unwrap();
        assert_eq!(peer.raw, b"SSH-2.0-foo");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn client_skips_banner_lines() {
        let buf = b"hello there\r\nlegal notice\r\nSSH-2.0-OpenSSH_9.6\r\n";
        let (peer, consumed) = parse_peer_id(buf, true).unwrap().unwrap();
        assert_eq!(peer.raw, b"SSH-2.0-OpenSSH_9.6");
        assert_eq!(consumed, buf.len());
    }

    #[test]
    fn server_rejects_banner_lines() {
        let buf = b"garbage\r\nSSH-2.0-x\r\n";
        assert!(matches!(
            parse_peer_id(buf, false),
            Err(SshError::BadVersion(_))
        ));
    }

    #[test]
    fn needs_more_bytes_when_incomplete() {
        let buf = b"SSH-2.0-OpenSSH_9.6";
        assert_eq!(parse_peer_id(buf, true).unwrap(), None);
    }

    #[test]
    fn local_id_line_is_crlf_terminated() {
        assert_eq!(local_id_line(), b"SSH-2.0-rust_ssh_0.1.0\r\n");
    }
}
