//! Reader/writer for the SSH wire data types defined in RFC 4251 §5
//! (`byte`, `boolean`, `uint32`, `uint64`, `string`, `mpint`, `name-list`).
//!
//! Protocol messages are framed by hand here rather than via `ssh-encoding`'s trait
//! machinery so the byte layout of every message — which feeds directly into the
//! exchange hash — is explicit and auditable. `ssh-key`/`ssh-encoding` are still used
//! for key and signature *blobs*.

use crate::{Result, SshError};

/// Cursor over a borrowed byte buffer that decodes SSH primitives.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> &'a [u8] {
        &self.buf[self.pos..]
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(SshError::Encoding("length overflow"))?;
        if end > self.buf.len() {
            return Err(SshError::Encoding("unexpected end of buffer"));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    pub fn boolean(&mut self) -> Result<bool> {
        // RFC 4251: any non-zero value is interpreted as true.
        Ok(self.u8()? != 0)
    }

    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    /// A `string`: a `uint32` length followed by that many bytes (returned borrowed).
    pub fn string(&mut self) -> Result<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    /// A `string` that must be valid UTF-8 (e.g. user names, algorithm names).
    pub fn utf8(&mut self) -> Result<&'a str> {
        core::str::from_utf8(self.string()?).map_err(|_| SshError::Encoding("invalid utf-8"))
    }

    /// An `mpint`, returned as the raw (signed, two's-complement) bytes on the wire.
    /// Callers that want the unsigned magnitude should strip a single leading `0x00`.
    pub fn mpint(&mut self) -> Result<&'a [u8]> {
        self.string()
    }

    /// A `name-list`: a `string` of comma-separated US-ASCII names.
    pub fn name_list(&mut self) -> Result<Vec<Box<str>>> {
        let s = self.string()?;
        if s.is_empty() {
            return Ok(Vec::new());
        }
        if !s.is_ascii() {
            return Err(SshError::Encoding("non-ascii name-list"));
        }
        // SAFETY-free: we just checked the bytes are ASCII, hence valid UTF-8.
        let s = core::str::from_utf8(s).map_err(|_| SshError::Encoding("invalid name-list"))?;
        Ok(s.split(',').map(Box::from).collect())
    }
}

/// Appends SSH primitives to an owned byte buffer.
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer::default()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn boolean(&mut self, v: bool) {
        self.buf.push(v as u8);
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Raw bytes with no length prefix.
    pub fn raw(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// A `string`: `uint32` length prefix followed by the bytes.
    pub fn string(&mut self, bytes: &[u8]) {
        self.u32(bytes.len() as u32);
        self.buf.extend_from_slice(bytes);
    }

    /// A `name-list` built from individual names.
    pub fn name_list(&mut self, names: &[&str]) {
        let joined = names.join(",");
        self.string(joined.as_bytes());
    }

    /// An `mpint` from an unsigned big-endian magnitude: leading zero bytes are
    /// trimmed and a single `0x00` is prepended if the top bit would otherwise be set
    /// (so the value is never misread as negative). Zero encodes as an empty string.
    pub fn mpint(&mut self, magnitude: &[u8]) {
        let first_nonzero = magnitude.iter().position(|&b| b != 0);
        match first_nonzero {
            None => self.u32(0), // value is zero
            Some(start) => {
                let mag = &magnitude[start..];
                if mag[0] & 0x80 != 0 {
                    self.u32((mag.len() + 1) as u32);
                    self.u8(0);
                    self.raw(mag);
                } else {
                    self.string(mag);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_scalars() {
        let mut w = Writer::new();
        w.u8(0x7f);
        w.boolean(true);
        w.u32(0xdead_beef);
        w.u64(0x0123_4567_89ab_cdef);
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8().unwrap(), 0x7f);
        assert!(r.boolean().unwrap());
        assert_eq!(r.u32().unwrap(), 0xdead_beef);
        assert_eq!(r.u64().unwrap(), 0x0123_4567_89ab_cdef);
        assert!(r.is_empty());
    }

    #[test]
    fn roundtrip_string_and_name_list() {
        let mut w = Writer::new();
        w.string(b"hello");
        w.name_list(&["curve25519-sha256", "ssh-ed25519"]);
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.string().unwrap(), b"hello");
        assert_eq!(
            r.name_list().unwrap(),
            vec![
                Box::<str>::from("curve25519-sha256"),
                Box::<str>::from("ssh-ed25519")
            ]
        );
    }

    #[test]
    fn empty_name_list_is_empty_vec() {
        let mut w = Writer::new();
        w.name_list(&[]);
        let bytes = w.into_bytes();
        // An empty name-list is a string of length 0.
        assert_eq!(bytes, vec![0, 0, 0, 0]);
        let mut r = Reader::new(&bytes);
        assert!(r.name_list().unwrap().is_empty());
    }

    #[test]
    fn mpint_prepends_zero_when_high_bit_set() {
        // 0x80 has its high bit set, so it must be encoded as 00 80.
        let mut w = Writer::new();
        w.mpint(&[0x80]);
        assert_eq!(w.into_bytes(), vec![0, 0, 0, 2, 0x00, 0x80]);
    }

    #[test]
    fn mpint_trims_leading_zeros() {
        let mut w = Writer::new();
        w.mpint(&[0x00, 0x00, 0x09, 0xa3]);
        assert_eq!(w.into_bytes(), vec![0, 0, 0, 2, 0x09, 0xa3]);
    }

    #[test]
    fn mpint_zero_is_empty() {
        let mut w = Writer::new();
        w.mpint(&[0x00, 0x00]);
        assert_eq!(w.into_bytes(), vec![0, 0, 0, 0]);
    }

    #[test]
    fn reader_rejects_truncated_string() {
        let buf = [0, 0, 0, 8, 1, 2, 3]; // claims 8 bytes, only 3 present
        let mut r = Reader::new(&buf);
        assert!(matches!(r.string(), Err(SshError::Encoding(_))));
    }
}
