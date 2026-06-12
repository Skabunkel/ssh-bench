//! Terminal input parsing: raw bytes from the SSH channel → [`KeyEvent`]s.
//!
//! With a PTY granted, the client terminal is in raw mode and sends keystrokes as bytes:
//! printable characters as UTF-8, control keys as C0 bytes, and special keys (arrows,
//! function keys, …) as escape sequences. [`InputParser`] decodes the common xterm-style
//! encodings, buffering partial sequences across reads.

use std::ops::BitOr;

/// A decoded key press.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub code: KeyCode,
    pub modifiers: KeyModifiers,
}

impl KeyEvent {
    pub const fn new(code: KeyCode, modifiers: KeyModifiers) -> Self {
        Self { code, modifiers }
    }

    pub const fn plain(code: KeyCode) -> Self {
        Self::new(code, KeyModifiers::NONE)
    }

    /// `Ctrl-C` — the interrupt convention. In raw mode this arrives as a plain `0x03`
    /// byte, not a signal; handlers that want the usual behaviour must check for it.
    pub fn is_interrupt(&self) -> bool {
        self.code == KeyCode::Char('c') && self.modifiers.contains(KeyModifiers::CTRL)
    }
}

/// Which key was pressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    Char(char),
    Enter,
    Tab,
    /// Shift-Tab (`CSI Z`).
    BackTab,
    Backspace,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Insert,
    Delete,
    /// Function key (1-based: `F(1)` is F1).
    F(u8),
}

/// Modifier keys held during a [`KeyEvent`], as reported by the terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct KeyModifiers(u8);

impl KeyModifiers {
    pub const NONE: Self = Self(0);
    pub const SHIFT: Self = Self(1);
    pub const ALT: Self = Self(2);
    pub const CTRL: Self = Self(4);

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// xterm encodes modifiers in CSI params as `value = 1 + bitfield` with
    /// bit 0 = shift, bit 1 = alt, bit 2 = ctrl.
    fn from_csi_param(param: u16) -> Self {
        Self((param.saturating_sub(1) & 0b111) as u8)
    }
}

impl BitOr for KeyModifiers {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

/// Incremental decoder for raw terminal input.
///
/// Feed it the chunks read from the channel; it returns the completed key events and
/// keeps incomplete trailing sequences (a split escape sequence or UTF-8 character)
/// buffered for the next feed. Unrecognized-but-complete sequences are discarded so
/// unsupported keys produce nothing rather than garbage `Char` events.
#[derive(Default)]
pub struct InputParser {
    pending: Vec<u8>,
}

/// Outcome of trying to decode one key at the front of the buffer.
enum Step {
    /// Decoded a key using this many bytes.
    Key(usize, KeyEvent),
    /// Recognized and consumed this many bytes, but they map to no key we report.
    Skip(usize),
    /// The buffer ends mid-sequence; wait for more input.
    Incomplete,
}

impl InputParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Decode `bytes` (appended to any buffered partial sequence) into key events.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<KeyEvent> {
        self.pending.extend_from_slice(bytes);
        let mut events = Vec::new();
        let mut at = 0;
        while at < self.pending.len() {
            match step(&self.pending[at..]) {
                Step::Key(n, event) => {
                    events.push(event);
                    at += n;
                }
                Step::Skip(n) => at += n,
                Step::Incomplete => break,
            }
        }
        self.pending.drain(..at);
        events
    }
}

fn step(buf: &[u8]) -> Step {
    match buf[0] {
        0x1b => esc(buf),
        b => match control(b) {
            Some(event) => Step::Key(1, event),
            None => utf8(buf),
        },
    }
}

/// C0 control bytes and DEL. Returns `None` for printable/UTF-8 bytes.
fn control(b: u8) -> Option<KeyEvent> {
    let ctrl = |c: char| KeyEvent::new(KeyCode::Char(c), KeyModifiers::CTRL);
    Some(match b {
        0x0d | 0x0a => KeyEvent::plain(KeyCode::Enter),
        0x09 => KeyEvent::plain(KeyCode::Tab),
        0x08 | 0x7f => KeyEvent::plain(KeyCode::Backspace),
        0x00 => ctrl(' '),
        // Ctrl-A .. Ctrl-Z (minus the keys above that share encodings).
        b @ 0x01..=0x1a => ctrl((b'a' + b - 1) as char),
        0x1c => ctrl('\\'),
        0x1d => ctrl(']'),
        0x1e => ctrl('^'),
        0x1f => ctrl('_'),
        _ => return None,
    })
}

/// Escape-introduced input: a lone Esc press, `CSI`/`SS3` sequences, or Alt+key.
fn esc(buf: &[u8]) -> Step {
    match buf.get(1) {
        // Nothing after ESC in this read. Terminals send a complete sequence per
        // keystroke (and SSH preserves the write), so a trailing lone ESC is the Esc
        // key, not a split sequence worth stalling on.
        None => Step::Key(1, KeyEvent::plain(KeyCode::Esc)),
        Some(b'[') => csi(buf),
        Some(b'O') => ss3(buf),
        Some(0x1b) => Step::Key(1, KeyEvent::plain(KeyCode::Esc)),
        // ESC + key = Alt+key (terminal "meta sends escape" convention).
        Some(_) => match step(&buf[1..]) {
            Step::Key(n, mut event) => {
                event.modifiers = event.modifiers | KeyModifiers::ALT;
                Step::Key(n + 1, event)
            }
            Step::Skip(n) => Step::Skip(n + 1),
            Step::Incomplete => Step::Incomplete,
        },
    }
}

/// `ESC [ params… final` — arrows, Home/End, and the `~`-terminated key codes.
fn csi(buf: &[u8]) -> Step {
    // Find the final byte (0x40..=0x7e ends a CSI sequence).
    let Some(end) = buf[2..].iter().position(|b| (0x40..=0x7e).contains(b)) else {
        return Step::Incomplete;
    };
    let (params_raw, final_byte) = (&buf[2..2 + end], buf[2 + end]);
    let len = end + 3;

    let mut params = params_raw
        .split(|&b| b == b';')
        .map(|p| std::str::from_utf8(p).ok()?.parse::<u16>().ok());
    let first = params.next().flatten();
    let modifiers = params
        .next()
        .flatten()
        .map(KeyModifiers::from_csi_param)
        .unwrap_or(KeyModifiers::NONE);

    let code = match final_byte {
        b'A' => KeyCode::Up,
        b'B' => KeyCode::Down,
        b'C' => KeyCode::Right,
        b'D' => KeyCode::Left,
        b'H' => KeyCode::Home,
        b'F' => KeyCode::End,
        b'Z' => return Step::Key(len, KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT)),
        b'~' => match first {
            Some(1) | Some(7) => KeyCode::Home,
            Some(2) => KeyCode::Insert,
            Some(3) => KeyCode::Delete,
            Some(4) | Some(8) => KeyCode::End,
            Some(5) => KeyCode::PageUp,
            Some(6) => KeyCode::PageDown,
            Some(n @ 11..=15) => KeyCode::F((n - 10) as u8),
            Some(n @ 17..=21) => KeyCode::F((n - 11) as u8),
            Some(n @ 23..=24) => KeyCode::F((n - 12) as u8),
            _ => return Step::Skip(len),
        },
        // Anything else (mouse reports, focus events, …) is consumed silently.
        _ => return Step::Skip(len),
    };
    Step::Key(len, KeyEvent::new(code, modifiers))
}

/// `ESC O final` — SS3 encodings: F1-F4 and application-mode arrows.
fn ss3(buf: &[u8]) -> Step {
    let Some(&final_byte) = buf.get(2) else {
        return Step::Incomplete;
    };
    let code = match final_byte {
        b'A' => KeyCode::Up,
        b'B' => KeyCode::Down,
        b'C' => KeyCode::Right,
        b'D' => KeyCode::Left,
        b'H' => KeyCode::Home,
        b'F' => KeyCode::End,
        b'P' => KeyCode::F(1),
        b'Q' => KeyCode::F(2),
        b'R' => KeyCode::F(3),
        b'S' => KeyCode::F(4),
        _ => return Step::Skip(3),
    };
    Step::Key(3, KeyEvent::plain(code))
}

/// Decode one UTF-8 character from the front of the buffer.
fn utf8(buf: &[u8]) -> Step {
    let want = match buf[0] {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        // Stray continuation or invalid lead byte: drop it and move on.
        _ => return Step::Skip(1),
    };
    if buf.len() < want {
        return Step::Incomplete;
    }
    match std::str::from_utf8(&buf[..want]) {
        Ok(s) => match s.chars().next() {
            Some(c) => Step::Key(want, KeyEvent::plain(KeyCode::Char(c))),
            None => Step::Skip(want),
        },
        Err(_) => Step::Skip(1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(bytes: &[u8]) -> Vec<KeyEvent> {
        InputParser::new().feed(bytes)
    }

    #[test]
    fn printable_ascii_and_control_keys() {
        assert_eq!(
            parse(b"hi\r"),
            vec![
                KeyEvent::plain(KeyCode::Char('h')),
                KeyEvent::plain(KeyCode::Char('i')),
                KeyEvent::plain(KeyCode::Enter),
            ]
        );
        assert_eq!(
            parse(&[0x03]),
            vec![KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CTRL)]
        );
        assert!(parse(&[0x03])[0].is_interrupt());
        assert_eq!(parse(&[0x7f]), vec![KeyEvent::plain(KeyCode::Backspace)]);
    }

    #[test]
    fn arrows_and_navigation_sequences() {
        assert_eq!(parse(b"\x1b[A"), vec![KeyEvent::plain(KeyCode::Up)]);
        assert_eq!(parse(b"\x1b[D"), vec![KeyEvent::plain(KeyCode::Left)]);
        assert_eq!(parse(b"\x1bOB"), vec![KeyEvent::plain(KeyCode::Down)]);
        assert_eq!(parse(b"\x1b[3~"), vec![KeyEvent::plain(KeyCode::Delete)]);
        assert_eq!(parse(b"\x1b[6~"), vec![KeyEvent::plain(KeyCode::PageDown)]);
        assert_eq!(parse(b"\x1b[15~"), vec![KeyEvent::plain(KeyCode::F(5))]);
        assert_eq!(parse(b"\x1bOP"), vec![KeyEvent::plain(KeyCode::F(1))]);
        assert_eq!(
            parse(b"\x1b[Z"),
            vec![KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT)]
        );
    }

    #[test]
    fn csi_modifier_parameters() {
        assert_eq!(
            parse(b"\x1b[1;5C"),
            vec![KeyEvent::new(KeyCode::Right, KeyModifiers::CTRL)]
        );
        assert_eq!(
            parse(b"\x1b[1;2A"),
            vec![KeyEvent::new(KeyCode::Up, KeyModifiers::SHIFT)]
        );
        assert_eq!(
            parse(b"\x1b[3;3~"),
            vec![KeyEvent::new(KeyCode::Delete, KeyModifiers::ALT)]
        );
    }

    #[test]
    fn alt_keys_and_lone_esc() {
        assert_eq!(
            parse(b"\x1bx"),
            vec![KeyEvent::new(KeyCode::Char('x'), KeyModifiers::ALT)]
        );
        assert_eq!(parse(b"\x1b"), vec![KeyEvent::plain(KeyCode::Esc)]);
        assert_eq!(
            parse(b"\x1b\x1b"),
            vec![KeyEvent::plain(KeyCode::Esc), KeyEvent::plain(KeyCode::Esc)]
        );
    }

    #[test]
    fn utf8_across_split_feeds() {
        let mut parser = InputParser::new();
        let bytes = "é".as_bytes(); // 2 bytes
        assert_eq!(parser.feed(&bytes[..1]), vec![]);
        assert_eq!(
            parser.feed(&bytes[1..]),
            vec![KeyEvent::plain(KeyCode::Char('é'))]
        );
        assert_eq!(
            parser.feed("🎰".as_bytes()),
            vec![KeyEvent::plain(KeyCode::Char('🎰'))]
        );
    }

    #[test]
    fn split_escape_sequence_waits_for_the_rest() {
        let mut parser = InputParser::new();
        assert_eq!(parser.feed(b"\x1b["), vec![]);
        assert_eq!(parser.feed(b"A"), vec![KeyEvent::plain(KeyCode::Up)]);
    }

    #[test]
    fn unknown_sequences_are_skipped_not_garbled() {
        // A mouse report (CSI M + 3 payload bytes we don't decode): the CSI part is
        // consumed; payload decodes as (garbage but harmless) chars — at minimum the
        // sequence must not wedge the parser.
        let mut parser = InputParser::new();
        let _ = parser.feed(b"\x1b[?1000h");
        assert_eq!(parser.feed(b"q"), vec![KeyEvent::plain(KeyCode::Char('q'))]);
        // Invalid UTF-8 is dropped byte-by-byte.
        assert_eq!(
            parse(&[0xff, 0xfe, b'a']),
            vec![KeyEvent::plain(KeyCode::Char('a'))]
        );
    }
}
