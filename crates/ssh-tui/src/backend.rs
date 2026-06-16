//! A [`ratatui` `Backend`](Backend) that renders to an in-memory byte buffer instead of
//! a local terminal.
//!
//! Ratatui's stock backends (crossterm, termion) assume the process *owns* a terminal:
//! they query the OS for size and write to stdout. Over SSH neither holds — the terminal
//! lives on the client, its size arrives via `pty-req`/`window-change`, and output goes
//! down an SSH channel. [`SshBackend`] therefore generates the ANSI escape sequences
//! itself, accumulating each frame into a buffer that the caller (see
//! [`SshTerminal`](crate::SshTerminal)) sends as channel writes.

use std::borrow::Cow;
use std::io;

use ratatui::backend::{Backend, ClearType, WindowSize};
use ratatui::buffer::Cell;
use ratatui::layout::{Position, Size};
use ratatui::style::{Color, Modifier};

/// A ratatui backend rendering ANSI escape sequences into an in-memory frame buffer.
///
/// The terminal size is whatever the SSH peer reported: seed it from the granted
/// [`PtyInfo`](ssh_io::PtyInfo) and update it on `window-change` via [`Self::set_size`]
/// — ratatui's autoresize picks the change up on the next draw. After each
/// `Terminal::draw`, take the rendered bytes with [`Self::take_frame`] and write them to
/// the channel.
pub struct SshBackend {
    buf: Vec<u8>,
    size: Size,
    /// Where the peer's cursor is after the bytes emitted so far, when known. `None`
    /// forces an explicit cursor move before the next cell (e.g. after a symbol whose
    /// on-screen width we can't cheaply know).
    cursor: Option<Position>,
    /// SGR state currently in effect on the peer, used to skip redundant codes.
    style: (Color, Color, Modifier),
}

impl SshBackend {
    pub fn new(cols: u16, rows: u16) -> Self {
        Self {
            buf: Vec::with_capacity(4096),
            size: Size::new(cols, rows),
            cursor: None,
            style: (Color::Reset, Color::Reset, Modifier::empty()),
        }
    }

    /// Record a new terminal size (from a `window-change`). Takes effect on the next
    /// draw through ratatui's autoresize, which also clears and repaints in full.
    pub fn set_size(&mut self, cols: u16, rows: u16) {
        self.size = Size::new(cols, rows);
    }

    /// Take the bytes rendered since the last call — one frame, ready to be written to
    /// the SSH channel in a single logical write.
    pub fn take_frame(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    fn move_to(&mut self, pos: Position) {
        use std::io::Write as _;
        // ANSI cursor positions are 1-based. Write straight into the frame buffer
        // (`Vec<u8>: io::Write`), avoiding a throwaway `String` from `format!`. Writing
        // to a `Vec` is infallible.
        let _ = write!(self.buf, "\x1b[{};{}H", pos.y + 1, pos.x + 1);
        self.cursor = Some(pos);
    }

    /// Emit the SGR codes taking the peer from `self.style` to (`fg`, `bg`, `modifier`).
    /// Modifiers have no reliable "remove one" code across terminals, so any modifier
    /// change resets and rebuilds the whole style.
    fn set_style(&mut self, fg: Color, bg: Color, modifier: Modifier) {
        let (cur_fg, cur_bg, cur_mod) = self.style;
        if modifier != cur_mod {
            // The reset already put both colors at Reset; only divergent ones need codes.
            self.buf.extend_from_slice(b"\x1b[0m");
            for code in modifier_codes(modifier) {
                self.sgr(code);
            }
            if fg != Color::Reset {
                self.sgr(&fg_code(fg));
            }
            if bg != Color::Reset {
                self.sgr(&bg_code(bg));
            }
        } else {
            if fg != cur_fg {
                self.sgr(&fg_code(fg));
            }
            if bg != cur_bg {
                self.sgr(&bg_code(bg));
            }
        }
        self.style = (fg, bg, modifier);
    }

    fn sgr(&mut self, code: &str) {
        self.buf.extend_from_slice(b"\x1b[");
        self.buf.extend_from_slice(code.as_bytes());
        self.buf.push(b'm');
    }
}

fn fg_code(c: Color) -> Cow<'static, str> {
    ansi_color(c, 30, "38")
}

fn bg_code(c: Color) -> Cow<'static, str> {
    ansi_color(c, 40, "48")
}

/// SGR fragment for a color: `base` is 30 (foreground) or 40 (background), `extended`
/// the corresponding 256/true-color introducer. The 16 basic colors (and reset) resolve
/// to borrowed `&'static str` codes — no allocation in the per-cell render path; only the
/// less common `Rgb`/`Indexed` cases allocate.
fn ansi_color(c: Color, base: u8, extended: &str) -> Cow<'static, str> {
    let simple = |offset: u8| Cow::Borrowed(sgr_num(base + offset));
    let bright = |offset: u8| Cow::Borrowed(sgr_num(base + 60 + offset));
    match c {
        Color::Reset => Cow::Borrowed(sgr_num(base + 9)),
        Color::Black => simple(0),
        Color::Red => simple(1),
        Color::Green => simple(2),
        Color::Yellow => simple(3),
        Color::Blue => simple(4),
        Color::Magenta => simple(5),
        Color::Cyan => simple(6),
        Color::Gray => simple(7),
        Color::DarkGray => bright(0),
        Color::LightRed => bright(1),
        Color::LightGreen => bright(2),
        Color::LightYellow => bright(3),
        Color::LightBlue => bright(4),
        Color::LightMagenta => bright(5),
        Color::LightCyan => bright(6),
        Color::White => bright(7),
        Color::Rgb(r, g, b) => Cow::Owned(format!("{extended};2;{r};{g};{b}")),
        Color::Indexed(i) => Cow::Owned(format!("{extended};5;{i}")),
    }
}

/// The static decimal string for a basic SGR color number. The domain is fixed by
/// [`ansi_color`]: foreground 30–37/39/90–97, background 40–47/49/100–107.
fn sgr_num(n: u8) -> &'static str {
    match n {
        30 => "30",
        31 => "31",
        32 => "32",
        33 => "33",
        34 => "34",
        35 => "35",
        36 => "36",
        37 => "37",
        39 => "39",
        40 => "40",
        41 => "41",
        42 => "42",
        43 => "43",
        44 => "44",
        45 => "45",
        46 => "46",
        47 => "47",
        49 => "49",
        90 => "90",
        91 => "91",
        92 => "92",
        93 => "93",
        94 => "94",
        95 => "95",
        96 => "96",
        97 => "97",
        100 => "100",
        101 => "101",
        102 => "102",
        103 => "103",
        104 => "104",
        105 => "105",
        106 => "106",
        107 => "107",
        _ => unreachable!("ansi_color only produces basic SGR color numbers"),
    }
}

fn modifier_codes(m: Modifier) -> impl Iterator<Item = &'static str> {
    const TABLE: [(Modifier, &str); 9] = [
        (Modifier::BOLD, "1"),
        (Modifier::DIM, "2"),
        (Modifier::ITALIC, "3"),
        (Modifier::UNDERLINED, "4"),
        (Modifier::SLOW_BLINK, "5"),
        (Modifier::RAPID_BLINK, "6"),
        (Modifier::REVERSED, "7"),
        (Modifier::HIDDEN, "8"),
        (Modifier::CROSSED_OUT, "9"),
    ];
    TABLE
        .into_iter()
        .filter(move |(flag, _)| m.contains(*flag))
        .map(|(_, code)| code)
}

impl Backend for SshBackend {
    type Error = io::Error;

    fn draw<'a, I>(&mut self, content: I) -> io::Result<()>
    where
        I: Iterator<Item = (u16, u16, &'a Cell)>,
    {
        for (x, y, cell) in content {
            let pos = Position::new(x, y);
            if self.cursor != Some(pos) {
                self.move_to(pos);
            }
            self.set_style(cell.fg, cell.bg, cell.modifier);
            let symbol = cell.symbol();
            self.buf.extend_from_slice(symbol.as_bytes());
            // A single ASCII printable always advances the cursor by one column. For
            // anything else (multi-byte, wide, combining) the on-screen width isn't
            // knowable without a width table, so force an explicit move next time.
            self.cursor = match symbol.as_bytes() {
                [b] if (0x20..0x7f).contains(b) => Some(Position::new(x + 1, y)),
                _ => None,
            };
        }
        // Leave the peer in a known style so non-cell output (and the next frame's
        // diffing assumptions) can't inherit stray attributes.
        if self.style != (Color::Reset, Color::Reset, Modifier::empty()) {
            self.buf.extend_from_slice(b"\x1b[0m");
            self.style = (Color::Reset, Color::Reset, Modifier::empty());
        }
        Ok(())
    }

    fn append_lines(&mut self, n: u16) -> io::Result<()> {
        for _ in 0..n {
            self.buf.push(b'\n');
        }
        if let Some(pos) = self.cursor {
            self.cursor = Some(Position::new(
                0,
                (pos.y + n).min(self.size.height.saturating_sub(1)),
            ));
        }
        Ok(())
    }

    fn hide_cursor(&mut self) -> io::Result<()> {
        self.buf.extend_from_slice(b"\x1b[?25l");
        Ok(())
    }

    fn show_cursor(&mut self) -> io::Result<()> {
        self.buf.extend_from_slice(b"\x1b[?25h");
        Ok(())
    }

    fn get_cursor_position(&mut self) -> io::Result<Position> {
        // Querying the real cursor would mean a round-trip through the client terminal;
        // the tracked position is exact whenever we set it, and ratatui only reads this
        // for inline viewports.
        Ok(self.cursor.unwrap_or_default())
    }

    fn set_cursor_position<P: Into<Position>>(&mut self, position: P) -> io::Result<()> {
        self.move_to(position.into());
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        self.buf.extend_from_slice(b"\x1b[2J");
        Ok(())
    }

    fn clear_region(&mut self, clear_type: ClearType) -> io::Result<()> {
        self.buf.extend_from_slice(match clear_type {
            ClearType::All => b"\x1b[2J".as_slice(),
            ClearType::AfterCursor => b"\x1b[0J",
            ClearType::BeforeCursor => b"\x1b[1J",
            ClearType::CurrentLine => b"\x1b[2K",
            ClearType::UntilNewLine => b"\x1b[0K",
        });
        Ok(())
    }

    fn size(&self) -> io::Result<Size> {
        Ok(self.size)
    }

    fn window_size(&mut self) -> io::Result<WindowSize> {
        Ok(WindowSize {
            columns_rows: self.size,
            pixels: Size::new(0, 0),
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        // Bytes stay buffered until the caller takes the frame: the channel write is
        // async and happens outside the (synchronous) Backend trait.
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cell(symbol: &str) -> Cell {
        let mut c = Cell::default();
        c.set_symbol(symbol);
        c
    }

    fn drawn(backend: &mut SshBackend, content: &[(u16, u16, Cell)]) -> String {
        backend
            .draw(content.iter().map(|(x, y, c)| (*x, *y, c)))
            .unwrap();
        String::from_utf8(backend.take_frame()).unwrap()
    }

    #[test]
    fn contiguous_ascii_cells_move_the_cursor_once() {
        let mut backend = SshBackend::new(80, 24);
        let out = drawn(
            &mut backend,
            &[(3, 1, cell("h")), (4, 1, cell("i")), (5, 1, cell("!"))],
        );
        assert_eq!(out, "\x1b[2;4Hhi!");
    }

    #[test]
    fn non_contiguous_cells_emit_explicit_moves() {
        let mut backend = SshBackend::new(80, 24);
        let out = drawn(&mut backend, &[(0, 0, cell("a")), (5, 2, cell("b"))]);
        assert_eq!(out, "\x1b[1;1Ha\x1b[3;6Hb");
    }

    #[test]
    fn non_ascii_symbol_forces_a_resync_move() {
        let mut backend = SshBackend::new(80, 24);
        // "宽" is double-width: the cursor lands 2 cells later, which we don't track —
        // the next cell must re-position explicitly even though it looks contiguous.
        let out = drawn(&mut backend, &[(0, 0, cell("宽")), (2, 0, cell("x"))]);
        assert_eq!(out, "\x1b[1;1H宽\x1b[1;3Hx");
    }

    #[test]
    fn style_changes_emit_sgr_and_reset_at_frame_end() {
        let mut backend = SshBackend::new(80, 24);
        let mut red = cell("r");
        red.fg = Color::Red;
        let mut bold_blue = cell("b");
        bold_blue.fg = Color::Blue;
        bold_blue.modifier = Modifier::BOLD;
        let out = drawn(&mut backend, &[(0, 0, red), (1, 0, bold_blue)]);
        // red: fg only; bold blue: modifier changed → full reset + rebuild; frame end: reset.
        assert_eq!(out, "\x1b[1;1H\x1b[31mr\x1b[0m\x1b[1m\x1b[34mb\x1b[0m");
    }

    #[test]
    fn unchanged_style_emits_no_sgr() {
        let mut backend = SshBackend::new(80, 24);
        let mut a = cell("a");
        a.fg = Color::Green;
        let mut b = cell("b");
        b.fg = Color::Green;
        let out = drawn(&mut backend, &[(0, 0, a), (1, 0, b)]);
        assert_eq!(out, "\x1b[1;1H\x1b[32mab\x1b[0m");
    }

    #[test]
    fn rgb_and_indexed_colors_use_extended_sgr() {
        assert_eq!(fg_code(Color::Rgb(1, 2, 3)), "38;2;1;2;3");
        assert_eq!(bg_code(Color::Indexed(208)), "48;5;208");
        assert_eq!(fg_code(Color::Reset), "39");
        assert_eq!(bg_code(Color::Reset), "49");
        assert_eq!(fg_code(Color::DarkGray), "90");
        assert_eq!(bg_code(Color::White), "107");
    }

    #[test]
    fn resize_is_reported_to_ratatui_via_size() {
        let mut backend = SshBackend::new(80, 24);
        assert_eq!(backend.size().unwrap(), Size::new(80, 24));
        backend.set_size(120, 40);
        assert_eq!(backend.size().unwrap(), Size::new(120, 40));
        assert_eq!(
            backend.window_size().unwrap().columns_rows,
            Size::new(120, 40)
        );
    }
}
