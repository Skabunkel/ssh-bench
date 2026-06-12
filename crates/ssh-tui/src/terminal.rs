//! [`SshTerminal`]: a ratatui [`Terminal`] wired to an SSH channel.
//!
//! Owns the alternate-screen lifecycle, sends each rendered frame as channel writes
//! (drawing inherits the session's output budget, so a stalled client pauses rendering
//! instead of growing buffers), and feeds `window-change` resizes to ratatui.

use std::io;

use ratatui::{Frame, Terminal};
use ssh_io::SessionWriter;

use crate::backend::SshBackend;

/// Enter the alternate screen so the app owns the display and the client's scrollback
/// is restored afterwards.
const ENTER: &[u8] = b"\x1b[?1049h\x1b[2J\x1b[H";
/// Undo everything an app might leave behind: stray SGR state, hidden cursor, alt screen.
const LEAVE: &[u8] = b"\x1b[0m\x1b[?1049l\x1b[?25h";

/// A full-screen ratatui terminal for an SSH channel session.
///
/// Construction switches the client to the alternate screen; call [`Self::restore`]
/// before returning from the handler so the user gets their scrollback and cursor back
/// (a dropped connection skips this gracefully — the writes just fail).
///
/// ```ignore
/// let Some(pty) = session.pty().cloned() else { /* no PTY: bail with a hint */ };
/// let mut resize = session.resize_events();
/// let (mut reader, writer) = session.split();
/// let mut terminal = SshTerminal::new(writer, (pty.cols, pty.rows)).await?;
/// loop {
///     terminal.draw(|frame| ui(frame, &state)).await?;
///     tokio::select! {
///         read = reader.read(&mut buf) => { /* InputParser::feed → update state */ }
///         _ = resize.changed() => terminal.resize(*resize.borrow_and_update()),
///     }
/// }
/// terminal.restore().await?;
/// ```
pub struct SshTerminal {
    terminal: Terminal<SshBackend>,
    writer: SessionWriter,
}

impl SshTerminal {
    /// Set up a full-screen terminal of the given size (use the granted PTY's
    /// `(cols, rows)`) and switch the client to the alternate screen.
    pub async fn new(writer: SessionWriter, (cols, rows): (u16, u16)) -> io::Result<Self> {
        let terminal = Terminal::new(SshBackend::new(cols, rows))?;
        writer.write_stdout(ENTER).await?;
        Ok(Self { terminal, writer })
    }

    /// Render one frame and send it to the client. The closure draws into the frame
    /// exactly as with any ratatui terminal; only the diff against the previous frame
    /// goes over the wire.
    pub async fn draw<F>(&mut self, render: F) -> io::Result<()>
    where
        F: FnOnce(&mut Frame),
    {
        self.terminal.draw(render)?;
        let frame = self.terminal.backend_mut().take_frame();
        self.writer.write_stdout(&frame).await
    }

    /// Apply a `window-change`. The next [`Self::draw`] repaints at the new size.
    pub fn resize(&mut self, (cols, rows): (u16, u16)) {
        self.terminal.backend_mut().set_size(cols, rows);
    }

    /// Leave the alternate screen and restore the cursor. Call on the way out of the
    /// handler; ignore the result if the client may already be gone.
    pub async fn restore(self) -> io::Result<()> {
        self.writer.write_stdout(LEAVE).await
    }

    /// The underlying ratatui terminal, for APIs this wrapper doesn't surface
    /// (cursor control, viewport queries, …). Bytes any operation queues in the
    /// backend are sent with the next [`Self::draw`].
    pub fn terminal_mut(&mut self) -> &mut Terminal<SshBackend> {
        &mut self.terminal
    }
}
