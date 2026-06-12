//! Ratatui-style TUIs over SSH, fully in-process.
//!
//! Bridges [`ratatui`] to an `ssh-io` [`ChannelSession`](ssh_io::ChannelSession): no OS
//! PTY, no spawned process — the handler renders frames and the client's terminal (in
//! raw mode thanks to the granted PTY) displays them.
//!
//! Three pieces:
//! - [`SshBackend`] — a ratatui `Backend` that renders ANSI bytes into a frame buffer
//!   instead of a local terminal.
//! - [`SshTerminal`] — the async wrapper: alternate-screen lifecycle, frame writes with
//!   backpressure, `window-change` resizes.
//! - [`InputParser`] — decodes the raw keystroke bytes from channel stdin into
//!   [`KeyEvent`]s.
//!
//! See `examples/slots.rs` for a complete interactive app.

mod backend;
mod input;
mod terminal;

pub use backend::SshBackend;
pub use input::{InputParser, KeyCode, KeyEvent, KeyModifiers};
pub use terminal::SshTerminal;

/// Re-exported so apps build their UI against the exact ratatui version this crate
/// links — widgets, layout, and style types all come from here.
pub use ratatui;
