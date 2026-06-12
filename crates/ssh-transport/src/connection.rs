//! Connection protocol (RFC 4254): session channels, flow-control windows, and the
//! `exec`/`shell` requests. This module holds the wire builders and a [`Channel`]
//! bookkeeping type; the client/server sessions drive the state.
//!
//! Process spawning for `exec`/`shell` is **not** here — it is I/O and belongs to the
//! Infra layer. The sessions surface request events and accept output via methods.

use std::collections::VecDeque;

use crate::msg;
use crate::wire::Writer;

/// Initial flow-control window we advertise per channel (bytes).
pub const DEFAULT_WINDOW: u32 = 1024 * 1024;
/// Maximum SSH payload we accept per channel data message.
pub const MAX_PACKET: u32 = 32768;
/// Smallest peer-advertised `maximum packet size` we will accept on a channel open. A
/// pathologically small value (e.g. 1) would force every byte of output into its own
/// channel-data packet — each a full binary-packet frame with its own AEAD tag — turning
/// a modest stream into a CPU and bandwidth amplification attack. No real client offers
/// anything near this small (OpenSSH and PuTTY use ≥16 KiB), so a tiny value is treated
/// as abuse and the channel open is refused.
pub const MIN_REMOTE_MAX_PACKET: u32 = 256;
/// The only channel type we support.
pub const CHANNEL_SESSION: &str = "session";

/// `CHANNEL_OPEN_FAILURE` reason codes (RFC 4254 §5.1).
pub mod open_failure {
    pub const ADMINISTRATIVELY_PROHIBITED: u32 = 1;
    pub const UNKNOWN_CHANNEL_TYPE: u32 = 3;
}

/// A granted `pty-req` (RFC 4254 §6.2): what the client's terminal looks like.
///
/// For in-process handlers no server-side PTY device exists — accepting the request is
/// what flips the *client's* terminal into raw mode (no local echo, no line editing),
/// which is exactly what a full-screen TUI wants. The handler then owns the screen:
/// it receives raw keystrokes and renders with escape sequences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PtyInfo {
    /// The client's `TERM` value (e.g. `xterm-256color`), for capability decisions.
    pub term: Box<str>,
    /// Terminal size in character cells (clamped to `u16`, which no real terminal
    /// exceeds; zero means the client did not know its size).
    pub cols: u16,
    pub rows: u16,
    /// Terminal size in pixels (often zero).
    pub width_px: u32,
    pub height_px: u32,
    /// The RFC 4254 §8 encoded terminal modes, kept raw. In-process handlers have no
    /// tty to apply them to; a future OS-PTY runner can decode them.
    pub modes: Vec<u8>,
}

/// One outgoing chunk awaiting flow-control window: normal stdout or stderr.
enum OutItem {
    Data(Vec<u8>),
    Ext(Vec<u8>),
}

/// Per-channel state and flow-control bookkeeping.
pub struct Channel {
    pub local_id: u32,
    pub remote_id: u32,
    /// Bytes the peer may still send us before we must replenish via WINDOW_ADJUST.
    local_window: u32,
    /// Bytes we may still send the peer.
    remote_window: u32,
    remote_max_packet: u32,
    /// Bytes received and consumed by the application, but not yet granted back to the
    /// peer via `WINDOW_ADJUST` (batched to keep adjusts infrequent).
    unacked: u32,
    /// Queued-output bytes emitted to the wire since [`Channel::take_flushed_out`].
    flushed_out: u64,
    out: VecDeque<OutItem>,
    pub sent_eof: bool,
    pub sent_close: bool,
    pub recv_close: bool,
    pub exit_status: Option<u32>,
    want_close: bool,
    want_eof: bool,
    /// The granted `pty-req`, if any (kept current by `window-change`).
    pty: Option<PtyInfo>,
}

impl Channel {
    /// A locally-initiated channel (client opening a session).
    pub fn new(local_id: u32) -> Self {
        Self {
            local_id,
            remote_id: 0,
            local_window: DEFAULT_WINDOW,
            remote_window: 0,
            remote_max_packet: 0,
            unacked: 0,
            flushed_out: 0,
            out: VecDeque::new(),
            sent_eof: false,
            sent_close: false,
            recv_close: false,
            exit_status: None,
            want_close: false,
            want_eof: false,
            pty: None,
        }
    }

    /// Record a granted `pty-req`.
    pub fn set_pty(&mut self, pty: PtyInfo) {
        self.pty = Some(pty);
    }

    /// The granted PTY, if the client requested (and was granted) one.
    pub fn pty(&self) -> Option<&PtyInfo> {
        self.pty.as_ref()
    }

    /// Apply a `window-change` to the granted PTY. Returns `false` (ignored) when no
    /// PTY was ever granted on this channel.
    pub fn update_pty_size(&mut self, cols: u16, rows: u16, width_px: u32, height_px: u32) -> bool {
        match self.pty.as_mut() {
            Some(pty) => {
                pty.cols = cols;
                pty.rows = rows;
                pty.width_px = width_px;
                pty.height_px = height_px;
                true
            }
            None => false,
        }
    }

    /// Request that the channel be closed once all queued output has drained.
    pub fn request_close(&mut self) {
        self.want_close = true;
    }

    pub fn close_requested(&self) -> bool {
        self.want_close
    }

    /// Request that EOF be sent once all queued output has drained (so buffered data is
    /// never reordered behind the EOF when the window opens late).
    pub fn request_eof(&mut self) {
        self.want_eof = true;
    }

    pub fn eof_requested(&self) -> bool {
        self.want_eof
    }

    /// Record the peer's parameters once the channel is open.
    pub fn set_remote(&mut self, remote_id: u32, remote_window: u32, remote_max_packet: u32) {
        self.remote_id = remote_id;
        self.remote_window = remote_window;
        self.remote_max_packet = remote_max_packet.max(1);
    }

    pub fn enqueue_stdout(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.out.push_back(OutItem::Data(data.to_vec()));
        }
    }

    pub fn enqueue_stderr(&mut self, data: &[u8]) {
        if !data.is_empty() {
            self.out.push_back(OutItem::Ext(data.to_vec()));
        }
    }

    pub fn add_remote_window(&mut self, n: u32) {
        self.remote_window = self.remote_window.saturating_add(n);
    }

    /// Whether all queued output has been flushed.
    pub fn out_is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Emit as many queued data messages as the remote window and max-packet allow,
    /// appending them via `emit`. Each call to `emit` receives a ready-to-send payload.
    pub fn drain_output(&mut self, mut emit: impl FnMut(Vec<u8>)) {
        while let Some(front) = self.out.front_mut() {
            let limit = self.remote_window.min(self.remote_max_packet) as usize;
            if limit == 0 {
                break;
            }
            let (is_ext, buf) = match front {
                OutItem::Data(b) => (false, b),
                OutItem::Ext(b) => (true, b),
            };
            let take = buf.len().min(limit);
            let chunk: Vec<u8> = buf.drain(..take).collect();
            if buf.is_empty() {
                self.out.pop_front();
            }
            self.remote_window -= take as u32;
            self.flushed_out += take as u64;
            if is_ext {
                emit(channel_extended_data(
                    self.remote_id,
                    msg::extended_data::STDERR,
                    &chunk,
                ));
            } else {
                emit(channel_data(self.remote_id, &chunk));
            }
        }
    }

    /// Account for `len` bytes received from the peer against the window we granted.
    /// Returns `false` if the peer sent more than its window allowed (a flow-control
    /// violation the caller must treat as fatal).
    ///
    /// Receiving data does **not** replenish the window: the window is the transport's
    /// backpressure mechanism, so it grows back only as the application consumes the
    /// data (see [`Channel::ack_incoming`]). Total unconsumed in-flight data is thereby
    /// bounded by [`DEFAULT_WINDOW`].
    pub fn consume_incoming(&mut self, len: u32) -> bool {
        if len > self.local_window {
            return false;
        }
        self.local_window -= len;
        true
    }

    /// Credit `len` bytes the application has consumed back toward the peer's window.
    /// Returns `Some(bytes_to_add)` when enough has accumulated that a `WINDOW_ADJUST`
    /// should be sent (half the window, or anything at all once the peer is stalled at
    /// a zero window so it never deadlocks behind the batching threshold).
    pub fn ack_incoming(&mut self, len: u32) -> Option<u32> {
        // Clamp so over-acking can never grow the window beyond its initial size.
        let outstanding = DEFAULT_WINDOW - self.local_window;
        self.unacked = self.unacked.saturating_add(len).min(outstanding);
        if self.unacked >= DEFAULT_WINDOW / 2 || (self.local_window == 0 && self.unacked > 0) {
            let add = core::mem::take(&mut self.unacked);
            self.local_window += add;
            Some(add)
        } else {
            None
        }
    }

    /// Bytes emitted to the wire by [`Channel::drain_output`] since the last call. Lets
    /// a driver release exactly that much of its handler-output budget (backpressure).
    pub fn take_flushed_out(&mut self) -> u64 {
        core::mem::take(&mut self.flushed_out)
    }
}

// --- message builders (recipient = the peer's channel id) ---

pub fn channel_open_session(sender_channel: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_OPEN);
    w.string(CHANNEL_SESSION.as_bytes());
    w.u32(sender_channel);
    w.u32(DEFAULT_WINDOW);
    w.u32(MAX_PACKET);
    w.into_bytes()
}

pub fn channel_open_confirmation(recipient: u32, sender: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_OPEN_CONFIRMATION);
    w.u32(recipient);
    w.u32(sender);
    w.u32(DEFAULT_WINDOW);
    w.u32(MAX_PACKET);
    w.into_bytes()
}

pub fn channel_open_failure(recipient: u32, reason: u32, description: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_OPEN_FAILURE);
    w.u32(recipient);
    w.u32(reason);
    w.string(description.as_bytes());
    w.string(b"");
    w.into_bytes()
}

pub fn channel_request_exec(recipient: u32, want_reply: bool, command: &str) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_REQUEST);
    w.u32(recipient);
    w.string(b"exec");
    w.boolean(want_reply);
    w.string(command.as_bytes());
    w.into_bytes()
}

pub fn channel_request_shell(recipient: u32, want_reply: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_REQUEST);
    w.u32(recipient);
    w.string(b"shell");
    w.boolean(want_reply);
    w.into_bytes()
}

/// `pty-req` (RFC 4254 §6.2). `pty.modes` is the raw RFC 4254 §8 encoding; an empty
/// slice becomes the bare `TTY_OP_END` terminator.
pub fn channel_request_pty(recipient: u32, want_reply: bool, pty: &PtyInfo) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_REQUEST);
    w.u32(recipient);
    w.string(b"pty-req");
    w.boolean(want_reply);
    w.string(pty.term.as_bytes());
    w.u32(pty.cols.into());
    w.u32(pty.rows.into());
    w.u32(pty.width_px);
    w.u32(pty.height_px);
    if pty.modes.is_empty() {
        w.string(&[0]); // TTY_OP_END
    } else {
        w.string(&pty.modes);
    }
    w.into_bytes()
}

/// `window-change` (RFC 4254 §6.7). Never wants a reply.
pub fn channel_request_window_change(
    recipient: u32,
    cols: u16,
    rows: u16,
    width_px: u32,
    height_px: u32,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_REQUEST);
    w.u32(recipient);
    w.string(b"window-change");
    w.boolean(false);
    w.u32(cols.into());
    w.u32(rows.into());
    w.u32(width_px);
    w.u32(height_px);
    w.into_bytes()
}

pub fn channel_request_exit_status(recipient: u32, status: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_REQUEST);
    w.u32(recipient);
    w.string(b"exit-status");
    w.boolean(false);
    w.u32(status);
    w.into_bytes()
}

pub fn channel_success(recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_SUCCESS);
    w.u32(recipient);
    w.into_bytes()
}

pub fn channel_failure(recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_FAILURE);
    w.u32(recipient);
    w.into_bytes()
}

pub fn channel_data(recipient: u32, data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_DATA);
    w.u32(recipient);
    w.string(data);
    w.into_bytes()
}

pub fn channel_extended_data(recipient: u32, data_type: u32, data: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_EXTENDED_DATA);
    w.u32(recipient);
    w.u32(data_type);
    w.string(data);
    w.into_bytes()
}

pub fn channel_window_adjust(recipient: u32, bytes_to_add: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_WINDOW_ADJUST);
    w.u32(recipient);
    w.u32(bytes_to_add);
    w.into_bytes()
}

pub fn channel_eof(recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_EOF);
    w.u32(recipient);
    w.into_bytes()
}

pub fn channel_close(recipient: u32) -> Vec<u8> {
    let mut w = Writer::new();
    w.u8(msg::CHANNEL_CLOSE);
    w.u32(recipient);
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_respects_window_and_max_packet() {
        let mut ch = Channel::new(0);
        ch.set_remote(1, 10, 4); // remote window 10, max packet 4
        ch.enqueue_stdout(&[0u8; 25]);

        let mut sent = Vec::new();
        ch.drain_output(|p| sent.push(p));
        // Window 10, max packet 4 → chunks of 4,4,2 = 10 bytes total, then stops.
        let total: usize = sent.iter().map(|p| payload_len(p)).sum();
        assert_eq!(total, 10);
        assert_eq!(sent.len(), 3);
        assert!(!ch.out_is_empty(), "15 bytes remain queued");

        // Replenish window; the rest flushes.
        ch.add_remote_window(100);
        let mut more = Vec::new();
        ch.drain_output(|p| more.push(p));
        let total2: usize = more.iter().map(|p| payload_len(p)).sum();
        assert_eq!(total2, 15);
        assert!(ch.out_is_empty());
    }

    #[test]
    fn receiving_data_does_not_replenish_the_window() {
        let mut ch = Channel::new(0);
        // The peer may send the whole window without the application consuming any of
        // it, but no further: receipt alone never grants more window (backpressure).
        assert!(ch.consume_incoming(DEFAULT_WINDOW));
        assert!(!ch.consume_incoming(1), "window must be exhausted");
    }

    #[test]
    fn consumption_replenishes_in_batches() {
        let mut ch = Channel::new(0);
        assert!(ch.consume_incoming(DEFAULT_WINDOW / 2 + 1));
        // Consuming less than half the window accumulates without an adjust.
        assert_eq!(ch.ack_incoming(DEFAULT_WINDOW / 4), None);
        // Crossing the half-window threshold grants everything accumulated back.
        assert_eq!(
            ch.ack_incoming(DEFAULT_WINDOW / 4 + 1),
            Some(DEFAULT_WINDOW / 2 + 1)
        );
        // The window is whole again.
        assert!(ch.consume_incoming(DEFAULT_WINDOW));
    }

    #[test]
    fn zero_window_unblocks_on_any_consumption() {
        let mut ch = Channel::new(0);
        assert!(ch.consume_incoming(DEFAULT_WINDOW));
        // With the peer stalled at a zero window, even a single consumed byte is
        // granted back immediately rather than waiting for the batching threshold.
        assert_eq!(ch.ack_incoming(1), Some(1));
    }

    #[test]
    fn over_acking_cannot_grow_the_window() {
        let mut ch = Channel::new(0);
        assert!(ch.consume_incoming(DEFAULT_WINDOW));
        // Acking more than was ever received is clamped to what is outstanding.
        assert_eq!(ch.ack_incoming(u32::MAX), Some(DEFAULT_WINDOW));
        // With nothing outstanding, further acks grant nothing.
        assert_eq!(ch.ack_incoming(u32::MAX), None);
        assert!(ch.consume_incoming(DEFAULT_WINDOW));
        assert!(!ch.consume_incoming(1));
    }

    #[test]
    fn incoming_window_overflow_is_a_violation() {
        let mut ch = Channel::new(0);
        // The local window starts at DEFAULT_WINDOW; sending more is a violation.
        assert!(!ch.consume_incoming(DEFAULT_WINDOW + 1));
    }

    // length of the `data`/ext payload carried by a CHANNEL_DATA/EXTENDED_DATA message
    fn payload_len(p: &[u8]) -> usize {
        use crate::wire::Reader;
        let mut r = Reader::new(p);
        let id = r.u8().unwrap();
        r.u32().unwrap(); // recipient
        if id == msg::CHANNEL_EXTENDED_DATA {
            r.u32().unwrap(); // data type
        }
        r.string().unwrap().len()
    }
}
