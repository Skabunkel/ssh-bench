//! In-process command handlers and the context that routes to them.
//!
//! An [`ExecContext`] is a registry of [`ExecHandler`]s keyed by command name. A handler
//! runs arbitrary async logic against a [`ChannelSession`] (an `AsyncRead` + `AsyncWrite`
//! duplex with a stderr side-channel) and returns an exit status — enough to implement
//! sftp, git, rsync, a virtual shell, etc. entirely in-process.
//!
//! A context grants **no system access of its own**: only the commands you register can
//! run. Process spawning, if wanted, is itself just a handler (see [`crate::system`]).
//!
//! Flow control: writes draw bytes from a budget the serve loop replenishes as output
//! reaches the wire, so a stalled client suspends the handler instead of growing server
//! buffers; reads report consumption back, which is what replenishes the client's SSH
//! window. Both directions therefore stay bounded end to end.

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use ssh_transport::PtyInfo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, watch};

/// Output produced by a handler, routed back to the SSH channel by the serve loop.
pub(crate) enum Outbound {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(u32),
}

/// Largest single budget reservation. Keeps any one write acquirable even against a
/// small configured budget, and matches the SSH channel max-packet size.
pub(crate) const MAX_RESERVE: usize = 32 * 1024;

/// The future returned by [`ExecHandler::run`].
pub type HandlerFuture = Pin<Box<dyn Future<Output = u32> + Send>>;

/// An in-process handler for a single exec command, subsystem, or shell.
///
/// Implement `run` to read from / write to `session` however you like and return the
/// exit status. Use `Box::pin(async move { … })` for the body; `self` is an [`Arc`] so
/// the future may hold handler state.
pub trait ExecHandler: Send + Sync + 'static {
    /// Run to completion. `command` is the full exec command line (for `exec`), the
    /// subsystem name (for a subsystem), or empty (for a shell). The returned value is
    /// the SSH exit status reported to the client.
    fn run(self: Arc<Self>, command: Box<str>, session: ChannelSession) -> HandlerFuture;
}

/// Routes SSH requests to registered [`ExecHandler`]s. A freshly-built context allows
/// nothing; register handlers to permit specific commands.
#[derive(Default, Clone)]
pub struct ExecContext {
    exec: HashMap<Box<str>, Arc<dyn ExecHandler>>,
    subsystem: HashMap<Box<str>, Arc<dyn ExecHandler>>,
    shell: Option<Arc<dyn ExecHandler>>,
    default_exec: Option<Arc<dyn ExecHandler>>,
}

impl ExecContext {
    /// An empty context: no exec commands, no subsystems, no shell — i.e. zero system
    /// access until handlers are registered.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a handler for an exact `exec` command name (matched against the first
    /// whitespace-separated token of the command line, e.g. `git-upload-pack`).
    pub fn on_exec(mut self, name: impl Into<Box<str>>, handler: impl ExecHandler) -> Self {
        self.exec.insert(name.into(), Arc::new(handler));
        self
    }

    /// Register a handler for a subsystem (e.g. `sftp`).
    pub fn on_subsystem(mut self, name: impl Into<Box<str>>, handler: impl ExecHandler) -> Self {
        self.subsystem.insert(name.into(), Arc::new(handler));
        self
    }

    /// Register the handler invoked for shell requests (a real or virtual shell). With
    /// none set, shell requests are rejected and the user is never dropped to a shell.
    pub fn on_shell(mut self, handler: impl ExecHandler) -> Self {
        self.shell = Some(Arc::new(handler));
        self
    }

    /// Register a catch-all handler for `exec` commands that match no named handler.
    /// Leave unset to reject unknown commands (the default, allowlist behaviour).
    pub fn on_unmatched_exec(mut self, handler: impl ExecHandler) -> Self {
        self.default_exec = Some(Arc::new(handler));
        self
    }

    pub(crate) fn exec_handler(&self, command: &str) -> Option<Arc<dyn ExecHandler>> {
        let name = command.split_whitespace().next().unwrap_or("");
        self.exec
            .get(name)
            .cloned()
            .or_else(|| self.default_exec.clone())
    }

    pub(crate) fn subsystem_handler(&self, name: &str) -> Option<Arc<dyn ExecHandler>> {
        self.subsystem.get(name).cloned()
    }

    pub(crate) fn shell_handler(&self) -> Option<Arc<dyn ExecHandler>> {
        self.shell.clone()
    }
}

/// A live session for a handler: read client input (stdin), write output (stdout) via
/// [`AsyncWrite`], emit stderr via [`ChannelSession::write_stderr`], and signal
/// completion by returning an exit status from the handler.
pub struct ChannelSession {
    reader: SessionReader,
    writer: SessionWriter,
    pty: Option<PtyInfo>,
    resize: watch::Receiver<(u16, u16)>,
}

impl ChannelSession {
    pub(crate) fn new(
        stdin: mpsc::UnboundedReceiver<Vec<u8>>,
        out: mpsc::UnboundedSender<Outbound>,
        budget: Arc<Semaphore>,
        consumed: watch::Sender<u64>,
        pty: Option<PtyInfo>,
        resize: watch::Receiver<(u16, u16)>,
    ) -> Self {
        Self {
            reader: SessionReader {
                stdin,
                consumed,
                chunk: Vec::new(),
                pos: 0,
            },
            writer: SessionWriter {
                out,
                budget,
                reserving: std::sync::Mutex::new(None),
            },
            pty,
            resize,
        }
    }

    /// The PTY granted to this session, if the client requested one (size as of the
    /// session start; track [`Self::resize_events`] for updates). `None` means the
    /// client is in cooked mode — full-screen rendering will look wrong there, so a
    /// TUI handler should print a hint (`ssh -t …`) and exit instead.
    pub fn pty(&self) -> Option<&PtyInfo> {
        self.pty.as_ref()
    }

    /// A watch over the terminal size, updated on every `window-change`. Grab a clone
    /// before [`Self::split`] and `select!` on `.changed()` to redraw on resize. The
    /// initial value is the granted PTY's size (or `(0, 0)` without a PTY).
    pub fn resize_events(&self) -> watch::Receiver<(u16, u16)> {
        self.resize.clone()
    }

    /// Split into independent read and write halves (useful for bidirectional pumping).
    pub fn split(self) -> (SessionReader, SessionWriter) {
        (self.reader, self.writer)
    }

    /// Write to the channel's stderr (SSH extended data). Waits for output budget, so a
    /// stalled client suspends the handler rather than growing server buffers.
    pub async fn write_stderr(&self, data: &[u8]) -> io::Result<()> {
        self.writer.write_stderr(data).await
    }
}

impl AsyncRead for ChannelSession {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChannelSession {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, data)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}

/// The read half of a [`ChannelSession`] (client → handler, i.e. stdin).
pub struct SessionReader {
    stdin: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Cumulative bytes consumed, watched by the serve loop: this is what replenishes
    /// the client's flow-control window, so unread stdin keeps the client stalled.
    consumed: watch::Sender<u64>,
    chunk: Vec<u8>,
    pos: usize,
}

impl AsyncRead for SessionReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        while me.pos >= me.chunk.len() {
            match me.stdin.poll_recv(cx) {
                Poll::Ready(Some(c)) if !c.is_empty() => {
                    me.chunk = c;
                    me.pos = 0;
                }
                Poll::Ready(Some(_)) => continue, // skip empty chunk
                Poll::Ready(None) => return Poll::Ready(Ok(())), // EOF
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = (me.chunk.len() - me.pos).min(buf.remaining());
        buf.put_slice(&me.chunk[me.pos..me.pos + n]);
        me.pos += n;
        me.consumed.send_modify(|total| *total += n as u64);
        Poll::Ready(Ok(()))
    }
}

/// An in-flight budget reservation (bytes wanted, the pending acquire).
type Reserving = (
    u32,
    Pin<Box<dyn Future<Output = Result<OwnedSemaphorePermit, AcquireError>> + Send>>,
);

/// The write half of a [`ChannelSession`] (handler → client). Cloneable and cheap.
///
/// All writes (stdout and stderr) draw bytes from a shared budget that the serve loop
/// replenishes only as output is actually flushed to the wire. A client that stops
/// reading therefore suspends the handler instead of growing server-side buffers.
pub struct SessionWriter {
    out: mpsc::UnboundedSender<Outbound>,
    budget: Arc<Semaphore>,
    /// Only touched through `&mut self` (so the lock is always uncontended); the
    /// `Mutex` exists to keep the boxed future from voiding `Sync` for the writer.
    reserving: std::sync::Mutex<Option<Reserving>>,
}

impl Clone for SessionWriter {
    fn clone(&self) -> Self {
        Self {
            out: self.out.clone(),
            budget: Arc::clone(&self.budget),
            reserving: std::sync::Mutex::new(None),
        }
    }
}

impl SessionWriter {
    /// Write to the channel's stdout. Waits for output budget (backpressure).
    pub async fn write_stdout(&self, data: &[u8]) -> io::Result<()> {
        self.reserve_and_send(data, false).await
    }

    /// Write to the channel's stderr (SSH extended data). Waits for output budget.
    pub async fn write_stderr(&self, data: &[u8]) -> io::Result<()> {
        self.reserve_and_send(data, true).await
    }

    async fn reserve_and_send(&self, data: &[u8], ext: bool) -> io::Result<()> {
        for chunk in data.chunks(MAX_RESERVE) {
            let permit = Arc::clone(&self.budget)
                .acquire_many_owned(chunk.len() as u32)
                .await
                .map_err(|_| closed())?;
            // The serve loop returns these bytes to the budget once they reach the
            // wire; the permit itself must not return them on drop.
            permit.forget();
            let item = if ext {
                Outbound::Stderr(chunk.to_vec())
            } else {
                Outbound::Stdout(chunk.to_vec())
            };
            self.out.send(item).map_err(|_| closed())?;
        }
        Ok(())
    }

    /// Resolves once the channel has gone away — the serve loop dropped its receiver,
    /// e.g. on disconnect. A handler can await this to stop work and tear down promptly
    /// (so a spawned process is not orphaned when the client disconnects).
    pub async fn closed(&self) {
        self.out.closed().await;
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "channel closed")
}

impl AsyncWrite for SessionWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let budget = Arc::clone(&me.budget);
        let reserving = me.reserving.get_mut().unwrap_or_else(|e| e.into_inner());
        if reserving.is_none() {
            let want = data.len().min(MAX_RESERVE) as u32;
            *reserving = Some((want, Box::pin(budget.acquire_many_owned(want))));
        }
        let (want, acquire) = reserving.as_mut().expect("reservation in progress");
        let permit = ready!(acquire.as_mut().poll(cx)).map_err(|_| closed())?;
        let want = *want as usize;
        *reserving = None;
        permit.forget();
        // The caller may legally retry with a different (shorter) buffer after Pending;
        // return any over-reserved bytes so the budget stays exact.
        let n = want.min(data.len());
        if n < want {
            me.budget.add_permits(want - n);
        }
        match me.out.send(Outbound::Stdout(data[..n].to_vec())) {
            Ok(()) => Poll::Ready(Ok(n)),
            Err(_) => Poll::Ready(Err(closed())),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
