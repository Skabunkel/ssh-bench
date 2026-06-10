//! In-process command handlers and the context that routes to them.
//!
//! An [`ExecContext`] is a registry of [`ExecHandler`]s keyed by command name. A handler
//! runs arbitrary async logic against a [`ChannelSession`] (an `AsyncRead` + `AsyncWrite`
//! duplex with a stderr side-channel) and returns an exit status — enough to implement
//! sftp, git, rsync, a virtual shell, etc. entirely in-process.
//!
//! A context grants **no system access of its own**: only the commands you register can
//! run. Process spawning, if wanted, is itself just a handler (see [`crate::system`]).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Output produced by a handler, routed back to the SSH channel by the serve loop.
pub(crate) enum Outbound {
    Stdout(Vec<u8>),
    Stderr(Vec<u8>),
    Exit(u32),
}

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
}

impl ChannelSession {
    pub(crate) fn new(
        stdin: mpsc::UnboundedReceiver<Vec<u8>>,
        out: mpsc::UnboundedSender<Outbound>,
    ) -> Self {
        Self {
            reader: SessionReader {
                stdin,
                chunk: Vec::new(),
                pos: 0,
            },
            writer: SessionWriter { out },
        }
    }

    /// Split into independent read and write halves (useful for bidirectional pumping).
    pub fn split(self) -> (SessionReader, SessionWriter) {
        (self.reader, self.writer)
    }

    /// Write to the channel's stderr (SSH extended data).
    pub fn write_stderr(&self, data: &[u8]) {
        self.writer.write_stderr(data);
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
        Poll::Ready(Ok(()))
    }
}

/// The write half of a [`ChannelSession`] (handler → client). Cloneable and cheap.
#[derive(Clone)]
pub struct SessionWriter {
    out: mpsc::UnboundedSender<Outbound>,
}

impl SessionWriter {
    /// Write to the channel's stdout.
    pub fn write_stdout(&self, data: &[u8]) {
        let _ = self.out.send(Outbound::Stdout(data.to_vec()));
    }

    /// Write to the channel's stderr (SSH extended data).
    pub fn write_stderr(&self, data: &[u8]) {
        let _ = self.out.send(Outbound::Stderr(data.to_vec()));
    }

    /// Resolves once the channel has gone away — the serve loop dropped its receiver,
    /// e.g. on disconnect. A handler can await this to stop work and tear down promptly
    /// (so a spawned process is not orphaned when the client disconnects).
    pub async fn closed(&self) {
        self.out.closed().await;
    }
}

impl AsyncWrite for SessionWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.out.send(Outbound::Stdout(data.to_vec())) {
            Ok(()) => Poll::Ready(Ok(data.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "channel closed",
            ))),
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
