//! **Infra** layer: drives a sans-IO SSH session over a `tokio` socket.
//!
//! [`Driver`] is generic over any [`Session`] (the client/server connection types from
//! [`ssh_transport`]), translating between socket byte I/O and the session's
//! `on_input` / `take_output` / `poll_event` interface.
//!
//! For servers, [`serve`] runs the whole connection and dispatches commands to an
//! [`ExecContext`] of in-process [`ExecHandler`]s.

pub mod exec;
pub mod keystore;
pub mod limits;
pub mod policy;
mod serve;
pub mod system;

pub use exec::{
    ChannelSession, ExecContext, ExecHandler, HandlerFuture, SessionReader, SessionWriter,
};
pub use keystore::{
    AuthorizedKeys, KnownHosts, load_host_key, load_or_create_host_key, save_host_key,
};
pub use limits::{ConnectionGuard, ConnectionLimiter, RateLimiter};
pub use policy::{
    AllowAll, ConnectionDecision, ConnectionPolicy, Fail2Ban, NoRetryReaction, RetryPolicy,
};
pub use serve::{ServeConfig, serve, serve_with};
pub use system::SystemRunner;

use std::io;

use ssh_transport::SshError;
use ssh_transport::client::{ClientAuthHandler, ClientConnection, ClientEvent};
use ssh_transport::rand_core::{CryptoRng, RngCore};
use ssh_transport::server::{ServerAuthHandler, ServerConnection, ServerEvent};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

/// A sans-IO SSH session that the [`Driver`] can pump over a socket.
pub trait Session {
    type Event;
    fn on_input(&mut self, data: &[u8]) -> Result<(), SshError>;
    fn take_output(&mut self) -> Vec<u8>;
    fn poll_event(&mut self) -> Option<Self::Event>;
}

impl<R: RngCore + CryptoRng, H: ClientAuthHandler> Session for ClientConnection<R, H> {
    type Event = ClientEvent;
    fn on_input(&mut self, data: &[u8]) -> Result<(), SshError> {
        ClientConnection::on_input(self, data)
    }
    fn take_output(&mut self) -> Vec<u8> {
        ClientConnection::take_output(self)
    }
    fn poll_event(&mut self) -> Option<ClientEvent> {
        ClientConnection::poll_event(self)
    }
}

impl<R: RngCore + CryptoRng, H: ServerAuthHandler> Session for ServerConnection<R, H> {
    type Event = ServerEvent;
    fn on_input(&mut self, data: &[u8]) -> Result<(), SshError> {
        ServerConnection::on_input(self, data)
    }
    fn take_output(&mut self) -> Vec<u8> {
        ServerConnection::take_output(self)
    }
    fn poll_event(&mut self) -> Option<ServerEvent> {
        ServerConnection::poll_event(self)
    }
}

/// Drives a [`Session`] over any byte stream. `T` defaults to [`TcpStream`] so existing
/// `Driver<S>` references keep working, but any `AsyncRead + AsyncWrite` transport (e.g.
/// `tokio::io::duplex` in tests, or a TLS stream) can be used instead.
pub struct Driver<S: Session, T = TcpStream> {
    stream: T,
    session: S,
    read_buf: Box<[u8; 32768]>,
}

impl<S: Session, T: AsyncRead + AsyncWrite + Unpin> Driver<S, T> {
    pub fn new(stream: T, session: S) -> Self {
        Self {
            stream,
            session,
            read_buf: Box::new([0u8; 32768]),
        }
    }

    pub fn session_mut(&mut self) -> &mut S {
        &mut self.session
    }

    /// Flush any bytes the session has queued for transmission.
    pub async fn flush(&mut self) -> io::Result<()> {
        let out = self.session.take_output();
        if !out.is_empty() {
            self.stream.write_all(&out).await?;
            self.stream.flush().await?;
        }
        Ok(())
    }

    /// Perform a single socket read and feed it to the session. Returns `Ok(false)` on
    /// EOF — including an abrupt reset by the peer, which is a normal way for clients to
    /// hang up. Use this when the caller needs to `select!` socket reads against other
    /// I/O (e.g. a child process), draining events via [`Self::session_mut`] afterwards.
    pub async fn read_once(&mut self) -> Result<bool, DriveError> {
        let n = match self.stream.read(&mut self.read_buf[..]).await {
            Ok(n) => n,
            Err(e) if is_disconnect(&e) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        if n == 0 {
            return Ok(false);
        }
        self.session.on_input(&self.read_buf[..n])?;
        Ok(true)
    }

    /// Drive until the next session event, performing socket I/O as needed. Returns
    /// `Ok(None)` on clean EOF.
    pub async fn next_event(&mut self) -> Result<Option<S::Event>, DriveError> {
        loop {
            if let Some(event) = self.session.poll_event() {
                self.flush().await?;
                return Ok(Some(event));
            }
            self.flush().await?;
            let n = match self.stream.read(&mut self.read_buf[..]).await {
                Ok(n) => n,
                Err(e) if is_disconnect(&e) => return Ok(None),
                Err(e) => return Err(e.into()),
            };
            if n == 0 {
                return Ok(None);
            }
            self.session.on_input(&self.read_buf[..n])?;
        }
    }
}

/// Whether an I/O error is an ordinary peer hang-up (abrupt TCP reset/abort) rather
/// than a real failure — treated as a clean EOF.
fn is_disconnect(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
            | io::ErrorKind::UnexpectedEof
    )
}

/// Errors from driving a connection: socket I/O or a protocol error.
#[derive(Debug)]
pub enum DriveError {
    Io(io::Error),
    Protocol(SshError),
    UnexpectedEof,
}

impl std::fmt::Display for DriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DriveError::Io(e) => write!(f, "io error: {e}"),
            DriveError::Protocol(e) => write!(f, "protocol error: {e}"),
            DriveError::UnexpectedEof => write!(f, "connection closed during handshake"),
        }
    }
}

impl std::error::Error for DriveError {}

impl From<io::Error> for DriveError {
    fn from(e: io::Error) -> Self {
        DriveError::Io(e)
    }
}

impl From<SshError> for DriveError {
    fn from(e: SshError) -> Self {
        DriveError::Protocol(e)
    }
}
