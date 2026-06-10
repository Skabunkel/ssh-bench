//! High-level server loop: drives a [`ServerConnection`] over a socket and dispatches
//! exec/shell/subsystem requests to an [`ExecContext`]'s handlers.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ssh_transport::rand_core::{CryptoRng, RngCore};
use ssh_transport::server::{ServerAuthHandler, ServerConnection, ServerEvent};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::exec::{ChannelSession, ExecContext, ExecHandler, Outbound};
use crate::policy::{NoRetryReaction, RetryPolicy};
use crate::{Driver, DriveError};

/// Per-connection limits applied while serving (the connection-level DoS knobs).
#[derive(Debug, Clone, Copy)]
pub struct ServeConfig {
    /// Maximum time to reach authentication before the connection is dropped.
    pub login_timeout: Duration,
    /// Drop the connection if no bytes arrive from the peer for this long (slow-loris
    /// guard). `None` disables the idle timeout.
    pub idle_timeout: Option<Duration>,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            login_timeout: Duration::from_secs(30),
            idle_timeout: None,
        }
    }
}

/// Serve one connection to completion with default limits and no retry reactions.
/// See [`serve_with`] to supply a [`ServeConfig`], the peer address, and a [`RetryPolicy`].
pub async fn serve<IO, R, H>(
    stream: IO,
    connection: ServerConnection<R, H>,
    ctx: ExecContext,
) -> Result<(), DriveError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    R: RngCore + CryptoRng,
    H: ServerAuthHandler,
{
    serve_with(stream, connection, ctx, ServeConfig::default(), None, &NoRetryReaction).await
}

/// Serve one connection to completion: run the handshake/auth (via `connection`), then
/// route exec/shell/subsystem requests through `ctx`. Requests with no registered
/// handler are rejected, so the connection's capabilities are exactly what `ctx` allows.
///
/// `config` bounds login/idle time; `peer` (when known) is passed to the `retry` hooks so
/// a [`RetryPolicy`] can record auth outcomes (e.g. for fail2ban-style bans).
pub async fn serve_with<IO, R, H, RP>(
    stream: IO,
    connection: ServerConnection<R, H>,
    ctx: ExecContext,
    config: ServeConfig,
    peer: Option<SocketAddr>,
    retry: &RP,
) -> Result<(), DriveError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    R: RngCore + CryptoRng,
    H: ServerAuthHandler,
    RP: RetryPolicy,
{
    let mut driver = Driver::new(stream, connection);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Outbound>();
    let mut stdin_tx: Option<mpsc::UnboundedSender<Vec<u8>>> = None;
    let mut active_channel = 0u32;

    // Drop connections that don't authenticate within the grace period.
    let login_timeout = tokio::time::sleep(config.login_timeout);
    tokio::pin!(login_timeout);
    // Idle (no-progress) timer; parked far in the future when disabled.
    let idle_far = Duration::from_secs(365 * 24 * 3600);
    let idle = tokio::time::sleep(config.idle_timeout.unwrap_or(idle_far));
    tokio::pin!(idle);
    let mut authenticated = false;

    loop {
        driver.flush().await?;
        tokio::select! {
            _ = &mut login_timeout, if !authenticated => {
                return Ok(());
            }
            _ = &mut idle, if config.idle_timeout.is_some() => {
                return Ok(());
            }
            read = driver.read_once() => {
                if !read? {
                    return Ok(());
                }
                // Progress from the peer resets the idle timer.
                if let Some(d) = config.idle_timeout {
                    idle.as_mut().reset(tokio::time::Instant::now() + d);
                }
                while let Some(event) = driver.session_mut().poll_event() {
                    match event {
                        ServerEvent::Authenticated { .. } => {
                            authenticated = true;
                            if let Some(p) = peer {
                                retry.on_authenticated(p);
                            }
                        }
                        ServerEvent::AuthExhausted => {
                            if let Some(p) = peer {
                                retry.on_auth_exhausted(p);
                            }
                            // Flush the queued DISCONNECT, then end the connection.
                            driver.flush().await?;
                            return Ok(());
                        }
                        ServerEvent::ExecRequest { channel, command } => {
                            active_channel = channel;
                            match ctx.exec_handler(&command) {
                                Some(h) => {
                                    driver.session_mut().accept_channel(channel)?;
                                    stdin_tx = Some(spawn_handler(h, command, out_tx.clone()));
                                }
                                None => driver.session_mut().reject_channel(channel)?,
                            }
                        }
                        ServerEvent::ShellRequest { channel } => {
                            active_channel = channel;
                            match ctx.shell_handler() {
                                Some(h) => {
                                    driver.session_mut().accept_channel(channel)?;
                                    stdin_tx = Some(spawn_handler(h, Box::from(""), out_tx.clone()));
                                }
                                None => driver.session_mut().reject_channel(channel)?,
                            }
                        }
                        ServerEvent::SubsystemRequest { channel, name } => {
                            active_channel = channel;
                            match ctx.subsystem_handler(&name) {
                                Some(h) => {
                                    driver.session_mut().accept_channel(channel)?;
                                    stdin_tx = Some(spawn_handler(h, name, out_tx.clone()));
                                }
                                None => driver.session_mut().reject_channel(channel)?,
                            }
                        }
                        ServerEvent::ChannelData { data, .. } => {
                            if !data.is_empty()
                                && let Some(tx) = &stdin_tx
                            {
                                let _ = tx.send(data);
                            }
                        }
                        ServerEvent::ChannelEof { .. } | ServerEvent::ChannelClose { .. } => {
                            stdin_tx = None; // EOF to the handler's stdin
                        }
                        ServerEvent::Disconnect { .. } => return Ok(()),
                    }
                }
            }
            Some(out) = out_rx.recv() => {
                match out {
                    Outbound::Stdout(data) => driver.session_mut().channel_stdout(active_channel, &data)?,
                    Outbound::Stderr(data) => driver.session_mut().channel_stderr(active_channel, &data)?,
                    Outbound::Exit(status) => driver.session_mut().channel_exit(active_channel, status)?,
                }
            }
        }
    }
}

/// Spawn a handler task, returning the sender for its stdin. The handler's exit status
/// is reported once it returns.
fn spawn_handler(
    handler: Arc<dyn ExecHandler>,
    command: Box<str>,
    out_tx: mpsc::UnboundedSender<Outbound>,
) -> mpsc::UnboundedSender<Vec<u8>> {
    let (stdin_tx, stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let session = ChannelSession::new(stdin_rx, out_tx.clone());
    tokio::spawn(async move {
        let status = handler.run(command, session).await;
        let _ = out_tx.send(Outbound::Exit(status));
    });
    stdin_tx
}
