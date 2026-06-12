//! High-level server loop: drives a [`ServerConnection`] over a socket and dispatches
//! exec/shell/subsystem requests to an [`ExecContext`]'s handlers.
//!
//! Flow control is enforced end to end in both directions:
//!
//! * **Inbound** — the client's SSH window is replenished only as the handler actually
//!   reads its stdin, so unread data is bounded by one window and a flooding client
//!   stalls instead of growing server buffers.
//! * **Outbound** — handler writes draw bytes from a budget
//!   ([`ServeConfig::max_buffered_output`]) that is released only as output reaches the
//!   wire, so a client that stops reading (or withholds window) suspends the handler.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use ssh_transport::rand_core::{CryptoRng, RngCore};
use ssh_transport::server::{ServerAuthHandler, ServerConnection, ServerEvent};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc, watch};

use crate::exec::{ChannelSession, ExecContext, ExecHandler, MAX_RESERVE, Outbound};
use crate::policy::{NoRetryReaction, RetryPolicy};
use crate::{DriveError, Driver};

/// Per-connection limits applied while serving (the connection-level DoS knobs).
#[derive(Debug, Clone, Copy)]
pub struct ServeConfig {
    /// Maximum time to reach authentication before the connection is dropped.
    pub login_timeout: Duration,
    /// Drop the connection if no bytes arrive from the peer for this long (slow-loris
    /// guard). `None` disables the idle timeout.
    pub idle_timeout: Option<Duration>,
    /// Maximum handler output (bytes) buffered server-side before writes suspend until
    /// the client drains it — the outbound backpressure bound. Values below the SSH
    /// max packet size (32 KiB) are raised to it so single writes stay acquirable.
    pub max_buffered_output: usize,
}

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            login_timeout: Duration::from_secs(30),
            idle_timeout: None,
            max_buffered_output: 256 * 1024,
        }
    }
}

/// Closes the handler-output budget when dropped, so writers blocked on it error out
/// (`BrokenPipe`) instead of waiting forever once the channel or connection is gone.
struct BudgetGuard(Arc<Semaphore>);

impl Drop for BudgetGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Aborts the handler task when dropped. Closing the budget and dropping the stdin
/// sender already make a *cooperative* handler unwind, but one that ignores its session
/// (a pure compute loop, or a future blocked on something unrelated) would otherwise
/// keep running — and keep any spawned child alive — after the connection ends. Holding
/// the join handle here guarantees teardown on channel close, handler replacement, or
/// connection exit; for a handler that already returned, the abort is a no-op.
struct TaskGuard(tokio::task::JoinHandle<()>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
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
    serve_with(
        stream,
        connection,
        ctx,
        ServeConfig::default(),
        None,
        &NoRetryReaction,
    )
    .await
}

/// Serve one connection to completion: run the handshake/auth (via `connection`), then
/// route exec/shell/subsystem requests through `ctx`. Requests with no registered
/// handler are rejected, so the connection's capabilities are exactly what `ctx` allows.
///
/// `config` bounds login/idle time and buffered handler output; `peer` (when known) is
/// passed to the `retry` hooks so a [`RetryPolicy`] can record auth outcomes (e.g. for
/// fail2ban-style bans).
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

    let out_limit = config.max_buffered_output.max(MAX_RESERVE);
    // Handler-output budget for the active handler: writes reserve bytes, the loop
    // releases them as they reach the wire. Closing it (guard drop) unblocks writers.
    let mut out_budget: Option<BudgetGuard> = None;
    // Bytes reserved by the handler and not yet flushed to the wire.
    let mut out_inflight: usize = 0;
    // Cumulative stdin bytes the handler has consumed (drives window replenishment).
    let mut consumed_rx: Option<watch::Receiver<u64>> = None;
    let mut last_consumed = 0u64;
    // Terminal size feed into the active handler (updated on `window-change`).
    let mut resize_tx: Option<watch::Sender<(u16, u16)>> = None;
    // The active handler's task. Dropped (and thereby aborted) when the channel closes,
    // a new handler replaces it, or `serve_with` returns — so no handler outlives its
    // connection.
    let mut handler_task: Option<TaskGuard> = None;

    // Drop connections that don't authenticate within the grace period.
    let login_timeout = tokio::time::sleep(config.login_timeout);
    tokio::pin!(login_timeout);
    // Idle (no-progress) timer; parked far in the future when disabled.
    let idle_far = Duration::from_secs(365 * 24 * 3600);
    let idle = tokio::time::sleep(config.idle_timeout.unwrap_or(idle_far));
    tokio::pin!(idle);
    let mut authenticated = false;

    loop {
        // Flush under the same timers as the rest of the loop: a peer that stops
        // reading its socket would otherwise wedge the connection here forever,
        // exempt from the login/idle limits.
        tokio::select! {
            flushed = driver.flush() => flushed?,
            _ = &mut login_timeout, if !authenticated => return Ok(()),
            _ = &mut idle, if config.idle_timeout.is_some() => return Ok(()),
        }
        // Output that reached the wire frees handler budget (the outbound half of the
        // backpressure loop).
        if let Some(budget) = &out_budget {
            let flushed = driver.session_mut().take_flushed_output(active_channel) as usize;
            let credit = flushed.min(out_inflight);
            if credit > 0 {
                out_inflight -= credit;
                budget.0.add_permits(credit);
            }
        }
        tokio::select! {
            _ = &mut login_timeout, if !authenticated => {
                return Ok(());
            }
            _ = &mut idle, if config.idle_timeout.is_some() => {
                return Ok(());
            }
            // Handler stdin consumption → replenish the client's flow-control window.
            // This is what lets the client send more: a handler that stops reading
            // stalls the client after one window (the inbound backpressure loop).
            update = async {
                let rx = consumed_rx.as_mut().expect("guarded by branch condition");
                let alive = rx.changed().await.is_ok();
                (alive, *rx.borrow_and_update())
            }, if consumed_rx.is_some() => {
                let (alive, total) = update;
                let delta = total.saturating_sub(last_consumed);
                last_consumed = total;
                if delta > 0 {
                    driver
                        .session_mut()
                        .channel_consumed(active_channel, u32::try_from(delta).unwrap_or(u32::MAX))?;
                }
                if !alive {
                    consumed_rx = None; // handler dropped its reader
                }
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
                            match ctx.exec_handler(&command) {
                                Some(h) => {
                                    driver.session_mut().accept_channel(channel)?;
                                    let pty = driver.session_mut().channel_pty(channel).cloned();
                                    let parts = spawn_handler(h, command, out_tx.clone(), out_limit, pty);
                                    (stdin_tx, out_budget, consumed_rx, resize_tx, handler_task) =
                                        wire_handler(parts, out_budget, handler_task);
                                    (active_channel, out_inflight, last_consumed) = (channel, 0, 0);
                                }
                                None => driver.session_mut().reject_channel(channel)?,
                            }
                        }
                        ServerEvent::ShellRequest { channel } => {
                            match ctx.shell_handler() {
                                Some(h) => {
                                    driver.session_mut().accept_channel(channel)?;
                                    let pty = driver.session_mut().channel_pty(channel).cloned();
                                    let parts = spawn_handler(h, Box::from(""), out_tx.clone(), out_limit, pty);
                                    (stdin_tx, out_budget, consumed_rx, resize_tx, handler_task) =
                                        wire_handler(parts, out_budget, handler_task);
                                    (active_channel, out_inflight, last_consumed) = (channel, 0, 0);
                                }
                                None => driver.session_mut().reject_channel(channel)?,
                            }
                        }
                        ServerEvent::SubsystemRequest { channel, name } => {
                            match ctx.subsystem_handler(&name) {
                                Some(h) => {
                                    driver.session_mut().accept_channel(channel)?;
                                    let pty = driver.session_mut().channel_pty(channel).cloned();
                                    let parts = spawn_handler(h, name, out_tx.clone(), out_limit, pty);
                                    (stdin_tx, out_budget, consumed_rx, resize_tx, handler_task) =
                                        wire_handler(parts, out_budget, handler_task);
                                    (active_channel, out_inflight, last_consumed) = (channel, 0, 0);
                                }
                                None => driver.session_mut().reject_channel(channel)?,
                            }
                        }
                        ServerEvent::WindowChange { cols, rows, .. } => {
                            if let Some(tx) = &resize_tx {
                                tx.send_replace((cols, rows));
                            }
                        }
                        ServerEvent::ChannelData { data, .. } => {
                            // Bounded despite the unbounded sender: the window only
                            // replenishes as the handler reads, so at most one window
                            // of unread stdin can ever be queued here.
                            if !data.is_empty()
                                && let Some(tx) = &stdin_tx
                            {
                                let _ = tx.send(data);
                            }
                        }
                        ServerEvent::ChannelEof { .. } => {
                            stdin_tx = None; // EOF to the handler's stdin
                        }
                        ServerEvent::ChannelClose { .. } => {
                            stdin_tx = None;
                            resize_tx = None;
                            // The channel is gone: queued output will never flush, so
                            // close the budget to unblock (and so terminate) writers, and
                            // abort the handler task so it can't outlive the channel.
                            out_budget = None;
                            handler_task = None;
                        }
                        ServerEvent::Disconnect { .. } => return Ok(()),
                    }
                }
                // The connection may have queued its own disconnect (e.g. a re-key flood
                // or an unsupported service): flush it, then end the connection.
                if driver.session_mut().is_closing() {
                    driver.flush().await?;
                    return Ok(());
                }
            }
            Some(out) = out_rx.recv() => {
                match out {
                    Outbound::Stdout(data) => {
                        out_inflight += data.len();
                        driver.session_mut().channel_stdout(active_channel, &data)?;
                    }
                    Outbound::Stderr(data) => {
                        out_inflight += data.len();
                        driver.session_mut().channel_stderr(active_channel, &data)?;
                    }
                    Outbound::Exit(status) => driver.session_mut().channel_exit(active_channel, status)?,
                }
            }
        }
    }
}

/// Everything a freshly spawned handler hands back to the serve loop.
type HandlerParts = (
    mpsc::UnboundedSender<Vec<u8>>,
    Arc<Semaphore>,
    watch::Receiver<u64>,
    watch::Sender<(u16, u16)>,
    tokio::task::JoinHandle<()>,
);

/// [`HandlerParts`] as held by the serve loop (each slot empty until a handler runs).
type WiredHandler = (
    Option<mpsc::UnboundedSender<Vec<u8>>>,
    Option<BudgetGuard>,
    Option<watch::Receiver<u64>>,
    Option<watch::Sender<(u16, u16)>>,
    Option<TaskGuard>,
);

/// Adopt a new handler's wiring, tearing down the previous handler's budget and task (if
/// any) so its writers cannot block forever — and the task itself cannot linger — on a
/// channel that will never drain again.
fn wire_handler(
    parts: HandlerParts,
    previous_budget: Option<BudgetGuard>,
    previous_task: Option<TaskGuard>,
) -> WiredHandler {
    drop(previous_budget);
    drop(previous_task);
    let (stdin_tx, budget, consumed_rx, resize_tx, task) = parts;
    (
        Some(stdin_tx),
        Some(BudgetGuard(budget)),
        Some(consumed_rx),
        Some(resize_tx),
        Some(TaskGuard(task)),
    )
}

/// Spawn a handler task, returning its stdin sender, output budget, consumption watch,
/// resize feed, and join handle. The handler's exit status is reported once it returns.
fn spawn_handler(
    handler: Arc<dyn ExecHandler>,
    command: Box<str>,
    out_tx: mpsc::UnboundedSender<Outbound>,
    out_limit: usize,
    pty: Option<ssh_transport::PtyInfo>,
) -> HandlerParts {
    let (stdin_tx, stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let budget = Arc::new(Semaphore::new(out_limit));
    let (consumed_tx, consumed_rx) = watch::channel(0u64);
    let initial_size = pty.as_ref().map(|p| (p.cols, p.rows)).unwrap_or((0, 0));
    let (resize_tx, resize_rx) = watch::channel(initial_size);
    let session = ChannelSession::new(
        stdin_rx,
        out_tx.clone(),
        Arc::clone(&budget),
        consumed_tx,
        pty,
        resize_rx,
    );
    let task = tokio::spawn(async move {
        let status = handler.run(command, session).await;
        let _ = out_tx.send(Outbound::Exit(status));
    });
    (stdin_tx, budget, consumed_rx, resize_tx, task)
}
