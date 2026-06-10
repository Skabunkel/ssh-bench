//! Minimal SSH server CLI. Completes the handshake, authenticates, and dispatches
//! commands through an [`ExecContext`]: a demo in-process `cat` handler plus the opt-in
//! [`SystemRunner`] for shell and other exec commands.
//!
//! To build a locked-down server with **no system access**, drop the two `SystemRunner`
//! registrations below — only the explicitly-registered handlers will then run, and
//! shell requests will be refused.

use std::sync::Arc;
use std::time::Duration;

use ssh_io::{
    AuthorizedKeys, ChannelSession, ConnectionDecision, ConnectionLimiter, ConnectionPolicy,
    ExecContext, ExecHandler, Fail2Ban, HandlerFuture, RateLimiter, ServeConfig, SystemRunner,
    load_or_create_host_key, serve_with,
};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{ServerAuthHandler, ServerConnection, UserPublicKey};
use tokio::net::TcpListener;

/// Demo auth policy: a fixed password plus an `authorized_keys` allowlist.
struct DemoPolicy {
    username: Box<str>,
    password: Box<str>,
    authorized_keys: Arc<AuthorizedKeys>,
    max_auth_attempts: u32,
}

impl ServerAuthHandler for DemoPolicy {
    fn banner(&mut self) -> Option<std::borrow::Cow<'static, str>> {
        Some("rust_ssh demo server\n".into())
    }
    fn verify_password(&mut self, user: &str, password: &str) -> bool {
        user == &*self.username && password == &*self.password
    }
    fn is_authorized_key(&mut self, _user: &str, key: &UserPublicKey) -> bool {
        self.authorized_keys.contains(key)
    }
    fn max_auth_attempts(&self) -> u32 {
        self.max_auth_attempts
    }
}

/// Demo in-process handler: echo stdin back to stdout (a stand-in for sftp/git/etc.).
struct CatHandler;

impl ExecHandler for CatHandler {
    fn run(self: Arc<Self>, _command: Box<str>, session: ChannelSession) -> HandlerFuture {
        Box::pin(async move {
            let (mut reader, mut writer) = session.split();
            let _ = tokio::io::copy(&mut reader, &mut writer).await;
            0
        })
    }
}

fn build_context() -> ExecContext {
    let ctx = ExecContext::new()
        // In-process command: `ssh host cat` echoes its stdin.
        .on_exec("cat", CatHandler);

    if std::env::var_os("SSH_RESTRICTED").is_some() {
        // Allowlist only: just `cat`. Other commands and shells are rejected — no system
        // access at all.
        ctx
    } else {
        // Opt-in system access: any other exec runs as a process, and shell works.
        ctx.on_unmatched_exec(SystemRunner).on_shell(SystemRunner)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2222".to_owned());

    // Load the authorized_keys allowlist (publickey auth) from SSH_AUTHORIZED_KEYS.
    let authorized_keys = Arc::new(match std::env::var_os("SSH_AUTHORIZED_KEYS") {
        Some(path) => {
            let ak = AuthorizedKeys::load(&path).unwrap_or_default();
            eprintln!(
                "[server] loaded {} authorized key(s) from {:?}",
                ak.len(),
                path
            );
            ak
        }
        None => AuthorizedKeys::default(),
    });

    // Load a stable host key (so clients can pin it via known_hosts), generating and
    // persisting one on first run. Path is overridable via SSH_HOST_KEY.
    let host_key_path = std::env::var_os("SSH_HOST_KEY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| ".ssh_host_ed25519_key".into());
    let host_key = load_or_create_host_key(&host_key_path, &mut OsRng)?;
    eprintln!("[server] host key: {host_key_path:?}");

    let listener = TcpListener::bind(&addr).await?;
    eprintln!("[server] listening on {addr} (user: myuser / mysecretpassword)");
    let ctx = build_context();

    // DoS / brute-force defences:
    //  * Fail2Ban: 6 auth attempts/connection; 3 exhausted logins from an IP → 5-min ban,
    //    enforced at accept time (acts as both ConnectionPolicy and RetryPolicy).
    //  * ConnectionLimiter: at most 256 concurrent connections, 8 per source IP.
    //  * RateLimiter: at most 50 new connections/sec (burst 100).
    //  * ServeConfig: 30s to authenticate, drop after 120s with no traffic (slow-loris).
    let fail2ban = Fail2Ban::new(6, 3, Duration::from_secs(300));
    let limiter = ConnectionLimiter::new(256, Some(8));
    let rate = RateLimiter::new(50.0, 100.0);
    let serve_cfg = ServeConfig {
        login_timeout: Duration::from_secs(30),
        idle_timeout: Some(Duration::from_secs(120)),
    };

    loop {
        let (stream, peer) = listener.accept().await?;

        // Cheap accept-time gates, before any handshake/crypto work.
        if !rate.try_acquire() {
            eprintln!("[server] rate limited {peer}, dropping");
            continue;
        }
        if fail2ban.evaluate(peer) == ConnectionDecision::Reject {
            eprintln!("[server] {} is banned, dropping", peer.ip());
            continue;
        }
        let Some(guard) = limiter.try_admit(peer.ip()) else {
            eprintln!("[server] connection cap reached, dropping {peer}");
            continue;
        };

        eprintln!("[server] accepted connection from {peer}");
        let ctx = ctx.clone();
        let authorized_keys = authorized_keys.clone();
        let host_key = host_key.clone();
        let fail2ban = fail2ban.clone();
        tokio::spawn(async move {
            let _guard = guard; // holds the connection slot for this connection's lifetime
            let policy = DemoPolicy {
                username: "myuser".into(),
                password: "mysecretpassword".into(),
                authorized_keys,
                max_auth_attempts: fail2ban.max_auth_attempts(),
            };
            let connection = ServerConnection::new(OsRng, host_key, policy);
            if let Err(e) = serve_with(stream, connection, ctx, serve_cfg, Some(peer), &fail2ban).await
            {
                eprintln!("[conn] {peer} ended: {e}");
            }
        });
    }
}
