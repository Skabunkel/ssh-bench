//! Minimal SSH server CLI. Completes the handshake, authenticates, and dispatches
//! commands through an [`ExecContext`]: a demo in-process `cat` handler plus the opt-in
//! [`SystemRunner`] for shell and other exec commands.
//!
//! To build a locked-down server with **no system access**, drop the two `SystemRunner`
//! registrations below — only the explicitly-registered handlers will then run, and
//! shell requests will be refused.

use std::sync::Arc;

use ssh_io::{AuthorizedKeys, ChannelSession, ExecContext, ExecHandler, HandlerFuture, SystemRunner, serve};
use ssh_transport::rand_core::OsRng;
use ssh_transport::{HostKey, ServerAuthHandler, ServerConnection, UserPublicKey};
use tokio::net::TcpListener;

/// Demo auth policy: a fixed password plus an `authorized_keys` allowlist.
struct DemoPolicy {
    username: Box<str>,
    password: Box<str>,
    authorized_keys: Arc<AuthorizedKeys>,
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
            eprintln!("[server] loaded {} authorized key(s) from {:?}", ak.len(), path);
            ak
        }
        None => AuthorizedKeys::default(),
    });

    let listener = TcpListener::bind(&addr).await?;
    eprintln!("[server] listening on {addr} (user: myuser / mysecretpassword)");
    let ctx = build_context();

    loop {
        let (stream, peer) = listener.accept().await?;
        eprintln!("[server] accepted connection from {peer}");
        let ctx = ctx.clone();
        let authorized_keys = authorized_keys.clone();
        tokio::spawn(async move {
            let host_key = HostKey::generate(&mut OsRng);
            let policy = DemoPolicy {
                username: "myuser".into(),
                password: "mysecretpassword".into(),
                authorized_keys,
            };
            let connection = ServerConnection::new(OsRng, host_key, policy);
            if let Err(e) = serve(stream, connection, ctx).await {
                eprintln!("[conn] {peer} ended: {e}");
            }
        });
    }
}
