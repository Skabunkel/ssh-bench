//! Server-side session: wraps the [`Transport`] and drives user authentication
//! (RFC 4252) and the connection protocol (RFC 4254). Authentication *policy* is
//! delegated to a [`ServerAuthHandler`]; process spawning for `exec`/`shell` is the
//! caller's job, driven by the [`ServerEvent`]s emitted here.

use rand_core::{CryptoRng, RngCore};

use crate::auth::{self, AuthRequest, Method, UserPublicKey};
use crate::connection::{self as conn, Channel, PtyInfo};
use crate::transport::Event;
use crate::wire::Reader;
use crate::{HostKey, Obfuscation, Result, SshError, Transport, msg};

/// Authentication policy provided by the embedding application.
pub trait ServerAuthHandler {
    fn banner(&mut self) -> Option<std::borrow::Cow<'static, str>> {
        None
    }
    fn allow_none(&mut self, _user: &str) -> bool {
        false
    }
    fn verify_password(&mut self, _user: &str, _password: &str) -> bool {
        false
    }
    fn is_authorized_key(&mut self, _user: &str, _key: &UserPublicKey) -> bool {
        false
    }
    fn methods(&self) -> Vec<&'static str> {
        vec![auth::METHOD_PUBLICKEY, auth::METHOD_PASSWORD]
    }
    /// Maximum failed authentication attempts before the server drops the connection
    /// (the protocol-level brute-force cap, akin to OpenSSH's `MaxAuthTries`). A driver
    /// can react to the resulting [`ServerEvent::AuthExhausted`] (e.g. to ban the peer).
    fn max_auth_attempts(&self) -> u32 {
        6
    }
    /// Maximum total authentication *requests* — of any kind — the server will process
    /// before dropping the connection. Unlike [`Self::max_auth_attempts`], which counts
    /// only failures, this counts every `USERAUTH_REQUEST`, including public-key *probes*
    /// (a query with no signature, answered with `PK_OK`) that never count as a failure.
    /// Without this bound a peer that knows an authorized public key — public information
    /// — could send unlimited probes, keeping the connection and the server's key parsing
    /// busy indefinitely without ever tripping the failure cap. The default is generous
    /// so legitimate multi-key or agent-backed clients are unaffected.
    fn max_auth_requests(&self) -> u32 {
        50
    }
}

/// High-level server events.
#[derive(Debug)]
pub enum ServerEvent {
    /// Authentication succeeded for `user`.
    Authenticated { user: Box<str> },
    /// The client requested command execution on `channel`.
    ExecRequest { channel: u32, command: Box<str> },
    /// The client requested an interactive shell on `channel`.
    ShellRequest { channel: u32 },
    /// The client requested a subsystem (e.g. `sftp`) on `channel`.
    SubsystemRequest { channel: u32, name: Box<str> },
    /// The client's terminal was resized (`window-change`). Only emitted for channels
    /// that were granted a PTY; the stored [`PtyInfo`] has already been updated.
    WindowChange { channel: u32, cols: u16, rows: u16 },
    /// Channel data from the client (process stdin).
    ChannelData { channel: u32, data: Box<[u8]> },
    /// The client sent EOF (no more stdin).
    ChannelEof { channel: u32 },
    /// The channel was closed.
    ChannelClose { channel: u32 },
    /// The peer disconnected.
    Disconnect { reason: u32, description: Box<str> },
    /// Authentication failed too many times; the server has sent `SSH_MSG_DISCONNECT`
    /// and the connection is finished. A driver can use this to record/ban the peer.
    AuthExhausted,
}

/// A server-side SSH connection (single session channel).
pub struct ServerConnection<R: RngCore + CryptoRng, H: ServerAuthHandler> {
    transport: Transport<R>,
    handler: H,
    authenticated: Option<Box<str>>,
    banner_sent: bool,
    channel: Option<Channel>,
    /// `want_reply` of a deferred exec/shell/subsystem request awaiting accept/reject.
    pending_reply: bool,
    /// Whether `pty-req` is granted. Off by default: accepting a PTY puts the *client's*
    /// terminal into raw mode (no echo, no line editing), which only makes sense when
    /// the registered handlers actually drive the screen (full-screen TUIs).
    allow_pty: bool,
    /// Count of failed authentication attempts (the brute-force cap).
    auth_failures: u32,
    /// Count of all authentication requests seen (the probe-flood cap).
    auth_requests: u32,
    /// Whether a session program (exec/shell/subsystem) has already been started on the
    /// open channel; a second request is refused (matches OpenSSH, and bounds handler
    /// spawning to one per channel so a peer can't churn handlers on one session).
    program_started: bool,
    events: std::collections::VecDeque<ServerEvent>,
}

/// Local channel id we assign (a single session channel is supported).
const LOCAL_CHANNEL: u32 = 0;

impl<R: RngCore + CryptoRng, H: ServerAuthHandler> ServerConnection<R, H> {
    pub fn new(rng: R, host_key: HostKey, handler: H) -> Self {
        Self {
            transport: Transport::new_server(rng, host_key),
            handler,
            authenticated: None,
            banner_sent: false,
            channel: None,
            pending_reply: false,
            allow_pty: false,
            auth_failures: 0,
            auth_requests: 0,
            program_started: false,
            events: std::collections::VecDeque::new(),
        }
    }

    pub fn on_input(&mut self, data: &[u8]) -> Result<()> {
        self.transport.on_input(data)?;
        self.pump()
    }

    pub fn take_output(&mut self) -> Vec<u8> {
        self.transport.take_output()
    }

    /// Borrow queued outbound bytes without taking ownership (see
    /// [`Transport::pending_output`]).
    pub fn pending_output(&self) -> &[u8] {
        self.transport.pending_output()
    }

    /// Reset the outbound buffer after writing, keeping its capacity (see
    /// [`Transport::clear_output`]).
    pub fn clear_output(&mut self) {
        self.transport.clear_output();
    }

    pub fn poll_event(&mut self) -> Option<ServerEvent> {
        self.events.pop_front()
    }

    pub fn is_authenticated(&self) -> bool {
        self.authenticated.is_some()
    }

    /// Whether the server has queued its own disconnect; the driver should flush and close.
    pub fn is_closing(&self) -> bool {
        self.transport.is_closing()
    }

    /// Low-level testing/fuzzing hook: send `payload` as a raw application packet over the
    /// established transport (framed, compressed if active, and encrypted as normal). It
    /// lets a harness drive the *peer's* post-authentication connection parsers with
    /// arbitrary plaintext — i.e. fuzz behind the crypto gate using real keys.
    #[doc(hidden)]
    pub fn send_raw_packet(&mut self, payload: &[u8]) -> Result<()> {
        self.transport.send_packet(payload)
    }

    pub fn session_id(&self) -> Option<&[u8]> {
        self.transport.session_id()
    }

    /// Begin a key re-exchange (queues application traffic until it completes).
    pub fn initiate_rekey(&mut self) {
        self.transport.initiate_rekey();
    }

    /// Tune the re-key flood guard: how many client-initiated re-keys are tolerated with
    /// no application traffic in between before the connection is dropped.
    pub fn set_max_consecutive_rekeys(&mut self, n: u32) {
        self.transport.set_max_consecutive_peer_rekeys(n);
    }

    /// Grant `pty-req` (default: refused). Granting flips the client's terminal into
    /// raw mode — no local echo, no line editing — so enable this only when handlers
    /// drive the screen themselves (full-screen TUIs). With a PTY granted, the handler
    /// sees raw keystrokes and `window-change` events ([`ServerEvent::WindowChange`]).
    pub fn set_allow_pty(&mut self, allow: bool) {
        self.allow_pty = allow;
    }

    /// Configure traffic obfuscation (channel-data chunking + `SSH_MSG_IGNORE` chaff).
    /// Off by default; see [`Obfuscation`]. Takes effect on subsequent channel writes.
    pub fn set_obfuscation(&mut self, obfuscation: Obfuscation) {
        self.transport.set_obfuscation(obfuscation);
    }

    /// Emit one chaff (`SSH_MSG_IGNORE`) packet with a random-length random payload. A
    /// driver may call this on an idle timer to mask output *timing*. No-op until the
    /// connection is established; the client silently discards it.
    pub fn send_chaff(&mut self) -> Result<()> {
        self.transport.send_chaff()
    }

    /// The PTY granted on `channel`, if any (size kept current by `window-change`).
    pub fn channel_pty(&self, channel: u32) -> Option<&PtyInfo> {
        self.channel
            .as_ref()
            .filter(|ch| ch.local_id == channel)
            .and_then(Channel::pty)
    }

    // --- connection-layer output API (called by the Infrastructure driver) ---

    /// Queue process stdout for `channel`.
    pub fn channel_stdout(&mut self, channel: u32, data: &[u8]) -> Result<()> {
        if let Some(ch) = self.channel_for(channel) {
            ch.enqueue_stdout(data);
        }
        self.flush_channel()
    }

    /// Queue process stderr for `channel`.
    pub fn channel_stderr(&mut self, channel: u32, data: &[u8]) -> Result<()> {
        if let Some(ch) = self.channel_for(channel) {
            ch.enqueue_stderr(data);
        }
        self.flush_channel()
    }

    /// Mark the process as exited with `status`; flushes remaining output, then sends
    /// `exit-status`, EOF, and CLOSE once the window drains.
    pub fn channel_exit(&mut self, channel: u32, status: u32) -> Result<()> {
        if let Some(ch) = self.channel_for(channel) {
            ch.exit_status = Some(status);
            ch.request_close();
        }
        self.flush_channel()
    }

    /// Report that the application has consumed `len` bytes of channel data (stdin it
    /// received via [`ServerEvent::ChannelData`]). This is what replenishes the client's
    /// flow-control window — a driver **must** call it as its handler drains data, or
    /// the client stalls after one window. Sends `WINDOW_ADJUST` in batches.
    pub fn channel_consumed(&mut self, channel: u32, len: u32) -> Result<()> {
        let adjust = self.channel_for(channel).and_then(|ch| {
            let remote = ch.remote_id;
            ch.ack_incoming(len).map(|add| (remote, add))
        });
        if let Some((remote, add)) = adjust {
            self.transport
                .send_packet(&conn::channel_window_adjust(remote, add))?;
        }
        Ok(())
    }

    /// Queued-output bytes flushed to the wire since the last call. A driver bounding
    /// how much handler output it buffers releases its budget by exactly this amount.
    pub fn take_flushed_output(&mut self, channel: u32) -> u64 {
        self.channel_for(channel)
            .map(Channel::take_flushed_out)
            .unwrap_or(0)
    }

    fn channel_for(&mut self, channel: u32) -> Option<&mut Channel> {
        self.channel.as_mut().filter(|ch| ch.local_id == channel)
    }

    // --- internals ---

    fn pump(&mut self) -> Result<()> {
        while let Some(event) = self.transport.poll_event() {
            match event {
                Event::Established | Event::ServerHostKey(_) => {}
                Event::Disconnect {
                    reason,
                    description,
                } => {
                    self.events.push_back(ServerEvent::Disconnect {
                        reason,
                        description,
                    });
                }
                Event::Packet(payload) => {
                    if self.authenticated.is_some() {
                        self.handle_connection(&payload)?;
                    } else {
                        self.handle_preauth(&payload)?;
                    }
                }
            }
        }
        Ok(())
    }

    fn handle_preauth(&mut self, payload: &[u8]) -> Result<()> {
        match payload.first().copied() {
            Some(msg::SERVICE_REQUEST) => self.handle_service_request(payload),
            Some(msg::USERAUTH_REQUEST) => self.handle_userauth(payload),
            _ => Ok(()),
        }
    }

    fn handle_service_request(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        if r.utf8()? != auth::SERVICE_USERAUTH {
            self.transport
                .disconnect(msg::disconnect::PROTOCOL_ERROR, "service not available");
            return Ok(());
        }
        self.transport
            .send_packet(&auth::service_accept(auth::SERVICE_USERAUTH))?;
        if !self.banner_sent {
            self.banner_sent = true;
            if let Some(banner) = self.handler.banner() {
                self.transport
                    .send_packet(&auth::userauth_banner(&banner))?;
            }
        }
        Ok(())
    }

    fn handle_userauth(&mut self, payload: &[u8]) -> Result<()> {
        // Cap total requests so public-key probes (which never count as failures) can't
        // keep the connection alive and the server busy indefinitely.
        self.auth_requests += 1;
        if self.auth_requests > self.handler.max_auth_requests() {
            self.transport.disconnect(
                msg::disconnect::PROTOCOL_ERROR,
                "too many authentication requests",
            );
            self.events.push_back(ServerEvent::AuthExhausted);
            return Ok(());
        }
        let req = AuthRequest::parse(payload)?;
        let granted = match &req.method {
            Method::None => self.handler.allow_none(&req.user),
            Method::Password { password } => self.handler.verify_password(&req.user, password),
            Method::PublicKey {
                key_algo,
                key_blob,
                signature,
            } => return self.handle_publickey(&req, key_algo, key_blob, signature.as_deref()),
            Method::Unknown { .. } => false,
        };
        self.finish_auth(req.user, granted)
    }

    fn handle_publickey(
        &mut self,
        req: &AuthRequest,
        key_algo: &str,
        key_blob: &[u8],
        signature: Option<&[u8]>,
    ) -> Result<()> {
        let key = match UserPublicKey::parse_blob(key_blob) {
            Ok(k) => k,
            Err(_) => return self.send_failure(),
        };
        if !self.handler.is_authorized_key(&req.user, &key) {
            return self.send_failure();
        }
        match signature {
            None => self
                .transport
                .send_packet(&auth::userauth_pk_ok(key_algo, key_blob)),
            Some(sig) => {
                let session_id = self
                    .transport
                    .session_id()
                    .ok_or(SshError::Protocol("no session id"))?
                    .to_vec();
                let signed = auth::publickey_signed_data(
                    &session_id,
                    &req.user,
                    &req.service,
                    key_algo,
                    key_blob,
                );
                let ok = key.verify(&signed, sig).is_ok();
                self.finish_auth(req.user.clone(), ok)
            }
        }
    }

    fn finish_auth(&mut self, user: Box<str>, granted: bool) -> Result<()> {
        if granted {
            self.transport.send_packet(&auth::userauth_success())?;
            self.authenticated = Some(user.clone());
            self.events.push_back(ServerEvent::Authenticated { user });
            Ok(())
        } else {
            self.send_failure()
        }
    }

    fn send_failure(&mut self) -> Result<()> {
        self.auth_failures += 1;
        if self.auth_failures >= self.handler.max_auth_attempts() {
            // Brute-force cap reached: drop the connection and signal the driver.
            self.transport.disconnect(
                msg::disconnect::NO_MORE_AUTH_METHODS_AVAILABLE,
                "too many authentication failures",
            );
            self.events.push_back(ServerEvent::AuthExhausted);
            return Ok(());
        }
        let methods = self.handler.methods();
        self.transport
            .send_packet(&auth::userauth_failure(&methods, false))
    }

    // --- connection protocol (RFC 4254) ---

    fn handle_connection(&mut self, payload: &[u8]) -> Result<()> {
        match payload.first().copied() {
            Some(msg::CHANNEL_OPEN) => self.handle_channel_open(payload),
            Some(msg::CHANNEL_REQUEST) => self.handle_channel_request(payload),
            Some(msg::CHANNEL_DATA) => self.handle_channel_data(payload),
            Some(msg::CHANNEL_WINDOW_ADJUST) => self.handle_window_adjust(payload),
            Some(msg::CHANNEL_EOF) => {
                self.events.push_back(ServerEvent::ChannelEof {
                    channel: LOCAL_CHANNEL,
                });
                Ok(())
            }
            Some(msg::CHANNEL_CLOSE) => self.handle_channel_close(),
            // Ignore other connection messages (e.g. GLOBAL_REQUEST) for now.
            _ => Ok(()),
        }
    }

    fn handle_channel_open(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let ch_type = r.utf8()?;
        let sender = r.u32()?;
        let window = r.u32()?;
        let max_packet = r.u32()?;

        if ch_type != conn::CHANNEL_SESSION {
            return self.transport.send_packet(&conn::channel_open_failure(
                sender,
                conn::open_failure::UNKNOWN_CHANNEL_TYPE,
                "only session channels are supported",
            ));
        }
        if self.channel.is_some() {
            return self.transport.send_packet(&conn::channel_open_failure(
                sender,
                conn::open_failure::ADMINISTRATIVELY_PROHIBITED,
                "only one channel supported",
            ));
        }
        // Refuse a pathologically small max-packet: it would force per-byte framing,
        // an AEAD-seal-per-byte amplification vector (see MIN_REMOTE_MAX_PACKET).
        if max_packet < conn::MIN_REMOTE_MAX_PACKET {
            return self.transport.send_packet(&conn::channel_open_failure(
                sender,
                conn::open_failure::ADMINISTRATIVELY_PROHIBITED,
                "maximum packet size too small",
            ));
        }
        let mut ch = Channel::new(LOCAL_CHANNEL);
        ch.set_remote(sender, window, max_packet);
        self.channel = Some(ch);
        self.program_started = false;
        self.transport
            .send_packet(&conn::channel_open_confirmation(sender, LOCAL_CHANNEL))
    }

    fn handle_channel_request(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let request = r.utf8()?;
        let want_reply = r.boolean()?;

        // A session runs exactly one program. A second exec/shell/subsystem on a channel
        // that already started one is refused, so a peer can't churn handlers (each its
        // own task, and for an OS runner its own child process) on a single session.
        if matches!(request, "exec" | "shell" | "subsystem") && self.program_started {
            if want_reply {
                let remote = self.remote_id();
                self.transport.send_packet(&conn::channel_failure(remote))?;
            }
            return Ok(());
        }

        match request {
            // exec/shell/subsystem are dispatched by the application, which decides
            // whether to accept or reject. We defer the reply until accept_channel /
            // reject_channel is called and surface the request as an event.
            "exec" => {
                let command = r.utf8()?.into();
                self.pending_reply = want_reply;
                self.program_started = true;
                self.events.push_back(ServerEvent::ExecRequest {
                    channel: LOCAL_CHANNEL,
                    command,
                });
            }
            "shell" => {
                self.pending_reply = want_reply;
                self.program_started = true;
                self.events.push_back(ServerEvent::ShellRequest {
                    channel: LOCAL_CHANNEL,
                });
            }
            "subsystem" => {
                let name = r.utf8()?.into();
                self.pending_reply = want_reply;
                self.program_started = true;
                self.events.push_back(ServerEvent::SubsystemRequest {
                    channel: LOCAL_CHANNEL,
                    name,
                });
            }
            // Accept env (values ignored) so clients proceed.
            "env" if want_reply => {
                let remote = self.remote_id();
                self.transport.send_packet(&conn::channel_success(remote))?;
            }
            "env" => {}
            // Grant a PTY when policy allows (full-screen TUI handlers); refusing keeps
            // the client in cooked mode, which is right for pipe-style handlers.
            "pty-req" => {
                let term = r.utf8()?;
                let cols = r.u32()?;
                let rows = r.u32()?;
                let width_px = r.u32()?;
                let height_px = r.u32()?;
                let modes = r.string()?.to_vec();
                let granted = self.allow_pty && self.channel.is_some();
                if granted {
                    let pty = PtyInfo {
                        term: term.into(),
                        cols: u16::try_from(cols).unwrap_or(u16::MAX),
                        rows: u16::try_from(rows).unwrap_or(u16::MAX),
                        width_px,
                        height_px,
                        modes,
                    };
                    if let Some(ch) = self.channel.as_mut() {
                        ch.set_pty(pty);
                    }
                }
                if want_reply {
                    let remote = self.remote_id();
                    let reply = if granted {
                        conn::channel_success(remote)
                    } else {
                        conn::channel_failure(remote)
                    };
                    self.transport.send_packet(&reply)?;
                }
            }
            // Track terminal resizes on channels that hold a PTY (RFC 4254 §6.7).
            "window-change" => {
                let cols = u16::try_from(r.u32()?).unwrap_or(u16::MAX);
                let rows = u16::try_from(r.u32()?).unwrap_or(u16::MAX);
                let width_px = r.u32()?;
                let height_px = r.u32()?;
                let applied = self
                    .channel
                    .as_mut()
                    .map(|ch| ch.update_pty_size(cols, rows, width_px, height_px))
                    .unwrap_or(false);
                if applied {
                    self.events.push_back(ServerEvent::WindowChange {
                        channel: LOCAL_CHANNEL,
                        cols,
                        rows,
                    });
                }
                if want_reply {
                    let remote = self.remote_id();
                    let reply = if applied {
                        conn::channel_success(remote)
                    } else {
                        conn::channel_failure(remote)
                    };
                    self.transport.send_packet(&reply)?;
                }
            }
            // Decline any other request type.
            _ if want_reply => {
                let remote = self.remote_id();
                self.transport.send_packet(&conn::channel_failure(remote))?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Accept a pending exec/shell/subsystem request, sending `CHANNEL_SUCCESS` if the
    /// client asked for a reply. Call before producing any output for the request.
    pub fn accept_channel(&mut self, _channel: u32) -> Result<()> {
        if core::mem::take(&mut self.pending_reply) {
            let remote = self.remote_id();
            self.transport.send_packet(&conn::channel_success(remote))?;
        }
        Ok(())
    }

    /// Reject a pending exec/shell/subsystem request, sending `CHANNEL_FAILURE`.
    pub fn reject_channel(&mut self, _channel: u32) -> Result<()> {
        if core::mem::take(&mut self.pending_reply) {
            let remote = self.remote_id();
            self.transport.send_packet(&conn::channel_failure(remote))?;
        }
        Ok(())
    }

    fn handle_channel_data(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let data = r.string()?;

        // Account against the window we granted; the window is replenished only as the
        // driver reports consumption via [`Self::channel_consumed`] (backpressure), so a
        // client can never have more than one window of data buffered server-side.
        if let Some(ch) = self.channel.as_mut()
            && !ch.consume_incoming(data.len() as u32)
        {
            // The client sent more than its flow-control window allowed: drop it.
            self.transport
                .disconnect(msg::disconnect::PROTOCOL_ERROR, "channel window exceeded");
            return Ok(());
        }
        self.events.push_back(ServerEvent::ChannelData {
            channel: LOCAL_CHANNEL,
            data: Box::from(data),
        });
        Ok(())
    }

    fn handle_window_adjust(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let add = r.u32()?;
        if let Some(ch) = self.channel.as_mut() {
            ch.add_remote_window(add);
        }
        self.flush_channel()
    }

    fn handle_channel_close(&mut self) -> Result<()> {
        let remote = self.remote_id();
        if let Some(ch) = self.channel.as_mut() {
            ch.recv_close = true;
            if !ch.sent_close {
                ch.sent_close = true;
                self.transport.send_packet(&conn::channel_close(remote))?;
            }
        }
        self.channel = None;
        self.program_started = false;
        self.events.push_back(ServerEvent::ChannelClose {
            channel: LOCAL_CHANNEL,
        });
        Ok(())
    }

    fn remote_id(&self) -> u32 {
        self.channel.as_ref().map(|c| c.remote_id).unwrap_or(0)
    }

    /// Flush queued channel output; once drained, finish a requested close by sending
    /// `exit-status`, EOF, and CLOSE.
    fn flush_channel(&mut self) -> Result<()> {
        // Split the borrow so each drained message is sealed straight into the transport
        // with no intermediate `Vec<Zeroizing<Vec<u8>>>` collecting them first: `channel`
        // and `transport` are disjoint fields.
        let Self {
            channel: Some(ch),
            transport,
            ..
        } = self
        else {
            return Ok(());
        };

        let max_chunk = transport.obfuscation().max_chunk;
        let mut send_result = Ok(());
        let mut sent_any = false;
        ch.drain_output(max_chunk, |p| {
            if send_result.is_ok() {
                sent_any = true;
                send_result = transport.send_packet(&p);
            }
        });
        send_result?;

        // Interleave chaff after real data so an observer can't tell which packets carry it.
        if sent_any {
            transport.send_chaff_burst()?;
        }

        if ch.out_is_empty() && ch.close_requested() && !ch.sent_close {
            ch.sent_eof = true;
            ch.sent_close = true;
            let remote = ch.remote_id;
            let status = ch.exit_status.unwrap_or(0);
            transport.send_packet(&conn::channel_request_exit_status(remote, status))?;
            transport.send_packet(&conn::channel_eof(remote))?;
            transport.send_packet(&conn::channel_close(remote))?;
        }
        Ok(())
    }
}
