//! Server-side session: wraps the [`Transport`] and drives user authentication
//! (RFC 4252) and the connection protocol (RFC 4254). Authentication *policy* is
//! delegated to a [`ServerAuthHandler`]; process spawning for `exec`/`shell` is the
//! caller's job, driven by the [`ServerEvent`]s emitted here.

use rand_core::{CryptoRng, RngCore};

use crate::auth::{self, AuthRequest, Method, UserPublicKey};
use crate::connection::{self as conn, Channel};
use crate::transport::Event;
use crate::wire::Reader;
use crate::{HostKey, Result, SshError, Transport, msg};

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
    /// Channel data from the client (process stdin).
    ChannelData { channel: u32, data: Vec<u8> },
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
    /// Count of failed authentication attempts (the brute-force cap).
    auth_failures: u32,
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
            auth_failures: 0,
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

    // --- connection-layer output API (called by the Infra driver) ---

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
        let mut ch = Channel::new(LOCAL_CHANNEL);
        ch.set_remote(sender, window, max_packet);
        self.channel = Some(ch);
        self.transport
            .send_packet(&conn::channel_open_confirmation(sender, LOCAL_CHANNEL))
    }

    fn handle_channel_request(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let request = r.utf8()?;
        let want_reply = r.boolean()?;

        match request {
            // exec/shell/subsystem are dispatched by the application, which decides
            // whether to accept or reject. We defer the reply until accept_channel /
            // reject_channel is called and surface the request as an event.
            "exec" => {
                let command = r.utf8()?.into();
                self.pending_reply = want_reply;
                self.events.push_back(ServerEvent::ExecRequest {
                    channel: LOCAL_CHANNEL,
                    command,
                });
            }
            "shell" => {
                self.pending_reply = want_reply;
                self.events.push_back(ServerEvent::ShellRequest {
                    channel: LOCAL_CHANNEL,
                });
            }
            "subsystem" => {
                let name = r.utf8()?.into();
                self.pending_reply = want_reply;
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
            // Decline pty-req (we have no PTY → keep the client in cooked mode) and any
            // other request type.
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
        let data = r.string()?.to_vec();

        let outcome = self
            .channel
            .as_mut()
            .map(|ch| (ch.remote_id, ch.consume_incoming(data.len() as u32)));
        match outcome {
            Some((remote, conn::WindowUpdate::Ok(Some(add)))) => {
                self.transport
                    .send_packet(&conn::channel_window_adjust(remote, add))?;
            }
            Some((_, conn::WindowUpdate::Exceeded)) => {
                // The client sent more than its flow-control window allowed: drop it.
                self.transport
                    .disconnect(msg::disconnect::PROTOCOL_ERROR, "channel window exceeded");
                return Ok(());
            }
            _ => {}
        }
        self.events.push_back(ServerEvent::ChannelData {
            channel: LOCAL_CHANNEL,
            data,
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
        let Some(ch) = self.channel.as_mut() else {
            return Ok(());
        };
        let mut packets: Vec<Vec<u8>> = Vec::new();
        ch.drain_output(|p| packets.push(p));

        let mut finish = None;
        if ch.out_is_empty() && ch.close_requested() && !ch.sent_close {
            ch.sent_eof = true;
            ch.sent_close = true;
            finish = Some((ch.remote_id, ch.exit_status.unwrap_or(0)));
        }

        for p in packets {
            self.transport.send_packet(&p)?;
        }
        if let Some((remote, status)) = finish {
            self.transport
                .send_packet(&conn::channel_request_exit_status(remote, status))?;
            self.transport.send_packet(&conn::channel_eof(remote))?;
            self.transport.send_packet(&conn::channel_close(remote))?;
        }
        Ok(())
    }
}
