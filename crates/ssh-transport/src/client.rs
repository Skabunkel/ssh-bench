//! Client-side session: wraps the [`Transport`], enforces host-key policy, drives user
//! authentication, and runs a session channel (`exec`). Credentials and known-hosts
//! policy come from a [`ClientAuthHandler`] (a generic parameter — no `dyn`).

use rand_core::{CryptoRng, RngCore};
use secrecy::ExposeSecret;

use crate::algo::HOSTKEY_ED25519;
use crate::auth::{self, Password, UserKeypair};
use crate::connection::{self as conn, Channel};
use crate::transport::Event;
use crate::wire::Reader;
use crate::{HostPublicKey, Obfuscation, Result, SshError, Transport, msg};

/// One authentication attempt the client will make.
pub enum AuthAttempt {
    /// A password (scrubbed from memory on drop).
    Password(Password),
    /// Boxed because an ed25519 keypair is much larger than the other variant.
    PublicKey(Box<UserKeypair>),
}

/// Client policy: host-key trust and credential selection.
pub trait ClientAuthHandler {
    fn username(&self) -> Box<str>;
    /// Decide whether to trust the server's host key (signature already verified).
    fn verify_host_key(&mut self, key: &HostPublicKey) -> bool;
    /// Next attempt to make; `can_continue` lists methods the server allows. `None`
    /// gives up.
    fn next_auth(&mut self, can_continue: &[Box<str>]) -> Option<AuthAttempt>;
}

/// High-level client events.
#[derive(Debug)]
pub enum ClientEvent {
    Banner(Box<str>),
    Authenticated,
    AuthFailed {
        methods: Vec<Box<str>>,
    },
    HostKeyRejected,
    /// The server granted our `pty-req`: it is now safe (and expected) to put the
    /// local terminal into raw mode for a full-screen session.
    PtyGranted,
    /// The server refused our `pty-req`. The session continues in cooked mode.
    PtyRefused,
    /// The session channel was opened and is ready for an `exec`/`shell` request.
    ChannelReady {
        channel: u32,
    },
    /// Opening the session channel failed.
    ChannelOpenFailure {
        reason: u32,
        description: Box<str>,
    },
    /// Process stdout.
    Stdout(Box<[u8]>),
    /// Process stderr.
    Stderr(Box<[u8]>),
    /// The command's exit status.
    ExitStatus(u32),
    /// The server refused the exec/shell/subsystem request (`CHANNEL_FAILURE`).
    RequestFailed,
    /// The channel was closed by the server.
    ChannelClosed,
    Disconnect {
        reason: u32,
        description: Box<str>,
    },
}

#[derive(PartialEq, Eq)]
enum State {
    Handshaking,
    ExpectServiceAccept,
    Authenticating,
    Authenticated,
    Done,
}

const LOCAL_CHANNEL: u32 = 0;

/// The session request to issue once the channel is confirmed open.
enum PendingRequest {
    Exec(Box<str>),
    Shell,
}

/// A `pty-req` to send between channel open and the session request.
struct PtyParams {
    term: Box<str>,
    cols: u16,
    rows: u16,
}

/// What an outstanding `want_reply` channel request was for, so `CHANNEL_SUCCESS` /
/// `CHANNEL_FAILURE` (which carry no request id and arrive strictly in order) can be
/// attributed: a refused PTY must not read as a failed exec/shell.
enum PendingReply {
    Pty,
    Session,
}

/// A client-side SSH connection (single session channel).
pub struct ClientConnection<R: RngCore + CryptoRng, H: ClientAuthHandler> {
    transport: Transport<R>,
    handler: H,
    state: State,
    host_rejected: bool,
    channel: Option<Channel>,
    pending: Option<PendingRequest>,
    want_pty: Option<PtyParams>,
    /// Outstanding `want_reply` requests, in send order (see [`PendingReply`]).
    reply_queue: std::collections::VecDeque<PendingReply>,
    events: std::collections::VecDeque<ClientEvent>,
}

impl<R: RngCore + CryptoRng, H: ClientAuthHandler> ClientConnection<R, H> {
    pub fn new(rng: R, handler: H) -> Self {
        Self::with_transport(Transport::new_client(rng), handler)
    }

    /// Like [`ClientConnection::new`] but offering `ciphers` (in preference order). Since
    /// negotiation prefers the client's order, this pins which cipher is selected when
    /// the server supports it — useful for testing a specific suite.
    pub fn with_cipher_preference(rng: R, handler: H, ciphers: &[&str]) -> Self {
        Self::with_transport(Transport::new_client_with_ciphers(rng, ciphers), handler)
    }

    /// Like [`ClientConnection::new`] but offering `compression` (in preference order).
    /// Listing `zlib@openssh.com` first turns on delayed compression when the server
    /// supports it (compression engages only after authentication).
    pub fn with_compression_preference(rng: R, handler: H, compression: &[&str]) -> Self {
        Self::with_transport(
            Transport::new_client_with_compression(rng, compression),
            handler,
        )
    }

    fn with_transport(transport: Transport<R>, handler: H) -> Self {
        Self {
            transport,
            handler,
            state: State::Handshaking,
            host_rejected: false,
            channel: None,
            pending: None,
            want_pty: None,
            reply_queue: std::collections::VecDeque::new(),
            events: std::collections::VecDeque::new(),
        }
    }

    /// The cipher negotiated for this connection, once the handshake has progressed far
    /// enough (e.g. `chacha20-poly1305@openssh.com`).
    pub fn negotiated_cipher(&self) -> Option<&str> {
        self.transport.negotiated_cipher()
    }

    /// The compression negotiated for this connection (e.g. `none` or `zlib@openssh.com`).
    pub fn negotiated_compression(&self) -> Option<&str> {
        self.transport.negotiated_compression()
    }

    /// Whether delayed compression has engaged (after authentication).
    pub fn is_compression_active(&self) -> bool {
        self.transport.is_compression_active()
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

    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        self.events.pop_front()
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, State::Authenticated)
    }

    /// Whether we have queued our own disconnect; the driver should flush and close.
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

    /// Tune the re-key flood guard: how many server-initiated re-keys are tolerated with
    /// no application traffic in between before the connection is dropped.
    pub fn set_max_consecutive_rekeys(&mut self, n: u32) {
        self.transport.set_max_consecutive_peer_rekeys(n);
    }

    /// Open a session channel and run `command` once the channel is confirmed. Must be
    /// called after [`ClientEvent::Authenticated`].
    pub fn exec(&mut self, command: &str) -> Result<()> {
        self.open_session(PendingRequest::Exec(command.into()))
    }

    /// Open a session channel and request an interactive shell once confirmed.
    pub fn shell(&mut self) -> Result<()> {
        self.open_session(PendingRequest::Shell)
    }

    /// Request a PTY for the next [`Self::exec`]/[`Self::shell`] session: the `pty-req`
    /// is sent between the channel open and the session request, like OpenSSH does.
    /// Watch for [`ClientEvent::PtyGranted`] (go raw) / [`ClientEvent::PtyRefused`]
    /// (stay cooked) before changing local terminal modes.
    pub fn request_pty(&mut self, term: &str, cols: u16, rows: u16) {
        self.want_pty = Some(PtyParams {
            term: term.into(),
            cols,
            rows,
        });
    }

    /// Tell the server the local terminal was resized (`window-change`). A no-op
    /// before the session channel is open.
    pub fn window_change(&mut self, cols: u16, rows: u16) -> Result<()> {
        let Some(ch) = self.channel.as_ref() else {
            return Ok(());
        };
        let remote = ch.remote_id;
        self.transport
            .send_packet(&conn::channel_request_window_change(
                remote, cols, rows, 0, 0,
            ))
    }

    fn open_session(&mut self, request: PendingRequest) -> Result<()> {
        if !self.is_authenticated() {
            return Err(SshError::Protocol("session open before authentication"));
        }
        self.channel = Some(Channel::new(LOCAL_CHANNEL));
        self.pending = Some(request);
        self.transport
            .send_packet(&conn::channel_open_session(LOCAL_CHANNEL))
    }

    /// Send process stdin (respecting the remote window).
    pub fn write_stdin(&mut self, data: &[u8]) -> Result<()> {
        if let Some(ch) = self.channel.as_mut() {
            ch.enqueue_stdout(data);
        }
        self.flush_channel()
    }

    /// Signal end-of-input on stdin. EOF is deferred until any queued stdin has been
    /// flushed, so it never overtakes buffered data when the window opens late.
    pub fn send_eof(&mut self) -> Result<()> {
        if let Some(ch) = self.channel.as_mut() {
            ch.request_eof();
        }
        self.flush_channel()
    }

    /// Configure traffic obfuscation (channel-data chunking + `SSH_MSG_IGNORE` chaff).
    /// Off by default; see [`Obfuscation`]. Takes effect on subsequent channel writes.
    pub fn set_obfuscation(&mut self, obfuscation: Obfuscation) {
        self.transport.set_obfuscation(obfuscation);
    }

    /// Emit one chaff (`SSH_MSG_IGNORE`) packet with a random-length random payload. A
    /// driver may call this on an idle timer to mask keystroke *timing*. No-op until the
    /// connection is established; the server silently discards it.
    pub fn send_chaff(&mut self) -> Result<()> {
        self.transport.send_chaff()
    }

    fn pump(&mut self) -> Result<()> {
        while let Some(event) = self.transport.poll_event() {
            match event {
                Event::ServerHostKey(key) => {
                    if !self.handler.verify_host_key(&key) {
                        self.host_rejected = true;
                        self.events.push_back(ClientEvent::HostKeyRejected);
                        self.transport
                            .disconnect(msg::disconnect::KEY_EXCHANGE_FAILED, "host key rejected");
                        self.state = State::Done;
                    }
                }
                Event::Established => {
                    if !self.host_rejected {
                        self.transport
                            .send_packet(&auth::service_request(auth::SERVICE_USERAUTH))?;
                        self.state = State::ExpectServiceAccept;
                    }
                }
                Event::Disconnect {
                    reason,
                    description,
                } => {
                    self.events.push_back(ClientEvent::Disconnect {
                        reason,
                        description,
                    });
                }
                Event::Packet(payload) => self.handle_packet(payload.expose_secret())?,
            }
        }
        Ok(())
    }

    fn handle_packet(&mut self, payload: &[u8]) -> Result<()> {
        match payload.first().copied() {
            Some(msg::SERVICE_ACCEPT) if self.state == State::ExpectServiceAccept => {
                self.state = State::Authenticating;
                self.try_next_auth(&[])
            }
            Some(msg::USERAUTH_BANNER) => {
                let mut r = Reader::new(payload);
                r.u8()?;
                self.events
                    .push_back(ClientEvent::Banner(r.utf8().unwrap_or("").into()));
                Ok(())
            }
            Some(msg::USERAUTH_SUCCESS) => {
                self.state = State::Authenticated;
                self.events.push_back(ClientEvent::Authenticated);
                Ok(())
            }
            Some(msg::USERAUTH_FAILURE) => {
                let mut r = Reader::new(payload);
                r.u8()?;
                let methods = r.name_list()?;
                let _partial = r.boolean()?;
                self.try_next_auth(&methods)
            }
            Some(msg::USERAUTH_PK_OK) => Ok(()),
            Some(msg::CHANNEL_OPEN_CONFIRMATION) => self.handle_open_confirmation(payload),
            Some(msg::CHANNEL_OPEN_FAILURE) => self.handle_open_failure(payload),
            Some(msg::CHANNEL_SUCCESS) => {
                // Replies arrive in send order; attribute against the queue.
                if let Some(PendingReply::Pty) = self.reply_queue.pop_front() {
                    self.events.push_back(ClientEvent::PtyGranted);
                }
                Ok(())
            }
            Some(msg::CHANNEL_FAILURE) => match self.reply_queue.pop_front() {
                // A refused PTY is survivable: the session continues in cooked mode.
                Some(PendingReply::Pty) => {
                    self.events.push_back(ClientEvent::PtyRefused);
                    Ok(())
                }
                // The exec/shell request was refused — report and tear the channel down.
                _ => self.handle_request_failure(),
            },
            Some(msg::CHANNEL_DATA) => self.handle_channel_data(payload),
            Some(msg::CHANNEL_EXTENDED_DATA) => self.handle_extended_data(payload),
            Some(msg::CHANNEL_WINDOW_ADJUST) => self.handle_window_adjust(payload),
            Some(msg::CHANNEL_REQUEST) => self.handle_channel_request(payload),
            Some(msg::CHANNEL_EOF) => Ok(()),
            Some(msg::CHANNEL_CLOSE) => self.handle_channel_close(),
            _ => Ok(()),
        }
    }

    fn try_next_auth(&mut self, can_continue: &[Box<str>]) -> Result<()> {
        let user = self.handler.username();
        match self.handler.next_auth(can_continue) {
            Some(AuthAttempt::Password(password)) => {
                let req = auth::password_request(&user, auth::SERVICE_CONNECTION, &password);
                self.transport.send_packet(&req)
            }
            Some(AuthAttempt::PublicKey(keypair)) => {
                let session_id = self
                    .transport
                    .session_id()
                    .ok_or(SshError::Protocol("no session id"))?
                    .to_vec();
                let blob = keypair.public().blob();
                let signed = auth::publickey_signed_data(
                    &session_id,
                    &user,
                    auth::SERVICE_CONNECTION,
                    HOSTKEY_ED25519,
                    &blob,
                );
                let signature = keypair.sign(&signed);
                let req = auth::publickey_request(
                    &user,
                    auth::SERVICE_CONNECTION,
                    HOSTKEY_ED25519,
                    &blob,
                    Some(&signature),
                );
                self.transport.send_packet(&req)
            }
            None => {
                self.events.push_back(ClientEvent::AuthFailed {
                    methods: can_continue.to_vec(),
                });
                self.state = State::Done;
                Ok(())
            }
        }
    }

    fn handle_open_confirmation(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let sender = r.u32()?;
        let window = r.u32()?;
        let max_packet = r.u32()?;
        let Some(ch) = self.channel.as_mut() else {
            return Ok(());
        };
        ch.set_remote(sender, window, max_packet);
        let remote = ch.remote_id;
        self.events.push_back(ClientEvent::ChannelReady {
            channel: LOCAL_CHANNEL,
        });
        // pty-req precedes the session request; replies arrive in the same order.
        if let Some(pty) = self.want_pty.take() {
            let info = conn::PtyInfo {
                term: pty.term,
                cols: pty.cols,
                rows: pty.rows,
                width_px: 0,
                height_px: 0,
                modes: Vec::new(),
            };
            self.transport
                .send_packet(&conn::channel_request_pty(remote, true, &info))?;
            self.reply_queue.push_back(PendingReply::Pty);
        }
        match self.pending.take() {
            Some(PendingRequest::Exec(command)) => {
                self.transport
                    .send_packet(&conn::channel_request_exec(remote, true, &command))?;
                self.reply_queue.push_back(PendingReply::Session);
            }
            Some(PendingRequest::Shell) => {
                self.transport
                    .send_packet(&conn::channel_request_shell(remote, true))?;
                self.reply_queue.push_back(PendingReply::Session);
            }
            None => {}
        }
        // Flush any stdin that was buffered before the window was known.
        self.flush_channel()
    }

    fn handle_open_failure(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let reason = r.u32()?;
        let description = r.utf8().unwrap_or("").into();
        self.channel = None;
        self.reply_queue.clear();
        self.events.push_back(ClientEvent::ChannelOpenFailure {
            reason,
            description,
        });
        Ok(())
    }

    fn handle_channel_data(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let data = r.string()?;
        self.replenish_window(data.len() as u32)?;
        self.events.push_back(ClientEvent::Stdout(data.into()));
        Ok(())
    }

    fn handle_extended_data(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let _data_type = r.u32()?;
        let data = r.string()?;
        self.replenish_window(data.len() as u32)?;
        self.events.push_back(ClientEvent::Stderr(data.into()));
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

    fn handle_channel_request(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let request = r.utf8()?;
        let _want_reply = r.boolean()?;
        if request == "exit-status" {
            let status = r.u32()?;
            self.events.push_back(ClientEvent::ExitStatus(status));
        }
        Ok(())
    }

    fn handle_request_failure(&mut self) -> Result<()> {
        self.events.push_back(ClientEvent::RequestFailed);
        if let Some(ch) = self.channel.as_mut()
            && !ch.sent_close
        {
            ch.sent_close = true;
            let remote = ch.remote_id;
            self.transport.send_packet(&conn::channel_close(remote))?;
        }
        self.channel = None;
        self.reply_queue.clear();
        self.events.push_back(ClientEvent::ChannelClosed);
        Ok(())
    }

    fn handle_channel_close(&mut self) -> Result<()> {
        if let Some(ch) = self.channel.as_mut()
            && !ch.sent_close
        {
            ch.sent_close = true;
            let remote = ch.remote_id;
            self.transport.send_packet(&conn::channel_close(remote))?;
        }
        self.channel = None;
        self.reply_queue.clear();
        self.events.push_back(ClientEvent::ChannelClosed);
        Ok(())
    }

    fn replenish_window(&mut self, len: u32) -> Result<()> {
        // The client hands data straight to the embedding application via events, so it
        // is consumed (acked) as soon as it is accounted — unlike the server, where the
        // window replenishes only as the handler actually drains its stdin.
        let Some(ch) = self.channel.as_mut() else {
            return Ok(());
        };
        if !ch.consume_incoming(len) {
            // The server overran the window it was granted: drop the connection.
            self.transport
                .disconnect(msg::disconnect::PROTOCOL_ERROR, "channel window exceeded");
            return Ok(());
        }
        let remote = ch.remote_id;
        if let Some(add) = ch.ack_incoming(len) {
            self.transport
                .send_packet(&conn::channel_window_adjust(remote, add))?;
        }
        Ok(())
    }

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

        // Interleave chaff after real data so an observer can't tell which packets carry
        // it (no-op unless obfuscation chaff is enabled).
        if sent_any {
            transport.send_chaff_burst()?;
        }

        if ch.out_is_empty() && ch.eof_requested() && !ch.sent_eof {
            ch.sent_eof = true;
            transport.send_packet(&conn::channel_eof(ch.remote_id))?;
        }
        Ok(())
    }
}
