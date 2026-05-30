//! Client-side session: wraps the [`Transport`], enforces host-key policy, drives user
//! authentication, and runs a session channel (`exec`). Credentials and known-hosts
//! policy come from a [`ClientAuthHandler`] (a generic parameter — no `dyn`).

use rand_core::{CryptoRng, RngCore};

use crate::algo::HOSTKEY_ED25519;
use crate::auth::{self, UserKeypair};
use crate::connection::{self as conn, Channel};
use crate::transport::Event;
use crate::wire::Reader;
use crate::{HostPublicKey, Result, SshError, Transport, msg};

/// One authentication attempt the client will make.
pub enum AuthAttempt {
    Password(Box<str>),
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
    AuthFailed { methods: Vec<Box<str>> },
    HostKeyRejected,
    /// The session channel was opened and is ready for an `exec`/`shell` request.
    ChannelReady { channel: u32 },
    /// Opening the session channel failed.
    ChannelOpenFailure { reason: u32, description: Box<str> },
    /// Process stdout.
    Stdout(Vec<u8>),
    /// Process stderr.
    Stderr(Vec<u8>),
    /// The command's exit status.
    ExitStatus(u32),
    /// The server refused the exec/shell/subsystem request (`CHANNEL_FAILURE`).
    RequestFailed,
    /// The channel was closed by the server.
    ChannelClosed,
    Disconnect { reason: u32, description: Box<str> },
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

/// A client-side SSH connection (single session channel).
pub struct ClientConnection<R: RngCore + CryptoRng, H: ClientAuthHandler> {
    transport: Transport<R>,
    handler: H,
    state: State,
    host_rejected: bool,
    channel: Option<Channel>,
    pending: Option<PendingRequest>,
    events: std::collections::VecDeque<ClientEvent>,
}

impl<R: RngCore + CryptoRng, H: ClientAuthHandler> ClientConnection<R, H> {
    pub fn new(rng: R, handler: H) -> Self {
        Self {
            transport: Transport::new_client(rng),
            handler,
            state: State::Handshaking,
            host_rejected: false,
            channel: None,
            pending: None,
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

    pub fn poll_event(&mut self) -> Option<ClientEvent> {
        self.events.pop_front()
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.state, State::Authenticated)
    }

    pub fn session_id(&self) -> Option<&[u8]> {
        self.transport.session_id()
    }

    /// Begin a key re-exchange (queues application traffic until it completes).
    pub fn initiate_rekey(&mut self) {
        self.transport.initiate_rekey();
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
                Event::Disconnect { reason, description } => {
                    self.events
                        .push_back(ClientEvent::Disconnect { reason, description });
                }
                Event::Packet(payload) => self.handle_packet(&payload)?,
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
            // The exec/shell/subsystem request was accepted; nothing to do.
            Some(msg::CHANNEL_SUCCESS) => Ok(()),
            // The request was refused — report it and tear the channel down.
            Some(msg::CHANNEL_FAILURE) => self.handle_request_failure(),
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
        self.events
            .push_back(ClientEvent::ChannelReady { channel: LOCAL_CHANNEL });
        match self.pending.take() {
            Some(PendingRequest::Exec(command)) => self
                .transport
                .send_packet(&conn::channel_request_exec(remote, true, &command))?,
            Some(PendingRequest::Shell) => self
                .transport
                .send_packet(&conn::channel_request_shell(remote, true))?,
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
        self.events
            .push_back(ClientEvent::ChannelOpenFailure { reason, description });
        Ok(())
    }

    fn handle_channel_data(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let data = r.string()?.to_vec();
        self.replenish_window(data.len() as u32)?;
        self.events.push_back(ClientEvent::Stdout(data));
        Ok(())
    }

    fn handle_extended_data(&mut self, payload: &[u8]) -> Result<()> {
        let mut r = Reader::new(payload);
        r.u8()?;
        let _recipient = r.u32()?;
        let _data_type = r.u32()?;
        let data = r.string()?.to_vec();
        self.replenish_window(data.len() as u32)?;
        self.events.push_back(ClientEvent::Stderr(data));
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
        self.events.push_back(ClientEvent::ChannelClosed);
        Ok(())
    }

    fn replenish_window(&mut self, len: u32) -> Result<()> {
        if let Some(ch) = self.channel.as_mut()
            && let Some(add) = ch.consume_incoming(len)
        {
            let remote = ch.remote_id;
            self.transport
                .send_packet(&conn::channel_window_adjust(remote, add))?;
        }
        Ok(())
    }

    fn flush_channel(&mut self) -> Result<()> {
        let Some(ch) = self.channel.as_mut() else {
            return Ok(());
        };
        let mut packets = Vec::new();
        ch.drain_output(|p| packets.push(p));

        let mut eof = None;
        if ch.out_is_empty() && ch.eof_requested() && !ch.sent_eof {
            ch.sent_eof = true;
            eof = Some(ch.remote_id);
        }

        for p in packets {
            self.transport.send_packet(&p)?;
        }
        if let Some(remote) = eof {
            self.transport.send_packet(&conn::channel_eof(remote))?;
        }
        Ok(())
    }
}
