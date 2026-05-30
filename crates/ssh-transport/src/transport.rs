//! The sans-IO SSH transport state machine (RFC 4253): identification exchange,
//! `KEXINIT` negotiation, `curve25519-sha256` key exchange, `NEWKEYS`, and the switch
//! to authenticated encryption. Drives both the client and server roles.
//!
//! The driver feeds socket bytes via [`Transport::on_input`], drains bytes to write via
//! [`Transport::take_output`], and pulls high-level [`Event`]s via
//! [`Transport::poll_event`]. After the handshake, application layers exchange packets
//! through [`Transport::send_packet`] and [`Event::Packet`].

use std::collections::VecDeque;

use rand_core::{CryptoRng, RngCore};

use crate::algo::{self, KexInit, Negotiated};
use crate::cipher::Cipher;
use crate::hostkey::{HostKey, HostPublicKey};
use crate::kdf::{self, ExchangeHashInput};
use crate::kex::EcdhKeypair;
use crate::version;
use crate::wire::{Reader, Writer};
use crate::{Result, SshError, msg};

/// Connection role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

/// High-level events surfaced to the driver.
#[derive(Debug)]
pub enum Event {
    /// Client only: the server's host key. The driver must enforce known-hosts policy
    /// and call [`Transport::disconnect`] if it is not trusted. The signature over the
    /// exchange hash has already been cryptographically verified.
    ServerHostKey(HostPublicKey),
    /// The secure transport is established; `session_id` is now available.
    Established,
    /// A decrypted application-layer packet (auth/connection protocol payload).
    Packet(Vec<u8>),
    /// The peer sent `SSH_MSG_DISCONNECT`.
    Disconnect { reason: u32, description: Box<str> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    NeedPeerVersion,
    Handshake,
    Established,
}

/// Application bytes after which we proactively re-key (RFC 4253 §9 suggests ~1 GiB).
const REKEY_BYTES: u64 = 1 << 30;

/// Pending new directional ciphers, installed at the corresponding `NEWKEYS`.
struct PendingKeys {
    out: Cipher,
    inn: Cipher,
}

/// The SSH transport engine.
pub struct Transport<R: RngCore + CryptoRng> {
    role: Role,
    rng: R,
    phase: Phase,

    rx: Vec<u8>,
    tx: Vec<u8>,
    tx_seq: u32,
    rx_seq: u32,
    cipher_out: Cipher,
    cipher_in: Cipher,

    local_id: Vec<u8>,
    peer_id: Option<Vec<u8>>,
    local_kexinit: Vec<u8>,
    peer_kexinit: Option<KexInit>,
    negotiated: Option<Negotiated>,
    ecdh: Option<EcdhKeypair>,
    pending: Option<PendingKeys>,
    sent_newkeys: bool,
    recv_newkeys: bool,
    skip_guess: bool,
    /// Strict KEX (Terrapin mitigation): reset sequence numbers at NEWKEYS and forbid
    /// non-KEX messages during the initial exchange. Enabled when both peers advertise.
    strict_kex: bool,
    /// Set once the first key exchange completes (the connection is up). Sequence-number
    /// resets under strict KEX apply only to that initial exchange, not to rekeys.
    initial_kex_done: bool,
    /// A re-key is in progress: we have sent our KEXINIT but not yet our NEWKEYS, so
    /// application packets are queued rather than sent.
    rekeying: bool,
    /// Whether our KEXINIT for the current round has been sent.
    kexinit_sent: bool,
    /// Application packets deferred while [`Self::rekeying`].
    tx_app_queue: VecDeque<Vec<u8>>,
    /// Application-payload bytes sent since the last key exchange (auto-rekey trigger).
    bytes_since_rekey: u64,
    session_id: Option<[u8; 32]>,

    host_key: Option<HostKey>,
    events: VecDeque<Event>,
}

impl<R: RngCore + CryptoRng> Transport<R> {
    /// Start a client transport, queuing our identification and KEXINIT.
    pub fn new_client(rng: R) -> Self {
        Self::start(Role::Client, rng, None)
    }

    /// Start a server transport with the given host key.
    pub fn new_server(rng: R, host_key: HostKey) -> Self {
        Self::start(Role::Server, rng, Some(host_key))
    }

    fn start(role: Role, rng: R, host_key: Option<HostKey>) -> Self {
        let mut t = Self {
            role,
            rng,
            phase: Phase::NeedPeerVersion,
            rx: Vec::new(),
            tx: version::local_id_line(),
            tx_seq: 0,
            rx_seq: 0,
            cipher_out: Cipher::None,
            cipher_in: Cipher::None,
            local_id: version::LOCAL_ID.as_bytes().to_vec(),
            peer_id: None,
            local_kexinit: Vec::new(),
            peer_kexinit: None,
            negotiated: None,
            ecdh: None,
            pending: None,
            sent_newkeys: false,
            recv_newkeys: false,
            skip_guess: false,
            strict_kex: false,
            initial_kex_done: false,
            rekeying: false,
            kexinit_sent: false,
            tx_app_queue: VecDeque::new(),
            bytes_since_rekey: 0,
            session_id: None,
            host_key,
            events: VecDeque::new(),
        };
        // KEXINIT is the first binary packet, sent unencrypted right after the version.
        t.send_kexinit();
        t
    }

    /// Build and queue our KEXINIT for the current key-exchange round.
    fn send_kexinit(&mut self) {
        let ki = KexInit::ours(&mut self.rng, self.role == Role::Server);
        self.local_kexinit = ki.payload;
        let payload = self.local_kexinit.clone();
        self.write_packet(&payload);
        self.kexinit_sent = true;
    }

    /// Feed bytes received from the socket and advance the state machine.
    pub fn on_input(&mut self, data: &[u8]) -> Result<()> {
        self.rx.extend_from_slice(data);
        self.drive()
    }

    /// Drain bytes that should be written to the socket.
    pub fn take_output(&mut self) -> Vec<u8> {
        core::mem::take(&mut self.tx)
    }

    /// Pull the next high-level event, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    pub fn is_established(&self) -> bool {
        self.phase == Phase::Established
    }

    pub fn session_id(&self) -> Option<&[u8]> {
        self.session_id.as_ref().map(|s| s.as_slice())
    }

    /// Queue an application-layer packet (only valid once established). While a re-key
    /// is in progress the packet is buffered and flushed once the new keys are in place
    /// (RFC 4253 §9 forbids non-KEX traffic during the exchange).
    pub fn send_packet(&mut self, payload: &[u8]) -> Result<()> {
        if self.phase != Phase::Established {
            return Err(SshError::Protocol("send before transport established"));
        }
        if self.rekeying {
            self.tx_app_queue.push_back(payload.to_vec());
            return Ok(());
        }
        self.write_packet(payload);
        self.bytes_since_rekey = self.bytes_since_rekey.saturating_add(payload.len() as u64);
        if self.bytes_since_rekey >= REKEY_BYTES {
            self.initiate_rekey();
        }
        Ok(())
    }

    /// Begin a key re-exchange if the connection is established and not already rekeying.
    /// Application traffic is queued until the new keys take effect.
    pub fn initiate_rekey(&mut self) {
        if self.phase == Phase::Established && !self.rekeying {
            self.begin_rekey_round();
        }
    }

    /// Whether a key re-exchange is currently in progress.
    pub fn is_rekeying(&self) -> bool {
        self.rekeying
    }

    /// Reset per-round KEX state and send a fresh KEXINIT to start a re-key.
    fn begin_rekey_round(&mut self) {
        self.rekeying = true;
        self.sent_newkeys = false;
        self.recv_newkeys = false;
        self.peer_kexinit = None;
        self.negotiated = None;
        self.ecdh = None;
        self.skip_guess = false;
        self.send_kexinit();
    }

    /// Queue a `SSH_MSG_DISCONNECT` and detail.
    pub fn disconnect(&mut self, reason: u32, description: &str) {
        let mut w = Writer::new();
        w.u8(msg::DISCONNECT);
        w.u32(reason);
        w.string(description.as_bytes());
        w.string(b""); // language tag
        self.write_packet(&w.into_bytes());
    }

    // --- internals ---

    fn write_packet(&mut self, payload: &[u8]) {
        if std::env::var_os("SSH_DEBUG").is_some() {
            let plaintext = matches!(self.cipher_out, Cipher::None);
            eprintln!(
                "[dbg {:?}] SEND msg={} seq={} plaintext={}",
                self.role,
                payload.first().copied().unwrap_or(0),
                self.tx_seq,
                plaintext
            );
        }
        let frame = self.cipher_out.seal(self.tx_seq, payload, &mut self.rng);
        self.tx.extend_from_slice(&frame);
        self.tx_seq = self.tx_seq.wrapping_add(1);
    }

    fn drive(&mut self) -> Result<()> {
        loop {
            if self.phase == Phase::NeedPeerVersion {
                let allow_banner = self.role == Role::Client;
                match version::parse_peer_id(&self.rx, allow_banner)? {
                    Some((peer, consumed)) => {
                        self.peer_id = Some(peer.raw);
                        self.rx.drain(..consumed);
                        self.phase = Phase::Handshake;
                    }
                    None => return Ok(()),
                }
                continue;
            }

            match self.cipher_in.open(self.rx_seq, &self.rx)? {
                Some((payload, consumed)) => {
                    self.rx.drain(..consumed);
                    self.rx_seq = self.rx_seq.wrapping_add(1);
                    self.handle_packet(payload)?;
                }
                None => return Ok(()),
            }
        }
    }

    fn handle_packet(&mut self, payload: Vec<u8>) -> Result<()> {
        let Some(&msg_id) = payload.first() else {
            return Err(SshError::BadPacket("empty payload"));
        };

        if std::env::var_os("SSH_DEBUG").is_some() {
            eprintln!(
                "[dbg {:?}] RECV msg={} seq={} phase={:?}",
                self.role,
                msg_id,
                self.rx_seq - 1,
                self.phase
            );
        }

        // Under strict KEX, no IGNORE/DEBUG/UNIMPLEMENTED may appear during the initial
        // key exchange — their presence is the Terrapin injection vector.
        if self.strict_kex
            && self.phase != Phase::Established
            && matches!(msg_id, msg::IGNORE | msg::DEBUG | msg::UNIMPLEMENTED)
        {
            return Err(SshError::Protocol("unexpected message during strict KEX"));
        }

        // Transport housekeeping messages are valid in any phase.
        match msg_id {
            msg::IGNORE | msg::DEBUG => return Ok(()),
            msg::DISCONNECT => {
                let mut r = Reader::new(&payload);
                r.u8()?;
                let reason = r.u32()?;
                let description = r.utf8().unwrap_or("").into();
                self.events.push_back(Event::Disconnect { reason, description });
                return Ok(());
            }
            _ => {}
        }

        // Key-exchange messages are handled in any phase — the initial handshake and a
        // mid-session re-key share the same machinery.
        match msg_id {
            msg::KEXINIT => return self.on_peer_kexinit(payload),
            msg::KEX_ECDH_INIT if self.role == Role::Server => return self.on_ecdh_init(&payload),
            msg::KEX_ECDH_REPLY if self.role == Role::Client => return self.on_ecdh_reply(&payload),
            msg::NEWKEYS => return self.on_newkeys(),
            _ => {}
        }

        if self.phase == Phase::Established {
            self.events.push_back(Event::Packet(payload));
            Ok(())
        } else {
            Err(SshError::Protocol("unexpected message during handshake"))
        }
    }

    fn on_peer_kexinit(&mut self, payload: Vec<u8>) -> Result<()> {
        // A KEXINIT received while established and idle is a peer-initiated re-key;
        // respond with our own KEXINIT before proceeding.
        if self.phase == Phase::Established && !self.kexinit_sent {
            self.begin_rekey_round();
        }
        let peer = KexInit::parse(&payload)?;
        let local = KexInit::parse(&self.local_kexinit)?;
        let (client, server) = match self.role {
            Role::Client => (&local, &peer),
            Role::Server => (&peer, &local),
        };
        let negotiated = algo::negotiate(client, server)?;

        // Strict KEX engages only if the peer advertised its role's marker, and is
        // decided by the *initial* exchange only — the markers are absent from (and
        // ignored in) rekey KEXINITs, so we must not clear the latched value.
        if !self.initial_kex_done {
            let peer_strict_marker = match self.role {
                Role::Client => algo::KEX_STRICT_SERVER,
                Role::Server => algo::KEX_STRICT_CLIENT,
            };
            self.strict_kex = peer.kex.iter().any(|a| &**a == peer_strict_marker);
        }

        // If the peer guessed and guessed wrong, its next KEX packet must be ignored.
        self.skip_guess = peer.first_kex_packet_follows
            && (peer.kex.first().map(|s| &**s) != Some(&*negotiated.kex)
                || peer.host_key.first().map(|s| &**s) != Some(&*negotiated.host_key));

        self.negotiated = Some(negotiated);
        self.peer_kexinit = Some(peer);

        if self.role == Role::Client {
            // Send SSH_MSG_KEX_ECDH_INIT with our ephemeral public value.
            let kp = EcdhKeypair::generate(&mut self.rng);
            let mut w = Writer::new();
            w.u8(msg::KEX_ECDH_INIT);
            w.string(&kp.public());
            self.write_packet(&w.into_bytes());
            self.ecdh = Some(kp);
        }
        Ok(())
    }

    fn on_ecdh_init(&mut self, payload: &[u8]) -> Result<()> {
        if self.skip_guess {
            self.skip_guess = false;
            return Ok(());
        }
        let mut r = Reader::new(payload);
        r.u8()?;
        let q_c = r.string()?.to_vec();

        let host_key = self
            .host_key
            .as_ref()
            .ok_or(SshError::Protocol("server without host key"))?;
        let host_blob = host_key.public_blob();

        let server_kp = EcdhKeypair::generate(&mut self.rng);
        let q_s = server_kp.public();
        let shared = server_kp.agree(&q_c)?;

        let h = self.compute_exchange_hash(&q_c, &q_s, &host_blob, &shared)?;
        let signature = self.host_key.as_ref().unwrap().sign_exchange_hash(&h);

        let mut w = Writer::new();
        w.u8(msg::KEX_ECDH_REPLY);
        w.string(&host_blob);
        w.string(&q_s);
        w.string(&signature);
        self.write_packet(&w.into_bytes());

        self.finish_kex(h, &shared)?;
        self.send_newkeys();
        Ok(())
    }

    fn on_ecdh_reply(&mut self, payload: &[u8]) -> Result<()> {
        if self.skip_guess {
            self.skip_guess = false;
            return Ok(());
        }
        let mut r = Reader::new(payload);
        r.u8()?;
        let host_blob = r.string()?.to_vec();
        let q_s = r.string()?.to_vec();
        let signature = r.string()?.to_vec();

        let kp = self
            .ecdh
            .take()
            .ok_or(SshError::Protocol("KEX_ECDH_REPLY before INIT"))?;
        let q_c = kp.public().to_vec();
        let shared = kp.agree(&q_s)?;

        let h = self.compute_exchange_hash(&q_c, &q_s, &host_blob, &shared)?;

        let host_pub = HostPublicKey::parse_blob(&host_blob)?;
        host_pub.verify(&h, &signature)?;
        self.events.push_back(Event::ServerHostKey(host_pub));

        self.finish_kex(h, &shared)?;
        self.send_newkeys();
        Ok(())
    }

    fn compute_exchange_hash(
        &self,
        q_c: &[u8],
        q_s: &[u8],
        host_blob: &[u8],
        shared: &[u8],
    ) -> Result<[u8; 32]> {
        let peer_id = self
            .peer_id
            .as_ref()
            .ok_or(SshError::Protocol("missing peer id"))?;
        let peer_kexinit = self
            .peer_kexinit
            .as_ref()
            .ok_or(SshError::Protocol("missing peer kexinit"))?;

        let (client_id, server_id, client_kexinit, server_kexinit) = match self.role {
            Role::Client => (&self.local_id, peer_id, &self.local_kexinit, &peer_kexinit.payload),
            Role::Server => (peer_id, &self.local_id, &peer_kexinit.payload, &self.local_kexinit),
        };

        Ok(kdf::exchange_hash(&ExchangeHashInput {
            client_id,
            server_id,
            client_kexinit,
            server_kexinit,
            host_key_blob: host_blob,
            client_ephemeral: q_c,
            server_ephemeral: q_s,
            shared_secret: shared,
        }))
    }

    /// Derive directional keys and stage the post-NEWKEYS ciphers.
    fn finish_kex(&mut self, h: [u8; 32], shared: &[u8]) -> Result<()> {
        // First key exchange fixes the session id.
        let session_id = *self.session_id.get_or_insert(h);
        let cipher = self.negotiated.as_ref().unwrap().cipher_c2s.clone();
        let key_len = Cipher::key_len(&cipher)?;
        let iv_len = Cipher::iv_len(&cipher)?;
        let keys = kdf::Keys::derive(shared, &h, &session_id, key_len, iv_len);

        let (out_key, out_iv, in_key, in_iv) = match self.role {
            Role::Client => (&keys.enc_c2s, &keys.iv_c2s, &keys.enc_s2c, &keys.iv_s2c),
            Role::Server => (&keys.enc_s2c, &keys.iv_s2c, &keys.enc_c2s, &keys.iv_c2s),
        };
        self.pending = Some(PendingKeys {
            out: Cipher::new(&cipher, out_key, out_iv)?,
            inn: Cipher::new(&cipher, in_key, in_iv)?,
        });
        Ok(())
    }

    fn send_newkeys(&mut self) {
        self.write_packet(&[msg::NEWKEYS]);
        // The next outbound packet uses the new cipher. Under strict KEX the send
        // sequence number resets to zero after *every* NEWKEYS (initial and rekey) —
        // OpenSSH does the same, so we must match to stay in sync.
        if let Some(p) = self.pending.as_mut() {
            self.cipher_out = core::mem::replace(&mut p.out, Cipher::None);
        }
        if self.strict_kex {
            self.tx_seq = 0;
        }
        self.sent_newkeys = true;
        self.maybe_complete_kex();
    }

    fn on_newkeys(&mut self) -> Result<()> {
        let p = self
            .pending
            .as_mut()
            .ok_or(SshError::Protocol("NEWKEYS before key exchange"))?;
        self.cipher_in = core::mem::replace(&mut p.inn, Cipher::None);
        if self.strict_kex {
            self.rx_seq = 0;
        }
        self.recv_newkeys = true;
        self.maybe_complete_kex();
        Ok(())
    }

    /// Once both NEWKEYS are exchanged, finish the round: establish the connection (on
    /// the first exchange) or end the re-key and flush queued application traffic.
    fn maybe_complete_kex(&mut self) {
        if !(self.sent_newkeys && self.recv_newkeys) {
            return;
        }
        self.pending = None;
        if !self.initial_kex_done {
            self.initial_kex_done = true;
            self.phase = Phase::Established;
            self.events.push_back(Event::Established);
        }
        // Reset per-round state so a later re-key starts clean.
        self.rekeying = false;
        self.kexinit_sent = false;
        self.sent_newkeys = false;
        self.recv_newkeys = false;
        self.bytes_since_rekey = 0;

        // Flush application packets deferred during the exchange.
        let queued: Vec<Vec<u8>> = self.tx_app_queue.drain(..).collect();
        for payload in queued {
            self.write_packet(&payload);
        }
    }
}
