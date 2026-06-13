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
use zeroize::Zeroizing;

use crate::algo::{self, COMPRESSION_ZLIB_OPENSSH, KexInit, Negotiated};
use crate::cipher::Cipher;
use crate::compress::{Compressor, Decompressor};
use crate::hostkey::{HostKey, HostPublicKey};
use crate::kdf::{self, ExchangeHashInput, SharedSecret};
use crate::kex::EcdhKeypair;
use crate::mlkem::{self, HybridClient};
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
    /// A decrypted application-layer packet (auth/connection protocol payload). Held in
    /// a [`Zeroizing`] buffer so the plaintext (which may carry a password) is scrubbed
    /// from memory once the consuming layer drops it.
    Packet(Zeroizing<Box<[u8]>>),
    /// The peer sent `SSH_MSG_DISCONNECT`.
    Disconnect { reason: u32, description: Box<str> },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    NeedPeerVersion,
    Handshake,
    Established,
}

/// Traffic bytes (either direction) after which we proactively re-key (RFC 4253 §9
/// suggests ~1 GiB).
const REKEY_BYTES: u64 = 1 << 30;

/// Packets (either direction) after which we proactively re-key (RFC 4344 §3.1 requires
/// rekeying before 2^31 packets). Kept far below 2^32, where the sequence number — which
/// is the AEAD nonce — would otherwise wrap and repeat under the same key.
const REKEY_PACKETS: u64 = 1 << 28;

/// Hard per-key-epoch packet cap. The sequence number may legitimately wrap mod 2^32
/// over a connection's lifetime, but within one key epoch a wrap would repeat an AEAD
/// nonce under the same key. We initiate a re-key at [`REKEY_PACKETS`]; a peer that is
/// still stonewalling it by this count is refused further traffic (RFC 4344 §3.1's
/// 2^31-packet maximum).
const EPOCH_HARD_PACKETS: u64 = 1 << 31;

/// Default for [`Transport::set_max_consecutive_peer_rekeys`]: how many peer-initiated
/// re-keys we tolerate with no application traffic in between before treating it as a
/// re-key flood (key exchange is CPU-heavy, so a peer spamming `KEXINIT` is a cheap
/// asymmetric DoS). The counter resets whenever an application packet arrives, so normal
/// use — which always interleaves data — is never affected.
pub const DEFAULT_MAX_CONSECUTIVE_PEER_REKEYS: u32 = 3;

/// Pending new directional ciphers, installed at the corresponding `NEWKEYS`.
struct PendingKeys {
    out: Cipher,
    inn: Cipher,
}

/// Client-side ephemeral key-exchange state held between our `SSH_MSG_KEX_ECDH_INIT` and
/// the server's reply: classical `curve25519-sha256` or the `mlkem768x25519-sha256`
/// hybrid, depending on what was negotiated this round.
enum KexEphemeral {
    Classical(EcdhKeypair),
    Hybrid(HybridClient),
}

/// Wrap the raw shared secret with the encoding its KEX method requires: the hybrid
/// method's `K` is already the 32-byte combined hash (an SSH `string`), while curve25519's
/// is the raw X25519 magnitude (an `mpint`).
fn shared_secret(hybrid: bool, shared: &[u8]) -> SharedSecret<'_> {
    if hybrid {
        SharedSecret::String(shared)
    } else {
        SharedSecret::Mpint(shared)
    }
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
    comp_out: Compressor,
    comp_in: Decompressor,
    /// Negotiated compression names for the current key epoch (directional).
    comp_out_name: Box<str>,
    comp_in_name: Box<str>,
    /// Whether delayed compression (`zlib@openssh.com`) has engaged (post-auth).
    comp_active: bool,

    local_id: Vec<u8>,
    peer_id: Option<Vec<u8>>,
    local_kexinit: Vec<u8>,
    peer_kexinit: Option<KexInit>,
    negotiated: Option<Negotiated>,
    kex_eph: Option<KexEphemeral>,
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
    /// Packets sent since the last key exchange (auto-rekey trigger).
    tx_packets_since_rekey: u64,
    /// Wire bytes received since the last key exchange (auto-rekey trigger).
    rx_bytes_since_rekey: u64,
    /// Packets received since the last key exchange (auto-rekey trigger).
    rx_packets_since_rekey: u64,
    /// Byte/packet thresholds that force a re-key ([`REKEY_BYTES`]/[`REKEY_PACKETS`] by
    /// default; settable so tests can exercise the trigger without gigabytes of traffic).
    rekey_bytes_limit: u64,
    rekey_packets_limit: u64,
    /// Peer-initiated re-keys since the last application packet (re-key flood guard).
    consecutive_peer_rekeys: u32,
    /// Tolerated burst before a re-key flood is treated as abuse (settable by user code).
    max_consecutive_peer_rekeys: u32,
    session_id: Option<[u8; 32]>,

    host_key: Option<HostKey>,
    events: VecDeque<Event>,
    /// Cipher names to offer (preference order), or `None` for the default set. Preserved
    /// across rekeys so a pinned preference stays in effect.
    offered_ciphers: Option<Vec<Box<str>>>,
    /// Compression names to offer (preference order), or `None` for the default set.
    offered_compression: Option<Vec<Box<str>>>,
    /// Set once we have queued our own `SSH_MSG_DISCONNECT`. No further peer input is
    /// processed; the driver should flush the queued bytes and close the connection.
    closing: bool,
}

impl<R: RngCore + CryptoRng> Transport<R> {
    /// Start a client transport, queuing our identification and KEXINIT.
    pub fn new_client(rng: R) -> Self {
        Self::start(Role::Client, rng, None, None, None)
    }

    /// Start a client transport offering `ciphers` (preference order) instead of the
    /// default set. Negotiation prefers the client's order, so this pins which cipher is
    /// selected when the server supports it.
    pub fn new_client_with_ciphers(rng: R, ciphers: &[&str]) -> Self {
        let pref = ciphers.iter().map(|s| Box::from(*s)).collect();
        Self::start(Role::Client, rng, None, Some(pref), None)
    }

    /// Start a client transport offering `compression` (preference order). Negotiation
    /// prefers the client's order, so listing `zlib@openssh.com` first turns on delayed
    /// compression when the server supports it.
    pub fn new_client_with_compression(rng: R, compression: &[&str]) -> Self {
        let pref = compression.iter().map(|s| Box::from(*s)).collect();
        Self::start(Role::Client, rng, None, None, Some(pref))
    }

    /// Start a server transport with the given host key.
    pub fn new_server(rng: R, host_key: HostKey) -> Self {
        Self::start(Role::Server, rng, Some(host_key), None, None)
    }

    fn start(
        role: Role,
        rng: R,
        host_key: Option<HostKey>,
        offered_ciphers: Option<Vec<Box<str>>>,
        offered_compression: Option<Vec<Box<str>>>,
    ) -> Self {
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
            comp_out: Compressor::None,
            comp_in: Decompressor::None,
            comp_out_name: Box::from("none"),
            comp_in_name: Box::from("none"),
            comp_active: false,
            local_id: version::LOCAL_ID.as_bytes().to_vec(),
            peer_id: None,
            local_kexinit: Vec::new(),
            peer_kexinit: None,
            negotiated: None,
            kex_eph: None,
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
            tx_packets_since_rekey: 0,
            rx_bytes_since_rekey: 0,
            rx_packets_since_rekey: 0,
            rekey_bytes_limit: REKEY_BYTES,
            rekey_packets_limit: REKEY_PACKETS,
            consecutive_peer_rekeys: 0,
            max_consecutive_peer_rekeys: DEFAULT_MAX_CONSECUTIVE_PEER_REKEYS,
            session_id: None,
            host_key,
            events: VecDeque::new(),
            offered_ciphers,
            offered_compression,
            closing: false,
        };
        // KEXINIT is the first binary packet, sent unencrypted right after the version.
        t.send_kexinit();
        t
    }

    /// Build and queue our KEXINIT for the current key-exchange round.
    fn send_kexinit(&mut self) {
        let is_server = self.role == Role::Server;
        let ciphers: Vec<&str> = match &self.offered_ciphers {
            Some(pref) => pref.iter().map(|s| &**s).collect(),
            None => algo::default_ciphers().to_vec(),
        };
        let compressions: Vec<&str> = match &self.offered_compression {
            Some(pref) => pref.iter().map(|s| &**s).collect(),
            None => algo::default_compressions().to_vec(),
        };
        let ki = KexInit::ours_with(&mut self.rng, is_server, &ciphers, &compressions);
        self.local_kexinit = ki.payload;
        let payload = self.local_kexinit.clone();
        self.write_packet(&payload);
        self.kexinit_sent = true;
    }

    /// Feed bytes received from the socket and advance the state machine.
    pub fn on_input(&mut self, data: &[u8]) -> Result<()> {
        // Once we have decided to disconnect, ignore (and do not buffer) further input.
        if self.closing {
            return Ok(());
        }
        self.rx.extend_from_slice(data);
        self.drive()
    }

    /// Whether we have queued our own disconnect and the connection should be closed once
    /// the pending output is flushed.
    pub fn is_closing(&self) -> bool {
        self.closing
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

    /// The cipher negotiated by the most recent key exchange, if any (e.g.
    /// `chacha20-poly1305@openssh.com`). Both directions always use the same cipher.
    pub fn negotiated_cipher(&self) -> Option<&str> {
        self.negotiated.as_ref().map(|n| &*n.cipher_c2s)
    }

    /// The compression negotiated by the most recent key exchange (e.g. `none` or
    /// `zlib@openssh.com`), if any.
    pub fn negotiated_compression(&self) -> Option<&str> {
        self.negotiated.as_ref().map(|n| &*n.comp_c2s)
    }

    /// Whether delayed compression has engaged (i.e. authentication has completed and a
    /// compressing algorithm was negotiated).
    pub fn is_compression_active(&self) -> bool {
        self.comp_active
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
        if self.bytes_since_rekey >= self.rekey_bytes_limit
            || self.tx_packets_since_rekey >= self.rekey_packets_limit
        {
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

    /// Set how many peer-initiated re-keys are tolerated with no application traffic in
    /// between before the peer is dropped as a re-key flood (see
    /// [`DEFAULT_MAX_CONSECUTIVE_PEER_REKEYS`]). A higher value is more permissive.
    pub fn set_max_consecutive_peer_rekeys(&mut self, n: u32) {
        self.max_consecutive_peer_rekeys = n;
    }

    /// Override the traffic thresholds (bytes and packets, per direction) that force an
    /// automatic re-key. The defaults (1 GiB / 2^28 packets) follow RFC 4253 §9 and
    /// RFC 4344 §3.1; raising the packet limit toward 2^32 risks AEAD nonce reuse.
    /// Intended for tests.
    pub fn set_rekey_limits(&mut self, bytes: u64, packets: u64) {
        self.rekey_bytes_limit = bytes;
        self.rekey_packets_limit = packets;
    }

    /// Reset per-round KEX state and send a fresh KEXINIT to start a re-key.
    fn begin_rekey_round(&mut self) {
        self.rekeying = true;
        self.sent_newkeys = false;
        self.recv_newkeys = false;
        self.peer_kexinit = None;
        self.negotiated = None;
        self.kex_eph = None;
        self.skip_guess = false;
        self.send_kexinit();
    }

    /// Queue a `SSH_MSG_DISCONNECT` and detail, and enter the closing state so no further
    /// peer input is processed (the driver flushes the queued bytes and closes).
    pub fn disconnect(&mut self, reason: u32, description: &str) {
        if self.closing {
            return;
        }
        let mut w = Writer::new();
        w.u8(msg::DISCONNECT);
        w.u32(reason);
        w.string(description.as_bytes());
        w.string(b""); // language tag
        self.write_packet(&w.into_bytes());
        self.closing = true;
    }

    // --- internals ---

    fn write_packet(&mut self, payload: &[u8]) {
        // Once closing (peer misbehaviour or sequence exhaustion), emit nothing further.
        if self.closing {
            return;
        }
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
        // Compress the payload (if active) before sealing.
        let compressed: Box<[u8]>;
        let body: &[u8] = if matches!(self.comp_out, Compressor::None) {
            payload
        } else {
            compressed = self.comp_out.compress(payload.into());
            &compressed
        };
        let frame = self.cipher_out.seal(self.tx_seq, body, &mut self.rng);
        self.tx.extend_from_slice(&frame);
        self.tx_packets_since_rekey += 1;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        if self.tx_packets_since_rekey >= EPOCH_HARD_PACKETS {
            // The peer has ignored our re-key for ~2 billion packets; continuing toward
            // 2^32 would reuse an AEAD nonce under the current key. Stop sending.
            self.closing = true;
        }

        // Delayed compression engages once the server has *sent* USERAUTH_SUCCESS (which
        // is itself sent uncompressed, above). All later packets are compressed.
        if self.role == Role::Server
            && !self.comp_active
            && &*self.comp_out_name == COMPRESSION_ZLIB_OPENSSH
            && payload.first() == Some(&msg::USERAUTH_SUCCESS)
        {
            self.activate_compression();
        }
    }

    /// Engage delayed compression in both directions (fresh contexts).
    fn activate_compression(&mut self) {
        self.comp_active = true;
        self.comp_out = Compressor::new(&self.comp_out_name);
        self.comp_in = Decompressor::new(&self.comp_in_name);
    }

    /// Decompress an inbound payload (passing it through when compression is inactive).
    fn decompress_in(&mut self, payload: Zeroizing<Box<[u8]>>) -> Result<Zeroizing<Box<[u8]>>> {
        if matches!(self.comp_in, Decompressor::None) {
            Ok(payload)
        } else {
            Ok(Zeroizing::new(self.comp_in.decompress(&payload)?))
        }
    }

    fn drive(&mut self) -> Result<()> {
        loop {
            // Stop processing as soon as we have decided to disconnect.
            if self.closing {
                return Ok(());
            }
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
                    self.rx_bytes_since_rekey =
                        self.rx_bytes_since_rekey.saturating_add(consumed as u64);
                    self.rx_packets_since_rekey += 1;
                    // The sequence number is the AEAD nonce: 2^32 packets in one key
                    // epoch would repeat a nonce under the same key (and let captured
                    // ciphertext be replayed). We initiate a re-key far earlier (below);
                    // a peer still flooding past this cap is refused.
                    if self.rx_packets_since_rekey >= EPOCH_HARD_PACKETS {
                        return Err(SshError::Protocol(
                            "peer exceeded per-key-epoch packet limit without re-keying",
                        ));
                    }
                    let payload = self.decompress_in(payload)?;
                    let first = payload.first().copied();
                    self.handle_packet(payload)?;
                    // Delayed compression engages once the client has *received*
                    // USERAUTH_SUCCESS (decompressed above as plaintext while inactive).
                    if self.role == Role::Client
                        && !self.comp_active
                        && &*self.comp_in_name == COMPRESSION_ZLIB_OPENSSH
                        && first == Some(msg::USERAUTH_SUCCESS)
                    {
                        self.activate_compression();
                    }
                    // Inbound traffic counts toward the re-key budget too — a peer that
                    // only ever sends must still not exceed one key epoch's safe volume.
                    if self.phase == Phase::Established
                        && (self.rx_bytes_since_rekey >= self.rekey_bytes_limit
                            || self.rx_packets_since_rekey >= self.rekey_packets_limit)
                    {
                        self.initiate_rekey();
                    }
                }
                None => return Ok(()),
            }
        }
    }

    fn handle_packet(&mut self, payload: Zeroizing<Box<[u8]>>) -> Result<()> {
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
                self.events.push_back(Event::Disconnect {
                    reason,
                    description,
                });
                return Ok(());
            }
            _ => {}
        }

        // Key-exchange messages are handled in any phase — the initial handshake and a
        // mid-session re-key share the same machinery.
        match msg_id {
            msg::KEXINIT => return self.on_peer_kexinit(&payload),
            msg::KEX_ECDH_INIT if self.role == Role::Server => return self.on_ecdh_init(&payload),
            msg::KEX_ECDH_REPLY if self.role == Role::Client => {
                return self.on_ecdh_reply(&payload);
            }
            msg::NEWKEYS => return self.on_newkeys(),
            _ => {}
        }

        if self.phase == Phase::Established {
            // Real application traffic resets the re-key flood guard.
            self.consecutive_peer_rekeys = 0;
            self.events.push_back(Event::Packet(payload));
            Ok(())
        } else {
            Err(SshError::Protocol("unexpected message during handshake"))
        }
    }

    fn on_peer_kexinit(&mut self, payload: &[u8]) -> Result<()> {
        // A KEXINIT received while established and idle is a peer-initiated re-key;
        // respond with our own KEXINIT before proceeding.
        if self.phase == Phase::Established && !self.kexinit_sent {
            self.consecutive_peer_rekeys += 1;
            if self.consecutive_peer_rekeys > self.max_consecutive_peer_rekeys {
                self.disconnect(msg::disconnect::PROTOCOL_ERROR, "re-key rate exceeded");
                return Ok(());
            }
            self.begin_rekey_round();
        }
        let peer = KexInit::parse(payload)?;
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
            // Send SSH_MSG_KEX_ECDH_INIT with our ephemeral public value(s). The hybrid
            // method carries the ML-KEM encapsulation key alongside the X25519 value.
            let mut w = Writer::new();
            w.u8(msg::KEX_ECDH_INIT);
            let eph = if self.kex_is_hybrid() {
                let hc = HybridClient::generate(&mut self.rng);
                w.string(hc.init());
                KexEphemeral::Hybrid(hc)
            } else {
                let kp = EcdhKeypair::generate(&mut self.rng);
                w.string(&kp.public());
                KexEphemeral::Classical(kp)
            };
            self.write_packet(&w.into_bytes());
            self.kex_eph = Some(eph);
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

        // `q_s` is the full reply blob (the hybrid one carries the ML-KEM ciphertext); it
        // is both written on the wire and bound into the exchange hash as `Q_S`.
        let hybrid = self.kex_is_hybrid();
        let (q_s, shared) = if hybrid {
            mlkem::server_respond(&mut self.rng, &q_c)?
        } else {
            let server_kp = EcdhKeypair::generate(&mut self.rng);
            let q_s = server_kp.public().to_vec();
            let shared = server_kp.agree(&q_c)?;
            (q_s, shared)
        };
        let k = shared_secret(hybrid, &shared[..]);

        let h = self.compute_exchange_hash(&q_c, &q_s, &host_blob, k)?;
        let signature = self.host_key.as_ref().unwrap().sign_exchange_hash(&h);

        let mut w = Writer::new();
        w.u8(msg::KEX_ECDH_REPLY);
        w.string(&host_blob);
        w.string(&q_s);
        w.string(&signature);
        self.write_packet(&w.into_bytes());

        self.finish_kex(h, k)?;
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

        let eph = self
            .kex_eph
            .take()
            .ok_or(SshError::Protocol("KEX_ECDH_REPLY before INIT"))?;
        // `q_c` must be the exact blob we sent in KEX_ECDH_INIT, since it is bound into
        // the exchange hash; recover it from the stored ephemeral.
        let (q_c, shared, hybrid) = match eph {
            KexEphemeral::Hybrid(hc) => {
                let q_c = hc.init().to_vec();
                let shared = hc.agree(&q_s)?;
                (q_c, shared, true)
            }
            KexEphemeral::Classical(kp) => {
                let q_c = kp.public().to_vec();
                let shared = kp.agree(&q_s)?;
                (q_c, shared, false)
            }
        };
        let k = shared_secret(hybrid, &shared[..]);

        let h = self.compute_exchange_hash(&q_c, &q_s, &host_blob, k)?;

        let host_pub = HostPublicKey::parse_blob(&host_blob)?;
        host_pub.verify(&h, &signature)?;
        self.events.push_back(Event::ServerHostKey(host_pub));

        self.finish_kex(h, k)?;
        self.send_newkeys();
        Ok(())
    }

    /// Whether the KEX negotiated this round is the `mlkem768x25519-sha256` hybrid (which
    /// runs ML-KEM, carries larger public blobs, and encodes `K` as a `string`).
    fn kex_is_hybrid(&self) -> bool {
        self.negotiated
            .as_ref()
            .is_some_and(|n| &*n.kex == mlkem::KEX_MLKEM768_X25519)
    }

    fn compute_exchange_hash(
        &self,
        q_c: &[u8],
        q_s: &[u8],
        host_blob: &[u8],
        shared: SharedSecret<'_>,
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
            Role::Client => (
                &self.local_id,
                peer_id,
                &self.local_kexinit,
                &peer_kexinit.payload,
            ),
            Role::Server => (
                peer_id,
                &self.local_id,
                &peer_kexinit.payload,
                &self.local_kexinit,
            ),
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
    fn finish_kex(&mut self, h: [u8; 32], shared: SharedSecret<'_>) -> Result<()> {
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

        // Record the negotiated compression names for this epoch (directional). The
        // contexts themselves are (re)installed at NEWKEYS, in step with the cipher.
        let n = self.negotiated.as_ref().unwrap();
        let (out_name, in_name) = match self.role {
            Role::Client => (n.comp_c2s.clone(), n.comp_s2c.clone()),
            Role::Server => (n.comp_s2c.clone(), n.comp_c2s.clone()),
        };
        self.comp_out_name = out_name;
        self.comp_in_name = in_name;
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
        // Compression context resets per key exchange (RFC 4253 §6.2). Only re-install it
        // if delayed compression has already engaged; otherwise it stays off until auth.
        if self.comp_active {
            self.comp_out = Compressor::new(&self.comp_out_name);
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
        if self.comp_active {
            self.comp_in = Decompressor::new(&self.comp_in_name);
        }
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
        self.tx_packets_since_rekey = 0;
        self.rx_bytes_since_rekey = 0;
        self.rx_packets_since_rekey = 0;

        // Flush application packets deferred during the exchange.
        let queued: Vec<Vec<u8>> = self.tx_app_queue.drain(..).collect();
        for payload in queued {
            self.write_packet(&payload);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostkey::HostKey;
    use rand_chacha::ChaCha8Rng;
    use rand_core::SeedableRng;

    fn establish() -> (Transport<ChaCha8Rng>, Transport<ChaCha8Rng>) {
        let host_key = HostKey::generate(&mut ChaCha8Rng::seed_from_u64(7));
        let mut client = Transport::new_client(ChaCha8Rng::seed_from_u64(1));
        let mut server = Transport::new_server(ChaCha8Rng::seed_from_u64(2), host_key);
        for _ in 0..32 {
            let c_out = client.take_output();
            if !c_out.is_empty() {
                server.on_input(&c_out).unwrap();
            }
            let s_out = server.take_output();
            if !s_out.is_empty() {
                client.on_input(&s_out).unwrap();
            }
            if client.is_established() && server.is_established() {
                break;
            }
        }
        assert!(client.is_established() && server.is_established());
        (client, server)
    }

    /// A peer that floods one key epoch past the hard packet cap (i.e. it has ignored
    /// our forced re-key for ~2 billion packets) must be rejected with a fatal error,
    /// since at 2^32 packets the AEAD nonce would repeat under the same key.
    #[test]
    fn inbound_epoch_packet_cap_is_fatal() {
        let (mut client, mut server) = establish();
        server.rx_packets_since_rekey = EPOCH_HARD_PACKETS - 1;
        client.send_packet(b"x").unwrap();
        let out = client.take_output();
        assert!(
            server.on_input(&out).is_err(),
            "exceeding the per-epoch packet cap must be fatal"
        );
    }

    /// Our own send path must refuse to run an epoch past the hard packet cap.
    #[test]
    fn outbound_epoch_packet_cap_stops_sending() {
        let (mut client, _server) = establish();
        client.tx_packets_since_rekey = EPOCH_HARD_PACKETS - 1;
        client.send_packet(b"x").unwrap();
        assert!(
            client.is_closing(),
            "hitting the cap must close the transport"
        );
        client.take_output();
        client.send_packet(b"y").unwrap_or(());
        assert!(
            client.take_output().is_empty(),
            "nothing may be emitted once closing"
        );
    }
}
