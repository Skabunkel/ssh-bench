//! Connection-admission and brute-force policies (the Infra side of DoS defence).
//!
//! * [`ConnectionPolicy`] gates a connection by peer address the instant it is accepted,
//!   before any handshake/crypto work — the place for allow/blocklists.
//! * [`RetryPolicy`] reacts to authentication outcomes (the protocol layer enforces the
//!   per-connection attempt cap and emits the events these hooks fire on).
//!
//! [`Fail2Ban`] implements both over one shared table, so a few lines wire up
//! fail2ban-style temporary IP bans: every exhausted login is a strike, and an IP that
//! collects enough strikes is rejected at accept time for a cooldown window.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// What to do with a freshly-accepted connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDecision {
    /// Proceed with the handshake.
    Accept,
    /// Close the connection immediately, before any protocol work.
    Reject,
}

/// Decides whether an inbound connection is allowed, by peer address. Implementations
/// keep their own allow/blocklists (static or dynamic, e.g. a [`Fail2Ban`] table).
pub trait ConnectionPolicy: Send + Sync + 'static {
    fn evaluate(&self, peer: SocketAddr) -> ConnectionDecision;
}

/// Accepts every connection (the default when no policy is configured).
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl ConnectionPolicy for AllowAll {
    fn evaluate(&self, _peer: SocketAddr) -> ConnectionDecision {
        ConnectionDecision::Accept
    }
}

/// Reacts to authentication outcomes for a connection. The protocol engine enforces the
/// attempt cap itself (`ServerAuthHandler::max_auth_attempts`); these hooks let a driver
/// record the outcome against the peer — e.g. to drive a ban table.
pub trait RetryPolicy: Send + Sync + 'static {
    /// The peer exhausted its authentication attempts and was disconnected.
    fn on_auth_exhausted(&self, _peer: SocketAddr) {}
    /// The peer authenticated successfully (a good place to reset failure counters).
    fn on_authenticated(&self, _peer: SocketAddr) {}
}

/// A [`RetryPolicy`] that does nothing (the default).
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRetryReaction;

impl RetryPolicy for NoRetryReaction {}

/// A fail2ban-style temporary ban table, usable as both a [`ConnectionPolicy`] and a
/// [`RetryPolicy`]. Cheap to clone (shared state behind an [`Arc`]).
///
/// Each fully-exhausted login counts as one strike against the peer's IP; once an IP
/// reaches `ban_threshold` strikes it is rejected at accept time until `ban_duration`
/// elapses. A successful authentication clears the IP's record.
#[derive(Clone)]
pub struct Fail2Ban {
    state: Arc<Mutex<HashMap<IpAddr, Record>>>,
    max_auth_attempts: u32,
    ban_threshold: u32,
    ban_duration: Duration,
}

#[derive(Default)]
struct Record {
    strikes: u32,
    banned_until: Option<Instant>,
}

impl Fail2Ban {
    /// * `max_auth_attempts` — failed attempts allowed per connection (feed this into the
    ///   server's auth handler so the protocol cap matches).
    /// * `ban_threshold` — exhausted logins from an IP before it is banned.
    /// * `ban_duration` — how long a banned IP stays rejected.
    pub fn new(max_auth_attempts: u32, ban_threshold: u32, ban_duration: Duration) -> Self {
        Self {
            state: Arc::new(Mutex::new(HashMap::new())),
            max_auth_attempts,
            ban_threshold,
            ban_duration,
        }
    }

    /// The per-connection attempt cap to configure on the auth handler.
    pub fn max_auth_attempts(&self) -> u32 {
        self.max_auth_attempts
    }

    /// Whether `ip` is currently banned (also clears an expired ban).
    pub fn is_banned(&self, ip: IpAddr) -> bool {
        let mut state = self.state.lock().unwrap();
        match state.get_mut(&ip) {
            Some(record) => match record.banned_until {
                Some(until) if Instant::now() < until => true,
                Some(_) => {
                    // Ban expired: forgive and forget.
                    state.remove(&ip);
                    false
                }
                None => false,
            },
            None => false,
        }
    }
}

impl ConnectionPolicy for Fail2Ban {
    fn evaluate(&self, peer: SocketAddr) -> ConnectionDecision {
        if self.is_banned(peer.ip()) {
            ConnectionDecision::Reject
        } else {
            ConnectionDecision::Accept
        }
    }
}

impl RetryPolicy for Fail2Ban {
    fn on_auth_exhausted(&self, peer: SocketAddr) {
        let mut state = self.state.lock().unwrap();
        let record = state.entry(peer.ip()).or_default();
        record.strikes = record.strikes.saturating_add(1);
        if record.strikes >= self.ban_threshold {
            record.banned_until = Some(Instant::now() + self.ban_duration);
        }
    }

    fn on_authenticated(&self, peer: SocketAddr) {
        self.state.lock().unwrap().remove(&peer.ip());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allow_all_accepts() {
        assert_eq!(
            AllowAll.evaluate(peer("10.0.0.1:1234")),
            ConnectionDecision::Accept
        );
    }

    #[test]
    fn fail2ban_bans_after_threshold_and_resets_on_success() {
        let f2b = Fail2Ban::new(6, 3, Duration::from_secs(60));
        let p = peer("203.0.113.7:5555");

        // Below the strike threshold: still accepted.
        f2b.on_auth_exhausted(p);
        f2b.on_auth_exhausted(p);
        assert_eq!(f2b.evaluate(p), ConnectionDecision::Accept);

        // Third strike trips the ban.
        f2b.on_auth_exhausted(p);
        assert_eq!(f2b.evaluate(p), ConnectionDecision::Reject);

        // A different IP is unaffected.
        assert_eq!(f2b.evaluate(peer("203.0.113.8:5555")), ConnectionDecision::Accept);
    }

    #[test]
    fn fail2ban_success_clears_strikes() {
        let f2b = Fail2Ban::new(6, 2, Duration::from_secs(60));
        let p = peer("198.51.100.4:9000");
        f2b.on_auth_exhausted(p);
        f2b.on_authenticated(p); // clears the record
        f2b.on_auth_exhausted(p); // back to one strike, not two
        assert_eq!(f2b.evaluate(p), ConnectionDecision::Accept);
    }

    #[test]
    fn expired_ban_is_forgiven() {
        let f2b = Fail2Ban::new(6, 1, Duration::from_millis(0));
        let p = peer("192.0.2.1:1");
        f2b.on_auth_exhausted(p); // threshold 1 → banned until now+0
        std::thread::sleep(Duration::from_millis(1));
        assert_eq!(f2b.evaluate(p), ConnectionDecision::Accept);
    }
}
