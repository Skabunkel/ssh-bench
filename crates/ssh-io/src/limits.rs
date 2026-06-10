//! Accept-time resource caps: a concurrent-connection limiter (global + per-IP) and a
//! token-bucket rate limiter. These bound how much work a flood of connections can
//! create before any per-connection handshake even starts.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Caps concurrent connections globally and per source IP. Cheap to clone (shared state).
#[derive(Clone)]
pub struct ConnectionLimiter {
    global: Arc<Semaphore>,
    per_ip_max: Option<usize>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
}

/// Holds a connection slot; releases it (global permit + per-IP count) on drop. Keep it
/// alive for the lifetime of the connection (e.g. move it into the serving task).
pub struct ConnectionGuard {
    _permit: OwnedSemaphorePermit,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
    counted: bool,
}

impl ConnectionLimiter {
    /// Allow at most `max_global` concurrent connections, and (if set) `per_ip_max` from
    /// any single source IP.
    pub fn new(max_global: usize, per_ip_max: Option<usize>) -> Self {
        Self {
            global: Arc::new(Semaphore::new(max_global)),
            per_ip_max,
            per_ip: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Try to admit a connection from `ip`. Returns a guard to keep for the connection's
    /// lifetime, or `None` if a global or per-IP cap is currently reached.
    pub fn try_admit(&self, ip: IpAddr) -> Option<ConnectionGuard> {
        // Check the per-IP cap while holding the map lock, then reserve a global permit
        // before committing the increment so the two stay consistent.
        let mut map = self.per_ip.lock().unwrap();
        if let Some(max) = self.per_ip_max {
            let count = map.entry(ip).or_insert(0);
            if *count >= max {
                return None;
            }
            let permit = Arc::clone(&self.global).try_acquire_owned().ok()?;
            *count += 1;
            Some(ConnectionGuard {
                _permit: permit,
                per_ip: Arc::clone(&self.per_ip),
                ip,
                counted: true,
            })
        } else {
            let permit = Arc::clone(&self.global).try_acquire_owned().ok()?;
            Some(ConnectionGuard {
                _permit: permit,
                per_ip: Arc::clone(&self.per_ip),
                ip,
                counted: false,
            })
        }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if !self.counted {
            return;
        }
        let mut map = self.per_ip.lock().unwrap();
        if let Some(count) = map.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// A token-bucket rate limiter for new connections: tokens refill at `rate_per_sec` up to
/// `burst`, and each accepted connection consumes one. Cheap to clone (shared state).
#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<Mutex<Bucket>>,
    rate_per_sec: f64,
    capacity: f64,
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    /// `rate_per_sec` tokens accrue per second, capped at `burst` (the most you can take
    /// at once after an idle period).
    pub fn new(rate_per_sec: f64, burst: f64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Bucket {
                tokens: burst,
                last: Instant::now(),
            })),
            rate_per_sec,
            capacity: burst,
        }
    }

    /// Consume one token. Returns `false` when the bucket is empty (the caller should
    /// drop the connection without serving it).
    pub fn try_acquire(&self) -> bool {
        let mut b = self.inner.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens = (b.tokens + elapsed * self.rate_per_sec).min(self.capacity);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn global_cap_blocks_extra_connections() {
        let lim = ConnectionLimiter::new(2, None);
        let a = lim.try_admit(ip("10.0.0.1")).unwrap();
        let b = lim.try_admit(ip("10.0.0.2")).unwrap();
        assert!(lim.try_admit(ip("10.0.0.3")).is_none(), "global cap of 2");
        drop(a);
        assert!(lim.try_admit(ip("10.0.0.3")).is_some(), "slot freed on drop");
        drop(b);
    }

    #[test]
    fn per_ip_cap_blocks_same_source() {
        let lim = ConnectionLimiter::new(100, Some(2));
        let _a = lim.try_admit(ip("203.0.113.1")).unwrap();
        let _b = lim.try_admit(ip("203.0.113.1")).unwrap();
        assert!(lim.try_admit(ip("203.0.113.1")).is_none(), "per-IP cap of 2");
        // A different IP is still fine.
        assert!(lim.try_admit(ip("203.0.113.2")).is_some());
    }

    #[test]
    fn rate_limiter_exhausts_then_refills() {
        let rl = RateLimiter::new(1000.0, 2.0);
        assert!(rl.try_acquire());
        assert!(rl.try_acquire());
        assert!(!rl.try_acquire(), "burst of 2 exhausted");
        std::thread::sleep(std::time::Duration::from_millis(5)); // ~5 tokens refill
        assert!(rl.try_acquire(), "tokens refilled over time");
    }
}
