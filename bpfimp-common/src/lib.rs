#![no_std]

pub const BPF_PROGRAM: &str = "bpfimp";
pub const EVENTS_RINGBUF: &str = "EVENTS";
pub const ALLOWED_V4_MAP: &str = "ALLOWED_BUCKETS_V4";
pub const ALLOWED_V6_MAP: &str = "ALLOWED_BUCKETS_V6";
pub const BLOCKED_V4_MAP: &str = "BLOCKED_BUCKETS_V4";
pub const BLOCKED_V6_MAP: &str = "BLOCKED_BUCKETS_V6";
pub const PKT_COUNTS_V4_MAP: &str = "PKT_COUNTS_V4";
pub const PKT_COUNTS_V6_MAP: &str = "PKT_COUNTS_V6";
pub const UNK_BKTS_V4_MAP: &str = "UNK_BKTS_V4";
pub const UNK_BKTS_V6_MAP: &str = "UNK_BKTS_V6";

pub const MAX_TOKENS: u32 = 200;
pub const MAX_SCORE: u32 = 100;
pub const NEW_MAX_TOKENS: u32 = 100;
pub const MIN_SCORE_TO_PASS: u32 = 20;
pub const REFILL_PER_SEC: u32 = 10;
pub const PENALTY: u32 = 10;
const NS_PER_SEC: u64 = 1_000_000_000;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpVersion {
    V4 = 4,
    V6 = 6,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventKind {
    Drop = 0,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ImpEvent {
    pub ts_ns: u64,
    pub addr: [u8; 16],
    pub kind: u8,
    pub ip_version: u8,
    pub _pad: [u8; 6],
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct TokenBucket {
    pub tokens: u32,
    pub last_refill_ns: u64,
}

impl TokenBucket {
    pub fn new(now_ns: u64, new: bool) -> Self {
        Self {
            tokens: if new { NEW_MAX_TOKENS } else { MAX_TOKENS },
            last_refill_ns: now_ns,
        }
    }

    pub fn try_consume(&mut self, max: u32, refill_per_sec: u32, now: u64) -> bool {
        let elapsed = now.saturating_sub(self.last_refill_ns) / NS_PER_SEC;
        if elapsed >= 1 {
            let add = (elapsed as u32).saturating_mul(refill_per_sec);
            self.tokens = self.tokens.saturating_add(add).min(max);
            self.last_refill_ns += elapsed * NS_PER_SEC;
        }

        if self.tokens == 0 {
            return false;
        }

        self.tokens -= 1;
        true
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Reputation {
    pub bucket: TokenBucket,
    pub score: u32,
}

impl Reputation {
    pub fn new(now_ns: u64) -> Self {
        Self {
            bucket: TokenBucket::new(now_ns, false),
            score: MAX_SCORE,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct BlockedEntry {
    pub hits: u64,
    pub last_seen_ns: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TokenBucket {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Reputation {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BlockedEntry {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ImpEvent {}

#[cfg(test)]
mod tests {
    use super::*;
    const S: u64 = NS_PER_SEC;

    #[test]
    fn empty_bucket_denies() {
        let mut b = TokenBucket {
            tokens: 0,
            last_refill_ns: 0,
        };

        assert!(!b.try_consume(100, 10, 0));
    }

    #[test]
    fn refill_caps_at_max() {
        let mut b = TokenBucket {
            tokens: 0,
            last_refill_ns: 0,
        };

        b.try_consume(100, 10, 1_000 * S);
        assert_eq!(b.tokens, 99);
    }

    #[test]
    fn sustained_packets_drains() {
        let mut b = TokenBucket {
            tokens: 10,
            last_refill_ns: 0,
        };

        let (mut now, mut allowed) = (0, 0);

        for _ in 0..200 {
            now += S / 100;
            if b.try_consume(100, 10, now) {
                allowed += 1;
            };
        }
        assert!((20..=32).contains(&allowed), "got {allowed}");
    }

    #[test]
    fn clock_going_backwards_safe() {
        let mut b = TokenBucket {
            tokens: 10,
            last_refill_ns: 10 * S,
        };

        assert!(b.try_consume(100, 10, 5 * S));
    }
}
