#![no_std]

pub const MAX_TOKENS: u32 = 200;
pub const MAX_SCORE: u32 = 100;
pub const NEW_MAX_TOKENS: u32 = 100;
pub const MIN_SCORE_TO_PASS: u32 = 20;
pub const REFILL_PER_SEC: u32 = 10;
pub const PENALTY: u32 = 10;

#[repr(C)]
#[derive(Clone, Copy)]
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
}

#[repr(C)]
#[derive(Clone, Copy)]
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
#[derive(Clone, Copy, Default)]
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
