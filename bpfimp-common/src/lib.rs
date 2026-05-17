#![no_std]

pub const MAX_TOKENS: u32 = 100;
pub const REFILL_PER_SEC: u32 = 10;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TokenBucket {
    pub tokens: u32,
    pub last_refill_ns: u64,
}

impl TokenBucket {
    pub fn new(now_ns: u64) -> Self {
        Self {
            tokens: MAX_TOKENS,
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
            bucket: TokenBucket::new(now_ns),
            score: 100,
        }
    }
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for TokenBucket {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for Reputation {}
