#![no_std]
#![no_main]

const NS_PER_SEC: u64 = 1_000_000_000;

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{HashMap, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{info, trace};
use bpfimp_common::{
    BlockedEntry, MAX_SCORE, MAX_TOKENS, MIN_SCORE_TO_PASS, PENALTY, REFILL_PER_SEC, Reputation,
    TokenBucket,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, Ipv6Hdr},
};

#[map]
static PACKET_COUNTS_V4: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(1024, 0);

#[map]
static PACKET_COUNTS_V6: HashMap<[u8; 16], u64> =
    HashMap::<[u8; 16], u64>::with_max_entries(1024, 0);

#[map]
static ALLOWED_BUCKETS_V4: LruHashMap<u32, Reputation> =
    LruHashMap::<u32, Reputation>::with_max_entries(1024, 0);

#[map]
static ALLOWED_BUCKETS_V6: LruHashMap<[u8; 16], Reputation> =
    LruHashMap::<[u8; 16], Reputation>::with_max_entries(1024, 0);

#[map]
static BLOCKED_BUCKETS_V4: LruHashMap<u32, BlockedEntry> =
    LruHashMap::<u32, BlockedEntry>::with_max_entries(1024, 0);

#[map]
static BLOCKED_BUCKETS_V6: LruHashMap<[u8; 16], BlockedEntry> =
    LruHashMap::<[u8; 16], BlockedEntry>::with_max_entries(1024, 0);

#[map]
static UNKNOWN_BUCKETS_V4: LruHashMap<u32, TokenBucket> =
    LruHashMap::<u32, TokenBucket>::with_max_entries(1024, 0);

#[map]
static UNKNOWN_BUCKETS_V6: LruHashMap<[u8; 16], TokenBucket> =
    LruHashMap::<[u8; 16], TokenBucket>::with_max_entries(1024, 0);

#[xdp]
pub fn bpfimp(ctx: XdpContext) -> u32 {
    match try_bpfimp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
unsafe fn try_consume(
    ctx: &XdpContext,
    b: *mut TokenBucket,
    max: u32,
    refill_per_sec: u32,
    now: u64,
) -> bool {
    let elapsed = (now - (*b).last_refill_ns) / NS_PER_SEC;
    if elapsed >= 1 {
        let add = (elapsed as u32).saturating_mul(refill_per_sec);
        (*b).tokens = (*b).tokens.saturating_add(add).min(max);
        (*b).last_refill_ns += elapsed * NS_PER_SEC;
    }

    if (*b).tokens == 0 {
        return false;
    }

    (*b).tokens -= 1;

    true
}

fn handle_ipv4(ctx: &XdpContext) -> Result<bool, ()> {
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    if let Some(entry) = BLOCKED_BUCKETS_V4.get_ptr_mut(&src_addr) {
        trace!(&ctx, "packet from blocked ip");

        unsafe {
            (*entry).hits += 1;
            (*entry).last_seen_ns = bpf_ktime_get_ns();
        }

        return Ok(false);
    }

    unsafe {
        match PACKET_COUNTS_V4.get_ptr_mut(&src_addr) {
            Some(counter) => {
                *counter += 1;
                trace!(&ctx, "SRC IP: {:i}, total: {}", src_addr, *counter);
            }
            None => {
                let _ = PACKET_COUNTS_V4.insert(&src_addr, &1, 1);
                trace!(&ctx, "SRC IP: {:i}, total: {}", src_addr, 1);
            }
        }
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let allowed = unsafe {
        if let Some(rep) = ALLOWED_BUCKETS_V4.get_ptr_mut(&src_addr) {
            let is_ok = ((*rep).score >= MIN_SCORE_TO_PASS)
                && try_consume(&ctx, &mut (*rep).bucket, MAX_TOKENS, REFILL_PER_SEC, now);

            if is_ok {
                (*rep).score = (*rep).score.saturating_add(1).min(MAX_SCORE);
            } else {
                info!(&ctx, "IP: {} penalized", src_addr);
                (*rep).score = (*rep).score.saturating_sub(PENALTY);
            }

            is_ok
        } else if let Some(b) = UNKNOWN_BUCKETS_V4.get_ptr_mut(&src_addr) {
            try_consume(&ctx, b, MAX_TOKENS, REFILL_PER_SEC, now)
        } else {
            let fresh = TokenBucket::new(now, true);
            let _ = UNKNOWN_BUCKETS_V4.insert(&src_addr, &fresh, 0);
            true
        }
    };

    Ok(allowed)
}

fn handle_ipv6(ctx: &XdpContext) -> Result<bool, ()> {
    let ipv6hdr: *const Ipv6Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = unsafe { (*ipv6hdr).src_addr };

    if let Some(entry) = BLOCKED_BUCKETS_V6.get_ptr_mut(&src_addr) {
        trace!(&ctx, "packet from blocked ip");

        unsafe {
            (*entry).hits += 1;
            (*entry).last_seen_ns = bpf_ktime_get_ns();
        }

        return Ok(false);
    }

    unsafe {
        match PACKET_COUNTS_V6.get_ptr_mut(&src_addr) {
            Some(counter) => {
                *counter += 1;
                trace!(&ctx, "SRC IP: {:i}, total: {}", src_addr, *counter);
            }
            None => {
                let _ = PACKET_COUNTS_V6.insert(&src_addr, &1, 1);
                trace!(&ctx, "SRC IP: {:i}, total: {}", src_addr, 1);
            }
        }
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let allowed = unsafe {
        if let Some(rep) = ALLOWED_BUCKETS_V6.get_ptr_mut(&src_addr) {
            let is_ok = (*rep).score >= MIN_SCORE_TO_PASS
                && try_consume(&ctx, &mut (*rep).bucket, MAX_TOKENS, REFILL_PER_SEC, now);

            if is_ok {
                (*rep).score = (*rep).score.saturating_add(1).min(MAX_SCORE);
            } else {
                info!(&ctx, "IPv6 {:i} penalized", src_addr);
                (*rep).score = (*rep).score.saturating_sub(PENALTY);
            }

            is_ok
        } else if let Some(b) = UNKNOWN_BUCKETS_V6.get_ptr_mut(&src_addr) {
            try_consume(&ctx, b, MAX_TOKENS, REFILL_PER_SEC, now)
        } else {
            let fresh = TokenBucket::new(now, true);
            let _ = UNKNOWN_BUCKETS_V6.insert(&src_addr, &fresh, 0);
            true
        }
    };

    Ok(allowed)
}

fn try_bpfimp(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    let allowed = match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => handle_ipv4(&ctx)?,
        Ok(EtherType::Ipv6) => handle_ipv6(&ctx)?,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    if !allowed {
        return Ok(xdp_action::XDP_DROP);
    }

    Ok(xdp_action::XDP_PASS)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
