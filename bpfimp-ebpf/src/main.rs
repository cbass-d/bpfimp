#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    helpers::bpf_ktime_get_ns,
    macros::{map, xdp},
    maps::{LruHashMap, LruPerCpuHashMap},
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
static PACKET_COUNTS_V4: LruPerCpuHashMap<u32, u64> =
    LruPerCpuHashMap::<u32, u64>::with_max_entries(1024, 0);

#[map]
static PACKET_COUNTS_V6: LruPerCpuHashMap<[u8; 16], u64> =
    LruPerCpuHashMap::<[u8; 16], u64>::with_max_entries(1024, 0);

#[map]
static ALLOWED_BUCKETS_V4: LruHashMap<u32, Reputation> =
    LruHashMap::<u32, Reputation>::pinned(1024, 0);

#[map]
static ALLOWED_BUCKETS_V6: LruHashMap<[u8; 16], Reputation> =
    LruHashMap::<[u8; 16], Reputation>::pinned(1024, 0);

#[map]
static BLOCKED_BUCKETS_V4: LruHashMap<u32, BlockedEntry> =
    LruHashMap::<u32, BlockedEntry>::pinned(1024, 0);

#[map]
static BLOCKED_BUCKETS_V6: LruHashMap<[u8; 16], BlockedEntry> =
    LruHashMap::<[u8; 16], BlockedEntry>::pinned(1024, 0);

#[map]
static UNKNOWN_BUCKETS_V4: LruPerCpuHashMap<u32, TokenBucket> =
    LruPerCpuHashMap::<u32, TokenBucket>::with_max_entries(1024, 0);

#[map]
static UNKNOWN_BUCKETS_V6: LruPerCpuHashMap<[u8; 16], TokenBucket> =
    LruPerCpuHashMap::<[u8; 16], TokenBucket>::with_max_entries(1024, 0);

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

fn handle_ipv4(ctx: &XdpContext) -> Result<bool, ()> {
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    if let Some(entry) = BLOCKED_BUCKETS_V4.get_ptr_mut(&src_addr) {
        trace!(ctx, "packet from blocked ip");

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
                trace!(ctx, "SRC IP: {:i}, total: {}", src_addr, *counter);
            }
            None => {
                let _ = PACKET_COUNTS_V4.insert(&src_addr, &1, 1);
                trace!(ctx, "SRC IP: {:i}, total: {}", src_addr, 1);
            }
        }
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let allowed = unsafe {
        if let Some(rep) = ALLOWED_BUCKETS_V4.get_ptr_mut(&src_addr) {
            let is_ok = ((*rep).score >= MIN_SCORE_TO_PASS)
                && (*rep).bucket.try_consume(MAX_TOKENS, REFILL_PER_SEC, now);

            if is_ok {
                (*rep).score = (*rep).score.saturating_add(1).min(MAX_SCORE);
            } else {
                info!(ctx, "IP: {} penalized", src_addr);
                (*rep).score = (*rep).score.saturating_sub(PENALTY);
            }

            is_ok
        } else if let Some(b) = UNKNOWN_BUCKETS_V4.get_ptr_mut(&src_addr) {
            (*b).try_consume(MAX_TOKENS, REFILL_PER_SEC, now)
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
        trace!(ctx, "packet from blocked ip");

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
                trace!(ctx, "SRC IP: {:i}, total: {}", src_addr, *counter);
            }
            None => {
                let _ = PACKET_COUNTS_V6.insert(&src_addr, &1, 1);
                trace!(ctx, "SRC IP: {:i}, total: {}", src_addr, 1);
            }
        }
    }

    let now = unsafe { bpf_ktime_get_ns() };
    let allowed = unsafe {
        if let Some(rep) = ALLOWED_BUCKETS_V6.get_ptr_mut(&src_addr) {
            let is_ok = (*rep).score >= MIN_SCORE_TO_PASS
                && (*rep).bucket.try_consume(MAX_TOKENS, REFILL_PER_SEC, now);

            if is_ok {
                (*rep).score = (*rep).score.saturating_add(1).min(MAX_SCORE);
            } else {
                info!(ctx, "IPv6 {:i} penalized", src_addr);
                (*rep).score = (*rep).score.saturating_sub(PENALTY);
            }

            is_ok
        } else if let Some(b) = UNKNOWN_BUCKETS_V6.get_ptr_mut(&src_addr) {
            (*b).try_consume(MAX_TOKENS, REFILL_PER_SEC, now)
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
