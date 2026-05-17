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
use aya_log_ebpf::info;
use bpfimp_common::{MAX_TOKENS, REFILL_PER_SEC, Reputation, TokenBucket};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[map]
static PACKET_COUNTS: HashMap<u32, u64> = HashMap::<u32, u64>::with_max_entries(1024, 0);

#[map]
static KNOWN_BUCKETS: LruHashMap<u32, Reputation> =
    LruHashMap::<u32, Reputation>::with_max_entries(1024, 0);

#[map]
static UKNOWN_BUCKETS: LruHashMap<u32, TokenBucket> =
    LruHashMap::<u32, TokenBucket>::with_max_entries(1024, 0);

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
unsafe fn try_consume(b: *mut TokenBucket, max: u32, refill_per_sec: u32, now: u64) -> bool {
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

fn try_bpfimp(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;

    match unsafe { (*ethhdr).ether_type() } {
        Ok(EtherType::Ipv4) => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let src_addr = u32::from_be_bytes(unsafe { (*ipv4hdr).src_addr });

    unsafe {
        match PACKET_COUNTS.get_ptr_mut(&src_addr) {
            Some(counter) => {
                *counter += 1;
                info!(&ctx, "SRC IP: {:i}, total: {}", src_addr, *counter);
            }
            None => {
                let _ = PACKET_COUNTS.insert(&src_addr, &1, 1);
                info!(&ctx, "SRC IP: {:i}, total: {}", src_addr, 1);
            }
        }
    }

    let now = unsafe { bpf_ktime_get_ns() };

    let allowed = unsafe {
        if let Some(rep) = KNOWN_BUCKETS.get_ptr_mut(&src_addr) {
            try_consume(&mut (*rep).bucket, MAX_TOKENS, REFILL_PER_SEC, now)
        } else if let Some(b) = UKNOWN_BUCKETS.get_ptr_mut(&src_addr) {
            try_consume(b, MAX_TOKENS, REFILL_PER_SEC, now)
        } else {
            let fresh = TokenBucket::new(now);
            let _ = UKNOWN_BUCKETS.insert(&src_addr, &fresh, 0);
            true
        }
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
