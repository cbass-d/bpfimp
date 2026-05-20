use anyhow::Result;
use std::{
    net::Ipv4Addr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context as _;
use aya::{
    Ebpf,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use bpfimp_common::{BlockedEntry, Reputation};
use clap::Parser;
use log::info;
use nix::time::{ClockId, clock_gettime};
use notify::{
    EventKind, RecursiveMode,
    event::{AccessKind, AccessMode},
};
use notify_debouncer_full::{DebouncedEvent, new_debouncer};
use tokio::sync::mpsc;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlan0")]
    iface: String,
    #[clap(short, long, default_value = "bpfimp.toml")]
    config: PathBuf,
}

#[derive(serde::Deserialize)]
struct Config {
    #[serde(default)]
    allowlist: Vec<String>,
    blocklist: Vec<String>,
}

fn clock_now_ns() -> u64 {
    let ts = clock_gettime(ClockId::CLOCK_MONOTONIC).expect("CLOCK_MONOTONIC get time failed");

    (ts.tv_sec() as u64) * 1_000_000_000 + ts.tv_nsec() as u64
}

fn reload_config_lists(ebpf: &mut Ebpf, path: &Path) -> Result<(usize, usize)> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read from {}", path.display()))?;
    let cfg: Config = toml::from_str(&raw)?;

    let mut allowed: HashMap<_, u32, Reputation> = HashMap::try_from(
        ebpf.map_mut("ALLOWED_BUCKETS")
            .context("ALLOWED_BUCKETS map missing")?,
    )?;

    let now = clock_now_ns();
    for ip_str in &cfg.allowlist {
        let ip: Ipv4Addr = ip_str.parse().with_context(|| format!("bad ip {ip_str}"))?;
        let key: u32 = ip.into();
        allowed.insert(key, Reputation::new(now), 0)?;
    }

    let mut blocked: HashMap<_, u32, BlockedEntry> = HashMap::try_from(
        ebpf.map_mut("BLOCKED_BUCKETS")
            .context("BLOCKED_BUCKETS map missing")?,
    )?;

    for ip_str in &cfg.blocklist {
        let ip: Ipv4Addr = ip_str.parse().with_context(|| format!("bad ip {ip_str}"))?;
        let key: u32 = ip.into();
        blocked.insert(key, BlockedEntry::default(), 0)?;
    }

    Ok((cfg.allowlist.len(), cfg.blocklist.len()))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/bpfimp"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { iface, config } = opt;
    let program: &mut Xdp = ebpf.program_mut("bpfimp").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("attached to the {} interface", iface);

    println!("Waiting for Ctrl-C...");

    let mut interval = tokio::time::interval(Duration::from_secs(10));

    let (tx, mut rx) = mpsc::channel(10);
    let mut debouncer = new_debouncer(Duration::from_millis(200), None, move |res| {
        let _ = tx.blocking_send(res);
    })?;

    let parent = config.parent().unwrap_or(Path::new("."));
    debouncer.watch(parent, RecursiveMode::NonRecursive)?;

    loop {
        tokio::select! {
            _  = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }

            Some(Ok(events)) = rx.recv() => {
                let is_config_save = |e: &DebouncedEvent| {
                    matches!(e.kind, EventKind::Access(AccessKind::Close(AccessMode::Write)))
                    && e.paths.iter().any(|p| p.ends_with(&config))
                };

                if events.iter().any(is_config_save) {
                    match reload_config_lists(&mut ebpf, &config) {
                        Ok((n, m)) => info!("loaded {n} allowed ips and {m} blocked ips from {}", config.display()),
                        Err(e) => warn!("peers reload failed: {e:#}"),
                    }
                }
            }
            _ = interval.tick() => {}
        }
    }

    Ok(())
}
