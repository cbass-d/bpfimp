use std::{net::Ipv4Addr, path::PathBuf, time::Duration};

use anyhow::Context as _;
use aya::{
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use bpfimp_common::Reputation;
use clap::Parser;
use log::info;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp0s20f3")]
    iface: String,
    #[clap(short, long, default_value = "peers.toml")]
    peers_config: PathBuf,
}

#[derive(serde::Deserialize)]
struct PeerConfig {
    #[serde(default)]
    peers: Vec<String>,
}

fn clock_now_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    (ts.tv_sec as u64) * 1_000_000_000 + ts.tv_nsec as u64
}

fn reload_known_peers(ebpf: &mut aya::Ebpf, path: &std::path::Path) -> anyhow::Result<usize> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let cfg: PeerConfig = toml::from_str(&raw)?;

    let mut known: HashMap<_, u32, Reputation> = HashMap::try_from(
        ebpf.map_mut("KNOWN_BUCKETS")
            .context("KNOWN_BUCKETS map missing")?,
    )?;

    let now = clock_now_ns();
    for ip_str in &cfg.peers {
        let ip: Ipv4Addr = ip_str.parse().with_context(|| format!("bad ip {ip_str}"))?;
        let key: u32 = ip.into();
        known.insert(key, Reputation::new(now), 0)?;
    }
    Ok(cfg.peers.len())
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
    let Opt {
        iface,
        peers_config,
    } = opt;
    let program: &mut Xdp = ebpf.program_mut("bpfimp").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    info!("attached to the {} interface", iface);

    println!("Waiting for Ctrl-C...");

    let mut interval = tokio::time::interval(Duration::from_secs(10));
    let mut reload = tokio::time::interval(Duration::from_secs(30));

    loop {
        tokio::select! {
            _  = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }
            _ = reload.tick() => {
                match reload_known_peers(&mut ebpf, &peers_config) {
                    Ok(n) => info!("loaded {n} known peers from {}", peers_config.display()),
                    Err(e) => warn!("peers reload failed: {e:#}"),
                }
            }
            _ = interval.tick() => {
                let counts: HashMap<_, u32, u64> = HashMap::try_from(ebpf.map("PACKET_COUNTS").unwrap())?;
                println!("The Top 10 Ips");

                let mut top: Vec<_> = counts.iter().filter_map(|e| e.ok()).collect();
                if top.is_empty() {
                    println!("<None>");
                    continue;
                }

                top.sort_by_key(|(_, c)| std::cmp::Reverse(*c));
                for (ip_u32, count) in top.into_iter().take(10) {
                    let ip = Ipv4Addr::from(ip_u32);
                    println!("{ip}: {count} packets");
                }
            }
        }
    }

    Ok(())
}
