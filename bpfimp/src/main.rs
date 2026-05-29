use anyhow::Result;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context as _;
use aya::{
    Ebpf, EbpfLoader,
    maps::HashMap,
    programs::{Xdp, XdpFlags},
};
use bpfimp_common::{BlockedEntry, Reputation};
use clap::{Command, arg};
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

const BPFS_FS_PATH: &str = "/sys/fs/bpf/bpfimp";

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

fn cli() -> Command {
    Command::new("bpfimp")
        .about("")
        .subcommand_required(true)
        .subcommand(
            Command::new("run")
                .about("run the binary")
                .arg(arg!(-i --iface <IFACE> "the interface to attach to").default_value("wlan0"))
                .arg(
                    arg!(-c --config <CONFIG> "path to config file")
                        .default_value("bpfimp.toml")
                        .value_parser(clap::value_parser!(PathBuf)),
                ),
        )
        .subcommand(Command::new("inspect").about("inspect bpf data persisted over runs"))
}

fn load_config_lists(ebpf: &mut Ebpf, path: &Path) -> Result<(usize, usize)> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read from {}", path.display()))?;
    let cfg: Config = toml::from_str(&raw)?;

    let (allow_v4, allow_v6) = partition_list(&cfg.allowlist);
    let (block_v4, block_v6) = partition_list(&cfg.blocklist);

    let now = clock_now_ns();

    let mut m: HashMap<_, u32, Reputation> =
        HashMap::try_from(ebpf.map_mut("ALLOWED_BUCKETS_V4").context("missing")?)?;

    let current_keys: Vec<u32> = m.iter().flatten().map(|(k, _)| k).collect();
    allow_v4
        .iter()
        .filter(|ip| !current_keys.contains(ip))
        .for_each(|ip| {
            if m.insert(ip, Reputation::new(now), 0).is_err() {
                warn!("failed to insert entry into ALLOWED_V6 map");
            }
        });

    let mut m: HashMap<_, [u8; 16], Reputation> =
        HashMap::try_from(ebpf.map_mut("ALLOWED_BUCKETS_V6").context("missing")?)?;

    let current_keys: Vec<[u8; 16]> = m.iter().flatten().map(|(k, _)| k).collect();
    allow_v6
        .iter()
        .filter(|ip| !current_keys.contains(ip))
        .for_each(|ip| {
            if m.insert(ip, Reputation::new(now), 0).is_err() {
                warn!("failed to insert entry into ALLOWED_V4 map");
            }
        });

    let mut m: HashMap<_, u32, BlockedEntry> =
        HashMap::try_from(ebpf.map_mut("BLOCKED_BUCKETS_V4").context("missing")?)?;

    let current_keys: Vec<u32> = m.iter().flatten().map(|(k, _)| k).collect();
    block_v4
        .iter()
        .filter(|ip| !current_keys.contains(ip))
        .for_each(|ip| {
            if m.insert(ip, BlockedEntry::default(), 0).is_err() {
                warn!("failed to insert entry into BLOCKED_V4 map");
            }
        });

    let mut m: HashMap<_, [u8; 16], BlockedEntry> =
        HashMap::try_from(ebpf.map_mut("BLOCKED_BUCKETS_V6").context("missing")?)?;

    let current_keys: Vec<[u8; 16]> = m.iter().flatten().map(|(k, _)| k).collect();
    block_v6
        .iter()
        .filter(|ip| !current_keys.contains(ip))
        .for_each(|ip| {
            if m.insert(ip, BlockedEntry::default(), 0).is_err() {
                warn!("failed to insert entry into BLOCKED_V6 map");
            }
        });

    Ok((
        allow_v4.len() + allow_v6.len(),
        block_v4.len() + block_v6.len(),
    ))
}

fn partition_list(list: &[String]) -> (Vec<u32>, Vec<[u8; 16]>) {
    let (mut v4, mut v6) = (Vec::new(), Vec::new());
    for ip_str in list {
        match ip_str.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => v4.push(ip.into()),
            Ok(IpAddr::V6(ip)) => v6.push(ip.octets()),
            Err(e) => warn!("invalid ip: {e}"),
        }
    }

    (v4, v6)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = cli().get_matches();

    if let Some(("inspect", _)) = cli.subcommand() {
        debug!("running inpspection command");
        let allowed_v4: HashMap<_, u32, Reputation> =
            HashMap::try_from(aya::maps::Map::LruHashMap(
                aya::maps::MapData::from_pin(format!("{BPFS_FS_PATH}/ALLOWED_BUCKETS_V4"))
                    .context("failed to load ALLOWED_V4 pinned map")?,
            ))
            .context("failed to ALLOWED_V4 covert to HashMap")?;

        println!("=== ALLOWED_V4 ===");
        for (ip, rep) in allowed_v4.iter().flatten() {
            let ip_v4 = IpAddr::V4(Ipv4Addr::from(ip));
            println!("* {ip_v4}\n\t- Rep Score: {}", rep.score);
        }

        let allowed_v6: HashMap<_, [u8; 16], Reputation> =
            HashMap::try_from(aya::maps::Map::LruHashMap(
                aya::maps::MapData::from_pin(format!("{BPFS_FS_PATH}/ALLOWED_BUCKETS_V6"))
                    .context("failed to load ALLOWED_V6 pinned map")?,
            ))
            .context("failed to ALLOWED_V6 covert to HashMap")?;

        println!("\n=== ALLOWED_V6 ===");
        for (ip, rep) in allowed_v6.iter().flatten() {
            let ip_v6 = IpAddr::V6(Ipv6Addr::from_octets(ip));
            println!("* {ip_v6}\n\t- Rep Score: {}", rep.score);
        }

        let blocked_v4: HashMap<_, u32, BlockedEntry> =
            HashMap::try_from(aya::maps::Map::LruHashMap(
                aya::maps::MapData::from_pin(format!("{BPFS_FS_PATH}/BLOCKED_BUCKETS_V4"))
                    .context("failed to load BLOCKED_V4 pinned map")?,
            ))
            .context("failed to BLOCKED_V4 covert to HashMap")?;

        println!("\n=== BLOCKED_V4 ===");
        for (ip, rep) in blocked_v4.iter().flatten() {
            let ip_v4 = IpAddr::V4(Ipv4Addr::from(ip));
            println!("* {ip_v4}\n\t- Hits: {}", rep.hits);
        }

        let blocked_v6: HashMap<_, [u8; 16], BlockedEntry> =
            HashMap::try_from(aya::maps::Map::LruHashMap(
                aya::maps::MapData::from_pin(format!("{BPFS_FS_PATH}/BLOCKED_BUCKETS_V6"))
                    .context("failed to load BLOCKED_V6 pinned map")?,
            ))
            .context("failed to BLOCKED_V6 covert to HashMap")?;

        println!("\n=== BLOCKED_V6 ===");
        for (ip, rep) in blocked_v6.iter().flatten() {
            let ip_v6 = IpAddr::V6(Ipv6Addr::from_octets(ip));
            println!("* {ip_v6}\n\t- Hits: {}", rep.hits);
        }

        return Ok(());
    }

    let (iface, config) = if let Some((_, sub_matches)) = cli.subcommand() {
        (
            sub_matches
                .get_one::<String>("iface")
                .map(|s| s.as_str())
                .unwrap(),
            sub_matches.get_one::<PathBuf>("config").unwrap(),
        )
    } else {
        return Ok(());
    };

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
    let mut ebpf =
        EbpfLoader::new()
            .map_pin_path("/sys/fs/bpf/bpfimp")
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/bpfimp"
            )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program: &mut Xdp = ebpf.program_mut("bpfimp").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, XdpFlags::default())
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

    // Initial load of config
    match load_config_lists(&mut ebpf, config) {
        Ok((n, m)) => info!(
            "loaded {n} allowed ips and {m} blocked ips from {}",
            config.display()
        ),
        Err(e) => warn!("peers reload failed: {e:#}"),
    }

    loop {
        tokio::select! {
            _  = signal::ctrl_c() => {
                println!("Exiting...");
                break;
            }

            Some(Ok(events)) = rx.recv() => {
                let is_config_save = |e: &DebouncedEvent| {
                    matches!(e.kind, EventKind::Access(AccessKind::Close(AccessMode::Write)))
                    && e.paths.iter().any(|p| p.ends_with(config))
                };

                if events.iter().any(is_config_save) {
                    match load_config_lists(&mut ebpf, config) {
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
