use anyhow::{Result, anyhow};
use std::{
    collections::HashSet,
    fs::DirBuilder,
    hash::Hash,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::Context as _;
use aya::{
    Ebpf, EbpfLoader, Pod,
    maps::{HashMap, Map, MapData, PerCpuHashMap, loaded_maps},
    programs::{Xdp, XdpFlags},
};
use bpfimp_common::{BlockedEntry, Reputation, TokenBucket};
use clap::{Command, arg};
use log::{error, info};
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

#[derive(serde::Serialize)]
struct AllowedRecord {
    ip: IpAddr,
    score: u32,
    tokens: u32,
}

#[derive(serde::Serialize)]
struct BlockedRecord {
    ip: IpAddr,
    hits: u64,
    last_seen_ns: u64,
}

#[derive(serde::Serialize)]
struct PacketCountRecord {
    ip: IpAddr,
    total: u64,
}

#[derive(serde::Serialize)]
struct InspectOutput {
    allowed: Vec<AllowedRecord>,
    blocked: Vec<BlockedRecord>,
    packet_counts: Vec<PacketCountRecord>,
    unknown_buckets: Vec<IpAddr>,
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
        .subcommand(
            Command::new("inspect")
                .about("inspect bpf data persisted over runs")
                .arg(arg!(-j --json "output as json")),
        )
}

/// Sync the keys in maps using the `desired` hashset
fn sync_keys<K, V>(
    map: &mut HashMap<&mut MapData, K, V>,
    desired: &HashSet<K>,
    make_value: impl Fn(&K) -> V,
) -> Result<()>
where
    K: Pod + Eq + Hash + Copy,
    V: Pod,
{
    let current: HashSet<K> = map.keys().filter_map(|k| k.ok()).collect();

    for k in current.difference(desired) {
        map.remove(k)?;
    }

    for k in desired.difference(&current) {
        map.insert(k, make_value(k), 0)?;
    }

    Ok(())
}

fn load_config_lists(ebpf: &mut Ebpf, path: &Path) -> Result<(usize, usize)> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read from {}", path.display()))?;
    let cfg: Config = toml::from_str(&raw)?;

    let (allow_v4, allow_v6) = partition_list(&cfg.allowlist);
    let (block_v4, block_v6) = partition_list(&cfg.blocklist);
    let now = clock_now_ns();

    let allow_v4: HashSet<u32> = allow_v4.into_iter().collect();
    let allow_v6: HashSet<[u8; 16]> = allow_v6.into_iter().collect();
    let block_v4: HashSet<u32> = block_v4.into_iter().collect();
    let block_v6: HashSet<[u8; 16]> = block_v6.into_iter().collect();

    sync_keys(&mut map_of(ebpf, "ALLOWED_BUCKETS_V4")?, &allow_v4, |_| {
        Reputation::new(now)
    })?;
    sync_keys(&mut map_of(ebpf, "ALLOWED_BUCKETS_V6")?, &allow_v6, |_| {
        Reputation::new(now)
    })?;
    sync_keys(&mut map_of(ebpf, "BLOCKED_BUCKETS_V4")?, &block_v4, |_| {
        BlockedEntry::default()
    })?;
    sync_keys(&mut map_of(ebpf, "BLOCKED_BUCKETS_V6")?, &block_v6, |_| {
        BlockedEntry::default()
    })?;

    Ok((
        allow_v4.len() + allow_v6.len(),
        block_v4.len() + block_v6.len(),
    ))
}

/// Returns an `aya::maps::HashMap` with the name provided if one
/// exists
fn map_of<'a, K: Pod, V: Pod>(
    ebpf: &'a mut Ebpf,
    name: &str,
) -> Result<HashMap<&'a mut MapData, K, V>> {
    Ok(HashMap::try_from(
        ebpf.map_mut(name)
            .with_context(|| format!("map {name} not found"))?,
    )?)
}

// /// Returns an `aya::maps::PerCpuHashMap` with the name provided if one
// /// exists
//fn percpu_map_of<'a, K: Pod, V: Pod>(
//    ebpf: &'a mut Ebpf,
//    name: &str,
//) -> Result<PerCpuHashMap<&'a mut MapData, K, V>> {
//    Ok(PerCpuHashMap::try_from(
//        ebpf.map_mut(name)
//            .with_context(|| format!("map {name} not found"))?,
//    )?)
//}

/// Return the per cpu map using 'loaded_maps()' if it exists on the host
/// system
fn load_percpu_map<K: Pod, V: Pod>(
    name: &str,
    key_size: u32,
) -> Result<PerCpuHashMap<MapData, K, V>> {
    debug!("loading map: {name}");
    let info = loaded_maps()
        .filter_map(|m| m.ok())
        .find(|m| m.name_as_str() == Some(name) && m.key_size() == key_size)
        .with_context(|| format!("failed to get map info for: {name}"))?;

    let map_data = aya::maps::MapData::from_id(info.id())
        .with_context(|| format!("failed to get map data: {name}"))?;

    let map: PerCpuHashMap<_, K, V> = PerCpuHashMap::try_from(Map::PerCpuLruHashMap(map_data))
        .with_context(|| format!("failed to convert LRU HashMap: {name}"))?;

    Ok(map)
}

/// Return the map using 'loaded_maps()' if it exists on the host
/// system
fn load_map<K: Pod, V: Pod>(name: &str, key_size: u32) -> Result<HashMap<MapData, K, V>> {
    debug!("loading map: {name}");
    let info = loaded_maps()
        .filter_map(|m| m.ok())
        .find(|m| m.name_as_str() == Some(name) && m.key_size() == key_size)
        .with_context(|| format!("failed to get map info for: {name}"))?;

    let map_data = aya::maps::MapData::from_id(info.id())
        .with_context(|| format!("failed to get map data: {name}"))?;

    let map: HashMap<_, K, V> = HashMap::try_from(Map::LruHashMap(map_data))
        .with_context(|| format!("failed to convert LRU HashMap: {name}"))?;

    Ok(map)
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

    if !nix::unistd::geteuid().is_root() {
        error!("binary must be ran with root privaleges");
        return Err(anyhow!("Binary must be ran as root"));
    }

    let cli = cli().get_matches();

    if let Some(("inspect", sub_matches)) = cli.subcommand() {
        let pkt_counts_v4 = load_percpu_map::<u32, u64>("PKT_COUNTS_V4", 4)?;
        let pkt_counts_v6 = load_percpu_map::<[u8; 16], u64>("PKT_COUNTS_V6", 16)?;

        let unknown_counts_v4 = load_map::<u32, TokenBucket>("UNK_BKTS_V4", 4)?;
        let unknown_counts_v6 = load_map::<[u8; 16], TokenBucket>("UNK_BKTS_V6", 16)?;

        debug!("maps loaded");

        // Allow and Block buckets
        let allowed_v4: HashMap<_, u32, Reputation> = HashMap::try_from(Map::LruHashMap(
            MapData::from_pin(format!("{BPFS_FS_PATH}/ALLOWED_BUCKETS_V4"))
                .context("failed to load ALLOWED_V4 pinned map")?,
        ))
        .context("failed to ALLOWED_V4 covert to HashMap")?;

        let allowed_v6: HashMap<_, [u8; 16], Reputation> = HashMap::try_from(Map::LruHashMap(
            MapData::from_pin(format!("{BPFS_FS_PATH}/ALLOWED_BUCKETS_V6"))
                .context("failed to load ALLOWED_V6 pinned map")?,
        ))
        .context("failed to ALLOWED_V6 covert to HashMap")?;

        let blocked_v4: HashMap<_, u32, BlockedEntry> = HashMap::try_from(Map::LruHashMap(
            MapData::from_pin(format!("{BPFS_FS_PATH}/BLOCKED_BUCKETS_V4"))
                .context("failed to load BLOCKED_V4 pinned map")?,
        ))
        .context("failed to BLOCKED_V4 covert to HashMap")?;

        let blocked_v6: HashMap<_, [u8; 16], BlockedEntry> = HashMap::try_from(Map::LruHashMap(
            MapData::from_pin(format!("{BPFS_FS_PATH}/BLOCKED_BUCKETS_V6"))
                .context("failed to load BLOCKED_V6 pinned map")?,
        ))
        .context("failed to BLOCKED_V6 covert to HashMap")?;

        if sub_matches.get_flag("json") {
            let mut allowed: Vec<AllowedRecord> = allowed_v4
                .iter()
                .flatten()
                .map(|(ip, rep)| AllowedRecord {
                    ip: IpAddr::V4(Ipv4Addr::from(ip)),
                    score: rep.score,
                    tokens: rep.bucket.tokens,
                })
                .collect();
            allowed.extend(allowed_v6.iter().flatten().map(|(ip, rep)| AllowedRecord {
                ip: IpAddr::V6(Ipv6Addr::from(ip)),
                score: rep.score,
                tokens: rep.bucket.tokens,
            }));

            let mut blocked: Vec<BlockedRecord> = blocked_v4
                .iter()
                .flatten()
                .map(|(ip, e)| BlockedRecord {
                    ip: IpAddr::V4(Ipv4Addr::from(ip)),
                    hits: e.hits,
                    last_seen_ns: e.last_seen_ns,
                })
                .collect();
            blocked.extend(blocked_v6.iter().flatten().map(|(ip, e)| BlockedRecord {
                ip: IpAddr::V6(Ipv6Addr::from(ip)),
                hits: e.hits,
                last_seen_ns: e.last_seen_ns,
            }));

            let mut packet_counts: Vec<PacketCountRecord> = pkt_counts_v4
                .iter()
                .flatten()
                .map(|(k, c)| PacketCountRecord {
                    ip: IpAddr::V4(Ipv4Addr::from(k)),
                    total: c.iter().sum(),
                })
                .collect();
            packet_counts.extend(
                pkt_counts_v6
                    .iter()
                    .flatten()
                    .map(|(k, c)| PacketCountRecord {
                        ip: IpAddr::V6(Ipv6Addr::from(k)),
                        total: c.iter().sum(),
                    }),
            );

            let mut unknown_buckets: Vec<IpAddr> = unknown_counts_v4
                .keys()
                .flatten()
                .map(|k| IpAddr::V4(Ipv4Addr::from(k)))
                .collect();
            unknown_buckets.extend(
                unknown_counts_v6
                    .keys()
                    .flatten()
                    .map(|k| IpAddr::V6(Ipv6Addr::from(k))),
            );

            let output = InspectOutput {
                allowed,
                blocked,
                packet_counts,
                unknown_buckets,
            };

            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            println!("=== ALLOWED_V4 ===");
            for (ip, rep) in allowed_v4.iter().flatten() {
                let ip_v4 = IpAddr::V4(Ipv4Addr::from(ip));
                println!("* {ip_v4}\n\t- Rep Score: {}", rep.score);
            }

            println!("\n=== ALLOWED_V6 ===");
            for (ip, rep) in allowed_v6.iter().flatten() {
                let ip_v6 = IpAddr::V6(Ipv6Addr::from_octets(ip));
                println!("* {ip_v6}\n\t- Rep Score: {}", rep.score);
            }

            println!("\n=== BLOCKED_V4 ===");
            for (ip, rep) in blocked_v4.iter().flatten() {
                let ip_v4 = IpAddr::V4(Ipv4Addr::from(ip));
                println!("* {ip_v4}\n\t- Hits: {}", rep.hits);
            }

            println!("\n=== BLOCKED_V6 ===");
            for (ip, rep) in blocked_v6.iter().flatten() {
                let ip_v6 = IpAddr::V6(Ipv6Addr::from_octets(ip));
                println!("* {ip_v6}\n\t- Hits: {}", rep.hits);
            }

            println!("\n=== PACKET COUNTS V4 ===");
            for (k, c) in pkt_counts_v4.iter().flatten() {
                let ip = Ipv4Addr::from(k);
                println!("* {}\n\t Total: {}", ip, c.iter().sum::<u64>());
            }

            println!("\n=== PACKET COUNTS V6 ===");
            for (k, c) in pkt_counts_v6.iter().flatten() {
                let ip = Ipv6Addr::from(k);
                println!("* {}\n\t Total: {}", ip, c.iter().sum::<u64>());
            }

            println!("\n=== UNKOWN BUCKETS V4 ===");
            for k in unknown_counts_v4.keys().flatten() {
                let ip = Ipv4Addr::from(k);
                println!("* {}", ip);
            }

            println!("\n=== UNKNOWN BUCKETS V6 ===");
            for k in unknown_counts_v6.keys().flatten() {
                let ip = Ipv6Addr::from(k);
                println!("* {}", ip);
            }
        }

        return Ok(());
    }

    // Check if the '/sys/fs/bpf/bpfimp' directory exists,
    // if not create it
    let path = Path::new("/sys/fs/bpf/bpfimp");
    if !path.exists() {
        DirBuilder::new()
            .recursive(true)
            .create(path)
            .with_context(|| "failed to create bpfimp map directory")?;
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

    info!("Waiting for Ctrl-C...");

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
        }
    }

    Ok(())
}
