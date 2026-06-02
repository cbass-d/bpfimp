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
    maps::{HashMap, Map, MapData, PerCpuHashMap, RingBuf, loaded_maps},
    programs::{Xdp, XdpFlags, loaded_programs},
};
use bpfimp_common::{
    ALLOWED_V4_MAP, ALLOWED_V6_MAP, BLOCKED_V4_MAP, BLOCKED_V6_MAP, BPF_PROGRAM, BlockedEntry,
    EVENTS_MAP, EventKind, ImpEvent, PKT_COUNTS_V4_MAP, PKT_COUNTS_V6_MAP, Reputation, TokenBucket,
    UNK_BKTS_V4_MAP, UNK_BKTS_V6_MAP,
};
use clap::{ArgMatches, Command, arg};
use log::{debug, error, info, warn};
use nix::time::{ClockId, clock_gettime};
use notify::{
    RecursiveMode,
    event::{AccessKind, AccessMode},
};
use notify_debouncer_full::{DebouncedEvent, new_debouncer};
use tokio::{
    io::unix::AsyncFd,
    signal::unix::{SignalKind, signal},
    sync::mpsc,
};

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

#[derive(serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum WatchEvent {
    Drop {
        ts_ns: u64,
        ip: IpAddr,
        ip_version: u8,
    },
}

impl WatchEvent {
    fn from_wire(e: &ImpEvent) -> Result<Self> {
        let ip = match e.ip_version {
            4 => IpAddr::V4(Ipv4Addr::new(e.addr[0], e.addr[1], e.addr[2], e.addr[3])),
            6 => IpAddr::V6(Ipv6Addr::from(e.addr)),
            v => return Err(anyhow!("invalid ip version on wire: {v}")),
        };

        match e.kind {
            k if k == EventKind::Drop as u8 => Ok(WatchEvent::Drop {
                ts_ns: e.ts_ns,
                ip,
                ip_version: e.ip_version,
            }),
            e => Err(anyhow!("invalid event kind on wire: {e}")),
        }
    }
}

fn clock_now_ns() -> u64 {
    let ts = clock_gettime(ClockId::CLOCK_MONOTONIC).expect("CLOCK_MONOTONIC get time failed");

    (ts.tv_sec() as u64) * 1_000_000_000 + ts.tv_nsec() as u64
}

fn cli() -> Command {
    Command::new("bpfimp")
        .about("XDP-based per-source-IP packet rate limiter")
        .long_about(
            "Attaches an XDP program that meters traffic per source IP against a \
             token bucket in the kernel. A userspace control plane hot-reloads \
             allow/block lists from a TOML file, snapshots live state, and streams \
             drop events over a ring buffer. Must be run as root.",
        )
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .after_help(
            "EXAMPLES:\n  \
             # Attach to eth0, reconciling lists from ./bpfimp.toml on save\n  \
             sudo bpfimp run --iface eth0\n\n  \
             # Snapshot live state as JSON (requires a running instance)\n  \
             sudo bpfimp inspect --json\n\n  \
             # Stream drop events as newline-delimited JSON\n  \
             sudo bpfimp watch --json | jq .\n\n\
             Set RUST_LOG=info (or debug/trace) to control log verbosity.",
        )
        .subcommand(
            Command::new("run")
                .about("load and attach the XDP program, then hot-reload the config")
                .arg(arg!(-i --iface <IFACE> "the interface to attach to").required(true))
                .arg(
                    arg!(-c --config <CONFIG> "path to config file")
                        .default_value("bpfimp.toml")
                        .value_parser(clap::value_parser!(PathBuf)),
                ),
        )
        .subcommand(
            Command::new("inspect")
                .about("snapshot live and persisted bpf state (requires a running instance)")
                .arg(arg!(-j --json "output as json")),
        )
        .subcommand(
            Command::new("watch")
                .about("tail a live feed of events (drops/blocks)")
                .arg(arg!(-j --json "output as JSON lines")),
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

    sync_keys(&mut map_of(ebpf, ALLOWED_V4_MAP)?, &allow_v4, |_| {
        Reputation::new(now)
    })?;
    sync_keys(&mut map_of(ebpf, ALLOWED_V6_MAP)?, &allow_v6, |_| {
        Reputation::new(now)
    })?;
    sync_keys(&mut map_of(ebpf, BLOCKED_V4_MAP)?, &block_v4, |_| {
        BlockedEntry::default()
    })?;
    sync_keys(&mut map_of(ebpf, BLOCKED_V6_MAP)?, &block_v6, |_| {
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
        .with_context(|| format!("map {name} not found among loaded BPF maps"))?;

    let map_data = aya::maps::MapData::from_id(info.id())
        .with_context(|| format!("failed to open map {name} (id {})", info.id()))?;

    let map: PerCpuHashMap<_, K, V> = PerCpuHashMap::try_from(Map::PerCpuLruHashMap(map_data))
        .with_context(|| format!("map {name} is not a per-cpu hash of the expected type"))?;

    Ok(map)
}

/// Return the map using 'loaded_maps()' if it exists on the host
/// system
fn load_map<K: Pod, V: Pod>(name: &str, key_size: u32) -> Result<HashMap<MapData, K, V>> {
    debug!("loading map: {name}");
    let info = loaded_maps()
        .filter_map(|m| m.ok())
        .find(|m| m.name_as_str() == Some(name) && m.key_size() == key_size)
        .with_context(|| format!("map {name} not found among loaded BPF maps"))?;

    let map_data = aya::maps::MapData::from_id(info.id())
        .with_context(|| format!("failed to open map {name} (id {})", info.id()))?;

    let map: HashMap<_, K, V> = HashMap::try_from(Map::LruHashMap(map_data))
        .with_context(|| format!("map {name} is not a hash of the expected type"))?;

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

/// Open a pinned LRU hash map from the bpffs and convert it to a typed
/// `aya::maps::HashMap`
fn load_pinned_lru<K: Pod, V: Pod>(name: &str) -> Result<HashMap<MapData, K, V>> {
    let map = MapData::from_pin(format!("{BPFS_FS_PATH}/{name}"))
        .with_context(|| format!("failed to open pinned map {name}"))?;
    HashMap::try_from(Map::LruHashMap(map))
        .with_context(|| format!("failed to convert pinned map {name} to HashMap"))
}

fn collect_allowed(
    v4: &HashMap<MapData, u32, Reputation>,
    v6: &HashMap<MapData, [u8; 16], Reputation>,
) -> Vec<AllowedRecord> {
    let mut out: Vec<AllowedRecord> = v4
        .iter()
        .flatten()
        .map(|(ip, rep)| AllowedRecord {
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            score: rep.score,
            tokens: rep.bucket.tokens,
        })
        .collect();
    out.extend(v6.iter().flatten().map(|(ip, rep)| AllowedRecord {
        ip: IpAddr::V6(Ipv6Addr::from(ip)),
        score: rep.score,
        tokens: rep.bucket.tokens,
    }));
    out
}

fn collect_blocked(
    v4: &HashMap<MapData, u32, BlockedEntry>,
    v6: &HashMap<MapData, [u8; 16], BlockedEntry>,
) -> Vec<BlockedRecord> {
    let mut out: Vec<BlockedRecord> = v4
        .iter()
        .flatten()
        .map(|(ip, e)| BlockedRecord {
            ip: IpAddr::V4(Ipv4Addr::from(ip)),
            hits: e.hits,
            last_seen_ns: e.last_seen_ns,
        })
        .collect();
    out.extend(v6.iter().flatten().map(|(ip, e)| BlockedRecord {
        ip: IpAddr::V6(Ipv6Addr::from(ip)),
        hits: e.hits,
        last_seen_ns: e.last_seen_ns,
    }));
    out
}

fn collect_counts(
    v4: &PerCpuHashMap<MapData, u32, u64>,
    v6: &PerCpuHashMap<MapData, [u8; 16], u64>,
) -> Vec<PacketCountRecord> {
    let mut out: Vec<PacketCountRecord> = v4
        .iter()
        .flatten()
        .map(|(k, c)| PacketCountRecord {
            ip: IpAddr::V4(Ipv4Addr::from(k)),
            total: c.iter().sum(),
        })
        .collect();
    out.extend(v6.iter().flatten().map(|(k, c)| PacketCountRecord {
        ip: IpAddr::V6(Ipv6Addr::from(k)),
        total: c.iter().sum(),
    }));
    out
}

fn collect_unknown(
    v4: &HashMap<MapData, u32, TokenBucket>,
    v6: &HashMap<MapData, [u8; 16], TokenBucket>,
) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = v4
        .keys()
        .flatten()
        .map(|k| IpAddr::V4(Ipv4Addr::from(k)))
        .collect();
    out.extend(v6.keys().flatten().map(|k| IpAddr::V6(Ipv6Addr::from(k))));
    out
}

fn print_human(output: &InspectOutput) {
    println!("=== ALLOWED ===");
    for r in &output.allowed {
        println!("* {}\n\t- Rep Score: {}", r.ip, r.score);
    }

    println!("\n=== BLOCKED ===");
    for r in &output.blocked {
        println!("* {}\n\t- Hits: {}", r.ip, r.hits);
    }

    println!("\n=== PACKET COUNTS ===");
    for r in &output.packet_counts {
        println!("* {}\n\t Total: {}", r.ip, r.total);
    }

    println!("\n=== UNKNOWN BUCKETS ===");
    for ip in &output.unknown_buckets {
        println!("* {ip}");
    }
}

/// Fetch the loaded `bpfimp` XDP program from the ebpf object, with distinct
/// errors for the two failure modes (missing program vs. wrong program type).
fn xdp_program(ebpf: &mut Ebpf) -> Result<&mut Xdp> {
    ebpf.program_mut(BPF_PROGRAM)
        .context("program 'bpfimp' not found")?
        .try_into()
        .context("program 'bpfimp' is not an Xdp program")
}

/// Check that a bpfimp instance is loaded before trying to read its maps,
/// so callers get one clear message instead of a per-map load error
fn ensure_running() -> Result<()> {
    let running = loaded_programs()
        .filter_map(|p| p.ok())
        .any(|m| m.name_as_str() == Some(BPF_PROGRAM));

    if !running {
        return Err(anyhow!("bpfimp does not appear to be running"));
    }

    Ok(())
}

/// Locate a loaded ring buffer map by name and open it for reading
fn load_ringbuf(name: &str) -> Result<RingBuf<MapData>> {
    debug!("loading ring buffer: {name}");

    let info = loaded_maps()
        .filter_map(|m| m.ok())
        .find(|m| m.name_as_str() == Some(name))
        .with_context(|| format!("ringbuf {name} not found among loaded BPF maps"))?;

    let map_data = MapData::from_id(info.id())
        .with_context(|| format!("failed to open ringbuf {name} (id {})", info.id()))?;

    RingBuf::try_from(Map::RingBuf(map_data))
        .with_context(|| format!("map {name} is not a ring buffer"))
}

fn print_event(ev: &WatchEvent, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string(ev)?);
    } else {
        match ev {
            WatchEvent::Drop { ts_ns, ip, .. } => println!("[{ts_ns}] DROP {ip}"),
        }
    }

    Ok(())
}

async fn run_watch(ring: RingBuf<MapData>, json: bool) -> Result<()> {
    let mut fd = AsyncFd::new(ring)?;

    loop {
        let mut guard = fd.readable_mut().await?;
        let ring = guard.get_inner_mut();

        // One readiness notification can cover many records, drain until empty
        while let Some(item) = ring.next() {
            let bytes = &item;
            if bytes.len() < std::mem::size_of::<ImpEvent>() {
                continue;
            }

            // ImpEvent is Pod, read_unaligned is sound regardless of alignment
            let raw: ImpEvent = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast()) };

            match WatchEvent::from_wire(&raw) {
                Ok(ev) => print_event(&ev, json)?,
                Err(e) => warn!("dropping malformed event: {e}"),
            }
        }

        guard.clear_ready();
    }
}

async fn watch(sub_matches: &ArgMatches) -> Result<()> {
    ensure_running()?;

    debug!("running watch command");

    let ring = load_ringbuf(EVENTS_MAP)?;
    run_watch(ring, sub_matches.get_flag("json")).await
}

fn inspect(sub_matches: &ArgMatches) -> Result<()> {
    ensure_running()?;

    debug!("running inspect command");

    // Read from the kernel by id
    let pkt_counts_v4 = load_percpu_map::<u32, u64>(PKT_COUNTS_V4_MAP, 4)?;
    let pkt_counts_v6 = load_percpu_map::<[u8; 16], u64>(PKT_COUNTS_V6_MAP, 16)?;
    let unknown_counts_v4 = load_map::<u32, TokenBucket>(UNK_BKTS_V4_MAP, 4)?;
    let unknown_counts_v6 = load_map::<[u8; 16], TokenBucket>(UNK_BKTS_V6_MAP, 16)?;

    // Allow and Block buckets, read from their pins
    let allowed_v4 = load_pinned_lru::<u32, Reputation>(ALLOWED_V4_MAP)?;
    let allowed_v6 = load_pinned_lru::<[u8; 16], Reputation>(ALLOWED_V6_MAP)?;
    let blocked_v4 = load_pinned_lru::<u32, BlockedEntry>(BLOCKED_V4_MAP)?;
    let blocked_v6 = load_pinned_lru::<[u8; 16], BlockedEntry>(BLOCKED_V6_MAP)?;

    debug!("all maps loaded");

    let output = InspectOutput {
        allowed: collect_allowed(&allowed_v4, &allowed_v6),
        blocked: collect_blocked(&blocked_v4, &blocked_v6),
        packet_counts: collect_counts(&pkt_counts_v4, &pkt_counts_v6),
        unknown_buckets: collect_unknown(&unknown_counts_v4, &unknown_counts_v6),
    };

    if sub_matches.get_flag("json") {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        print_human(&output);
    }

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let cli = cli().get_matches();

    if !nix::unistd::geteuid().is_root() {
        error!("binary must be run with root privileges");
        return Err(anyhow!("binary must be run as root"));
    }

    if let Some(("inspect", sub_matches)) = cli.subcommand() {
        inspect(sub_matches).with_context(|| "failed to handle inspect command")?;
        return Ok(());
    }

    if let Some(("watch", sub_matches)) = cli.subcommand() {
        watch(sub_matches)
            .await
            .with_context(|| "failed to handle watch command")?;
        return Ok(());
    }

    // Check if the bpffs pin directory exists, if not create it
    let path = Path::new(BPFS_FS_PATH);
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
            .map_pin_path(BPFS_FS_PATH)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/bpfimp"
            )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    let program = xdp_program(&mut ebpf)?;
    program.load()?;
    let link = program.attach(iface, XdpFlags::default())
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

    let mut sigint = signal(SignalKind::interrupt())
        .with_context(|| "failed to setup tokio signal for SIGINT")?;
    let mut sigterm = signal(SignalKind::terminate())
        .with_context(|| "failed to setup tokio signal for SIGTERM")?;

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                info!("Exiting...");
                break;
            }
            _ = sigterm.recv() => {
                info!("SIGTERM received, exiting...");
                break;
            }
            Some(Ok(events)) = rx.recv() => {
                let is_config_save = |e: &DebouncedEvent| {
                    matches!(e.kind, notify::EventKind::Access(AccessKind::Close(AccessMode::Write)))
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

    drop(debouncer);

    let program = xdp_program(&mut ebpf)?;

    if let Err(e) = program.detach(link) {
        warn!("failed to detach Xdp program cleanly: {e}");
    } else {
        info!("detached from {iface}");
    }

    Ok(())
}
