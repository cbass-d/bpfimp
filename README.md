# bpfimp

An XDP-based packet rate limiter written in Rust with [aya]. Traffic is
classified per source IP and metered against a token bucket in the kernel; a
small userspace control plane hot-reloads allow/block lists from disk.
Handles both IPv4 and IPv6.

> Status: working demo. Tested against a veth/netns harness.

## What it does

For every IPv4 or IPv6 packet arriving on the attached interface, the XDP
program:

1. Looks the source IP up in the **blocklist** map
   (`BLOCKED_BUCKETS_V4` / `BLOCKED_BUCKETS_V6`). A hit drops the packet and
   bumps a per-entry hit counter.
2. Otherwise increments a per-source-IP packet counter
   (`PACKET_COUNTS_V4` / `PACKET_COUNTS_V6`).
3. Looks the source up in one of two LRU maps:
   - **Allowed peers** (`ALLOWED_BUCKETS_V4` / `ALLOWED_BUCKETS_V6`) — IPs
     loaded from `bpfimp.toml`. Each has a token bucket *and* a reputation
     score. The score gates the bucket: an IP only passes if
     `score >= MIN_SCORE_TO_PASS` *and* a token is available. Successful
     packets nudge the score up (capped at `MAX_SCORE`); a denied packet
     subtracts `PENALTY`. This lets a trusted peer absorb a burst but get
     throttled if it sustains abuse.
   - **Unknown IPs** (`UNKNOWN_BUCKETS_V4` / `UNKNOWN_BUCKETS_V6`) —
     auto-inserted with a smaller starting balance (`NEW_MAX_TOKENS`) and a
     plain token bucket.
4. Returns `XDP_PASS` or `XDP_DROP` based on the result.

IPv4 and IPv6 are tracked in independent map families; a peer that appears
under both families gets two independent buckets and reputations.

Userspace (`bpfimp`) loads the program, attaches it to `--iface`, and watches
`bpfimp.toml` with a debounced filesystem notifier so edits take effect
without a restart.

## Architecture

```
                  kernel  |  user
                          |
   NIC ── XDP hook ───────|
        │                 |
        ▼                 |
   BLOCKED_BUCKETS_V{4,6} ◄──|──┐
        │                 |    │
        ▼                 |    ├── bpfimp.toml  (notify + debouncer)
   PACKET_COUNTS_V{4,6}   |    │
        │                 |    │
        ▼                 |    │
   ALLOWED_BUCKETS_V{4,6} ◄──|─┘
   UNKNOWN_BUCKETS_V{4,6} |
        │                 |
        ▼                 |
   XDP_PASS / XDP_DROP    |
```

The three crates split cleanly: `bpfimp-ebpf` is the `no_std` kernel program,
`bpfimp` is the Tokio-based loader, and `bpfimp-common` holds the POD types
(`TokenBucket`, `Reputation`, `BlockedEntry`) and policy constants shared by
both sides.

## Persistence

The maps are pinned to bpffs under `/sys/fs/bpf/bpfimp/`. The loader declares
them with `pinned(...)` on the kernel side and opens them through
`EbpfLoader::map_pin_path("/sys/fs/bpf/bpfimp")`, so on startup it reuses an
existing pin when one is present and creates+pins a fresh map otherwise. As a
result reputation scores, block-hit counters, and per-IP packet totals survive
a `bpfimp run` restart — they are *not* zeroed on reload.

`bpfimp inspect` reads those pinned maps directly without loading or attaching
the eBPF program, so you can dump the persisted state at any time (even while
`bpfimp run` is not active). To wipe the state, remove the pins:

```shell
sudo rm -rf /sys/fs/bpf/bpfimp
```

## Quickstart

Prerequisites:

- Rust stable + nightly (`rustup toolchain install stable nightly --component rust-src`)
- `bpf-linker` (`cargo install bpf-linker`)
- A Linux kernel with XDP support (most distros, 5.x+)

A self-contained veth/netns harness ships in `scripts/`:

```shell
# 1. Create the test netns + veth pair (host 10.200.0.1, peer 10.200.0.2)
sudo ./scripts/setup_netns.sh

# 2. Build and attach the XDP program to the host veth
sudo ./scripts/run_bpfimp.sh

# 3. In another shell, generate traffic
sudo ./scripts/gen_traffic.sh         # 20 v4 pings at 1/s — should all pass
sudo ./scripts/gen_traffic.sh burst   # v4 flood — bucket drains, drops appear
sudo ./scripts/gen_traffic.sh ping6   # same against the v6 ULA (fd00:200::1)
sudo ./scripts/gen_traffic.sh burst6  # v6 flood

# 4. Tear it all down
sudo ./scripts/teardown_netns.sh
```

The attached eBPF logs (`RUST_LOG=info`) show individual `packet dropped` lines
as the bucket empties during the flood.

The harness assigns both an IPv4 (`10.200.0.0/24`) and an IPv6 ULA
(`fd00:200::/64`) address to each end of the veth, so both code paths are
exercised. Router advertisements and autoconf are disabled on the test
interfaces to keep address state deterministic.

## Configuring allow/block lists

`bpfimp.toml` lists IPs to reputation-track (`allowlist`) or drop outright
(`blocklist`). Both IPv4 and IPv6 addresses are accepted; entries are
dispatched into the right map family based on the parsed address type:

```toml
allowlist = [
    "10.200.0.2",
    "2001:db8::50",
]
blocklist = [
    "192.168.1.50",
    "2001:db8::dead",
]
```

Edits are picked up live — the userspace watcher debounces filesystem events
and reconciles both lists against the kernel maps on save. The reconcile is a
set diff: IPs removed from the file are deleted from their map, newly-added IPs
are inserted, and IPs that are still listed are left untouched — so an allowed
peer keeps its accumulated reputation across edits instead of being reset.

## Policy knobs

The rate-limit constants live in [`bpfimp-common/src/lib.rs`](bpfimp-common/src/lib.rs)
and apply uniformly to both v4 and v6:

| Constant            | Default | Meaning                                                       |
| ------------------- | ------- | ------------------------------------------------------------- |
| `MAX_TOKENS`        | 200     | Bucket cap for established (allowed) peers                    |
| `NEW_MAX_TOKENS`    | 100     | Starting balance for newly-seen unknown IPs                   |
| `REFILL_PER_SEC`    | 10      | Tokens replenished per second                                 |
| `MAX_SCORE`         | 100     | Cap on reputation score                                       |
| `MIN_SCORE_TO_PASS` | 20      | Score floor below which an allowed peer is dropped            |
| `PENALTY`           | 10      | Score subtracted on a denied packet                           |

With the defaults a steady rate above ~10 pkt/s will eventually empty an
unknown IP's bucket; an allowed peer with a healthy score absorbs bursts up to
200 packets before throttling.

## CLI

`bpfimp` is subcommand-based:

```
bpfimp run [--iface <NAME>] [--config <PATH>]

  -i, --iface   interface to attach XDP to (default: wlan0)
  -c, --config  path to bpfimp.toml (default: ./bpfimp.toml)

bpfimp inspect
```

- **`run`** loads and attaches the XDP program, then watches the config file
  and reconciles the allow/block lists on every save.
- **`inspect`** reads the pinned maps under `/sys/fs/bpf/bpfimp/` and prints the
  current allowed-peer reputation scores and blocked-IP hit counts. It does not
  load or attach the program, so it works whether or not `run` is active (as
  long as the pins exist from a prior `run`).

`RUST_LOG=info` (or `debug`/`trace`) controls log verbosity.

## Limitations

- **Reputation doesn't decay over time** — a penalized IP that goes silent
  stays penalized until evicted from the LRU map.
- **v4 and v6 of the same peer are tracked independently** — no cross-family
  association.
- XDP attach defaults to native mode; on interfaces that don't support it
  (some virtio configs), switch to `XdpFlags::SKB_MODE` in
  `bpfimp/src/main.rs`.

## Cross-compiling

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package bpfimp --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The resulting `target/${ARCH}-unknown-linux-musl/release/bpfimp` can be copied
to a Linux host and run there.

## License

With the exception of eBPF code, bpfimp is distributed under the terms of
either the [MIT license] or the [Apache License] (version 2.0), at your option.

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your option.

[aya]: https://github.com/aya-rs/aya
[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
