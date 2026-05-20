# bpfimp

An XDP-based packet rate limiter written in Rust with [aya]. Traffic is
classified per source IP and metered against a token bucket in the kernel; a
small userspace control plane hot-reloads a list of known peers from disk.

> Status: working demo. Tested against a veth/netns harness. IPv4 only.

## What it does

For every IPv4 packet arriving on the attached interface, the XDP program:

1. Increments a per-source-IP packet counter (`PACKET_COUNTS`).
2. Looks the source up in one of two LRU maps:
   - **Known peers** (`KNOWN_BUCKETS`) — IPs loaded from `peers.toml`. Each has
     a token bucket *and* a reputation score. The score gates the bucket: an
     IP only passes if `score >= MIN_SCORE_TO_PASS` *and* a token is available.
     Successful packets nudge the score up (capped at `MAX_SCORE`); a denied
     packet subtracts `PENALTY`. This lets a trusted peer absorb a burst but
     get throttled if it sustains abuse.
   - **Unknown IPs** (`UNKNOWN_BUCKETS`) — auto-inserted with a smaller
     starting balance (`NEW_MAX_TOKENS`) and a plain token bucket.
3. Returns `XDP_PASS` or `XDP_DROP` based on the result.

Userspace (`bpfimp`) loads the program, attaches it to `--iface`, and watches
`peers.toml` with a debounced filesystem notifier so edits take effect without
a restart.

## Architecture

```
                kernel  |  user
                        |
   NIC ── XDP hook ─────|
        │               |
        ▼               |
   PACKET_COUNTS        |
        │               |
        ▼               |
   KNOWN_BUCKETS  ◄─────|──── peers.toml  (notify + debouncer)
   UNKNOWN_BUCKETS      |
        │               |
        ▼               |
   XDP_PASS / XDP_DROP  |
```

The two crates split cleanly: `bpfimp-ebpf` is the `no_std` kernel program,
`bpfimp` is the Tokio-based loader, and `bpfimp-common` holds the POD types
(`TokenBucket`, `Reputation`) and policy constants shared by both sides.

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
sudo ./scripts/gen_traffic.sh        # 20 pings at 1/s — should all pass
sudo ./scripts/gen_traffic.sh burst  # ping flood — bucket drains, drops appear

# 4. Tear it all down
sudo ./scripts/teardown_netns.sh
```

The attached eBPF logs (`RUST_LOG=info`) show individual `packet dropped` lines
as the bucket empties during the flood.

## Configuring known peers

`peers.toml` lists IPs that should be tracked with reputation scoring instead
of the unknown-IP bucket:

```toml
peers = [
    "10.200.0.2",
    "192.168.1.50",
]
```

Edits are picked up live — the userspace watcher debounces filesystem events
and re-pushes the list into `KNOWN_BUCKETS` on save. Removed IPs naturally age
out via the LRU map.

## Policy knobs

The rate-limit constants live in [`bpfimp-common/src/lib.rs`](bpfimp-common/src/lib.rs):

| Constant            | Default | Meaning                                                       |
| ------------------- | ------- | ------------------------------------------------------------- |
| `MAX_TOKENS`        | 200     | Bucket cap for established (known) peers                      |
| `NEW_MAX_TOKENS`    | 100     | Starting balance for newly-seen unknown IPs                   |
| `REFILL_PER_SEC`    | 10      | Tokens replenished per second                                 |
| `MAX_SCORE`         | 100     | Cap on reputation score                                       |
| `MIN_SCORE_TO_PASS` | 20      | Score floor below which a known peer is dropped               |
| `PENALTY`           | 10      | Score subtracted on a denied packet                           |

With the defaults a steady rate above ~10 pkt/s will eventually empty an
unknown IP's bucket; a known peer with a healthy score absorbs bursts up to
200 packets before throttling.

## CLI

```
bpfimp --iface <NAME> [--peers-config <PATH>]

  -i, --iface         interface to attach XDP to (default: wlp0s20f3)
  -p, --peers-config  path to peers.toml (default: ./peers.toml)
```

`RUST_LOG=info` (or `debug`/`trace`) controls log verbosity.

## Limitations

- **IPv4 only.** IPv6 packets are passed through unmetered. The netns setup
  script explicitly disables v6 on the test veth so the demo isn't polluted by
  RA/NDP chatter.
- **No persistent counters.** Maps are zeroed on program reload.
- **Reputation doesn't decay over time** — a penalized IP that goes silent
  stays penalized until evicted from the LRU map.
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
