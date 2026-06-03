# demo/demo.tape -- VHS script for the bpfimp README demo GIF.

Output demo/demo.gif

Require tmux
Require sudo
Require cargo

Set Shell "bash"
Set FontSize 13
Set Width 1300
Set Height 760
Set Padding 20
Set Theme "Dracula"
Set TypingSpeed 45ms
Set WaitTimeout 30s

# ----------------------------------------------------------- setup (not shown)
Hide
Type "clear" Enter
Type "sudo ./scripts/setup_netns.sh >/dev/null 2>&1" Enter
Sleep 1s
Type "cp demo/unknown.toml demo/run.toml" Enter

# Build the 3-pane tmux layout on a private socket, started with NO user config
Type "tmux -L bpfimpdemo kill-server 2>/dev/null" Enter
Type "tmux -L bpfimpdemo -f /dev/null new-session -d -s bpfimp 'bash --norc --noprofile'" Enter
Type "tmux -L bpfimpdemo set -g default-command 'bash --norc --noprofile'" Enter
Type "tmux -L bpfimpdemo split-window -v -l 34% -t bpfimp:0.0" Enter
Type "tmux -L bpfimpdemo split-window -h -l 50% -t bpfimp:0.0" Enter
Type "tmux -L bpfimpdemo send-keys -t bpfimp:0.0 'sudo RUST_LOG=info ./target/release/bpfimp run --iface vbpfimp0 --config demo/run.toml' Enter" Enter
# `watch` errors until the program is loaded, so retry until it attaches
# instead of guessing a fixed delay.
Type "tmux -L bpfimpdemo send-keys -t bpfimp:0.1 'until sudo ./target/release/bpfimp watch --json 2>/dev/null; do sleep 1; done' Enter" Enter
Type "tmux -L bpfimpdemo select-pane -t bpfimp:0.2" Enter
Type "tmux -L bpfimpdemo send-keys -t bpfimp:0.2 clear Enter" Enter
Type "tmux -L bpfimpdemo attach -t bpfimp" Enter
# Gate the reveal on the XDP program actually being attached to the iface, then
# print a short one-word marker. Matching a tiny sentinel at column 0 is robust;
# matching a long, timestamped log line in a narrow pane is not (it wraps).
Type "until ip link show vbpfimp0 2>/dev/null | grep -qi xdp; do sleep 0.5; done; echo DEMO_READY" Enter
Wait+Screen /DEMO_READY/
Sleep 1s
Show

# ----------------------------------------------------------- demo (recorded)
# Each flood is followed by `Wait+Screen /packet loss/`, which blocks the
# recording until ping prints its summary line

Type "clear; cat demo/run.toml" Enter
Sleep 2s
Type "# peer 10.200.0.2 is unknown: fresh 100-token bucket, +10 tok/s" Enter
Sleep 1500ms
Type "sudo ./scripts/gen_traffic.sh burst" Enter
Wait+Screen /packet loss/
Sleep 3s
Type "# ~138/500 passed = 100 start + ~10/s over a ~4s flood. drops scroll top-right." Enter
Sleep 2s
Type "sudo ./target/release/bpfimp inspect" Enter
Sleep 4s

Type "# --- block the peer: save a new policy, no restart ---" Enter
Sleep 1s
# `&& sleep 2` makes bash itself wait for the debounced reload to land.
Type "cp demo/block.toml demo/run.toml && sleep 2" Enter
Sleep 1s
Type "clear; cat demo/run.toml" Enter
Sleep 2s
Type "sudo ./scripts/gen_traffic.sh burst" Enter
Wait+Screen /packet loss/
Sleep 3s
Type "# ~100% loss: every packet XDP_DROP'd at the blocklist" Enter
Sleep 2s

Type "# --- trust the peer instead: move it to the allowlist ---" Enter
Sleep 1s
Type "cp demo/allow.toml demo/run.toml && sleep 2" Enter
Sleep 1s
Type "clear; cat demo/run.toml" Enter
Sleep 2s
Type "sudo ./scripts/gen_traffic.sh burst" Enter
Wait+Screen /packet loss/
Sleep 3s
Type "# ~240/500 passed: allowed peers get a 200-token bucket + reputation" Enter
Sleep 3s

# ----------------------------------------------------------- teardown (hidden)
Hide
Type "tmux -L bpfimpdemo send-keys -t bpfimp:0.0 C-c" Enter
Sleep 1s
Type "tmux -L bpfimpdemo kill-server" Enter
Type "sudo ./scripts/teardown_netns.sh >/dev/null 2>&1" Enter
Type "rm -f demo/run.toml" Enter
Show
