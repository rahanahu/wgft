#!/usr/bin/env bash
# rust-agent.sh runs the v2 Rust agent prototype against the unchanged Go v1 server for one server
# mode and prints PASS/FAIL per check:
#
#   lab/lab exec vm bash /wgft/lab/rust-agent.sh kernel      # Go server as root, kernel WireGuard
#   lab/lab exec vm bash /wgft/lab/rust-agent.sh userspace   # Go server as wgftlab, wireguard-go
#
# The kernel run checks the Rust agent against Linux kernel WireGuard, the userspace run against
# wireguard-go. Four phases share one server:
#
#   1. The Rust agent enrolls itself as "home" with a join string, brings up its TUN tunnel, passes
#      the WireGuard handshake and the keepalive ping to the server's tunnel address, and relays a
#      TCP rule from the server's public side to a target in the LAN: 8 MiB each way, compared by
#      SHA-256.
#   2. Sanity: the Go v1 agent enrolls as "home2" against the same server and forwards a TCP rule.
#   3. The Rust agent starts from the agent.json the Go agent wrote in phase 2, with no join string,
#      and forwards home2's rule with the same checksum check.
#   4. The Go agent starts from the agent.json the Rust agent wrote in phase 1 and forwards home's
#      rule the same way.
#
# The Rust binary is wgft-rs, built by `WGFT_LAB_RUST=1 lab/lab build` (cargo zigbuild for
# x86_64-unknown-linux-musl). The Rust agent runs as root in the home namespace: the prototype
# carries the tunnel on a Linux TUN device and the kernel's TCP/IP. Requires `lab/lab build` and the
# netns topology (`lab/lab net up`). Leftovers from earlier runs are killed first.
set -u
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: rust-agent.sh kernel|userspace" >&2; exit 2;; esac

. "$(dirname "$0")/sandbox.sh"   # sandbox: netns names, workdir, process scope
DATA=$W/wgft-rs-server
RDATA=$W/wgft-rs-agent
GDATA=$W/wgft-rs-goagent
SLOG=$W/wgft-rs-$mode-server.log
RLOG=$W/wgft-rs-$mode-agent.log
GLOG=$W/wgft-rs-$mode-goagent.log
R2LOG=$W/wgft-rs-$mode-agent-from-go.log
G2LOG=$W/wgft-rs-$mode-goagent-from-rust.log
BLOB=$W/wgft-rs-blob
ADMIN=127.0.0.1:8687
TUN=wgftrs0
fail=0
check() { # check <label> <expected-substring> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
vps() { ip netns exec "$VPS_NS" "$@"; }
client() { ip netns exec "$CLIENT_NS" bash -c "$1"; }
lan() { ip netns exec "$LAN_NS" "$@"; }
agent_row() { vps wgft agent ls --admin "$ADMIN" | awk -v n="$1" '$1 == n { print; found=1 } END { if (!found) exit 1 }'; }
# agent_field <name> <expr>: evaluates a Python expression over the agent's `agent ls --json` entry `a`
agent_field() {
  vps wgft agent ls --json --admin "$ADMIN" | python3 -c '
import json, sys
name, expr = sys.argv[1], sys.argv[2]
data = json.load(sys.stdin)
rows = data if isinstance(data, list) else data.get("agents", [])
a = next((r for r in rows if r.get("name") == name), None)
print("" if a is None else eval(expr))' "$1" "$2"
}
# wait_for <seconds> <command...>: retries the command once a second until it succeeds
wait_for() {
  local t=$1; shift
  for _ in $(seq "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  return 1
}
kill_all() { sandbox_kill_named wgft wgft-rs socat; sleep 1; }
kill_named() { sandbox_kill_named "$1"; sleep 1; }
kill_go_agent() { # the Go agent shares the comm name wgft with the server, so match the command line
  for p in $(sandbox_wgft_pids); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q ' agent run' && kill "$p"
  done
  sleep 1
}
cleanup() {
  kill_all
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  ip netns exec "$HOME_NS" ip link del "$TUN" 2>/dev/null
  rm -rf "$DATA" "$RDATA" "$GDATA" "$BLOB"
}
# handshake_ok <name>: the server saw a WireGuard handshake from the agent, and the agent's heartbeat
# reports an ok tunnel
handshake_ok() { [ "$(agent_field "$1" 'bool(a["last_handshake"]) and a["tunnel"]["state"] == "ok"')" = True ]; }
start_rust() { # start_rust <data-dir> <log> [join]
  WGFT_JOIN="${3:-}" WGFT_WG_INTERFACE="$TUN" \
    ip netns exec "$HOME_NS" setsid nohup wgft-rs agent run --data-dir "$1" > "$2" 2>&1 < /dev/null &
  disown
}
# transfer <label> <public-port>: 8 MiB up to sha256sum at the target, 8 MiB down from the target
transfer() {
  local want up down
  want=$(sha256sum < "$BLOB" | cut -d' ' -f1)
  up=$(client "timeout -k 5 60 socat -t 30 -T 30 - TCP:198.51.100.1:$2 < $BLOB" | cut -d' ' -f1)
  check "$1: 8 MiB up, sha256 at the target" "$want" "${up:-none}"
  down=$(client "timeout -k 5 60 socat -u -T 30 TCP:198.51.100.1:$(( $2 + 1 )) - | sha256sum" | cut -d' ' -f1)
  check "$1: 8 MiB down, sha256 at the client" "$want" "${down:-none}"
}

command -v wgft-rs >/dev/null || { echo "FAIL  wgft-rs is not installed; run WGFT_LAB_RUST=1 lab/lab build"; exit 1; }
cleanup
mkdir -p "$DATA"
head -c 8388608 /dev/urandom > "$BLOB"
chmod 0644 "$BLOB"
if [ "$mode" = userspace ]; then
  id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab
  chown wgftlab "$DATA"
  run_server="runuser -u wgftlab -- wgft server run"
else
  run_server="wgft server run"
fi
echo "== $mode: start the Go v1 server"
vps setsid nohup $run_server --mode "$mode" --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
  > "$SLOG" 2>&1 < /dev/null &
disown
wait_for 20 grep -q 'admin api' "$SLOG"
check "server up" "admin api" "$(grep -o 'admin api' "$SLOG" | head -1)"
# Targets in the LAN: 25570 reads to EOF and answers the SHA-256, 25571 sends the blob.
lan setsid nohup socat TCP-LISTEN:25570,bind=192.168.50.3,reuseaddr,fork SYSTEM:'sha256sum' >/dev/null 2>&1 < /dev/null &
disown
# Each connection gets its own cat: a FILE address opened once would be shared by the forked
# children and hand later connections an empty stream.
lan setsid nohup socat TCP-LISTEN:25571,bind=192.168.50.3,reuseaddr,fork SYSTEM:"cat $BLOB" >/dev/null 2>&1 < /dev/null &
disown

echo "== $mode: phase 1, the Rust agent enrolls itself"
join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
start_rust "$RDATA" "$RLOG" "$join"
wait_for 20 agent_row home
check "rust agent registered" "home" "$(agent_row home)"
check "rust agent sent its own key" "generated wg key pair" "$(grep -o 'generated wg key pair' "$RLOG")"
check "server selected protocol v1" "server selected protocol v1" "$(grep -o 'server selected protocol v1' "$RLOG")"
check "tun device carries the tunnel address" "10.200.0.2/" "$(ip netns exec "$HOME_NS" ip -4 -o addr show dev "$TUN" 2>&1)"
wait_for 40 handshake_ok home
check "wireguard handshake seen by the server" "True" "$(agent_field home 'bool(a["last_handshake"])')"
check "agent reports an ok tunnel" "ok" "$(agent_field home 'a["tunnel"]["state"] + " " + a["tunnel"].get("reason", "")')"
# The agent pings the server's tunnel address every keepalive, 25 s. A userspace server answers from
# its netstack. A kernel server drops new flows from wg0 in its nftables input chain, so the request
# reaches wgft0 and no reply comes back.
if [ "$mode" = kernel ]; then
  pings=$(vps timeout 60 tcpdump -lni wgft0 -c 1 'icmp[icmptype] == icmp-echo and src 10.200.0.2' 2>/dev/null | head -1)
  check "keepalive ping reaches the server's wgft0" "ICMP echo request" "$pings"
  # the agent waits 2 s for a reply before it logs the silence
  wait_for 10 grep -q 'does not answer pings' "$RLOG"
  check "kernel server leaves the ping unanswered" "does not answer pings" "$(grep -o 'does not answer pings' "$RLOG" | head -1)"
else
  wait_for 60 grep -q 'answers pings' "$RLOG"
  check "keepalive ping answered by the server" "answers pings" "$(grep -o 'answers pings' "$RLOG" | head -1)"
fi
vps wgft rule add --agent home --tcp 39981 --to 192.168.50.3:25570 --admin "$ADMIN" >/dev/null
vps wgft rule add --agent home --tcp 39982 --to 192.168.50.3:25571 --admin "$ADMIN" >/dev/null
wait_for 20 grep -q 'applied generation 2: ' "$RLOG"
wait_for 40 test "$(agent_field home 'len(a.get("rules") or [])')" = 2
check "agent reports both rules ok" "ok ok" "$(agent_field home '" ".join(r["state"] for r in a.get("rules") or [])')"
transfer "rust agent" 39981
check "agent.json written in the v1 shape" '"last_state"' "$(cat "$RDATA/agent.json")"
kill_named wgft-rs
check "tun device removed on stop" "does not exist" "$(ip netns exec "$HOME_NS" ip link show "$TUN" 2>&1)"

echo "== $mode: phase 2, the Go v1 agent still works against the same server"
join=$(vps wgft agent join-string --name home2 --admin "$ADMIN" 2>/dev/null | head -1)
WGFT_JOIN="$join" ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$GDATA" > "$GLOG" 2>&1 < /dev/null &
disown
wait_for 20 agent_row home2
vps wgft rule add --agent home2 --tcp 39991 --to 192.168.50.3:25570 --admin "$ADMIN" >/dev/null
vps wgft rule add --agent home2 --tcp 39992 --to 192.168.50.3:25571 --admin "$ADMIN" >/dev/null
wait_for 40 handshake_ok home2
transfer "go agent" 39991
kill_go_agent

echo "== $mode: phase 3, the Rust agent starts from the Go agent's agent.json"
before=$(cat "$GDATA/agent.json")
start_rust "$GDATA" "$R2LOG"
wait_for 20 grep -q 'stream: connected' "$R2LOG"
check "no new registration" "name home2, mode userspace" "$(grep -o 'name home2, mode userspace' "$R2LOG")"
wait_for 40 handshake_ok home2
check "handshake with the Go agent's key" "ok" "$(agent_field home2 'a["tunnel"]["state"]')"
check "same public key as the Go agent" "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["wg_private_key"][:8])' <(echo "$before"))" \
  "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["wg_private_key"][:8])' "$GDATA/agent.json")"
transfer "rust agent on go credentials" 39991
kill_named wgft-rs

echo "== $mode: phase 4, the Go v1 agent starts from the agent.json the Rust agent wrote"
ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$RDATA" > "$G2LOG" 2>&1 < /dev/null &
disown
wait_for 20 grep -q 'stream: connected' "$G2LOG"
check "go agent reads the rust agent.json" "name home, mode userspace" "$(grep -o 'name home, mode userspace' "$G2LOG")"
wait_for 40 handshake_ok home
transfer "go agent on rust credentials" 39981
kill_go_agent

echo "== $mode: teardown"
for p in $(sandbox_wgft_pids); do
  tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q ' server run' && kill "$p"
done
sleep 1
for f in "$RLOG" "$R2LOG"; do
  if grep -q panicked "$f"; then echo "FAIL  $f has a panic"; fail=1; fi
done
cleanup
if [ "$fail" = 0 ]; then echo "== $mode: ALL PASS"; else echo "== $mode: FAILURES (logs in $W/wgft-rs-$mode-*.log)"; fi
exit "$fail"
