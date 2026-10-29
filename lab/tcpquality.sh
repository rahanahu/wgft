#!/usr/bin/env bash
# tcpquality.sh measures TCP quality through a rule over an impaired path, for the agent modes
# given, with the server in kernel mode, which only DNATs and masquerades:
#
#   lab/lab exec vm bash /wgft/lab/tcpquality.sh                    # kernel, then userspace
#   lab/lab exec vm bash /wgft/lab/tcpquality.sh userspace
#
# With a kernel-mode agent the client's TCP ends at the LAN host's kernel; with a userspace-mode
# agent it ends at the agent's gVisor netstack, which relays to the LAN host. The path between the
# vps and homerouter namespaces, which carries the WireGuard packets, gets netem on both
# directions: DELAY_MS each way and LOSS_PCT random loss each way. The client downloads BYTES of a
# pseudo-random stream from the LAN host; from OUTAGE_AT seconds into the transfer the path drops
# everything for OUTAGE_S seconds. A fixed size, not a fixed sending time, keeps the modes
# comparable: a userspace-mode agent's relay reads ahead of the client into its buffers.
#
# Per mode it prints the transfer's duration, the throughput before the outage and after recovery,
# the recovery time, the longest gap between reads, and whether the SHA-256 of what the client
# read matches what the LAN host sent. Only the hash is asserted on: the numbers are
# measurements, for a person to compare. Run it alone in the VM.
#
# Requires `lab/lab build` and the netns topology (`lab/lab net up`).
set -u
MODES=${*:-kernel userspace}
DELAY_MS=${DELAY_MS:-25}
LOSS_PCT=${LOSS_PCT:-1}
BYTES=${BYTES:-8388608}
OUTAGE_AT=${OUTAGE_AT:-8}
OUTAGE_S=${OUTAGE_S:-2}

. "$(dirname "$0")/sandbox.sh"
Q="python3 $(cd "$(dirname "$0")" && pwd)/tcpquality.py"
ADMIN=127.0.0.1:8686
DATA=$W/wgft-tq-server
ADATA=$W/wgft-tq-agent
TARGET=192.168.50.3:25800
fail=0

vps() { ip netns exec "$VPS_NS" "$@"; }
router() { ip netns exec "$ROUTER_NS" "$@"; }
wait_until() {
  local deadline=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    (( SECONDS >= deadline )) && return 1
    sleep 0.2
  done
}
field() { echo "$2" | grep -oE "(^| )$1=[^ ]*" | head -1 | cut -d= -f2; }
handshaken() {
  vps wgft agent ls --admin "$ADMIN" --json 2>/dev/null | python3 -c "
import json, sys
sys.exit(0 if any(a.get('name') == 'home' and a.get('last_handshake') for a in json.load(sys.stdin)) else 1)"
}
rule_ok() { [ "$(ip netns exec "$CLIENT_NS" bash -c 'echo ping | timeout 3 socat -t 2 - TCP:198.51.100.1:41800' 2>/dev/null)" = pong ]; }
netem() { # netem <netem args...>: the same qdisc on both ends of the vps-homerouter link
  vps tc qdisc replace dev pub1 root netem "$@"
  router tc qdisc replace dev wan0 root netem "$@"
}
cleanup() {
  sandbox_kill_named wgft
  sandbox_kill_cmdline '/tcpquality.py '
  sleep 1
  vps tc qdisc del dev pub1 root 2>/dev/null
  router tc qdisc del dev wan0 root 2>/dev/null
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  ip netns exec "$HOME_NS" ip link del wgft0 2>/dev/null
  ip netns exec "$HOME_NS" nft delete table inet wgft_agent 2>/dev/null
  rm -rf "$DATA" "$ADATA"
}
trap cleanup EXIT

for mode in $MODES; do
  case "$mode" in kernel|userspace) ;; *) echo "usage: tcpquality.sh [kernel|userspace]..." >&2; exit 2;; esac
  echo "== agent $mode: delay ${DELAY_MS}ms and loss ${LOSS_PCT}% each way, ${BYTES}-byte download, ${OUTAGE_S}s outage at ${OUTAGE_AT}s"
  cleanup
  mkdir -p "$DATA"
  vps setsid nohup wgft server run --mode kernel --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
    > "$W/wgft-tq-server-$mode.log" 2>&1 < /dev/null &
  disown
  wait_until 30 vps wgft agent ls --admin "$ADMIN" || { echo "FAIL  the server did not come up"; fail=1; continue; }
  join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_MODE=$mode WGFT_JOIN="$join" WGFT_AGENT_ALLOW_TARGETS=$TARGET \
    ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$ADATA" > "$W/wgft-tq-agent-$mode.log" 2>&1 < /dev/null &
  disown
  wait_until 30 handshaken || { echo "FAIL  the agent did not register"; fail=1; continue; }
  ip netns exec "$LAN_NS" setsid nohup $Q serve 192.168.50.3 25800 "$BYTES" 7 > "$W/wgft-tq-serve-$mode.log" 2>&1 < /dev/null &
  disown
  vps wgft rule add --agent home --tcp 41800 --to "$TARGET" --admin "$ADMIN" >/dev/null
  wait_until 30 rule_ok || { echo "FAIL  the rule does not forward"; fail=1; continue; }

  netem delay "${DELAY_MS}ms" loss "${LOSS_PCT}%"
  ip netns exec "$CLIENT_NS" $Q fetch 198.51.100.1 41800 "$W/wgft-tq-samples-$mode" > "$W/wgft-tq-fetch-$mode.log" 2>&1 &
  fetcher=$!
  sleep "$OUTAGE_AT"
  out_start=$(date +%s.%N)
  netem delay "${DELAY_MS}ms" loss 100%
  sleep "$OUTAGE_S"
  netem delay "${DELAY_MS}ms" loss "${LOSS_PCT}%"
  out_end=$(date +%s.%N)
  wait "$fetcher"
  netem delay 0ms

  got=$(tail -1 "$W/wgft-tq-fetch-$mode.log")
  wait_until 10 grep -q sha256 "$W/wgft-tq-serve-$mode.log"
  sent=$(tail -1 "$W/wgft-tq-serve-$mode.log")
  stats=$($Q analyze "$W/wgft-tq-samples-$mode" "$out_start" "$out_end")
  echo "   sent:     $sent"
  echo "   received: $got"
  echo "   $stats"
  if [ -n "$(field sha256 "$got")" ] && [ "$(field sha256 "$got")" = "$(field sha256 "$sent")" ] && [ "$(field received "$got")" = "$(field sent "$sent")" ]; then
    echo "PASS  agent $mode: the client read exactly the stream the LAN host sent"
  else
    echo "FAIL  agent $mode: the stream differs"; fail=1
  fi
  echo "RESULT mode=$mode delay_ms=$DELAY_MS loss_pct=$LOSS_PCT $stats bytes=$(field received "$got")"
done
exit "$fail"
