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
# pseudo-random stream from the LAN host; once it has read OUTAGE_AFTER bytes the path drops
# everything for OUTAGE_S seconds. A fixed size, not a fixed sending time, keeps the modes
# comparable: a userspace-mode agent's relay reads ahead of the client into its buffers. Each mode
# runs RUNS times with the same server, agent and rule.
#
# Per run it prints the transfer's duration and throughput, the throughput before the outage and
# after recovery, the recovery time from the end of the outage to the first byte after it, the
# stall across the outage, the longest gap between reads outside the outage, and whether the
# SHA-256 of what the client read matches what the LAN host sent. A run without reads on both
# sides of the outage is UNDETERMINED. Per mode it then prints the medians. Only the hash is
# asserted on: the numbers are measurements, for a person to compare. Run it alone in the VM.
#
# NETEM_SEED fixes netem's loss pattern where tc and the kernel accept netem's seed option; where
# they do not, the script says so and the loss differs from run to run.
#
# Requires `lab/lab build` and the netns topology (`lab/lab net up`).
set -u
MODES=${*:-kernel userspace}
DELAY_MS=${DELAY_MS:-25}
LOSS_PCT=${LOSS_PCT:-1}
BYTES=${BYTES:-8388608}
OUTAGE_AFTER=${OUTAGE_AFTER:-2097152}
OUTAGE_S=${OUTAGE_S:-2}
RUNS=${RUNS:-3}
NETEM_SEED=${NETEM_SEED:-}

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
served() { [ "$(grep -c sha256 "$W/wgft-tq-serve-$1.log")" -ge "$2" ]; } # served <mode> <runs>
rule_ok() { [ "$(ip netns exec "$CLIENT_NS" bash -c 'echo ping | timeout 3 socat -t 2 - TCP:198.51.100.1:41800' 2>/dev/null)" = pong ]; }
netem() { # netem <netem args...>: the same qdisc on both ends of the vps-homerouter link
  vps tc qdisc replace dev pub1 root netem "$@" "${SEED_ARGS[@]}"
  router tc qdisc replace dev wan0 root netem "$@" "${SEED_ARGS[@]}"
}
SEED_ARGS=()
if [ -n "$NETEM_SEED" ]; then
  if vps tc qdisc replace dev pub1 root netem loss 1% seed "$NETEM_SEED" 2>/dev/null; then
    SEED_ARGS=(seed "$NETEM_SEED")
    echo "netem seed: $NETEM_SEED"
  else
    echo "netem seed: not supported by this tc or kernel; the loss pattern differs from run to run"
  fi
  vps tc qdisc del dev pub1 root 2>/dev/null
fi
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
  echo "== agent $mode: delay ${DELAY_MS}ms and loss ${LOSS_PCT}% each way, ${BYTES}-byte download, ${OUTAGE_S}s outage after ${OUTAGE_AFTER} bytes, $RUNS runs"
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
  : > "$W/wgft-tq-serve-$mode.log"
  ip netns exec "$LAN_NS" setsid nohup $Q serve 192.168.50.3 25800 "$BYTES" 7 > "$W/wgft-tq-serve-$mode.log" 2>&1 < /dev/null &
  disown
  vps wgft rule add --agent home --tcp 41800 --to "$TARGET" --admin "$ADMIN" >/dev/null
  wait_until 30 rule_ok || { echo "FAIL  the rule does not forward"; fail=1; continue; }

  results=$W/wgft-tq-results-$mode
  : > "$results"
  for run in $(seq 1 "$RUNS"); do
    mark=$W/wgft-tq-mark-$mode
    rm -f "$mark"
    netem delay "${DELAY_MS}ms" loss "${LOSS_PCT}%"
    ip netns exec "$CLIENT_NS" $Q fetch 198.51.100.1 41800 "$W/wgft-tq-samples-$mode" "$OUTAGE_AFTER" "$mark" \
      > "$W/wgft-tq-fetch-$mode.log" 2>&1 &
    fetcher=$!
    if wait_until 120 test -e "$mark"; then
      out_start=$(date +%s.%N)
      netem delay "${DELAY_MS}ms" loss 100%
      sleep "$OUTAGE_S"
      netem delay "${DELAY_MS}ms" loss "${LOSS_PCT}%"
      out_end=$(date +%s.%N)
    else
      out_start=0 out_end=0
    fi
    wait "$fetcher"
    netem delay 0ms

    got=$(tail -1 "$W/wgft-tq-fetch-$mode.log")
    wait_until 10 served "$mode" "$run"
    sent=$(grep sha256 "$W/wgft-tq-serve-$mode.log" | sed -n "${run}p")
    stats=$($Q analyze "$W/wgft-tq-samples-$mode" "$out_start" "$out_end")
    echo "   run $run sent:     $sent"
    echo "   run $run received: $got"
    if [ -n "$(field sha256 "$got")" ] && [ "$(field sha256 "$got")" = "$(field sha256 "$sent")" ] && [ "$(field received "$got")" = "$(field sent "$sent")" ]; then
      echo "PASS  agent $mode run $run: the client read exactly the stream the LAN host sent"
    else
      echo "FAIL  agent $mode run $run: the stream differs"; fail=1
    fi
    if [ "$(field undetermined "$stats")" = 1 ]; then
      echo "UNDETERMINED  agent $mode run $run: no reads on both sides of the outage; $stats"
    fi
    echo "RESULT mode=$mode run=$run delay_ms=$DELAY_MS loss_pct=$LOSS_PCT $stats bytes=$(field received "$got")"
    echo "$stats" >> "$results"
  done
  echo "MEDIAN mode=$mode $($Q median "$results")"
done
exit "$fail"
