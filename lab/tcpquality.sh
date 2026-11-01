#!/usr/bin/env bash
# tcpquality.sh measures TCP quality through a rule over an impaired path, for the agent modes
# given, with the server in kernel mode, which only DNATs and masquerades:
#
#   lab/lab exec vm bash /wgft/lab/tcpquality.sh                    # kernel, then userspace
#   lab/lab exec vm bash /wgft/lab/tcpquality.sh userspace
#   lab/lab exec vm env CPU=1 bash /wgft/lab/tcpquality.sh gvisor wgstack
#
# The modes are kernel, userspace, which leaves WGFT_AGENT_NETSTACK unset, and gvisor and wgstack,
# which run the Go agent in userspace mode with WGFT_AGENT_NETSTACK set to that name; all four run
# the Go wgft on PATH. rust runs the Rust agent, which has one netstack, its own wgstack: the
# binary `lab/lab build` installs when WGFT_LAB_AGENT_IMPL=rust (RUST_WGFT in sandbox.sh). The
# server is always the Go wgft in kernel mode.
#
# WGFT_BIN_DIR, when set, runs another build: it is put first on PATH, so the server and a Go agent
# are its wgft, and the rust mode runs its rust/wgft. `lab/lab paired --base` uses it to run the
# build of a base commit beside the work tree's.
#
# With a kernel-mode agent the client's TCP ends at the LAN host's kernel; with a userspace-mode
# agent it ends at the agent's netstack, gVisor or wgstack, which relays to the LAN host. The path
# between the vps and homerouter namespaces, which carries the WireGuard packets, gets netem on both
# directions: DELAY_MS each way and LOSS_PCT random loss each way. The client downloads BYTES of a
# pseudo-random stream from the LAN host; once it has read OUTAGE_AFTER bytes the path drops
# everything for OUTAGE_S seconds. A fixed size, not a fixed sending time, keeps the modes
# comparable: a userspace-mode agent's relay reads ahead of the client into its buffers. Each mode
# runs RUNS times with the same server, agent and rule.
#
# DIRECTION=up reverses the transfer: the client uploads BYTES to the LAN host, the first 4 MiB + 1
# bytes of the stream repeated so that the client's own CPU stays low; the odd length divides no
# power-of-two buffer, so data shifted by a whole lap of one still fails the hash. The outage
# starts once the LAN host has read OUTAGE_AFTER bytes, and the times and the hash are the LAN
# host's reads, so the agent's netstack is the receiver. The default is down.
#
# Per run it prints the transfer's duration and throughput, the throughput before the outage and
# after recovery, the recovery time from the end of the outage to the first byte after it, the
# stall across the outage, the longest gap between reads outside the outage, and whether the
# SHA-256 of what the client read matches what the LAN host sent. A run without reads on both
# sides of the outage is UNDETERMINED. Per mode it then prints the medians. Only the hash is
# asserted on: the numbers are measurements, for a person to compare. Run it alone in the VM.
#
# RATE_MBIT, a whole number of Mbit/s, when set also limits each direction of that path to the
# rate, with a drop-tail queue of QUEUE_PKTS packets on top of the packets the delay holds.
# OUTAGE_S=0 runs without an outage; the per-run line then has the duration, throughput and longest
# gap only. With DELAY_MS=0, LOSS_PCT=0, no RATE_MBIT and OUTAGE_S=0 the path has no netem at all:
# the fast path, where the agent's CPU is the limit.
#
# CPU=1 adds the CPU time per transferred byte. Each process measured gets a cgroup of its own
# once it is running, and its CPU time is read from cpu.stat, to the microsecond, just before the
# client connects and just after the client exits, which is after the last byte has been read, so
# the agent's start-up is not counted; without cgroup v2 the script falls back to utime+stime from
# /proc/<pid>/stat, in clock ticks. The agent's seconds are divided by the bytes the receiver read
# and printed as seconds per GB, 10^9 bytes, beside its share of one CPU over the transfer. The
# server's process and the LAN host's end are measured the same way for context, and on an upload
# the client reports its own CPU time as client_cpu_share: a kernel-mode server only programs the
# kernel, whose WireGuard work is not in any process, and a sender near one CPU means the fast path
# measured the sender, not the agent.
#
# During the run the agent's eth0 has UDP segmentation offload off, so the router's netem queues
# and drops the datagrams one by one, as a real bottleneck does, and the agent pays for segmenting
# them; the reasons are at the code that turns it off.
#
# NETEM_SEED fixes netem's loss pattern where tc and the kernel accept netem's seed option; where
# they do not, the script says so and the loss differs from run to run.
#
# SYNC=1 lines each run up with a run in another VM, for `lab/lab paired`: before the client
# connects it prints "SYNC ready mode=<mode> run=<run>" and waits up to SYNC_WAIT_S seconds, 300 by
# default, for the file $W/wgft-tq-go-<mode>-<run>. The host writes into it a start time, in
# seconds since the epoch, a little ahead, and the run starts at that time by this VM's clock; the
# line "SYNC go" gives the wait, negative when the file came after the time. Without the file in
# time the run starts anyway, with a line "SYNC timeout". The result line then has sync=go, late
# (the wait was negative) or timeout; without SYNC it has sync=-. With CPU=1 the result line also
# has the run's window, t_start and t_end, by this VM's clock. Every result line has pass=1 when
# the run passed and pass=0 when it failed, so that an analysis can leave failed runs out.
#
# Requires `lab/lab build` and the netns topology (`lab/lab net up`).
set -u
MODES=${*:-kernel userspace}
DIRECTION=${DIRECTION:-down}
DELAY_MS=${DELAY_MS:-25}
LOSS_PCT=${LOSS_PCT:-1}
BYTES=${BYTES:-8388608}
OUTAGE_AFTER=${OUTAGE_AFTER:-2097152}
OUTAGE_S=${OUTAGE_S:-2}
RUNS=${RUNS:-3}
NETEM_SEED=${NETEM_SEED:-}
RATE_MBIT=${RATE_MBIT:-}
QUEUE_PKTS=${QUEUE_PKTS:-200}
CPU=${CPU:-}
SYNC=${SYNC:-}
SYNC_WAIT_S=${SYNC_WAIT_S:-300}
if [ -n "${WGFT_BIN_DIR:-}" ]; then
  PATH=$WGFT_BIN_DIR:$PATH
  export PATH
fi

. "$(dirname "$0")/sandbox.sh"
# the Rust agent of the rust mode: the one lab/lab build installs, or the one of WGFT_BIN_DIR's build
RUST_AGENT=${WGFT_BIN_DIR:+$WGFT_BIN_DIR/rust/wgft}
RUST_AGENT=${RUST_AGENT:-$RUST_WGFT}
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
# rule_ok reads the reply line and returns at once. socat after the end of its input waits out its
# -t time even when the reply has come, which spent 2 s on every successful probe; timeout 3 bounds
# a probe that gets no reply.
rule_ok() { [ "$(ip netns exec "$CLIENT_NS" timeout 3 bash -c 'exec 3<>/dev/tcp/198.51.100.1/41800 && echo ping >&3 && IFS= read -r l <&3 && echo "$l"' 2>/dev/null)" = pong ]; }
netem() { # netem <netem args...>: the same qdisc on both ends of the vps-homerouter link
  vps tc qdisc replace dev pub1 root netem "$@" "${RATE_ARGS[@]}" "${SEED_ARGS[@]}"
  router tc qdisc replace dev wan0 root netem "$@" "${RATE_ARGS[@]}" "${SEED_ARGS[@]}"
}
impair() { # the run's path: netem with the delay, loss and rate, or no qdisc on the fast path
  if [ "$DELAY_MS" = 0 ] && [ "$LOSS_PCT" = 0 ] && [ -z "$RATE_MBIT" ]; then
    vps tc qdisc del dev pub1 root 2>/dev/null
    router tc qdisc del dev wan0 root 2>/dev/null
    return 0
  fi
  netem delay "${DELAY_MS}ms" loss "${LOSS_PCT}%"
}
RATE_ARGS=()
if [ -n "$RATE_MBIT" ]; then
  # netem's limit counts the packets the delay holds too: about rate x delay / 1500 bytes of them
  RATE_ARGS=(rate "${RATE_MBIT}mbit" limit $((QUEUE_PKTS + (RATE_MBIT * 1000 * DELAY_MS + 11999) / 12000)))
fi
# ns_pid <netns> <command-line substring>: the first process in the namespace whose command line has it
ns_pid() {
  local p
  for p in $(ip netns pids "$1" 2>/dev/null); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q -- "$2" && { echo "$p"; return 0; }
  done
  return 1
}
CG_ROOT=/sys/fs/cgroup/wgft-tq${SANDBOX:+-$SANDBOX}
CLK_TCK=$(getconf CLK_TCK)
cg_own() { # cg_own <name> <pid>: move the process into a cgroup of its own; prints its directory
  [ -n "$2" ] && [ -e /sys/fs/cgroup/cgroup.controllers ] || return 0
  mkdir -p "$CG_ROOT-$1" 2>/dev/null && echo "$2" > "$CG_ROOT-$1/cgroup.procs" 2>/dev/null && echo "$CG_ROOT-$1"
}
cpu_us() { # cpu_us <pid> <cgroup directory or empty>: the process's CPU time so far, in microseconds
  if [ -n "$2" ]; then
    awk '$1 == "usage_usec" { print $2 }' "$2/cpu.stat"
  elif [ -n "$1" ]; then
    sed 's/.*) //' "/proc/$1/stat" 2>/dev/null | awk -v hz="$CLK_TCK" '{ printf "%d\n", ($12 + $13) * 1000000 / hz }'
  fi
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
tq_pids() { # the tcpquality.py processes of this sandbox
  local p
  if [ -z "$SANDBOX" ]; then pgrep -f -- '/tcpquality.py '; return 0; fi
  for p in $(sandbox_pids); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q -- '/tcpquality.py ' && echo "$p"
  done
  return 0
}
none_running() { ! sandbox_any_named wgft && [ -z "$(tq_pids)" ]; }
cleanup() {
  sandbox_kill_named wgft
  sandbox_kill_cmdline '/tcpquality.py '
  # the teardown below and the next mode's start want the killed processes gone, which takes well
  # under a second; 10 s bounds a process that does not stop
  wait_until 10 none_running
  vps tc qdisc del dev pub1 root 2>/dev/null
  router tc qdisc del dev wan0 root 2>/dev/null
  rmdir "$CG_ROOT"-* 2>/dev/null
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  ip netns exec "$HOME_NS" ip link del wgft0 2>/dev/null
  ip netns exec "$HOME_NS" nft delete table inet wgft_agent 2>/dev/null
  rm -rf "$DATA" "$ADATA"
}
trap cleanup EXIT

for mode in $MODES; do
  case "$mode" in kernel|userspace|gvisor|wgstack|rust) ;; *) echo "usage: tcpquality.sh [kernel|userspace|gvisor|wgstack|rust]..." >&2; exit 2;; esac
  if [ "$mode" = rust ] && [ ! -x "$RUST_AGENT" ]; then
    echo "tcpquality.sh: the rust mode needs the Rust agent at $RUST_AGENT; build it with WGFT_LAB_AGENT_IMPL=rust lab/lab build" >&2
    exit 2
  fi
done
case "$DIRECTION" in
  down) transfer=download reader="the client" writer="the LAN host" dir_field= ;;
  up) transfer=upload reader="the LAN host" writer="the client" dir_field="direction=up " ;;
  *) echo "tcpquality.sh: DIRECTION is down or up" >&2; exit 2 ;;
esac
# The agent's UDP segmentation offload is off on every path, for two reasons:
# - netem: wireguard-go's Linux bind sends a run of same-sized datagrams as one UDP GSO packet, and
#   the agent's veth hands it whole to the router. netem counts it as one packet against the queue,
#   releases all its datagrams together after the whole run's transmission time, and decides loss
#   for the packet as a whole, so up to 64 datagrams are delayed or lost together. A real link
#   carries the datagrams one by one, so no bottleneck past it does that.
# - CPU: without netem the GSO packet would cross the veth and the router namespace whole and never
#   be segmented, while every real host without UDP segmentation offload pays for that. With the
#   offload off, the agent's kernel segments the datagrams before they leave the namespace, as on a
#   host whose NIC lacks the offload: the conservative case. A host with the offload lies between
#   the two. Whether the router namespace's forwarding is counted in the agent's cgroup is not
#   verified.
# The trap that restores the starting state is set before the change, so a partial change is undone
# too; a failed restore makes the run fail. The helper reads the state back and fails loudly if the
# offload stays on.
gso_was=$(ip netns exec "$HOME_NS" $Q udpgso eth0 show | grep -o 'requested=[a-z]*' | cut -d= -f2)
if [ "$gso_was" != on ]; then
  echo "WARN  UDP segmentation offload on the agent's eth0 is ${gso_was:-unreadable} at the start; it is not turned back on at exit"
fi
restore_gso() {
  [ "$gso_was" = on ] || return 0
  ip netns exec "$HOME_NS" $Q udpgso eth0 on >/dev/null && return 0
  echo "FAIL  cannot turn UDP segmentation offload back on on the agent's eth0"
  return 1
}
on_exit() {
  local rc=$?
  cleanup
  restore_gso || rc=1
  exit "$rc"
}
trap on_exit EXIT
gso_now=$(ip netns exec "$HOME_NS" $Q udpgso eth0 off) ||
  { echo "FAIL  cannot turn off UDP segmentation offload on the agent's eth0: $gso_now"; exit 1; }
echo "   agent eth0: $gso_now"
for mode in $MODES; do
  agent_env=(-u WGFT_AGENT_NETSTACK WGFT_MODE="$mode")
  case "$mode" in
    gvisor|wgstack) agent_env=(WGFT_MODE=userspace WGFT_AGENT_NETSTACK="$mode") ;;
    rust) agent_env=(-u WGFT_AGENT_NETSTACK WGFT_MODE=userspace) ;;
  esac
  if [ "$OUTAGE_S" = 0 ]; then outage="no outage"; else outage="${OUTAGE_S}s outage after ${OUTAGE_AFTER} bytes"; fi
  path="delay ${DELAY_MS}ms and loss ${LOSS_PCT}%${RATE_MBIT:+ at ${RATE_MBIT} Mbit/s with a ${QUEUE_PKTS}-packet queue}"
  echo "== agent $mode: $path each way, ${BYTES}-byte $transfer, $outage, $RUNS runs"
  cleanup
  mkdir -p "$DATA"
  vps setsid nohup wgft server run --mode kernel --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
    > "$W/wgft-tq-server-$mode.log" 2>&1 < /dev/null &
  disown
  wait_until 30 vps wgft agent ls --admin "$ADMIN" || { echo "FAIL  the server did not come up"; fail=1; continue; }
  join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  if [ "$mode" = rust ]; then
    env "${agent_env[@]}" WGFT_JOIN="$join" "WGFT_AGENT_ALLOW_TARGETS=$TARGET" \
      ip netns exec "$HOME_NS" setsid nohup "$RUST_AGENT" agent run --data-dir "$ADATA" > "$W/wgft-tq-agent-$mode.log" 2>&1 < /dev/null &
  else
    env "${agent_env[@]}" WGFT_JOIN="$join" "WGFT_AGENT_ALLOW_TARGETS=$TARGET" \
      ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$ADATA" > "$W/wgft-tq-agent-$mode.log" 2>&1 < /dev/null &  # lab: go agent
  fi
  disown
  wait_until 30 handshaken || { echo "FAIL  the agent did not register"; fail=1; continue; }
  : > "$W/wgft-tq-serve-$mode.log"
  ip netns exec "$LAN_NS" setsid nohup $Q serve 192.168.50.3 25800 "$BYTES" 7 > "$W/wgft-tq-serve-$mode.log" 2>&1 < /dev/null &
  disown
  vps wgft rule add --agent home --tcp 41800 --to "$TARGET" --admin "$ADMIN" >/dev/null
  wait_until 30 rule_ok || { echo "FAIL  the rule does not forward"; fail=1; continue; }
  if [ -n "$CPU" ]; then
    agent_pid=$(ns_pid "$HOME_NS" "agent run --data-dir $ADATA")
    server_pid=$(ns_pid "$VPS_NS" "server run --mode kernel --data-dir $DATA")
    lan_pid=$(ns_pid "$LAN_NS" "tcpquality.py serve")
    agent_cg=$(cg_own agent "$agent_pid") server_cg=$(cg_own server "$server_pid") lan_cg=$(cg_own lan "$lan_pid")
    if [ -z "$agent_pid" ]; then
      echo "FAIL  agent $mode: no agent process found, so its CPU time is not measured"; fail=1
    elif [ -n "$agent_cg" ]; then
      echo "   cpu time from cgroup cpu.stat"
    else
      echo "   cpu time from /proc/<pid>/stat in 1/${CLK_TCK} s ticks"
    fi
  fi

  results=$W/wgft-tq-results-$mode
  : > "$results"
  for run in $(seq 1 "$RUNS"); do
    mark=$W/wgft-tq-mark-$mode
    rm -f "$mark" "$W/wgft-tq-samples-$mode"
    impair
    run_pass=1 sync_state=-
    if [ -n "$SYNC" ]; then
      go=$W/wgft-tq-go-$mode-$run
      rm -f "$go"
      echo "SYNC ready mode=$mode run=$run"
      if wait_until "$SYNC_WAIT_S" test -s "$go"; then
        wait_s=$(awk -v t="$(cat "$go")" -v n="$(date +%s.%N)" 'BEGIN { printf "%.3f", t - n }')
        case "$wait_s" in -*) sync_state=late ;; *) sync_state=go; sleep "$wait_s" ;; esac
        echo "SYNC go mode=$mode run=$run wait_s=$wait_s"
      else
        sync_state=timeout
        echo "SYNC timeout mode=$mode run=$run"
      fi
      rm -f "$go"
    fi
    if [ -n "$CPU" ]; then
      t0=$(date +%s.%N) a0=$(cpu_us "$agent_pid" "$agent_cg") s0=$(cpu_us "$server_pid" "$server_cg") l0=$(cpu_us "$lan_pid" "$lan_cg")
    fi
    if [ "$DIRECTION" = up ]; then
      ip netns exec "$CLIENT_NS" $Q push 198.51.100.1 41800 "$BYTES" 7 "$W/wgft-tq-samples-$mode" "$OUTAGE_AFTER" "$mark" \
        > "$W/wgft-tq-fetch-$mode.log" 2>&1 &
    else
      ip netns exec "$CLIENT_NS" $Q fetch 198.51.100.1 41800 "$W/wgft-tq-samples-$mode" "$OUTAGE_AFTER" "$mark" \
        > "$W/wgft-tq-fetch-$mode.log" 2>&1 &
    fi
    fetcher=$!
    if [ "$OUTAGE_S" = 0 ]; then
      out_start=- out_end=-
    elif wait_until 120 test -e "$mark"; then
      out_start=$(date +%s.%N)
      netem delay "${DELAY_MS}ms" loss 100%
      sleep "$OUTAGE_S"
      netem delay "${DELAY_MS}ms" loss "${LOSS_PCT}%"
      out_end=$(date +%s.%N)
    else
      out_start=0 out_end=0
    fi
    wait "$fetcher"
    if [ -n "$CPU" ]; then
      t1=$(date +%s.%N) a1=$(cpu_us "$agent_pid" "$agent_cg") s1=$(cpu_us "$server_pid" "$server_cg") l1=$(cpu_us "$lan_pid" "$lan_cg")
    fi
    netem delay 0ms

    got=$(tail -1 "$W/wgft-tq-fetch-$mode.log")
    wait_until 10 served "$mode" "$run"
    sent=$(grep sha256 "$W/wgft-tq-serve-$mode.log" | sed -n "${run}p")
    if [ "$DIRECTION" = up ]; then swap=$got; got=$sent; sent=$swap; fi
    stats=$($Q analyze "$W/wgft-tq-samples-$mode" "$out_start" "$out_end")
    if [ -n "$CPU" ] && [ -n "$agent_pid" ] && { [ -z "$a0" ] || [ -z "$a1" ] || [ "$a1" -lt "$a0" ]; }; then
      echo "FAIL  agent $mode run $run: the agent's CPU time could not be read over the whole transfer"; fail=1 run_pass=0
    elif [ -n "$CPU" ] && [ -n "$agent_pid" ]; then
      stats="$stats $(awk -v t0="$t0" -v t1="$t1" -v n="$(field received "$got")" -v c="$(field cpu_s "$sent")" \
        -v a="$((${a1:-0} - ${a0:-0}))" -v s="$((${s1:-0} - ${s0:-0}))" -v l="$((${l1:-0} - ${l0:-0}))" 'BEGIN {
          t = t1 - t0
          printf "t_start=%.3f t_end=%.3f window_s=%.3f agent_cpu_s=%.3f agent_cpu_s_per_gb=%.3f agent_cpu_share=%.3f server_cpu_s=%.3f lan_cpu_share=%.3f",
            t0, t1, t, a / 1e6, (n > 0 ? a / 1e6 / (n / 1e9) : -1), a / 1e6 / t, s / 1e6, l / 1e6 / t
          if (c != "") printf " client_cpu_share=%.3f", c / t }')"
    fi
    echo "   run $run sent:     $sent"
    echo "   run $run received: $got"
    if [ -n "$(field sha256 "$got")" ] && [ "$(field sha256 "$got")" = "$(field sha256 "$sent")" ] && [ "$(field received "$got")" = "$(field sent "$sent")" ]; then
      echo "PASS  agent $mode run $run: $reader read exactly the stream $writer sent"
    else
      echo "FAIL  agent $mode run $run: the stream differs"; fail=1 run_pass=0
    fi
    if [ "$(field undetermined "$stats")" = 1 ]; then
      echo "UNDETERMINED  agent $mode run $run: no reads on both sides of the outage; $stats"
    fi
    echo "RESULT mode=$mode run=$run ${dir_field}delay_ms=$DELAY_MS loss_pct=$LOSS_PCT ${RATE_MBIT:+rate_mbit=$RATE_MBIT }$stats bytes=$(field received "$got") pass=$run_pass sync=$sync_state"
    echo "$stats" >> "$results"
  done
  echo "MEDIAN mode=$mode $($Q median "$results")"
done
exit "$fail"
