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
# them; the reasons are at the code that turns it off. AGENT_GSO=on leaves it on instead, on the
# fast path only: a sender's UDP GSO packet then crosses the veth and the router whole, as on a
# host whose NIC segments, and the comparison of two modes must use the same setting.
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
# TOOL=iperf3 moves data with iperf3 instead of tcpquality.py: the LAN host runs the iperf3
# server, and the client runs `iperf3 -t IPERF_S -P STREAMS`, with -R on a download, for IPERF_S
# seconds, 10 by default, instead of BYTES. iperf3 3.18 notices the end of a test sized in bytes
# only at its one-second report tick, which rounded every run up to whole seconds in a trial, so the
# run has a fixed time; and two modes measured at once in `lab/lab paired` then run for the same
# time whatever their speeds. The result line has the bytes the receiving iperf3 read and its rate
# over its own duration. STREAMS, 1 by default, is the number of parallel TCP connections and needs
# TOOL=iperf3 when above 1. iperf3 sends one buffer again and again and checks nothing, so it costs
# the sender and the receiver far less CPU per byte than tcpquality.py, which matters on the fast
# path at kernel speeds; there is no hash and no outage, so TOOL=iperf3 wants OUTAGE_S=0, and a run
# passes when iperf3 exits 0 and the receiver read data.
#
# IPERF_MBIT caps each iperf3 stream at that many Mbit/s (iperf3 -b); unset, iperf3 sends as fast as
# the path takes. A capped transfer leaves the agent below its limit, so that a latency comparison
# sees the same offered load in both modes instead of each mode's own standing queue.
#
# UDPPING=1, with TOOL=iperf3, also measures the round-trip time of small UDP datagrams through a
# UDP rule of the same agent, the path a game's traffic takes: the LAN host runs tcpquality.py's
# UDP echo on 192.168.50.3:25801, the server forwards UDP 41801 to it, and the client sends a
# 100-byte datagram every UDPPING_MS, 10 by default. Each run first pings alone for UDPPING_IDLE_S
# seconds, 5 by default, after the start barrier and before the CPU window, and then pings while the
# bulk transfer runs, from half a second after it starts for IPERF_S - 1 seconds. The result line
# gets udp_idle_* and udp_load_*: sent, lost, the median, the 99th percentile and the maximum of the
# round-trip time in ms, and the jitter, the mean absolute difference between consecutive round
# trips. The datagrams of the load phase cross the agent while the agent is busiest, so they add a
# little to its CPU time per byte, the same for every mode. `tcpquality.py latpaired` compares two
# modes measured so by `lab/lab paired`. UDPPING=0 or unset turns it off. The UDP target is always
# in the agent's allowlist, so that the agent's configuration does not depend on UDPPING.
#
# KERNEL_RMEM_MAX, a whole number of bytes, lowers the receiving end's TCP receive buffer maximum, the
# third value of net.ipv4.tcp_rmem in the namespace of the process that reads (the LAN host on an
# upload, the client on a download), for the kernel mode only; the other modes run with the
# namespace's own value. The receive buffer autotuning of the kernel's TCP then advertises no more
# than that buffer allows, which is how the receive-window stage of
# docs/design/v2/agent-throughput.md sets the kernel mode it compares with. The default value of
# tcp_rmem is lowered to the maximum when it is above it, and both are put back after the mode and at
# exit. The result line then has rcv_rmem_max.
#
# With CPU=1 the result line also has the whole VM's CPU time per byte, vm_cpu_s_per_gb, and the
# number of CPUs busy over the transfer, vm_cpu_share, from the busy times in /proc/stat: user,
# nice, system, irq and softirq. Kernel work that runs in no process of the agent, such as kernel
# WireGuard's encryption, the forwarding between the namespaces and softirq time charged to another
# process, is counted only there. All five namespaces share the VM, so the value includes the
# client, the LAN host, the server and the router; between two modes on the same path only the
# agent's side differs. sender_cpu_share and receiver_cpu_share name the process that sent and the
# one that read, and with TOOL=iperf3 the client's CPU is read from a cgroup of its own.
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
TOOL=${TOOL:-tcpquality}
AGENT_GSO=${AGENT_GSO:-off}
IPERF_S=${IPERF_S:-10}
IPERF_MBIT=${IPERF_MBIT:-}
UDPPING=${UDPPING:-}
UDPPING_MS=${UDPPING_MS:-10}
UDPPING_IDLE_S=${UDPPING_IDLE_S:-5}
STREAMS=${STREAMS:-1}
KERNEL_RMEM_MAX=${KERNEL_RMEM_MAX:-}
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
UDP_TARGET=192.168.50.3:25801
ALLOW=$TARGET,$UDP_TARGET
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
# udp_or_lost <prefix> <seconds> <pinger line>: the pinger's line, or, when it printed none (it
# failed or was killed), every datagram it was to send counted as sent and lost, so that totals
# do not drop the run; such a line has no p99, and the analysis counts the run as failed
udp_or_lost() {
  case "$3" in
    *"$1_sent="*) echo "$3" ;;
    *) local n; n=$(awk -v s="$2" -v ms="$UDPPING_MS" 'BEGIN { printf "%d", s * 1000 / ms }')
       echo "$1_sent=$n $1_lost=$n" ;;
  esac
}
vm_cpu_us() { # the VM's busy CPU time so far over all CPUs, in microseconds: user, nice, system, irq, softirq
  awk -v hz="$CLK_TCK" '$1 == "cpu" { printf "%d\n", ($2 + $3 + $4 + $7 + $8) * 1000000 / hz; exit }' /proc/stat
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
none_running() { ! sandbox_any_named wgft iperf3 && [ -z "$(tq_pids)" ]; }
cleanup() {
  sandbox_kill_named wgft iperf3
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
case "$TOOL" in
  tcpquality) [ "$STREAMS" = 1 ] || { echo "tcpquality.sh: STREAMS above 1 needs TOOL=iperf3" >&2; exit 2; } ;;
  iperf3) [ "$OUTAGE_S" = 0 ] || { echo "tcpquality.sh: TOOL=iperf3 needs OUTAGE_S=0" >&2; exit 2; } ;;
  *) echo "tcpquality.sh: TOOL is tcpquality or iperf3" >&2; exit 2 ;;
esac
case "$AGENT_GSO" in
  off) ;;
  on) [ "$DELAY_MS" = 0 ] && [ "$LOSS_PCT" = 0 ] && [ -z "$RATE_MBIT" ] ||
    { echo "tcpquality.sh: AGENT_GSO=on is for the fast path only, where no netem queues the datagrams" >&2; exit 2; } ;;
  *) echo "tcpquality.sh: AGENT_GSO is off or on" >&2; exit 2 ;;
esac
case "$UDPPING" in
  1) [ "$TOOL" = iperf3 ] || { echo "tcpquality.sh: UDPPING=1 needs TOOL=iperf3" >&2; exit 2; } ;;
  ''|0) UDPPING= ;;
  *) echo "tcpquality.sh: UDPPING is 1 or 0" >&2; exit 2 ;;
esac
case "$IPERF_MBIT" in
  '') ;;
  *[!0-9]*|0) echo "tcpquality.sh: IPERF_MBIT is a whole number of Mbit/s of 1 or more" >&2; exit 2 ;;
  *) [ "$TOOL" = iperf3 ] || { echo "tcpquality.sh: IPERF_MBIT needs TOOL=iperf3" >&2; exit 2; } ;;
esac
case "$STREAMS" in ''|*[!0-9]*|0) echo "tcpquality.sh: STREAMS is a whole number of 1 or more" >&2; exit 2 ;; esac
case "$KERNEL_RMEM_MAX" in
  '') ;;
  *[!0-9]*) echo "tcpquality.sh: KERNEL_RMEM_MAX is a whole number of bytes" >&2; exit 2 ;;
  *) [ "$KERNEL_RMEM_MAX" -ge 4096 ] || { echo "tcpquality.sh: KERNEL_RMEM_MAX is at least 4096 bytes" >&2; exit 2; } ;;
esac
case "$DIRECTION" in
  down) transfer=download reader="the client" writer="the LAN host" dir_field= READER_NS=$CLIENT_NS ;;
  up) transfer=upload reader="the LAN host" writer="the client" dir_field="direction=up " READER_NS=$LAN_NS ;;
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
# the reader's tcp_rmem for KERNEL_RMEM_MAX: read once, lowered for the kernel mode, put back after it
rmem_was=$(ip netns exec "$READER_NS" sysctl -n net.ipv4.tcp_rmem | tr -s ' \t' '  ')
rmem_set=
set_rmem() { # set_rmem <min default max>
  ip netns exec "$READER_NS" sysctl -qw net.ipv4.tcp_rmem="$*" &&
    [ "$(ip netns exec "$READER_NS" sysctl -n net.ipv4.tcp_rmem | tr -s ' \t' '  ')" = "$*" ]
}
restore_rmem() {
  [ -n "$rmem_set" ] || return 0
  set_rmem $rmem_was && { rmem_set=; return 0; }
  echo "FAIL  cannot put tcp_rmem back to $rmem_was in the $READER_NS namespace"
  return 1
}
on_exit() {
  local rc=$?
  cleanup
  restore_gso || rc=1
  restore_rmem || rc=1
  exit "$rc"
}
trap on_exit EXIT
gso_now=$(ip netns exec "$HOME_NS" $Q udpgso eth0 "$AGENT_GSO") ||
  { echo "FAIL  cannot turn $AGENT_GSO UDP segmentation offload on the agent's eth0: $gso_now"; exit 1; }
echo "   agent eth0: $gso_now"
for mode in $MODES; do
  agent_env=(-u WGFT_AGENT_NETSTACK WGFT_MODE="$mode")
  case "$mode" in
    gvisor|wgstack) agent_env=(WGFT_MODE=userspace WGFT_AGENT_NETSTACK="$mode") ;;
    rust) agent_env=(-u WGFT_AGENT_NETSTACK WGFT_MODE=userspace) ;;
  esac
  rmem_field=
  if [ "$mode" = kernel ] && [ -n "$KERNEL_RMEM_MAX" ]; then
    # shellcheck disable=SC2086 # the three values of tcp_rmem are words on purpose
    set -- $rmem_was
    rmem_set=1
    set_rmem "$1" "$(( $2 < KERNEL_RMEM_MAX ? $2 : KERNEL_RMEM_MAX ))" "$KERNEL_RMEM_MAX" ||
      { echo "FAIL  cannot set the tcp_rmem maximum to $KERNEL_RMEM_MAX in the $READER_NS namespace"; fail=1; restore_rmem; continue; }
    echo "   $READER_NS tcp_rmem: $(ip netns exec "$READER_NS" sysctl -n net.ipv4.tcp_rmem)"
    rmem_field="rcv_rmem_max=$KERNEL_RMEM_MAX "
  else
    restore_rmem || fail=1
  fi
  if [ "$OUTAGE_S" = 0 ]; then outage="no outage"; else outage="${OUTAGE_S}s outage after ${OUTAGE_AFTER} bytes"; fi
  path="delay ${DELAY_MS}ms and loss ${LOSS_PCT}%${RATE_MBIT:+ at ${RATE_MBIT} Mbit/s with a ${QUEUE_PKTS}-packet queue}"
  if [ "$TOOL" = iperf3 ]; then size="${IPERF_S}-second"; else size="${BYTES}-byte"; fi
  echo "== agent $mode: $path each way, $size $transfer by $TOOL with $STREAMS stream(s), $outage, $RUNS runs"
  cleanup
  mkdir -p "$DATA"
  vps setsid nohup wgft server run --mode kernel --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
    > "$W/wgft-tq-server-$mode.log" 2>&1 < /dev/null &
  disown
  wait_until 30 vps wgft agent ls --admin "$ADMIN" || { echo "FAIL  the server did not come up"; fail=1; continue; }
  join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  if [ "$mode" = rust ]; then
    env "${agent_env[@]}" WGFT_JOIN="$join" "WGFT_AGENT_ALLOW_TARGETS=$ALLOW" \
      ip netns exec "$HOME_NS" setsid nohup "$RUST_AGENT" agent run --data-dir "$ADATA" > "$W/wgft-tq-agent-$mode.log" 2>&1 < /dev/null &
  else
    env "${agent_env[@]}" WGFT_JOIN="$join" "WGFT_AGENT_ALLOW_TARGETS=$ALLOW" \
      ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$ADATA" > "$W/wgft-tq-agent-$mode.log" 2>&1 < /dev/null &  # lab: go agent
  fi
  disown
  wait_until 30 handshaken || { echo "FAIL  the agent did not register"; fail=1; continue; }
  : > "$W/wgft-tq-serve-$mode.log"
  ip netns exec "$LAN_NS" setsid nohup $Q serve 192.168.50.3 25800 "$BYTES" 7 > "$W/wgft-tq-serve-$mode.log" 2>&1 < /dev/null &
  disown
  vps wgft rule add --agent home --tcp 41800 --to "$TARGET" --admin "$ADMIN" >/dev/null
  wait_until 30 rule_ok || { echo "FAIL  the rule does not forward"; fail=1; continue; }
  if [ "$TOOL" = iperf3 ]; then
    # the probe above needs tcpquality.py's server; iperf3's takes the target port from here on
    sandbox_kill_cmdline '/tcpquality.py '
    wait_until 10 sh -c "! ip netns exec $LAN_NS ss -Htln 'sport = :25800' | grep -q ."
    ip netns exec "$LAN_NS" setsid nohup iperf3 -s -B 192.168.50.3 -p 25800 > "$W/wgft-tq-serve-$mode.log" 2>&1 < /dev/null &
    disown
    wait_until 10 sh -c "ip netns exec $LAN_NS ss -Htln 'sport = :25800' | grep -q ." || { echo "FAIL  iperf3 did not listen"; fail=1; continue; }
  fi
  if [ -n "$UDPPING" ]; then
    ip netns exec "$LAN_NS" setsid nohup $Q uecho 192.168.50.3 25801 > "$W/wgft-tq-uecho-$mode.log" 2>&1 < /dev/null &
    disown
    vps wgft rule add --agent home --udp 41801 --to "$UDP_TARGET" --admin "$ADMIN" >/dev/null
    # the rule is up once a datagram comes back
    wait_until 30 sh -c "ip netns exec $CLIENT_NS $Q uping 198.51.100.1 41801 0.2 10 probe | grep -q 'probe_p50_ms='" \
      || { echo "FAIL  the UDP rule does not echo"; fail=1; continue; }
  fi
  if [ -n "$CPU" ]; then
    agent_pid=$(ns_pid "$HOME_NS" "agent run --data-dir $ADATA")
    server_pid=$(ns_pid "$VPS_NS" "server run --mode kernel --data-dir $DATA")
    if [ "$TOOL" = iperf3 ]; then lan_pid=$(ns_pid "$LAN_NS" "iperf3 -s"); else lan_pid=$(ns_pid "$LAN_NS" "tcpquality.py serve"); fi
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
    udp_idle= udp_load=
    if [ -n "$UDPPING" ]; then
      udp_idle=$(ip netns exec "$CLIENT_NS" $Q uping 198.51.100.1 41801 "$UDPPING_IDLE_S" "$UDPPING_MS" udp_idle)
      udp_idle=$(udp_or_lost udp_idle "$UDPPING_IDLE_S" "$udp_idle")
    fi
    if [ -n "$CPU" ]; then
      t0=$(date +%s.%N) a0=$(cpu_us "$agent_pid" "$agent_cg") s0=$(cpu_us "$server_pid" "$server_cg") l0=$(cpu_us "$lan_pid" "$lan_cg") v0=$(vm_cpu_us)
    fi
    if [ "$TOOL" = iperf3 ]; then
      # the client runs in a cgroup of its own from its first instruction, so its CPU time is read like the others'
      client_cg=$CG_ROOT-client-$run
      mkdir -p "$client_cg" 2>/dev/null || client_cg=
      rev=; [ "$DIRECTION" = down ] && rev=-R
      bash -c 'if [ -n "$1" ]; then echo $$ > "$1/cgroup.procs"; fi; shift; exec "$@"' _ "$client_cg" \
        ip netns exec "$CLIENT_NS" iperf3 -c 198.51.100.1 -p 41800 -t "$IPERF_S" -P "$STREAMS" $rev -J \
        ${IPERF_MBIT:+-b "${IPERF_MBIT}M"} > "$W/wgft-tq-iperf-$mode.json" 2> "$W/wgft-tq-fetch-$mode.log" &
      fetcher=$!
      if [ -n "$UDPPING" ]; then
        (sleep 0.5; exec ip netns exec "$CLIENT_NS" $Q uping 198.51.100.1 41801 "$((IPERF_S - 1))" "$UDPPING_MS" udp_load) \
          > "$W/wgft-tq-uping-$mode.log" 2>&1 &
        pinger=$!
      fi
    elif [ "$DIRECTION" = up ]; then
      ip netns exec "$CLIENT_NS" $Q push 198.51.100.1 41800 "$BYTES" 7 "$W/wgft-tq-samples-$mode" "$OUTAGE_AFTER" "$mark" \
        > "$W/wgft-tq-fetch-$mode.log" 2>&1 &
      fetcher=$!
    else
      ip netns exec "$CLIENT_NS" $Q fetch 198.51.100.1 41800 "$W/wgft-tq-samples-$mode" "$OUTAGE_AFTER" "$mark" \
        > "$W/wgft-tq-fetch-$mode.log" 2>&1 &
      fetcher=$!
    fi
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
    tool_rc=$?
    # the CPU window closes when the transfer ends; the pinger's last second of waiting for late
    # echoes is not part of it
    if [ -n "$CPU" ]; then
      t1=$(date +%s.%N) a1=$(cpu_us "$agent_pid" "$agent_cg") s1=$(cpu_us "$server_pid" "$server_cg") l1=$(cpu_us "$lan_pid" "$lan_cg") v1=$(vm_cpu_us)
    fi
    if [ -n "$UDPPING" ]; then
      wait "$pinger"
      udp_load=$(udp_or_lost udp_load "$((IPERF_S - 1))" "$(tail -1 "$W/wgft-tq-uping-$mode.log")")
    fi
    netem delay 0ms

    if [ "$TOOL" = iperf3 ]; then
      # one line with received=, sent=, the receiver's duration and rate, and the sender's retransmits
      got=$($Q iperf "$W/wgft-tq-iperf-$mode.json")
      sent=$got
      stats="undetermined=0 streams=$STREAMS duration_s=$(field duration_s "$got") overall_mbit=$(field mbit "$got") retransmits=$(field retransmits "$got")"
      c_us=; [ -n "$client_cg" ] && c_us=$(awk '$1 == "usage_usec" { print $2 }' "$client_cg/cpu.stat" 2>/dev/null)
      rmdir "$client_cg" 2>/dev/null
    else
      got=$(tail -1 "$W/wgft-tq-fetch-$mode.log")
      wait_until 10 served "$mode" "$run"
      sent=$(grep sha256 "$W/wgft-tq-serve-$mode.log" | sed -n "${run}p")
      if [ "$DIRECTION" = up ]; then swap=$got; got=$sent; sent=$swap; fi
      stats=$($Q analyze "$W/wgft-tq-samples-$mode" "$out_start" "$out_end")
      c_us=$(field cpu_s "$sent" | awk '{ if ($1 != "") printf "%d", $1 * 1000000 }')
    fi
    if [ -n "$CPU" ] && [ -n "$agent_pid" ] && { [ -z "$a0" ] || [ -z "$a1" ] || [ "$a1" -lt "$a0" ]; }; then
      echo "FAIL  agent $mode run $run: the agent's CPU time could not be read over the whole transfer"; fail=1 run_pass=0
    elif [ -n "$CPU" ] && [ -n "$agent_pid" ]; then
      stats="$stats $(awk -v t0="$t0" -v t1="$t1" -v n="$(field received "$got")" -v c="$c_us" -v dir="$DIRECTION" -v tool="$TOOL" \
        -v a="$((${a1:-0} - ${a0:-0}))" -v s="$((${s1:-0} - ${s0:-0}))" -v l="$((${l1:-0} - ${l0:-0}))" -v v="$((${v1:-0} - ${v0:-0}))" 'BEGIN {
          t = t1 - t0
          printf "t_start=%.3f t_end=%.3f window_s=%.3f agent_cpu_s=%.3f agent_cpu_s_per_gb=%.3f agent_cpu_share=%.3f server_cpu_s=%.3f lan_cpu_share=%.3f",
            t0, t1, t, a / 1e6, (n > 0 ? a / 1e6 / (n / 1e9) : -1), a / 1e6 / t, s / 1e6, l / 1e6 / t
          printf " vm_cpu_s_per_gb=%.3f vm_cpu_share=%.3f", (n > 0 ? v / 1e6 / (n / 1e9) : -1), v / 1e6 / t
          # tcpquality.py reports the client CPU only for an upload, where the client sends; the analysis
          # reads client_cpu_share as the sender, so with iperf3 the client is named by its role only
          if (c != "" && (tool != "iperf3" || dir == "up")) printf " client_cpu_share=%.3f", c / 1e6 / t
          if (dir == "up") { snd = c; rcv = l * 1 } else { snd = l; rcv = c }
          if (snd != "") printf " sender_cpu_share=%.3f", snd / 1e6 / t
          if (rcv != "" && (tool == "iperf3" || dir == "up")) printf " receiver_cpu_share=%.3f", rcv / 1e6 / t }')"
    fi
    echo "   run $run sent:     $sent"
    echo "   run $run received: $got"
    if [ "$TOOL" = iperf3 ]; then
      if [ "$tool_rc" = 0 ] && [ "$(field received "$got")" -gt 0 ] 2>/dev/null; then
        echo "PASS  agent $mode run $run: iperf3 exited 0 and $reader read $(field received "$got") bytes"
      else
        echo "FAIL  agent $mode run $run: iperf3 exited $tool_rc and $reader read $(field received "$got") bytes"; fail=1 run_pass=0
        tail -5 "$W/wgft-tq-fetch-$mode.log"
      fi
    elif [ -n "$(field sha256 "$got")" ] && [ "$(field sha256 "$got")" = "$(field sha256 "$sent")" ] && [ "$(field received "$got")" = "$(field sent "$sent")" ]; then
      echo "PASS  agent $mode run $run: $reader read exactly the stream $writer sent"
    else
      echo "FAIL  agent $mode run $run: the stream differs"; fail=1 run_pass=0
    fi
    if [ "$(field undetermined "$stats")" = 1 ]; then
      echo "UNDETERMINED  agent $mode run $run: no reads on both sides of the outage; $stats"
    fi
    echo "RESULT mode=$mode run=$run ${dir_field}${rmem_field}delay_ms=$DELAY_MS loss_pct=$LOSS_PCT ${RATE_MBIT:+rate_mbit=$RATE_MBIT }$stats bytes=$(field received "$got") pass=$run_pass sync=$sync_state${udp_idle:+ $udp_idle}${udp_load:+ $udp_load}"
    echo "$stats" >> "$results"
  done
  echo "MEDIAN mode=$mode $($Q median "$results")"
done
exit "$fail"
