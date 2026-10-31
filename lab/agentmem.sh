#!/usr/bin/env bash
# agentmem.sh measures the peak memory of the userspace agent under hostile load, for one netstack
# at a time, and compares it with the design's bound for the same settings
# (docs/design/userspace/memory-agent-host.md):
#
#   lab/lab exec vm bash /wgft/lab/agentmem.sh gvisor
#   lab/lab exec vm bash /wgft/lab/agentmem.sh wgstack syn ooo
#
# The agent is the userspace-mode agent behind a kernel-mode server, so a public client reaches its
# netstack through DNAT, as an untrusted user does. It runs with --max-tcp-flows $K and
# --max-udp-flows $U, the smallest settings at which the loads below are past the budget, and with
# WGFT_AGENT_NETSTACK set to the argument. Every load starts a fresh server and agent, so the
# agent's VmHWM is the load's own peak.
#
# Loads (memload.py and traffic.py run in the client and lan namespaces):
#   syn     a raw SYN flood to a forwarded TCP port: 32 addresses x 1500 source ports, the SYN-ACKs
#           left unanswered (the client drops its own RSTs)
#   noread  $K+ established connections whose LAN side never reads, each writing 4 MiB, so the
#           agent's receive buffers fill to the floor and ask for boost
#   ooo     200 connections opened with a raw handshake, then one-byte segments on every second byte
#           past a hole at the first byte, for 30 s; then the holes filled in reverse order
#   twchurn short connections the target closes first, at 1000 a second for 100 s, so the agent's
#           netstack keeps the TIME_WAIT rows
#   udp     raw datagrams from 32 addresses x 2000 source ports to one UDP rule, for 30 s
#   lis1    2048 connections at once, each writing 32 KiB, to one TCP listener
#   lis8    the same 2048 connections spread over 8 TCP listeners
#
# Each load prints one RESULT line (peak RSS, peak live heap, the bound and the ratios) and, for
# wgstack, a STATS line with the largest value each Device counter reached. The heap and the Device's
# Stats come from the probe in internal/dataplane/userspace/tunnel/memprobe_on.go, which only a
# build with `WGFT_LAB_BUILD_TAGS=labmemprobe lab/lab build` contains; the heap is also read from
# GODEBUG=gctrace=1, the RSS from /proc.
#
# The loads run alone (lab/suite.txt's exclusive-heavy): the value read is a memory peak.
# Requires the labmemprobe build and the netns topology (`lab/lab net up`).
set -u
ulimit -n 100000 2>/dev/null || true
NETSTACK=${1:-}
case "$NETSTACK" in gvisor|wgstack) ;; *) echo "usage: agentmem.sh gvisor|wgstack [load...]" >&2; exit 2;; esac
shift
ALL_LOADS="syn noread ooo twchurn udp lis1 lis8"
LOADS="${*:-$ALL_LOADS}"
for c in $LOADS; do
  case " $ALL_LOADS " in *" $c "*) ;; *) echo "agentmem.sh: unknown load '$c' (use: $ALL_LOADS)" >&2; exit 2;; esac
done

. "$(dirname "$0")/sandbox.sh"
HERE=$(cd "$(dirname "$0")" && pwd)
TRAFFIC="python3 $HERE/traffic.py"
MEMLOAD="python3 $HERE/memload.py"
AGENTMEM="python3 $HERE/agentmem.py"
ADMIN=127.0.0.1:8686
K=${WGFT_LAB_AGENTMEM_K:-256}
U=${WGFT_LAB_AGENTMEM_U:-256}
DATA=$W/wgft-am-server
ADATA=$W/wgft-am-agent
SLOG=$W/wgft-am-server.log
ALOG=$W/wgft-am-agent.log
PROBE=$W/wgft-am-probe.jsonl
RSSF=$W/wgft-am-rss.txt
fail=0

okcheck() { if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
yes_if() { if "$@"; then echo 1; else echo 0; fi; }
vps() { ip netns exec "$VPS_NS" "$@"; }
cl() { ip netns exec "$CLIENT_NS" "$@"; }
home() { ip netns exec "$HOME_NS" "$@"; }
lan() { ip netns exec "$LAN_NS" "$@"; }
wait_until() {
  local timeout=$1; shift
  local deadline=$((SECONDS + timeout))
  while :; do
    "$@" >/dev/null 2>&1 && return 0
    (( SECONDS >= deadline )) && return 1
    sleep 0.2
  done
}
must_wait() {
  local label=$1 timeout=$2; shift 2
  wait_until "$timeout" "$@" && return 0
  echo "FAIL  $label: timed out"; fail=1; return 1
}
log_has() { grep -q "$2" "$1" 2>/dev/null; }
rss_mib() { awk '/VmRSS/{print int($2/1024)}' "/proc/$1/status" 2>/dev/null; }
hwm_mib() { awk '/VmHWM/{print int($2/1024)}' "/proc/$1/status" 2>/dev/null; }
max_of() { sort -n "$1" 2>/dev/null | tail -1; }
admin_up() { vps wgft agent ls --admin "$ADMIN" >/dev/null 2>&1; }
agent_registered() {
  vps wgft agent ls --admin "$ADMIN" --json 2>/dev/null | python3 -c "
import json, sys
try:
    agents = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
sys.exit(0 if any(a.get('name') == 'home' and a.get('last_handshake') for a in agents) else 1)
"
}
rule_add() { vps wgft rule add --admin "$ADMIN" "$@" | grep -oE 'r_[A-Z0-9]+'; }
tcp_echo_ok() { [[ "$(cl bash -c "echo hi | timeout -k 5 20 socat -t 1 -T 10 - TCP:198.51.100.1:$1" 2>/dev/null)" == *tcp-echo* ]]; }
find_agent_pid() {
  local p
  for p in $(sandbox_wgft_pids); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q "agent run --data-dir $ADATA" && { echo "$p"; return; }
  done
}
# live_heap <log> <from-line> max: the largest live heap, in MiB, of the GC trace lines of the log
# after the line number
gc_peak() {
  awk -v a="$2" 'NR > a && /^gc [0-9]+ @/ {
      if (match($0, /[0-9]+->[0-9]+->[0-9]+ MB/)) {
        split(substr($0, RSTART, RLENGTH - 3), v, "->"); x = v[3] + 0
        if (!seen || x > m) m = x; seen = 1
      }
    } END { if (seen) print m; else print 0 }' "$1"
}
bg() { # bg <netns> <log> <command...>
  local ns=$1 log=$2; shift 2
  ip netns exec "$ns" setsid nohup "$@" > "$log" 2>&1 < /dev/null &
  disown
}

SRC_FIRST=10 SRC_LAST=41
srcs_csv() { local n=$1 i s=""; for i in $(seq $SRC_FIRST $((SRC_FIRST + n - 1))); do s+="198.51.100.$i,"; done; echo "${s%,}"; }

none_running() { ! sandbox_any_named wgft echo && [ -z "$(traffic_pids)" ]; }
traffic_pids() {
  local p
  for p in $(sandbox_pids); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q -- '/\(traffic\|memload\).py ' && echo "$p"
  done
  return 0
}
cleanup() {
  [ -n "${SAMPLER:-}" ] && kill "$SAMPLER" 2>/dev/null
  SAMPLER=
  sandbox_kill_named wgft echo
  sandbox_kill_cmdline '/traffic.py '
  sandbox_kill_cmdline '/memload.py '
  wait_until 10 none_running
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  cl nft delete table inet am 2>/dev/null
  local i
  for i in $(seq $SRC_FIRST $SRC_LAST); do cl ip addr del "198.51.100.$i/24" dev eth0 2>/dev/null; done
  [ -n "${SAVED_HOME_PORTS:-}" ] && home sysctl -qw net.ipv4.ip_local_port_range="$SAVED_HOME_PORTS"
  SAVED_HOME_PORTS=
  rm -rf "$DATA" "$ADATA"
}
trap cleanup EXIT

# setup: a fresh kernel-mode server, the userspace agent with the netstack under test, the LAN
# targets, the client's addresses and its RST drop, and the sampler of the agent's RSS
setup() {
  cleanup
  rm -f "$PROBE" "$RSSF" "$ALOG"
  local i
  for i in $(seq $SRC_FIRST $SRC_LAST); do cl ip addr add "198.51.100.$i/24" dev eth0 2>/dev/null; done
  # the client kernel knows none of the raw connections and half-open attempts, and would reset them
  cl nft add table inet am
  cl nft add chain inet am out '{ type filter hook output priority 0; }'
  cl nft add rule inet am out tcp flags rst drop
  SAVED_HOME_PORTS=$(home sysctl -n net.ipv4.ip_local_port_range | tr '\t' ' ')
  home sysctl -qw net.ipv4.ip_local_port_range="1024 65000"
  mkdir -p "$DATA"
  vps setsid nohup env GODEBUG=gctrace=1 wgft server run --mode kernel --data-dir "$DATA" \
    --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" > "$SLOG" 2>&1 < /dev/null &
  disown
  must_wait "server admin api comes up" 30 admin_up || return 1
  local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_MODE=userspace WGFT_JOIN="$join" WGFT_AGENT_NETSTACK=$NETSTACK GODEBUG=gctrace=1 WGFT_LAB_MEMPROBE="$PROBE" \
    ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$ADATA" --max-tcp-flows "$K" --max-udp-flows "$U" \
    > "$ALOG" 2>&1 < /dev/null &
  disown
  must_wait "agent registers and handshakes" 30 agent_registered || return 1
  APID=$(find_agent_pid)
  [ -n "$APID" ] || { echo "FAIL  agent pid not found"; fail=1; return 1; }
  lan setsid nohup echo -bind 192.168.50.3 -tcp 25720 -udp 25721 > /dev/null 2>&1 < /dev/null &
  disown
  bg "$LAN_NS" $W/wgft-am-noread.log $MEMLOAD serve-noread 192.168.50.3 25701 4096
  bg "$LAN_NS" $W/wgft-am-close.log $TRAFFIC serve-close-first 192.168.50.3 25702
  must_wait "noread target listens" 10 log_has $W/wgft-am-noread.log "listening=" || return 1
  must_wait "close-first target listens" 10 log_has $W/wgft-am-close.log "listening=" || return 1
  rule_add --agent home --udp 41705 --to 192.168.50.3:25721 >/dev/null
  if [ "$NETSTACK" = wgstack ]; then
    must_wait "the agent's wgstack probe writes (the labmemprobe build)" 10 test -s "$PROBE" || return 1
  fi
  : > "$RSSF"
  ( while kill -0 "$APID" 2>/dev/null; do rss_mib "$APID" >> "$RSSF"; sleep 0.5; done ) > /dev/null 2>&1 &
  SAMPLER=$!
  return 0
}

# finish <load> <tcp listeners>: let the agent settle, read the peaks, print the result against the
# bound
finish() {
  local load=$1 lt=$2
  sleep 6
  local hwm rss gcp base
  hwm=$(hwm_mib "$APID"); rss=$(max_of "$RSSF")
  [ "${hwm:-0}" -gt "${rss:-0}" ] && rss=$hwm
  gcp=$(gc_peak "$ALOG" 0)
  kill "$SAMPLER" 2>/dev/null; SAMPLER=
  echo "== $NETSTACK $load"
  if [ -s "$PROBE" ]; then
    $AGENTMEM summarize "$NETSTACK" "$K" "$U" "$lt" 1 "$PROBE" "${rss:-0}" "${gcp:-0}" | sed "s/^RESULT/RESULT load=$load/"
    cp "$PROBE" "$W/wgft-am-probe-$NETSTACK-$load.jsonl" 2>/dev/null
  else
    echo "NOTE  no probe file: this binary was built without the labmemprobe tag; only RSS and gctrace are available"
    echo "RESULT load=$load netstack=$NETSTACK peak_rss_mib=${rss:-?} peak_live_mib=${gcp:-?}"
  fi
  echo "   agent log lines mentioning a refusal: $(grep -ci 'refus' "$ALOG"); conntrack entries on the VPS: $(vps conntrack -C 2>/dev/null)"
  okcheck "$load: the agent is still running" "$(yes_if kill -0 "$APID")"
  grep -c "panic\|fatal error" "$ALOG" | grep -qx 0 || { echo "FAIL  $load: the agent log has a panic"; fail=1; }
}

load_syn() {
  setup || return
  rule_add --agent home --tcp 41701 --to 192.168.50.3:25720 >/dev/null
  must_wait "the rule forwards" 30 tcp_echo_ok 41701 || return
  local out; out=$(cl $MEMLOAD synflood 198.51.100.1 41701 "$(srcs_csv 32)" 1500 30 20000)
  echo "   load: $out"
  finish syn 1
}

load_noread() {
  setup || return
  rule_add --agent home --tcp 41702 --to 192.168.50.3:25701 >/dev/null
  # the first connection only proves the rule forwards; the target never answers
  sleep 3
  bg "$CLIENT_NS" $W/wgft-am-hold.log $TRAFFIC hold 198.51.100.1 41702 "$(srcs_csv 8)" 40 4194304 20
  must_wait "the connections are opened" 60 log_has $W/wgft-am-hold.log "^attempted=" || return
  echo "   load: $(grep '^attempted=' $W/wgft-am-hold.log)"
  sleep 22
  finish noread 1
}

load_ooo() {
  setup || return
  rule_add --agent home --tcp 41703 --to 192.168.50.3:25701 >/dev/null
  sleep 3
  local out; out=$(cl $MEMLOAD ooo 198.51.100.1 41703 "$(srcs_csv 8)" 200 2000 30 | tr '\n' ' ')
  echo "   load: $out"
  finish ooo 1
}

load_twchurn() {
  setup || return
  rule_add --agent home --tcp 41704 --to 192.168.50.3:25702 >/dev/null
  sleep 3
  local out; out=$(cl $TRAFFIC churn 198.51.100.1 41704 1000 100 server-first - 1024 | tail -1)
  echo "   load: $out"
  finish twchurn 1
}

load_udp() {
  setup || return
  rule_add --agent home --tcp 41701 --to 192.168.50.3:25720 >/dev/null
  sleep 3
  local out; out=$(cl $MEMLOAD udpmany 198.51.100.1 41705 "$(srcs_csv 32)" 2000 30 20000)
  echo "   load: $out"
  finish udp 1
}

# lis <n>: 2048 connections at once, each writing 32 KiB, spread over n TCP listeners
load_lis() {
  local n=$1 i per
  setup || return
  for i in $(seq 1 "$n"); do rule_add --agent home --tcp $((41710 + i)) --to 192.168.50.3:25720 >/dev/null; done
  must_wait "the first rule forwards" 30 tcp_echo_ok 41711 || return
  # 32 sources x (64 / n) per source for each listener: 2048 attempts in all
  per=$((64 / n))
  for i in $(seq 1 "$n"); do
    bg "$CLIENT_NS" $W/wgft-am-hold$i.log $TRAFFIC hold 198.51.100.1 $((41710 + i)) "$(srcs_csv 32)" "$per" 32768 15
  done
  for i in $(seq 1 "$n"); do
    must_wait "listener $i: the connections are opened" 90 log_has $W/wgft-am-hold$i.log "^attempted=" || return
    echo "   load $i: $(grep '^attempted=' $W/wgft-am-hold$i.log)"
  done
  sleep 17
  finish "lis$n" "$n"
}
load_lis1() { load_lis 1; }
load_lis8() { load_lis 8; }

echo "agentmem: netstack=$NETSTACK K=$K U=$U loads: $LOADS"
for l in $LOADS; do
  "load_$l"
done
cleanup
if [ "$fail" = 0 ]; then echo "== $NETSTACK: ALL PASS"; else echo "== $NETSTACK: FAILURES"; fi
exit "$fail"
