#!/usr/bin/env bash
# exhaustion.sh drives the userspace dataplane's retained resources with external input and checks
# that they stay bounded, that exhaustion degrades into a counted and logged failure, and that the
# Device recovers once the load stops, without a rebuild. It prints the measured numbers each check
# rests on, and a few checks only measure, for limitations the design keeps:
#
#   lab/lab exec vm bash /wgft/lab/exhaustion.sh userspace postclose
#   lab/lab exec vm bash /wgft/lab/exhaustion.sh kernel mss
#
# Checks (the design documents named are under docs/design/userspace/):
#   postclose  the post-close table of tcp-retention.md. Short TCP connections that the netstack
#              closes first, so that it keeps them in TIME_WAIT, are opened and closed at 400 a
#              second, faster than the table can hold for 60 s (M / 60, about 218 a second).
#              userspace mode: through the server's relay; the client closes first, so the server's
#              netstack sends the first FIN. kernel mode: through the agent behind the kernel-mode
#              server; the target closes first, so the agent's netstack sends the first FIN. The
#              client takes its source ports in turn, so no 4-tuple comes back within 60 s: a new
#              SYN on a TIME_WAIT 4-tuple ends that endpoint early on the listening side, which
#              would let rows leave the table before 60 s (tcp-retention.md). The load stops once
#              the second eviction log line, a minute after the first, is out.
#              Asserts that the first eviction comes at M closes (within 10 %), that the second
#              line's eviction count is at least 0.9 of the closes past M, that the live heap stays
#              flat once the table is full and within 128 MiB of the idle value (gVisor's own
#              60 s TIME_WAIT at this rate would hold about 24,000 rows, past that), that another
#              flow keeps answering, and that after 65 s idle a burst of 10,000 closes evicts
#              nothing, in the same process with one tunnel up line.
#              The drain checks do not notice a stopped sweeper: with the sweeper stopped, finished
#              rows stay and a full table replaces them without an eviction. The unit test
#              TestPostCloseDrainsAfterTimeWait covers the sweeper.
#   mss        the MSS floor of packet-validation.md. kernel mode: a client SYN rewritten to MSS 48
#              toward the agent's netstack listener is dropped and counted, and no connection
#              forms; with the rewrite gone the same port connects; a client on an MTU 576 link
#              moves 2 MiB each way. userspace mode: with a kernel-mode agent, the target's SYN-ACK
#              rewritten to MSS 48 toward the server's netstack is dropped and counted and the
#              relay forwards nothing; a target on an MTU 576 link moves 2 MiB each way.
#   acceptq    kernel mode only: the agent's accept queue behind a kernel-mode server. Opens 2304
#              connections at once, each writing 32 KiB, from 32 source addresses, each under the
#              server's per-source cap; the server has no rule-wide cap of its own here, and the
#              agent resets what is past its own flow budget. Samples every 0.1 s how many the
#              client sees established that the agent has not yet relayed to the target (an upper
#              bound on the accept queue, which also counts connections the relay has accepted and
#              is about to reset or dial for), and the agent's live heap and RSS. Measures only;
#              asserts that once the burst settles nothing is left waiting, and that the agent
#              forwards again afterwards.
#   ackflood   kernel mode only: duplicate zero-payload ACKs, as fast as one sender can write them,
#              through WireGuard to one connection on the agent's netstack. Measures the agent's
#              live heap and RSS and another connection's round-trip time against an idle
#              baseline; asserts that both connections still echo afterwards.
#   wgstall    userspace mode only: two agents; one agent's target sends UDP at full speed toward
#              the server, which can fill that peer's receive queue in wireguard-go and make the
#              receive goroutine wait (flow-limits.md, a limitation kept). Measures the other
#              agent's TCP and UDP round-trip times against an idle baseline, the server's WireGuard
#              socket drops and live heap; asserts that the other agent forwards again afterwards.
#
# The live heap is read from the Go runtime's own GC trace (GODEBUG=gctrace=1, the third value of
# "a->b->c MB", in MiB): neither process exports its heap or the post-close table's length. The
# table's length is checked through its effects, its eviction count and the live heap.
#
# The checks that measure a heap, an RSS, a rate or a round-trip time run alone (lab/suite.txt's
# exclusive-heavy); mss does not measure and runs in the pool.
# Requires `lab/lab build` and the netns topology (`lab/lab net up`). Leftovers from earlier runs
# are killed first.
set -u
ulimit -n 100000 2>/dev/null || true
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: exhaustion.sh kernel|userspace [check...]" >&2; exit 2;; esac
shift || true
ALL_CHECKS="postclose mss acceptq ackflood wgstall"
CHECKS="${*:-$ALL_CHECKS}"
for c in $CHECKS; do
  case " $ALL_CHECKS " in *" $c "*) ;; *) echo "exhaustion.sh: unknown check '$c' (use: $ALL_CHECKS)" >&2; exit 2;; esac
done

. "$(dirname "$0")/sandbox.sh"   # sandbox: netns names, workdir, process scope
TRAFFIC="python3 $(cd "$(dirname "$0")" && pwd)/traffic.py"
ADMIN=127.0.0.1:8686
DATA=$W/wgft-exh-server
ADATA=$W/wgft-exh-agent
BDATA=$W/wgft-exh-agent2
SLOG=$W/wgft-exh-server.log
ALOG=$W/wgft-exh-agent.log
BLOG=$W/wgft-exh-agent2.log
# M of tcp-retention.md: 128 MiB / 10 KiB.
M=13107
fail=0

okcheck() { if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
skip() { echo "SKIP  $1 (does not apply to $mode mode)"; }
# field <name> <text>: the value after "<name>=" in text, or empty
field() { echo "$2" | grep -oE "(^| )$1=[^ ]*" | head -1 | cut -d= -f2; }
# le/ge <a> <b>: integer comparisons that are false, not an error, on an empty value
le() { [ -n "$1" ] && [ -n "$2" ] && [ "$1" -le "$2" ] 2>/dev/null; }
ge() { [ -n "$1" ] && [ -n "$2" ] && [ "$1" -ge "$2" ] 2>/dev/null; }
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
lines_of() { wc -l < "$1" 2>/dev/null || echo 0; }
rss_mib() { awk '/VmRSS/{print int($2/1024)}' "/proc/$1/status" 2>/dev/null; }

# live_heap <log> <from-line> <to-line> max|last: the largest or the last live heap, in MiB, of the
# GC trace lines between the two line numbers of the log (from exclusive, to inclusive), or empty
# when no GC ran there.
live_heap() {
  awk -v a="$2" -v b="$3" -v how="$4" 'NR > a && NR <= b && /^gc [0-9]+ @/ {
      if (match($0, /[0-9]+->[0-9]+->[0-9]+ MB/)) {
        split(substr($0, RSTART, RLENGTH - 3), v, "->"); x = v[3] + 0
        if (how == "last" || !seen || x > m) m = x; seen = 1
      }
    } END { if (seen) print m }' "$1"
}

admin_up() { vps wgft agent ls --admin "$ADMIN" >/dev/null 2>&1; }
agent_registered() {
  vps wgft agent ls --admin "$ADMIN" --json 2>/dev/null | python3 -c "
import json, sys
try:
    agents = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
sys.exit(0 if any(a.get('name') == '$1' and a.get('last_handshake') for a in agents) else 1)
"
}

ensure_wgftlab() { id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab; }
start_server() {
  mkdir -p "$DATA"
  if [ "$mode" = userspace ]; then
    ensure_wgftlab
    chown wgftlab "$DATA"
    vps setsid nohup runuser -u wgftlab -- env GODEBUG=gctrace=1 wgft server run --mode "$mode" --data-dir "$DATA" \
      --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" > "$SLOG" 2>&1 < /dev/null &
  else
    vps setsid nohup env GODEBUG=gctrace=1 wgft server run --mode "$mode" --data-dir "$DATA" \
      --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" > "$SLOG" 2>&1 < /dev/null &
  fi
  disown
  must_wait "server admin api comes up" 30 admin_up
}
# start_agent <name> <netns> <data-dir> <log> [agent mode]: a userspace agent unless the mode says
# kernel; the kernel-mode agent runs as root, the same as lab/agentkernel.sh.
start_agent() {
  local name=$1 ns=$2 data=$3 log=$4 amode=${5:-userspace} join
  join=$(vps wgft agent join-string --name "$name" --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_MODE=$amode WGFT_JOIN="$join" GODEBUG=gctrace=1 ip netns exec "$ns" setsid nohup wgft agent run --data-dir "$data" \
    > "$log" 2>&1 < /dev/null &
  disown
  must_wait "agent $name registers and handshakes" 30 agent_registered "$name"
}
# bg <netns> <log> <traffic args...>: a traffic.py process in the background
bg() {
  local ns=$1 log=$2; shift 2
  ip netns exec "$ns" setsid nohup $TRAFFIC "$@" > "$log" 2>&1 < /dev/null &
  disown
}
listening() { log_has "$1" "listening="; }
rule_add() { vps wgft rule add --admin "$ADMIN" "$@" | grep -oE 'r_[A-Z0-9]+'; }
tcp_line_ok() { [ "$(cl $TRAFFIC tcp-rtt 198.51.100.1 "$1" 0.1 0.1 2>/dev/null | grep -o 'ok=1')" = ok=1 ]; }
find_pid() { # find_pid <substring of the wgft command line>
  local p
  for p in $(sandbox_wgft_pids); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q " $1" && { echo "$p"; return; }
  done
}
find_agent_pid() { # find_agent_pid <data-dir>
  local p
  for p in $(sandbox_wgft_pids); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q "agent run --data-dir $1" && { echo "$p"; return; }
  done
}
# sample_rss <pid> <file>: appends the RSS in MiB every second until stopped
sample_rss() {
  ( while kill -0 "$1" 2>/dev/null; do rss_mib "$1" >> "$2"; sleep 1; done ) > /dev/null 2>&1 &
  echo $!
}
# answered_95 <udp-rtt result>: at least one, and at least 95 %, of the datagrams answered
answered_95() {
  local ok sent; ok=$(field ok "$1"); sent=$(field sent "$1")
  [ -n "$ok" ] && [ -n "$sent" ] && [ "$ok" -ge 1 ] && [ $((ok * 100)) -ge $((sent * 95)) ]
}
# flow_ok <tcp-rtt result>: every round trip answered
flow_ok() { [ "$(field fail "$1")" = 0 ] && ge "$(field ok "$1")" 1; }
max_of() { sort -n "$1" 2>/dev/null | tail -1; }

# traffic_pids: the traffic.py processes this script started, found by their command line in this
# sandbox's namespaces (in the whole VM outside a sandbox, as sandbox_kill_cmdline does)
traffic_pids() {
  local p
  if [ -z "$SANDBOX" ]; then pgrep -f -- '/traffic.py '; return 0; fi
  for p in $(sandbox_pids); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q -- '/traffic.py ' && echo "$p"
  done
  return 0
}
none_running() { ! sandbox_any_named wgft echo && [ -z "$(traffic_pids)" ]; }
cleanup() {
  [ -n "${SAMPLER:-}" ] && kill "$SAMPLER" 2>/dev/null
  SAMPLER=
  sandbox_kill_named wgft echo
  sandbox_kill_cmdline '/traffic.py '
  wait_until 10 none_running
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  # what the kernel-mode agent leaves when it is killed, as lab/agentkernel.sh removes it
  home ip link del wgft0 2>/dev/null
  home nft delete table inet wgft_agent 2>/dev/null
  home ip rule del to 10.200.0.1 lookup 52 2>/dev/null
  home ip route flush table 52 2>/dev/null
  cl nft delete table inet exh 2>/dev/null
  lan nft delete table inet exh 2>/dev/null
  cl ip link set eth0 mtu 1500 2>/dev/null
  lan ip link set eth0 mtu 1500 2>/dev/null
  local i
  for i in $(seq 10 41); do cl ip addr del "198.51.100.$i/24" dev eth0 2>/dev/null; done
  [ -n "${SAVED_TS:-}" ] && cl sysctl -qw net.ipv4.tcp_timestamps="$SAVED_TS"
  SAVED_TS=
  [ -n "${SAVED_CL_PORTS:-}" ] && cl sysctl -qw net.ipv4.ip_local_port_range="$SAVED_CL_PORTS"
  [ -n "${SAVED_HOME_PORTS:-}" ] && home sysctl -qw net.ipv4.ip_local_port_range="$SAVED_HOME_PORTS"
  SAVED_CL_PORTS= SAVED_HOME_PORTS=
  rm -rf "$DATA" "$ADATA" "$BDATA"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------------------------
# postclose
# ---------------------------------------------------------------------------------------------
check_postclose() {
  echo "== $mode: postclose: the post-close table under short connections faster than M/60"
  cleanup
  # The agent's host side dials the target once per connection; widen its ephemeral range, which
  # is per network namespace, so that a reused 4-tuple there is not what fails. The client binds
  # its own source ports in turn (traffic.py churn's first-port).
  SAVED_HOME_PORTS=$(home sysctl -n net.ipv4.ip_local_port_range | tr '\t' ' ')
  home sysctl -qw net.ipv4.ip_local_port_range="1024 65000"
  start_server || return
  start_agent home "$HOME_NS" "$ADATA" "$ALOG" || return
  local order nslog pid
  bg "$LAN_NS" $W/wgft-exh-lines.log serve-lines 192.168.50.3 25700
  bg "$LAN_NS" $W/wgft-exh-close.log serve-close-first 192.168.50.3 25701
  must_wait "line server listens" 10 listening $W/wgft-exh-lines.log || return
  must_wait "close-first server listens" 10 listening $W/wgft-exh-close.log || return
  if [ "$mode" = userspace ]; then
    # The client sends the first FIN; the server's relay passes it on, so the server's netstack
    # closes first toward the agent and keeps TIME_WAIT.
    rule_add --agent home --tcp 41700 --to 192.168.50.3:25700 >/dev/null
    order=client-first nslog=$SLOG pid=$(find_pid 'server run')
  else
    # The target closes first; the agent's relay passes it on, so the agent's netstack closes first
    # toward the client and keeps TIME_WAIT.
    rule_add --agent home --tcp 41700 --to 192.168.50.3:25701 >/dev/null
    order=server-first nslog=$ALOG pid=$(find_agent_pid "$ADATA")
  fi
  rule_add --agent home --tcp 41701 --to 192.168.50.3:25700 >/dev/null
  must_wait "load rule forwards" 20 tcp_or_close_ok 41700 "$order" || return
  must_wait "other-flow rule forwards" 20 tcp_line_ok 41701 || return

  local base_line base_heap base_rss
  base_line=$(lines_of "$nslog")
  base_heap=$(live_heap "$nslog" 0 "$base_line" last)
  base_rss=$(rss_mib "$pid")
  : > $W/wgft-exh-rss.txt
  SAMPLER=$(sample_rss "$pid" $W/wgft-exh-rss.txt)

  # 400 a second fills the table after about 33 s; the eviction log line is allowed once a minute,
  # so the second line, about a minute after the first, carries the count the eviction ratio below
  # reads. The load stops as soon as that line is out, so no fixed length has to cover it.
  local rate=400 stop=$W/wgft-exh-churn.stop
  rm -f "$stop"
  bg "$CLIENT_NS" $W/wgft-exh-other.log tcp-rtt 198.51.100.1 41701 0.2 200 "$stop"
  bg "$CLIENT_NS" $W/wgft-exh-churn.log churn 198.51.100.1 41700 $rate 180 "$order" "$stop" 10000
  local l_full l_end
  must_wait "the table fills and the first eviction is logged" 90 evictions_since "$nslog" "$base_line" 1
  l_full=$(lines_of "$nslog")
  must_wait "the second eviction line is logged" 90 evictions_since "$nslog" "$base_line" 2
  l_end=$(lines_of "$nslog")
  touch "$stop"
  must_wait "load finishes" 30 log_has $W/wgft-exh-churn.log "^started="
  must_wait "other flow finishes" 30 log_has $W/wgft-exh-other.log "^sent="
  kill "$SAMPLER" 2>/dev/null; SAMPLER=
  local churn other evlines ev1 ev2 c1 c2 h1 h2 hmax rss_max
  churn=$(grep '^started=' $W/wgft-exh-churn.log)
  other=$(grep '^sent=' $W/wgft-exh-other.log)
  evlines=$(sed -n "$((base_line + 1)),${l_end}p" "$nslog" | grep 'reset closed TCP connections')
  ev1=$(echo "$evlines" | sed -n 1p); ev2=$(echo "$evlines" | sed -n 2p)
  c1=$(closes_at "$ev1"); c2=$(closes_at "$ev2")
  local n2; n2=$(echo "$ev2" | grep -oE '[0-9]+ reset since' | grep -oE '^[0-9]+')
  read -r h1 h2 hmax <<< "$(live_heap_halves "$nslog" "$l_full" "$l_end")"
  rss_max=$(max_of $W/wgft-exh-rss.txt)
  echo "   load: $churn"
  echo "   other flow during the load: $other"
  echo "   first eviction logged after ${c1:-?} closes (M = $M); second after ${c2:-?} closes: ${n2:-?} evicted, $(ratio "${n2:-0}" "$(( ${c2:-0} - M ))") of the closes past M"
  echo "   live heap MiB: idle ${base_heap:-none}; once full, max ${h1:-none} in the first half and ${h2:-none} in the second"
  echo "   RSS MiB: idle ${base_rss:-?}, max during the load ${rss_max:-?}"
  okcheck "the load closes at least 1.5 x M/60 = $((M * 3 / 120)) connections a second (got $(field rate "$churn")/s)" \
    "$(yes_if ge "$(field rate "$churn")" $((M * 3 / 120)))"
  okcheck "the table holds M rows: the first eviction comes within 10 % of M closes" \
    "$(yes_if within "${c1:-0}" $((M * 9 / 10)) $((M * 11 / 10)))"
  okcheck "evictions keep pace: at least 0.9 of the closes past M were evicted, so rows never pile up past M" \
    "$(yes_if keeps_pace "${n2:-}" "${c2:-}")"
  okcheck "the live heap stays flat once the table is full (growth at most 16 MiB)" \
    "$(yes_if le "${h2:-}" "$(( ${h1:-0} + 16 ))")"
  okcheck "the live heap stays within the table's 128 MiB over idle" \
    "$(yes_if le "${hmax:-}" "$(( ${base_heap:-0} + 128 ))")"
  okcheck "another flow keeps answering during the load" "$(yes_if flow_ok "$other")"

  # Wall-clock wait on purpose: TIME_WAIT is 60 s and the sweeper runs every second. The eviction
  # log line is also allowed again once a minute has passed since the last one, so an eviction in
  # the burst below would log at once.
  echo "   idle for 65 s"
  sleep 65
  local lb0 lb1 burst evburst
  lb0=$(lines_of "$nslog")
  cl $TRAFFIC churn 198.51.100.1 41700 400 25 "$order" - 10000 > $W/wgft-exh-burst.log 2>&1
  lb1=$(lines_of "$nslog")
  burst=$(grep '^started=' $W/wgft-exh-burst.log)
  evburst=$(sed -n "$((lb0 + 1)),${lb1}p" "$nslog" | grep -c 'reset closed TCP connections')
  echo "   burst after 65 s idle: $burst; live heap MiB max $(live_heap "$nslog" "$lb0" "$lb1" max)"
  # the same floor as the main load's rate check, over the burst's 25 s
  local burst_min=$(( M * 3 / 120 * 25 ))
  okcheck "after 65 s idle the burst closes at least $burst_min connections in 25 s" \
    "$(yes_if ge "$(field ok "$burst")" "$burst_min")"
  okcheck "the table drained without a rebuild: that burst evicts nothing" "$(yes_if [ "$evburst" = 0 ])"
  okcheck "the Device is the one built at start: same process, one tunnel up line" \
    "$(yes_if same_device "$pid" "$nslog")"
}
# evictions_since <log> <line> <n>: at least n eviction log lines after the line number
evictions_since() { [ "$(sed -n "$(($2 + 1)),\$p" "$1" | grep -c 'reset closed TCP connections')" -ge "$3" ]; }
# closes_at <log line>: the closes traffic.py churn had counted at the line's log time, from its
# per-second progress lines (the log time has a resolution of one second)
closes_at() {
  local t
  t=$(date -d "$(echo "$1" | cut -d' ' -f1,2 | tr / -)" +%s 2>/dev/null) || return
  awk -v t="$t.5" '/^progress=/ {
      e = ""; o = ""
      for (i = 1; i <= NF; i++) { split($i, kv, "="); if (kv[1] == "epoch") e = kv[2]; if (kv[1] == "ok") o = kv[2] }
      d = e - t; if (d < 0) d = -d
      if (!seen || d < best) { best = d; v = o; seen = 1 }
    } END { if (seen && best <= 1) print v }' $W/wgft-exh-churn.log
}
# live_heap_halves <log> <from-line> <to-line>: the largest live heap in the first and in the
# second half of the GC trace lines between the two line numbers, and the largest of all
live_heap_halves() {
  awk -v a="$2" -v b="$3" 'NR > a && NR <= b && /^gc [0-9]+ @/ {
      if (match($0, /[0-9]+->[0-9]+->[0-9]+ MB/)) { split(substr($0, RSTART, RLENGTH - 3), v, "->"); x[n++] = v[3] + 0 }
    } END {
      for (i = 0; i < n; i++) { if (i < n / 2) { if (x[i] > m1) m1 = x[i] } else { if (x[i] > m2) m2 = x[i] } }
      if (n >= 2) print m1, m2, (m1 > m2 ? m1 : m2)
    }' "$1"
}
within() { ge "$1" "$2" && le "$1" "$3"; }
# keeps_pace <evicted> <closes>: both known, closes past M, and evicted at least 0.9 of those
keeps_pace() { [ -n "$1" ] && [ -n "$2" ] && [ "$2" -gt "$M" ] && [ $(($1 * 10)) -ge $((($2 - M) * 9)) ]; }
ratio() { if [ "${2:-0}" -gt 0 ] 2>/dev/null; then awk -v a="$1" -v b="$2" 'BEGIN { printf "%.2f", a / b }'; else echo "?"; fi; }
same_device() { kill -0 "$1" 2>/dev/null && [ "$(grep -c 'tunnel: up addr=' "$2")" = 1 ]; }
tcp_or_close_ok() { # tcp_or_close_ok <port> client-first|server-first
  local o; o=$(cl $TRAFFIC churn 198.51.100.1 "$1" 10 0.15 "$2" 2>/dev/null | grep '^started=')
  [ "$(field fail "$o")" = 0 ] && ge "$(field ok "$o")" 1
}

# ---------------------------------------------------------------------------------------------
# mss
# ---------------------------------------------------------------------------------------------
mss_log() { grep 'dropped TCP handshakes that advertise an MSS below 536' "$1" | tail -1; }
bulk_ok() { # bulk_ok <upload result> <download result>: 2 MiB each way
  [ "$(field echoed "$1")" = 2097152 ] && [ "$(field received "$2")" = 2097152 ]
}
check_mss() {
  echo "== $mode: mss: handshakes below MSS 536 are dropped and counted, an MTU 576 path works"
  cleanup
  start_server || return
  local nslog
  if [ "$mode" = kernel ]; then
    start_agent home "$HOME_NS" "$ADATA" "$ALOG" || return
    nslog=$ALOG
  else
    # the agent must not run a netstack of its own, so that the target's SYN-ACK reaches the
    # server's netstack as the target sent it
    start_agent home "$HOME_NS" "$ADATA" "$ALOG" kernel || return
    nslog=$SLOG
  fi
  bg "$LAN_NS" $W/wgft-exh-lines.log serve-lines 192.168.50.3 25710
  bg "$LAN_NS" $W/wgft-exh-source.log serve-source 192.168.50.3 25711 2097152
  lan setsid nohup echo -bind 192.168.50.3 -tcp 25712 > $W/wgft-exh-echo.log 2>&1 < /dev/null &
  disown
  must_wait "line server listens" 10 listening $W/wgft-exh-lines.log || return
  must_wait "source server listens" 10 listening $W/wgft-exh-source.log || return
  rule_add --agent home --tcp 41710 --to 192.168.50.3:25710 >/dev/null
  rule_add --agent home --tcp 41711 --to 192.168.50.3:25711 >/dev/null
  rule_add --agent home --tcp 41712 --to 192.168.50.3:25712 >/dev/null
  must_wait "rule forwards before the MSS rewrite" 30 tcp_line_ok 41710 || return

  local r
  if [ "$mode" = kernel ]; then
    cl nft -f - <<'EOF'
table inet exh {
  chain out {
    type filter hook output priority 0;
    tcp dport 41710 tcp flags & (syn | ack) == syn tcp option maxseg size set 48
  }
}
EOF
  else
    lan nft -f - <<'EOF'
table inet exh {
  chain out {
    type filter hook output priority 0;
    tcp sport 25710 tcp flags & (syn | ack) == syn | ack tcp option maxseg size set 48
  }
}
EOF
  fi
  r=$(cl $TRAFFIC tcp-rtt 198.51.100.1 41710 1 8 2>&1 | tail -1)
  echo "   with MSS 48: $r"
  must_wait "the MSS drop is logged" 20 log_has "$nslog" 'dropped TCP handshakes that advertise an MSS below 536'
  local l; l=$(mss_log "$nslog")
  echo "   drop log: ${l:-none}"
  okcheck "no connection forms through a handshake with MSS 48" "$(yes_if [ "$(field ok "$r")" = 0 ])"
  okcheck "the handshake is dropped and counted" "$(yes_if ge "$(echo "$l" | grep -oE '[0-9]+ dropped since' | grep -oE '^[0-9]+')" 1)"
  cl nft delete table inet exh 2>/dev/null; lan nft delete table inet exh 2>/dev/null
  okcheck "the same port connects once the MSS is ordinary again" "$(yes_if wait_until 20 tcp_line_ok 41710)"

  if [ "$mode" = kernel ]; then
    cl ip link set eth0 mtu 576
    echo "   client link MTU 576: the client advertises MSS 536 to the agent's netstack"
  else
    lan ip link set eth0 mtu 576
    echo "   target link MTU 576: the target advertises MSS 536 to the server's netstack"
  fi
  local up down
  up=$(cl $TRAFFIC bulk-up 198.51.100.1 41712 2097152 2>&1 | tail -1)
  down=$(cl $TRAFFIC bulk-down 198.51.100.1 41711 2>&1 | tail -1)
  echo "   upload: $up"
  echo "   download: $down"
  okcheck "ordinary TCP over an MTU 576 path moves 2 MiB each way" "$(yes_if bulk_ok "$up" "$down")"
  cl ip link set eth0 mtu 1500; lan ip link set eth0 mtu 1500
}

# ---------------------------------------------------------------------------------------------
# acceptq
# ---------------------------------------------------------------------------------------------
check_acceptq() {
  echo "== $mode: acceptq: the agent's accept queue behind a kernel-mode server"
  if [ "$mode" != kernel ]; then skip "acceptq"; return; fi
  cleanup
  start_server || return
  start_agent home "$HOME_NS" "$ADATA" "$ALOG" || return
  lan setsid nohup echo -bind 192.168.50.3 -tcp 25720 > /dev/null 2>&1 < /dev/null &
  disown
  rule_add --agent home --tcp 41720 --to 192.168.50.3:25720 >/dev/null
  must_wait "rule forwards" 30 tcp_echo_ok 41720 || return
  local i srcs=""
  for i in $(seq 10 41); do cl ip addr add "198.51.100.$i/24" dev eth0 2>/dev/null; srcs+="198.51.100.$i,"; done
  srcs=${srcs%,}
  local apid base_line; apid=$(find_agent_pid "$ADATA"); base_line=$(lines_of "$ALOG")
  : > $W/wgft-exh-rss.txt
  SAMPLER=$(sample_rss "$apid" $W/wgft-exh-rss.txt)
  # 32 sources x 72 = 2304 attempts, past the server's default of 2048 TCP flows; each source stays
  # under the per-source cap of 128.
  bg "$CLIENT_NS" $W/wgft-exh-hold.log hold 198.51.100.1 41720 "$srcs" 72 32768 15
  : > $W/wgft-exh-queue.txt
  local t0=$SECONDS est rel
  while (( SECONDS - t0 < 14 )); do
    est=$(cl ss -Htn state established "( dport = :41720 )" | wc -l)
    rel=$(home ss -Htn state established "( dport = :25720 )" | wc -l)
    echo "$est $rel $((est - rel))" >> $W/wgft-exh-queue.txt
    sleep 0.1
  done
  must_wait "the connections are opened" 30 log_has $W/wgft-exh-hold.log "^attempted="
  local hold qmax estmax relmax heap rss
  hold=$(grep '^attempted=' $W/wgft-exh-hold.log)
  qmax=$(awk '{print $3}' $W/wgft-exh-queue.txt | sort -n | tail -1)
  estmax=$(awk '{print $1}' $W/wgft-exh-queue.txt | sort -n | tail -1)
  relmax=$(awk '{print $2}' $W/wgft-exh-queue.txt | sort -n | tail -1)
  heap=$(live_heap "$ALOG" "$base_line" "$(lines_of "$ALOG")" max)
  must_wait "the client closes them" 30 none_held
  kill "$SAMPLER" 2>/dev/null; SAMPLER=
  rss=$(max_of $W/wgft-exh-rss.txt)
  echo "   client: $hold"
  echo "   established at the client, max $estmax; relayed to the target by the agent, max $relmax"
  echo "   established but not yet relayed (an upper bound on the accept queue), max $qmax over $(wc -l < $W/wgft-exh-queue.txt) samples"
  echo "   agent live heap MiB max ${heap:-none}, RSS MiB max ${rss:-?}"
  local last; last=$(tail -1 $W/wgft-exh-queue.txt)
  echo "   at the end of the hold: established at the client ${last%% *}, relayed $(echo "$last" | cut -d' ' -f2); the agent reset the rest past its flow budget"
  okcheck "once the burst settles, nothing is left waiting: every connection still established is relayed" \
    "$(yes_if [ "$(echo "$last" | cut -d' ' -f3)" = 0 ])"
  okcheck "the agent forwards again after the connections close" "$(yes_if wait_until 20 tcp_echo_ok 41720)"
}
tcp_echo_ok() { [[ "$(cl bash -c "echo hi | timeout -k 5 20 socat -t 1 -T 10 - TCP:198.51.100.1:$1" 2>/dev/null)" == *tcp-echo* ]]; }
none_held() { [ "$(home ss -Htn state established "( dport = :25720 )" | wc -l)" = 0 ]; }

# ---------------------------------------------------------------------------------------------
# ackflood
# ---------------------------------------------------------------------------------------------
check_ackflood() {
  echo "== $mode: ackflood: duplicate ACKs through WireGuard to one netstack connection"
  if [ "$mode" != kernel ]; then skip "ackflood"; return; fi
  cleanup
  # without timestamps the flood's bare 20-byte TCP header is a segment the agent processes
  SAVED_TS=$(cl sysctl -n net.ipv4.tcp_timestamps)
  cl sysctl -qw net.ipv4.tcp_timestamps=0
  start_server || return
  start_agent home "$HOME_NS" "$ADATA" "$ALOG" || return
  bg "$LAN_NS" $W/wgft-exh-lines.log serve-lines 192.168.50.3 25730
  must_wait "line server listens" 10 listening $W/wgft-exh-lines.log || return
  rule_add --agent home --tcp 41730 --to 192.168.50.3:25730 >/dev/null
  rule_add --agent home --tcp 41731 --to 192.168.50.3:25730 >/dev/null
  must_wait "rule forwards" 30 tcp_line_ok 41730 || return
  must_wait "rule forwards" 30 tcp_line_ok 41731 || return
  local apid base; apid=$(find_agent_pid "$ADATA")
  base=$(cl $TRAFFIC tcp-rtt 198.51.100.1 41731 0.05 10 | tail -1)
  local l0 tx0 tx1 heap rss flood other
  l0=$(lines_of "$ALOG")
  : > $W/wgft-exh-rss.txt
  SAMPLER=$(sample_rss "$apid" $W/wgft-exh-rss.txt)
  tx0=$(vps cat /sys/class/net/wgft0/statistics/tx_packets)
  bg "$CLIENT_NS" $W/wgft-exh-flood.log ackflood 198.51.100.1 41730 15
  must_wait "the flood starts" 10 log_has $W/wgft-exh-flood.log "progress=flooding" || return
  other=$(cl $TRAFFIC tcp-rtt 198.51.100.1 41731 0.05 14 | tail -1)
  must_wait "the flood ends" 30 log_has $W/wgft-exh-flood.log "^sent="
  tx1=$(vps cat /sys/class/net/wgft0/statistics/tx_packets)
  kill "$SAMPLER" 2>/dev/null; SAMPLER=
  flood=$(grep '^sent=' $W/wgft-exh-flood.log)
  heap=$(live_heap "$ALOG" 0 "$l0" last)
  local hmax; hmax=$(live_heap "$ALOG" "$l0" "$(lines_of "$ALOG")" max)
  rss=$(max_of $W/wgft-exh-rss.txt)
  echo "   flood: $flood"
  echo "   packets the server sent into WireGuard during the flood: $((tx1 - tx0))"
  echo "   other connection idle: $base"
  echo "   other connection during the flood: $other"
  echo "   agent live heap MiB: before ${heap:-none}, max during ${hmax:-none}; RSS MiB max ${rss:-?}"
  okcheck "the flooded connection still echoes afterwards" "$(yes_if [ "$(field alive_after "$flood")" = 1 ])"
  okcheck "the other connection answers throughout the flood" "$(yes_if [ "$(field fail "$other")" = 0 ])"
}

# ---------------------------------------------------------------------------------------------
# wgstall
# ---------------------------------------------------------------------------------------------
check_wgstall() {
  echo "== $mode: wgstall: one agent's flood toward the server and the other agent's latency"
  if [ "$mode" != userspace ]; then skip "wgstall"; return; fi
  cleanup
  start_server || return
  start_agent home "$HOME_NS" "$ADATA" "$ALOG" || return
  start_agent lan "$LAN_NS" "$BDATA" "$BLOG" || return
  bg "$LAN_NS" $W/wgft-exh-blast.log serve-udp-blast 192.168.50.3 25740 1200 20
  bg "$LAN_NS" $W/wgft-exh-lines.log serve-lines 192.168.50.3 25741
  bg "$LAN_NS" $W/wgft-exh-uecho.log serve-udp-echo 192.168.50.3 25742
  must_wait "blast server listens" 10 listening $W/wgft-exh-blast.log || return
  must_wait "line server listens" 10 listening $W/wgft-exh-lines.log || return
  must_wait "udp echo listens" 10 listening $W/wgft-exh-uecho.log || return
  rule_add --agent home --udp 41740 --to 192.168.50.3:25740 >/dev/null
  rule_add --agent lan --tcp 41741 --to 192.168.50.3:25741 >/dev/null
  rule_add --agent lan --udp 41742 --to 192.168.50.3:25742 >/dev/null
  must_wait "the other agent's rule forwards" 30 tcp_line_ok 41741 || return
  local spid; spid=$(find_pid 'server run')
  local bt bu dt du at au drops0 drops1 l0 heap hmax rss blast
  cl $TRAFFIC udp-rtt 198.51.100.1 41742 0.05 10 > $W/wgft-exh-bu.log 2>&1 &
  local up=$!
  bt=$(cl $TRAFFIC tcp-rtt 198.51.100.1 41741 0.05 10 | tail -1); wait "$up"; bu=$(tail -1 $W/wgft-exh-bu.log)
  l0=$(lines_of "$SLOG")
  drops0=$(wg_drops)
  : > $W/wgft-exh-rss.txt
  SAMPLER=$(sample_rss "$spid" $W/wgft-exh-rss.txt)
  # one datagram starts 20 s of 1200-byte datagrams from the first agent's target
  cl bash -c "echo go | socat -u - UDP:198.51.100.1:41740"
  must_wait "the blast starts" 10 blast_started || return
  cl $TRAFFIC udp-rtt 198.51.100.1 41742 0.05 18 > $W/wgft-exh-du.log 2>&1 &
  up=$!
  dt=$(cl $TRAFFIC tcp-rtt 198.51.100.1 41741 0.05 18 | tail -1); wait "$up"; du=$(tail -1 $W/wgft-exh-du.log)
  must_wait "the blast ends" 15 log_has $W/wgft-exh-blast.log "^blast_to="
  drops1=$(wg_drops)
  kill "$SAMPLER" 2>/dev/null; SAMPLER=
  blast=$(grep '^blast_to=' $W/wgft-exh-blast.log)
  heap=$(live_heap "$SLOG" 0 "$l0" last)
  hmax=$(live_heap "$SLOG" "$l0" "$(lines_of "$SLOG")" max)
  rss=$(max_of $W/wgft-exh-rss.txt)
  cl $TRAFFIC udp-rtt 198.51.100.1 41742 0.05 5 > $W/wgft-exh-au.log 2>&1 &
  up=$!
  at=$(cl $TRAFFIC tcp-rtt 198.51.100.1 41741 0.05 5 | tail -1); wait "$up"; au=$(tail -1 $W/wgft-exh-au.log)
  echo "   first agent's target: $blast"
  echo "   server WireGuard socket drops during the blast: $((drops1 - drops0))"
  echo "   other agent idle: tcp $bt; udp $bu"
  echo "   other agent during the blast: tcp $dt; udp $du"
  echo "   other agent after the blast: tcp $at; udp $au"
  echo "   server live heap MiB: before ${heap:-none}, max during ${hmax:-none}; RSS MiB max ${rss:-?}"
  okcheck "the other agent forwards TCP again after the blast" "$(yes_if flow_ok "$at")"
  okcheck "the other agent forwards UDP again after the blast: at least 95 % answered" \
    "$(yes_if answered_95 "$au")"
}
blast_started() { [ -n "$(home ss -Huan "( dport = :25740 )" 2>/dev/null)" ] || log_has $W/wgft-exh-blast.log "^blast_to="; }
# wg_drops: the kernel's drop count of the server's WireGuard UDP socket (ss -m's d field)
wg_drops() { vps ss -Huanm "( sport = :51820 )" | grep -oE ',d[0-9]+\)' | grep -oE '[0-9]+' | head -1; }

for c in $CHECKS; do
  "check_$c"
done
if [ "$fail" = 0 ]; then echo "== $mode: ALL PASS"; else echo "== $mode: FAILURES"; fi
exit "$fail"
