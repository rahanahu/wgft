#!/usr/bin/env bash
# lifecycle.sh pins down today's observable lifecycle behaviour of the SERVER (vpsd) as a
# migration oracle for the upcoming dataplane rewrite (planner, backends, transactional apply).
# Unlike e2e.sh it is not one scenario; each check sets up and tears down its own
# server/agent/target, so checks can be read (and re-run) independently. A check that does not
# apply to the given mode prints SKIP with the reason instead of running.
#
#   lab/lab exec vm bash /wgft/lab/lifecycle.sh kernel
#   lab/lab exec vm bash /wgft/lab/lifecycle.sh userspace
#   lab/lab exec vm bash /wgft/lab/lifecycle.sh kernel 3 3b   # only checks 3 and 3b
#
# Checks:
#   1. server restart: kernel mode keeps forwarding an established TCP session and a UDP
#      stream, and keeps wg0/table inet wgft/conntrack entries, while `vpsd` is stopped for a
#      few seconds (design 9, 10.3 sections: wg0 and the nft table outlive the process).
#      Userspace mode stops forwarding while stopped (design 6.3 section); only new flows work
#      after restart.
#   2. adding, retargeting, disabling and deleting an unrelated rule B, and a group/note edit
#      of rule A, do not cut A's long-lived TCP session and UDP stream. Changing A's own target,
#      or deleting A, does cut them (design 6.1 conntrack convergence, design 7 port-based
#      reconciliation).
#   3. kernel mode only: a proxy rule whose port is already bound by another process logs the
#      bind failure without an nft accounting line for that port; the next apply (port freed)
#      adds the line; same across a server restart (design 6.2 section). 3b: a failed nftables
#      table swap (another process owns table inet wgft) rolls back a newly-opened proxy
#      listener and leaves an already-committed one untouched, until the obstruction is gone
#      and the next apply converges (internal/vpsd/proxyrelay's two-phase Prepare/Commit/
#      Rollback).
#   4. `server teardown`, with and without --purge, removes only wgft's own wg interface and
#      nft table, leaving a foreign wg interface and a foreign nft table with a rule untouched
#      (design 10.3 section). internal/vpsd/teardown_lab_test.go already covers this at the
#      package level (`lab/lab test internal/vpsd`); this check drives the same scenario
#      through the CLI, in the netns topology, end to end.
#   5. under the default flow caps (design 7 section), holding and flooding past them keeps RSS
#      under the derived memory soft limit plus a margin, for the userspace server's own relay
#      and for the agent (which relays every connection regardless of the server's mode).
#
# Requires `lab/lab build` (wgft and echo in /usr/local/bin of the VM) and the netns topology
# (`lab/lab net up`). Leftovers from earlier runs are killed first. Waits for the admin API
# (and for agent registration) to respond instead of using fixed sleeps wherever the timing of
# a check matters; short fixed sleeps remain where a nftables/conntrack change just needs to
# take effect, matching e2e.sh and friends.
set -u
ulimit -n 100000 2>/dev/null || true  # check 5 floods thousands of sockets from the client
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: lifecycle.sh kernel|userspace [check...]" >&2; exit 2;; esac
shift || true
# Optional check names after the mode (1 2 3 3b 4 5) run only those checks; none runs all of them.
ALL_CHECKS="1 2 3 3b 4 5"
CHECKS="${*:-$ALL_CHECKS}"
for c in $CHECKS; do
  case " $ALL_CHECKS " in *" $c "*) ;; *) echo "lifecycle.sh: unknown check '$c' (use: $ALL_CHECKS)" >&2; exit 2;; esac
done

ADMIN=127.0.0.1:8686
PY=/tmp/wgft-lifecycle-py
# design 7: 32 MiB + 12 KiB * WGFT_MAX_UDP_FLOWS(8192, default) + 44 KiB * WGFT_MAX_TCP_FLOWS(2048, default).
SOFT_LIMIT_MIB=216
# RSS is expected to sit well under the soft limit here, since each check only fills one rule
# (capped at half the process-wide total) rather than every rule at once; the margin exists to
# absorb Go's GC catching up rather than to paper over a real regression.
MARGIN_MIB=100
fail=0

check() { # check <label> <expected-substring> <actual>
  # an empty expected substring matches anything, so it would always pass; refuse it
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
absent() { # absent <label> <substring-that-must-not-appear> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty substring (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "FAIL  $1: got '$3'"; fail=1; else echo "PASS  $1"; fi
}
# field <name> <text>: the integer after "<name>=" in text, or empty
field() { echo "$2" | grep -oE "$1=[0-9]+" | head -1 | cut -d= -f2; }
okcheck() { # okcheck <label> <ok-if-true 1/0>
  if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi
}
skip() { echo "SKIP  $1 (does not apply to $mode mode)"; }

vps() { ip netns exec vps "$@"; }
client() { ip netns exec client bash -c "$1"; }

wait_admin() { for _ in $(seq 1 60); do vps wgft agent ls --admin "$ADMIN" >/dev/null 2>&1 && return 0; sleep 0.5; done; echo "!! admin api did not come up" >&2; return 1; }
wait_agent() { for _ in $(seq 1 60); do vps wgft agent ls --admin "$ADMIN" 2>/dev/null | tail -1 | grep -q "$1" && return 0; sleep 0.5; done; echo "!! agent $1 did not register" >&2; return 1; }

ensure_wgftlab() { id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab; }

# start_server <data-dir> <log-file>: starts `wgft server run` in $mode, backgrounded.
start_server() {
  local data=$1 log=$2
  if [ "$mode" = userspace ]; then
    ensure_wgftlab
    chown wgftlab "$data"
    vps setsid nohup runuser -u wgftlab -- wgft server run --mode "$mode" --data-dir "$data" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
      > "$log" 2>&1 < /dev/null &
  else
    vps setsid nohup wgft server run --mode "$mode" --data-dir "$data" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
      > "$log" 2>&1 < /dev/null &
  fi
  disown
}
kill_server() {
  for p in $(pgrep -x wgft); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q ' server run' && kill "$p"
  done
  sleep 1
}
kill_all() { pkill -x wgft; pkill -x echo; pkill -x socat; sleep 1; }
reset_kernel_state() {
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  vps ip link del wg9 2>/dev/null
  vps nft delete table ip foreigntest 2>/dev/null
}
# flows_established <listen-port>: number of established flows from the client, for the
# before/after comparisons that show a change cutting (or not cutting) an open TCP session.
flows_established() {
  if [ "$mode" = kernel ]; then
    vps conntrack -L -p tcp --dport "$1" --src 198.51.100.2 2>/dev/null | grep -c ESTABLISHED
  else
    vps ss -tn state established "( sport = :$1 )" | grep -c 198.51.100.2
  fi
}
# set_target <rule-id> <new-target>: changes one rule's target via export + `rule import`
# (a full-set batch upsert), since the CLI's `rule set` only touches group/note (design 5.4).
set_target() {
  local id=$1 target=$2 f=/tmp/wgft-lifecycle-settarget.json
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['id'] == '$id':
        r['target'] = '$target'
json.dump(d['rules'], open('$f', 'w'))
"
  vps wgft rule import "$f" --admin "$ADMIN" >/dev/null
}
rss_mib() { awk '/VmRSS/{print int($2/1024)}' "/proc/$1/status" 2>/dev/null; }
# find_wgft_pid <substring>: the pid of the "wgft" process whose cmdline contains <substring>
# (e.g. "server run" or "agent run"). Matches on the exact comm name first (pgrep -x wgft, safe
# against any wrapping shell or helper process that happens to have the same words in its own
# argv, e.g. `runuser -u wgftlab -- wgft server run ...` or incus's own exec plumbing) and only
# then greps cmdline, the same technique kill_server() uses.
find_wgft_pid() {
  local p
  for p in $(pgrep -x wgft); do
    if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q " $1"; then echo "$p"; return; fi
  done
}

# write_helpers writes the python helpers used by several checks once, outside the repo's
# read-only share (VM-local /tmp). Kept as standalone files instead of inline heredocs because
# they are reused by more than one check and are long enough that nesting them inside the
# client()/vps() wrappers would need two layers of shell quoting.
write_helpers() {
  mkdir -p "$PY"
  cat > "$PY/tcpprobe.py" <<'PYEOF'
# tcpprobe.py <dst-ip> <port> <rounds> <interval>
# Connects once, sends a 10-byte chunk every <interval> seconds for <rounds> rounds without
# closing, then half-closes and reads tools/echo's final "tcp-echo ... got=<n>; ..." reply.
# Prints "sent=<bytes> broke_at=<round-or-None> got=<reply-or-error>": whether every byte sent
# across the whole session (including any window where the peer might have been unreachable)
# was actually delivered is the end-to-end proof, not just that sendall() did not raise.
import socket, sys, time

dst, port, rounds, interval = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect((dst, port))
except OSError as e:
    print('sent=0 broke_at=connect got=%r' % str(e))
    sys.exit(0)

sent = 0
broke_at = None
for i in range(rounds):
    chunk = b'x' * 10
    try:
        s.sendall(chunk)
        sent += len(chunk)
    except OSError:
        broke_at = i
        break
    time.sleep(interval)

got = None
try:
    s.shutdown(socket.SHUT_WR)
    s.settimeout(5)
    buf = b''
    while True:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    got = buf.decode(errors='replace').strip()
except OSError as e:
    got = 'recv-error:' + str(e)

print('sent=%d broke_at=%s got=%r' % (sent, broke_at, got))
PYEOF
  cat > "$PY/udpprobe.py" <<'PYEOF'
# udpprobe.py <dst-ip> <port> <rounds> <interval>
# One UDP socket, one datagram per round, checking for an echo each time. Prints a final
# "summary oks=<n> fails=<n> failed_rounds=<csv>" line.
import socket, sys, time

dst, port, rounds, interval = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(0.8)
oks = 0
fails = []
for i in range(rounds):
    try:
        s.sendto(('p%d' % i).encode(), (dst, port))
        s.recvfrom(2048)
        oks += 1
    except OSError:
        fails.append(i)
    time.sleep(interval)
print('summary oks=%d fails=%d failed_rounds=%s' % (oks, len(fails), ','.join(map(str, fails))))
PYEOF
  cat > "$PY/flood.py" <<'PYEOF'
# flood.py udp|tcp <dst-ip> <dst-port> <src-ips-csv> <attempts-per-src> [hold-seconds]
# Opens sockets from each of several source addresses (threaded), optionally holds them open
# for <hold-seconds> before closing, and prints "<kind>: attempted=<n> established=<n>" (tcp)
# or "<kind>: attempted=<n> answered=<n>" (udp). Used to fill and overflow the flow caps.
import socket, sys, threading, time

kind, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
srcs = sys.argv[4].split(',')
per = int(sys.argv[5])
hold = float(sys.argv[6]) if len(sys.argv) > 6 else 0

socks = []
lock = threading.Lock()


def one(src):
    if kind == 'udp':
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((src, 0))
        s.settimeout(0.3)
        s.sendto(b'f', (dst, port))
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((src, 0))
        s.settimeout(2)
        try:
            s.connect((dst, port))
        except OSError:
            s.close()
            return
    with lock:
        socks.append(s)


threads = []
for src in srcs:
    for _ in range(per):
        t = threading.Thread(target=one, args=(src,))
        threads.append(t)
        t.start()
        if len(threads) % 100 == 0:
            time.sleep(0.02)
for t in threads:
    t.join()

if kind == 'udp':
    time.sleep(1.5)
    answered = 0
    for s in socks:
        s.settimeout(0.05)
        try:
            s.recvfrom(2048)
            answered += 1
        except OSError:
            pass
    print('udp: attempted=%d answered=%d' % (len(srcs) * per, answered))
else:
    print('tcp: attempted=%d established=%d' % (len(srcs) * per, len(socks)))

if hold:
    time.sleep(hold)
for s in socks:
    try:
        s.close()
    except OSError:
        pass
PYEOF
}

# ---------------------------------------------------------------------------------------------
# check 1: server restart
# ---------------------------------------------------------------------------------------------
check1() {
  echo "== $mode: check 1: server restart keeps (kernel) or drops (userspace) in-flight flows"
  local DATA=/tmp/wgft-lifecycle-c1 ADATA=/tmp/wgft-lifecycle-c1-agent
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"; mkdir -p "$DATA"

  start_server "$DATA" /tmp/wgft-lifecycle-c1-server.log
  if ! wait_admin; then echo "FAIL  check1 setup: admin api never came up"; fail=1; return; fi
  local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-lifecycle-c1-agent.log 2>&1 < /dev/null &
  disown
  ip netns exec lan setsid nohup echo -bind 192.168.50.3 -tcp 25580 -udp 19150 > /tmp/wgft-lifecycle-c1-echo.log 2>&1 < /dev/null &
  disown
  if ! wait_agent home; then echo "FAIL  check1 setup: agent never registered"; fail=1; return; fi

  vps wgft rule add --agent home --tcp 39980 --to 192.168.50.3:25580 --admin "$ADMIN" >/dev/null
  vps wgft rule add --agent home --udp 27020 --to 192.168.50.3:19150 --admin "$ADMIN" >/dev/null
  sleep 2
  check "tcp works before the restart" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39980')"
  check "udp works before the restart" "udp-echo" "$(client 'echo hi | socat -t 3 - UDP:198.51.100.1:27020')"

  local rounds=20 interval=0.5
  ip netns exec client python3 "$PY/tcpprobe.py" 198.51.100.1 39980 "$rounds" "$interval" \
    > /tmp/wgft-lifecycle-c1-tcp.log 2>&1 < /dev/null &
  local tcp_pid=$!
  ip netns exec client python3 "$PY/udpprobe.py" 198.51.100.1 27020 "$rounds" "$interval" \
    > /tmp/wgft-lifecycle-c1-udp.log 2>&1 < /dev/null &
  local udp_pid=$!

  sleep 2
  kill_server
  if [ "$mode" = kernel ]; then
    okcheck "wg0 still present while the server is stopped" "$(vps ip link show wgft0 >/dev/null 2>&1 && echo 1 || echo 0)"
    okcheck "table inet wgft still present while the server is stopped" "$(vps nft list table inet wgft >/dev/null 2>&1 && echo 1 || echo 0)"
  else
    skip "wg0/table inet wgft presence while stopped (userspace mode has neither)"
  fi
  local before_line before_sport
  if [ "$mode" = kernel ]; then
    before_line=$(vps conntrack -L -p tcp --dport 39980 --src 198.51.100.2 2>/dev/null | grep ESTABLISHED | head -1)
    before_sport=$(echo "$before_line" | grep -oE 'sport=[0-9]+' | head -1)
  fi
  sleep 5
  start_server "$DATA" /tmp/wgft-lifecycle-c1-server2.log
  if ! wait_admin; then echo "FAIL  check1: admin api never came back up after the restart"; fail=1; fi

  if [ "$mode" = kernel ]; then
    sleep 1
    local after_line after_sport
    after_line=$(vps conntrack -L -p tcp --dport 39980 --src 198.51.100.2 2>/dev/null | grep ESTABLISHED | head -1)
    after_sport=$(echo "$after_line" | grep -oE 'sport=[0-9]+' | head -1)
    okcheck "the tcp conntrack entry is found before the restart" "$([ -n "$before_sport" ] && echo 1 || echo 0)"
    check "the same tcp conntrack entry (same source port) persists across the restart" "$before_sport" "$after_sport"
  fi

  wait "$tcp_pid" "$udp_pid" 2>/dev/null
  local want_bytes=$((rounds * 10))
  if [ "$mode" = kernel ]; then
    check "tcp session survives the restart unbroken (full byte count delivered)" "got=$want_bytes;" "$(cat /tmp/wgft-lifecycle-c1-tcp.log)"
    check "udp stream survives the restart unbroken" "oks=$rounds fails=0" "$(cat /tmp/wgft-lifecycle-c1-udp.log)"
  else
    local tcp_log; tcp_log=$(cat /tmp/wgft-lifecycle-c1-tcp.log)
    if [[ "$tcp_log" == *"got=$want_bytes;"* ]]; then
      echo "FAIL  userspace tcp session should not survive the stop uninterrupted"; fail=1
    else
      echo "PASS  userspace tcp session does not survive the stop uninterrupted (matches design 6.3: vpsd を止めると転送も止まる); log: $tcp_log"
    fi
    local udp_log; udp_log=$(cat /tmp/wgft-lifecycle-c1-udp.log)
    if [[ "$udp_log" == *"fails=0"* ]]; then
      echo "FAIL  userspace udp stream should have seen failures while the server was stopped"; fail=1
    else
      echo "PASS  userspace udp stream sees failures while the server is stopped (matches design 6.3); log: $udp_log"
    fi
  fi

  echo "-- new flows work after the restart, in both modes"
  check "new tcp flow works after restart" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39980')"
  check "new udp flow works after restart" "udp-echo" "$(client 'echo hi | socat -t 3 - UDP:198.51.100.1:27020')"

  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"
}

# ---------------------------------------------------------------------------------------------
# check 2: rule add/update/disable/delete of an unrelated rule does not cut a flow; changing
# the flow's own rule's target, or deleting it, does.
# ---------------------------------------------------------------------------------------------
check2() {
  echo "== $mode: check 2: unrelated rule churn does not cut A; changing A's target or deleting A does"
  local DATA=/tmp/wgft-lifecycle-c2 ADATA=/tmp/wgft-lifecycle-c2-agent
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"; mkdir -p "$DATA"

  start_server "$DATA" /tmp/wgft-lifecycle-c2-server.log
  if ! wait_admin; then echo "FAIL  check2 setup: admin api never came up"; fail=1; return; fi
  local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-lifecycle-c2-agent.log 2>&1 < /dev/null &
  disown
  ip netns exec lan setsid nohup echo -bind 192.168.50.3 -tcp 25581 -udp 19151 > /tmp/wgft-lifecycle-c2-echo.log 2>&1 < /dev/null &
  disown
  if ! wait_agent home; then echo "FAIL  check2 setup: agent never registered"; fail=1; return; fi

  local a_tcp a_udp
  a_tcp=$(vps wgft rule add --agent home --tcp 39982 --to 192.168.50.3:25581 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  a_udp=$(vps wgft rule add --agent home --udp 27022 --to 192.168.50.3:19151 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  sleep 2
  check "tcp on A works before anything" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39982')"
  check "udp on A works before anything" "udp-echo" "$(client 'echo hi | socat -t 3 - UDP:198.51.100.1:27022')"

  echo "-- add / retarget / disable / delete an unrelated rule B, and edit A's own group/note"
  local rounds=16 interval=0.5
  ip netns exec client python3 "$PY/tcpprobe.py" 198.51.100.1 39982 "$rounds" "$interval" \
    > /tmp/wgft-lifecycle-c2-tcpA.log 2>&1 < /dev/null &
  local tcp_pid=$!
  ip netns exec client python3 "$PY/udpprobe.py" 198.51.100.1 27022 "$rounds" "$interval" \
    > /tmp/wgft-lifecycle-c2-udpA.log 2>&1 < /dev/null &
  local udp_pid=$!

  local b
  b=$(vps wgft rule add --agent home --tcp 39990 --to 192.168.50.3:25581 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  sleep 1
  set_target "$b" 192.168.50.3:25582
  sleep 1
  vps wgft rule disable "$b" --admin "$ADMIN" >/dev/null
  sleep 1
  vps wgft rule rm "$b" --admin "$ADMIN" >/dev/null
  sleep 1
  vps wgft rule set "$a_tcp" --group lifecycle --note "changed mid-flow" --admin "$ADMIN" >/dev/null
  vps wgft rule set "$a_udp" --group lifecycle --note "changed mid-flow" --admin "$ADMIN" >/dev/null
  sleep 1

  wait "$tcp_pid" "$udp_pid" 2>/dev/null
  local want_bytes=$((rounds * 10))
  check "tcp on A survives add/retarget/disable/delete of B and A's own note edit" "got=$want_bytes;" "$(cat /tmp/wgft-lifecycle-c2-tcpA.log)"
  check "udp on A survives the same churn" "oks=$rounds fails=0" "$(cat /tmp/wgft-lifecycle-c2-udpA.log)"

  echo "-- changing A's own target does cut its flows (design 6.1 convergence / design 7 reconciliation)"
  local a_tcp2 a_udp2
  a_tcp2=$(vps wgft rule add --agent home --tcp 39983 --to 192.168.50.3:25581 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  a_udp2=$(vps wgft rule add --agent home --udp 27023 --to 192.168.50.3:19151 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  sleep 2
  client 'python3 -c "
import socket, time
s = socket.create_connection((\"198.51.100.1\", 39983), timeout=5); s.send(b\"x\"); time.sleep(6)
"' &
  sleep 2
  local before after
  before=$(flows_established 39983)
  set_target "$a_tcp2" 192.168.50.3:25599
  sleep 2
  after=$(flows_established 39983)
  wait
  check "changing A's target cuts A's open tcp session" "before=1 after=0" "before=$before after=$after"

  check "udp on the second A still worked before the target change" "udp-echo" "$(client 'echo hi | socat -t 3 - UDP:198.51.100.1:27023')"
  set_target "$a_udp2" 192.168.50.3:19199
  sleep 1
  absent "changing A's target silences its udp flow" "udp-echo" "$(client 'echo hi | socat -t 2 - UDP:198.51.100.1:27023' 2>&1)"

  echo "-- deleting A cuts its flows too"
  local a_tcp3
  a_tcp3=$(vps wgft rule add --agent home --tcp 39984 --to 192.168.50.3:25581 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  sleep 2
  client 'python3 -c "
import socket, time
s = socket.create_connection((\"198.51.100.1\", 39984), timeout=5); s.send(b\"x\"); time.sleep(6)
"' &
  sleep 2
  before=$(flows_established 39984)
  vps wgft rule rm "$a_tcp3" --admin "$ADMIN" >/dev/null
  sleep 2
  after=$(flows_established 39984)
  wait
  check "deleting A cuts A's open tcp session" "before=1 after=0" "before=$before after=$after"

  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"
}

# ---------------------------------------------------------------------------------------------
# check 3: proxy listener bind failure does not leak into nftables (kernel mode only)
# ---------------------------------------------------------------------------------------------
check3() {
  echo "== $mode: check 3: a proxy bind failure does not add an nft accounting line"
  if [ "$mode" != kernel ]; then
    skip "proxy bind-failure nft accounting (proxy mode's nft lines only exist in kernel mode, design 6.1/6.2)"
    return
  fi
  local DATA=/tmp/wgft-lifecycle-c3 ADATA=/tmp/wgft-lifecycle-c3-agent
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"; mkdir -p "$DATA"

  start_server "$DATA" /tmp/wgft-lifecycle-c3-server.log
  if ! wait_admin; then echo "FAIL  check3 setup: admin api never came up"; fail=1; return; fi
  local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-lifecycle-c3-agent.log 2>&1 < /dev/null &
  disown
  ip netns exec lan setsid nohup echo -bind 192.168.50.3 -tcp 25590 > /tmp/wgft-lifecycle-c3-echo.log 2>&1 < /dev/null &
  disown
  if ! wait_agent home; then echo "FAIL  check3 setup: agent never registered"; fail=1; return; fi

  src_flow_lines() { vps nft list table inet wgft 2>/dev/null | grep -c "dport 8461 .*src_flow"; }
  squat() { vps setsid nohup socat TCP-LISTEN:8461,reuseaddr,fork EXEC:/bin/cat > /tmp/wgft-lifecycle-c3-squat.log 2>&1 < /dev/null & disown; sleep 0.5; }
  unsquat() { pkill -x socat; sleep 0.5; }

  echo "-- rule creation while another process owns 8461"
  squat
  vps wgft rule add --agent home --tcp 8461 --to 192.168.50.3:25590 --proxy --admin "$ADMIN" >/dev/null
  sleep 2
  okcheck "no nft accounting line while the port is squatted" "$([ "$(src_flow_lines)" = 0 ] && echo 1 || echo 0)"
  check "bind failure is logged" "cannot open listener for 8461" "$(grep -o 'cannot open listener for 8461.*' /tmp/wgft-lifecycle-c3-server.log | tail -1)"

  echo "-- the port is freed; the next apply opens it"
  unsquat
  vps wgft rule add --agent home --tcp 39985 --to 192.168.50.3:25590 --admin "$ADMIN" >/dev/null
  sleep 2
  okcheck "nft accounting line appears once the port is free" "$([ "$(src_flow_lines)" -ge 1 ] && echo 1 || echo 0)"

  echo "-- restart while another process owns 8461"
  kill_server
  squat
  start_server "$DATA" /tmp/wgft-lifecycle-c3-server2.log
  if ! wait_admin; then echo "FAIL  check3: admin api never came back up"; fail=1; return; fi
  sleep 2
  okcheck "no nft accounting line after a restart while squatted" "$([ "$(src_flow_lines)" = 0 ] && echo 1 || echo 0)"

  echo "-- restart with the port free"
  kill_server
  unsquat
  start_server "$DATA" /tmp/wgft-lifecycle-c3-server3.log
  if ! wait_admin; then echo "FAIL  check3: admin api never came back up"; fail=1; return; fi
  sleep 2
  okcheck "nft accounting line appears after a restart with the port free" "$([ "$(src_flow_lines)" -ge 1 ] && echo 1 || echo 0)"

  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"
}

# ---------------------------------------------------------------------------------------------
# check 3b: a failed nftables table swap (another process owns table inet wgft) rolls back any
# newly-opened proxy listener and leaves listeners already committed untouched, since the two
# phases (Prepare/Commit/Rollback, internal/vpsd/proxyrelay) are independent of the rule store,
# which already committed the mutation regardless of whether the data plane converged.
# ---------------------------------------------------------------------------------------------
check3b() {
  echo "== $mode: check 3b: a failed nftables swap rolls back new proxy listeners, keeps old ones"
  if [ "$mode" != kernel ]; then
    skip "table-swap rollback (the nft two-phase apply this exercises only exists in kernel mode)"
    return
  fi
  local DATA=/tmp/wgft-lifecycle-c3b ADATA=/tmp/wgft-lifecycle-c3b-agent
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"; mkdir -p "$DATA"

  start_server "$DATA" /tmp/wgft-lifecycle-c3b-server.log
  if ! wait_admin; then echo "FAIL  check3b setup: admin api never came up"; fail=1; return; fi
  local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-lifecycle-c3b-agent.log 2>&1 < /dev/null &
  disown
  ip netns exec lan setsid nohup echo -bind 192.168.50.3 -tcp 25597 > /tmp/wgft-lifecycle-c3b-echo.log 2>&1 < /dev/null &
  disown
  if ! wait_agent home; then echo "FAIL  check3b setup: agent never registered"; fail=1; return; fi

  local r_del
  r_del=$(vps wgft rule add --agent home --tcp 8462 --to 192.168.50.3:25597 --proxy --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  sleep 2
  check "the soon-to-be-deleted proxy rule works before anything" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:8462')"

  echo "-- another process claims ownership of table inet wgft (nft -i fed through a fifo kept open, so it never sees EOF and keeps holding the table)"
  vps nft delete table inet wgft
  rm -f /tmp/wgft-lifecycle-c3b-fifo /tmp/wgft-lifecycle-c3b-owner.log
  mkfifo /tmp/wgft-lifecycle-c3b-fifo
  vps bash -c 'exec 3<>/tmp/wgft-lifecycle-c3b-fifo; nft -i <&3 >/tmp/wgft-lifecycle-c3b-owner.log 2>&1 &'
  sleep 1
  echo 'add table inet wgft { flags owner; }' > /tmp/wgft-lifecycle-c3b-fifo
  sleep 1
  local owner_pid; owner_pid=$(vps pgrep -x nft | head -1)
  okcheck "a foreign table with flags owner exists before we provoke the swap failure" \
    "$(vps nft list table inet wgft 2>/dev/null | grep -q 'flags owner' && echo 1 || echo 0)"

  echo "-- delete the existing proxy rule and add a new one while the table is owned by someone else"
  vps wgft rule rm "$r_del" --admin "$ADMIN" >/dev/null 2>&1
  vps wgft rule add --agent home --tcp 8463 --to 192.168.50.3:25597 --proxy --admin "$ADMIN" >/dev/null 2>&1
  sleep 1
  local r_add
  r_add=$(vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['listen_port'] == '8463':
        print(r['id'])
")
  check "the swap failure is logged" "failed to apply nftables" "$(tail -8 /tmp/wgft-lifecycle-c3b-server.log)"
  check "the deleted rule's listener is kept (fail-static; only Commit closes removed listeners, and it did not run)" \
    "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:8462')"
  check "the newly-added rule's listener is not left open (Rollback closed what Prepare opened)" \
    "Connection refused" "$(client 'echo hi | socat -t 2 - TCP:198.51.100.1:8463' 2>&1)"

  echo "-- the owner process exits; the next apply converges"
  [ -n "$owner_pid" ] && kill "$owner_pid" 2>/dev/null
  sleep 1
  # `rule set --note` would not do here: a note-only edit does not change the agent-facing view
  # (design 5.3/5.4), so it neither bumps the generation nor pushes full state to the agent, and
  # the agent would never learn to open its own listener for the new rule. disable+enable does
  # (design 7: enabled toggles a listener's presence in the declared state).
  vps wgft rule disable "$r_add" --admin "$ADMIN" >/dev/null 2>&1
  sleep 1
  vps wgft rule enable "$r_add" --admin "$ADMIN" >/dev/null 2>&1
  sleep 2
  check "once the owner is gone, the deleted rule's listener is finally closed" "Connection refused" "$(client 'echo hi | socat -t 2 - TCP:198.51.100.1:8462' 2>&1)"
  # the agent only opens its own local listener for the new rule once it receives the full state
  # over the stream, a round trip through the WG tunnel; poll instead of trusting a fixed sleep.
  local got=""
  for _ in $(seq 1 10); do
    got=$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:8463')
    [[ "$got" == *tcp-echo* ]] && break
    sleep 1
  done
  check "once the owner is gone, the newly-added rule now actually works" "tcp-echo" "$got"

  rm -f /tmp/wgft-lifecycle-c3b-fifo /tmp/wgft-lifecycle-c3b-owner.log
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"
}

# ---------------------------------------------------------------------------------------------
# check 4: teardown removes only wgft-owned state (kernel mode only; userspace mode has nothing
# in the kernel to remove, design 6.3)
# ---------------------------------------------------------------------------------------------
check4() {
  echo "== $mode: check 4: teardown removes only wgft-owned wg0/table, with and without --purge"
  if [ "$mode" != kernel ]; then
    skip "teardown of wg0/table inet wgft (userspace mode's teardown only ever purges the database)"
    return
  fi
  local DATA=/tmp/wgft-lifecycle-c4
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA"; mkdir -p "$DATA"

  start_server "$DATA" /tmp/wgft-lifecycle-c4-server.log
  if ! wait_admin; then echo "FAIL  check4 setup: admin api never came up"; fail=1; return; fi
  kill_server

  echo "-- creating a foreign wg interface (wg9) and a foreign nft table with a rule"
  (umask 077; vps wg genkey > /tmp/wgft-lifecycle-c4-foreignkey)
  vps ip link add wg9 type wireguard
  vps wg set wg9 private-key /tmp/wgft-lifecycle-c4-foreignkey
  vps ip addr add 10.99.0.1/24 dev wg9
  vps ip link set wg9 up
  vps nft -f - <<'NFT'
table ip foreigntest {
  chain c {
    type filter hook input priority 0;
    counter
  }
}
NFT

  echo "-- teardown without --purge"
  local out1; out1=$(vps wgft server teardown --data-dir "$DATA" 2>&1)
  check "teardown (no purge) runs" "deleted table inet wgft" "$out1"
  okcheck "own wg interface wgft0 is gone" "$(vps ip link show wgft0 >/dev/null 2>&1 && echo 0 || echo 1)"
  okcheck "own table inet wgft is gone" "$(vps nft list table inet wgft >/dev/null 2>&1 && echo 0 || echo 1)"
  okcheck "foreign wg9 is untouched" "$(vps ip link show wg9 >/dev/null 2>&1 && echo 1 || echo 0)"
  okcheck "foreign table ip foreigntest is untouched" "$(vps nft list table ip foreigntest >/dev/null 2>&1 && echo 1 || echo 0)"
  okcheck "server database is kept without --purge" "$([ -f "$DATA/wgft.sqlite" ] && echo 1 || echo 0)"

  echo "-- restart (recreates wgft0/table from the retained database), stop, teardown --purge"
  start_server "$DATA" /tmp/wgft-lifecycle-c4-server2.log
  if ! wait_admin; then echo "FAIL  check4: admin api never came back up for the second cycle"; fail=1; return; fi
  kill_server
  local out2; out2=$(vps wgft server teardown --data-dir "$DATA" --purge --yes 2>&1)
  check "teardown --purge runs" "deleted $DATA/wgft.sqlite" "$out2"
  okcheck "own wg interface wgft0 is gone (2nd cycle)" "$(vps ip link show wgft0 >/dev/null 2>&1 && echo 0 || echo 1)"
  okcheck "own table inet wgft is gone (2nd cycle)" "$(vps nft list table inet wgft >/dev/null 2>&1 && echo 0 || echo 1)"
  okcheck "foreign wg9 is still untouched" "$(vps ip link show wg9 >/dev/null 2>&1 && echo 1 || echo 0)"
  okcheck "foreign table ip foreigntest is still untouched" "$(vps nft list table ip foreigntest >/dev/null 2>&1 && echo 1 || echo 0)"
  okcheck "server database is purged" "$([ ! -f "$DATA/wgft.sqlite" ] && echo 1 || echo 0)"

  vps ip link del wg9 2>/dev/null
  vps nft delete table ip foreigntest 2>/dev/null
  kill_all; rm -rf "$DATA" /tmp/wgft-lifecycle-c4-foreignkey
}

# ---------------------------------------------------------------------------------------------
# check 5: memory stays bounded under the default flow caps (design 7)
# ---------------------------------------------------------------------------------------------
check5_server_memory() {
  echo "-- the userspace server's own relay"
  local DATA=/tmp/wgft-lifecycle-c5s ADATA=/tmp/wgft-lifecycle-c5s-agent
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  rm -rf "$DATA" "$ADATA"; mkdir -p "$DATA"
  local i addrs=""
  for i in $(seq 10 30); do ip netns exec client ip addr add "198.51.100.$i/24" dev eth0 2>/dev/null; addrs+="198.51.100.$i,"; done
  addrs=${addrs%,}

  start_server "$DATA" /tmp/wgft-lifecycle-c5s-server.log
  if ! wait_admin; then echo "FAIL  check5 (server) setup: admin api never came up"; fail=1
  else
    local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
    WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-lifecycle-c5s-agent.log 2>&1 < /dev/null &
    disown
    ip netns exec lan setsid nohup echo -bind 192.168.50.3 -tcp 25595 -udp 19160 > /tmp/wgft-lifecycle-c5s-echo.log 2>&1 < /dev/null &
    disown
    if ! wait_agent home; then echo "FAIL  check5 (server) setup: agent never registered"; fail=1
    else
      vps wgft rule add --agent home --udp 27040 --to 192.168.50.3:19160 --admin "$ADMIN" >/dev/null
      vps wgft rule add --agent home --tcp 39995 --to 192.168.50.3:25595 --admin "$ADMIN" >/dev/null
      sleep 2
      local spid; spid=$(find_wgft_pid 'server run')

      local udp_out; udp_out=$(ip netns exec client python3 "$PY/flood.py" udp 198.51.100.1 27040 "$addrs" 260)
      echo "   $udp_out"
      ip netns exec client python3 "$PY/flood.py" tcp 198.51.100.1 39995 "$addrs" 60 12 > /tmp/wgft-lifecycle-c5s-tcpflood.log 2>&1 &
      local flood_pid=$!
      sleep 7
      # a client-side connect() can succeed (three-way handshake done) even for an over-cap
      # connection that the relay accepts and immediately RSTs, so the flood's own "established"
      # count is not trustworthy; count on the accepting
      # side instead: the VPS's public listener, which vpsd itself holds in userspace mode.
      local held; held=$(vps ss -tn state established '( sport = :39995 )' | grep -c ':39995')
      local rss; rss=$(rss_mib "$spid")
      wait "$flood_pid"
      echo "   $(cat /tmp/wgft-lifecycle-c5s-tcpflood.log)"
      echo "   tcp connections actually held (ss on the accepting side, not client-side connect success): $held"
      echo "   server RSS while flooded past caps: ${rss:-unknown} MiB (soft limit $SOFT_LIMIT_MIB MiB, margin $MARGIN_MIB MiB)"
      # the RSS bound only means something if the caps were actually reached: one rule, 21
      # sources x 60 TCP (per-rule cap 1024) and x 260 UDP (per-rule cap 4096) with the defaults
      okcheck "server: the tcp flood actually fills the per-rule cap (held $held of 1024)" \
        "$([ "$held" -ge 1000 ] && [ "$held" -le 1024 ] && echo 1 || echo 0)"
      local udp_att udp_ans; udp_att=$(field attempted "$udp_out"); udp_ans=$(field answered "$udp_out")
      okcheck "server: the udp flood fills the per-rule cap and is refused beyond it (answered $udp_ans of $udp_att)" \
        "$([ -n "$udp_ans" ] && [ "$udp_ans" -ge 3900 ] && [ "$udp_ans" -le 4096 ] && [ "$udp_ans" -lt "$udp_att" ] && echo 1 || echo 0)"
      okcheck "server RSS stays under the soft limit plus margin while flooded past the default caps" \
        "$([ -n "${rss:-}" ] && [ "$rss" -le "$((SOFT_LIMIT_MIB + MARGIN_MIB))" ] && echo 1 || echo 0)"
      check "server logs its derived memory soft limit at start" "memory soft limit: $SOFT_LIMIT_MIB MiB" "$(grep 'memory soft limit' /tmp/wgft-lifecycle-c5s-server.log)"
    fi
  fi

  for i in $(seq 10 30); do ip netns exec client ip addr del "198.51.100.$i/24" dev eth0 2>/dev/null; done
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  rm -rf "$DATA" "$ADATA"
}

check5_agent_memory() {
  echo "-- the agent (via the faster kernel-mode forwarding path)"
  local DATA=/tmp/wgft-lifecycle-c5a ADATA=/tmp/wgft-lifecycle-c5a-agent
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"; mkdir -p "$DATA"
  local i addrs=""
  for i in $(seq 10 30); do ip netns exec client ip addr add "198.51.100.$i/24" dev eth0 2>/dev/null; addrs+="198.51.100.$i,"; done
  addrs=${addrs%,}

  vps setsid nohup wgft server run --mode kernel --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
    > /tmp/wgft-lifecycle-c5a-server.log 2>&1 < /dev/null &
  disown
  if ! wait_admin; then echo "FAIL  check5 (agent) setup: admin api never came up"; fail=1
  else
    local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
    WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-lifecycle-c5a-agent.log 2>&1 < /dev/null &
    disown
    ip netns exec lan setsid nohup echo -bind 192.168.50.3 -tcp 25596 -udp 19161 > /tmp/wgft-lifecycle-c5a-echo.log 2>&1 < /dev/null &
    disown
    if ! wait_agent home; then echo "FAIL  check5 (agent) setup: agent never registered"; fail=1
    else
      vps wgft rule add --agent home --udp 27041 --to 192.168.50.3:19161 --admin "$ADMIN" >/dev/null
      vps wgft rule add --agent home --tcp 39996 --to 192.168.50.3:25596 --admin "$ADMIN" >/dev/null
      sleep 2
      local apid; apid=$(find_wgft_pid 'agent run')

      local udp_out; udp_out=$(ip netns exec client python3 "$PY/flood.py" udp 198.51.100.1 27041 "$addrs" 260)
      echo "   $udp_out"
      ip netns exec client python3 "$PY/flood.py" tcp 198.51.100.1 39996 "$addrs" 60 12 > /tmp/wgft-lifecycle-c5a-tcpflood.log 2>&1 &
      local flood_pid=$!
      sleep 7
      # count in the home netns: the agent's own accepting side (10.200.0.2:39996) lives inside
      # its userspace netstack, not a real Linux socket, so `ss` cannot see it; the agent's
      # outgoing dial to the target on the lan host is a real socket there, one per held
      # connection, selected by the target's port as the peer (dport).
      local held; held=$(ip netns exec home ss -tn state established '( dport = :25596 )' | grep -c ':25596')
      local rss; rss=$(rss_mib "$apid")
      wait "$flood_pid"
      echo "   $(cat /tmp/wgft-lifecycle-c5a-tcpflood.log)"
      echo "   tcp connections actually held (ss on the agent's own listener, not client-side connect success): $held"
      echo "   agent RSS while flooded past caps: ${rss:-unknown} MiB (soft limit $SOFT_LIMIT_MIB MiB, margin $MARGIN_MIB MiB)"
      # the RSS bound only means something if the caps were actually reached: one rule, 21
      # sources x 60 TCP (per-rule cap 1024) and x 260 UDP (per-rule cap 4096) with the defaults
      okcheck "agent: the tcp flood actually fills the per-rule cap (held $held of 1024)" \
        "$([ "$held" -ge 1000 ] && [ "$held" -le 1024 ] && echo 1 || echo 0)"
      local udp_att udp_ans; udp_att=$(field attempted "$udp_out"); udp_ans=$(field answered "$udp_out")
      okcheck "agent: the udp flood fills the per-rule cap and is refused beyond it (answered $udp_ans of $udp_att)" \
        "$([ -n "$udp_ans" ] && [ "$udp_ans" -ge 3900 ] && [ "$udp_ans" -le 4096 ] && [ "$udp_ans" -lt "$udp_att" ] && echo 1 || echo 0)"
      okcheck "agent RSS stays under the soft limit plus margin while flooded past the default caps" \
        "$([ -n "${rss:-}" ] && [ "$rss" -le "$((SOFT_LIMIT_MIB + MARGIN_MIB))" ] && echo 1 || echo 0)"
      check "agent logs its derived memory soft limit at start" "memory soft limit: $SOFT_LIMIT_MIB MiB" "$(grep 'memory soft limit' /tmp/wgft-lifecycle-c5a-agent.log)"
    fi
  fi

  for i in $(seq 10 30); do ip netns exec client ip addr del "198.51.100.$i/24" dev eth0 2>/dev/null; done
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"
}

check5() {
  echo "== $mode: check 5: memory stays bounded under the default flow caps"
  if [ "$mode" = userspace ]; then
    check5_server_memory
  else
    skip "the userspace server's own relay memory (kernel mode holds no per-flow state in vpsd, design 6.1)"
  fi
  if [ "$mode" = kernel ]; then
    check5_agent_memory
  else
    skip "agent memory under flood (already exercised via the faster kernel-mode forwarding path in the kernel run, to keep this check short)"
  fi
}

# ---------------------------------------------------------------------------------------------
write_helpers
kill_all
reset_kernel_state
for c in $CHECKS; do "check$c"; done
kill_all
reset_kernel_state

label="$mode"; [ "$CHECKS" != "$ALL_CHECKS" ] && label="$mode (checks $CHECKS)"
if [ "$fail" = 0 ]; then echo "== $label: ALL PASS"; else echo "== $label: FAILURES"; fi
exit "$fail"
