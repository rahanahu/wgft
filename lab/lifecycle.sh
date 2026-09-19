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
#   6. rule-local (Prepare) failures are fail-closed, not backend-wide (design 7a.3 section): a.
#      kernel mode, a squatted proxy port reports that one rule not_active with a bind-failed
#      reason, without blocking an unrelated rule's active state or the active generation, and
#      without an nft accounting line for the squatted port. b. kernel mode, retargeting an
#      established proxy rule onto a squatted port reports it not_active with drift.retiring, and
#      refuses new connections on the old port, but (since listen_port also changes) the agent's
#      own port-based reconciliation (design 7) closes the established sessions through it, by
#      design, not a Phase 4 gap. c. kernel mode, the same port-change closure for a Transparent
#      rule moved to a fail-closed Relay on a different, squatted port. f. userspace mode, one
#      squatted port of a range rule fails the whole range's bind (no partial listen). h. kernel
#      mode, flipping only vps_mode (not listen_port) on an established Transparent rule to a
#      fail-closed Relay on the same, now-squatted port: the agent's declaration never changes, so
#      its established DNAT session survives the fail-closed attempt end to end (conntrack stays
#      ESTABLISHED, full byte count keeps flowing) until a source_deny actually covers it (Retire).
#   7. kernel mode only: backend-wide (Commit) failures (design 7a.3 section). d. holding table
#      inet wgft as another process (as check 3b) and then changing one rule and deleting another
#      leaves every rule pending (the held table lost their rows) with apply_error set, and the
#      deleted rule listed in drift.active_only, all without advancing the active generation;
#      once the obstruction is gone the next apply converges (generations equal, drift empty).
#      e. a known number of deny drops read just before a failed swap are not accumulated twice
#      once the next swap succeeds (internal/vpsd/apply.go's accumulateDrops).
#   8. a rule-local bind failure recovers on its own via the 30s retry (design 7a.3 section)
#      once the squatted port is freed, without any other change, and a retry that would publish
#      nothing new does not replace the nft table (kernel mode: `nft -a list table inet wgft`
#      handles are unchanged across a 35s window while still squatted).
#   9. kernel mode only: kernel state changed outside wgft is restored (design 7a.3 section,
#      実際の状態への収束). `nft flush ruleset` and `nft delete table inet wgft` are each noticed
#      through the nftables change notifications and republished within a few seconds with one
#      log line; with nothing changed (and after an unrelated table's churn) the table's rule
#      handles stay the same across a full retry interval; a table held by another process
#      (flags owner) leaves an admin change pending until the holder exits, after which the
#      pending generation is published and delivered to the agent without any admin change.
#
# Requires `lab/lab build` (wgft and echo in /usr/local/bin of the VM) and the netns topology
# (`lab/lab net up`). Leftovers from earlier runs are killed first. Wherever a step waits on
# something observable (the admin API answering, an agent registering, a rule's dataplane effect,
# a log line, a process exiting), it polls for that condition instead of a fixed sleep, with
# wait_until where the assertion right after re-checks the same condition (so a timeout still
# surfaces as that assertion's normal FAIL), or must_wait, which fails on its own on a timeout,
# where nothing downstream would otherwise notice. A fixed sleep remains only where the check
# deliberately waits for wall-clock time to pass (a session held mid-flow before a restart, a
# few real seconds of downtime); those are each commented at the call site.
set -u
ulimit -n 100000 2>/dev/null || true  # check 5 floods thousands of sockets from the client
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: lifecycle.sh kernel|userspace [check...]" >&2; exit 2;; esac
shift || true
# Optional check names after the mode (1 2 3 3b 4 5 6 7 8 9) run only those checks; none runs all.
ALL_CHECKS="1 2 3 3b 4 5 6 7 8 9"
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

# wait_until <timeout-seconds> <command...>: polls <command...> (a plain command or a function
# defined in this script; it runs directly, not through a subshell, so a function sees the rest
# of this script's other functions and variables) every 0.2s until it exits 0, or until
# <timeout-seconds> (a whole number) elapses. Returns non-zero on timeout so that the caller's
# own, unchanged assertion (the check/okcheck/absent right after) runs anyway and reports its
# usual FAIL; wait_until itself never prints PASS/FAIL and never turns a real failure into a
# silent pass.
wait_until() {
  local timeout=$1; shift
  local tries=$((timeout * 5)) i
  for ((i = 0; i < tries; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}
# must_wait <label> <timeout-seconds> <command...>: like wait_until, but for a wait whose
# condition is NOT re-checked by the assertion that follows it (an unrelated or differently-named
# rule, a process actually having exited, a log line that a later assertion does not also grep
# for). Without this, a timeout would fall through to the next step in whatever state things
# happened to be in, and a later, unrelated assertion could still pass "by accident" even though
# the thing this wait was actually confirming never happened (the script does not run with
# `set -e`, so a bare wait_until's non-zero return is otherwise ignored). On timeout this prints
# FAIL and sets fail=1 itself, the same way check/okcheck/absent do.
must_wait() {
  local label=$1 timeout=$2; shift 2
  if wait_until "$timeout" "$@"; then
    return 0
  fi
  echo "FAIL  $label: timed out"
  fail=1
  return 1
}

vps() { ip netns exec vps "$@"; }
client() { ip netns exec client bash -c "$1"; }

admin_up() { vps wgft agent ls --admin "$ADMIN" >/dev/null 2>&1; }
wait_admin() { wait_until 30 admin_up || { echo "!! admin api did not come up" >&2; return 1; }; }
agent_registered() { vps wgft agent ls --admin "$ADMIN" 2>/dev/null | tail -1 | grep -q "$1"; }
wait_agent() { wait_until 30 agent_registered "$1" || { echo "!! agent $1 did not register" >&2; return 1; }; }

# tcp_probe_ok/udp_probe_ok <port>: a single short-timeout round trip through tools/echo, used to
# poll for "the rule just added/retargeted actually forwards" instead of guessing how long that
# takes; the check right after this always redoes the same probe (with its own, unchanged
# timeout) to produce the value it asserts on.
tcp_probe_ok() { [[ "$(client "echo hi | socat -t 1 - TCP:198.51.100.1:$1" 2>/dev/null)" == *tcp-echo* ]]; }
udp_probe_ok() { [[ "$(client "echo hi | socat -t 1 - UDP:198.51.100.1:$1" 2>/dev/null)" == *udp-echo* ]]; }
# tcp_flow_gone/tcp_flow_up <port>: flows_established (defined below) reaching 0 / at least 1.
tcp_flow_gone() { [ "$(flows_established "$1")" = 0 ]; }
tcp_flow_up() { [ "$(flows_established "$1")" -ge 1 ]; }
# log_has <log-file> <substring>: the log already contains the line an okcheck/check is about to
# grep for, so we stop polling the moment the server has actually written it.
log_has() { grep -q "$2" "$1" 2>/dev/null; }
# proc_gone <pid>: the process no longer exists (kill_server and check3b's foreign nft -i use it).
proc_gone() { ! kill -0 "$1" 2>/dev/null; }

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
  local p
  for p in $(pgrep -x wgft); do
    if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q ' server run'; then
      kill "$p"
      must_wait "kill_server: pid $p (server run) exited" 5 proc_gone "$p"
    fi
  done
}
none_running() { ! pgrep -x wgft >/dev/null 2>&1 && ! pgrep -x echo >/dev/null 2>&1 && ! pgrep -x socat >/dev/null 2>&1; }
kill_all() { pkill -x wgft; pkill -x echo; pkill -x socat; must_wait "kill_all: leftover wgft/echo/socat processes gone" 5 none_running; }
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
# rule_field <rule-id> <json-field>: that field's current value for that rule, via the admin
# API's own JSON, or empty if the rule is gone. `rule add`/`rule set`/`rule rm`/`rule import` all
# apply synchronously (the server writes to SQLite and pushes to nftables before the CLI
# returns), so this and rule_absent below almost always match on their first poll; they still go
# through wait_until, not a bare check, so a genuine regression in that synchronicity reports the
# usual FAIL instead of racing.
rule_field() {
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['id'] == '$1':
        print(r.get('$2', ''))
"
}
rule_field_is() { [ "$(rule_field "$1" "$2")" = "$3" ]; }
rule_absent() {
  ! vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if any(r['id'] == '$1' for r in d['rules']) else 1)
"
}
# set_listen_port <rule-id> <new-port>: changes one rule's listen_port via export + `rule import`,
# the same technique set_target uses (design 5.4: `rule set` only touches group/note).
set_listen_port() {
  local id=$1 port=$2 f=/tmp/wgft-lifecycle-setport.json
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['id'] == '$id':
        r['listen_port'] = '$port'
json.dump(d['rules'], open('$f', 'w'))
"
  vps wgft rule import "$f" --admin "$ADMIN" >/dev/null
}
# retarget_as_proxy <rule-id> <new-port>: changes one rule's vps_mode to proxy (Relay) and
# listen_port in the same batch, the way an admin turning a Transparent rule into a Relay rule
# on a new port would (design 7a.2: vps_mode/proxy_protocol map to Forwarding).
retarget_as_proxy() {
  local id=$1 port=$2 f=/tmp/wgft-lifecycle-setproxy.json
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['id'] == '$id':
        r['listen_port'] = '$port'
        r['vps_mode'] = 'proxy'
json.dump(d['rules'], open('$f', 'w'))
"
  vps wgft rule import "$f" --admin "$ADMIN" >/dev/null
}
# retarget_same_port_as_proxy <rule-id>: changes only vps_mode to proxy, leaving listen_port and
# target untouched. The agent's own declared rule (id, proto, listen_port, target, enabled; design
# 5.3/6.2) does not change at all, so this is the one way to give a rule a rule-local (Prepare)
# failure without the agent's own port-based reconciliation (design 7) touching its listener.
retarget_same_port_as_proxy() {
  local id=$1 f=/tmp/wgft-lifecycle-setproxysameport.json
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['id'] == '$id':
        r['vps_mode'] = 'proxy'
json.dump(d['rules'], open('$f', 'w'))
"
  vps wgft rule import "$f" --admin "$ADMIN" >/dev/null
}
# add_source_deny <rule-id> <cidr>: appends one CIDR to a rule's source_deny via export + import.
add_source_deny() {
  local id=$1 cidr=$2 f=/tmp/wgft-lifecycle-setdeny.json
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['id'] == '$id':
        r.setdefault('source_deny', []).append('$cidr')
json.dump(d['rules'], open('$f', 'w'))
"
  vps wgft rule import "$f" --admin "$ADMIN" >/dev/null
}
# remove_source_deny <rule-id> <cidr>: removes one CIDR from a rule's source_deny via export + import.
remove_source_deny() {
  local id=$1 cidr=$2 f=/tmp/wgft-lifecycle-undeny.json
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['id'] == '$id':
        r['source_deny'] = [c for c in (r.get('source_deny') or []) if c != '$cidr']
json.dump(d['rules'], open('$f', 'w'))
"
  vps wgft rule import "$f" --admin "$ADMIN" >/dev/null
}
# retarget_and_delete <rule-id-to-retarget> <new-target> <rule-id-to-delete>: one `rule import`
# batch that both retargets one rule and removes another, so both land in the same transaction
# (design 7a.3: a backend-wide failure affects everything a transaction was carrying).
retarget_and_delete() {
  local id=$1 target=$2 delid=$3 f=/tmp/wgft-lifecycle-c7-import.json
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
out = []
for r in d['rules']:
    if r['id'] == '$delid':
        continue
    if r['id'] == '$id':
        r['target'] = '$target'
    out.append(r)
json.dump(out, open('$f', 'w'))
"
  vps wgft rule import "$f" --admin "$ADMIN" >/dev/null 2>&1
}
# rule_state_field <rule-id> <apply_state|reason|active_generation>: that field of
# rule_states[<rule-id>] in the admin API's own JSON (design 7a.3 節), or empty if the rule has no
# reported state yet.
rule_state_field() {
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
st = d.get('rule_states', {}).get('$1', {})
print(st.get('$2', ''))
"
}
rule_state_is() { [ "$(rule_state_field "$1" "$2")" = "$3" ]; }
rule_state_reason_has() { case "$(rule_state_field "$1" reason)" in *"$2"*) return 0;; *) return 1;; esac; }
# apply_top_field <desired_generation|active_generation|apply_error>: that top-level field of the
# admin API's rules response.
apply_top_field() {
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
v = d.get('$1', '')
print(v if v is not None else '')
"
}
generations_equal() {
  local d a; d=$(apply_top_field desired_generation); a=$(apply_top_field active_generation)
  [ -n "$d" ] && [ "$d" = "$a" ]
}
# drift_has <active_only|retiring> <rule-id>: that rule id appears in drift.<kind> (design 7a.3 節).
drift_has() {
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
items = d.get('drift', {}).get('$1', [])
sys.exit(0 if any(x['rule_id'] == '$2' for x in items) else 1)
"
}
drift_empty() {
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
sys.exit(0 if len(d.get('drift', {}).get('$1', [])) == 0 else 1)
"
}
# rule_drops <rule-id>: that rule's cumulative drop packet count (admin API's `drops`), or empty.
rule_drops() {
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
print(d.get('drops', {}).get('$1', ''))
"
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
# tcpprobe.py <dst-ip> <port> <rounds> <interval> [src-ip]
# Connects once, sends a 10-byte chunk every <interval> seconds for <rounds> rounds without
# closing, then half-closes and reads tools/echo's final "tcp-echo ... got=<n>; ..." reply.
# Prints "sent=<bytes> broke_at=<round-or-None> got=<reply-or-error>": whether every byte sent
# across the whole session (including any window where the peer might have been unreachable)
# was actually delivered is the end-to-end proof, not just that sendall() did not raise. The
# optional src-ip binds the client socket to one of the client netns's addresses, so two calls
# from different addresses can be told apart on the accepting side (check6's Retire scenario).
import socket, sys, time

dst, port, rounds, interval = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), float(sys.argv[4])
src = sys.argv[5] if len(sys.argv) > 5 else None
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
if src:
    s.bind((src, 0))
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
# Opens sockets from each of several source addresses, all non-blocking and driven from one
# selectors.DefaultSelector event loop instead of one OS thread per socket: at the thousands of
# attempts check 5 needs to fill and overflow the flow caps, a thread per socket makes Python's
# GIL and per-thread setup cost the dominant wall-clock cost, not the actual network round trip
# (measured: ~70s of a ~90s check for 5460 UDP attempts, before this rewrote it). Optionally
# holds established TCP connections open for <hold-seconds> before closing, and prints
# "<kind>: attempted=<n> established=<n>" (tcp) or "<kind>: attempted=<n> answered=<n>" (udp).
import selectors
import socket
import sys
import time

kind, dst, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
srcs = sys.argv[4].split(',')
per = int(sys.argv[5])
hold = float(sys.argv[6]) if len(sys.argv) > 6 else 0
attempted = len(srcs) * per

if kind == 'udp':
    socks = []
    for src in srcs:
        for _ in range(per):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((src, 0))
            s.setblocking(False)
            socks.append(s)
    # a plain send-them-all-at-once loop is fast enough to overwhelm the userspace relay's own
    # per-packet processing (measured: bursting all 5460 sends dropped the answered count to a
    # small fraction of the per-rule cap, well under what a paced send reliably delivers), so
    # this paces sends in small batches, the same shape as the old thread-per-socket version's
    # incidental pacing (its thread creation overhead alone spread sends out, without meaning to).
    for i, s in enumerate(socks):
        try:
            s.sendto(b'f', (dst, port))
        except OSError:
            pass
        if (i + 1) % 200 == 0:
            time.sleep(0.05)

    sel = selectors.DefaultSelector()
    for s in socks:
        sel.register(s, selectors.EVENT_READ)
    answered = 0
    deadline = time.monotonic() + 2.5
    while sel.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        events = sel.select(timeout=remaining)
        if not events:
            break
        for key, _ in events:
            sel.unregister(key.fileobj)
            try:
                key.fileobj.recvfrom(2048)
                answered += 1
            except OSError:
                pass
    print('udp: attempted=%d answered=%d' % (attempted, answered))
    for s in socks:
        s.close()
else:
    sel = selectors.DefaultSelector()
    for src in srcs:
        for _ in range(per):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.bind((src, 0))
            except OSError:
                s.close()
                continue
            s.setblocking(False)
            try:
                s.connect((dst, port))
            except BlockingIOError:
                pass
            except OSError:
                s.close()
                continue
            sel.register(s, selectors.EVENT_WRITE)

    established = []
    deadline = time.monotonic() + 5
    while sel.get_map():
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        events = sel.select(timeout=remaining)
        if not events:
            break
        for key, _ in events:
            s = key.fileobj
            sel.unregister(s)
            if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                s.setblocking(True)
                established.append(s)
            else:
                s.close()
    for key in list(sel.get_map().values()):
        key.fileobj.close()

    # flush=True: the shell side must_waits for this exact line to appear in the (redirected to a
    # file) log while this process is still running and holding connections open, before it
    # samples RSS; stdout to a file is fully buffered by default, so without an explicit flush
    # the line could sit unwritten until this process exits, well after the hold is over.
    print('tcp: attempted=%d established=%d' % (attempted, len(established)), flush=True)
    if hold:
        time.sleep(hold)
    for s in established:
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
  # bare wait_until: re-checked immediately below by the check() calls, which redo the exact
  # same probe with their own (unchanged) timeout and would FAIL on the unmatched substring.
  wait_until 10 tcp_probe_ok 39980
  wait_until 10 udp_probe_ok 27020
  check "tcp works before the restart" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39980')"
  check "udp works before the restart" "udp-echo" "$(client 'echo hi | socat -t 3 - UDP:198.51.100.1:27020')"

  local rounds=20 interval=0.5
  ip netns exec client python3 "$PY/tcpprobe.py" 198.51.100.1 39980 "$rounds" "$interval" \
    > /tmp/wgft-lifecycle-c1-tcp.log 2>&1 < /dev/null &
  local tcp_pid=$!
  ip netns exec client python3 "$PY/udpprobe.py" 198.51.100.1 27020 "$rounds" "$interval" \
    > /tmp/wgft-lifecycle-c1-udp.log 2>&1 < /dev/null &
  local udp_pid=$!

  # deliberate: the point of this check is a restart while the sessions are mid-flow, not just
  # freshly established, so give tcpprobe/udpprobe (0.5s per round) a few rounds' head start
  # before we pull the server out from under them.
  sleep 2
  local old_pid; old_pid=$(find_wgft_pid 'server run')
  kill_server
  # kill_server's own must_wait already fails loudly if a matched pid does not die in time, but
  # it silently does nothing if pgrep/cmdline never matched the process in the first place; this
  # is the general safety net for "the server is actually stopped" that the rest of this block
  # (wg0/nft/conntrack while stopped) assumes.
  okcheck "no wgft server run process remains after kill_server" "$([ -z "$(find_wgft_pid 'server run')" ] && echo 1 || echo 0)"
  if [ -n "$(find_wgft_pid 'server run')" ]; then
    # The server did not stop, so nothing below about "while the server is stopped" can be
    # checked, and waiting on it would only hang. Stop here (the FAILs above already record it),
    # force the leftovers down (SIGCONT first, in case it is stopped rather than running) and clean up.
    echo "   the server did not stop; skipping the rest of check 1"
    kill "$tcp_pid" "$udp_pid" 2>/dev/null
    pkill -CONT -x wgft; pkill -KILL -x wgft; pkill -x echo; pkill -x socat
    wait "$tcp_pid" "$udp_pid" 2>/dev/null
    vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
    rm -rf "$DATA" "$ADATA"
    return
  fi
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
  # deliberate: the design claim under test is that wg0/table inet wgft/conntrack outlive vpsd
  # while it is stopped for a real stretch of wall-clock time, not just for an instant.
  sleep 5
  start_server "$DATA" /tmp/wgft-lifecycle-c1-server2.log
  if ! wait_admin; then echo "FAIL  check1: admin api never came back up after the restart"; fail=1; fi
  # wait_admin only proves *an* admin API answered; if kill_server's process check above had a
  # gap, that could still be the pre-restart process. Confirm it is actually the new one.
  local new_pid; new_pid=$(find_wgft_pid 'server run')
  okcheck "the restarted server is a new process, not the pre-restart one (old=$old_pid new=$new_pid)" \
    "$([ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ] && echo 1 || echo 0)"

  if [ "$mode" = kernel ]; then
    # bare wait_until: re-checked immediately below, since a timed-out (still empty or stale)
    # after_sport would fail to match before_sport in the check() that follows.
    wait_until 5 tcp_flow_up 39980
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
  # bare wait_until: re-checked immediately below by the check() calls (same probe, same port).
  wait_until 10 tcp_probe_ok 39982
  wait_until 10 udp_probe_ok 27022
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

  # each of these confirms the churn on B (and A's own note edit) actually applied before moving
  # on; none of it is re-checked by anything else (the only assertions left in this block test
  # A's flows surviving, not B's state), so a timeout here must fail loudly on its own or the
  # whole point of exercising "B's churn happened, and A survived it" would be lost silently.
  local b
  b=$(vps wgft rule add --agent home --tcp 39990 --to 192.168.50.3:25581 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  must_wait "check2: rule B add applied" 3 rule_field_is "$b" target "192.168.50.3:25581"
  set_target "$b" 192.168.50.3:25582
  must_wait "check2: rule B retarget applied" 3 rule_field_is "$b" target "192.168.50.3:25582"
  vps wgft rule disable "$b" --admin "$ADMIN" >/dev/null
  must_wait "check2: rule B disable applied" 3 rule_field_is "$b" enabled "False"
  vps wgft rule rm "$b" --admin "$ADMIN" >/dev/null
  must_wait "check2: rule B delete applied" 3 rule_absent "$b"
  vps wgft rule set "$a_tcp" --group lifecycle --note "changed mid-flow" --admin "$ADMIN" >/dev/null
  vps wgft rule set "$a_udp" --group lifecycle --note "changed mid-flow" --admin "$ADMIN" >/dev/null
  must_wait "check2: A's own note edit applied" 3 rule_field_is "$a_udp" note "changed mid-flow"

  wait "$tcp_pid" "$udp_pid" 2>/dev/null
  local want_bytes=$((rounds * 10))
  check "tcp on A survives add/retarget/disable/delete of B and A's own note edit" "got=$want_bytes;" "$(cat /tmp/wgft-lifecycle-c2-tcpA.log)"
  check "udp on A survives the same churn" "oks=$rounds fails=0" "$(cat /tmp/wgft-lifecycle-c2-udpA.log)"

  echo "-- changing A's own target does cut its flows (design 6.1 convergence / design 7 reconciliation)"
  local a_tcp2 a_udp2
  a_tcp2=$(vps wgft rule add --agent home --tcp 39983 --to 192.168.50.3:25581 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  a_udp2=$(vps wgft rule add --agent home --udp 27023 --to 192.168.50.3:19151 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  # bare wait_until below: each is re-checked by the "before"/"after" comparison a couple of
  # lines later, since before/after both come straight from flows_established() and a timed-out
  # wait leaves them at whatever value that produces (0 when the rule was never ready, unchanged
  # when the cut never happened), which the check() right after "before=1 after=0" catches.
  wait_until 10 tcp_probe_ok 39983
  client 'python3 -c "
import socket, time
s = socket.create_connection((\"198.51.100.1\", 39983), timeout=5); s.send(b\"x\"); time.sleep(6)
"' &
  wait_until 5 tcp_flow_up 39983
  local before after
  before=$(flows_established 39983)
  set_target "$a_tcp2" 192.168.50.3:25599
  wait_until 5 tcp_flow_gone 39983
  after=$(flows_established 39983)
  wait
  check "changing A's target cuts A's open tcp session" "before=1 after=0" "before=$before after=$after"

  check "udp on the second A still worked before the target change" "udp-echo" "$(client 'echo hi | socat -t 3 - UDP:198.51.100.1:27023')"
  set_target "$a_udp2" 192.168.50.3:19199
  # bare wait_until: re-checked by the absent() call right after, since a target that never
  # actually changed would still answer with "udp-echo", which absent() treats as a failure.
  wait_until 3 rule_field_is "$a_udp2" target "192.168.50.3:19199"
  absent "changing A's target silences its udp flow" "udp-echo" "$(client 'echo hi | socat -t 2 - UDP:198.51.100.1:27023' 2>&1)"

  echo "-- deleting A cuts its flows too"
  local a_tcp3
  a_tcp3=$(vps wgft rule add --agent home --tcp 39984 --to 192.168.50.3:25581 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  # bare wait_until below: same reasoning as the a_tcp2 block above (before/after feed straight
  # into the "before=1 after=0" check that follows).
  wait_until 10 tcp_probe_ok 39984
  client 'python3 -c "
import socket, time
s = socket.create_connection((\"198.51.100.1\", 39984), timeout=5); s.send(b\"x\"); time.sleep(6)
"' &
  wait_until 5 tcp_flow_up 39984
  before=$(flows_established 39984)
  vps wgft rule rm "$a_tcp3" --admin "$ADMIN" >/dev/null
  wait_until 5 tcp_flow_gone 39984
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
  src_flow_present() { [ "$(src_flow_lines)" -ge 1 ]; }
  port_listening() { vps ss -ltn 2>/dev/null | grep -q ":$1 "; }
  port_free() { ! port_listening "$1"; }
  # squat/unsquat's own waits are bare: if socat never actually bound (or never actually freed)
  # 8461, the very next block's okcheck/check would see the opposite of what it expects (an
  # accounting line where there should be none, or none where one should appear) and FAIL.
  squat() { vps setsid nohup socat TCP-LISTEN:8461,reuseaddr,fork EXEC:/bin/cat > /tmp/wgft-lifecycle-c3-squat.log 2>&1 < /dev/null & disown; wait_until 3 port_listening 8461; }
  unsquat() { pkill -x socat; wait_until 3 port_free 8461; }

  echo "-- rule creation while another process owns 8461"
  squat
  vps wgft rule add --agent home --tcp 8461 --to 192.168.50.3:25590 --proxy --admin "$ADMIN" >/dev/null
  # bare wait_until: re-checked by the check() right after (same log, same substring).
  wait_until 5 log_has /tmp/wgft-lifecycle-c3-server.log "cannot open listener for 8461"
  okcheck "no nft accounting line while the port is squatted" "$([ "$(src_flow_lines)" = 0 ] && echo 1 || echo 0)"
  check "bind failure is logged" "cannot open listener for 8461" "$(grep -o 'cannot open listener for 8461.*' /tmp/wgft-lifecycle-c3-server.log | tail -1)"

  echo "-- the port is freed; the next apply opens it"
  unsquat
  vps wgft rule add --agent home --tcp 39985 --to 192.168.50.3:25590 --admin "$ADMIN" >/dev/null
  # bare wait_until: re-checked by the okcheck right after (same src_flow_lines condition).
  wait_until 5 src_flow_present
  okcheck "nft accounting line appears once the port is free" "$([ "$(src_flow_lines)" -ge 1 ] && echo 1 || echo 0)"

  echo "-- restart while another process owns 8461"
  kill_server
  squat
  start_server "$DATA" /tmp/wgft-lifecycle-c3-server2.log
  if ! wait_admin; then echo "FAIL  check3: admin api never came back up"; fail=1; return; fi
  # must_wait: the okcheck right after asserts accounting-line *absence*, a different condition
  # that a startup apply which simply had not run yet would also satisfy; without confirming the
  # bind-retry was actually logged, that okcheck could pass without the restart path having been
  # exercised at all.
  must_wait "check3: restart-while-squatted bind failure logged" 5 log_has /tmp/wgft-lifecycle-c3-server2.log "cannot open listener for 8461"
  okcheck "no nft accounting line after a restart while squatted" "$([ "$(src_flow_lines)" = 0 ] && echo 1 || echo 0)"

  echo "-- restart with the port free"
  kill_server
  unsquat
  start_server "$DATA" /tmp/wgft-lifecycle-c3-server3.log
  if ! wait_admin; then echo "FAIL  check3: admin api never came back up"; fail=1; return; fi
  # bare wait_until: re-checked by the okcheck right after (same src_flow_lines condition).
  wait_until 5 src_flow_present
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
  # bare wait_until: re-checked by the check() right after (same probe, same port).
  wait_until 10 tcp_probe_ok 8462
  check "the soon-to-be-deleted proxy rule works before anything" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:8462')"

  echo "-- another process claims ownership of table inet wgft (nft -i fed through a fifo kept open, so it never sees EOF and keeps holding the table)"
  # The replacement is one nftables transaction (add, delete, add with flags owner on one line), not
  # a separate `nft delete table` first: the server notices a deleted table within a second and
  # republishes it (design 7a.3 section, 実際の状態への収束), and an existing table cannot be given
  # an owner afterwards.
  rm -f /tmp/wgft-lifecycle-c3b-fifo /tmp/wgft-lifecycle-c3b-owner.log
  mkfifo /tmp/wgft-lifecycle-c3b-fifo
  vps bash -c 'exec 3<>/tmp/wgft-lifecycle-c3b-fifo; nft -i <&3 >/tmp/wgft-lifecycle-c3b-owner.log 2>&1 &'
  nft_i_ready() { vps pgrep -x nft >/dev/null 2>&1; }
  # must_wait, and bail out here rather than falling through: the next line's `echo ... > fifo`
  # is a plain write-only open on a named pipe, which blocks until some reader has it open. If
  # nft -i never actually started (never became the reader), that write would hang this whole
  # script forever instead of just failing this check, which no downstream assertion could ever
  # turn into a normal FAIL.
  if ! must_wait "check3b: nft -i reading the fifo" 3 nft_i_ready; then
    rm -f /tmp/wgft-lifecycle-c3b-fifo /tmp/wgft-lifecycle-c3b-owner.log
    kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
    rm -rf "$DATA" "$ADATA"
    return
  fi
  echo 'add table inet wgft; delete table inet wgft; add table inet wgft { flags owner; }' > /tmp/wgft-lifecycle-c3b-fifo
  foreign_owner_table_present() { vps nft list table inet wgft 2>/dev/null | grep -q 'flags owner'; }
  # bare wait_until: re-checked by the okcheck right after (same condition).
  wait_until 5 foreign_owner_table_present
  local owner_pid; owner_pid=$(vps pgrep -x nft | head -1)
  okcheck "a foreign table with flags owner exists before we provoke the swap failure" \
    "$(vps nft list table inet wgft 2>/dev/null | grep -q 'flags owner' && echo 1 || echo 0)"

  echo "-- delete the existing proxy rule and add a new one while the table is owned by someone else"
  vps wgft rule rm "$r_del" --admin "$ADMIN" >/dev/null 2>&1
  vps wgft rule add --agent home --tcp 8463 --to 192.168.50.3:25597 --proxy --admin "$ADMIN" >/dev/null 2>&1
  # bare wait_until: re-checked by "the swap failure is logged" check() a few lines down (same
  # log, same substring).
  wait_until 5 log_has /tmp/wgft-lifecycle-c3b-server.log "failed to apply nftables"
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
  # must_wait: if the owner never actually exits, the table stays foreign-owned and every apply
  # from here on keeps failing for the same old reason, which the checks below could otherwise
  # misread as some other, unrelated problem instead of "the owner never left".
  must_wait "check3b: foreign nft -i (owner pid $owner_pid) exited" 5 proc_gone "$owner_pid"
  # `rule set --note` would not do here: a note-only edit does not change the agent-facing view
  # (design 5.3/5.4), so it neither bumps the generation nor pushes full state to the agent, and
  # the agent would never learn to open its own listener for the new rule. disable+enable does
  # (design 7: enabled toggles a listener's presence in the declared state).
  vps wgft rule disable "$r_add" --admin "$ADMIN" >/dev/null 2>&1
  # must_wait: nothing downstream re-checks "enabled" itself (the checks below test connection
  # behaviour), so a disable that silently never applied would not be caught any other way.
  must_wait "check3b: rule (re)add disable applied" 3 rule_field_is "$r_add" enabled "False"
  vps wgft rule enable "$r_add" --admin "$ADMIN" >/dev/null 2>&1
  tcp_refused() { [[ "$(client "echo hi | socat -t 1 - TCP:198.51.100.1:$1" 2>&1)" == *"Connection refused"* ]]; }
  # bare wait_until: re-checked by the check() right after (same probe, same port).
  wait_until 10 tcp_refused 8462
  check "once the owner is gone, the deleted rule's listener is finally closed" "Connection refused" "$(client 'echo hi | socat -t 2 - TCP:198.51.100.1:8462' 2>&1)"
  # the agent only opens its own local listener for the new rule once it receives the full state
  # over the stream, a round trip through the WG tunnel; poll instead of trusting a fixed sleep.
  # bare wait_until: re-checked by the check() right after (same probe, same port).
  wait_until 10 tcp_probe_ok 8463
  check "once the owner is gone, the newly-added rule now actually works" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:8463')"

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
      # bare wait_until: a rule that was never actually ready surfaces downstream as an
      # out-of-range held/answered count (0, not 1000..1024 or 3900..4096), which the okchecks
      # below correctly turn into a FAIL.
      wait_until 10 tcp_probe_ok 39995
      wait_until 10 udp_probe_ok 27040
      local spid; spid=$(find_wgft_pid 'server run')

      local udp_out; udp_out=$(ip netns exec client python3 "$PY/flood.py" udp 198.51.100.1 27040 "$addrs" 260)
      echo "   $udp_out"
      ip netns exec client python3 "$PY/flood.py" tcp 198.51.100.1 39995 "$addrs" 60 5 > /tmp/wgft-lifecycle-c5s-tcpflood.log 2>&1 &
      local flood_pid=$!
      # a client-side connect() can succeed (three-way handshake done) even for an over-cap
      # connection that the relay accepts and immediately RSTs, so the flood's own "established"
      # count is not trustworthy; count on the accepting
      # side instead: the VPS's public listener, which vpsd itself holds in userspace mode.
      c5s_held_near_cap() { [ "$(vps ss -tn state established '( sport = :39995 )' | grep -c ':39995')" -ge 1000 ]; }
      # must_wait, in order: first confirm the flood has finished *attempting* every one of its
      # 1260 connections (flood.py only prints this once every attempt has completed or failed,
      # not just once the cap is reached), then confirm the accepting side has settled on a held
      # count near the cap. Sampling RSS before both of these could catch the relay mid-flight,
      # before it has finished accepting-and-immediately-rejecting the over-cap connections,
      # which is exactly the memory-growth-under-continued-rejection regression this check
      # exists to catch (RSS sampled too early could simply miss it).
      must_wait "check5 (server): tcp flood finished attempting all connections" 10 log_has /tmp/wgft-lifecycle-c5s-tcpflood.log "tcp: attempted="
      must_wait "check5 (server): tcp held count reaches the per-rule cap" 10 c5s_held_near_cap
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
      # bare wait_until: a rule that was never actually ready surfaces downstream as an
      # out-of-range held/answered count (0, not 1000..1024 or 3900..4096), which the okchecks
      # below correctly turn into a FAIL.
      wait_until 10 tcp_probe_ok 39996
      wait_until 10 udp_probe_ok 27041
      local apid; apid=$(find_wgft_pid 'agent run')

      local udp_out; udp_out=$(ip netns exec client python3 "$PY/flood.py" udp 198.51.100.1 27041 "$addrs" 260)
      echo "   $udp_out"
      ip netns exec client python3 "$PY/flood.py" tcp 198.51.100.1 39996 "$addrs" 60 5 > /tmp/wgft-lifecycle-c5a-tcpflood.log 2>&1 &
      local flood_pid=$!
      # count in the home netns: the agent's own accepting side (10.200.0.2:39996) lives inside
      # its userspace netstack, not a real Linux socket, so `ss` cannot see it; the agent's
      # outgoing dial to the target on the lan host is a real socket there, one per held
      # connection, selected by the target's port as the peer (dport).
      c5a_held_near_cap() { [ "$(ip netns exec home ss -tn state established '( dport = :25596 )' | grep -c ':25596')" -ge 1000 ]; }
      # must_wait, in order: see check5_server_memory's identical comment above (finish
      # attempting every connection, only then confirm the held count, only then sample RSS).
      must_wait "check5 (agent): tcp flood finished attempting all connections" 10 log_has /tmp/wgft-lifecycle-c5a-tcpflood.log "tcp: attempted="
      must_wait "check5 (agent): tcp held count reaches the per-rule cap" 10 c5a_held_near_cap
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
# check 6: rule-local (Prepare) failures are fail-closed, not backend-wide (design 7a.3 節). A
# squatted proxy port reports only that one rule not_active, without blocking an unrelated rule's
# active state or the active generation, and without an nft accounting line for the squatted
# port (a). Retargeting an established proxy rule onto a squatted port keeps its established
# connections going (Retiring/StopAccepting), refuses new ones, and a source_deny added
# afterwards (Retire) closes only the sessions it newly refuses (b). Turning an established
# Transparent rule into a fail-closed Relay on a squatted port keeps its established DNAT session
# in conntrack (c). Userspace mode only has the range-rule case: one squatted port fails the
# whole range's bind, since the staged Prepare opens all of a rule's ports or none (f).
# ---------------------------------------------------------------------------------------------
check6() {
  echo "== $mode: check 6: rule-local bind failures are fail-closed, not backend-wide"
  local DATA=/tmp/wgft-lifecycle-c6 ADATA=/tmp/wgft-lifecycle-c6-agent
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"; mkdir -p "$DATA"

  start_server "$DATA" /tmp/wgft-lifecycle-c6-server.log
  if ! wait_admin; then echo "FAIL  check6 setup: admin api never came up"; fail=1; return; fi
  local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-lifecycle-c6-agent.log 2>&1 < /dev/null &
  disown
  ip netns exec lan setsid nohup echo -bind 192.168.50.3 -tcp 25620,25621,25622,25623,25624 \
    > /tmp/wgft-lifecycle-c6-echo.log 2>&1 < /dev/null &
  disown
  if ! wait_agent home; then echo "FAIL  check6 setup: agent never registered"; fail=1; return; fi

  port_listening() { vps ss -ltn 2>/dev/null | grep -q ":$1 "; }
  port_free() { ! port_listening "$1"; }
  # squat_port/unsquat_port <port>: same technique as check3's squat, parameterized. unsquat_port
  # kills every squatting socat, which is safe here since check6 only ever squats one port at a
  # time (each sub-scenario frees its own before the next squats a different one).
  squat_port() {
    vps setsid nohup socat "TCP-LISTEN:$1,reuseaddr,fork" EXEC:/bin/cat \
      > "/tmp/wgft-lifecycle-c6-squat-$1.log" 2>&1 < /dev/null &
    disown
    wait_until 3 port_listening "$1"
  }
  unsquat_port() { pkill -x socat; wait_until 3 port_free "$1"; }
  src_flow_for_port() { vps nft list table inet wgft 2>/dev/null | grep -c "dport $1 .*src_flow"; }
  tcp_refused() { [[ "$(client "echo hi | socat -t 1 - TCP:198.51.100.1:$1" 2>&1)" == *"Connection refused"* ]]; }

  if [ "$mode" = kernel ]; then
    echo "-- a. a squatted proxy port is a rule-local (not backend-wide) failure"
    local ctrl bad
    ctrl=$(vps wgft rule add --agent home --tcp 39997 --to 192.168.50.3:25620 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
    wait_until 10 tcp_probe_ok 39997
    check "the control rule works before anything" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39997')"
    squat_port 8471
    bad=$(vps wgft rule add --agent home --tcp 8471 --to 192.168.50.3:25621 --proxy --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
    # bare wait_until: re-checked by the okcheck/check calls right after (same rule_state field).
    wait_until 5 rule_state_is "$bad" apply_state not_active
    okcheck "the squatted rule reports not_active" "$(rule_state_is "$bad" apply_state not_active && echo 1 || echo 0)"
    check "its reason names the bind failure" "bind failed" "$(rule_state_field "$bad" reason)"
    okcheck "the unrelated control rule is unaffected (stays active)" "$(rule_state_is "$ctrl" apply_state active && echo 1 || echo 0)"
    okcheck "the active generation still advances to the desired generation" "$(generations_equal && echo 1 || echo 0)"
    okcheck "no nft accounting line exists for the squatted port" "$([ "$(src_flow_for_port 8471)" = 0 ] && echo 1 || echo 0)"
    unsquat_port 8471
    vps wgft rule rm "$bad" --admin "$ADMIN" >/dev/null; vps wgft rule rm "$ctrl" --admin "$ADMIN" >/dev/null

    echo "-- b. a fail-closed Relay: not_active, drift.retiring, refuses new connections to the old port"
    # NOTE: retargeting a proxy rule's listen_port is the only way to provoke a rule-local bind
    # failure for it, but listen_port is also the agent's own declared listener key (design 5.3,
    # 6.2: the agent only ever receives id, proto, listen_port, target, enabled and listens on the
    # same port as the VPS). A listen_port change is therefore, by design, reconciled by the agent
    # like any other port change (design 7's port-based reconciliation table: the old port "現在に
    # あって宣言にない: 閉じる", including its in-flight TCP connections, before the new one opens) -
    # this closes the very sessions the VPS side's own Retiring/StopAccepting bookkeeping otherwise
    # keeps open, but it is intended agent behaviour, not a Phase 4 gap (see scenario h below for a
    # same-port Transparent-to-Relay conversion, where the agent's declaration never changes and
    # the established session does survive end to end). Verified in the lab: vpsd's own log reports
    # "closed 0 connections its new declaration refuses" (it kept everything on its side), while
    # the agent's log for the same moment reports a plain "listener tcp/<port> closed" and both an
    # already-established session and a second one from a different, never-denied source break
    # within well under a second of the retarget, before any source_deny is even added. This check
    # asserts that expected, port-change-driven cut so it stays a reliable regression oracle.
    ip netns exec client ip addr add 198.51.100.9/24 dev eth0 2>/dev/null
    local r; r=$(vps wgft rule add --agent home --tcp 8472 --to 192.168.50.3:25622 --proxy --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
    wait_until 10 tcp_probe_ok 8472
    local rounds=20 interval=0.4
    ip netns exec client python3 "$PY/tcpprobe.py" 198.51.100.1 8472 "$rounds" "$interval" 198.51.100.2 \
      > /tmp/wgft-lifecycle-c6-s1.log 2>&1 < /dev/null &
    local s1_pid=$!
    ip netns exec client python3 "$PY/tcpprobe.py" 198.51.100.1 8472 "$rounds" "$interval" 198.51.100.9 \
      > /tmp/wgft-lifecycle-c6-s2.log 2>&1 < /dev/null &
    local s2_pid=$!
    # deliberate: give both sessions a couple of rounds so they are actually established (and past
    # their first send) before the retarget below fail-closes the rule mid-flow.
    sleep 1.5
    squat_port 8473
    retarget_as_proxy "$r" 8473
    must_wait "check6b: rule retargeted to the squatted port is reported not_active" 5 rule_state_is "$r" apply_state not_active
    check "its reason names the bind failure" "bind failed" "$(rule_state_field "$r" reason)"
    okcheck "the old port is listed as retiring" "$(drift_has retiring "$r" && echo 1 || echo 0)"
    okcheck "a new connection to the old port is refused (StopAccepting closed the listener)" \
      "$(tcp_refused 8472 && echo 1 || echo 0)"
    wait "$s1_pid" "$s2_pid" 2>/dev/null
    local s1log s2log; s1log=$(cat /tmp/wgft-lifecycle-c6-s1.log); s2log=$(cat /tmp/wgft-lifecycle-c6-s2.log)
    if [[ "$s1log" == *"got=$((rounds * 10));"* ]] || [[ "$s2log" == *"got=$((rounds * 10));"* ]]; then
      echo "FAIL  an established session survived the listen_port change (expected the agent's own port-based reconciliation, design 7, to close it)"; fail=1
    else
      echo "PASS  both established sessions are cut by the listen_port change, including the one from a never-denied source (the agent's own listener close on any port change, design 7; not the VPS's Retire); s1: $s1log; s2: $s2log"
    fi
    unsquat_port 8473
    vps wgft rule rm "$r" --admin "$ADMIN" >/dev/null
    ip netns exec client ip addr del 198.51.100.9/24 dev eth0 2>/dev/null

    echo "-- c. a kernel Transparent rule moved to a different port as a fail-closed Relay: not_active, but the old port change closes its established session (same design-7 port reconciliation as b)"
    # NOTE: this retargets both listen_port and vps_mode at once (a Transparent rule's port is
    # never bound on the VPS host, design 6.1, so squatting its current port alone would not fail
    # anything; converting to Relay is what gives it a rule-local Prepare failure to fail-closed
    # on). Since the port also changes here, the same design-7 port-based agent reconciliation as
    # scenario b applies (close the old port's connections, then try the new one), independently
    # of the VPS side's own conntrack convergence. Verified in the lab: the vpsd-side conntrack
    # entry for the pre-existing DNAT session moves from ESTABLISHED to CLOSE right after the
    # retarget (a real FIN/RST, not an expiry). Scenario h below isolates the same-port case (only
    # vps_mode changes), where the agent's declaration is untouched and the session does survive.
    local t; t=$(vps wgft rule add --agent home --tcp 39998 --to 192.168.50.3:25623 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
    wait_until 10 tcp_probe_ok 39998
    local rounds2=16 interval2=0.4
    ip netns exec client python3 "$PY/tcpprobe.py" 198.51.100.1 39998 "$rounds2" "$interval2" \
      > /tmp/wgft-lifecycle-c6-c.log 2>&1 < /dev/null &
    local c_pid=$!
    wait_until 5 tcp_flow_up 39998
    squat_port 8474
    retarget_as_proxy "$t" 8474
    must_wait "check6c: the retargeted rule is reported not_active" 5 rule_state_is "$t" apply_state not_active
    check "its reason names the bind failure" "bind failed" "$(rule_state_field "$t" reason)"
    wait "$c_pid" 2>/dev/null
    local clog; clog=$(cat /tmp/wgft-lifecycle-c6-c.log)
    if [[ "$clog" == *"got=$((rounds2 * 10));"* ]]; then
      echo "FAIL  the established DNAT session survived the port change (expected the agent's own port-based reconciliation, design 7, to close it)"; fail=1
    else
      echo "PASS  the established DNAT session is cut by the port change (same design-7 agent reconciliation as scenario b, not a VPS-side bug); log: $clog"
    fi
    unsquat_port 8474
    vps wgft rule rm "$t" --admin "$ADMIN" >/dev/null

    echo "-- h. a same-port Transparent-to-Relay conversion: the agent's declaration never changes, so its established session survives the fail-closed Relay attempt end to end; Retire still cuts it once a source_deny actually covers it"
    # Unlike b/c, this keeps listen_port (and target) fixed and flips only vps_mode, so the agent
    # never sees a different declared rule (design 5.3/6.2: it only ever receives id, proto,
    # listen_port, target, enabled) and does not touch its listener at all. A Transparent rule's
    # port is never bound on the VPS host (design 6.1: pure DNAT), so squatting it first does not
    # conflict with anything until the retarget asks proxyrelay to bind it. This is Phase 4's
    # "Relay のルールを fail-closed にしても安全な成立済みの TCP 接続が残ること" criterion isolated
    # from the agent's own (intended, design 7) port-change behaviour exercised in b/c.
    local h; h=$(vps wgft rule add --agent home --tcp 39996 --to 192.168.50.3:25624 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
    wait_until 10 tcp_probe_ok 39996
    # conntrack accounting (per netns) makes the entry's packet counter visible, so the hold below
    # can tell a session that keeps carrying data from an entry that merely stays ESTABLISHED. It
    # only applies to entries created after it is set, so it is set before the session starts.
    local acct_before; acct_before=$(vps sysctl -n net.netfilter.nf_conntrack_acct)
    vps sysctl -qw net.netfilter.nf_conntrack_acct=1
    # h_orig_packets: the orig-direction packet count of the session's conntrack entry (the one
    # with source port $h_before_sport), or empty when there is no such entry.
    h_orig_packets() {
      vps conntrack -L -p tcp --dport 39996 --src 198.51.100.2 -o extended 2>/dev/null \
        | grep ESTABLISHED | grep -- "$h_before_sport " | grep -oE 'packets=[0-9]+' | head -1 | cut -d= -f2
    }
    # 50 rounds at 0.4s (20s) outlasts the retarget, its checks, the 3s hold and the source_deny.
    local rounds3=50 interval3=0.4
    ip netns exec client python3 "$PY/tcpprobe.py" 198.51.100.1 39996 "$rounds3" "$interval3" \
      > /tmp/wgft-lifecycle-c6-h.log 2>&1 < /dev/null &
    local h_pid=$!
    wait_until 5 tcp_flow_up 39996
    local h_before_sport; h_before_sport=$(vps conntrack -L -p tcp --dport 39996 --src 198.51.100.2 2>/dev/null | grep ESTABLISHED | grep -oE 'sport=[0-9]+' | head -1)
    squat_port 39996
    retarget_same_port_as_proxy "$h"
    must_wait "check6h: the same-port Transparent->Relay is reported not_active" 5 rule_state_is "$h" apply_state not_active
    check "its reason names the bind failure" "bind failed" "$(rule_state_field "$h" reason)"
    okcheck "the port is listed as retiring" "$(drift_has retiring "$h" && echo 1 || echo 0)"
    absent "a new connection gets no reply from wgft's target while the rule is not_active (no dispatch is published for it)" \
      "tcp-echo" "$(client 'echo hi | socat -t 2 - TCP:198.51.100.1:39996' 2>&1)"
    okcheck "the established session is still running (not yet broken) right after the retarget" \
      "$([ ! -s /tmp/wgft-lifecycle-c6-h.log ] && echo 1 || echo 0)"
    okcheck "its conntrack entry is still ESTABLISHED" \
      "$(vps conntrack -L -p tcp --dport 39996 --src 198.51.100.2 2>/dev/null | grep -q ESTABLISHED && echo 1 || echo 0)"
    local h_after_sport; h_after_sport=$(vps conntrack -L -p tcp --dport 39996 --src 198.51.100.2 2>/dev/null | grep ESTABLISHED | grep -oE 'sport=[0-9]+' | head -1)
    check "it is the same conntrack entry (same source port), not a new one" "$h_before_sport" "$h_after_sport"
    echo "-- the session keeps carrying data while the rule stays not_active (held 3s, then asserted again)"
    local pk_before; pk_before=$(h_orig_packets)
    # deliberate: survival over time is the point, so wall-clock time has to pass here.
    sleep 3
    local pk_after; pk_after=$(h_orig_packets)
    okcheck "after the hold, the same entry (source port ${h_before_sport#sport=}) is still ESTABLISHED" \
      "$(vps conntrack -L -p tcp --dport 39996 --src 198.51.100.2 2>/dev/null | grep ESTABLISHED | grep -q -- "$h_before_sport " && echo 1 || echo 0)"
    okcheck "after the hold, data is still flowing: the entry's packet counter grew ($pk_before -> $pk_after)" \
      "$([ -n "$pk_before" ] && [ -n "$pk_after" ] && [ "$pk_after" -gt "$pk_before" ] && echo 1 || echo 0)"
    okcheck "after the hold, the client session has not ended" "$([ ! -s /tmp/wgft-lifecycle-c6-h.log ] && echo 1 || echo 0)"
    echo "-- adding a source_deny that covers the session's source cuts it (Retire); the source was allowed by both the old and the new policy until now"
    add_source_deny "$h" 198.51.100.2/32
    # must_wait: nothing downstream re-checks the conntrack entry itself before the final log
    # check, which only inspects the client-side python process's own (possibly slower, TCP-
    # timeout-bound) view of the break.
    must_wait "check6h: the established session's conntrack entry is removed once denied" 10 tcp_flow_gone 39996
    wait "$h_pid" 2>/dev/null
    local hlog; hlog=$(cat /tmp/wgft-lifecycle-c6-h.log)
    if [[ "$hlog" == *"got=$((rounds3 * 10));"* ]]; then
      echo "FAIL  the session should have been cut once the source_deny covered it, not run to completion: $hlog"; fail=1
    else
      echo "PASS  the session, safe while not_active, is cut once a source_deny actually covers its source (Retire); log: $hlog"
    fi
    vps sysctl -qw net.netfilter.nf_conntrack_acct="$acct_before"
    echo "-- recovery: with the deny removed and the port freed, the rule becomes active as Relay on its own and serves new connections"
    remove_source_deny "$h" 198.51.100.2/32
    deny_removed() { ! rule_field "$h" source_deny | grep -q 198.51.100.2; }
    must_wait "check6h: the source_deny is removed" 3 deny_removed
    unsquat_port 39996
    # must_wait: 45s covers one full 30s retry interval plus slack; nothing else changes the rule.
    must_wait "check6h: the rule becomes active (as Relay) via the retry" 45 rule_state_is "$h" apply_state active
    check "it is a Relay rule now" "proxy" "$(rule_field "$h" vps_mode)"
    # bare wait_until: re-checked by the check() right after (same probe, same port).
    wait_until 10 tcp_probe_ok 39996
    check "a new connection gets tcp-echo through the proxy" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39996')"
    vps wgft rule rm "$h" --admin "$ADMIN" >/dev/null
  else
    skip "proxy bind failures and Relay fail-closed semantics (proxy mode's public listener and nft DNAT only exist in kernel mode, design 6.1/6.2/7a.3)"
  fi

  if [ "$mode" = userspace ]; then
    echo "-- f. one squatted port of a range rule fails the whole range's bind (no partial listen)"
    squat_port 25631
    local f; f=$(vps wgft rule add --agent home --tcp 25630-25632 --to 192.168.50.3:25630 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
    must_wait "check6f: the range rule is reported not_active" 5 rule_state_is "$f" apply_state not_active
    check "its reason names the bind failure" "bind failed" "$(rule_state_field "$f" reason)"
    # 25631 itself shows as listening (our own squat holds it); the check is that wgft did not
    # also bind the other two ports of the range on top of it (no partial listen).
    okcheck "the two free ports of the range are not bound by wgft (no partial listen)" \
      "$([ "$(vps ss -ltn | grep -cE ':(25630|25632) ')" = 0 ] && echo 1 || echo 0)"
    unsquat_port 25631
    vps wgft rule rm "$f" --admin "$ADMIN" >/dev/null
  else
    skip "range-rule all-or-nothing bind (userspace-only: kernel Transparent ranges are plain nft DNAT with no bind involved, design 6.1)"
  fi

  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"
}

# ---------------------------------------------------------------------------------------------
# check 7: backend-wide (Commit) failures (design 7a.3 節), kernel mode only: the foreign-owner
# table-swap failure this exercises is the same nft transaction check3b uses, which only exists
# in the kernel backend. d: holding table inet wgft as another process and then changing one rule
# and deleting another leaves the rules pending with apply_error set (the held table lost their
# rows), and the deleted rule listed in drift.active_only, all without advancing the active
# generation; once the obstruction is gone the next apply converges. e: a known number of deny
# drops read just before a failed swap are not accumulated twice once the next swap succeeds.
# ---------------------------------------------------------------------------------------------
check7() {
  echo "== $mode: check 7: backend-wide failures leave rules pending, list drift, and do not double count drops"
  if [ "$mode" != kernel ]; then
    skip "backend-wide nftables swap failures (the foreign-table-owner technique this exercises only applies to the kernel backend's nft transaction)"
    return
  fi
  local DATA=/tmp/wgft-lifecycle-c7 ADATA=/tmp/wgft-lifecycle-c7-agent
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"; mkdir -p "$DATA"

  start_server "$DATA" /tmp/wgft-lifecycle-c7-server.log
  if ! wait_admin; then echo "FAIL  check7 setup: admin api never came up"; fail=1; return; fi
  local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-lifecycle-c7-agent.log 2>&1 < /dev/null &
  disown
  ip netns exec lan setsid nohup echo -bind 192.168.50.3 -tcp 25640 -udp 19190 \
    > /tmp/wgft-lifecycle-c7-echo.log 2>&1 < /dev/null &
  disown
  if ! wait_agent home; then echo "FAIL  check7 setup: agent never registered"; fail=1; return; fi

  # hold_table/release_table: the same foreign-owner technique check3b uses (nft -i fed through a
  # fifo kept open, so it never sees EOF and keeps holding the table), factored out here since
  # check7 uses it twice (scenarios d and e).
  nft_i_ready() { vps pgrep -x nft >/dev/null 2>&1; }
  foreign_owner_table_present() { vps nft list table inet wgft 2>/dev/null | grep -q 'flags owner'; }
  # The replacement is one nftables transaction, for the same reason as in check3b.
  hold_table() {
    rm -f /tmp/wgft-lifecycle-c7-fifo /tmp/wgft-lifecycle-c7-owner.log
    mkfifo /tmp/wgft-lifecycle-c7-fifo
    vps bash -c 'exec 3<>/tmp/wgft-lifecycle-c7-fifo; nft -i <&3 >/tmp/wgft-lifecycle-c7-owner.log 2>&1 &'
    # must_wait, and bail out here rather than falling through: the next line's write to the fifo
    # blocks until some reader has it open, so a nft -i that never actually started would hang the
    # whole script instead of just failing this check (same reasoning as check3b's own hold).
    must_wait "check7: nft -i reading the fifo" 3 nft_i_ready || return 1
    echo 'add table inet wgft; delete table inet wgft; add table inet wgft { flags owner; }' > /tmp/wgft-lifecycle-c7-fifo
    must_wait "check7: a foreign owner table exists" 5 foreign_owner_table_present
  }
  release_table() {
    local owner_pid; owner_pid=$(vps pgrep -x nft | head -1)
    [ -n "$owner_pid" ] && kill "$owner_pid" 2>/dev/null
    must_wait "check7: the foreign nft -i (owner pid $owner_pid) exited" 5 proc_gone "$owner_pid"
    rm -f /tmp/wgft-lifecycle-c7-fifo /tmp/wgft-lifecycle-c7-owner.log
  }
  apply_error_set() { [ -n "$(apply_top_field apply_error)" ]; }
  all_active() { rule_state_is "$z" apply_state active && rule_state_is "$x" apply_state active && rule_state_is "$y" apply_state active; }

  echo "-- d. a backend-wide failure leaves the rules pending and a deleted rule in drift.active_only"
  local z x y
  z=$(vps wgft rule add --agent home --tcp 39999 --to 192.168.50.3:25640 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  x=$(vps wgft rule add --agent home --tcp 8480 --to 192.168.50.3:25640 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  y=$(vps wgft rule add --agent home --tcp 8481 --to 192.168.50.3:25640 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  must_wait "check7: z, x and y all start active" 5 all_active

  if ! hold_table; then
    kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
    rm -rf "$DATA" "$ADATA"; return
  fi
  retarget_and_delete "$x" 192.168.50.3:25641 "$y"
  # bare wait_until: re-checked by the check() right after (same field).
  wait_until 5 apply_error_set
  check "apply_error reports the failed swap" "operation not permitted" "$(apply_top_field apply_error)"
  check "the swap failure is logged" "failed to apply nftables" "$(tail -5 /tmp/wgft-lifecycle-c7-server.log)"
  okcheck "desired_generation is now ahead of active_generation" \
    "$([ "$(apply_top_field desired_generation)" != "$(apply_top_field active_generation)" ] && echo 1 || echo 0)"
  okcheck "the retargeted rule x is pending, not silently active or not_active" \
    "$(rule_state_is "$x" apply_state pending && echo 1 || echo 0)"
  # Holding the table replaces its contents, which the server notices as drift (design 7a.3 section,
  # 実際の状態への収束): z's rows are gone and cannot be republished, so z is honestly pending
  # too, not active. That an untouched rule stays active through a backend-wide failure that
  # leaves the table alone is covered by internal/reconcile's unit tests.
  # bare wait_until: re-checked by the okcheck right after (same condition). The drift is noticed
  # asynchronously, a moment after the hold.
  wait_until 5 rule_state_is "$z" apply_state pending
  okcheck "the untouched control rule z is pending as well, since the held table no longer has its rows" \
    "$(rule_state_is "$z" apply_state pending && echo 1 || echo 0)"
  okcheck "the deleted rule y is listed as still-active drift" "$(drift_has active_only "$y" && echo 1 || echo 0)"

  echo "-- once the owner is gone, the next apply converges: generations match again and drift clears"
  release_table
  # disable+enable x, the same trick check3b uses, to force a real (non-retry) apply once the
  # obstruction is gone, since a note-only edit would not push new state (design 5.3/5.4).
  vps wgft rule disable "$x" --admin "$ADMIN" >/dev/null 2>&1
  must_wait "check7: disabling x applied" 3 rule_field_is "$x" enabled "False"
  vps wgft rule enable "$x" --admin "$ADMIN" >/dev/null 2>&1
  must_wait "check7: x is active again" 10 rule_state_is "$x" apply_state active
  okcheck "generations are equal again after the recovering apply" "$(generations_equal && echo 1 || echo 0)"
  okcheck "drift.active_only is empty again" "$(drift_empty active_only && echo 1 || echo 0)"
  okcheck "drift.retiring is empty" "$(drift_empty retiring && echo 1 || echo 0)"
  vps wgft rule rm "$x" --admin "$ADMIN" >/dev/null 2>&1

  echo "-- e. drop counters read just before a failed swap are not accumulated twice once the next swap succeeds"
  local denysrc=203.0.113.50 flood_n=40
  local w; w=$(vps wgft rule add --agent home --udp 27050 --to 192.168.50.3:19190 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  wait_until 10 udp_probe_ok 27050
  add_source_deny "$w" "$denysrc/32"
  deny_applied() { rule_field "$w" source_deny | grep -q "$denysrc"; }
  must_wait "check7e: source_deny applied" 3 deny_applied
  ip netns exec client ip addr add "$denysrc/24" dev eth0 2>/dev/null
  ip netns exec client python3 "$PY/flood.py" udp 198.51.100.1 27050 "$denysrc" "$flood_n" \
    > /tmp/wgft-lifecycle-c7-flood.log 2>&1
  echo "   $(cat /tmp/wgft-lifecycle-c7-flood.log)"
  # committing the flood's drops via a normal (non-seized) apply first is deliberate: nftables has
  # no way to hand table inet wgft to a foreign owner without deleting it first (as hold_table
  # does), which would destroy its live counters along with it. Reading them into the store via an
  # ordinary apply, on a rule unrelated to w, before the table is ever seized, is what lets the
  # failed-then-successful swap below be a clean test of "not accumulated twice" rather than of
  # data loss (confirmed by hand in the lab: seizing before this step reads back 0, not flood_n).
  vps wgft rule disable "$z" --admin "$ADMIN" >/dev/null 2>&1
  vps wgft rule enable "$z" --admin "$ADMIN" >/dev/null 2>&1
  drops_committed() { [ "$(rule_drops "$w")" = "$flood_n" ]; }
  must_wait "check7e: the flood's drops are committed" 5 drops_committed
  local before; before=$(rule_drops "$w"); [ -z "$before" ] && before=0
  check "the flood's drops are committed exactly once before any swap failure" "$flood_n" "$before"

  if ! hold_table; then
    kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
    rm -rf "$DATA" "$ADATA"; return
  fi
  vps wgft rule disable "$z" --admin "$ADMIN" >/dev/null 2>&1
  wait_until 5 apply_error_set
  check "apply_error reports the failed swap (drop counters were read but the swap, and any commit, did not happen)" \
    "operation not permitted" "$(apply_top_field apply_error)"
  release_table
  vps wgft rule enable "$z" --admin "$ADMIN" >/dev/null 2>&1
  must_wait "check7e: z is active again after the successful swap" 10 rule_state_is "$z" apply_state active
  local after; after=$(rule_drops "$w"); [ -z "$after" ] && after=0
  check "the rule's cumulative drops still equal exactly what was sent, not double counted" "$flood_n" "$after"

  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"
}

# ---------------------------------------------------------------------------------------------
# check 8: a rule-local bind failure recovers on its own via the 30s retry (design 7a.3 節,
# internal/vpsd/apply.go's retryOnce) once the squatted port is freed, without any other change,
# and a retry that would publish nothing new does not replace the nft table (kernel mode:
# `nft -a list table inet wgft` handles are unchanged across a window while still squatted). Runs
# in both modes since the retry loop and its no-op check are backend-agnostic; only the handle
# comparison itself is kernel-specific (userspace has no nftables table).
# ---------------------------------------------------------------------------------------------
check8() {
  echo "== $mode: check 8: a rule-local bind failure recovers via the 30s retry; a no-op retry does not replace the nft table"
  local DATA=/tmp/wgft-lifecycle-c8 ADATA=/tmp/wgft-lifecycle-c8-agent
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"; mkdir -p "$DATA"

  start_server "$DATA" /tmp/wgft-lifecycle-c8-server.log
  if ! wait_admin; then echo "FAIL  check8 setup: admin api never came up"; fail=1; return; fi
  local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-lifecycle-c8-agent.log 2>&1 < /dev/null &
  disown
  ip netns exec lan setsid nohup echo -bind 192.168.50.3 -tcp 25650 \
    > /tmp/wgft-lifecycle-c8-echo.log 2>&1 < /dev/null &
  disown
  if ! wait_agent home; then echo "FAIL  check8 setup: agent never registered"; fail=1; return; fi

  local port=8490
  port_listening() { vps ss -ltn 2>/dev/null | grep -q ":$port "; }
  port_free() { ! port_listening; }
  squat() {
    vps setsid nohup socat "TCP-LISTEN:$port,reuseaddr,fork" EXEC:/bin/cat \
      > /tmp/wgft-lifecycle-c8-squat.log 2>&1 < /dev/null &
    disown
    wait_until 3 port_listening
  }
  unsquat() { pkill -x socat; wait_until 3 port_free; }

  squat
  local r
  if [ "$mode" = kernel ]; then
    r=$(vps wgft rule add --agent home --tcp "$port" --to 192.168.50.3:25650 --proxy --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  else
    r=$(vps wgft rule add --agent home --tcp "$port" --to 192.168.50.3:25650 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  fi
  must_wait "check8: the squatted rule is reported not_active" 5 rule_state_is "$r" apply_state not_active
  check "its reason names the bind failure" "bind failed" "$(rule_state_field "$r" reason)"
  local fail_line
  if [ "$mode" = kernel ]; then fail_line="cannot open listener for $port:"; else fail_line="listener tcp/$port:"; fi
  fail_log_count() {
    if [ "$mode" = kernel ]; then
      grep -c "$fail_line" /tmp/wgft-lifecycle-c8-server.log
    else
      grep "$fail_line" /tmp/wgft-lifecycle-c8-server.log | grep -vc "opened after"
    fi
  }
  okcheck "the bind failure is logged exactly once so far" "$([ "$(fail_log_count)" = 1 ] && echo 1 || echo 0)"

  local before_handles=""
  if [ "$mode" = kernel ]; then before_handles=$(vps nft -a list table inet wgft 2>/dev/null); fi
  # deliberate: retries run every 30s from server startup (design 7a.3), so a 35s wait guarantees
  # at least one retry tick lands while the port is still squatted, without depending on exactly
  # when in that cycle the rule was added.
  sleep 35
  okcheck "the rule is still not_active after a no-op retry window" "$(rule_state_is "$r" apply_state not_active && echo 1 || echo 0)"
  okcheck "the bind failure is still logged exactly once (the no-op retry did not re-log it)" \
    "$([ "$(fail_log_count)" = 1 ] && echo 1 || echo 0)"
  if [ "$mode" = kernel ]; then
    local after_handles; after_handles=$(vps nft -a list table inet wgft 2>/dev/null)
    check "a no-op retry does not replace table inet wgft (handles are unchanged)" "$before_handles" "$after_handles"
  else
    skip "nft table handle stability (userspace mode has no nftables table)"
  fi

  unsquat
  # must_wait: ~40s covers one full retry interval plus scheduling slack; nothing else changes the
  # rule, so recovery can only come from the retry loop noticing the port is free.
  must_wait "check8: the rule recovers to active within ~40s via the retry, with no other change" 45 rule_state_is "$r" apply_state active
  check "it actually forwards once active" "tcp-echo" "$(client "echo hi | socat -t 3 - TCP:198.51.100.1:$port")"
  local recover_line
  if [ "$mode" = kernel ]; then recover_line="$port: listener opened after"; else recover_line="listener tcp/$port: opened after"; fi
  okcheck "the recovery is logged exactly once" "$([ "$(grep -c "$recover_line" /tmp/wgft-lifecycle-c8-server.log)" = 1 ] && echo 1 || echo 0)"
  okcheck "the rule-level recovery is logged exactly once" \
    "$([ "$(grep -c "rule $r: no longer failing" /tmp/wgft-lifecycle-c8-server.log)" = 1 ] && echo 1 || echo 0)"

  vps wgft rule rm "$r" --admin "$ADMIN" >/dev/null 2>&1
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"
}

# ---------------------------------------------------------------------------------------------
# check 9: kernel state changed outside wgft is restored (design 7a.3 節, 実際の状態への収束),
# kernel mode only. The nftables change notifications wake the server, which observes the table
# and republishes it when it differs from what it committed; with nothing changed it commits
# nothing. A table held by another process (flags owner) disappears without any notification
# when that process exits, so the release is picked up by the 30s retry instead.
# ---------------------------------------------------------------------------------------------
check9() {
  echo "== $mode: check 9: kernel state changed outside wgft is restored"
  if [ "$mode" != kernel ]; then
    skip "restoring table inet wgft (userspace mode keeps its dataplane inside the process, with no kernel state to lose, design 6.3/7a.3)"
    return
  fi
  local DATA=/tmp/wgft-lifecycle-c9 ADATA=/tmp/wgft-lifecycle-c9-agent LOG=/tmp/wgft-lifecycle-c9-server.log
  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"; mkdir -p "$DATA"

  start_server "$DATA" "$LOG"
  if ! wait_admin; then echo "FAIL  check9 setup: admin api never came up"; fail=1; return; fi
  local join; join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-lifecycle-c9-agent.log 2>&1 < /dev/null &
  disown
  ip netns exec lan setsid nohup echo -bind 192.168.50.3 -tcp 25660 > /tmp/wgft-lifecycle-c9-echo.log 2>&1 < /dev/null &
  disown
  if ! wait_agent home; then echo "FAIL  check9 setup: agent never registered"; fail=1; return; fi

  local r; r=$(vps wgft rule add --agent home --tcp 39990 --to 192.168.50.3:25660 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  # bare wait_until: re-checked by the check() right after (same probe, same port).
  wait_until 10 tcp_probe_ok 39990
  check "the rule forwards before anything" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39990')"
  drift_lines() { grep -c "data plane changed outside wgft" "$LOG"; }
  applied_lines() { grep -c "applied table inet wgft" "$LOG"; }

  echo "-- a. nft flush ruleset (what a reload of an nftables.conf starting with flush ruleset does)"
  vps nft flush ruleset
  # must_wait: the change notification wakes the server within a debounce of 250ms; 5s is slack.
  must_wait "check9a: forwarding is back within 5s of the flush" 5 tcp_probe_ok 39990
  check "the rule forwards again after the flush" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39990')"
  check "one log line names what drifted" "data plane changed outside wgft (table inet wgft is missing)" "$(grep "data plane changed" "$LOG")"
  okcheck "exactly one drift line so far" "$([ "$(drift_lines)" = 1 ] && echo 1 || echo 0)"

  echo "-- b. nft delete table inet wgft"
  vps nft delete table inet wgft
  must_wait "check9b: forwarding is back within 5s of the delete" 5 tcp_probe_ok 39990
  check "the rule forwards again after the delete" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39990')"
  okcheck "exactly one more drift line" "$([ "$(drift_lines)" = 2 ] && echo 1 || echo 0)"

  echo "-- c. with nothing of wgft's changed, nothing is republished (another table's churn included)"
  # table_handles: every line of the table that carries a handle (table, chains, sets, rules), without
  # the elements of the dynamic sets (flows_tcp, meters), which change with traffic alone.
  table_handles() { vps nft -a list table inet wgft 2>/dev/null | grep '# handle'; }
  local before_handles before_applied; before_handles=$(table_handles)
  before_applied=$(applied_lines)
  vps nft add table ip wgft-lifecycle-unrelated
  vps nft add chain ip wgft-lifecycle-unrelated c
  vps nft delete table ip wgft-lifecycle-unrelated
  # deliberate: nothing observable happens when nothing is republished, so a full 30s retry
  # interval plus slack has to pass to show that neither the notifications of wgft's own commits,
  # nor another table's changes, nor the retry timer replace the table.
  sleep 35
  check "table inet wgft's handles are unchanged" "$before_handles" "$(table_handles)"
  okcheck "no apply was logged in the window" "$([ "$(applied_lines)" = "$before_applied" ] && echo 1 || echo 0)"
  okcheck "no drift line was logged in the window" "$([ "$(drift_lines)" = 2 ] && echo 1 || echo 0)"

  echo "-- d. a table held by another process leaves an admin change pending until the holder exits"
  # Same foreign-owner technique as check3b/check7, as one nftables transaction.
  rm -f /tmp/wgft-lifecycle-c9-fifo /tmp/wgft-lifecycle-c9-owner.log
  mkfifo /tmp/wgft-lifecycle-c9-fifo
  vps bash -c 'exec 3<>/tmp/wgft-lifecycle-c9-fifo; nft -i <&3 >/tmp/wgft-lifecycle-c9-owner.log 2>&1 &'
  nft_i_ready() { vps pgrep -x nft >/dev/null 2>&1; }
  if ! must_wait "check9: nft -i reading the fifo" 3 nft_i_ready; then
    rm -f /tmp/wgft-lifecycle-c9-fifo
    kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
    rm -rf "$DATA" "$ADATA"; return
  fi
  echo 'add table inet wgft; delete table inet wgft; add table inet wgft { flags owner; }' > /tmp/wgft-lifecycle-c9-fifo
  foreign_owner_table_present() { vps nft list table inet wgft 2>/dev/null | grep -q 'flags owner'; }
  must_wait "check9: a foreign owner table exists" 5 foreign_owner_table_present
  local owner_pid; owner_pid=$(vps pgrep -x nft | head -1)
  vps wgft rule add --agent home --tcp 39991 --to 192.168.50.3:25660 --admin "$ADMIN" >/dev/null 2>&1
  local r2; r2=$(vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['listen_port'] == '39991':
        print(r['id'])
")
  apply_error_set() { [ -n "$(apply_top_field apply_error)" ]; }
  # bare wait_until: re-checked by the check() right after (same field).
  wait_until 5 apply_error_set
  check "apply_error reports the held table" "operation not permitted" "$(apply_top_field apply_error)"
  okcheck "the added rule is pending" "$(rule_state_is "$r2" apply_state pending && echo 1 || echo 0)"
  okcheck "desired_generation is ahead of active_generation" \
    "$([ "$(apply_top_field desired_generation)" != "$(apply_top_field active_generation)" ] && echo 1 || echo 0)"
  local log_before; log_before=$(wc -l < "$LOG")
  [ -n "$owner_pid" ] && kill "$owner_pid" 2>/dev/null
  must_wait "check9: the foreign nft -i (owner pid $owner_pid) exited" 5 proc_gone "$owner_pid"
  rm -f /tmp/wgft-lifecycle-c9-fifo /tmp/wgft-lifecycle-c9-owner.log
  # must_wait: the release sends no notification, so the 30s retry picks it up; 45s is one full
  # interval plus slack. No admin change is made from here on.
  must_wait "check9d: the pending generation is published without an admin change" 45 generations_equal
  okcheck "the added rule is active" "$(rule_state_is "$r2" apply_state active && echo 1 || echo 0)"
  okcheck "the first rule is active" "$(rule_state_is "$r" apply_state active && echo 1 || echo 0)"
  okcheck "no admin change was logged after the release" \
    "$(tail -n +"$((log_before + 1))" "$LOG" | grep -q "rules: cli" && echo 0 || echo 1)"
  # bare wait_until: re-checked by the check() right after. The agent opens its listener for the
  # new rule once the published generation is delivered over the stream.
  wait_until 10 tcp_probe_ok 39991
  check "the rule added while the table was held forwards end to end" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39991')"
  check "the first rule forwards again" "tcp-echo" "$(client 'echo hi | socat -t 3 - TCP:198.51.100.1:39990')"

  kill_all; vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1; reset_kernel_state
  rm -rf "$DATA" "$ADATA"
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
