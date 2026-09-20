#!/usr/bin/env bash
# rates.sh exercises the three rate limits of a UDP rule and a Relay (proxy) rule under load, in
# one forwarding mode, and judges the result PASS/FAIL (design.md 7a.9 節: Admission Policy の
# evaluation order deny -> allow -> per_source -> src_flow -> new_flow -> packet):
#
#   lab/lab exec vm bash /wgft/lab/rates.sh kernel
#   lab/lab exec vm bash /wgft/lab/rates.sh userspace
#
# What each block proves:
#   packet       packet_rate caps a UDP flow's own datagram rate, far below what an unlimited flow
#                gets through
#   per-source   per_source_rate caps new UDP flows per source address; a second, fresh address is
#                judged on its own bucket, not blocked by the first address's flood
#   new-flow     new_flow_rate is judged once for the WHOLE rule, not once per source: flooding
#                four different source addresses at once still only lets roughly one burst through
#                in total, not one burst PER address
#   ordering     a source blocked by source_deny (an earlier stage) does not spend the rule's
#                aggregate new_flow_rate tokens (a later stage): a fresh, undenied address right
#                after the denied flood still gets its full new-flow allowance
#   tcp-packet   packet_rate stored on a TCP (Relay) rule has no effect (design 7a.9 節): a burst of
#                TCP connections succeeds at essentially the unlimited rate despite the setting
#   relay        the Relay (proxy) rule's per-source and new-flow rates behave the same way as the
#                Transparent rule's (design 7a.9 節: Relay ルールも Admission Policy のすべての段を持つ)
#
# Every numeric assertion is a bound derived from the configured rate and the fixed token-bucket
# burst (5, design 7a.9 節), never an exact packet count from a rate limiter: token refill timing
# and scheduling jitter make exact counts flaky. The SAME bound formulas are used regardless of
# $mode, so a PASS in both a `kernel` run and a `userspace` run of this script is how this script
# shows kernel and userspace agree within the tolerance those bounds allow; it does not diff one
# run's numbers against the other run's numbers directly (see docs/testing.md's L3 entry).
#
# PARALLEL-SAFETY: unlike lab/lifecycle.sh's check 5 family, this script's bursts are small (at
# most 500 datagrams or 20-40 connections, not thousands) and do not sample RSS, so it is
# reasonably parallel-safe against other lab scripts. It is timing-sensitive, though (the
# packet/per-source/new-flow bounds assume real-time token bucket refills over a few seconds), so
# do not run two copies of it (e.g. its own kernel and userspace runs) against the same VM's CPU at
# once; run them one after another like every other pair of mode runs in this lab.
#
# Requires `lab/lab build` and the netns topology; leftovers from earlier runs are killed first.
set -u
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: rates.sh kernel|userspace" >&2; exit 2;; esac

. "$(dirname "$0")/sandbox.sh"   # sandbox: netns names, workdir, process scope
DATA=$W/wgft-rates-server
ADATA=$W/wgft-rates-agent
ADMIN=127.0.0.1:8686
fail=0

check() { # check <label> <expected-substring> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
eqcheck() { # eqcheck <label> <want> <got>: integers must be equal.
  if [ "$2" -eq "$3" ] 2>/dev/null; then echo "PASS  $1"; else echo "FAIL  $1: got '$3', want '$2'"; fail=1; fi
}
okcheck() { # okcheck <label> <ok-if-true 1/0>
  if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi
}
# bound <label> <got> <min> <max>: got must fall in [min, max], inclusive.
bound() {
  local label=$1 got=$2 min=$3 max=$4
  okcheck "$label (got $got, want $min..$max)" \
    "$([ -n "$got" ] && [ "$got" -ge "$min" ] 2>/dev/null && [ "$got" -le "$max" ] 2>/dev/null && echo 1 || echo 0)"
}

vps() { ip netns exec "$VPS_NS" "$@"; }
client() { ip netns exec "$CLIENT_NS" bash -c "$1"; }
kill_all() { sandbox_kill_named wgft echo socat; sleep 1; }
cleanup() {
  kill_all
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  rm -rf "$DATA" "$ADATA"
}

# wait_until <timeout-seconds> <command...>: polls WALL-CLOCK time ($SECONDS), not an iteration
# count, the same helper (and the same reasoning) as lab/ipv6.sh's.
wait_until() {
  local timeout=$1; shift
  local deadline=$((SECONDS + timeout))
  while :; do
    "$@" >/dev/null 2>&1 && return 0
    (( SECONDS >= deadline )) && return 1
    sleep 0.2
  done
}
admin_up() { vps wgft agent ls --admin "$ADMIN" >/dev/null 2>&1; }
# agent_registered: true once "home" has registered AND its WireGuard peer has handshaken (same
# technique, and the same reason, as lab/ipv6.sh's agent_registered).
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
tcp_probe_ok() { [[ "$(client "echo hi | timeout -k 5 20 socat -t 1 -T 8 - TCP:198.51.100.1:$1" 2>/dev/null)" == *tcp-echo* ]]; }
udp_probe_ok() { [[ "$(client "echo hi | timeout -k 5 20 socat -t 1 -T 8 - UDP:198.51.100.1:$1" 2>/dev/null)" == *udp-echo* ]]; }

cleanup
mkdir -p "$DATA"
if [ "$mode" = userspace ]; then
  id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab
  chown wgftlab "$DATA"
  run_server="runuser -u wgftlab -- wgft server run"
else
  run_server="wgft server run"
fi
vps setsid nohup $run_server --mode "$mode" --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
  > $W/wgft-rates-server.log 2>&1 < /dev/null &
disown
if ! wait_until 30 admin_up; then echo "FAIL  setup: admin api did not come up"; fail=1; fi
join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
WGFT_JOIN="$join" ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$ADATA" > $W/wgft-rates-agent.log 2>&1 < /dev/null &
disown
ip netns exec "$LAN_NS" setsid nohup echo -udp 19132 -tcp 19133 > $W/wgft-rates-echo.log 2>&1 < /dev/null &
disown
if ! wait_until 30 agent_registered; then echo "FAIL  setup: agent never registered"; fail=1; fi
u=$(vps wgft rule add --agent home --udp 27015 --to 192.168.50.3:19132 --admin "$ADMIN" | grep -oE 'r_[A-Z0-9]+')
p=$(vps wgft rule add --agent home --tcp 27016 --to 192.168.50.3:19133 --proxy --admin "$ADMIN" | grep -oE 'r_[A-Z0-9]+')
wait_until 15 udp_probe_ok 27015
wait_until 15 tcp_probe_ok 27016
# .3 through .9: extra client-side source addresses for the per-source, aggregate and ordering
# blocks below (each needs traffic that is distinguishable, or independent, by source address).
for i in 3 4 5 6 7 8 9; do
  ip netns exec "$CLIENT_NS" ip addr add "198.51.100.$i/24" dev eth0 2>/dev/null
done

# flows <src-ip> <n>: open n UDP sockets from src-ip, send one datagram each, count sockets that
# got an answer.
flows() {
  client "python3 - <<EOF
import socket, time
got = 0
socks = []
for i in range($2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"$1\", 0)); s.settimeout(0.05)
    s.sendto(b\"f\", (\"198.51.100.1\", 27015)); socks.append(s)
time.sleep(1.5)
for s in socks:
    s.settimeout(0.01)
    try:
        s.recvfrom(2048); got += 1
    except socket.timeout:
        pass
print(got)
EOF"
}
# flows_multi <n-per-src> <src-ip...>: like flows(), but opens n-per-src UDP sockets from EACH of
# several source addresses at once and returns the combined total that got an answer. Used to show
# new_flow_rate is judged once for the whole rule: a (buggy) per-source judgement would let every
# address in up to its own burst, so the total would scale with the number of addresses; the
# correct, rule-wide judgement keeps the total close to one burst no matter how many addresses send.
flows_multi() {
  local n=$1; shift
  client "python3 - <<EOF
import socket, time
srcs = '$*'.split()
got = 0
socks = []
for src in srcs:
    for i in range($n):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((src, 0)); s.settimeout(0.05)
        s.sendto(b'f', ('198.51.100.1', 27015)); socks.append(s)
time.sleep(1.5)
for s in socks:
    s.settimeout(0.01)
    try:
        s.recvfrom(2048); got += 1
    except socket.timeout:
        pass
print(got)
EOF"
}
# burst <n>: one flow sends n datagrams back to back, counts echoes received within 3 seconds.
burst() {
  client "python3 - <<EOF
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"198.51.100.2\", 0)); s.settimeout(0.2)
for i in range($1):
    s.sendto(b\"p\", (\"198.51.100.1\", 27015))
got = 0; end = time.time() + 3
while time.time() < end:
    try:
        s.recvfrom(2048); got += 1
    except socket.timeout:
        pass
print(got)
EOF"
}
# conns <src-ip> <n>: open n TCP connections to the Relay port at once and count how many complete
# a round trip. A refused connection appears as a connect timeout in kernel mode (nftables drops
# the SYN) and as a reset in userspace mode (the evaluator refuses after accept), so counting round
# trips works the same way in both modes.
conns() {
  client "python3 - <<EOF
import socket, threading
got = []
lock = threading.Lock()
def one():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((\"$1\", 0)); s.settimeout(1.5)
    try:
        s.connect((\"198.51.100.1\", 27016))
        s.sendall(b\"t\")
        s.shutdown(socket.SHUT_WR)
        if s.recv(256):
            with lock:
                got.append(1)
    except OSError:
        pass
    s.close()
ts = [threading.Thread(target=one) for _ in range($2)]
for t in ts:
    t.start()
for t in ts:
    t.join()
print(len(got))
EOF"
}
drops_of() { vps wgft rule ls --json --admin "$ADMIN" 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin); print((d.get("drops") or {}).get("'"$1"'", 0))' 2>/dev/null; }
drops() { drops_of "$u"; }
# bump_apply forces a real reconcile/apply (add then remove a throwaway, unrelated rule) so that a
# subsequent drops() reflects what actually happened since the last apply: in kernel mode the
# admin API's "drops" field is only updated when an apply runs (design 6.1 節), and this rule's own
# rate changes are the only applies this script otherwise triggers. Same technique as
# lab/ipv6.sh's bump_apply, with the same caveat: it also resets every rule's meter (kernel mode's
# table_replacement_reset tolerance, design 7a.4 節), so it must only run AFTER any allowance check
# that depends on the meter still holding whatever a preceding flood left it in.
bump_apply() {
  local id
  id=$(vps wgft rule add --agent home --udp 27099 --to 192.168.50.3:19132 --admin "$ADMIN" 2>/dev/null | grep -oE 'r_[A-Za-z0-9]+')
  [ -n "$id" ] && vps wgft rule rm "$id" --admin "$ADMIN" >/dev/null 2>&1
}

echo "== $mode: packet_rate caps a UDP flow's own rate"
echo "-- baseline: no limit, 1 flow sends 500 datagrams"
unlimited_burst=$(burst 500)
echo "   echoes: $unlimited_burst"
# A wide-open lower bound: an unlimited burst of 500 back-to-back datagrams can lose a good
# fraction to socket buffers and scheduling under host load (observed as low as ~280 of 500 in the
# lab), which is not what this block is testing; what matters is that it clearly beats the limited
# case below, checked as a ratio (not a fixed gap) for the same reason.
bound "packet: unlimited burst gets a clear majority of datagrams echoed" "$unlimited_burst" 150 500
echo "-- packet_rate 10/second (burst 5, so a 3s window allows at most 5 + ceil(3*10) refills)"
vps wgft rule rate packet "$u" 10/second --admin "$ADMIN" >/dev/null; sleep 2
limited_burst=$(burst 500)
d=$(drops)
echo "   echoes: $limited_burst   drops: $d"
bound "packet: limited burst stays within the token-bucket bound" "$limited_burst" 1 45
okcheck "packet: the rate clearly limits (unlimited $unlimited_burst, limited $limited_burst, want unlimited >= 3x limited)" \
  "$([ "$((limited_burst * 3))" -le "$unlimited_burst" ] && echo 1 || echo 0)"
vps wgft rule rate packet "$u" none --admin "$ADMIN" >/dev/null; sleep 2

echo "== $mode: per_source_rate caps new UDP flows per source, independently per address"
echo "-- baseline: no limit, 20 flows from 198.51.100.2"
unlimited_flows=$(flows 198.51.100.2 20)
echo "   answered: $unlimited_flows"
bound "per-source: unlimited flows mostly get through" "$unlimited_flows" 15 20
echo "-- per-source 5/minute (burst 5, negligible refill over the 1.5s collection window)"
vps wgft rule rate per-source "$u" 5/minute --admin "$ADMIN" >/dev/null; sleep 2
limited_flows=$(flows 198.51.100.3 20)
fresh_flows=$(flows 198.51.100.4 5)
d=$(drops)
echo "   20 flows from 198.51.100.3 -> answered: $limited_flows"
echo "   5 flows from 198.51.100.4  -> answered: $fresh_flows   drops: $d"
bound "per-source: limited address stays within the token-bucket bound" "$limited_flows" 1 7
okcheck "per-source: a second, fresh address is judged on its own bucket" \
  "$([ "$fresh_flows" -ge 4 ] && echo 1 || echo 0)"
vps wgft rule rate per-source "$u" none --admin "$ADMIN" >/dev/null; sleep 2

echo "== $mode: new_flow_rate caps the whole rule, not each source separately"
echo "-- new-flow 8/minute, 5 flows from EACH of 4 different addresses at once (20 attempts total)"
vps wgft rule rate new-flow "$u" 8/minute --admin "$ADMIN" >/dev/null; sleep 2
agg_answered=$(flows_multi 5 198.51.100.5 198.51.100.6 198.51.100.7 198.51.100.8)
d=$(drops)
echo "   total answered across 4 addresses: $agg_answered   drops: $d"
bound "new-flow: aggregate total stays within one burst's bound, not 4x that" "$agg_answered" 1 8
vps wgft rule rate new-flow "$u" none --admin "$ADMIN" >/dev/null; sleep 2

echo "== $mode: an earlier stage's refusal (source_deny) does not spend a later stage's tokens (new_flow_rate)"
vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['id'] == '$u':
        r.setdefault('source_deny', []).append('198.51.100.4/32')
json.dump(d['rules'], open('$W/wgft-rates-deny.json', 'w'))
"
vps wgft rule import $W/wgft-rates-deny.json --admin "$ADMIN" >/dev/null
vps wgft rule rate new-flow "$u" 8/minute --admin "$ADMIN" >/dev/null; sleep 2
before=$(drops)
denied_answered=$(flows 198.51.100.4 20)
echo "   198.51.100.4 is denied: 20 flows -> answered: $denied_answered"
eqcheck "ordering: the denied flood answers none of its flows" 0 "$denied_answered"
# Measured BEFORE bump_apply below, which also resets the meter (its own comment): if this ran
# after that reset, a fresh address would trivially get its full allowance back regardless of
# whether the denied flood spent any of it, hiding exactly the regression this is meant to catch.
fresh_after_deny=$(flows 198.51.100.9 5)
echo "   198.51.100.9 (fresh, not denied) right after: answered: $fresh_after_deny"
okcheck "ordering: a fresh, undenied address keeps its full new-flow allowance right after the denied flood" \
  "$([ "$fresh_after_deny" -ge 4 ] && echo 1 || echo 0)"
bump_apply
after=$(drops)
echo "   drops before/after: $before/$after"
eqcheck "ordering: the denied flood's 20 packets are all counted as drops" "$((before + 20))" "$after"
vps wgft rule rate new-flow "$u" none --admin "$ADMIN" >/dev/null
vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['id'] == '$u':
        r['source_deny'] = [c for c in (r.get('source_deny') or []) if c != '198.51.100.4/32']
json.dump(d['rules'], open('$W/wgft-rates-undeny.json', 'w'))
"
vps wgft rule import $W/wgft-rates-undeny.json --admin "$ADMIN" >/dev/null
sleep 2

echo "== $mode: packet_rate stored on a TCP (Relay) rule has no effect (design 7a.9 節)"
unlimited_conns=$(conns 198.51.100.2 20)
echo "-- baseline: no limit, 20 connections -> answered: $unlimited_conns"
vps wgft rule rate packet "$p" 1/second --admin "$ADMIN" >/dev/null; sleep 2
tcp_packet_conns=$(conns 198.51.100.3 20)
echo "-- packet_rate 1/second (would leave a UDP rule far below 20 answered): 20 connections -> answered: $tcp_packet_conns"
okcheck "tcp-packet: packet_rate on a TCP rule does not reduce throughput (unlimited $unlimited_conns, with packet_rate $tcp_packet_conns)" \
  "$([ "$tcp_packet_conns" -ge $((unlimited_conns - 2)) ] && echo 1 || echo 0)"
vps wgft rule rate packet "$p" none --admin "$ADMIN" >/dev/null; sleep 2

echo "== $mode: a Relay rule's per-source and new-flow rates are judged the same as a Transparent rule's"
vps wgft rule rate per-source "$p" 5/minute --admin "$ADMIN" >/dev/null; sleep 2
relay_limited=$(conns 198.51.100.2 20)
relay_fresh=$(conns 198.51.100.3 5)
d=$(drops_of "$p")
echo "   per-source 5/minute: 20 connections from 198.51.100.2 -> answered: $relay_limited"
echo "   5 connections from 198.51.100.3  -> answered: $relay_fresh   drops: $d"
bound "relay per-source: limited address stays within the token-bucket bound" "$relay_limited" 1 7
okcheck "relay per-source: a second, fresh address is judged on its own bucket" \
  "$([ "$relay_fresh" -ge 4 ] && echo 1 || echo 0)"
vps wgft rule rate per-source "$p" none --admin "$ADMIN" >/dev/null; sleep 2

vps wgft rule rate new-flow "$p" 8/minute --admin "$ADMIN" >/dev/null; sleep 2
relay_newflow=$(conns 198.51.100.2 20)
d=$(drops_of "$p")
echo "   new-flow 8/minute: 20 connections from 198.51.100.2 -> answered: $relay_newflow   drops: $d"
bound "relay new-flow: aggregate stays within the token-bucket bound" "$relay_newflow" 1 8
vps wgft rule rate new-flow "$p" none --admin "$ADMIN" >/dev/null; sleep 2

for i in 3 4 5 6 7 8 9; do
  ip netns exec "$CLIENT_NS" ip addr del "198.51.100.$i/24" dev eth0 2>/dev/null
done
cleanup
if [ "$fail" = 0 ]; then echo "== $mode: ALL PASS"; else echo "== $mode: FAILURES"; fi
exit "$fail"
