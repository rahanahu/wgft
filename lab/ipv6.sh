#!/usr/bin/env bash
# ipv6.sh proves the IPv4-only fail-closed guard for IPv6 sources (design.md 7a.9 節「IPv4 だけを
# 扱う v1 の守り」): an IPv6 source cannot reach a judged Transparent or Relay port, and an IPv6
# flood cannot spend the aggregate new_flow_rate/packet_rate token buckets that IPv4 traffic on
# the same rule relies on.
#
#   lab/lab exec vm bash /wgft/lab/ipv6.sh kernel
#   lab/lab exec vm bash /wgft/lab/ipv6.sh userspace
#
# The two modes enforce the guard at different layers, so what each check actually proves differs:
#   kernel     nftables never matches an IPv6 packet: DNAT was already IPv4-only (no route for it
#              exists past the VPS anyway, since only the client-vps link has IPv6 addresses), and
#              every Admission Policy row now carries `meta nfproto ipv4` (Phase 5 step 3), so the
#              aggregate new_flow_rate/packet_rate rows do not match an IPv6 packet either and
#              record no drop for it.
#   userspace  the relay's listeners are IPv4-only (tcp4/udp4), so the host kernel refuses an IPv6
#              SYN or datagram (RST / ICMPv6 unreachable) before wgft's own code ever runs; a flood
#              cannot spend the evaluator's tokens because it never arrives at the process.
# Both modes forward IPv4 normally before and after the IPv6 traffic, on a Transparent rule and on
# a Relay (--proxy) rule.
#
# Requires `lab/lab build` (wgft and echo in /usr/local/bin of the VM) and the netns topology,
# which gives the client and vps a 2001:db8::/64 address on their shared link (lab/netns.sh; the
# documentation prefix, not routed past the VPS). Leftovers from earlier runs are killed first.
set -u
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: ipv6.sh kernel|userspace" >&2; exit 2;; esac

DATA=/tmp/wgft-ipv6-server
ADATA=/tmp/wgft-ipv6-agent
ADMIN=127.0.0.1:8686
CLIENT6=2001:db8::2
VPS6=2001:db8::1
fail=0
check() { # check <label> <expected-substring> <actual>: for a marker string (e.g. tcp-echo), not
  # a number. Substring matching a number is wrong ("10" contains "0"); use eqcheck for those.
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
eqcheck() { # eqcheck <label> <want> <got>: integers must be equal. An empty or non-numeric $3
  # (a probe that crashed or printed nothing) makes `-eq` itself fail, which the else branch below
  # reports as FAIL, not a silent pass.
  if [ "$2" -eq "$3" ] 2>/dev/null; then echo "PASS  $1"; else echo "FAIL  $1: got '$3', want '$2'"; fail=1; fi
}
not_forwarded() { # not_forwarded <label> <forbidden-substring> <actual>: the inverse of check.
  if [[ "$3" == *"$2"* ]]; then echo "FAIL  $1: got '$3'"; fail=1; else echo "PASS  $1 (got '$3')"; fi
}
okcheck() { # okcheck <label> <ok-if-true 1/0>
  if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi
}
vps() { ip netns exec vps "$@"; }
client() { ip netns exec client bash -c "$1"; }
kill_all() { pkill -x wgft; pkill -x echo; pkill -x socat; sleep 1; }
cleanup() {
  kill_all
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  rm -rf "$DATA" "$ADATA"
}

# wait_until <timeout-seconds> <command...>: polls until <command...> exits 0 or the timeout
# elapses (0.2s steps). Non-zero on timeout; the caller's own check/okcheck right after re-does
# the same probe, so a timeout still surfaces as that assertion's normal FAIL.
wait_until() {
  local timeout=$1; shift
  local tries=$((timeout * 5)) i
  for ((i = 0; i < tries; i++)); do
    "$@" >/dev/null 2>&1 && return 0
    sleep 0.2
  done
  return 1
}
admin_up() { vps wgft agent ls --admin "$ADMIN" >/dev/null 2>&1; }
agent_registered() { vps wgft agent ls --admin "$ADMIN" 2>/dev/null | tail -1 | grep -q home; }
tcp4_probe_ok() { [[ "$(client "echo hi | timeout -k 5 20 socat -t 1 -T 8 - TCP:198.51.100.1:$1" 2>/dev/null)" == *tcp-echo* ]]; }
udp4_probe_ok() { [[ "$(client "echo hi | timeout -k 5 20 socat -t 1 -T 8 - UDP:198.51.100.1:$1" 2>/dev/null)" == *udp-echo* ]]; }

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
  > /tmp/wgft-ipv6-server.log 2>&1 < /dev/null &
disown
if ! wait_until 30 admin_up; then echo "FAIL  setup: admin api did not come up"; fail=1; fi
join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-ipv6-agent.log 2>&1 < /dev/null &
disown
ip netns exec lan setsid nohup echo -tcp 25566 -udp 19140 > /tmp/wgft-ipv6-echo.log 2>&1 < /dev/null &
disown
if ! wait_until 30 agent_registered; then echo "FAIL  setup: agent never registered"; fail=1; fi

t=$(vps wgft rule add --agent home --tcp 39975 --to 192.168.50.3:25566 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
u=$(vps wgft rule add --agent home --udp 27019 --to 192.168.50.3:19140 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
r=$(vps wgft rule add --agent home --tcp 8447 --to 192.168.50.3:25566 --proxy --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
wait_until 10 tcp4_probe_ok 39975
wait_until 10 udp4_probe_ok 27019
wait_until 10 tcp4_probe_ok 8447

echo "== $mode: ipv4 works before any ipv6 traffic (transparent tcp/udp and a relay port)"
check "transparent tcp works over ipv4 before" "tcp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:39975')"
check "transparent udp works over ipv4 before" "udp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:27019')"
check "relay tcp works over ipv4 before" "tcp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:8447')"

echo "== $mode: an ipv6 source is not forwarded"
not_forwarded "ipv6 tcp (transparent) is not forwarded" "tcp-echo" \
  "$(client "echo hi | timeout -k 5 20 socat -t 2 -T 8 - TCP6:[$VPS6]:39975 2>&1")"
not_forwarded "ipv6 udp (transparent) is not forwarded" "udp-echo" \
  "$(client "echo hi | timeout -k 5 20 socat -t 2 -T 8 - UDP6:[$VPS6]:27019 2>&1")"
not_forwarded "ipv6 tcp (relay) is not forwarded" "tcp-echo" \
  "$(client "echo hi | timeout -k 5 20 socat -t 2 -T 8 - TCP6:[$VPS6]:8447 2>&1")"

# flows <family 4|6> <src-ip> <dst-ip> <port> <n>: opens n UDP sockets from src-ip (a distinct
# source port each), sends one datagram from each to dst-ip:port, and counts sockets that got an
# answer within 0.5s. Same technique as lab/rates.sh's flows(), parameterised on address family so
# it can drive either the ipv6 flood or the ipv4 traffic that follows it. The wait is kept short
# (rather than rates.sh's 1.5s) on purpose: the allowance checks below run this right after a
# flood meant to have spent the rule's token bucket, and a long wait would let the bucket refill
# on its own before the count is taken, hiding a real regression behind an unrelated recovery.
flows() {
  client "python3 - <<EOF
import socket, time
fam = socket.AF_INET6 if '$1' == '6' else socket.AF_INET
got = 0
socks = []
for i in range($5):
    s = socket.socket(fam, socket.SOCK_DGRAM); s.bind(('$2', 0)); s.settimeout(0.05)
    s.sendto(b'f', ('$3', $4)); socks.append(s)
time.sleep(0.5)
for s in socks:
    s.settimeout(0.01)
    try:
        s.recvfrom(2048); got += 1
    except OSError:
        pass
print(got)
EOF"
}
# burst <family 4|6> <src-ip> <dst-ip> <port> <n>: one flow sends n datagrams back to back, counts
# echoes received within 1 second. Same technique as lab/rates.sh's burst(), with a shorter
# collection window than rates.sh's 3s for the same reason flows() above shortened its own wait.
burst() {
  client "python3 - <<EOF
import socket, time
fam = socket.AF_INET6 if '$1' == '6' else socket.AF_INET
s = socket.socket(fam, socket.SOCK_DGRAM); s.bind(('$2', 0)); s.settimeout(0.1)
for i in range($5):
    s.sendto(b'p', ('$3', $4))
got = 0; end = time.time() + 1
while time.time() < end:
    try:
        s.recvfrom(2048); got += 1
    except OSError:
        pass
print(got)
EOF"
}
drops() { vps wgft rule ls --json --admin "$ADMIN" 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin); print((d.get("drops") or {}).get("'"$1"'", 0))' 2>/dev/null; }
# bump_apply forces a real reconcile/apply (add then remove a throwaway, unrelated rule) so that
# a subsequent drops() reflects what actually happened since the last apply. The admin API's
# "drops" field is only updated when an apply runs (design 6.1 節: 差し替えの直前に読んだ増分を
# 累積する), and a metadata-only edit of the rule under test (note/group) is a NoOp that never
# applies at all, so neither would move drops() on its own; a throwaway rule's add/remove is a
# real Plan change that always triggers one. Because Apply replaces the whole table in one
# transaction, this also resets every rule's meter (kernel mode's table_replacement_reset
# tolerance, design 7a.4 節) - useful right before measuring a fresh token bucket, but exactly why
# this must never run between a flood and the allowance check that is supposed to prove that same
# flood did not touch the bucket.
bump_apply() {
  local id
  id=$(vps wgft rule add --agent home --udp 27029 --to 192.168.50.3:19140 --admin "$ADMIN" 2>/dev/null | grep -oE 'r_[A-Za-z0-9]+')
  [ -n "$id" ] && vps wgft rule rm "$id" --admin "$ADMIN" >/dev/null 2>&1
}

echo "== $mode: an ipv6 flood does not spend the aggregate new_flow_rate tokens"
vps wgft rule rate new-flow "$u" 6/minute --admin "$ADMIN" >/dev/null; sleep 2

before=$(drops "$u")
flows 6 "$CLIENT6" "$VPS6" 27019 40 >/dev/null
bump_apply
after=$(drops "$u")
eqcheck "ipv6 flood alone does not add to the rule's drop counter" "$before" "$after"

# bump_apply above also reset the meter (see its comment), so this flood starts from a fresh
# bucket; nothing else may apply between here and the allowance check right after it.
v6_answered=$(flows 6 "$CLIENT6" "$VPS6" 27019 40)
eqcheck "ipv6 flood (40 new flows) answers none of them" 0 "$v6_answered"
v4_answered=$(flows 4 198.51.100.2 198.51.100.1 27019 6)
okcheck "ipv4 keeps its full new-flow allowance right after the ipv6 flood (answered=$v4_answered, want>=5 of 6)" \
  "$([ "$v4_answered" -ge 5 ] && echo 1 || echo 0)"
vps wgft rule rate new-flow "$u" none --admin "$ADMIN" >/dev/null; sleep 2

echo "== $mode: an ipv6 flood does not spend the aggregate packet_rate tokens"
# limit rate ... burst 5 starts full (design.md 7a.9 節: 容量 5、満杯から始まる), so a burst sent as
# fast as possible - ipv4 or ipv6 - only ever gets a handful of answers through, regardless of how
# many datagrams it contains; that ceiling (not the configured rate) is what a fresh bucket
# actually allows an instant flood. The rate is set to a slow 2/second (rather than something
# game-traffic-realistic) on purpose: burst()'s own 1s collection window (see its comment above)
# already refills 2 tokens at that rate, which the allowance check's tolerance below accounts for;
# a faster configured rate would refill the whole bucket inside that same window and hide a real
# regression behind that unrelated recovery, the same problem a longer window would cause.
vps wgft rule rate packet "$u" 2/second --admin "$ADMIN" >/dev/null; sleep 2

before=$(drops "$u")
burst 6 "$CLIENT6" "$VPS6" 27019 300 >/dev/null
bump_apply
after=$(drops "$u")
eqcheck "ipv6 flood alone does not add to the rule's drop counter (packet_rate)" "$before" "$after"

v6_burst=$(burst 6 "$CLIENT6" "$VPS6" 27019 300)
eqcheck "ipv6 flood (300 datagrams) answers none of them" 0 "$v6_burst"
v4_burst=$(burst 4 198.51.100.2 198.51.100.1 27019 5)
okcheck "ipv4 keeps its full packet-rate allowance right after the ipv6 flood (answered=$v4_burst, want>=4 of 5; token bucket burst is 5)" \
  "$([ "$v4_burst" -ge 4 ] && echo 1 || echo 0)"
vps wgft rule rate packet "$u" none --admin "$ADMIN" >/dev/null; sleep 2

echo "== $mode: ipv4 still works after the ipv6 traffic"
check "transparent tcp works over ipv4 after" "tcp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:39975')"
check "transparent udp works over ipv4 after" "udp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:27019')"
check "relay tcp works over ipv4 after" "tcp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:8447')"

echo "== $mode: teardown"
cleanup
if [ "$fail" = 0 ]; then echo "== $mode: ALL PASS"; else echo "== $mode: FAILURES"; fi
exit "$fail"
