#!/usr/bin/env bash
# rates.sh exercises the three rate limits of a UDP rule under load, in one forwarding mode:
#
#   lab/lab exec vm bash /wgft/lab/rates.sh kernel
#   lab/lab exec vm bash /wgft/lab/rates.sh userspace
#
# For each limit it prints what got through, so kernel mode (nftables limit/meter) and userspace
# mode (the Go evaluator, internal/policy/goengine) can be compared side by side:
#   packet      one flow sends 500 datagrams as fast as it can; how many echoes come back
#   per-source  20 flows (distinct source ports) from one address, then 5 flows from a second
#               address; how many flows get an answer from each
#   new-flow    20 flows from one address against a rule-wide cap
# The rule's DROPPED counters are printed after each step. Requires `lab/lab build` and the
# netns topology; leftovers from earlier runs are killed first.
set -u
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: rates.sh kernel|userspace" >&2; exit 2;; esac

DATA=/tmp/wgft-rates-server
ADATA=/tmp/wgft-rates-agent
ADMIN=127.0.0.1:8686
vps() { ip netns exec vps "$@"; }
client() { ip netns exec client bash -c "$1"; }
kill_all() { pkill -x wgft; pkill -x echo; pkill -x socat; sleep 1; }

kill_all
vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
vps ip link del wgft0 2>/dev/null
vps nft delete table inet wgft 2>/dev/null
rm -rf "$DATA" "$ADATA"
mkdir -p "$DATA"
if [ "$mode" = userspace ]; then
  id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab
  chown wgftlab "$DATA"
  run_server="runuser -u wgftlab -- wgft server run"
else
  run_server="wgft server run"
fi
vps setsid nohup $run_server --mode "$mode" --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
  > /tmp/wgft-rates-server.log 2>&1 < /dev/null &
disown
sleep 3
join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-rates-agent.log 2>&1 < /dev/null &
disown
ip netns exec lan setsid nohup echo -udp 19132 > /tmp/wgft-rates-echo.log 2>&1 < /dev/null &
disown
sleep 6
u=$(vps wgft rule add --agent home --udp 27015 --to 192.168.50.3:19132 --admin "$ADMIN" | grep -oE 'r_[A-Z0-9]+')
sleep 4
ip netns exec client ip addr add 198.51.100.3/24 dev "$(ip netns exec client ip -o -4 route show default | awk '{print $5}')" 2>/dev/null

# flows <src-ip> <n>: open n UDP sockets from src-ip, send one datagram each, count sockets that got an answer
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
# burst <n>: one flow sends n datagrams back to back, counts echoes received within 3 seconds
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
drops() { vps wgft rule ls --json --admin "$ADMIN" 2>/dev/null | python3 -c 'import json,sys
d=json.load(sys.stdin); print((d.get("drops") or {}).get("'"$u"'", 0))' 2>/dev/null; }

echo "== $mode: no limits: 1 flow, 500 datagrams -> echoes: $(burst 500)"
echo "== $mode: packet 50/second"
vps wgft rule rate packet "$u" 50/second --admin "$ADMIN" >/dev/null; sleep 2
echo "   1 flow, 500 datagrams -> echoes: $(burst 500)   drops: $(drops)"
vps wgft rule rate packet "$u" none --admin "$ADMIN" >/dev/null; sleep 2

echo "== $mode: per-source 5/minute"
vps wgft rule rate per-source "$u" 5/minute --admin "$ADMIN" >/dev/null; sleep 2
echo "   20 flows from 198.51.100.2 -> answered: $(flows 198.51.100.2 20)"
echo "   5 flows from 198.51.100.3  -> answered: $(flows 198.51.100.3 5)   drops: $(drops)"
vps wgft rule rate per-source "$u" none --admin "$ADMIN" >/dev/null; sleep 2

echo "== $mode: new-flow 8/minute"
vps wgft rule rate new-flow "$u" 8/minute --admin "$ADMIN" >/dev/null; sleep 2
echo "   20 flows from 198.51.100.2 -> answered: $(flows 198.51.100.2 20)   drops: $(drops)"

kill_all
vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
ip netns exec client ip addr del 198.51.100.3/24 dev "$(ip netns exec client ip -o -4 route show default | awk '{print $5}')" 2>/dev/null
rm -rf "$DATA" "$ADATA"
echo "== $mode: done"
