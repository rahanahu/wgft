#!/usr/bin/env bash
# connlimit.sh exercises the kernel-mode per-source-IP concurrent flow cap (design section 6.1,
# `ct count` in the shared flows_tcp / flows_udp sets) under load:
#
#   lab/lab exec vm bash /wgft/lab/connlimit.sh
#
# This limit only exists in kernel mode (userspace mode already enforces it in Go, see
# internal/flowcap and internal/vpsd/srcpolicy, and is covered by their unit tests). The script:
#
#   - opens far more than 128 concurrent TCP connections and 256 concurrent UDP flows from one
#     source address, and checks that close to (but not over) the cap gets through while the
#     drop counter for the rule rises
#   - opens a handful of TCP connections and UDP flows from a second source address at the same
#     time, and checks they all get through (the cap is per source, not a rule-wide lockout)
#   - keeps the first few connections/flows accepted from the first address open while the flood
#     continues, then exchanges data on them afterwards, to check the cap never evicts an
#     existing flow (only ct state new is subject to the cap)
#   - restarts the server (keeping the same rules and agent) with WGFT_MAX_TCP_FLOWS_PER_SOURCE=200
#     and checks the cap follows the setting instead of staying at the default 128. This value
#     stays well under the agent's own per-rule cap (half of WGFT_MAX_TCP_FLOWS, 1024 by default),
#     which also applies since the agent relays every kernel-mode DNAT'd connection to the LAN
#     target (design section 7), so the kernel per-source cap is the only thing being isolated
#
# Requires `lab/lab build` (wgft and echo in /usr/local/bin of the VM) and the netns topology
# (`lab/lab net up`). Leftovers from earlier runs are killed first.
set -u

DATA=/tmp/wgft-connlimit-server
ADATA=/tmp/wgft-connlimit-agent
ADMIN=127.0.0.1:8686
fail=0
check() { # check <label> <ok-if-true>
  if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi
}
vps() { ip netns exec vps "$@"; }
client() { ip netns exec client bash -c "$1"; }
kill_all() { pkill -x wgft; pkill -x echo; sleep 1; }
# kill_server stops only the server (wgft server run), leaving the agent and echo listener up,
# so the second phase can restart the server alone with a different setting.
kill_server() {
  for p in $(pgrep -x wgft); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q ' server run' && kill "$p"
  done
  sleep 1
}
cleanup() {
  kill_all
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  rm -rf "$DATA" "$ADATA"
  ip netns exec client ip addr del 198.51.100.3/24 dev "$(ip netns exec client ip -o -4 route show default | awk '{print $5}')" 2>/dev/null
}

cleanup
mkdir -p "$DATA"
vps setsid nohup wgft server run --mode kernel --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
  > /tmp/wgft-connlimit-server.log 2>&1 < /dev/null &
disown
sleep 3
join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-connlimit-agent.log 2>&1 < /dev/null &
disown
ip netns exec lan setsid nohup echo -tcp 25567 -udp 19134 > /tmp/wgft-connlimit-echo.log 2>&1 < /dev/null &
disown
sleep 6
tcp_rule=$(vps wgft rule add --agent home --tcp 28016 --to 192.168.50.3:25567 --admin "$ADMIN" | grep -oE 'r_[A-Z0-9]+')
udp_rule=$(vps wgft rule add --agent home --udp 28017 --to 192.168.50.3:19134 --admin "$ADMIN" | grep -oE 'r_[A-Z0-9]+')
sleep 4
ip netns exec client ip addr add 198.51.100.3/24 dev "$(ip netns exec client ip -o -4 route show default | awk '{print $5}')" 2>/dev/null

# drops <rule-id>: the live src_flow counter in nftables. `rule ls` shows the drops accumulated in
# SQLite, which vpsd only updates right before a table swap (design section 6.1), so it stays 0 here.
drops() {
  vps nft list table inet wgft 2>/dev/null | grep "wgft:$1:src_flow" | grep -oE 'packets [0-9]+' | awk '{s+=$2} END {print s+0}'
}
# in_set <set> <ip>: 1 if the dynamic set still has an element for ip
in_set() { vps nft list set inet wgft "$1" 2>/dev/null | grep -qF "$2" && echo 1 || echo 0; }
# freed <set> <ip> <seconds>: 1 if the element for ip disappears within the given time
freed() {
  for _ in $(seq 1 "$3"); do [ "$(in_set "$1" "$2")" = 0 ] && { echo 1; return; }; sleep 1; done
  echo 0
}

# tcp_flood <src-ip> <n>: opens n TCP connections from src-ip as fast as possible, each with a
# short connect timeout (the cap drops the SYN silently, so a refused connection just times out
# rather than getting a RST). Prints "<established> <alive-after-hold>": the number that
# connected, and how many of the first 5 of those still round-trip data after a 2s hold.
# With a third argument <src2>, it also opens 5 connections from src2 while the n connections are
# still held, and prints how many of those connected as a third number.
tcp_flood() {
  client "python3 - <<EOF
import socket, threading, time

src, n, src2 = \"$1\", $2, \"${3:-}\"
socks = []
lock = threading.Lock()

def one(src=src, socks=socks):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((src, 0))
    s.settimeout(0.3)
    try:
        s.connect((\"198.51.100.1\", 28016))
    except OSError:
        s.close()
        return
    with lock:
        socks.append(s)

threads = [threading.Thread(target=one) for _ in range(n)]
for t in threads:
    t.start()
for t in threads:
    t.join()

established = len(socks)
second = []
if src2:
    ts = [threading.Thread(target=one, args=(src2, second)) for _ in range(5)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    for s in second:
        s.close()
alive = 0
if established:
    time.sleep(2)
    for s in socks[:5]:
        try:
            s.settimeout(1)
            s.sendall(b\"x\")
            s.shutdown(socket.SHUT_WR)
            s.recv(4096)
            alive += 1
        except OSError:
            pass
for s in socks:
    s.close()
print(established, alive, len(second))
EOF"
}

# udp_flood <src-ip> <n>: like rates.sh's flows(), but with a bigger n to exceed the 256 cap.
# Prints how many of the n flows (distinct source ports) got an echo back.
udp_flood() {
  client "python3 - <<EOF
import socket, time
got = 0
socks = []
for i in range($2):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"$1\", 0)); s.settimeout(0.05)
    s.sendto(b\"f\", (\"198.51.100.1\", 28017)); socks.append(s)
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

echo "== tcp: 160 connections from 198.51.100.2 (cap 128), and 5 from 198.51.100.3 while they are held"
read -r tcp_established tcp_alive tcp2_established <<< "$(tcp_flood 198.51.100.2 160 198.51.100.3)"
echo "   established: $tcp_established, still alive after 2s hold + round trip: $tcp_alive, second address: $tcp2_established"
check "tcp per-source cap admits at most 128" "$([ "$tcp_established" -le 128 ] && echo 1 || echo 0)"
check "tcp per-source cap admits a substantial fraction of 128 (not near 0)" "$([ "$tcp_established" -ge 100 ] && echo 1 || echo 0)"
check "tcp drop counter rose" "$([ "$(drops "$tcp_rule")" -gt 0 ] && echo 1 || echo 0)"
check "tcp: connections accepted before the cap was hit stay open and answer" "$([ "$tcp_alive" -eq 5 ] && echo 1 || echo 0)"

check "tcp: a second source is not locked out while the first source is at its cap" "$([ "$tcp2_established" -eq 5 ] && echo 1 || echo 0)"
check "tcp: the set element is freed once the connections are closed" "$(freed flows_tcp 198.51.100.2 10)"

echo "== udp: 320 flows from 198.51.100.2 (cap 256)"
udp_answered=$(udp_flood 198.51.100.2 320)
echo "   answered: $udp_answered"
check "udp per-source cap admits at most 256" "$([ "$udp_answered" -le 256 ] && echo 1 || echo 0)"
check "udp per-source cap admits a substantial fraction of 256 (not near 0)" "$([ "$udp_answered" -ge 200 ] && echo 1 || echo 0)"
check "udp drop counter rose" "$([ "$(drops "$udp_rule")" -gt 0 ] && echo 1 || echo 0)"

echo "== udp: 5 flows from a second address (198.51.100.3) while the first address still has 256 in conntrack"
udp2_answered=$(udp_flood 198.51.100.3 5)
echo "   answered: $udp2_answered"
check "udp: a second source is not locked out by the first source's cap" "$([ "$udp2_answered" -eq 5 ] && echo 1 || echo 0)"
vps conntrack -D -p udp -s 198.51.100.2 >/dev/null 2>&1
check "udp: the set element is freed once its conntrack entries are gone" "$(freed flows_udp 198.51.100.2 10)"

echo "== restarting the server alone with WGFT_MAX_TCP_FLOWS_PER_SOURCE=200 (same rules, same agent)"
kill_server
vps env WGFT_MAX_TCP_FLOWS_PER_SOURCE=200 setsid nohup wgft server run --mode kernel --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
  > /tmp/wgft-connlimit-server2.log 2>&1 < /dev/null &
disown
sleep 3

echo "== tcp: 220 connections from 198.51.100.2 (cap now 200, was 128)"
read -r tcp_established3 _ _ <<< "$(tcp_flood 198.51.100.2 220)"
echo "   established: $tcp_established3"
check "tcp per-source cap follows WGFT_MAX_TCP_FLOWS_PER_SOURCE=200, not the default 128" \
  "$([ "$tcp_established3" -le 200 ] && [ "$tcp_established3" -ge 180 ] && echo 1 || echo 0)"

cleanup
if [ "$fail" = 1 ]; then echo "== connlimit: FAIL"; exit 1; fi
echo "== connlimit: PASS"
