#!/usr/bin/env bash
# rcvwin.sh checks, in userspace mode, that the relay does not give back a boost slot while the
# kernel TCP socket on vpsd's public side still holds receive memory above the floor
# (design.md 7 節「中継のカーネルの TCP ソケットの受信のバッファ」):
#
#   lab/lab exec vm bash /wgft/lab/rcvwin.sh
#
# Lowering SO_RCVBUF does not free data a socket already holds. A client that leaves a hole in its
# stream and then goes silent leaves the out-of-order data in the kernel socket; the relay reads
# nothing, so on the netstack side the flow is an idle slot holder. The check fills all boost slots
# with such flows, has another flow ask for a slot, and then fills the holes:
#   - while the holes are open, no public socket is lowered to the floor while it holds receive
#     memory above the floor, every hole flow keeps its boost, and the asking flow gets no slot;
#   - once the holes are filled the transfers complete, and a new flow that asks for a slot gets
#     one, so a slot that could not be returned is returned once its data drained.
# Each request is made only after the target has received everything sent before the hole (or, the
# second time, everything), plus more than a second, so that every holder is idle with an empty
# send queue on vpsd's netstack side and is tried by the request.
# The hole is made in the vps namespace with nftables, before vpsd's socket sees the packet: the
# segment that starts at a chosen sequence number is dropped every time it arrives. A drop in the
# client's own output path would not do, since the client's TCP then retries the same segment and
# sends nothing behind it. After the data behind the hole has arrived, every packet of the hole
# flows is dropped, so that no later segment makes the kernel prune its out-of-order queue.
# Requires `lab/lab build` and the netns topology. Leftovers from earlier runs are killed first.
set -u

. "$(dirname "$0")/sandbox.sh"   # sandbox: netns names, workdir, process scope
DATA=$W/wgft-rcvwin-server
ADATA=$W/wgft-rcvwin-agent
SINK=$W/wgft-rcvwin-sink.total
ADMIN=127.0.0.1:8686
PORT=39981
fail=0
sink_pid=
vps() { ip netns exec "$VPS_NS" "$@"; }
kill_all() {
  sandbox_kill_named wgft
  [ -n "$sink_pid" ] && kill "$sink_pid" 2>/dev/null
  sleep 1
}
cleanup() {
  kill_all
  vps nft delete table inet wgftlab_hole 2>/dev/null
  ip netns exec "$CLIENT_NS" tc qdisc del dev eth0 root 2>/dev/null
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  rm -rf "$DATA" "$ADATA" "$SINK"
}
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
tcp_open() { ip netns exec "$CLIENT_NS" bash -c "exec 3<>/dev/tcp/198.51.100.1/$PORT" 2>/dev/null; }

cleanup
mkdir -p "$DATA"
# As root, so that SO_RCVBUFFORCE gives the boost its full 8 MiB and the data behind a hole can be
# well above the floor; as wgftlab the boost would be capped at twice net.core.rmem_max.
vps setsid nohup wgft server run --mode userspace --data-dir "$DATA" \
  --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" > "$W/wgft-rcvwin-server.log" 2>&1 < /dev/null &
disown
if ! wait_until 30 admin_up; then echo "FAIL  setup: admin api did not come up"; fail=1; fi
join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
WGFT_JOIN="$join" ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$ADATA" \
  > "$W/wgft-rcvwin-agent.log" 2>&1 < /dev/null &
disown
# The target reads and discards everything, and keeps the byte count in $SINK.
ip netns exec "$LAN_NS" python3 -c '
import os, socket, sys, threading, time
path, total, lock = sys.argv[1], [0], threading.Lock()
srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("0.0.0.0", 25571))
srv.listen(128)
def serve(c):
    while True:
        b = c.recv(1 << 20)
        if not b:
            break
        with lock:
            total[0] += len(b)
    c.close()
def report():
    while True:
        with open(path + ".tmp", "w") as f:
            f.write(str(total[0]))
        os.replace(path + ".tmp", path)
        time.sleep(0.05)
threading.Thread(target=report, daemon=True).start()
while True:
    c, _ = srv.accept()
    threading.Thread(target=serve, args=(c,), daemon=True).start()
' "$SINK" > "$W/wgft-rcvwin-sink.log" 2>&1 < /dev/null &
sink_pid=$!
if ! wait_until 30 agent_registered; then echo "FAIL  setup: agent never registered"; fail=1; fi
vps wgft rule add --agent home --tcp "$PORT" --to 192.168.50.3:25571 --admin "$ADMIN" >/dev/null
wait_until 15 tcp_open || { echo "FAIL  setup: rule never forwarded"; fail=1; }

# Slow start after idle would shrink the window of the hole flows to the initial window, and their
# data behind the hole would stay below the floor.
ip netns exec "$CLIENT_NS" sysctl -qw net.ipv4.tcp_slow_start_after_idle=0
# A round trip of 20 ms lets the congestion window grow during phase A, so that the data sent behind
# the hole in phase B is one large burst rather than an initial window.
ip netns exec "$CLIENT_NS" tc qdisc replace dev eth0 root netem delay 20ms limit 100000

ip netns exec "$CLIENT_NS" python3 - "$VPS_NS" "$PORT" "$SINK" <<'PY' || fail=1
import fcntl, re, socket, struct, subprocess, sys, threading, time

VPS_NS, PORT, SINK = sys.argv[1], int(sys.argv[2]), sys.argv[3]
SERVER = "198.51.100.1"
N = 16                     # the boost slots per process (design.md 7 節)
PHASE_A = 8 << 20          # enough demand to take a slot
PHASE_B = 2 << 20          # sent behind the hole
REQUEST = 16 << 20         # what an asking flow sends
FLOOR = 2 * (128 << 10)    # the floor's effective SO_RCVBUF
IDLE = 1.5                 # more than the idle time after which a holder can be reclaimed
SIOCOUTQ = 0x5411
failed = False


def result(ok, label, detail=""):
    global failed
    if ok:
        print("PASS  %s%s" % (label, " (%s)" % detail if detail else ""), flush=True)
    else:
        print("FAIL  %s%s" % (label, ": %s" % detail if detail else ""), flush=True)
        failed = True


def skmem():
    """client port -> (rmem_alloc, sk_rcvbuf) of vpsd's public sockets"""
    out = subprocess.run(["ip", "netns", "exec", VPS_NS, "ss", "-tmnHO", "state", "established",
                          "( sport = :%d )" % PORT], capture_output=True, text=True).stdout
    got = {}
    for line in out.splitlines():
        peer = re.search(r"198\.51\.100\.2:(\d+)", line)
        mem = re.search(r"skmem:\(r(\d+),rb(\d+)", line)
        if peer and mem:
            got[int(peer.group(1))] = (int(mem.group(1)), int(mem.group(2)))
    return got


def outq(s):
    return struct.unpack("i", fcntl.ioctl(s.fileno(), SIOCOUTQ, b"\0" * 4))[0]


def sunk():
    try:
        with open(SINK) as f:
            return int(f.read() or 0)
    except (OSError, ValueError):
        return -1


def wait(cond, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if cond():
            return True
        time.sleep(0.05)
    return cond()


def nft(script):
    subprocess.run(["ip", "netns", "exec", VPS_NS, "nft", "-f", "-"], input=script, text=True, check=True)


# Capture the initial sequence numbers from the SYNs, to know where each hole starts.
sniff = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
sniff.bind(("eth0", 0))
sniff.settimeout(0.2)
conns = [socket.create_connection((SERVER, PORT)) for _ in range(N)]
ports = [s.getsockname()[1] for s in conns]
isn = {}
deadline = time.time() + 5
while len(isn) < N and time.time() < deadline:
    try:
        frame = sniff.recv(256)
    except socket.timeout:
        continue
    if len(frame) < 54 or frame[12:14] != b"\x08\x00" or frame[23] != 6:
        continue
    ihl = (frame[14] & 0x0F) * 4
    tcp = frame[14 + ihl:]
    sport, dport, seq = struct.unpack("!HHI", tcp[:8])
    flags = tcp[13]
    if dport == PORT and sport in ports and flags & 0x12 == 0x02:
        isn[sport] = seq
sniff.close()
result(len(isn) == N, "setup: initial sequence numbers of every hole flow captured", "%d of %d" % (len(isn), N))

# Phase A: each flow sends enough to take a boost slot on vpsd. Wait until the target has it all.
for s in conns:
    s.sendall(b"\0" * PHASE_A)
expected = N * PHASE_A
result(wait(lambda: sunk() >= expected, 120), "setup: the target received phase A", "%d of %d bytes" % (sunk(), expected))
mem = skmem()
boosted = [p for p in ports if p in mem and mem[p][1] > FLOOR]
result(len(boosted) == N, "setup: every hole flow holds a boost slot on vpsd", "%d of %d boosted" % (len(boosted), N))

# Phase B: drop the segment that starts the next data, send data behind it, then go silent.
rules = "\n".join("ip saddr 198.51.100.2 tcp dport %d tcp sport %d tcp sequence %d drop" % (PORT, p, (isn[p] + 1 + PHASE_A) & 0xFFFFFFFF) for p in ports if p in isn)
nft("table inet wgftlab_hole {\n chain pre {\n type filter hook prerouting priority -300; policy accept;\n%s\n }\n}\n" % rules)
sent_b = 0
for s in conns:
    s.setblocking(False)
    sent = 0
    try:
        while sent < PHASE_B:
            sent += s.send(b"\1" * min(65536, PHASE_B - sent))
    except BlockingIOError:
        pass
    sent_b += sent
time.sleep(1.0)
nft("".join("add rule inet wgftlab_hole pre ip saddr 198.51.100.2 tcp dport %d tcp sport %d drop\n" % (PORT, p) for p in ports))
time.sleep(IDLE)
mem = skmem()
held = [p for p in ports if p in mem and mem[p][0] > FLOOR]
result(len(held) == N, "setup: every hole flow holds receive memory above the floor in vpsd's public socket",
       "%d of %d; r/rb %s" % (len(held), N, sorted(mem[p] for p in ports if p in mem)))
result(sunk() == expected, "setup: nothing behind the holes reached the target", "%d bytes, want %d" % (sunk(), expected))


def requester():
    """Another flow sends a bulk transfer and so asks for a slot. Returns the flow and the
    violations seen meanwhile: a public socket at the floor that holds receive memory above it."""
    r = socket.create_connection((SERVER, PORT))
    done = threading.Event()

    def send():
        try:
            r.sendall(b"\2" * REQUEST)
            wait(lambda: outq(r) == 0, 60)
        finally:
            done.set()

    threading.Thread(target=send, daemon=True).start()
    bad = set()
    while True:
        finished = done.is_set()
        for p, (rmem, rcvbuf) in skmem().items():
            if rcvbuf <= FLOOR and rmem > FLOOR:
                bad.add((p, rmem, rcvbuf))
        if finished:
            break
        time.sleep(0.05)
    return r, bad


r1, bad = requester()
result(not bad, "holes open: no public socket went to the floor while holding receive memory above it",
       "violations %s" % sorted(bad))
mem = skmem()
kept = [p for p in held if p in mem and mem[p][1] > FLOOR]
result(len(kept) == len(held), "holes open: every hole flow that holds data above the floor keeps its boost",
       "%d of %d" % (len(kept), len(held)))
port1 = r1.getsockname()[1]
result(len(held) == N and port1 in mem and mem[port1][1] <= FLOOR,
       "holes open: the asking flow gets no slot, since every slot holder holds data above the floor",
       "asking flow r/rb %s" % (mem.get(port1),))
r1.close()
expected += REQUEST

# Fill the holes: the next retransmission of each hole goes through and the transfers complete.
subprocess.run(["ip", "netns", "exec", VPS_NS, "nft", "delete", "table", "inet", "wgftlab_hole"], check=True)
for s in conns:
    s.setblocking(True)
expected += sent_b
result(wait(lambda: sunk() >= expected, 120), "holes filled: the target received everything",
       "%d of %d bytes" % (sunk(), expected))
result(all(skmem().get(p, (0, 0))[0] <= FLOOR for p in ports),
       "holes filled: the relay read the data out of vpsd's public sockets")
time.sleep(IDLE)

r2, bad = requester()
mem = skmem()
port2 = r2.getsockname()[1]
result(not bad, "holes filled: no public socket went to the floor while holding receive memory above it",
       "violations %s" % sorted(bad))
result(port2 in mem and mem[port2][1] > FLOOR, "holes filled: a new flow gets a slot back from a drained hole flow",
       "new flow r/rb %s" % (mem.get(port2),))
r2.close()
for s in conns:
    s.close()
sys.exit(1 if failed else 0)
PY

cleanup
ip netns exec "$CLIENT_NS" sysctl -qw net.ipv4.tcp_slow_start_after_idle=1
if [ "$fail" = 0 ]; then echo "rcvwin: all checks passed"; else echo "rcvwin: some checks FAILED"; exit 1; fi
