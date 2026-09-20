#!/usr/bin/env bash
# e2e.sh runs the end-to-end scenario inside the lab VM for one forwarding mode and prints
# PASS/FAIL per check. It is the same scenario for both modes (design section 6.3):
#
#   lab/lab exec vm bash /wgft/lab/e2e.sh kernel      # server as root, kernel WireGuard + nftables
#   lab/lab exec vm bash /wgft/lab/e2e.sh userspace   # server as the unprivileged user wgftlab
#
# Checks: registration, TCP and UDP through the VPS, a 3000-byte UDP datagram, PROXY protocol to
# ppecho, the agent's target allowlist refusing a target that would otherwise forward, immediate
# cut of a TCP session and silence for UDP after a deny, and teardown.
# Requires `lab/lab build` (wgft, echo and ppecho in /usr/local/bin of the VM) and the netns
# topology (`lab/lab net up`). Leftovers from earlier runs are killed first.
set -u
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: e2e.sh kernel|userspace" >&2; exit 2;; esac

DATA=/tmp/wgft-e2e-server
ADATA=/tmp/wgft-e2e-agent
ADMIN=127.0.0.1:8686
fail=0
check() { # check <label> <expected-substring> <actual>
  # an empty expected substring matches anything, so it would always pass; refuse it
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
eqcheck() { # eqcheck <label> <want> <got>: integers must be equal. check()'s substring match is
  # wrong for a bare number (e.g. a byte count of "0" is itself a substring of "10" or "20").
  if [ "$2" -eq "$3" ] 2>/dev/null; then echo "PASS  $1"; else echo "FAIL  $1: got '$3', want '$2'"; fail=1; fi
}
not_forwarded() { # not_forwarded <label> <forbidden-substring> <actual>: the inverse of check.
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "FAIL  $1: got '$3'"; fail=1; else echo "PASS  $1 (got '$3')"; fi
}
vps() { ip netns exec vps "$@"; }
client() { ip netns exec client bash -c "$1"; }
kill_all() { pkill -x wgft; pkill -x echo; pkill -x ppecho; pkill -x socat; sleep 1; }
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
}

cleanup
mkdir -p "$DATA"
if [ "$mode" = userspace ]; then
  id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab
  chown wgftlab "$DATA"
  run_server="runuser -u wgftlab -- wgft server run"
else
  run_server="wgft server run"
fi
echo "== $mode: start server"
vps setsid nohup $run_server --mode "$mode" --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
  > /tmp/wgft-e2e-server.log 2>&1 < /dev/null &
disown
sleep 3
check "server up" "admin api" "$(grep -o 'admin api' /tmp/wgft-e2e-server.log | head -1)"

join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
# The agent's target allowlist holds exactly the three targets the rules below use (design section
# 7). The echo server also answers on 192.168.50.3:25567, which is deliberately left out of the
# list: a rule to it would forward if the allowlist were absent, so the refusal check has teeth.
ALLOW=192.168.50.3:25565,192.168.50.3:19132,192.168.50.3:8444
WGFT_JOIN="$join" WGFT_AGENT_ALLOW_TARGETS="$ALLOW" \
  ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-e2e-agent.log 2>&1 < /dev/null &
disown
ip netns exec lan setsid nohup echo -tcp 25565,25567 -udp 19132 > /tmp/wgft-e2e-echo.log 2>&1 < /dev/null &
disown
ip netns exec lan setsid nohup ppecho -addr 192.168.50.3:8444 > /tmp/wgft-e2e-ppecho.log 2>&1 < /dev/null &
disown
sleep 6
check "agent registered" "home" "$(vps wgft agent ls --admin "$ADMIN" | tail -1)"

t=$(vps wgft rule add --agent home --tcp 39971 --to 192.168.50.3:25565 --admin "$ADMIN" | grep -oE 'r_[A-Z0-9]+')
u=$(vps wgft rule add --agent home --udp 27015 --to 192.168.50.3:19132 --admin "$ADMIN" | grep -oE 'r_[A-Z0-9]+')
vps wgft rule add --agent home --tcp 8444 --to 192.168.50.3:8444 --proxy --proxy-protocol --admin "$ADMIN" >/dev/null
sleep 5
check "tcp through the VPS" "tcp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:39971')"
check "udp through the VPS" "udp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:27015')"
check "3000-byte udp" "len=3000" "$(client 'head -c 3000 /dev/zero | tr "\0" a | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:27015')"
check "proxy protocol carries the client ip" "198.51.100.2" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:8444' | head -1)"

# A rule to 192.168.50.3:25567, where the echo server really answers, must not forward: the port is
# outside WGFT_AGENT_ALLOW_TARGETS, so the agent opens no listener for it and reports the rule as an
# error with the reason. Without the allowlist this same rule replies tcp-echo, so both checks fail.
vps wgft rule add --agent home --tcp 39972 --to 192.168.50.3:25567 --admin "$ADMIN" >/dev/null
sleep 4
not_forwarded "target outside the allowlist does not forward" "tcp-echo" \
  "$(client 'echo hi | timeout -k 5 20 socat -t 2 -T 10 - TCP:198.51.100.1:39972 2>&1')"
check "target outside the allowlist is reported" "WGFT_AGENT_ALLOW_TARGETS" "$(vps wgft agent ls --admin "$ADMIN" | tail -1)"

# deny: a TCP session opened before the deny must be cut at once. Seen from the VPS: in kernel
# mode the conntrack entry of the flow disappears (its later packets hit the deny rule), in
# userspace mode the relay closes its sockets. The client just holds the session open meanwhile.
flows() {
  if [ "$mode" = kernel ]; then
    vps conntrack -L -p tcp --dport 39971 --src 198.51.100.2 2>/dev/null | grep -c ESTABLISHED
  else
    vps ss -tn state established '( sport = :39971 )' | grep -c 198.51.100.2
  fi
}
client 'python3 -c "
import socket, time
s = socket.create_connection((\"198.51.100.1\", 39971), timeout=5); s.send(b\"x\"); time.sleep(6)
"' &
sleep 2
before=$(flows)
vps wgft rule deny add "$t" 198.51.100.2/32 --admin "$ADMIN" >/dev/null
vps wgft rule deny add "$u" 198.51.100.2/32 --admin "$ADMIN" >/dev/null
sleep 1
after=$(flows)
wait
check "deny cuts the open tcp session" "before=1 after=0" "before=$before after=$after"
eqcheck "deny silences udp" "0" "$(client 'echo hi | timeout -k 5 20 socat -t 2 -T 10 - UDP:198.51.100.1:27015' | wc -c)"
vps wgft rule deny rm "$t" 198.51.100.2/32 --admin "$ADMIN" >/dev/null; sleep 1
check "tcp again after deny rm" "tcp-echo" "$(client 'echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:39971')"

echo "== $mode: teardown"
kill_server
if [ "$mode" = userspace ]; then
  out=$(vps runuser -u wgftlab -- wgft server teardown --data-dir "$DATA" --purge --yes 2>&1)
else
  out=$(vps wgft server teardown --data-dir "$DATA" --purge --yes 2>&1)
fi
check "teardown runs" "deleted $DATA/wgft.sqlite" "$out"
check "no wg interface left" "does not exist" "$(vps ip link show wgft0 2>&1)"
kill_all
rm -rf "$DATA" "$ADATA"
if [ "$fail" = 0 ]; then echo "== $mode: ALL PASS"; else echo "== $mode: FAILURES"; fi
exit "$fail"
