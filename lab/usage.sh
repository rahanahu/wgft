#!/usr/bin/env bash
# usage.sh checks the kinds of traffic ordinary use puts through a rule, in one forwarding mode,
# with the agent in its default userspace mode:
#
#   lab/lab exec vm bash /wgft/lab/usage.sh kernel
#   lab/lab exec vm bash /wgft/lab/usage.sh userspace
#
#   web          HTTP: four parallel GETs of a 1 MiB file, each with the same SHA-256 as the file
#   interactive  an SSH-like session: 200 single keystrokes, each echoed before the next, 20 ms apart
#   game         game-like UDP: 30 datagrams a second for 6 s, each echoed; at least 95 % answered
#   bulk         32 MiB uploaded and 32 MiB downloaded, every byte counted on the other end
#
# The round-trip times and transfer rates are printed, not asserted on: the check runs beside
# others in the lab's pool. The game check's 95 % leaves room for a neighbour's load; the lab has
# lost none so far. lab/exhaustion.sh checks the same dataplane under load.
# Requires `lab/lab build` and the netns topology (`lab/lab net up`). Leftovers from earlier runs
# are killed first.
set -u
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: usage.sh kernel|userspace" >&2; exit 2;; esac

. "$(dirname "$0")/sandbox.sh"   # sandbox: netns names, workdir, process scope
TRAFFIC="python3 $(cd "$(dirname "$0")" && pwd)/traffic.py"
ADMIN=127.0.0.1:8686
DATA=$W/wgft-usage-server
ADATA=$W/wgft-usage-agent
WEB=$W/wgft-usage-web
SLOG=$W/wgft-usage-server.log
fail=0

okcheck() { if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
field() { echo "$2" | grep -oE "(^| )$1=[^ ]*" | head -1 | cut -d= -f2; }
yes_if() { if "$@"; then echo 1; else echo 0; fi; }
vps() { ip netns exec "$VPS_NS" "$@"; }
cl() { ip netns exec "$CLIENT_NS" "$@"; }
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
  sandbox_kill_named wgft echo
  sandbox_kill_cmdline '/traffic.py '
  wait_until 10 none_running
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  rm -rf "$DATA" "$ADATA" "$WEB"
}
trap cleanup EXIT
bg() {
  local ns=$1 log=$2; shift 2
  ip netns exec "$ns" setsid nohup "$@" > "$log" 2>&1 < /dev/null &
  disown
}
tcp_line_ok() { [ "$(field ok "$(cl $TRAFFIC tcp-rtt 198.51.100.1 "$1" 0.1 0.1 2>/dev/null)")" = 1 ]; }
game_ok() { # game_ok <udp-rtt result>
  local ok lost sent; ok=$(field ok "$1"); lost=$(field lost "$1"); sent=$(field sent "$1")
  [ -n "$ok" ] && [ -n "$lost" ] && [ -n "$sent" ] && [ "$ok" -ge 1 ] && [ $((ok * 100)) -ge $((sent * 95)) ]
}
web_ok() { [ "$(cl curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://198.51.100.1:$1/" 2>/dev/null)" = 200 ]; }

cleanup
mkdir -p "$DATA" "$WEB"
if [ "$mode" = userspace ]; then
  id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab
  chown wgftlab "$DATA"
  bg "$VPS_NS" "$SLOG" runuser -u wgftlab -- wgft server run --mode "$mode" --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN"
else
  bg "$VPS_NS" "$SLOG" wgft server run --mode "$mode" --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN"
fi
must_wait "server admin api comes up" 30 admin_up || exit 1
join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
WGFT_JOIN="$join" ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$ADATA" > $W/wgft-usage-agent.log 2>&1 < /dev/null &
disown
must_wait "agent registers and handshakes" 30 agent_registered || exit 1

head -c 1048576 /dev/urandom > "$WEB/file.bin"
want=$(sha256sum "$WEB/file.bin" | cut -d' ' -f1)
bg "$LAN_NS" $W/wgft-usage-http.log $TRAFFIC serve-http 192.168.50.3 25750 "$WEB"
bg "$LAN_NS" $W/wgft-usage-lines.log $TRAFFIC serve-lines 192.168.50.3 25751
bg "$LAN_NS" $W/wgft-usage-uecho.log $TRAFFIC serve-udp-echo 192.168.50.3 25752
bg "$LAN_NS" $W/wgft-usage-echo.log echo -bind 192.168.50.3 -tcp 25753
bg "$LAN_NS" $W/wgft-usage-source.log $TRAFFIC serve-source 192.168.50.3 25754 33554432
for r in "--tcp 41750 --to 192.168.50.3:25750" "--tcp 41751 --to 192.168.50.3:25751" \
         "--udp 41752 --to 192.168.50.3:25752" "--tcp 41753 --to 192.168.50.3:25753" \
         "--tcp 41754 --to 192.168.50.3:25754"; do
  # shellcheck disable=SC2086
  vps wgft rule add --agent home $r --admin "$ADMIN" >/dev/null
done
must_wait "web rule forwards" 30 web_ok 41750
must_wait "line rule forwards" 30 tcp_line_ok 41751

echo "== $mode: web"
for i in 1 2 3 4; do
  cl curl -s --max-time 120 -o "$W/wgft-usage-get$i" -w '%{http_code} %{speed_download}\n' "http://198.51.100.1:41750/file.bin" > "$W/wgft-usage-get$i.code" &
done
wait
good=0
for i in 1 2 3 4; do
  echo "   GET $i: $(cat "$W/wgft-usage-get$i.code")"
  if [ "$(cut -d' ' -f1 "$W/wgft-usage-get$i.code")" = 200 ] && [ "$(sha256sum "$W/wgft-usage-get$i" | cut -d' ' -f1)" = "$want" ]; then
    good=$((good + 1))
  fi
done
okcheck "four parallel HTTP GETs return the whole file" "$(yes_if [ "$good" = 4 ])"

echo "== $mode: interactive"
k=$(cl $TRAFFIC keys 198.51.100.1 41751 200 0.02 2>&1 | tail -1)
echo "   $k"
okcheck "every keystroke is echoed in order" "$(yes_if [ "$(field echoed "$k")" = 200 ])"

echo "== $mode: game"
g=$(cl $TRAFFIC udp-rtt 198.51.100.1 41752 0.033 6 2>&1 | tail -1)
echo "   $g"
okcheck "game-like UDP: at least 95 % of the datagrams are answered" "$(yes_if game_ok "$g")"

echo "== $mode: bulk"
up=$(cl $TRAFFIC bulk-up 198.51.100.1 41753 33554432 2>&1 | tail -1)
down=$(cl $TRAFFIC bulk-down 198.51.100.1 41754 2>&1 | tail -1)
echo "   upload: $up"
echo "   download: $down"
okcheck "a 32 MiB upload arrives whole" "$(yes_if [ "$(field echoed "$up")" = 33554432 ])"
okcheck "a 32 MiB download arrives whole" "$(yes_if [ "$(field received "$down")" = 33554432 ])"

if [ "$fail" = 0 ]; then echo "== $mode: ALL PASS"; else echo "== $mode: FAILURES"; fi
exit "$fail"
