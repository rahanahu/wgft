#!/usr/bin/env bash
# split-merge.sh drives the Web UI's split/merge endpoints (POST /ui/rules/{id}/split
# and /merge) against a UDP range rule while a session flows through one of its
# ports, and checks the session is not interrupted -- the same method e2e.sh uses for
# the deny-list session cut (a background socat loop, checked before/after). It proves
# that split and merge, like the CLI's `rule split`/`rule merge` they share their
# construction and validation with (proto.Rule.Split, proto.Merge), do not move any
# rule's effective target (design 5.4, 7 sections), so an open UDP session on the
# range's first port survives both operations.
#
#   lab/lab exec vm bash /wgft/lab/split-merge.sh kernel
#   lab/lab exec vm bash /wgft/lab/split-merge.sh userspace
# Requires `lab/lab build` and the netns topology (`lab/lab up` / `lab/lab net up`).
set -u
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: split-merge.sh kernel|userspace" >&2; exit 2;; esac

DATA=/tmp/wgft-splitmerge-server
ADATA=/tmp/wgft-splitmerge-agent
ADMIN=127.0.0.1:8686
fail=0
check() { # check <label> <expected-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
vps() { ip netns exec vps "$@"; }
client() { ip netns exec client bash -c "$1"; }
kill_all() { pkill -x wgft; pkill -x echo; sleep 1; }
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
  rm -rf "$DATA" "$ADATA" /tmp/wgft-splitmerge-flow.log
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
  > /tmp/wgft-splitmerge-server.log 2>&1 < /dev/null &
disown
sleep 3
check "server up" "admin api" "$(grep -o 'admin api' /tmp/wgft-splitmerge-server.log | head -1)"

join=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
WGFT_JOIN="$join" ip netns exec home setsid nohup wgft agent run --data-dir "$ADATA" > /tmp/wgft-splitmerge-agent.log 2>&1 < /dev/null &
disown
ip netns exec home setsid nohup echo -udp 19132 > /tmp/wgft-splitmerge-echo.log 2>&1 < /dev/null &
disown
sleep 6
check "agent registered" "home" "$(vps wgft agent ls --admin "$ADMIN" | tail -1)"

r=$(vps wgft rule add --agent home --udp 2456-2457 --to 192.168.50.2:19132 --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
sleep 2
check "udp through the VPS before split" "udp-echo" "$(client 'echo hi | socat -t 3 - UDP:198.51.100.1:2456')"

# A session flowing on port 2456 (the range's first port; the split point below is
# 2457, so 2456's effective target never moves) throughout the split and the merge.
client 'ok=0; bad=0; for i in $(seq 1 24); do
  out=$(echo "n$i" | socat -t 1 - UDP:198.51.100.1:2456)
  if [[ "$out" == *udp-echo* ]]; then ok=$((ok+1)); else bad=$((bad+1)); fi
  sleep 0.25
done; echo "ok=$ok bad=$bad"' > /tmp/wgft-splitmerge-flow.log 2>&1 &
flow_pid=$!
sleep 1

split_code=$(vps curl -s -o /dev/null -w "%{http_code}" -X POST "http://$ADMIN/ui/rules/$r/split" --data "at=2457")
check "split via the web UI redirects" "303" "$split_code"

tail_id=$(vps wgft rule ls --admin "$ADMIN" --json | python3 -c '
import json, sys
rules = json.load(sys.stdin)["rules"]
for rule in rules:
    if rule["listen_port"] == "2457":
        print(rule["id"])
')
check "split created a tail rule for port 2457" "r_" "$tail_id"
listen_port_of() { # listen_port_of <rule-id>
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
rules = json.load(sys.stdin)['rules']
for rule in rules:
    if rule['id'] == '$1':
        print(rule['listen_port'])
"
}
check "head keeps the original id and shrinks to port 2456" "2456" "$(listen_port_of "$r")"

sleep 1
merge_code=$(vps curl -s -o /dev/null -w "%{http_code}" -X POST "http://$ADMIN/ui/rules/$r/merge" --data "other=$tail_id")
check "merge via the web UI redirects" "303" "$merge_code"
check "merge restored the 2456-2457 range under the original id" "2456-2457" "$(listen_port_of "$r")"

wait "$flow_pid"
flow_result=$(cat /tmp/wgft-splitmerge-flow.log)
check "the flow on port 2456 saw no failed round-trip during split+merge" "bad=0" "$flow_result"

echo "== $mode: teardown"
kill_server
if [ "$mode" = userspace ]; then
  out=$(vps runuser -u wgftlab -- wgft server teardown --data-dir "$DATA" --purge --yes 2>&1)
else
  out=$(vps wgft server teardown --data-dir "$DATA" --purge --yes 2>&1)
fi
check "teardown runs" "deleted $DATA/wgft.sqlite" "$out"
kill_all
rm -rf "$DATA" "$ADATA" /tmp/wgft-splitmerge-flow.log
if [ "$fail" = 0 ]; then echo "== $mode: ALL PASS"; else echo "== $mode: FAILURES"; fi
exit "$fail"
