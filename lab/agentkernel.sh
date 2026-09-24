#!/usr/bin/env bash
# agentkernel.sh runs the kernel-mode agent scenarios (design section 7b) inside the lab VM: the
# server in kernel mode in the vps namespace, the agent with WGFT_MODE=kernel as root in the home
# namespace, and LAN services in the lan namespace and on the agent host itself. It prints
# PASS/FAIL per check.
#
#   lab/lab exec vm bash /wgft/lab/agentkernel.sh            # every check, in order
#   lab/lab exec vm bash /wgft/lab/agentkernel.sh 16 22      # only these checks
#
# Checks:
#   16. basic forwarding: agent.json records kernel mode, wgft0 and table inet wgft_agent exist,
#       ip_forward is 1, TCP and UDP reach a LAN host through the VPS, every rule's state reaches
#       the server, and the generation lag, from a rule change until the agent's heartbeat reports
#       the new generation, is measured and printed.
#   17. agent stop and restart: an established TCP flow keeps flowing while the agent is stopped
#       and across its restart, new TCP and UDP flows work while it is stopped, and wgft0 and the
#       table stay in place.
#   18. an unrelated rule change, adding and deleting another rule, does not cut an established
#       TCP flow.
#   22. the guards: a target outside WGFT_AGENT_ALLOW_TARGETS gets no DNAT and is reported, a
#       loopback target is an error, a DNAT to the agent host's own LAN address works and the
#       service sees the VPS tunnel address as the source, nothing else on the agent host is
#       reachable from wgft0, not even through another table's DNAT, while the same service and
#       DNAT answer from the LAN and a published port answers from wgft0, and another table's
#       forward policy drop is named in the agent's startup log.
#   24. MSS clamp: with ICMP "fragmentation needed" dropped on both ends, 2 MB of TCP goes through
#       in each direction.
#   resolve. the 30-second check resolves a rule's host name again: a change that keeps the chosen
#       address publishes nothing, a changed address moves new flows to it, and a name that stops
#       resolving keeps forwarding to the last good address and says so in the rule's state. The
#       name is served from the home namespace's own /etc/hosts, /etc/netns/<ns>/hosts.
#   drift. the 30-second check repairs changes made outside wgft: a deleted table, a deleted row,
#       a changed MTU and a deleted wgft0, without a route warning while wgft0 is gone.
#   session. the keepalive datagram: with a kernel-mode server it reaches the server's tunnel
#       address on UDP port 9 and leaves the server's nftables counters alone; in both server
#       modes server doctor gives the same results before and after a minute of datagrams; and after
#       the server loses a fresh session, by a deleted wg interface in kernel mode or a restart in
#       userspace mode, the agent's side brings the handshake back within 60 s.
#   route. a policy routing rule that sends the server's tunnel address to another table, the way
#       Tailscale's table 52 can, is named in the agent's log within one 30-second check, and so is
#       its removal; so are a main-table route that covers the address and its removal.
#
# The server runs in kernel mode unless the first argument is "userspace" or "kernel":
#
#   lab/lab exec vm bash /wgft/lab/agentkernel.sh userspace session
#
# With a userspace-mode server, two parts are skipped. The VPS side of check 22 connects from the
# vps namespace to the agent's tunnel address, which that namespace's kernel has no route to. The
# negative control of check 24 needs a path that depends on the agent's MSS rows; a userspace-mode
# server relays TCP, ending the client's connection and opening its own inside the tunnel.
#
# Requires `lab/lab build` and the netns topology (`lab/lab net up`). Leftovers from earlier runs
# are removed first. The agent runs as root here; the CAP_NET_ADMIN-only deployment is a separate
# change.
set -u
. "$(dirname "$0")/sandbox.sh"
DATA=$W/wgft-ak-server
ADATA=$W/wgft-ak-agent
SLOG=$W/wgft-ak-server.log
ALOG=$W/wgft-ak-agent.log
ELOG=$W/wgft-ak-echo.log
ADMIN=127.0.0.1:8686
SERVER_MODE=kernel
case "${1:-}" in kernel|userspace) SERVER_MODE=$1; shift ;; esac
CHECKS=${*:-16 17 18 22 24 resolve drift session route}
HOSTS=/etc/netns/$HOME_NS/hosts
fail=0

check() { # check <label> <expected-substring> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
not_forwarded() { # not_forwarded <label> <forbidden-substring> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "FAIL  $1: got '$3'"; fail=1; else echo "PASS  $1 (got '$3')"; fi
}
skip() { echo "SKIP  $1: $2"; } # skip <label> <reason>
okcheck() { if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi; }
wait_until() { # wait_until <seconds> <command...>: polls every 0.2s against the wall clock
  local deadline=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    (( SECONDS >= deadline )) && return 1
    sleep 0.2
  done
}
vps() { ip netns exec "$VPS_NS" "$@"; }
home() { ip netns exec "$HOME_NS" "$@"; }
lan() { ip netns exec "$LAN_NS" "$@"; }
client() { ip netns exec "$CLIENT_NS" bash -c "$1"; }

agent_pids() {
  local p
  for p in $(ip netns pids "$HOME_NS" 2>/dev/null); do
    [ "$(cat "/proc/$p/comm" 2>/dev/null)" = wgft ] && echo "$p"
  done
}
agent_running() { [ -n "$(agent_pids)" ]; }
agent_stopped() { [ -z "$(agent_pids)" ]; }

cleanup() {
  sandbox_kill_named wgft echo socat python3
  sleep 1
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps runuser -u wgftlab -- wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps nft delete table inet ak_probe9 2>/dev/null
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  # wgft agent teardown is a later change; remove the agent's kernel state by hand
  home ip link del wgft0 2>/dev/null
  home nft delete table inet wgft_agent 2>/dev/null
  home nft delete table ip docker_like 2>/dev/null
  home nft delete table inet otherfw 2>/dev/null
  home ip rule del to 10.200.0.1 lookup 52 2>/dev/null
  home ip route flush table 52 2>/dev/null
  client 'nft delete table inet noicmp 2>/dev/null'
  lan nft delete table inet noicmp 2>/dev/null
  rm -rf "$DATA" "$ADATA" "/etc/netns/$HOME_NS"
}
# set_hosts <line>...: the home namespace's /etc/hosts. `ip netns exec` bind-mounts the file when it
# starts a process, so the file is rewritten in place to keep the running agent's view of it.
set_hosts() { printf '127.0.0.1 localhost\n' > "$HOSTS"; printf '%s\n' "$@" >> "$HOSTS"; }

# The allowlist holds every target the rules use except the one that must be refused. 127.0.0.1 is
# in it, so the loopback rule is refused for being loopback, not for the list.
ALLOW=192.168.50.3:25565,192.168.50.3:19132,192.168.50.3:25570,192.168.50.2:25580,192.168.50.2:25565,192.168.50.4:25565,192.168.50.5:25565,127.0.0.1:25565
start_agent() {
  WGFT_MODE=kernel WGFT_JOIN="${JOIN:-}" WGFT_AGENT_ALLOW_TARGETS="$ALLOW" \
    home setsid nohup wgft agent run --data-dir "$ADATA" >> "$ALOG" 2>&1 < /dev/null &
  disown
  wait_until 20 agent_running
}
stop_agent() {
  local p
  for p in $(agent_pids); do kill "$p"; done
  wait_until 20 agent_stopped
}

gen_server() { vps wgft rule ls --admin "$ADMIN" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["generation"])'; }
agent_field() { # agent_field <field>
  vps wgft agent ls --admin "$ADMIN" --json | python3 -c "
import json, sys
a = next((x for x in json.load(sys.stdin) if x.get('name') == 'home'), {})
v = a.get('$1')
print('' if v is None else v)
"
}
caught_up() { [ "$(agent_field generation)" = "$(gen_server)" ]; }
handshaken() { [ -n "$(agent_field last_handshake)" ] && [ "$(agent_field last_handshake)" != "0001-01-01T00:00:00Z" ]; }
rule_status() { # rule_status <rule-id>: "<state> <reason>" from the agent's heartbeat
  vps wgft agent ls --admin "$ADMIN" --json | python3 -c "
import json, sys
a = next((x for x in json.load(sys.stdin) if x.get('name') == 'home'), {})
r = next((x for x in a.get('rules') or [] if x.get('id') == '$1'), {})
print(r.get('state', 'none'), r.get('reason', ''))
"
}
add_rule() { vps wgft rule add --agent home "$@" --admin "$ADMIN" | grep -oE 'r_[A-Z0-9]+'; }

tcp_echo() { client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:$1 2>&1"; }
udp_echo() { client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:$1 2>&1"; }

# slow_flow <port> <seconds> <outfile>: an established TCP flow in the background that sends one
# byte every half second for <seconds>, then half-closes and prints the echo's byte count. A flow
# that breaks on the way prints an error or a short count.
slow_flow() {
  client "python3 - $1 $2 > $3 2>&1 <<'PY' &
import socket, sys, time
port, secs = int(sys.argv[1]), float(sys.argv[2])
s = socket.create_connection(('198.51.100.1', port), timeout=10)
n = 0
end = time.time() + secs
while time.time() < end:
    s.send(b'x'); n += 1
    time.sleep(0.5)
s.shutdown(socket.SHUT_WR)
print('sent=%d' % n, s.makefile().read().strip())
PY"
}
flow_ok() { # flow_ok <outfile>: the echo counted every byte the flow sent
  python3 - "$1" <<'PY'
import re, sys
t = open(sys.argv[1]).read()
m = re.search(r'sent=(\d+).*got=(\d+)', t)
sys.exit(0 if m and m.group(1) == m.group(2) else 1)
PY
}

echo "== agent kernel mode: setup"
cleanup
mkdir -p "$DATA" "$ADATA" "/etc/netns/$HOME_NS"
# 192.168.50.4 and .5 answer nothing. They are listed first and allowed, so a rule that took the
# first address instead of the smallest would fail the echo.
set_hosts "192.168.50.4 game.lan" "192.168.50.3 game.lan"
: > "$ALOG"
start_server() {
  if [ "$SERVER_MODE" = userspace ]; then
    id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab
    chown wgftlab "$DATA"
    vps setsid nohup runuser -u wgftlab -- wgft server run --mode userspace --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
      >> "$SLOG" 2>&1 < /dev/null &
  else
    vps setsid nohup wgft server run --mode kernel --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
      >> "$SLOG" 2>&1 < /dev/null &
  fi
  disown
}
server_pids() {
  local p
  for p in $(ip netns pids "$VPS_NS" 2>/dev/null); do
    [ "$(cat "/proc/$p/comm" 2>/dev/null)" = wgft ] && tr '\0' ' ' < "/proc/$p/cmdline" | grep -q ' server run' && echo "$p"
  done
}
server_stopped() { [ -z "$(server_pids)" ]; }
: > "$SLOG"
start_server
wait_until 30 vps wgft agent ls --admin "$ADMIN" || echo "!! the server did not come up"
lan setsid nohup echo -tcp 25565,25567 -udp 19132 > "$ELOG" 2>&1 < /dev/null &
disown
home setsid nohup echo -bind 192.168.50.2 -tcp 25580,25565 >> "$ELOG" 2>&1 < /dev/null &
disown
# a LAN service that sends 2 MB on every connection, for the download direction of check 24
lan setsid nohup python3 -c '
import socket, threading
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("0.0.0.0", 25570)); ls.listen(8)
def serve(c):
    c.sendall(b"y" * 2000000); c.close()
while True:
    c, _ = ls.accept(); threading.Thread(target=serve, args=(c,), daemon=True).start()
' > /dev/null 2>&1 < /dev/null &
disown
# a service on the agent host that no rule publishes
home setsid nohup python3 -c '
import socket
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("0.0.0.0", 22222)); ls.listen(8)
while True:
    c, _ = ls.accept(); c.sendall(b"private-service\n"); c.close()
' > /dev/null 2>&1 < /dev/null &
disown
forward_before=$(home cat /proc/sys/net/ipv4/ip_forward)
JOIN=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
start_agent || echo "!! the agent did not start"
wait_until 30 handshaken || echo "!! the agent did not handshake"
JOIN=
R_TCP=$(add_rule --tcp 39971 --to 192.168.50.3:25565)
R_UDP=$(add_rule --udp 27015 --to 192.168.50.3:19132)
R_BIG=$(add_rule --tcp 39973 --to 192.168.50.3:25570)
R_SELF=$(add_rule --tcp 39974 --to 192.168.50.2:25580)
R_OUT=$(add_rule --tcp 39972 --to 192.168.50.3:25567)
R_LO=$(add_rule --tcp 39975 --to 127.0.0.1:25565)
R_NAME=$(add_rule --tcp 39977 --to game.lan:25565)
wait_until 30 caught_up || echo "!! the agent did not catch up"

check_16() {
  echo "== 16: basic forwarding"
  check "agent.json records kernel mode" '"mode": "kernel"' "$(cat "$ADATA/agent.json")"
  check "agent.json records the publication" '"kernel_publication"' "$(cat "$ADATA/agent.json")"
  check "wgft0 exists" "wgft0" "$(home ip -br link show wgft0 2>&1)"
  check "table inet wgft_agent exists" "chain nat_pre" "$(home nft list table inet wgft_agent 2>&1)"
  check "ip_forward is 1" "1" "$(home cat /proc/sys/net/ipv4/ip_forward)"
  if [ "$forward_before" = 0 ]; then
    check "agent.json records the ip_forward change" '"ip_forward_enabled_at"' "$(cat "$ADATA/agent.json")"
  fi
  check "tcp through the VPS" "tcp-echo" "$(tcp_echo 39971)"
  check "udp through the VPS" "udp-echo" "$(udp_echo 27015)"
  check "tcp rule state reaches the server" "ok" "$(rule_status "$R_TCP")"
  check "udp rule state reaches the server" "ok" "$(rule_status "$R_UDP")"
  # generation lag: from a rule change on the server until the agent's heartbeat reports the new
  # generation. server doctor calls a lag longer than 60 s a failure (design 10.2a).
  local i t0 t1 lag max=0 extra
  for i in 1 2 3; do
    t0=$(date +%s.%N)
    extra=$(add_rule --udp $((27020 + i)) --to 192.168.50.3:19132)
    wait_until 60 caught_up
    t1=$(date +%s.%N)
    lag=$(python3 -c "print('%.2f' % ($t1 - $t0))")
    echo "INFO  generation lag sample $i: ${lag}s"
    max=$(python3 -c "print(max($max, $lag))")
    vps wgft rule rm "$extra" --admin "$ADMIN" >/dev/null
    wait_until 60 caught_up
  done
  echo "INFO  generation lag max of 3: ${max}s, including the admin CLI round trip"
  okcheck "generation lag stays far below server doctor's 60 s" "$(python3 -c "print(1 if $max < 10 else 0)")"
}

check_17() {
  echo "== 17: agent stop and restart"
  local out=$W/wgft-ak-flow17
  slow_flow 39971 16 "$out"
  sleep 2
  stop_agent
  okcheck "the agent stopped" "$(agent_stopped && echo 1 || echo 0)"
  check "wgft0 stays while the agent is stopped" "wgft0" "$(home ip -br link show wgft0 2>&1)"
  check "the table stays while the agent is stopped" "chain nat_pre" "$(home nft list table inet wgft_agent 2>&1)"
  check "new tcp while the agent is stopped" "tcp-echo" "$(tcp_echo 39971)"
  check "new udp while the agent is stopped" "udp-echo" "$(udp_echo 27015)"
  sleep 3
  start_agent
  wait_until 30 caught_up
  check "new tcp after the restart" "tcp-echo" "$(tcp_echo 39971)"
  wait_until 30 test -s "$out"
  okcheck "the established flow survived the stop and the restart" "$(flow_ok "$out" && echo 1 || echo 0)"
  echo "INFO  flow: $(cat "$out")"
  check "the restart converged without refusing its own wgft0" "applied generation" "$(tail -n 40 "$ALOG")"
}

check_18() {
  echo "== 18: an unrelated rule change"
  local out=$W/wgft-ak-flow18 other
  slow_flow 39971 10 "$out"
  sleep 2
  other=$(add_rule --tcp 39976 --to 192.168.50.3:25565)
  wait_until 30 caught_up
  vps wgft rule rm "$other" --admin "$ADMIN" >/dev/null
  wait_until 30 caught_up
  wait_until 30 test -s "$out"
  okcheck "the established flow survived an unrelated add and delete" "$(flow_ok "$out" && echo 1 || echo 0)"
  echo "INFO  flow: $(cat "$out")"
}

check_22() {
  echo "== 22: guards"
  not_forwarded "no DNAT to a target outside the allowlist" "tcp-echo" "$(tcp_echo 39972)"
  check "the refused target is reported" "WGFT_AGENT_ALLOW_TARGETS" "$(rule_status "$R_OUT")"
  check "a loopback target is an error" "loopback" "$(rule_status "$R_LO")"
  check "DNAT to the agent host's own LAN address" "tcp-echo" "$(tcp_echo 39974)"
  check "the host's own service sees the VPS tunnel address" "from=10.200.0.1" "$(tcp_echo 39974)"
  # Each negative check below has a positive control in the same step: the same path reaches a
  # published port, and the same service or DNAT answers from the LAN side.
  local no_vps_tunnel=""
  [ "$SERVER_MODE" = userspace ] && no_vps_tunnel="a userspace-mode server has no tunnel address in the vps namespace's kernel"
  if [ -n "$no_vps_tunnel" ]; then
    skip "the VPS reaches a published port at the agent's tunnel address" "$no_vps_tunnel"
  else
    check "the VPS reaches a published port at the agent's tunnel address" "tcp-echo" \
      "$(vps bash -c 'echo hi | timeout -k 2 8 socat -t 2 -T 3 - TCP:10.200.0.2:39971,connect-timeout=3 2>&1')"
  fi
  check "the unpublished service answers from the LAN" "private-service" \
    "$(lan timeout -k 2 8 socat -T 3 - TCP:192.168.50.2:22222,connect-timeout=3 2>&1)"
  if [ -n "$no_vps_tunnel" ]; then
    skip "an unpublished port of the agent host is not reachable from wgft0" "$no_vps_tunnel"
  else
    not_forwarded "an unpublished port of the agent host is not reachable from wgft0" "private-service" \
      "$(vps timeout -k 2 8 socat -T 3 - TCP:10.200.0.2:22222,connect-timeout=3 2>&1)"
  fi
  home nft -f - <<'NFT'
table ip docker_like {
  chain pre {
    type nat hook prerouting priority dstnat;
    tcp dport 8080 dnat to 192.168.50.2:25580
  }
}
NFT
  check "another table's DNAT works from the LAN" "tcp-echo 192.168.50.2:25580" \
    "$(lan bash -c 'echo hi | timeout -k 2 8 socat -t 2 -T 3 - TCP:192.168.50.2:8080,connect-timeout=3 2>&1')"
  if [ -n "$no_vps_tunnel" ]; then
    skip "another table's DNAT is not reachable from wgft0" "$no_vps_tunnel"
  else
    not_forwarded "another table's DNAT is not reachable from wgft0" "tcp-echo" \
      "$(vps bash -c 'echo hi | timeout -k 2 8 socat -t 2 -T 3 - TCP:10.200.0.2:8080,connect-timeout=3 2>&1')"
  fi
  home nft delete table ip docker_like
  # another table's forward policy drop is named in the startup log
  home nft -f - <<'NFT'
table inet otherfw {
  chain forward_drop {
    type filter hook forward priority 0; policy drop;
  }
}
NFT
  stop_agent
  : > "$ALOG"
  start_agent
  wait_until 30 grep -q "drops forwarded packets by default" "$ALOG"
  check "another table's forward policy drop is in the log" "drops forwarded packets by default" "$(cat "$ALOG")"
  home nft delete table inet otherfw
  wait_until 30 caught_up
}

check_24() {
  echo "== 24: MSS clamp on a path that drops ICMP"
  client 'nft -f - <<NFT
table inet noicmp {
  chain in {
    type filter hook input priority -300; policy accept;
    icmp type destination-unreachable drop
  }
}
NFT'
  lan nft -f - <<'NFT'
table inet noicmp {
  chain in {
    type filter hook input priority -300; policy accept;
    icmp type destination-unreachable drop
  }
}
NFT
  check "2 MB upload through the VPS" "got=2000000" "$(upload_2mb)"
  check "2 MB download through the VPS" "2000000" "$(download_2mb)"
  # The same transfers without the agent's two MSS rows, to show that the path needs them. The
  # agent is stopped meanwhile: its 30-second check would put the rows back in the middle of a
  # transfer. The kernel keeps forwarding with the table as it is.
  stop_agent
  delete_mss_rows
  # Forget what each host learned about path MTUs, so that neither end reuses a smaller MSS or PMTU
  # it learned from the transfers above.
  client 'ip route flush cache'; lan ip route flush cache; home ip route flush cache; vps ip route flush cache
  echo "INFO  lan tcp_mtu_probing=$(lan cat /proc/sys/net/ipv4/tcp_mtu_probing) client tcp_mtu_probing=$(client 'cat /proc/sys/net/ipv4/tcp_mtu_probing')"
  if [ "$SERVER_MODE" = userspace ]; then
    skip "without the MSS rows the upload and the download stall" "a userspace-mode server relays TCP, so the path does not depend on the agent's MSS rows"
  else
    not_forwarded "without the MSS rows the upload stalls" "got=2000000" "$(upload_2mb)"
    okcheck "the MSS rows were still absent after the upload" "$(mss_rows_absent && echo 1 || echo 0)"
    not_forwarded "without the MSS rows the download stalls" "2000000" "$(download_2mb)"
    okcheck "the MSS rows were still absent after the download" "$(mss_rows_absent && echo 1 || echo 0)"
  fi
  client 'nft delete table inet noicmp'
  lan nft delete table inet noicmp
  # The restart's startup convergence publishes the whole table before the first 30-second check,
  # which runs 30 s after the start. Rows back within that time came from the restart.
  local applied t0
  applied=$(grep -c "applied generation" "$ALOG")
  t0=$SECONDS
  start_agent
  wait_until 25 applied_since "$applied"
  okcheck "the restart puts the MSS rows back before the first 30-second check: after $((SECONDS - t0))s" \
    "$(mss_rows_back && [ $((SECONDS - t0)) -lt 30 ] && echo 1 || echo 0)"
}
delete_mss_rows() {
  local h
  for h in $(home nft -a list chain inet wgft_agent forward | grep maxseg | grep -oE 'handle [0-9]+' | awk '{print $2}'); do
    home nft delete rule inet wgft_agent forward handle "$h"
  done
}
mss_rows_absent() { [ "$(home nft list chain inet wgft_agent forward | grep -c maxseg)" = 0 ]; }
applied_since() { [ "$(grep -c "applied generation" "$ALOG")" -gt "$1" ]; }
mss_rows_back() { [ "$(home nft list chain inet wgft_agent forward | grep -c maxseg)" = 2 ]; }
upload_2mb() { client 'head -c 2000000 /dev/zero | timeout -k 5 30 socat -t 10 -T 20 - TCP:198.51.100.1:39971 2>&1'; }
download_2mb() { client 'timeout -k 5 30 socat -T 20 -u TCP:198.51.100.1:39973 - 2>/dev/null | wc -c'; }

check_resolve() {
  echo "== resolve: the 30-second check resolves names again"
  check "a host-name rule reaches the smallest address" "tcp-echo 0.0.0.0:25565" "$(tcp_echo 39977)"
  local before
  before=$(grep -c "target resolution changed" "$ALOG")
  # the allowed candidates change from .3 and .4 to .3 and .5; the smallest stays .3
  set_hosts "192.168.50.5 game.lan" "192.168.50.3 game.lan"
  sleep 40
  check "the new candidates keep the smallest address" "tcp-echo 0.0.0.0:25565" "$(tcp_echo 39977)"
  okcheck "a change that keeps the chosen address publishes nothing" \
    "$([ "$(grep -c "target resolution changed" "$ALOG")" = "$before" ] && echo 1 || echo 0)"
  set_hosts "192.168.50.2 game.lan"
  wait_until 45 grep -q "target resolution changed the DNAT of $R_NAME" "$ALOG"
  check "a changed address moves new flows" "tcp-echo 192.168.50.2:25565" "$(tcp_echo 39977)"
  set_hosts
  wait_until 60 rule_reason_has "$R_NAME" "still forwarding to 192.168.50.2"
  check "a name that stops resolving keeps the last good address" "still forwarding to 192.168.50.2" "$(rule_status "$R_NAME")"
  check "and says the name did not resolve" "name resolution" "$(rule_status "$R_NAME")"
  check "and keeps forwarding" "tcp-echo 192.168.50.2:25565" "$(tcp_echo 39977)"
  set_hosts "192.168.50.3 game.lan"
  wait_until 60 rule_state_ok "$R_NAME"
  check "the name resolves again" "ok" "$(rule_status "$R_NAME")"
}
rule_reason_has() { [[ "$(rule_status "$1")" == *"$2"* ]]; }
rule_state_ok() { [[ "$(rule_status "$1")" == "ok "* ]]; }

check_drift() {
  echo "== drift: the 30-second check repairs changes made outside wgft"
  home nft delete table inet wgft_agent
  wait_until 45 home nft list table inet wgft_agent
  check "a deleted table is published again" "chain nat_pre" "$(home nft list table inet wgft_agent 2>&1)"
  check "forwarding is back after the table was deleted" "tcp-echo" "$(tcp_echo 39971)"
  check "the log names the missing table" "table inet wgft_agent is gone" "$(cat "$ALOG")"
  local h
  h=$(home nft -a list chain inet wgft_agent postrouting | grep masquerade | grep -oE 'handle [0-9]+' | awk '{print $2}')
  home nft delete rule inet wgft_agent postrouting handle "$h"
  wait_until 45 masquerade_back
  okcheck "a deleted row is published again" "$(masquerade_back && echo 1 || echo 0)"
  check "the log names the changed table" "was changed outside wgft" "$(cat "$ALOG")"
  home ip link set wgft0 mtu 1280
  wait_until 45 mtu_back
  okcheck "a changed MTU is converged back" "$(mtu_back && echo 1 || echo 0)"
  local warned
  warned=$(grep -c "leaves through" "$ALOG")
  home ip link del wgft0
  wait_until 60 home ip link show wgft0
  wait_until 60 handshaken
  check "a deleted wgft0 is created again" "wgft0" "$(home ip -br link show wgft0 2>&1)"
  wait_until 30 tcp_ok 39971
  check "forwarding is back after wgft0 was deleted" "tcp-echo" "$(tcp_echo 39971)"
  # While wgft0 is gone, the route to the server leaves through the default route; the route check
  # runs after the repair, so it does not warn about that
  okcheck "no route warning while wgft0 was gone" "$(count_above "leaves through" "$warned" && echo 0 || echo 1)"
}
masquerade_back() { home nft list chain inet wgft_agent postrouting | grep -q masquerade; }
mtu_back() { home ip link show wgft0 | grep -q 'mtu 1420'; }
tcp_ok() { [[ "$(tcp_echo "$1")" == *tcp-echo* ]]; }

check_session() {
  echo "== session: the keepalive datagram, with a $SERVER_MODE-mode server"
  local before after ctr_before ctr_after n t0 t1 hs0 lag
  before=$(doctor_states)
  if [ "$SERVER_MODE" = kernel ]; then
    vps nft -f - <<'NFT'
table inet ak_probe9 {
  chain in {
    type filter hook input priority -300; policy accept;
    iifname "wgft0" udp dport 9 counter
  }
}
NFT
    ctr_before=$(server_counters)
  fi
  sleep 60
  after=$(doctor_states)
  okcheck "server doctor is unchanged by a minute of datagrams" "$([ -n "$before" ] && [ "$before" = "$after" ] && echo 1 || echo 0)"
  echo "INFO  server doctor before: $before"
  [ "$before" = "$after" ] || echo "INFO  server doctor after: $after"
  if [ "$SERVER_MODE" = kernel ]; then
    n=$(vps nft list table inet ak_probe9 | grep -oE 'packets [0-9]+' | awk '{print $2}')
    okcheck "the keepalive datagram reaches the server's tunnel address on port 9: ${n:-0} in 60 s" "$([ "${n:-0}" -ge 2 ] && echo 1 || echo 0)"
    ctr_after=$(server_counters)
    okcheck "the server's nftables counters are unchanged" "$([ "$ctr_before" = "$ctr_after" ] && echo 1 || echo 0)"
    vps nft delete table inet ak_probe9
  fi
  # The server loses the session: in kernel mode the wg interface is deleted and vpsd creates it
  # again, in userspace mode the server process restarts. The server keeps no endpoint for the
  # agent then, so only the agent's side can start the new handshake.
  #
  # Without the datagram, the agent keeps using its keys until they are REKEY_AFTER_TIME (120 s) old,
  # or REJECT_AFTER_TIME (180 s) when the server started that handshake, so how long the recovery
  # takes depends on the keys' age at the loss. The session is therefore lost twice: the first loss
  # only brings a fresh handshake, and the measured loss follows it at once, when the keys are new
  # and nothing but the datagram can start a handshake within the 60 s limit.
  hs0=$(agent_wg_handshake)
  t0=$(date +%s)
  lose_session
  wait_until 240 agent_wg_handshake_after "$hs0"
  echo "INFO  warm-up: handshake back $(( $(date +%s) - t0 ))s after the first loss"
  hs0=$(agent_wg_handshake)
  t0=$(date +%s)
  lose_session
  wait_until 180 agent_wg_handshake_after "$hs0"
  t1=$(date +%s)
  lag=$((t1 - t0))
  echo "INFO  handshake back ${lag}s after the server lost a fresh session"
  okcheck "the agent's side brings the handshake back within 60 s of losing a fresh session: ${lag}s" "$([ "$lag" -lt 60 ] && echo 1 || echo 0)"
  wait_until 30 tcp_ok 39971
  check "forwarding is back after the session was lost" "tcp-echo" "$(tcp_echo 39971)"
}
lose_session() {
  if [ "$SERVER_MODE" = kernel ]; then
    vps ip link del wgft0
  else
    for p in $(server_pids); do kill "$p"; done
    wait_until 20 server_stopped
    start_server
    wait_until 30 vps wgft agent ls --admin "$ADMIN"
  fi
}
# agent_wg_handshake: the latest handshake of wgft0's peer on the agent host, in seconds since the epoch
agent_wg_handshake() { home wg show wgft0 latest-handshakes 2>/dev/null | awk '{print $2; exit}'; }
agent_wg_handshake_after() { local h; h=$(agent_wg_handshake); [ -n "$h" ] && [ "$h" != 0 ] && [ "$h" != "$1" ]; }
check_route() {
  echo "== route: a policy routing rule that takes the server's tunnel address away from wgft0"
  home ip route add 10.200.0.1/32 via 192.168.50.1 dev eth0 table 52
  home ip rule add to 10.200.0.1 lookup 52 priority 100
  wait_until 45 grep -q "leaves through eth0, not wgft0" "$ALOG"
  check "the agent names the route that leaves through another interface" "leaves through eth0, not wgft0" "$(cat "$ALOG")"
  home ip rule del to 10.200.0.1 lookup 52
  home ip route flush table 52
  wait_until 45 grep -q "leaves through wgft0 again" "$ALOG"
  check "the agent names the route coming back" "leaves through wgft0 again" "$(cat "$ALOG")"
  wait_until 30 tcp_ok 39971
  check "forwarding works with the rule removed" "tcp-echo" "$(tcp_echo 39971)"
  # A route in the main table that covers the server's tunnel address and is more specific than
  # wgft0's range, which appears while the agent runs, is found by the same check.
  local warned back
  warned=$(grep -c "leaves through eth0, not wgft0" "$ALOG")
  back=$(grep -c "leaves through wgft0 again" "$ALOG")
  home ip route add 10.200.0.1/32 via 192.168.50.1 dev eth0
  wait_until 45 count_above "leaves through eth0, not wgft0" "$warned"
  okcheck "the agent names a main-table route that takes the address" "$(count_above "leaves through eth0, not wgft0" "$warned" && echo 1 || echo 0)"
  home ip route del 10.200.0.1/32 via 192.168.50.1 dev eth0
  wait_until 45 count_above "leaves through wgft0 again" "$back"
  okcheck "the agent names the route coming back after that" "$(count_above "leaves through wgft0 again" "$back" && echo 1 || echo 0)"
  wait_until 30 tcp_ok 39971
  check "forwarding works with the route removed" "tcp-echo" "$(tcp_echo 39971)"
}
count_above() { [ "$(grep -c "$1" "$ALOG")" -gt "$2" ]; } # count_above <pattern> <count>: in the agent's log
# doctor_states: every "id=status" in server doctor's JSON, sorted, on one line.
doctor_states() {
  vps wgft server doctor --admin "$ADMIN" --json 2>/dev/null | python3 -c '
import json, sys
out = []
def walk(v):
    if isinstance(v, dict):
        if "id" in v and "status" in v:
            out.append("%s=%s" % (v["id"], v["status"]))
        for x in v.values():
            walk(x)
    elif isinstance(v, list):
        for x in v:
            walk(x)
try:
    walk(json.load(sys.stdin))
except ValueError:
    pass
print(" ".join(sorted(out)))
'
}
server_counters() { vps nft list table inet wgft 2>/dev/null | grep -oE 'counter packets [0-9]+ bytes [0-9]+' | tr '\n' ' '; }
handshake_after() { local h; h=$(agent_field last_handshake); [ -n "$h" ] && [ "$h" != "$1" ] && [ "$h" != "0001-01-01T00:00:00Z" ]; }

for c in $CHECKS; do
  case "$c" in
    16|17|18|22|24|resolve|drift|session|route) "check_$c" ;;
    *) echo "FAIL  unknown check $c"; fail=1 ;;
  esac
done

echo "== agent kernel mode: cleanup"
cleanup
if [ "$fail" = 0 ]; then echo "== agent kernel mode: ALL PASS"; else echo "== agent kernel mode: FAILURES"; fi
exit "$fail"
