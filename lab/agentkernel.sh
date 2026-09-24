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
#   19. a retarget closes the established flows to the old target, and a delete closes the
#       deleted rule's flows; the agent's conntrack convergence does it, not the table.
#   22. the guards: a target outside WGFT_AGENT_ALLOW_TARGETS gets no DNAT and is reported, a
#       loopback target is an error, a DNAT to the agent host's own LAN address works and the
#       service sees the VPS tunnel address as the source, nothing else on the agent host is
#       reachable from wgft0, not even through another table's DNAT, while the same service and
#       DNAT answer from the LAN and a published port answers from wgft0, and another table's
#       forward policy drop is named in the agent's startup log.
#   24. MSS clamp: with ICMP "fragmentation needed" dropped on both ends, 2 MB of TCP goes through
#       in each direction.
#   25. disabling the agent on the server removes the home DNAT and closes the agent's flows, also
#       when the agent was stopped at the time and learns of it after a restart and reconnect.
#   resolve. the 30-second check resolves a rule's host name again: a change that keeps the chosen
#       address publishes nothing, a changed address moves new flows to it, and a name that stops
#       resolving keeps forwarding to the last good address and says so in the rule's state. The
#       name is served from the home namespace's own /etc/hosts, /etc/netns/<ns>/hosts. server
#       doctor reads that rule as still forwarding (design 10.2a): target resolve unknown, shown
#       DEGRADED, exit 0. When the old address then refuses, the agent's report carries the probe
#       error and doctor stops the rule at the target. A name that never resolved still stops at
#       target resolve.
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
#   teardown. wgft agent teardown: it refuses while the agent runs; pointed at a directory without
#       agent.json while the agent runs, it removes nothing and forwarding goes on; a stopped
#       kernel-mode agent's leftovers make a userspace start refuse; teardown removes the agent's
#       interfaces, found by key under any name, its table and its records, keeps agent.json's
#       owner, and leaves a WireGuard interface with another key and an unrelated table alone; the
#       agent then forwards in userspace mode, and the outage from stopping the kernel-mode agent
#       until forwarding is back is measured and printed; kernel mode comes back after a teardown;
#       a wgft0 holding the previous key after a stopped rotate-key is removed, and without
#       last_state the flows are found by wgft0's address; a foreign-key wgft0 is left and named;
#       a host with only the records left, as after a reboot, is cleared; an unknown recorded mode
#       stops it with exit code 3 and changes nothing; a run without CAP_NET_ADMIN is a
#       prerequisite refusal; a second run finds nothing to remove.
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
CHECKS=${*:-16 17 18 19 22 24 25 resolve drift session route teardown}
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
  # remove the agent's kernel state by hand, so that a run stopped before wgft agent teardown
  # leaves nothing either
  home ip link del wgft0 2>/dev/null
  home nft delete table inet wgft_agent 2>/dev/null
  home nft delete table ip docker_like 2>/dev/null
  home nft delete table inet otherfw 2>/dev/null
  home ip rule del to 10.200.0.1 lookup 52 2>/dev/null
  home ip route flush table 52 2>/dev/null
  home ip link del wgold 2>/dev/null
  home ip link del wgunrel 2>/dev/null
  home nft delete table inet unrelated 2>/dev/null
  client 'nft delete table inet noicmp 2>/dev/null'
  lan nft delete table inet noicmp 2>/dev/null
  home nft delete table inet stalereject 2>/dev/null
  rm -rf "$DATA" "$ADATA" "/etc/netns/$HOME_NS"
}
# set_hosts <line>...: the home namespace's /etc/hosts. `ip netns exec` bind-mounts the file when it
# starts a process, so the file is rewritten in place to keep the running agent's view of it.
set_hosts() { printf '127.0.0.1 localhost\n' > "$HOSTS"; printf '%s\n' "$@" >> "$HOSTS"; }

# The allowlist holds every target the rules use except the one that must be refused. 127.0.0.1 is
# in it, so the loopback rule is refused for being loopback, not for the list.
ALLOW=192.168.50.3:25565,192.168.50.3:19132,192.168.50.3:25570,192.168.50.2:25580,192.168.50.2:25565,192.168.50.4:25565,192.168.50.5:25565,127.0.0.1:25565
start_agent() { # start_agent [mode]: kernel unless given
  WGFT_MODE=${1:-kernel} WGFT_JOIN="${JOIN:-}" WGFT_AGENT_ALLOW_TARGETS="$ALLOW" \
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
# The home namespace's resolver points at its own loopback, where nothing listens, so a name that is
# not in its hosts file fails at once and no lookup leaves the lab.
printf 'nameserver 127.0.0.1\n' > "/etc/netns/$HOME_NS/resolv.conf"
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
  # server doctor does not call a rule that still forwards from the last good address stopped
  # (design 10.2a): target resolve is unknown, read DEGRADED, and the command exits 0.
  local out rcode
  eqcheck "doctor: target resolve while the name fails" "unknown target_resolve_failed" "$(doctor_field "$R_NAME" check rule.target_resolve)"
  eqcheck "doctor: target while the old address answers" "ok -" "$(doctor_field "$R_NAME" check rule.target)"
  eqcheck "doctor: the rule is unknown, not stopped" "unknown -" "$(doctor_field "$R_NAME" rule)"
  out=$(vps wgft server doctor "$R_NAME" --admin "$ADMIN" 2>&1); rcode=$?
  eqcheck "doctor exits 0 while the rule still forwards" 0 "$rcode"
  check "doctor reads the resolve line DEGRADED" "target resolve     DEGRADED" "$out"
  check "doctor's result says it still forwards" "Result: still forwarding to 192.168.50.2" "$out"
  not_forwarded "doctor does not say traffic stops" "traffic stops" "$out"
  echo "INFO  server doctor while the name fails:"; echo "$out" | sed -n '/^Agent/,/^Result/p' | sed 's/^/INFO    /'
  # the old address stops answering too: now traffic does stop at the target
  home nft -f - <<'NFT'
table inet stalereject {
  chain in {
    type filter hook input priority -10; policy accept;
    ip daddr 192.168.50.2 tcp dport 25565 reject with tcp reset
  }
}
NFT
  # The lookup's own error can read "connection refused" too (the resolver on the loopback), so wait
  # for the probe's error, which names the old address after the stale part of the reason. The probe
  # runs every 30 s and the heartbeat that carries it every 30 s, so allow up to 90 s.
  wait_until 90 rule_reason_has "$R_NAME" "resolution; target 192.168.50.2:25565"
  check "the agent reports the old address refusing" "resolution; target 192.168.50.2:25565" "$(rule_status "$R_NAME")"
  echo "INFO  the rule's state: $(rule_status "$R_NAME")"
  not_forwarded "and the rule does not forward" "tcp-echo" "$(tcp_echo 39977)"
  eqcheck "doctor: target resolve stays unknown" "unknown target_resolve_failed" "$(doctor_field "$R_NAME" check rule.target_resolve)"
  eqcheck "doctor: target fails with connection_refused" "failed connection_refused" "$(doctor_field "$R_NAME" check rule.target)"
  eqcheck "doctor: the rule stops at the target" "failed rule.target" "$(doctor_field "$R_NAME" rule)"
  vps wgft server doctor "$R_NAME" --admin "$ADMIN" >/dev/null 2>&1; rcode=$?
  eqcheck "doctor exits 1 when the old address refuses" 1 "$rcode"
  home nft delete table inet stalereject
  wait_until 90 rule_reason_lacks "$R_NAME" "resolution; target 192.168.50.2:25565"
  eqcheck "doctor: target is ok again once the old address answers" "ok -" "$(doctor_field "$R_NAME" check rule.target)"
  # a name that never resolved has no old address and no DNAT: doctor still says it stops there
  local never
  never=$(add_rule --tcp 39978 --to never.lan:25565)
  wait_until 30 caught_up
  wait_until 30 rule_reason_has "$never" "name resolution"
  eqcheck "doctor: a name that never resolved fails" "failed target_resolve_failed" "$(doctor_field "$never" check rule.target_resolve)"
  eqcheck "doctor: that rule stops at target resolve" "failed rule.target_resolve" "$(doctor_field "$never" rule)"
  vps wgft rule rm "$never" --admin "$ADMIN" >/dev/null
  wait_until 30 caught_up
  set_hosts "192.168.50.3 game.lan"
  wait_until 60 rule_state_ok "$R_NAME"
  check "the name resolves again" "ok" "$(rule_status "$R_NAME")"
}
rule_reason_has() { [[ "$(rule_status "$1")" == *"$2"* ]]; }
rule_reason_lacks() { [[ "$(rule_status "$1")" != *"$2"* ]]; }
eqcheck() { if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: want '$2', got '$3'"; fail=1; fi; }
# doctor_field <rule-id> check <check-id> | doctor_field <rule-id> rule: "<status> <reason>" of one
# check, or "<status> <stopped_at>" of the rule, from server doctor --json on that rule ("-" if empty).
doctor_field() {
  vps wgft server doctor "$1" --json --admin "$ADMIN" 2>/dev/null | python3 -c "
import json, sys
rep = json.load(sys.stdin)
if '$2' == 'rule':
    r = next((x for x in rep.get('rules') or [] if x.get('rule_id') == '$1'), {})
    print(r.get('status', 'none'), r.get('stopped_at') or '-')
else:
    c = next((x for x in rep.get('checks') or [] if x.get('rule_id') == '$1' and x.get('id') == '${3:-}'), {})
    print(c.get('status', 'none'), c.get('reason') or '-')
"
}
rule_state_ok() { [[ "$(rule_status "$1")" == "ok "* ]]; }

check_drift() {
  echo "== drift: the 30-second check repairs changes made outside wgft"
  # A TCP flow held across each deletion is only observed and printed, not judged: what the kernel
  # does with an established flow when the table goes is not a promise of wgft's
  local held=$W/wgft-ak-flowdrift
  slow_flow 39971 45 "$held"
  sleep 3
  home nft delete table inet wgft_agent
  wait_until 45 home nft list table inet wgft_agent
  check "a deleted table is published again" "chain nat_pre" "$(home nft list table inet wgft_agent 2>&1)"
  check "forwarding is back after the table was deleted" "tcp-echo" "$(tcp_echo 39971)"
  check "the log names the missing table" "table inet wgft_agent is gone" "$(cat "$ALOG")"
  wait_until 60 test -s "$held"
  echo "INFO  a TCP flow held across the deleted table: $(flow_ok "$held" && echo survived || echo "ended: $(tail -1 "$held")")"
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
  slow_flow 39971 45 "$held"
  sleep 3
  home ip link del wgft0
  wait_until 60 home ip link show wgft0
  wait_until 60 handshaken
  check "a deleted wgft0 is created again" "wgft0" "$(home ip -br link show wgft0 2>&1)"
  wait_until 30 tcp_ok 39971
  check "forwarding is back after wgft0 was deleted" "tcp-echo" "$(tcp_echo 39971)"
  # While wgft0 is gone, the route to the server leaves through the default route; the route check
  # runs after the repair, so it does not warn about that
  okcheck "no route warning while wgft0 was gone" "$(count_above "leaves through" "$warned" && echo 0 || echo 1)"
  wait_until 60 test -s "$held"
  echo "INFO  a TCP flow held across the deleted wgft0: $(flow_ok "$held" && echo survived || echo "ended: $(tail -1 "$held")")"
}
check_teardown() {
  echo "== teardown: wgft agent teardown removes only what the agent owns"
  local out rc t_stop t_down t_up key other owner before probe=$W/wgft-ak-probe nocap=$W/wgft-ak-nocap
  wait_until 30 caught_up
  out=$(home wgft agent teardown --data-dir "$ADATA" 2>&1); rc=$?
  check "teardown refuses while the agent runs" "the agent is running, so nothing was removed" "$out"
  okcheck "the refusal exits 1" "$([ "$rc" = 1 ] && echo 1 || echo 0)"
  check "wgft0 stays after the refusal" "wgft0" "$(home ip -br link show wgft0 2>&1)"
  check "the table stays after the refusal" "chain nat_pre" "$(home nft list table inet wgft_agent 2>&1)"

  # A data directory without agent.json, as when --data-dir is left out while the agent uses another
  # directory: the lock there says nothing about the running agent, so teardown must remove nothing.
  local empty=$W/wgft-ak-empty
  rm -rf "$empty"; mkdir -p "$empty"
  out=$(home wgft agent teardown --data-dir "$empty" 2>&1); rc=$?
  check "a directory without agent.json removes nothing" "does not exist, so nothing was removed" "$out"
  okcheck "and exits 1" "$([ "$rc" = 1 ] && echo 1 || echo 0)"
  check "it names the table it found" "found: table inet wgft_agent" "$out"
  check "it names wgft0 as wgft's configured name" "found: the WireGuard interface wgft0, wgft's configured name" "$out"
  check "it points at --data-dir" "Point --data-dir" "$out"
  check "the running agent's table stays" "chain nat_pre" "$(home nft list table inet wgft_agent 2>&1)"
  check "the running agent's wgft0 stays up" "UP" "$(home ip -br link show wgft0 2>&1)"
  check "forwarding goes on right after it" "tcp-echo" "$(tcp_echo 39971)"
  okcheck "it created nothing in that directory" "$([ -z "$(ls -A "$empty")" ] && echo 1 || echo 0)"
  rm -rf "$empty"

  # Forwarding is probed every 0.1 s from the client through the VPS, each probe a new TCP
  # connection that gives up after 0.5 s, for the outage measured below.
  client "python3 - > $probe 2>&1 <<'PY' &
import socket, time
end = time.time() + 120
while time.time() < end:
    t = time.time()
    try:
        # the echo answers once the client half-closes
        s = socket.create_connection(('198.51.100.1', 39971), timeout=0.5)
        s.settimeout(0.5); s.sendall(b'hi'); s.shutdown(socket.SHUT_WR)
        ok = b'tcp-echo' in s.recv(200); s.close()
    except OSError:
        ok = False
    print('%.3f %s' % (t, 'ok' if ok else 'fail'), flush=True)
    time.sleep(max(0, 0.1 - (time.time() - t)))
PY"
  sleep 2
  t_stop=$(date +%s.%N)
  stop_agent
  sleep 3
  check "forwarding goes on while the kernel-mode agent is stopped" "tcp-echo" "$(tcp_echo 39971)"

  # the agent's key under an old name, a WireGuard interface with another key, an unrelated table
  key=$W/wgft-ak-agentkey
  other=$W/wgft-ak-otherkey
  (umask 077; python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["wg_private_key"])' "$ADATA/agent.json" > "$key"; wg genkey > "$other")
  home ip link add wgold type wireguard && home wg set wgold private-key "$key"
  home ip link add wgunrel type wireguard && home wg set wgunrel private-key "$other"
  home nft add table inet unrelated && home nft add chain inet unrelated keep

  out=$(WGFT_MODE=userspace home timeout -k 5 30 wgft agent run --data-dir "$ADATA" 2>&1); rc=$?
  check "a userspace start is refused while the kernel-mode leftovers remain" "refusing to start [mode-gate WGFT_MODE]" "$out"
  okcheck "the mode gate exits 3" "$([ "$rc" = 3 ] && echo 1 || echo 0)"

  out=$(home wgft agent teardown --data-dir "$ADATA" --dry-run 2>&1)
  check "dry run lists wgft0" "remove: the WireGuard interface wgft0, which holds this agent's key" "$out"
  check "dry run lists the old name" "remove: the WireGuard interface wgold, which holds this agent's key" "$out"
  not_forwarded "dry run does not list the interface with another key" "wgunrel" "$out"
  check "dry run changes nothing" "wgft0" "$(home ip -br link show wgft0 2>&1)"
  check "dry run keeps the records" '"mode": "kernel"' "$(cat "$ADATA/agent.json")"

  owner=$(stat -c %u:%g "$ADATA/agent.json")
  chown 65534:65534 "$ADATA/agent.json"
  t_down=$(date +%s.%N)
  out=$(home wgft agent teardown --data-dir "$ADATA" 2>&1); rc=$?
  echo "$out" | sed 's/^/INFO  teardown: /'
  okcheck "teardown exits 0" "$([ "$rc" = 0 ] && echo 1 || echo 0)"
  check "teardown deleted wgft0" "deleted the WireGuard interface wgft0" "$out"
  okcheck "teardown closed the agent's conntrack entries" "$([[ "$out" =~ conntrack:\ closed\ [1-9] ]] && echo 1 || echo 0)"
  okcheck "wgft0 is gone" "$(home ip link show wgft0 >/dev/null 2>&1 && echo 0 || echo 1)"
  okcheck "the old-name interface with the agent's key is gone" "$(home ip link show wgold >/dev/null 2>&1 && echo 0 || echo 1)"
  okcheck "table inet wgft_agent is gone" "$(home nft list table inet wgft_agent >/dev/null 2>&1 && echo 0 || echo 1)"
  check "the WireGuard interface with another key stays" "wgunrel" "$(home ip -br link show wgunrel 2>&1)"
  check "the unrelated table stays" "chain keep" "$(home nft list table inet unrelated 2>&1)"
  not_forwarded "agent.json has no mode record" '"mode"' "$(cat "$ADATA/agent.json")"
  check "agent.json keeps the registration" '"permanent_token"' "$(cat "$ADATA/agent.json")"
  check "agent.json keeps its owner" "65534:65534" "$(stat -c %u:%g "$ADATA/agent.json")"
  chown "$owner" "$ADATA/agent.json"
  if [ "$forward_before" = 0 ]; then
    check "the ip_forward change is shown with the command to restore it" "sysctl -w net.ipv4.ip_forward=0" "$out"
  fi
  out=$(home wgft agent teardown --data-dir "$ADATA" 2>&1); rc=$?
  check "a second run finds nothing" "nothing to remove" "$out"
  okcheck "a second run exits 0" "$([ "$rc" = 0 ] && echo 1 || echo 0)"

  t_up=$(date +%s.%N)
  start_agent userspace
  wait_until 60 tcp_ok 39971
  check "the agent forwards tcp in userspace mode after teardown" "tcp-echo" "$(tcp_echo 39971)"
  check "and udp" "udp-echo" "$(udp_echo 27015)"
  okcheck "userspace mode made no wgft0" "$(home ip link show wgft0 >/dev/null 2>&1 && echo 0 || echo 1)"
  sleep 3
  python3 - "$probe" "$t_stop" "$t_down" "$t_up" <<'PY'
import sys
t_stop, t_down, t_up = (float(x) for x in sys.argv[2:5])
rows = [(float(t), r) for t, r in (l.split() for l in open(sys.argv[1]) if len(l.split()) == 2)]
# A probe gives up after 0.5 s, so one started up to 0.6 s before teardown can fail because of it.
stopped = [r for t, r in rows if t_stop + 0.5 < t < t_down - 0.6]
print('%s  no probe failed while the kernel-mode agent was stopped, before teardown: %d of %d failed' %
      ('PASS' if stopped and 'fail' not in stopped else 'FAIL', stopped.count('fail'), len(stopped)))
last_ok = max((t for t, r in rows if r == 'ok' and t < t_down), default=None)
back = min((t for t, r in rows if r == 'ok' and t > t_up), default=None)
if last_ok is None or back is None:
    print('FAIL  outage: the probes do not show forwarding before teardown and back in userspace mode')
    sys.exit(1)
failed = sum(1 for t, r in rows if last_ok < t < back and r == 'fail')
print('PASS  outage: forwarding is back in userspace mode after %d failed probes' % failed)
print('INFO  outage: gap from the last good probe before teardown to the first good one in userspace mode: %.2fs' % (back - last_ok))
print('INFO  outage: from running teardown until forwarding was back: %.2fs' % (back - t_down))
print('INFO  outage: from starting the userspace-mode agent until forwarding was back: %.2fs' % (back - t_up))
print('INFO  outage: from stopping the kernel-mode agent until forwarding was back, with a 3 s pause and the checks before teardown: %.2fs' % (back - t_stop))
sys.exit(0 if stopped and 'fail' not in stopped else 1)
PY
  [ $? = 0 ] || fail=1

  echo "-- kernel mode again after teardown"
  stop_agent
  start_agent kernel
  wait_until 60 tcp_ok 39971
  check "kernel mode forwards again after teardown" "tcp-echo" "$(tcp_echo 39971)"
  check "kernel mode is recorded again" '"mode": "kernel"' "$(cat "$ADATA/agent.json")"

  echo "-- a wgft0 that holds the previous key after a stopped rotate-key"
  stop_agent
  check "a stopped rotate-key keeps the old key as the previous one" "the old key is kept as the previous key" "$(home wgft agent rotate-key --data-dir "$ADATA" 2>&1)"
  not_forwarded "the stopped rotate-key cleared last_state" '"last_state": {' "$(cat "$ADATA/agent.json")"
  out=$(home wgft agent teardown --data-dir "$ADATA" 2>&1); rc=$?
  check "teardown names wgft0 by the previous key" "remove: the WireGuard interface wgft0, which holds this agent's previous key" "$out"
  okcheck "without last_state it closes the agent's conntrack entries by wgft0's address" "$([[ "$out" =~ conntrack:\ closed\ [1-9] ]] && echo 1 || echo 0)"
  okcheck "and deletes it" "$([ "$rc" = 0 ] && ! home ip link show wgft0 >/dev/null 2>&1 && echo 1 || echo 0)"
  not_forwarded "the previous key is cleared" '"previous_wg_private_key"' "$(cat "$ADATA/agent.json")"

  echo "-- a wgft0 with another key"
  start_agent kernel
  wait_until 60 tcp_ok 39971
  stop_agent
  home wgft agent teardown --data-dir "$ADATA" > /dev/null 2>&1
  home ip link add wgft0 type wireguard && home wg set wgft0 private-key "$other"
  home nft add table inet wgft_agent
  out=$(home wgft agent teardown --data-dir "$ADATA" 2>&1); rc=$?
  check "a wgft0 with another key is named" "leave: wgft0 is a WireGuard interface that holds neither this agent's key nor its previous one" "$out"
  okcheck "and teardown succeeds" "$([ "$rc" = 0 ] && echo 1 || echo 0)"
  check "the wgft0 with another key stays" "wgft0" "$(home ip -br link show wgft0 2>&1)"
  okcheck "the table named wgft_agent is removed beside it" "$(home nft list table inet wgft_agent >/dev/null 2>&1 && echo 0 || echo 1)"
  home ip link del wgft0

  echo "-- only the records left, as after a reboot"
  start_agent kernel
  wait_until 60 tcp_ok 39971
  stop_agent
  home ip link del wgft0
  home nft delete table inet wgft_agent
  out=$(WGFT_MODE=userspace home timeout -k 5 30 wgft agent run --data-dir "$ADATA" 2>&1); rc=$?
  okcheck "the records alone make a userspace start refuse" "$([ "$rc" = 3 ] && [[ "$out" == *mode-gate* ]] && echo 1 || echo 0)"
  out=$(home wgft agent teardown --data-dir "$ADATA" 2>&1); rc=$?
  check "teardown clears the records alone" "cleared the kernel-mode records" "$out"
  okcheck "and exits 0" "$([ "$rc" = 0 ] && echo 1 || echo 0)"
  not_forwarded "agent.json has no mode record after that" '"mode"' "$(cat "$ADATA/agent.json")"

  echo "-- an unknown recorded mode"
  start_agent kernel
  wait_until 60 tcp_ok 39971
  stop_agent
  set_recorded_mode future
  before=$(sha256sum < "$ADATA/agent.json")
  out=$(home wgft agent teardown --data-dir "$ADATA" 2>&1); rc=$?
  check "an unknown mode stops teardown" "cannot continue [conflict WGFT_MODE]" "$out"
  okcheck "with exit code 3" "$([ "$rc" = 3 ] && echo 1 || echo 0)"
  okcheck "agent.json is unchanged" "$([ "$(sha256sum < "$ADATA/agent.json")" = "$before" ] && echo 1 || echo 0)"
  check "wgft0 is untouched" "wgft0" "$(home ip -br link show wgft0 2>&1)"
  check "the table is untouched" "chain nat_pre" "$(home nft list table inet wgft_agent 2>&1)"
  set_recorded_mode kernel

  echo "-- without CAP_NET_ADMIN"
  rm -rf "$nocap"; mkdir -p "$nocap"; cp "$ADATA/agent.json" "$nocap/"; chown -R 65534:65534 "$nocap"
  out=$(home runuser -u nobody -- wgft agent teardown --data-dir "$nocap" --config "$nocap/none.env" 2>&1); rc=$?
  check "a run without CAP_NET_ADMIN is a prerequisite refusal" "cannot continue [prerequisite CAP_NET_ADMIN]" "$out"
  okcheck "with exit code 3" "$([ "$rc" = 3 ] && echo 1 || echo 0)"
  check "and wgft0 stays" "wgft0" "$(home ip -br link show wgft0 2>&1)"
  rm -rf "$nocap" "$key" "$other"
  home wgft agent teardown --data-dir "$ADATA" > /dev/null 2>&1
  home ip link del wgunrel
  home nft delete table inet unrelated
}
set_recorded_mode() { # set_recorded_mode <mode>: rewrite the mode record in agent.json by hand
  python3 - "$ADATA/agent.json" "$1" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["mode"] = sys.argv[2]
json.dump(d, open(p, "w"), indent=2)
PY
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

check_19() {
  echo "== 19: a retarget or a delete closes the old target's flows"
  local out=$W/wgft-ak-flow19 r closed
  closed=$(grep -cE "conntrack: closed [1-9]" "$ALOG")
  slow_flow 39971 12 "$out"
  sleep 3
  set_target "$R_TCP" 192.168.50.2:25565
  wait_until 30 caught_up
  wait_until 30 test -s "$out"
  okcheck "a retarget closes the established flow to the old target" "$(flow_ok "$out" && echo 0 || echo 1)"
  echo "INFO  flow: $(cat "$out" | tail -1)"
  check "new flows reach the new target" "tcp-echo 192.168.50.2:25565" "$(tcp_echo 39971)"
  okcheck "the agent logs the closed flows" "$([ "$(grep -cE "conntrack: closed [1-9]" "$ALOG")" -gt "$closed" ] && echo 1 || echo 0)"
  set_target "$R_TCP" 192.168.50.3:25565
  wait_until 30 caught_up
  r=$(add_rule --tcp 39978 --to 192.168.50.3:25565)
  wait_until 30 caught_up
  out=$W/wgft-ak-flow19b
  slow_flow 39978 12 "$out"
  sleep 3
  closed=$(grep -cE "conntrack: closed [1-9]" "$ALOG")
  vps wgft rule rm "$r" --admin "$ADMIN" >/dev/null
  wait_until 30 caught_up
  wait_until 30 test -s "$out"
  okcheck "a delete closes the deleted rule's established flow" "$(flow_ok "$out" && echo 0 || echo 1)"
  echo "INFO  flow: $(cat "$out" | tail -1)"
  # The server closes its own side of a deleted rule's flow too, so the flow ending does not show
  # that the agent closed it; the agent's log does.
  okcheck "the agent logs the deleted rule's closed flow" "$([ "$(grep -cE "conntrack: closed [1-9]" "$ALOG")" -gt "$closed" ] && echo 1 || echo 0)"
  check "the retarget was undone" "tcp-echo 0.0.0.0:25565" "$(tcp_echo 39971)"
}

check_25() {
  echo "== 25: disabling the agent removes the home DNAT and closes its flows"
  local out=$W/wgft-ak-flow25 closed
  slow_flow 39971 12 "$out"
  sleep 3
  closed=$(grep -cE "conntrack: closed [1-9]" "$ALOG")
  vps wgft agent disable home --admin "$ADMIN" >/dev/null
  wait_until 30 caught_up
  wait_until 30 test -s "$out"
  okcheck "disabling closes the agent's established flow" "$(flow_ok "$out" && echo 0 || echo 1)"
  # as in check 19, the server closes its own side too; the agent's log shows the agent closed it
  okcheck "the agent logs the disabled agent's closed flow" "$([ "$(grep -cE "conntrack: closed [1-9]" "$ALOG")" -gt "$closed" ] && echo 1 || echo 0)"
  okcheck "a disabled agent publishes no DNAT at home" "$(home_dnat_rows | grep -q . && echo 0 || echo 1)"
  vps wgft agent enable home --admin "$ADMIN" >/dev/null
  wait_until 30 caught_up
  wait_until 30 tcp_ok 39971
  check "enabling brings forwarding back" "tcp-echo" "$(tcp_echo 39971)"

  # disabled while the agent is stopped: the home side keeps the old DNAT and the flow's conntrack
  # entry until the agent restarts, reconnects and learns of it
  slow_flow 39971 20 "$out"
  sleep 3
  stop_agent
  vps wgft agent disable home --admin "$ADMIN" >/dev/null
  sleep 2
  okcheck "while stopped, the home DNAT is still there" "$(home_dnat_rows | grep -q . && echo 1 || echo 0)"
  okcheck "while stopped, the home conntrack still holds the flow" "$([ "$(home_flows 39971)" -gt 0 ] && echo 1 || echo 0)"
  start_agent
  wait_until 60 caught_up
  wait_until 30 home_no_dnat
  okcheck "after the restart, the home DNAT is gone" "$(home_no_dnat && echo 1 || echo 0)"
  okcheck "after the restart, the flow's home conntrack entry is gone" "$([ "$(home_flows 39971)" = 0 ] && echo 1 || echo 0)"
  vps wgft agent enable home --admin "$ADMIN" >/dev/null
  wait_until 30 caught_up
  wait_until 30 tcp_ok 39971
  check "enabling brings forwarding back after the restart" "tcp-echo" "$(tcp_echo 39971)"
}
home_dnat_rows() { home nft list chain inet wgft_agent nat_pre | grep dnat; }
home_no_dnat() { ! home_dnat_rows | grep -q .; }
home_flows() { home conntrack -L -p tcp --dport "$1" 2>/dev/null | grep -c . ; }
# set_target <rule-id> <new-target>: changes one rule's target via export and `rule import`, since
# `rule set` only touches the group and the note.
set_target() {
  local f=$W/wgft-ak-settarget.json
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d['rules']:
    if r['id'] == '$1':
        r['target'] = '$2'
json.dump(d['rules'], open('$f', 'w'))
"
  vps wgft rule import "$f" --admin "$ADMIN" >/dev/null
}

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
    16|17|18|19|22|24|25|resolve|drift|session|route|teardown) "check_$c" ;;
    *) echo "FAIL  unknown check $c"; fail=1 ;;
  esac
done

echo "== agent kernel mode: cleanup"
cleanup
if [ "$fail" = 0 ]; then echo "== agent kernel mode: ALL PASS"; else echo "== agent kernel mode: FAILURES"; fi
exit "$fail"
