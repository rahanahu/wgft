#!/usr/bin/env bash
# agentdoctor.sh runs `wgft agent doctor` against a kernel-mode agent inside the lab VM (design
# section 10.2c, the part on the kernel-mode agent) and prints PASS/FAIL per check. The server runs in
# the vps namespace in the given mode; the agent runs in the home namespace with WGFT_MODE=kernel as
# the unprivileged user wgftlab holding only an ambient CAP_NET_ADMIN, the way a systemd unit with
# AmbientCapabilities=CAP_NET_ADMIN would run it.
#
#   lab/lab exec vm bash /wgft/lab/agentdoctor.sh kernel      # server in kernel mode (the default)
#   lab/lab exec vm bash /wgft/lab/agentdoctor.sh userspace   # server in userspace mode
#
# The doctor runs as three principals: root, wgftlab through runuser, which carries no capability,
# and wgftlab with an ambient CAP_NET_ADMIN through setpriv.
#
# Checks, in order:
#   running    the running agent reports its kernel state itself: the user without capabilities gets
#              exit 0 with interface, table and forwarding OK, and the relay items NOT TESTED; root
#              gets running_as_root with the agent's uid and user named.
#   rules      a loopback target makes table FAILED with listener_error, and server doctor names the
#              rule's reason target_loopback_unsupported.
#   disabled   an agent the server disabled reads SKIPPED agent_disabled on the three items.
#   hints      another table's forward policy drop reads forward_policy_drop, and a policy rule that
#              sends the server's tunnel address to another table reads route_not_via_interface.
#   stopped    with the agent stopped, forwarding goes on and root gets exit 0 with process FAILED and
#              table UNKNOWN agent_not_running; the user without capabilities gets exit 2 with
#              needs_cap_net_admin; the user with CAP_NET_ADMIN gets exit 0 like root.
#   broken     with the agent stopped, a row added to nat_pre makes table UNKNOWN table_changed and
#              is counted once; filter_pre's and forward's drop moved to the top read table_changed,
#              not missing, while forwarding stops; filter_pre's established accept moved to the end
#              is the only row named as moved; input's drop deleted with an accept added to
#              filter_pre does not claim that filter_pre's drop still closes the host, which the
#              tunnel then reaches; a deleted guard row, filter_pre's drop, makes table UNKNOWN
#              guard_rows_missing with exit 0 while forwarding goes on; a deleted masquerade makes it
#              FAILED table_rows_missing with exit 1 while forwarding to the LAN stops; a deleted DNAT
#              row makes table FAILED with table_rows_missing
#              and exit 1, ip_forward 0 makes forwarding FAILED with ip_forward_off, and a down or
#              missing wgft0 fails interface even for the user without capabilities; another owner's
#              down WireGuard wgft0, keyless or with another key, is interface_not_ours for root, not
#              interface_down; a restart
#              repairs all of it.
#   userspace  a userspace-mode agent reads the three items NOT TESTED with userspace_mode and its
#              listeners OK. With AGENTDOCTOR_BASELINE set to an older wgft binary, the ids, states and
#              reasons that binary reports for the same agent, running and stopped, must be unchanged.
#
# Requires `lab/lab build` and the netns topology (`lab/lab net up`). Leftovers of earlier runs are
# removed first.
set -u
. "$(dirname "$0")/sandbox.sh"
MODE=${1:-kernel}
DATA=$W/wgft-ad-server
ADATA=$W/wgft-ad-agent
UDATA=$W/wgft-ad-agent-us
SLOG=$W/wgft-ad-server.log
ALOG=$W/wgft-ad-agent.log
ULOG=$W/wgft-ad-agent-us.log
ELOG=$W/wgft-ad-echo.log
ADMIN=127.0.0.1:8686
USER_NAME=wgftlab
fail=0

check() { # check <label> <expected-substring> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
not_forwarded() { # not_forwarded <label> <forbidden-substring> <actual>
  if [[ "$3" == *"$2"* ]]; then echo "FAIL  $1: got '$3'"; fail=1; else echo "PASS  $1"; fi
}
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

# the ambient CAP_NET_ADMIN the agent runs with, and the one principal of the doctor that has it
WITH_CAP="setpriv --reuid=$USER_NAME --regid=$USER_NAME --init-groups --inh-caps=+net_admin --ambient-caps=+net_admin"

agent_pids() { # agent_pids <data dir>
  local p
  for p in $(ip netns pids "$HOME_NS" 2>/dev/null); do
    [ "$(cat "/proc/$p/comm" 2>/dev/null)" = wgft ] || continue
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q -- "--data-dir $1" && echo "$p"
  done
}
agent_up() { [ -n "$(agent_pids "$1")" ]; }
agent_down() { [ -z "$(agent_pids "$1")" ]; }
start_kernel_agent() {
  WGFT_MODE=kernel WGFT_JOIN="${JOIN:-}" home setsid nohup $WITH_CAP wgft agent run --data-dir "$ADATA" >> "$ALOG" 2>&1 < /dev/null &
  disown
  wait_until 20 agent_up "$ADATA"
}
stop_agent() { # stop_agent <data dir>
  local p
  for p in $(agent_pids "$1"); do kill "$p"; done
  wait_until 20 agent_down "$1"
}

# doctor <principal> <data dir>: runs agent doctor --json and prints "exit=N" and one line per check:
# "<id> <status> <reason> [unreachable]", then "detail <id>: <detail>" for every check.
doctor() {
  local who=$1 dir=$2 out code pre
  case "$who" in
    root) pre="" ;;
    user) pre="runuser -u $USER_NAME --" ;;
    usercap) pre=$WITH_CAP ;;
    *) pre="$who" ;;
  esac
  out=$(home $pre ${DOCTOR_BIN:-wgft} agent doctor --data-dir "$dir" --json 2>/dev/null)
  code=$?
  echo "exit=$code"
  printf '%s' "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
for c in d["checks"]:
    print(c["id"], c["status"], c.get("reason", "-"), "unreachable" if c.get("evidence_unreachable") else "")
for c in d["checks"]:
    print("detail %s: %s" % (c["id"], c["detail"]))
'
}
# answers <data dir>: the running agent answers doctor on its control socket. A restarted agent
# applies its saved state and forwards again before it opens the socket, and the server's generation
# is caught up from before the restart, so a doctor right after the restart can find no socket yet.
answers() { [[ "$(doctor user "$1")" == *"agent.control ok"* ]]; }
line() { printf '%s\n' "$1" | grep -E "^$2 " | head -1; } # line <doctor output> <id>

gen_server() { vps wgft rule ls --admin "$ADMIN" --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["generation"])'; }
agent_gen() { # agent_gen <name>
  vps wgft agent ls --admin "$ADMIN" --json | python3 -c "
import json, sys
a = next((x for x in json.load(sys.stdin) if x.get('name') == '$1'), {})
print(a.get('generation', ''))
"
}
registered() { vps wgft agent ls --admin "$ADMIN" --json | python3 -c "
import json, sys
sys.exit(0 if any(x.get('name') == '$1' for x in json.load(sys.stdin)) else 1)
"; }
caught_up() { [ "$(agent_gen "${1:-home}")" = "$(gen_server)" ]; }
add_rule() { vps wgft rule add --agent "${AGENT:-home}" "$@" --admin "$ADMIN" | grep -oE 'r_[A-Z0-9]+'; }
tcp_echo() { client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:$1 2>&1"; }

cleanup() {
  sandbox_kill_named wgft echo python3
  sleep 1
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  home ip link del wgft0 2>/dev/null
  home nft delete table inet wgft_agent 2>/dev/null
  home nft delete table inet otherfw 2>/dev/null
  home ip rule del to 10.200.0.1/32 lookup 52 priority 5270 2>/dev/null
  home ip route flush table 52 2>/dev/null
  home sysctl -qw net.ipv4.ip_forward=1
  rm -rf "$DATA" "$ADATA" "$UDATA"
}

echo "== agent doctor, server in $MODE mode: setup"
cleanup
id "$USER_NAME" >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin "$USER_NAME"
mkdir -p "$DATA" "$ADATA" "$UDATA"
chown "$USER_NAME:$USER_NAME" "$ADATA" "$UDATA"
: > "$ALOG"; : > "$ULOG"
run_server="wgft server run"
if [ "$MODE" = userspace ]; then
  chown "$USER_NAME" "$DATA"
  run_server="runuser -u $USER_NAME -- wgft server run"
fi
vps setsid nohup $run_server --mode "$MODE" --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
  > "$SLOG" 2>&1 < /dev/null &
disown
wait_until 30 vps wgft agent ls --admin "$ADMIN" || echo "!! the server did not come up"
lan setsid nohup echo -tcp 25565 -udp 19132 > "$ELOG" 2>&1 < /dev/null &
disown
# a service on the agent host that no rule publishes; the guard rows keep the tunnel from it
home setsid nohup python3 -c '
import socket
ls = socket.socket(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("0.0.0.0", 5555)); ls.listen(8)
while True:
    c, _ = ls.accept(); c.sendall(b"private-service\n"); c.close()
' > /dev/null 2>&1 < /dev/null &
disown
JOIN=$(vps wgft agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
start_kernel_agent || echo "!! the agent did not start"
wait_until 30 registered home || echo "!! the agent did not register"
wait_until 30 answers "$ADATA" || echo "!! the agent does not answer doctor"
JOIN=
R_TCP=$(add_rule --tcp 39971 --to 192.168.50.3:25565)
R_UDP=$(add_rule --udp 27015 --to 192.168.50.3:19132)
wait_until 30 caught_up || echo "!! the agent did not catch up"
wait_until 20 bash -c "[[ \"\$(echo hi | ip netns exec $CLIENT_NS timeout -k 2 5 socat -t 2 -T 3 - TCP:198.51.100.1:39971 2>&1)\" == *tcp-echo* ]]"

echo "== running"
out=$(doctor user "$ADATA")
check "user without capabilities: exit 0" "exit=0" "$out"
check "interface OK" "dataplane.interface ok" "$(line "$out" dataplane.interface)"
check "table OK" "dataplane.table ok" "$(line "$out" dataplane.table)"
check "forwarding OK" "host.forwarding ok" "$(line "$out" host.forwarding)"
check "listeners NOT TESTED" "relay.listeners not_tested kernel_mode" "$(line "$out" relay.listeners)"
check "watchdog NOT TESTED" "tunnel.watchdog not_tested kernel_mode" "$(line "$out" tunnel.watchdog)"
check "allowlist still read" "relay.allow_targets ok" "$(line "$out" relay.allow_targets)"
check "privileges name the agent's CAP_NET_ADMIN" "the running agent holds CAP_NET_ADMIN" "$(line "$out" "detail host.privileges:")"
check "table lists each rule's DNAT" "DNAT on 1 of 1 port" "$(line "$out" "detail dataplane.table:")"
check "the route goes through wgft0" "goes through wgft0" "$(line "$out" "detail dataplane.interface:")"
out=$(doctor root "$ADATA")
check "root: exit 0" "exit=0" "$out"
check "root: running_as_root" "host.privileges unknown running_as_root" "$(line "$out" host.privileges)"
check "root: the agent's uid and user are named" "the running agent runs as uid $(id -u "$USER_NAME"), $USER_NAME and holds CAP_NET_ADMIN" \
  "$(line "$out" "detail host.privileges:")"

echo "INFO  the report of the running agent for $USER_NAME:"
home runuser -u "$USER_NAME" -- wgft agent doctor --data-dir "$ADATA" | sed 's/^/INFO  | /'
echo "== rules"
R_LO=$(add_rule --tcp 39975 --to 127.0.0.1:25565)
wait_until 30 caught_up
out=$(doctor user "$ADATA")
check "a loopback target: exit 1" "exit=1" "$out"
check "a loopback target fails the table" "dataplane.table failed listener_error" "$(line "$out" dataplane.table)"
check "the rule line says why" "DNAT on 0 of 1 port, target 127.0.0.1 is a loopback address" "$(line "$out" "detail dataplane.table:")"
sdoc=$(vps wgft server doctor "$R_LO" --admin "$ADMIN" --json 2>/dev/null | python3 -c '
import json, sys
d = json.load(sys.stdin)
print(" ".join(c["id"] + "=" + c.get("reason", "") for c in d["checks"] if c["id"] == "rule.target"))
')
check "server doctor names target_loopback_unsupported" "rule.target=target_loopback_unsupported" "$sdoc"
vps wgft rule rm "$R_LO" --admin "$ADMIN" >/dev/null
wait_until 30 caught_up

echo "== disabled"
vps wgft agent disable home --admin "$ADMIN" >/dev/null
wait_until 30 caught_up
out=$(doctor user "$ADATA")
check "disabled: interface SKIPPED" "dataplane.interface skipped agent_disabled" "$(line "$out" dataplane.interface)"
check "disabled: table SKIPPED" "dataplane.table skipped agent_disabled" "$(line "$out" dataplane.table)"
check "disabled: forwarding SKIPPED" "host.forwarding skipped agent_disabled" "$(line "$out" host.forwarding)"
check "disabled: exit 0" "exit=0" "$out"
vps wgft agent enable home --admin "$ADMIN" >/dev/null
wait_until 30 caught_up

echo "== hints"
home nft -f - <<'NFT'
table inet otherfw {
  chain forward_drop {
    type filter hook forward priority 0; policy drop;
  }
}
NFT
out=$(doctor user "$ADATA")
check "another table's drop policy is named" "host.forwarding unknown forward_policy_drop" "$(line "$out" host.forwarding)"
check "and where it is" "otherfw" "$(line "$out" "detail host.forwarding:")"
home nft delete table inet otherfw
home ip route add 10.200.0.1/32 dev lo table 52
home ip rule add to 10.200.0.1/32 lookup 52 priority 5270
out=$(doctor user "$ADATA")
check "a policy route away from wgft0 is named" "dataplane.interface unknown route_not_via_interface" "$(line "$out" dataplane.interface)"
check "and the interface it takes" "goes through lo" "$(line "$out" "detail dataplane.interface:")"
home ip rule del to 10.200.0.1/32 lookup 52 priority 5270
home ip route flush table 52

echo "== stopped"
stop_agent "$ADATA"
okcheck "the agent stopped" "$(agent_down "$ADATA" && echo 1 || echo 0)"
check "forwarding goes on while the agent is stopped" "tcp-echo" "$(tcp_echo 39971)"
out=$(doctor root "$ADATA")
check "root, stopped: exit 0" "exit=0" "$out"
check "root, stopped: process FAILED" "agent.process failed agent_not_running" "$(line "$out" agent.process)"
check "root, stopped: the process line says the kernel may forward" "may still be forwarding" "$(line "$out" "detail agent.process:")"
check "root, stopped: interface OK" "dataplane.interface ok" "$(line "$out" dataplane.interface)"
check "root, stopped: table UNKNOWN" "dataplane.table unknown agent_not_running" "$(line "$out" dataplane.table)"
check "root, stopped: forwarding OK" "host.forwarding ok" "$(line "$out" host.forwarding)"
check "root, stopped: listeners NOT TESTED" "relay.listeners not_tested kernel_mode" "$(line "$out" relay.listeners)"
out=$(doctor user "$ADATA")
check "user, stopped: exit 2" "exit=2" "$out"
check "user, stopped: interface needs CAP_NET_ADMIN" "dataplane.interface unknown needs_cap_net_admin unreachable" "$(line "$out" dataplane.interface)"
check "user, stopped: table needs CAP_NET_ADMIN" "dataplane.table unknown needs_cap_net_admin unreachable" "$(line "$out" dataplane.table)"
check "user, stopped: forwarding needs CAP_NET_ADMIN" "host.forwarding unknown needs_cap_net_admin unreachable" "$(line "$out" host.forwarding)"
check "user, stopped: the route is still read" "goes through wgft0" "$(line "$out" "detail dataplane.interface:")"
echo "INFO  the report of the stopped agent for root:"
home wgft agent doctor --data-dir "$ADATA" | sed 's/^/INFO  | /'
out=$(doctor usercap "$ADATA")
check "user with CAP_NET_ADMIN, stopped: exit 0" "exit=0" "$out"
check "user with CAP_NET_ADMIN, stopped: table UNKNOWN" "dataplane.table unknown agent_not_running" "$(line "$out" dataplane.table)"

echo "== broken"
home nft add rule inet wgft_agent nat_pre tcp dport 40999 accept
out=$(doctor root "$ADATA")
check "an added nat_pre row: table UNKNOWN" "dataplane.table unknown table_changed" "$(line "$out" dataplane.table)"
check "and counted once" "The table also has 1 item wgft does not write:" "$(line "$out" "detail dataplane.table:")"
h=$(home nft -a list chain inet wgft_agent nat_pre | grep 'dport 40999' | grep -oE 'handle [0-9]+' | awk '{print $2}')
home nft delete rule inet wgft_agent nat_pre handle "$h"
# a drop row moved to the top of its chain is not missing: the change is one whose effect is not
# known, so the table reads table_changed and never says forwarding may still work
move_drop_to_top() { # move_drop_to_top <chain> <nft match>: delete the row, insert it again first
  local h
  h=$(home nft -a list chain inet wgft_agent "$1" | grep -E "^\s*$2 drop # handle" | grep -oE 'handle [0-9]+' | awk '{print $2}')
  home nft delete rule inet wgft_agent "$1" handle "$h"
  home nft insert rule inet wgft_agent "$1" $2 drop
}
put_drop_back() { # put_drop_back <chain> <nft match> [<nft match of the next row>]: back where wgft writes it
  local h next
  h=$(home nft -a list chain inet wgft_agent "$1" | grep -E "^\s*$2 drop # handle" | grep -oE 'handle [0-9]+' | awk '{print $2}')
  home nft delete rule inet wgft_agent "$1" handle "$h"
  if [ -n "${3:-}" ]; then
    next=$(home nft -a list chain inet wgft_agent "$1" | grep -E "^\s*$3 drop # handle" | grep -oE 'handle [0-9]+' | awk '{print $2}')
    home nft insert rule inet wgft_agent "$1" position "$next" $2 drop
  else
    home nft add rule inet wgft_agent "$1" $2 drop
  fi
}
for moved in "filter_pre|iifname \"wgft0\"|" "forward|iifname \"wgft0\"|oifname \"wgft0\""; do
  IFS='|' read -r chain match next <<< "$moved"
  move_drop_to_top "$chain" "$match"
  out=$(doctor root "$ADATA")
  check "$chain drop moved to the top: exit 0" "exit=0" "$out"
  check "$chain drop moved to the top: table UNKNOWN table_changed" "dataplane.table unknown table_changed" "$(line "$out" dataplane.table)"
  check "$chain drop moved to the top: named as moved" "in another position" "$(line "$out" "detail dataplane.table:")"
  not_forwarded "$chain drop moved to the top: no claim that forwarding may work" "may still work" "$(line "$out" "detail dataplane.table:")"
  not_forwarded "$chain drop moved to the top: forwarding stops" "tcp-echo" "$(tcp_echo 39971)"
  put_drop_back "$chain" "$match" "$next"
  out=$(doctor root "$ADATA")
  check "$chain drop back in place: table UNKNOWN agent_not_running" "dataplane.table unknown agent_not_running" "$(line "$out" dataplane.table)"
done
# one row moved to the end: only that row is named, not the rows that stayed in order
h=$(home nft -a list chain inet wgft_agent filter_pre | grep 'ct state established,related accept' | grep -oE 'handle [0-9]+' | awk '{print $2}')
home nft delete rule inet wgft_agent filter_pre handle "$h"
home nft add rule inet wgft_agent filter_pre iifname wgft0 ct state established,related accept
out=$(doctor root "$ADATA")
check "a row moved to the end: table UNKNOWN table_changed" "dataplane.table unknown table_changed" "$(line "$out" dataplane.table)"
check "a row moved to the end: only that row is named" "has 1 row that wgft writes in another position: filter_pre: accept established" "$(line "$out" "detail dataplane.table:")"
h=$(home nft -a list chain inet wgft_agent filter_pre | grep 'ct state established,related accept' | grep -oE 'handle [0-9]+' | awk '{print $2}')
home nft delete rule inet wgft_agent filter_pre handle "$h"
first=$(home nft -a list chain inet wgft_agent filter_pre | grep iifname | head -1 | grep -oE 'handle [0-9]+' | awk '{print $2}')
home nft insert rule inet wgft_agent filter_pre position "$first" iifname wgft0 ct state established,related accept
out=$(doctor root "$ADATA")
check "the row back in place: table UNKNOWN agent_not_running" "dataplane.table unknown agent_not_running" "$(line "$out" dataplane.table)"
# input's drop deleted and an accept added at the top of filter_pre: the added row passes packets
# before filter_pre's drop, so the finding must not say that the drop still closes the host ports
h=$(home nft -a list chain inet wgft_agent input | grep -E '^\s*iifname "wgft0" drop' | grep -oE 'handle [0-9]+' | awk '{print $2}')
home nft delete rule inet wgft_agent input handle "$h"
home nft insert rule inet wgft_agent filter_pre iifname wgft0 accept
out=$(doctor root "$ADATA")
check "a missing input drop and an added accept: table UNKNOWN guard_rows_missing" "dataplane.table unknown guard_rows_missing" "$(line "$out" dataplane.table)"
check "and names the added row" "1 item wgft does not write" "$(line "$out" "detail dataplane.table:")"
not_forwarded "and does not say a drop still closes the host" "still keeps" "$(line "$out" "detail dataplane.table:")"
# a userspace-mode server carries the tunnel in its own netstack, so the vps namespace has no route
# into it; the reach checks need a kernel-mode server
if [ "$MODE" = kernel ]; then
  check "a host port is reached from the tunnel" "private-service" "$(vps timeout -k 2 6 socat -T 3 - TCP:10.200.0.2:5555,connect-timeout=3 2>&1)"
else
  echo "SKIP  a host port is reached from the tunnel: the vps namespace has no route into a userspace-mode server's tunnel"
fi
h=$(home nft -a list chain inet wgft_agent filter_pre | grep -E '^\s*iifname "wgft0" accept # handle' | grep -oE 'handle [0-9]+' | awk '{print $2}')
home nft delete rule inet wgft_agent filter_pre handle "$h"
home nft add rule inet wgft_agent input iifname wgft0 drop
out=$(doctor root "$ADATA")
check "input drop back and the accept gone: table UNKNOWN agent_not_running" "dataplane.table unknown agent_not_running" "$(line "$out" dataplane.table)"
if [ "$MODE" = kernel ]; then
  not_forwarded "the host port is closed again" "private-service" "$(vps timeout -k 2 6 socat -T 3 - TCP:10.200.0.2:5555,connect-timeout=3 2>&1)"
fi
# a guard row: forwarding goes on without it, so the table is UNKNOWN and the exit code stays 0
h=$(home nft -a list chain inet wgft_agent filter_pre | grep -E 'iifname "wgft0" drop' | grep -oE 'handle [0-9]+' | awk '{print $2}')
home nft delete rule inet wgft_agent filter_pre handle "$h"
out=$(doctor root "$ADATA")
check "a deleted guard row: exit 0" "exit=0" "$out"
check "a deleted guard row: table UNKNOWN" "dataplane.table unknown guard_rows_missing" "$(line "$out" dataplane.table)"
check "and names the row" "filter_pre: drop the rest from wgft0" "$(line "$out" "detail dataplane.table:")"
check "and says what it opens" "traffic from the tunnel may reach other tables' DNAT" "$(line "$out" "detail dataplane.table:")"
check "and what the remaining rows still close" "The drop row in input still keeps the tunnel from ports on this host" "$(line "$out" "detail dataplane.table:")"
not_forwarded "and does not claim host ports open" "may reach ports on this host" "$(line "$out" "detail dataplane.table:")"
check "forwarding goes on without the guard row" "tcp-echo" "$(tcp_echo 39971)"
# a forwarding row: without the masquerade a LAN target is not reached, so the table fails
h=$(home nft -a list chain inet wgft_agent postrouting | grep masquerade | grep -oE 'handle [0-9]+' | awk '{print $2}')
home nft delete rule inet wgft_agent postrouting handle "$h"
out=$(doctor root "$ADATA")
check "a deleted masquerade: exit 1" "exit=1" "$out"
check "a deleted masquerade fails the table" "dataplane.table failed table_rows_missing" "$(line "$out" dataplane.table)"
check "and still names the guard row" "guard rows of table inet wgft_agent are missing" "$(line "$out" "detail dataplane.table:")"
not_forwarded "forwarding to the LAN stops without the masquerade" "tcp-echo" "$(tcp_echo 39971)"
h=$(home nft -a list chain inet wgft_agent nat_pre | grep 'dport 39971' | grep -oE 'handle [0-9]+' | awk '{print $2}')
home nft delete rule inet wgft_agent nat_pre handle "$h"
out=$(doctor root "$ADATA")
check "a deleted DNAT row: exit 1" "exit=1" "$out"
check "a deleted DNAT row fails the table" "dataplane.table failed table_rows_missing" "$(line "$out" dataplane.table)"
# the row and its DNAT are one item; the masquerade deleted earlier is the other
check "and counts the row once" "lacks 2 items that forwarding needs" "$(line "$out" "detail dataplane.table:")"
not_forwarded "and does not count its DNAT again" "; DNAT tcp 39971" "$(line "$out" "detail dataplane.table:")"
check "and names the rule" "$R_TCP" "$(line "$out" "detail dataplane.table:")"
home sysctl -qw net.ipv4.ip_forward=0
out=$(doctor usercap "$ADATA")
check "ip_forward 0 fails forwarding" "host.forwarding failed ip_forward_off" "$(line "$out" host.forwarding)"
out=$(doctor user "$ADATA")
check "ip_forward 0 is read without CAP_NET_ADMIN" "host.forwarding failed ip_forward_off" "$(line "$out" host.forwarding)"
home sysctl -qw net.ipv4.ip_forward=1
home ip link set wgft0 down
out=$(doctor user "$ADATA")
check "a down wgft0 is read without CAP_NET_ADMIN" "dataplane.interface failed interface_down" "$(line "$out" dataplane.interface)"
home ip link del wgft0
out=$(doctor user "$ADATA")
check "a missing wgft0 is read without CAP_NET_ADMIN" "dataplane.interface failed interface_missing" "$(line "$out" dataplane.interface)"
# another owner's WireGuard link, down, under the name: keyless, then with another key. Ownership
# comes before down, since the agent refuses to start over it rather than setting it up
home ip link add wgft0 type wireguard
out=$(doctor root "$ADATA")
check "a keyless down wgft0 is not ours" "dataplane.interface failed interface_not_ours" "$(line "$out" dataplane.interface)"
check "and says it holds no key" "holds no key" "$(line "$out" "detail dataplane.interface:")"
out=$(doctor user "$ADATA")
check "without CAP_NET_ADMIN it is down, key unread" "dataplane.interface failed interface_down" "$(line "$out" dataplane.interface)"
check "and says the key was not read" "whether it holds this agent's key could not be read" "$(line "$out" "detail dataplane.interface:")"
home bash -c 'wg genkey > /tmp/k9-other.key; wg set wgft0 private-key /tmp/k9-other.key; rm -f /tmp/k9-other.key'
out=$(doctor root "$ADATA")
check "another key's down wgft0 is not ours" "dataplane.interface failed interface_not_ours" "$(line "$out" dataplane.interface)"
check "and says it holds another key" "holds another key" "$(line "$out" "detail dataplane.interface:")"
home ip link del wgft0
start_kernel_agent
wait_until 30 caught_up
wait_until 30 answers "$ADATA" || echo "!! the restarted agent does not answer doctor"
wait_until 30 bash -c "[[ \"\$(echo hi | ip netns exec $CLIENT_NS timeout -k 2 5 socat -t 2 -T 3 - TCP:198.51.100.1:39971 2>&1)\" == *tcp-echo* ]]"
out=$(doctor user "$ADATA")
check "after the restart: exit 0" "exit=0" "$out"
check "after the restart: table OK" "dataplane.table ok" "$(line "$out" dataplane.table)"
stop_agent "$ADATA"
home ip link del wgft0 2>/dev/null
home nft delete table inet wgft_agent 2>/dev/null

echo "== userspace"
JOIN=$(vps wgft agent join-string --name home-us --admin "$ADMIN" 2>/dev/null | head -1)
WGFT_JOIN="$JOIN" home setsid nohup runuser -u "$USER_NAME" -- wgft agent run --data-dir "$UDATA" >> "$ULOG" 2>&1 < /dev/null &
disown
wait_until 20 agent_up "$UDATA"
wait_until 30 registered home-us || echo "!! the userspace agent did not register"
wait_until 30 answers "$UDATA" || echo "!! the userspace agent does not answer doctor"
AGENT=home-us add_rule --tcp 39981 --to 192.168.50.3:25565 >/dev/null
wait_until 30 caught_up home-us
wait_until 30 bash -c "[[ \"\$(echo hi | ip netns exec $CLIENT_NS timeout -k 2 5 socat -t 2 -T 3 - TCP:198.51.100.1:39981 2>&1)\" == *tcp-echo* ]]"
out=$(doctor user "$UDATA")
check "userspace: exit 0" "exit=0" "$out"
check "userspace: interface NOT TESTED" "dataplane.interface not_tested userspace_mode" "$(line "$out" dataplane.interface)"
check "userspace: table NOT TESTED" "dataplane.table not_tested userspace_mode" "$(line "$out" dataplane.table)"
check "userspace: forwarding NOT TESTED" "host.forwarding not_tested userspace_mode" "$(line "$out" host.forwarding)"
check "userspace: listeners OK" "relay.listeners ok" "$(line "$out" relay.listeners)"
baseline_compare() { # baseline_compare <label>
  local now old
  now=$(doctor user "$UDATA" | grep -vE '^(detail |dataplane\.|host\.forwarding )' | grep -v '^exit=')
  old=$(DOCTOR_BIN=$AGENTDOCTOR_BASELINE doctor user "$UDATA" | grep -v '^detail ' | grep -v '^exit=')
  if [ "$now" = "$old" ]; then echo "PASS  userspace, $1: the same ids, states and reasons as the baseline"
  else echo "FAIL  userspace, $1: differs from the baseline"; diff <(echo "$old") <(echo "$now"); fail=1; fi
}
if [ -n "${AGENTDOCTOR_BASELINE:-}" ]; then baseline_compare running; fi
stop_agent "$UDATA"
out=$(doctor user "$UDATA")
check "userspace, stopped: exit 1, as before" "exit=1" "$out"
check "userspace, stopped: process FAILED" "agent.process failed agent_not_running" "$(line "$out" agent.process)"
if [ -n "${AGENTDOCTOR_BASELINE:-}" ]; then baseline_compare stopped; else echo "SKIP  userspace baseline: AGENTDOCTOR_BASELINE is not set"; fi

echo "== agent doctor: cleanup"
cleanup
if [ "$fail" = 0 ]; then echo "== agent doctor, server in $MODE mode: ALL PASS"; else echo "== agent doctor, server in $MODE mode: FAILURES"; fi
exit "$fail"
