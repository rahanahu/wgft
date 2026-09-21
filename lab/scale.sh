#!/usr/bin/env bash
# scale.sh is C3, the scale check (docs/testing.md): one server, several agents in the sandbox's
# home namespace, and a ladder of rule counts, added both as one `rule import` batch (one
# generation) and one `rule add` at a time (one generation per rule). It measures, and PRINTS as
# findings (not assertions: design makes no scale promise, and the expected use is a handful of
# rules at home):
#   - wall-clock time from the mutating CLI call to every rule reporting apply_state active
#     (polled through `rule ls --json`, design's own convergence signal, never a fixed sleep);
#   - the byte size of the full-state message an agent is served (GET /api/v1/agents/{name}/state,
#     the cheapest honest measure: it is exactly the JSON design 5.2 節 says vpsd pushes over the
#     stream, and proto/state.go's AgentRule/State show it holds one entry per rule of that agent,
#     not one entry per port, so a wide port range should cost the same as a single port; this
#     check is what tells us whether that holds under an actual apply);
#   - kernel mode: the line count of `nft list table inet wgft` (a proxy for table size) and how
#     long that same list takes to run (a proxy for table size, not for the netlink replace
#     transaction itself: internal/dataplane/linuxkernel/nft talks to the kernel through the
#     google/nftables library directly, never `nft -f`, and logs no elapsed time for the replace,
#     so the replace's own duration is folded into the apply-time figure above and is not isolated
#     here; see docs/testing.md's C3 entry and the report this scenario's PR carries);
#   - server and agent RSS, and a loose leak check that deleting every rule returns RSS, the nft
#     table and the dashboard's own page size to about where they started;
#   - that forwarding still works, with a real TCP and a real UDP probe, through the FIRST rule
#     (always TCP, always the same port) and the LAST rule (always UDP, the ladder's top port) of
#     whatever rule set the current step just converged to.
#
# What this checks for CORRECTNESS, not as a printed finding: every rule in a step reaches
# apply_state active; a batch import advances the generation by exactly one regardless of how many
# rules it carries; N one-by-one `rule add` calls advance it by exactly N; forwarding through the
# first and last rule after each step; an oversized batch (past the admin API's 1 MiB request cap,
# internal/vpsd/admin/admin.go's postBatch) is refused atomically, leaving zero rules, not a
# partial apply; and that cleanup leaves no rule, no leftover nft line (kernel mode) and no
# leftover process.
#
# Both ladders cut short once a rung stops converging, and then skip every larger rung FOR THAT
# METHOD ONLY: the rung that failed is evidence a larger one would only take as long or longer, not
# new information (the wall-clock timing rule of docs/testing.md, this script's own variant of it:
# budgets below are bounds on how long we wait, not speed claims). The one-by-one ladder cuts short
# on its own per-rung ONEBYONE_BUDGET timing out; the rules actually added are left in place and
# checked as far as they got. The batch ladder cuts short the first time a `rule import` fails to
# converge within BATCH_APPLY_BUDGET -- this DOES happen on this lab VM, at kernel mode's netlink
# wall (see LADDER below), even though one `rule import` call replaces the whole set in a single
# apply regardless of how many rules the file carries; that non-convergence is itself the finding,
# and repeating it at every larger rung would only re-spend the budget, not learn anything new.
#
#   lab/lab exec vm bash /wgft/lab/scale.sh kernel
#   lab/lab exec vm bash /wgft/lab/scale.sh userspace
# Requires `lab/lab build` and the netns topology (`lab/lab up` / `lab/lab net up`).
set -u
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: scale.sh kernel|userspace" >&2; exit 2;; esac

. "$(dirname "$0")/sandbox.sh"   # sandbox: netns names, workdir, process scope
ADMIN=127.0.0.1:8686
DATA=$W/wgft-scale-server
fail=0

# --- configuration -----------------------------------------------------------------------------
# Several agents in one home namespace: the agent's own WireGuard socket
# (internal/dataplane/userspace/tunnel/tunnel.go's conn.NewDefaultBind, no listen_port set) binds
# an ephemeral local UDP port, and every listener it opens for a rule is on its own netstack
# (internal/nettun), isolated per process; nothing an agent binds collides with another agent's
# bind in the same real network namespace. What actually bounds how many agents the topology can
# host is the /24 WireGuard pool (design's 10.200.0.0/24, ~253 usable addresses) and each agent
# process's own RSS, not a port collision. A first trial with N_AGENTS=8 starting at once (and
# again at 5, with only a 0.3s stagger) left some agents unregistered: their own log showed
# "Error: registration API: HTTP 429: too many attempts", traced to
# internal/vpsd/agentapi/server.go's newIPLimiter(1, 5), a per-source-IP token bucket (1/s refill,
# burst 5) shared between /register and the stream endpoint (its own comment: "stream のハンドラも
# 使う"). Every agent in this topology's one home namespace registers from the SAME NATed address
# (the homerouter's WAN side), and each agent spends two tokens (register, then its stream
# connect), so 5 agents starting within about a second can spend up to 10 tokens against a burst
# of 5 -- a real anti-abuse control doing its job, not a bug. AGENT_START_STAGGER below is picked
# so the bucket refills faster than agents consume it (5 agents x 2 tokens over the stagger below,
# against 1 token/s refill, never goes negative; the arithmetic is in the PR text). N_AGENTS is
# chosen small against the 2 GiB lab VM's own budget, not because more would collide on ports or
# addresses; this scenario does not claim to have tested more agents than this.
N_AGENTS=5
AGENT_START_STAGGER=1.5     # seconds between starting each agent process; see the rate limiter
                            # note above. Not a claim about how fast registration should be.
AGENT_REGISTER_BUDGET=45    # generous upper bound per agent (docs/testing.md's wall-clock rule)
# All rules go to agent home0, so home0's own full-state message and RSS are the ones that grow
# with the ladder (proto/state.go's AgentState filters rules by agent, design 5.2 節); home1..4
# stay registered with zero rules the whole run, showing that a push to several idle agents does
# not itself grow with the ladder.
RULE_AGENT=home0
BASE=20000                 # ladder rules occupy BASE..BASE+R-1
# A first trial with the suggested 10/100/500/1000 ladder found a hard wall in between: kernel
# mode's apply flushes the WHOLE table in one netlink SendMessages call
# (github.com/google/nftables@v0.3.0 conn.go's Flush), and on this lab VM's default socket buffer
# sizes that call starts failing somewhere around 100-200 rules. An isolated bisection by hand,
# server and one idle agent only, no other load, found 100 rules applying cleanly and the wall
# starting at 150 (reply read failing with ENOBUFS even though the write went through) and 200
# (the send itself failing with EMSGSIZE, "message too long", applying nothing). Full runs of this
# scenario (5 agents, the checks that precede the ladder) instead see the wall at R=100 itself
# (ENOBUFS), reproducibly: more netlink and admin-API traffic already in flight around the same
# socket buffers moves the wall down from the isolated bisection's number. Wherever it lands, it
# is a hard wall, not a slow path: PASS/FAIL below is the correctness signal, not a speed number.
# 150 and 200 stay in the ladder to double-check the wall from a second rung when it is reached;
# 500 and 1000 stay to be skipped, on record, by the cut-short above rather than silently absent.
LADDER="10 100 150 200 500 1000"
# RANGE_LO/HI and OVERLIMIT_BASE are chosen below 32768: a first trial placed them at 45000-49999
# and 55000+, inside this lab VM's ephemeral port range (net.ipv4.ip_local_port_range, 32768-60999
# here), and the range rule's userspace-mode listeners (each port in a range rule opens its own
# real bind, confirmed by the server log: "listener tcp/N: listen tcp4 :N: bind: address already
# in use") then intermittently collided with an ordinary outbound connection (a probe, an admin
# API call) that the kernel had handed an ephemeral source port inside that same window -- a test
# artifact from the port choice, not a scaling bug: it reproduced 2 of 3 times at 45000-49999 and
# 0 of 3 times once moved below the ephemeral range.
RANGE_LO=22000 RANGE_HI=26999      # one rule, 5000 ports, well clear of the ladder's own range
OVERLIMIT_BASE=27000 OVERLIMIT_N=4000  # a batch import expected to exceed the 1 MiB admin API cap
BATCH_APPLY_BUDGET=60       # generous upper bound, not a speed claim (docs/testing.md's wall-clock rule)
ONEBYONE_BUDGET=120         # per rung; a rung that runs past this is cut short (see header)
CONVERGE_BUDGET=10          # short poll after a step that should already be synchronous
RSS_MARGIN_SERVER_MIB=80    # leak check margins: loose on purpose, see header. A first trial found
                            # the agent's own RSS about 70 MiB above its baseline after the full
                            # ladder (many ~100 KiB full-state pushes and thousands of generations),
                            # which a 40 MiB margin flagged; lab/lifecycle.sh's own RSS checks use a
                            # 100 MiB margin for the same reason (Go's GC does not always return
                            # freed heap to the OS promptly), so the agent margin below matches that
                            # precedent rather than asserting on what looks like ordinary GC lag.
RSS_MARGIN_AGENT_MIB=100
NFT_LINE_MARGIN=2
onebyone_cut_short=0        # once a rung is cut short, every larger rung skips the one-by-one method

check() { # check <label> <expected-substring> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
eqcheck() { # eqcheck <label> <want> <got>: integer equality (check()'s substring match is wrong for
  # a bare count: "2" is a substring of "12").
  if [ "$2" -eq "$3" ] 2>/dev/null; then echo "PASS  $1"; else echo "FAIL  $1: got '$3', want '$2'"; fail=1; fi
}
okcheck() { if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fi; [ "$2" = "1" ] || fail=1; }
measure() { echo "MEASURE $*"; }  # a printed finding, not a verdict; never starts with PASS/FAIL/SKIP
  # (tools/labhost/suite.go's countVerdicts matches only those three prefixes)

# wait_until/must_wait: see lab/lifecycle.sh for the full rationale (polls a predicate against a
# wall-clock deadline tracked with $SECONDS; never itself prints PASS/FAIL so a timeout falls
# through to the caller's own, unchanged assertion).
wait_until() {
  local timeout=$1; shift
  local deadline=$((SECONDS + timeout))
  while :; do
    if "$@" >/dev/null 2>&1; then return 0; fi
    if (( SECONDS >= deadline )); then return 1; fi
    sleep 0.2
  done
}
must_wait() {
  local label=$1 timeout=$2; shift 2
  if wait_until "$timeout" "$@"; then return 0; fi
  echo "FAIL  $label: timed out after ${timeout}s"; fail=1; return 1
}

vps() { ip netns exec "$VPS_NS" "$@"; }
client() { ip netns exec "$CLIENT_NS" bash -c "$1"; }

admin_up() { vps wgft agent ls --admin "$ADMIN" >/dev/null 2>&1; }
wait_admin() { wait_until 30 admin_up || { echo "!! admin api did not come up" >&2; return 1; }; }
agent_registered() { # agent_registered <name>: registered AND its wg peer has handshaked
  vps wgft agent ls --admin "$ADMIN" --json 2>/dev/null | python3 -c "
import json, sys
try:
    agents = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
sys.exit(0 if any(a.get('name') == '$1' and a.get('last_handshake') for a in agents) else 1)
"
}
wait_agent() { wait_until "$AGENT_REGISTER_BUDGET" agent_registered "$1" || { echo "!! agent $1 did not register" >&2; return 1; }; }

# find_wgft_pid_all <substr>...: the pid of the "wgft" process (matched by comm, so a wrapping
# runuser/setsid/nohup in userspace mode is not confused with it) whose cmdline contains every
# given substring. Robust against how many forks setsid/runuser add, unlike trusting `&`'s $!.
find_wgft_pid_all() {
  local p cmd s ok
  for p in $(sandbox_wgft_pids); do
    cmd=$(tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null) || continue
    ok=1
    for s in "$@"; do case "$cmd" in *" $s"*) ;; *) ok=0; break;; esac; done
    if [ "$ok" = 1 ]; then echo "$p"; return; fi
  done
}
rss_mib() { awk '/VmRSS/{print int($2/1024)}' "/proc/$1/status" 2>/dev/null; }

none_running() { ! sandbox_any_named wgft echo socat; }
kill_all() { sandbox_kill_named wgft echo socat; must_wait "cleanup: leftover wgft/echo/socat processes gone" 10 none_running; }

tcp_probe() { client "echo hi | timeout -k 5 20 socat -t 2 -T 10 - TCP:198.51.100.1:$1" 2>/dev/null; }
udp_probe() { client "echo hi | timeout -k 5 20 socat -t 2 -T 10 - UDP:198.51.100.1:$1" 2>/dev/null; }
tcp_probe_ok() { [[ "$(tcp_probe "$1")" == *tcp-echo* ]]; }
udp_probe_ok() { [[ "$(udp_probe "$1")" == *udp-echo* ]]; }

# rule_count/all_rules_active/apply_top_field/generations_equal: the same admin-JSON reads
# lab/lifecycle.sh's helpers of the same name use, against $ADMIN.
rule_count() { vps wgft rule ls --admin "$ADMIN" --json | python3 -c 'import json, sys; print(len(json.load(sys.stdin)["rules"]))'; }
all_rules_active() { # all_rules_active <expected-count>: every rule present and apply_state active
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
rules = d.get('rules', [])
if len(rules) != $1:
    sys.exit(1)
states = d.get('rule_states', {})
for r in rules:
    if states.get(r['id'], {}).get('apply_state') != 'active':
        sys.exit(1)
sys.exit(0)
"
}
apply_top_field() {
  vps wgft rule ls --admin "$ADMIN" --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
v = d.get('$1', '')
print(v if v is not None else '')
"
}

agent_state_bytes() { vps curl -s "http://$ADMIN/api/v1/agents/$1/state" | wc -c; }
nft_lines() { vps nft list table inet wgft 2>/dev/null | wc -l; }
nft_list_ms() {
  local t0 t1
  t0=$(date +%s%3N); vps nft list table inet wgft >/dev/null 2>&1; t1=$(date +%s%3N)
  echo $((t1 - t0))
}
ui_ms() { # dashboard GET / (design 5.2 節's Web UI), time_total in ms
  local s; s=$(vps curl -s -o /dev/null -w '%{time_total}' "http://$ADMIN/" 2>/dev/null)
  awk -v s="$s" 'BEGIN{printf "%d", s*1000}'
}

reset_rules() { # replace the whole rule set with nothing (proto's own full-replace semantics)
  echo "[]" > "$W/wgft-scale-empty.json"
  vps wgft rule import "$W/wgft-scale-empty.json" --admin "$ADMIN" >/dev/null 2>&1
  wait_until 30 all_rules_active 0
}

# build_ladder_rules <R> <outfile>: R rules on RULE_AGENT, ports BASE..BASE+R-1, all TCP except
# the last (index R-1), which is UDP -- so "the first rule" is always TCP on a fixed port, and
# "the last rule" is always UDP on the ladder's top port, giving both a real TCP and a real UDP
# probe across the two ends of the list, as the check policy asks for.
build_ladder_rules() {
  local r=$1 out=$2
  python3 -c "
import json
R = $r
base = $BASE
rules = []
for i in range(R):
    p = base + i
    proto = 'udp' if i == R - 1 else 'tcp'
    rules.append({
        'id': f'r_scale{i:05d}', 'agent': '$RULE_AGENT', 'proto': proto,
        'listen_port': str(p), 'target': f'192.168.50.2:{p}',
        'vps_mode': 'kernel', 'enabled': True,
    })
json.dump(rules, open('$out', 'w'))
"
}

cleanup() { # kills before tearing down (server teardown refuses while the process is running,
  # as lab/import-export.sh's own cleanup does). Removes data dirs (so a previous run's agent
  # credentials never get reused) and generated JSON files, but leaves logs in place, like the
  # other scenarios' cleanup does, for a postmortem after a failed run.
  kill_all
  vps wgft server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  rm -rf "$DATA" "$W"/wgft-scale-*.json
  local i
  for ((i = 0; i < N_AGENTS; i++)); do rm -rf "$W/wgft-scale-agent$i"; done
}

cleanup
mkdir -p "$DATA"
echo "== $mode: start server, $N_AGENTS agents in one home namespace"
if [ "$mode" = userspace ]; then
  id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab
  chown wgftlab "$DATA"
  vps setsid nohup runuser -u wgftlab -- wgft server run --mode "$mode" --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
    > "$W/wgft-scale-server.log" 2>&1 < /dev/null &
else
  vps setsid nohup wgft server run --mode "$mode" --data-dir "$DATA" --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" \
    > "$W/wgft-scale-server.log" 2>&1 < /dev/null &
fi
disown
wait_admin || { echo "FAIL  server did not come up"; exit 1; }

for ((i = 0; i < N_AGENTS; i++)); do
  adir="$W/wgft-scale-agent$i"
  mkdir -p "$adir"
  join=$(vps wgft agent join-string --name "home$i" --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_JOIN="$join" WGFT_NAME="home$i" ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$adir" \
    > "$W/wgft-scale-agent$i.log" 2>&1 < /dev/null &
  disown
  sleep "$AGENT_START_STAGGER"
done
for ((i = 0; i < N_AGENTS; i++)); do
  wait_agent "home$i" || fail=1
done
check "all $N_AGENTS agents registered" "$N_AGENTS" "$(vps wgft agent ls --admin "$ADMIN" --json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"

home0_pid=$(find_wgft_pid_all 'agent run' "$W/wgft-scale-agent0")
server_pid=$(find_wgft_pid_all 'server run')

# One echo listener covers every port this run will ever probe: the fixed "first" port, the
# ladder's "last" port for each rung (known up front from LADDER and BASE), and the range rule's
# first/last ports. All are started once, before the ladder, and kept up throughout.
last_udp_ports=""
for r in $LADDER; do last_udp_ports="$last_udp_ports,$((BASE + r - 1))"; done
last_udp_ports=${last_udp_ports#,}
ip netns exec "$HOME_NS" setsid nohup echo -bind 192.168.50.2 -tcp "$BASE,$RANGE_LO,$RANGE_HI" -udp "$last_udp_ports" \
  > "$W/wgft-scale-echo.log" 2>&1 < /dev/null &
disown
sleep 1

echo "== baseline (0 rules) before the ladder"
base_server_rss=$(rss_mib "$server_pid")
base_agent_rss=$(rss_mib "$home0_pid")
base_nft_lines=0
[ "$mode" = kernel ] && base_nft_lines=$(nft_lines)
measure "baseline server_rss_mib=${base_server_rss:-unknown} agent_rss_mib=${base_agent_rss:-unknown} nft_lines=$base_nft_lines"

run_forwarding_checks() { # run_forwarding_checks <label> <last-port>
  local label=$1 last=$2
  okcheck "$label: forwarding through the first rule (TCP, port $BASE)" "$(tcp_probe_ok "$BASE" && echo 1 || echo 0)"
  okcheck "$label: forwarding through the last rule (UDP, port $last)" "$(udp_probe_ok "$last" && echo 1 || echo 0)"
}

echo "== batch import ladder (one \`rule import\` call per rung, one generation each)"
batch_cut_short=0  # once a rung fails to converge, every larger rung is skipped for the batch
                   # method only: a single netlink-level wall (see below) reproduces at every
                   # larger rung too, so re-spending BATCH_APPLY_BUDGET on each one only burns
                   # wall-clock time and adds no new information (the same reasoning the
                   # one-by-one ladder already uses below for its own cut-short).
for R in $LADDER; do
  if [ "$batch_cut_short" = 1 ]; then
    echo "SKIP  batch R=$R (a smaller rung already failed to converge; see the rung above)"
    continue
  fi
  reset_rules
  gen_before=$(apply_top_field desired_generation)
  RFILE="$W/wgft-scale-batch-$R.json"
  build_ladder_rules "$R" "$RFILE"
  t0=$(date +%s%3N)
  import_out=$(vps wgft rule import "$RFILE" --admin "$ADMIN" 2>&1)
  converged=1
  wait_until "$BATCH_APPLY_BUDGET" all_rules_active "$R" || converged=0
  t1=$(date +%s%3N)
  apply_ms=$((t1 - t0))
  gen_after=$(apply_top_field desired_generation)
  bytes=$(agent_state_bytes "$RULE_AGENT")
  lines=0; lms=0
  if [ "$mode" = kernel ]; then lines=$(nft_lines); lms=$(nft_list_ms); fi
  measure "batch R=$R apply_ms=$apply_ms state_bytes=$bytes nft_lines=$lines nft_list_ms=$lms ui_ms=$(ui_ms) server_rss_mib=$(rss_mib "$server_pid") agent_rss_mib=$(rss_mib "$home0_pid") cli_output=[$import_out]"
  okcheck "batch R=$R: every rule reached apply_state active within ${BATCH_APPLY_BUDGET}s" "$converged"
  eqcheck "batch R=$R: generation advanced by exactly 1" "$((gen_before + 1))" "$gen_after"
  run_forwarding_checks "batch R=$R" "$((BASE + R - 1))"
  [ "$converged" = 0 ] && batch_cut_short=1
done

echo "== one-by-one ladder (R separate \`rule add\` calls, R generations; budget ${ONEBYONE_BUDGET}s/rung)"
for R in $LADDER; do
  if [ "$onebyone_cut_short" = 1 ]; then
    echo "SKIP  one-by-one R=$R (a smaller rung already ran past the ${ONEBYONE_BUDGET}s budget; see the rung above)"
    continue
  fi
  reset_rules
  gen_before=$(apply_top_field desired_generation)
  t0=$(date +%s%3N)
  loop_deadline=$((SECONDS + ONEBYONE_BUDGET))
  added=0 addfail=0 last_add_err=""
  for ((i = 0; i < R; i++)); do
    if (( SECONDS >= loop_deadline )); then break; fi
    p=$((BASE + i))
    if (( i == R - 1 )); then
      last_add_err=$(vps wgft rule add --agent "$RULE_AGENT" --udp "$p" --to "192.168.50.2:$p" --admin "$ADMIN" 2>&1 1>/dev/null)
    else
      last_add_err=$(vps wgft rule add --agent "$RULE_AGENT" --tcp "$p" --to "192.168.50.2:$p" --admin "$ADMIN" 2>&1 1>/dev/null)
    fi
    [ -n "$last_add_err" ] && addfail=$((addfail + 1))
    added=$((added + 1))
    case $added in 10|100|500) measure "one-by-one R=$R checkpoint added=$added elapsed_ms=$(( $(date +%s%3N) - t0 ))" ;; esac
  done
  cut_short=0
  if [ "$added" -lt "$R" ]; then cut_short=1; onebyone_cut_short=1; fi
  converged=1
  wait_until "$CONVERGE_BUDGET" all_rules_active "$added" || converged=0
  t1=$(date +%s%3N)
  apply_ms=$((t1 - t0))
  gen_after=$(apply_top_field desired_generation)
  bytes=$(agent_state_bytes "$RULE_AGENT")
  lines=0; lms=0
  if [ "$mode" = kernel ]; then lines=$(nft_lines); lms=$(nft_list_ms); fi
  measure "one-by-one R=$R added=$added addfail=$addfail cut_short=$cut_short total_ms=$apply_ms state_bytes=$bytes nft_lines=$lines nft_list_ms=$lms ui_ms=$(ui_ms) server_rss_mib=$(rss_mib "$server_pid") agent_rss_mib=$(rss_mib "$home0_pid") last_add_error=[$last_add_err]"
  if [ "$cut_short" = 1 ]; then
    echo "== one-by-one R=$R stopped after $added/$R rules; ${ONEBYONE_BUDGET}s budget exceeded; larger rungs skipped for this method"
  fi
  okcheck "one-by-one R=$R: the $added rules added reached apply_state active" "$converged"
  eqcheck "one-by-one R=$R: generation advanced by exactly the $added rules added" "$((gen_before + added))" "$gen_after"
  okcheck "one-by-one R=$R: forwarding through the first rule (TCP, port $BASE)" "$(tcp_probe_ok "$BASE" && echo 1 || echo 0)"
  if [ "$cut_short" = 0 ]; then
    okcheck "one-by-one R=$R: forwarding through the last rule (UDP, port $((BASE + R - 1)))" "$(udp_probe_ok "$((BASE + R - 1))" && echo 1 || echo 0)"
  else
    echo "SKIP  one-by-one R=$R: last-rule probe (the last rule was never added)"
  fi
done

echo "== one port-range rule ($((RANGE_HI - RANGE_LO + 1)) ports in a single rule)"
reset_rules
gen_before=$(apply_top_field desired_generation)
RFILE="$W/wgft-scale-range.json"
python3 -c "
import json
json.dump([{
    'id': 'r_scalerange', 'agent': '$RULE_AGENT', 'proto': 'tcp',
    'listen_port': '$RANGE_LO-$RANGE_HI', 'target': '192.168.50.2:$RANGE_LO',
    'vps_mode': 'kernel', 'enabled': True,
}], open('$RFILE', 'w'))
"
t0=$(date +%s%3N)
vps wgft rule import "$RFILE" --admin "$ADMIN" >/dev/null 2>&1
converged=1
wait_until "$BATCH_APPLY_BUDGET" all_rules_active 1 || converged=0
t1=$(date +%s%3N)
gen_after=$(apply_top_field desired_generation)
bytes=$(agent_state_bytes "$RULE_AGENT")
lines=0
[ "$mode" = kernel ] && lines=$(nft_lines)
measure "range ports=$((RANGE_HI - RANGE_LO + 1)) apply_ms=$((t1 - t0)) state_bytes=$bytes nft_lines=$lines"
okcheck "range rule: reached apply_state active" "$converged"
eqcheck "range rule: generation advanced by exactly 1" "$((gen_before + 1))" "$gen_after"
okcheck "range rule: forwarding through the range's first port ($RANGE_LO, TCP)" "$(tcp_probe_ok "$RANGE_LO" && echo 1 || echo 0)"
okcheck "range rule: forwarding through the range's last port ($RANGE_HI, TCP)" "$(tcp_probe_ok "$RANGE_HI" && echo 1 || echo 0)"

echo "== an oversized batch import (past the admin API's 1 MiB request cap) is refused atomically"
reset_rules
RFILE="$W/wgft-scale-overlimit.json"
python3 -c "
import json
base = $OVERLIMIT_BASE
rules = [{
    'id': f'r_over{i:05d}', 'agent': '$RULE_AGENT', 'proto': 'tcp',
    'listen_port': str(base + i), 'target': f'192.168.50.2:{base + i}',
    'vps_mode': 'kernel', 'enabled': True,
} for i in range($OVERLIMIT_N)]
json.dump(rules, open('$RFILE', 'w'))
"
overlimit_bytes=$(wc -c < "$RFILE")
overlimit_out=$(vps wgft rule import "$RFILE" --admin "$ADMIN" 2>&1)
overlimit_rc=$?
measure "overlimit N=$OVERLIMIT_N file_bytes=$overlimit_bytes exit=$overlimit_rc output=[$overlimit_out]"
okcheck "oversized import is rejected (non-zero exit)" "$([ "$overlimit_rc" -ne 0 ] && echo 1 || echo 0)"
eqcheck "oversized import left zero rules (no partial apply)" "0" "$(rule_count)"

echo "== cleanup: delete every rule and confirm the leak check"
reset_rules
eqcheck "0 rules after the final reset" "0" "$(rule_count)"
final_server_rss=$(rss_mib "$server_pid")
final_agent_rss=$(rss_mib "$home0_pid")
final_nft_lines=0
[ "$mode" = kernel ] && final_nft_lines=$(nft_lines)
measure "final server_rss_mib=${final_server_rss:-unknown} agent_rss_mib=${final_agent_rss:-unknown} nft_lines=$final_nft_lines (baseline was server=${base_server_rss:-unknown} agent=${base_agent_rss:-unknown} nft_lines=$base_nft_lines)"
if [ -n "${final_server_rss:-}" ] && [ -n "${base_server_rss:-}" ]; then
  okcheck "server RSS returns to about its baseline (+${RSS_MARGIN_SERVER_MIB} MiB margin, a loose leak check)" \
    "$([ "$final_server_rss" -le "$((base_server_rss + RSS_MARGIN_SERVER_MIB))" ] && echo 1 || echo 0)"
else
  echo "SKIP  server RSS leak check (a reading was unavailable)"
fi
if [ -n "${final_agent_rss:-}" ] && [ -n "${base_agent_rss:-}" ]; then
  okcheck "agent RSS returns to about its baseline (+${RSS_MARGIN_AGENT_MIB} MiB margin, a loose leak check)" \
    "$([ "$final_agent_rss" -le "$((base_agent_rss + RSS_MARGIN_AGENT_MIB))" ] && echo 1 || echo 0)"
else
  echo "SKIP  agent RSS leak check (a reading was unavailable)"
fi
if [ "$mode" = kernel ]; then
  okcheck "nft table returns to about its baseline line count (+-${NFT_LINE_MARGIN} lines)" \
    "$([ "$((final_nft_lines - base_nft_lines))" -le "$NFT_LINE_MARGIN" ] && [ "$((base_nft_lines - final_nft_lines))" -le "$NFT_LINE_MARGIN" ] && echo 1 || echo 0)"
fi

echo "== teardown"
kill_all   # server teardown refuses while the process is running; kill it first, as the setup
           # above already relies on (lab/import-export.sh's cleanup does the same)
out=$(vps wgft server teardown --data-dir "$DATA" --purge --yes 2>&1)
check "teardown runs" "deleted $DATA/wgft.sqlite" "$out"
rm -rf "$DATA" "$W"/wgft-scale-*.json
for ((i = 0; i < N_AGENTS; i++)); do rm -rf "$W/wgft-scale-agent$i"; done
if [ "$fail" = 0 ]; then echo "== $mode: ALL PASS"; else echo "== $mode: FAILURES"; fi
exit "$fail"
