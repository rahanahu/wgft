#!/usr/bin/env bash
# version-skew.sh checks the wire-protocol version negotiation (design 7a.6 section) across the
# combinations the design promises to keep working during a rolling upgrade: the current build
# talks to an agent with no protocol fields at all (legacy v0), the current build talks to the
# immediately-previous release's agent, and the immediately-previous release's server talks to
# the current build's agent. For each pairing this checks: the agent registers, the tunnel comes
# up, a TCP and a UDP rule forward, a rule added after registration reaches the agent, and the
# selected protocol version is what design 7a.6 requires, both in the server's own log line
# ("protocol legacy v0" or "protocol v<N>") and in the agent's ("server selected protocol ...").
# The server and then the agent are restarted in turn (data and credentials kept, so this is a
# reconnect, not a fresh setup) and the same negotiation, registration and forwarding checks are
# repeated, because a rolling upgrade restarts one side while the other keeps running.
#
#   lab/lab exec vm bash /wgft/lab/version-skew.sh                    # all four combinations
#   lab/lab exec vm bash /wgft/lab/version-skew.sh old-agent baseline # only these two
#
# Combinations (name used on the command line in parentheses):
#   legacy      (legacy)      current server build, v0.3.0 agent. v0.3.0 predates version
#                             negotiation entirely (no protocol_min/protocol_max/capabilities in
#                             its pubkey message at all), so this is the legacy v0 case. Design
#                             7a.6 keeps this a permanent, not a rolling, requirement: legacy v0
#                             must be supported by both sides for as long as the product is in
#                             the v1.0.x line (7a.6's own wording), so LEGACY_VERSION stays
#                             v0.3.0 - the only release that predates negotiation - regardless of
#                             which release OLD_AGENT_VERSION points at.
#   old agent   (old-agent)   current server build, OLD_AGENT_VERSION agent (the
#                             immediately-previous release; it already speaks protocol v1). Also
#                             checks agent disable/enable against this old agent (see below).
#   old server  (old-server)  OLD_AGENT_VERSION server, current agent build.
#   baseline    (baseline)    current server build, current agent build (both v1); a sanity
#                             check that the harness itself works, run last so a failure here
#                             says the script is wrong rather than the version combinations.
#
# OLD_AGENT_VERSION (below) tracks whichever release is immediately previous to the current
# build, not a fixed protocol version: design 7a.6 promises interoperability between the current
# and immediately-previous NUMBERED protocol version, and every release from v0.4.0 onward speaks
# the same protocol v1 (no v2 has been introduced yet), so old-agent/old-server exist to exercise
# an actual previous release's registration/forwarding/reconnect behaviour, not to add protocol
# coverage a unit test does not already have. It moves forward with each release: v0.6.0 as of
# this revision (main is v0.6.0 plus whatever has landed since), v0.5.0 previously.
#
# v0.3.0 predates the "stream: server selected protocol ..." log line by design (it has no
# concept of a negotiated version to log), so the legacy combination only checks the server's own
# log line; this is called out at the call site below, not silently skipped.
#
# Design 7a.6 also specifies two refusal paths: a malformed protocol_min/protocol_max
# advertisement is closed with WebSocket code proto.CloseProtocolMalformed (4004), and a
# range with no overlap is closed with proto.CloseProtocolMismatch (4003). Both need a peer that
# sends a pubkey message no real agent build ever sends (a missing half of the range, an invalid
# range, or a range that deliberately does not overlap); this script has no such fake client, so
# it prints SKIP for both instead of building one. proto.SelectProtocolVersion, ProtocolRange.Valid
# and the stream hub's negotiateVersion already cover every combination of malformed and
# mismatched ranges as a table-driven unit test (docs/design.md's revision record entry for the
# version negotiation feature has the detail on why the lab could not reach this either).
#
# The old-agent combination also checks agent disable/enable (design 5.1 section), since disable is
# a server-side-only guarantee added after every release this script can fetch (checked directly:
# neither v0.6.0 nor any 1.x release ancestors the commit that added `wgft agent disable`). Disabling
# home with the current server's own CLI is checked to stop that agent's forwarding and to show up
# in `wgft agent ls`, `wgft status` and `wgft server doctor`; enabling it again is checked to bring
# forwarding back. The OLD_AGENT_VERSION agent, which has no idea disable exists, is also checked to
# neither crash nor reconnect-loop while disabled: lab/lifecycle.sh's check 11 (L15) already covers
# disable/enable in full against a current-build agent, so this only adds what is specific to an old
# agent watching it happen. Only the old-agent combination runs this: old-server has no `agent
# disable` command to run at all (that combination's server_bin predates the feature entirely), and
# baseline/legacy add no version-skew information L15 does not already have.
#
# Old binaries: OLD_AGENT_VERSION and v0.3.0 (wgft-linux-amd64) are downloaded from the GitHub
# release assets of this repository and checked against the published .sha256 file. A download is
# cached under $CACHE (below) so the two combinations that both need OLD_AGENT_VERSION do not
# fetch it twice, and so a repeat run of this script in the same VM does not re-download at all.
# Nothing is added to the repository. Some hosts' Incus VMs have no outbound IPv4 on the bridge
# and GitHub has no IPv6 (lab/README.md's "VM が IPv4 で外に出られない"); on such a host, place
# the verified release binaries and their .sha256 files (named exactly wgft-v$OLD_AGENT_VERSION /
# wgft-v0.3.0, matching what a successful download would leave) in $CACHE before running this
# script. This script only fetches what is not already cached there, so pre-staged files are used
# as they are. The download and verification itself (fetch_release) lives in lab/oldrelease.sh,
# shared with lab/upgrade.sh (D4).
#
# Requires `lab/lab build` (wgft in /usr/local/bin of the VM) and the netns topology (`lab/lab
# net up`). Runs the server in kernel mode only; version negotiation does not depend on the
# forwarding mode, which lab/e2e.sh and lab/lifecycle.sh already exercise in both modes. Leftovers
# from earlier runs are killed first.
set -u

GH_REPO=rahanahu/wgft
OLD_AGENT_VERSION=0.6.0  # immediately-previous release: already speaks protocol v1 (design 7a.6)
LEGACY_VERSION=0.3.0     # predates version negotiation entirely: legacy v0. Fixed regardless of
  # OLD_AGENT_VERSION (see the "legacy" combination's own comment above): design 7a.6 requires
  # legacy v0 support through v1.0.x, and v0.3.0 is the only release that is actually legacy v0.
. "$(dirname "$0")/sandbox.sh"   # sandbox: netns names, workdir, process scope
CACHE=/tmp/wgft-version-skew-cache
ADMIN=127.0.0.1:8686
DATA=$W/wgft-version-skew-server
ADATA=$W/wgft-version-skew-agent
LAN_TCP=25590
LAN_UDP=19160
TCP_PORT=39995
UDP_PORT=27030
TCP_PORT2=39996
fail=0

ALL_COMBOS="legacy old-agent old-server baseline"
COMBOS="${*:-$ALL_COMBOS}"
for c in $COMBOS; do
  case " $ALL_COMBOS " in *" $c "*) ;; *) echo "usage: version-skew.sh [$ALL_COMBOS]" >&2; exit 2;; esac
done

check() { # check <label> <expected-substring> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
skip() { echo "SKIP  $1"; }
vps() { ip netns exec "$VPS_NS" "$@"; }
client() { ip netns exec "$CLIENT_NS" bash -c "$1"; }

# wait_until <timeout-seconds> <command...>: polls every 0.2s until <command...> exits 0, or the
# timeout elapses. The timeout is a wall-clock deadline, so a slow predicate (one that starts
# python3 or a probe) cannot stretch it. Non-zero on timeout; the assertion right after re-checks
# the same condition and reports the usual FAIL (same convention as lab/lifecycle.sh).
wait_until() {
  local timeout=$1; shift
  local deadline=$((SECONDS + timeout))
  while :; do
    "$@" >/dev/null 2>&1 && return 0
    [ "$SECONDS" -ge "$deadline" ] && return 1
    sleep 0.2
  done
}

# fetch_release (download-and-verify a tagged release binary, with caching and retries) is
# shared with lab/upgrade.sh (D4, docs/testing.md), which needs the same previous-release binary;
# see lab/oldrelease.sh's header comment for why it is factored out instead of kept inline here.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lab/oldrelease.sh
. "$SCRIPT_DIR/oldrelease.sh"

# kill_all resets the server/agent under test between combinations. It deliberately leaves the
# shared LAN echo target (started once, below) running; that target is only killed at the very
# end of the script, in final_cleanup.
kill_all() {
  sandbox_kill_named wgft 2>/dev/null
  sandbox_kill_cmdline "$CACHE/wgft-v" 2>/dev/null
  sandbox_kill_named socat 2>/dev/null
  sleep 1
}
final_cleanup() {
  kill_all
  sandbox_kill_named echo 2>/dev/null
  sleep 1
}
teardown_data() { # teardown_data <server-bin>
  vps "$1" server teardown --data-dir "$DATA" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  rm -rf "$DATA" "$ADATA"
}

admin_up() { vps "$1" agent ls --admin "$ADMIN" >/dev/null 2>&1; }
agent_registered() { vps "$1" agent ls --admin "$ADMIN" 2>/dev/null | tail -1 | grep -q home; }
tcp_probe_ok() { [[ "$(client "echo hi | timeout -k 5 20 socat -t 1 -T 10 - TCP:198.51.100.1:$1" 2>/dev/null)" == *tcp-echo* ]]; }
udp_probe_ok() { [[ "$(client "echo hi | timeout -k 5 20 socat -t 1 -T 10 - UDP:198.51.100.1:$1" 2>/dev/null)" == *udp-echo* ]]; }
tcp_refused() { ! tcp_probe_ok "$1"; }
udp_refused() { ! udp_probe_ok "$1"; }
# log_has <log-file> <substring>: used with wait_until to poll for a log line, since "agent ls"
# showing the agent as registered (agent_registered, above) only means the admin API's view of
# the database, not that the stream has actually reconnected and re-negotiated the protocol yet.
log_has() { grep -q -- "$2" "$1" 2>/dev/null; }

# tunnel_reset/tunnel_up/tunnel_state_text <server-bin>: read the one agent's tunnel state via
# "agent ls --json" (the same --json + python3 idiom lab/lifecycle.sh's flows_established uses).
# This test only ever has one agent ("home"), so the last entry is unambiguous. The state only
# becomes "ok" once the WireGuard handshake has actually completed (heartbeat(),
# internal/agent/agent.go); it is "error" with reason "handshake not established" until then.
# agent_registered (above) only means the admin API already knows the agent's name, which is
# true well before that: after a restart, probing TCP/UDP before the tunnel is actually up sends
# the first SYN into a wgft0 that has no peer configured yet, and that SYN is dropped and
# retried, which is slow rather than a true hang now that every probe below is wrapped in
# `timeout -k 5 20`, but still adds up over 8 combinations x 2 restarts. Waiting for tunnel_up
# first avoids hitting that path at all.
#
# tunnel_reset has to be waited for BEFORE tunnel_up, not just as a defensive extra: a restarted
# process's stream connection is accepted (and its own state read starts) before it has sent any
# heartbeat, so hub.status[agent] is replaced by a brand new, heartbeat-less Status the instant
# any new connection is accepted (internal/vpsd/stream/hub.go's serve(); dropping the OLD
# connection only sets Connected=false there, it does not clear the old Heartbeat/Tunnel). Right
# after a restart, "agent ls --json" can therefore still read back the OLD connection's last
# known-good "tunnel":"ok" for a moment, with no "last_heartbeat" key at all once the new
# connection has taken over (confirmed in the lab: a poll immediately after an agent restart read
# "generation":0 and no "last_heartbeat" key, i.e. freshly reset, one second after the last
# "state":"ok" reading from the pre-restart connection). A plain `wait_until N tunnel_up` can
# match that stale "ok" and return immediately; the check() right after it does a SEPARATE, later
# read, which can by then already show the freshly-reset empty state, failing even though the
# restarted agent has not had any chance yet to report anything at all. This was caught directly
# in the lab: "wg tunnel re-establishes after an agent restart" failed with 'state= reason=' only
# 4 seconds after the restart, far short of any real wait, immediately after a run where the
# same check passed by genuinely waiting close to 30 seconds. Waiting for tunnel_reset first
# removes the ambiguity: once a reset is observed, any "ok" read afterward can only be the new
# connection's own heartbeat, since a stale one is by definition no longer there to match.
#
# The wait_until budget for tunnel_up is 100s (a wall-clock deadline): in the current build, a
# heartbeat right after apply is retried every second until the handshake completes (up to 10s,
# runHeartbeats in internal/agent/stream.go); the v0.3.0 legacy binary predates that immediate
# retry (unconfirmed directly, but its own log in the lab showed no heartbeat line at all until
# its plain 30-second tick, timed from process start rather than from the restart), so it only
# reports on its next scheduled tick, up to 30s after it starts. 100s covers that with margin;
# the other combinations report within a few seconds either way.
tunnel_reset() {
  vps "$1" agent ls --admin "$ADMIN" --json 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if d and 'last_heartbeat' not in d[-1] else 1)
"
}
tunnel_up() {
  vps "$1" agent ls --admin "$ADMIN" --json 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if d and d[-1].get('tunnel', {}).get('state') == 'ok' else 1)
"
}
tunnel_state_text() {
  vps "$1" agent ls --admin "$ADMIN" --json 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin)
t = d[-1].get('tunnel', {}) if d else {}
print('state=%s reason=%s' % (t.get('state'), t.get('reason', '')))
"
}

# proc_gone <pid>: the process no longer exists (same idiom as lab/lifecycle.sh's kill_server).
proc_gone() { ! kill -0 "$1" 2>/dev/null; }

# find_pid <bin-path> <cmdline-substring>: the pid of the process running <bin-path> whose
# cmdline contains <cmdline-substring> ("server run" or "agent run"). Matches on the exact comm
# name first (the basename of <bin-path>; execve sets /proc/pid/comm from argv[0]'s last path
# component, so the old release binaries under $CACHE show up as e.g. "wgft-v0.4.0", distinct
# from the current build's "wgft") and only then greps cmdline, the same two-step lab/lifecycle.sh
# uses to stay safe against a wrapping shell that happens to share the same words in its own argv.
find_pid() {
  local bin=$1 sub=$2 name p
  name=$(basename "$bin")
  for p in $(sandbox_pids_named "$name" 2>/dev/null); do
    if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q " $sub"; then echo "$p"; return; fi
  done
}

# restart_proc <bin-path> <cmdline-substring>: kills the matching process (SIGTERM, the same
# signal kill_server uses) and waits for it to exit. Non-zero if no matching process was found or
# it did not exit in time, so the caller can FAIL the combination instead of restarting nothing.
restart_proc() {
  local bin=$1 sub=$2 p
  p=$(find_pid "$bin" "$sub") || return 1
  [ -n "$p" ] || return 1
  kill "$p" 2>/dev/null
  wait_until 5 proc_gone "$p"
}

mkdir -p "$CACHE"

# the LAN target every combination forwards to. Started once, outside kill_all/run_combo's own
# cleanup (which only resets the server/agent under test), so it survives across all combinations.
sandbox_kill_named echo 2>/dev/null
ip netns exec "$LAN_NS" setsid nohup echo -bind 192.168.50.3 -tcp "$LAN_TCP" -udp "$LAN_UDP" \
  > $W/wgft-version-skew-echo.log 2>&1 < /dev/null &
disown

# run_combo <name> <server-bin> <agent-bin> <expect-protocol-label> <agent-has-protocol-log 0/1>
#           <check-disable 0/1>
run_combo() {
  local name=$1 server_bin=$2 agent_bin=$3 want_label=$4 agent_logs_protocol=$5 check_disable=${6:-0}
  echo "== combination: $name (server=$(basename "$server_bin"), agent=$(basename "$agent_bin"))"
  kill_all
  teardown_data "$server_bin"
  mkdir -p "$DATA"
  local slog=$W/wgft-version-skew-$name-server.log
  local alog=$W/wgft-version-skew-$name-agent.log
  : > "$slog"; : > "$alog"

  vps setsid nohup "$server_bin" server run --mode kernel --data-dir "$DATA" \
    --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" > "$slog" 2>&1 < /dev/null &
  disown
  if ! wait_until 15 admin_up "$server_bin"; then
    echo "FAIL  $name: admin api never came up"; fail=1
    kill_all; teardown_data "$server_bin"; return
  fi

  local join
  join=$(vps "$server_bin" agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
  WGFT_JOIN="$join" ip netns exec "$HOME_NS" setsid nohup "$agent_bin" agent run --data-dir "$ADATA" \
    > "$alog" 2>&1 < /dev/null &
  disown
  if ! wait_until 20 agent_registered "$server_bin"; then
    echo "FAIL  $name: agent never registered"; fail=1
    kill_all; teardown_data "$server_bin"; return
  fi
  check "$name: agent registers" "home" "$(vps "$server_bin" agent ls --admin "$ADMIN" | tail -1)"

  vps "$server_bin" rule add --agent home --tcp "$TCP_PORT" --to 192.168.50.3:"$LAN_TCP" --admin "$ADMIN" >/dev/null
  vps "$server_bin" rule add --agent home --udp "$UDP_PORT" --to 192.168.50.3:"$LAN_UDP" --admin "$ADMIN" >/dev/null
  wait_until 15 tcp_probe_ok "$TCP_PORT"
  wait_until 10 udp_probe_ok "$UDP_PORT"
  check "$name: tunnel forwards tcp" "tcp-echo" "$(client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:$TCP_PORT")"
  check "$name: tunnel forwards udp" "udp-echo" "$(client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:$UDP_PORT")"

  # a rule added after the agent is already up and forwarding (not part of its first state) has
  # to reach it over the live stream connection, not just on initial registration.
  vps "$server_bin" rule add --agent home --tcp "$TCP_PORT2" --to 192.168.50.3:"$LAN_TCP" --admin "$ADMIN" >/dev/null
  wait_until 15 tcp_probe_ok "$TCP_PORT2"
  check "$name: a rule added after registration reaches the agent" "tcp-echo" \
    "$(client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:$TCP_PORT2")"

  check "$name: server log shows the negotiated protocol" "protocol $want_label" "$(cat "$slog")"
  if [ "$agent_logs_protocol" = 1 ]; then
    check "$name: agent log shows the negotiated protocol" "server selected protocol $want_label" "$(cat "$alog")"
  else
    skip "$name: agent log line ($(basename "$agent_bin") predates the \"server selected protocol\" log line entirely)"
  fi

  # reconnect (docs/testing.md B7, design 7a.6): a rolling upgrade restarts one side while the
  # other keeps running, so the negotiation above has to happen again on the same data, not just
  # once at a freshly-created state. First the server alone, keeping $DATA (its database and
  # wg0/nftables state) so this is a restart, not a fresh setup; then the agent alone, keeping
  # $ADATA (its stored credentials) so it reconnects rather than re-joining.
  local rslog=$W/wgft-version-skew-$name-server-restart.log
  : > "$rslog"
  if restart_proc "$server_bin" "server run"; then
    vps setsid nohup "$server_bin" server run --mode kernel --data-dir "$DATA" \
      --wg-endpoint 203.0.113.1:51820 --admin "$ADMIN" > "$rslog" 2>&1 < /dev/null &
    disown
    if wait_until 15 admin_up "$server_bin"; then
      if wait_until 40 agent_registered "$server_bin"; then
        check "$name: agent re-registers after a server restart" "home" "$(vps "$server_bin" agent ls --admin "$ADMIN" | tail -1)"
      else
        echo "FAIL  $name: agent never re-registered after a server restart"; fail=1
      fi
      # bare wait_until: agent_registered above only reflects the admin API's view of the
      # database, not that the stream has actually reconnected and re-negotiated the protocol
      # yet; the check() right after re-checks the same log with its own (unchanged) timeout.
      wait_until 15 log_has "$rslog" "protocol $want_label"
      check "$name: server log shows the negotiated protocol again after a server restart" "protocol $want_label" "$(cat "$rslog")"
      # gate the forwarding probes on the wg handshake, not just registration; see tunnel_up's
      # own comment for why probing before this is slow (a dropped SYN into an unconfigured wgft0).
      # tunnel_reset first: see tunnel_reset's own comment for why skipping straight to tunnel_up
      # can match the pre-restart connection's stale "ok" and make the check() right after it
      # fail on the freshly-reset value instead.
      wait_until 20 tunnel_reset "$server_bin"
      wait_until 100 tunnel_up "$server_bin"
      check "$name: wg tunnel re-establishes after a server restart" "state=ok" "$(tunnel_state_text "$server_bin")"
      wait_until 15 tcp_probe_ok "$TCP_PORT"
      wait_until 10 udp_probe_ok "$UDP_PORT"
      check "$name: tcp forwards again after a server restart" "tcp-echo" "$(client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:$TCP_PORT")"
      check "$name: udp forwards again after a server restart" "udp-echo" "$(client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:$UDP_PORT")"
    else
      echo "FAIL  $name: admin api never came back up after a server restart"; fail=1
    fi
  else
    echo "FAIL  $name: could not find the server process to restart"; fail=1
  fi

  local ralog=$W/wgft-version-skew-$name-agent-restart.log
  : > "$ralog"
  if restart_proc "$agent_bin" "agent run"; then
    WGFT_JOIN="$join" ip netns exec "$HOME_NS" setsid nohup "$agent_bin" agent run --data-dir "$ADATA" \
      > "$ralog" 2>&1 < /dev/null &
    disown
    if wait_until 40 agent_registered "$server_bin"; then
      check "$name: agent re-registers after an agent restart" "home" "$(vps "$server_bin" agent ls --admin "$ADMIN" | tail -1)"
    else
      echo "FAIL  $name: agent never re-registered after an agent restart"; fail=1
    fi
    if [ "$agent_logs_protocol" = 1 ]; then
      wait_until 15 log_has "$ralog" "server selected protocol $want_label"
      check "$name: agent log shows the negotiated protocol again after an agent restart" "server selected protocol $want_label" "$(cat "$ralog")"
    else
      skip "$name: agent log line after an agent restart ($(basename "$agent_bin") predates the \"server selected protocol\" log line entirely)"
    fi
    wait_until 20 tunnel_reset "$server_bin"
    wait_until 100 tunnel_up "$server_bin"
    check "$name: wg tunnel re-establishes after an agent restart" "state=ok" "$(tunnel_state_text "$server_bin")"
    wait_until 15 tcp_probe_ok "$TCP_PORT"
    wait_until 10 udp_probe_ok "$UDP_PORT"
    check "$name: tcp forwards again after an agent restart" "tcp-echo" "$(client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:$TCP_PORT")"
    check "$name: udp forwards again after an agent restart" "udp-echo" "$(client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:$UDP_PORT")"
  else
    echo "FAIL  $name: could not find the agent process to restart"; fail=1
  fi

  if [ "$check_disable" = 1 ]; then
    echo "-- $name: agent disable and enable, current server with the $(basename "$agent_bin") agent (design 5.1 section)"
    local pre_pid pre_reconnects dout drc eout erc
    pre_pid=$(find_pid "$agent_bin" "agent run")
    pre_reconnects=$(grep -c "stream: reconnecting" "$ralog" 2>/dev/null || echo 0)

    dout=$(vps "$server_bin" agent disable home --admin "$ADMIN" 2>&1); drc=$?
    if [ "$drc" = 0 ]; then echo "PASS  $name: wgft agent disable home exits 0"; else echo "FAIL  $name: wgft agent disable home exited $drc"; fail=1; fi
    check "$name: wgft agent disable home reports the generation" "disabled agent home at generation" "$dout"
    wait_until 15 tcp_refused "$TCP_PORT"
    wait_until 10 udp_refused "$UDP_PORT"
    if tcp_refused "$TCP_PORT" && udp_refused "$UDP_PORT"; then
      echo "PASS  $name: tcp and udp stop forwarding once home is disabled"
    else
      echo "FAIL  $name: tcp or udp still forwards after disabling home"; fail=1
    fi
    check "$name: agent ls shows home disabled" "disabled" "$(vps "$server_bin" agent ls --admin "$ADMIN" | tail -1)"
    check "$name: status shows home out of the healthy ratio" "0 / 0 healthy, 1 disabled" "$(vps "$server_bin" status --admin "$ADMIN" 2>&1)"
    check "$name: status counts every rule as agent disabled" "0 active, 3 agent disabled / 3" "$(vps "$server_bin" status --admin "$ADMIN" 2>&1)"
    check "$name: server doctor's survey skips home as disabled" 'SKIPPED    not tested: agent "home" is disabled' "$(vps "$server_bin" server doctor --admin "$ADMIN" 2>&1)"

    # Observation window for the negative claim below (docs/testing.md's wall-clock rule: state
    # has already converged - forwarding stopped, confirmed above - before this interval starts).
    # An old agent that could not make sense of a disable might drop its stream and reconnect
    # repeatedly, or panic; watching this many seconds with no fixed-length sleep elsewhere in the
    # combination gives a real reconnect loop room to show up before the post-* reads below.
    sleep 8
    local post_pid post_reconnects
    post_pid=$(find_pid "$agent_bin" "agent run")
    post_reconnects=$(grep -c "stream: reconnecting" "$ralog" 2>/dev/null || echo 0)
    if [ -n "$post_pid" ] && [ "$post_pid" = "$pre_pid" ]; then
      echo "PASS  $name: the $(basename "$agent_bin") agent process is still running under the same pid while home is disabled"
    else
      echo "FAIL  $name: the $(basename "$agent_bin") agent process pid changed or disappeared while home was disabled (was $pre_pid, now $post_pid)"; fail=1
    fi
    if [ "$post_reconnects" = "$pre_reconnects" ]; then
      echo "PASS  $name: the $(basename "$agent_bin") agent's stream did not reconnect while home was disabled"
    else
      echo "FAIL  $name: the $(basename "$agent_bin") agent reconnected $((post_reconnects - pre_reconnects)) more time(s) while home was disabled (see $ralog)"; fail=1
    fi

    eout=$(vps "$server_bin" agent enable home --admin "$ADMIN" 2>&1); erc=$?
    if [ "$erc" = 0 ]; then echo "PASS  $name: wgft agent enable home exits 0"; else echo "FAIL  $name: wgft agent enable home exited $erc"; fail=1; fi
    check "$name: wgft agent enable home reports the generation" "enabled agent home at generation" "$eout"
    wait_until 15 tcp_probe_ok "$TCP_PORT"
    wait_until 10 udp_probe_ok "$UDP_PORT"
    check "$name: tcp forwards again once home is enabled" "tcp-echo" "$(client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:$TCP_PORT")"
    check "$name: udp forwards again once home is enabled" "udp-echo" "$(client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:$UDP_PORT")"
    check "$name: agent ls shows home enabled again" "enabled" "$(vps "$server_bin" agent ls --admin "$ADMIN" | tail -1)"
  fi

  kill_all
  teardown_data "$server_bin"
}

for c in $COMBOS; do
  case "$c" in
    legacy)
      fetch_release "$LEGACY_VERSION" "$CACHE/wgft-v$LEGACY_VERSION" || { echo "FAIL  legacy: could not obtain v$LEGACY_VERSION (see this script's header comment)"; fail=1; continue; }
      run_combo legacy wgft "$CACHE/wgft-v$LEGACY_VERSION" "legacy v0" 0
      ;;
    old-agent)
      fetch_release "$OLD_AGENT_VERSION" "$CACHE/wgft-v$OLD_AGENT_VERSION" || { echo "FAIL  old-agent: could not obtain v$OLD_AGENT_VERSION (see this script's header comment)"; fail=1; continue; }
      run_combo old-agent wgft "$CACHE/wgft-v$OLD_AGENT_VERSION" "v1" 1 1
      ;;
    old-server)
      fetch_release "$OLD_AGENT_VERSION" "$CACHE/wgft-v$OLD_AGENT_VERSION" || { echo "FAIL  old-server: could not obtain v$OLD_AGENT_VERSION (see this script's header comment)"; fail=1; continue; }
      run_combo old-server "$CACHE/wgft-v$OLD_AGENT_VERSION" wgft "v1" 1
      ;;
    baseline)
      run_combo baseline wgft wgft "v1" 1
      ;;
  esac
done

# the two refusal paths (design 7a.6): a malformed protocol_min/protocol_max advertisement
# (proto.CloseProtocolMalformed, 4004) and a non-overlapping range (proto.CloseProtocolMismatch,
# 4003). No real agent build sends either; see the header comment for why this is a SKIP rather
# than a fake client, and where the same ground is already covered.
skip "malformed protocol advertisement closed with code 4004 (needs a fake client; see header comment)"
skip "non-overlapping protocol range closed with code 4003 (needs a fake client; see header comment)"

# design 7a.6: a rule that the older side cannot express because it needs a capability becomes
# not_active with a reason, instead of a silent downgrade. SupportedCapabilities (proto/version.go)
# is an empty vocabulary today (no capability-gated feature exists in the planner, the stream
# negotiation or anywhere else), so there is nothing yet to advertise a gap for; this SKIP stands
# in for that check and should turn into a real one the day the first capability is introduced.
skip "not_active with a reason for a capability the older side cannot express: no capability-gated feature exists yet; enable this check when the first capability is introduced"

final_cleanup
if [ "$fail" = 0 ]; then echo "== version-skew: ALL PASS"; else echo "== version-skew: FAILURES"; fi
exit "$fail"
