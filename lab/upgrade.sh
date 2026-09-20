#!/usr/bin/env bash
# upgrade.sh proves the in-place UPGRADE from a previous release (docs/testing.md D4, design
# 7a.6 section "既存のデータの置き場からの更新"): the CURRENT build started on an old install's
# data (server database, WireGuard keys, agent credentials) keeps everything working after a
# clean stop and a binary swap, the way a package upgrade (systemd ExecStart pointing at a new
# binary, then a single restart) would. Unlike lab/version-skew.sh, which proves the wire
# protocol negotiates correctly with FRESH data on both sides, the point here is OLD DATA: a
# database and a credentials file that the old release itself created.
#
# The old release is $OLD_VERSION (below), default v0.5.0: the immediately-previous release,
# which is the upgrade operators actually run next now that the current build is v0.5.1 plus
# nothing yet. v0.4.0, the oldest release the project's release notes still promise an upgrade
# from ("a rolling upgrade from v0.5.0 or v0.4.0 is supported"), is covered by overriding the
# version, which every v0.4.0-specific assertion below still runs under in full:
#
#   lab/lab exec vm bash /wgft/lab/upgrade.sh kernel                              # v0.5.0 -> current
#   lab/lab exec vm bash /wgft/lab/upgrade.sh userspace                           # v0.5.0 -> current
#   WGFT_UPGRADE_OLD_VERSION=0.4.0 lab/lab exec vm bash /wgft/lab/upgrade.sh kernel     # v0.4.0 -> current
#   WGFT_UPGRADE_OLD_VERSION=0.4.0 lab/lab exec vm bash /wgft/lab/upgrade.sh userspace  # v0.4.0 -> current
#
# Between v0.4.0 and v0.5.0, phase 5 (Admission Policy compilers: TCP packet_rate stops taking
# effect, Relay listeners become IPv4-only) and phase 6 (Resource Guard: the flow budget line)
# landed, so v0.5.0's own CLI already shows some of what step 5 below asserts as "new" for
# v0.4.0. old_has (below) gates each such assertion on $OLD_VERSION, so the v0.4.0 run keeps
# asserting the genuine before/after change while the v0.5.0 run SKIPs only the part that is no
# longer a change (with a stated reason), never silently drops it.
#
# Scenario, all against the SAME data directories throughout (never recreated), except where
# noted:
#   1. start the old release's server and agent on fresh data, create one rule of each
#      representative shape through the old release's own CLI (plain TCP, plain UDP, a UDP port
#      range, a rule with a source_deny and a source_allow, a TCP rule with all three rates
#      including packet_rate, a disabled rule, a Relay/PROXY-protocol rule), prove forwarding,
#      and record the old release's own `rule ls` (plain and `--json`), `agent ls --json`,
#      WireGuard public keys and the agent's credentials file. A snapshot of both data
#      directories is taken right after this (SIGTERM'd, so no writer is mid-write), for step
#      4's partial-upgrade scenarios below.
#   2. stop both cleanly (SIGTERM, wait for exit: stop_server/stop_agent below), then start the CURRENT
#      build's server and agent on the SAME data directories, flags and environment the old
#      release used (design 7a.6 promises the CLI, WGFT_*, admin API v1 and wire protocol as an
#      external contract; a diff of v0.5.0..current and v0.4.0..current cmd/wgft/*.go found only
#      additions, no renames or removals - see the "no settings changed" note below).
#   3. assert: the new server comes up with no extra step and no schema/migration error; every
#      rule from step 1 is still there, compared field by field (proto.Rule itself did not
#      change between either old release and current, so this is exact equality, not tolerance -
#      the fields the new version ADDS live one level up, on the list response, not on each
#      rule; see compare_rules.py's own comment); the agent reconnects on its existing
#      credentials with no re-enrolment; both sides' WireGuard keys are unchanged; the negotiated
#      protocol is what design 7a.6 requires; TCP and UDP forward again through every enabled
#      rule; the disabled rule stays disabled; deny and allow still bite (two throwaway rules
#      created and removed after this step, so they do not appear in the rule comparison).
#   4. partial upgrades in both orders, using a snapshot of step 1's OLD data (not fresh data,
#      which is what lab/version-skew.sh already covers): new server + still-old agent, and old
#      server + new agent. Each only has to keep forwarding.
#   5. behaviour changes an upgrade makes visible, asserted the way the design states them:
#      packet_rate on the TCP rule from step 1 is kept but the CLI now says it has no effect;
#      Relay listeners are IPv4-only (the v0.4.0 dual-stack bug design.md's revision record
#      describes); `rule ls` now prints a flow budget line (Resource Guard, design 7a.10; a
#      single rule using the whole budget under flood is L8's job, not re-verified here). Each
#      of these three is also checked directly against the old release's own pre-upgrade output
#      (old_has, above); for v0.4.0 this proves a genuine before/after change, for v0.5.0 (which
#      already has all three) that half of the check is a stated SKIP instead.
#
# Requires `lab/lab build` (current wgft, echo, ppecho in /usr/local/bin of the VM) and the netns
# topology (`lab/lab net up`). Runs kernel and userspace mode; both v0.4.0 and v0.5.0 support
# both.
#
# SANDBOX-READY / PARALLEL-SAFE: every file this script writes lives under $WORK (one variable,
# defaulting under /tmp), and the netns names and every port/address are variables (today's fixed
# topology and ports by default). It never does a VM-wide process lookup (no pkill by name, no
# pgrep, no ps/grep over the whole process table; the one exception is ss run INSIDE one netns at a
# time, see resource_check), and it never signals a process it did not itself start in THIS run.
# stop_server/stop_agent/stop_targets only ever act on pids this exact instance holds in a variable
# right now, the moment after starting them, resolved through leaf_pid to their real descendant so
# they wait for the actual target process to exit, not just its wrapper - there is no restart and
# no window for pid reuse to matter there (see leaf_pid's own comment). Across runs, stale_cleanup
# checks for two kinds of leftover from a PREVIOUS run of this script, but never signals or waits
# on either, verified or not: it only reports what it finds and removes the stale record.
# report_stale verifies the wrapper and leaf pids $WORK/pid.* recorded (boot id and process start
# time, so pid reuse cannot fool it); resource_check looks for the vps WireGuard interface,
# nftables table, and any port this run binds already being held (see both functions' own
# comments). If either finds a live leftover, the whole run refuses to continue instead of risking
# a collision (see stale_cleanup's own comment for exactly what would collide and why that is worse
# than stopping). Deliberately kept small: this is a verified detect-and-report safety net for
# running this one script directly, not a general-purpose reaper; owning a whole sandbox's
# leftovers is the coming lab harness's job. The one thing that is NOT yet sandboxed is the netns
# topology itself (client/vps/home/lan are one shared set per VM today, same as every other
# lab/*.sh script); that is a lab/netns.sh limitation this script does not attempt to fix.
set -u
# job control (set -m) is needed for term_group below: without it, a non-interactive bash script
# never gives a background job its own process group (every "cmd &" just stays in the script's
# own group), so "kill -- -$pid" would target nothing and a plain "kill $pid" would only kill the
# immediate child bash forks for a backgrounded shell function call, orphaning the real target
# process underneath it instead of stopping it (confirmed in the lab: with monitor off, "vps sleep
# &"'s $! was a bash subshell, not sleep itself; killing it left sleep running, reparented to
# init). With -m on, $! for "vps CMD &" is that job's own process group leader, so a plain kill by
# pid already reaches everything the job forked, and the group kill is an extra safety net.
set -m
GH_REPO=rahanahu/wgft
OLD_VERSION=${WGFT_UPGRADE_OLD_VERSION:-0.5.0}  # default: the immediately-previous release, the
  # upgrade operators actually run next. Override with WGFT_UPGRADE_OLD_VERSION=0.4.0 for the
  # oldest release the project's release notes still promise an upgrade from (see header comment).
mode=${1:-kernel}
case "$mode" in kernel|userspace) ;; *) echo "usage: upgrade.sh kernel|userspace" >&2; exit 2;; esac

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lab/oldrelease.sh
. "$SCRIPT_DIR/oldrelease.sh"

WORK=${WGFT_UPGRADE_WORK:-/tmp/wgft-upgrade}
CACHE=${WGFT_UPGRADE_CACHE:-/tmp/wgft-upgrade-cache}  # old-release binary cache; deliberately
  # outside $WORK so a repeat run (or another sandbox wanting the same v0.4.0 binary) does not
  # re-download it. fetch_release itself is safe for two sandboxes sharing this directory at the
  # same time (see its own comment in lab/oldrelease.sh).
NS_CLIENT=${WGFT_NS_CLIENT:-client}
NS_VPS=${WGFT_NS_VPS:-vps}
NS_HOME=${WGFT_NS_HOME:-home}
NS_LAN=${WGFT_NS_LAN:-lan}
ADMIN=${WGFT_UPGRADE_ADMIN:-127.0.0.1:8686}
WG_ENDPOINT=203.0.113.1:51820
LAN_ADDR=192.168.50.3
# WG_INTERFACE/WG_PORT/AGENT_API: wgft's own defaults (cmd/wgft/server.go), made explicit here -
# and passed to start_server below - instead of left implicit, so resource_check (stale_cleanup's
# leftover-resource check) has a single source of truth for what it looks for in the vps
# namespace, rather than a second, independently-hardcoded copy of the same constants.
WG_INTERFACE=wgft0
WG_PORT=51820
AGENT_API=0.0.0.0:8443

# VPS-side listen ports and LAN-side target ports for the seven representative rules (§ scenario
# step 1). Chosen not to collide with any other lab/*.sh script's hardcoded ports, though that
# only matters if two scripts somehow shared one netns set at once, which today's topology does
# not allow anyway.
P_TCP=39920;        T_TCP=25620
P_UDP=27040;        T_UDP=19180
P_RANGE_LO=39930;   P_RANGE_HI=39932;  T_RANGE_LO=20010  # 3 ports, first maps to T_RANGE_LO
P_ACL=39940;        T_ACL=25621
P_RATES=39950;      T_RATES=25622
P_DISABLED=39960;   T_DISABLED=25623  # never actually dialled; the rule stays disabled
P_RELAY=39970;      T_RELAY=8461      # ppecho, not echo: proves the PROXY protocol header

VPS6=2001:db8::1; CLIENT6=2001:db8::2  # documentation prefix, client-vps link only (lab/README.md);
  # used by both step 1 (the old release's own relay, old_has-gated) and step 5 (current build's)

fail=0
check() { # check <label> <expected-substring> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3'"; fail=1; fi
}
absent() { # absent <label> <substring-that-must-not-appear> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty substring (test bug)"; fail=1; return; fi
  if [[ "$3" == *"$2"* ]]; then echo "FAIL  $1: got '$3'"; fail=1; else echo "PASS  $1"; fi
}
strcheck() { # strcheck <label> <want> <got>: exact string equality (checksums, pubkeys, ids -
  # check()'s substring match would let e.g. one pubkey that is a prefix of another slip through).
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug or a capture that returned nothing)"; fail=1; return; fi
  if [ "$2" = "$3" ]; then echo "PASS  $1"; else echo "FAIL  $1: got '$3', want '$2'"; fail=1; fi
}
eqcheck() { # eqcheck <label> <want> <got>: integers must be equal, not substring-match.
  if [ "$2" -eq "$3" ] 2>/dev/null; then echo "PASS  $1"; else echo "FAIL  $1: got '$3', want '$2'"; fail=1; fi
}
okcheck() { # okcheck <label> <ok-if-true 1/0>
  if [ "$2" = "1" ]; then echo "PASS  $1"; else echo "FAIL  $1"; fail=1; fi
}
skip() { echo "SKIP  $1"; }

# old_has <capability>: whether $OLD_VERSION's OWN build already implements the named phase 5/6
# behaviour, so step 1's and step 5's before/after assertions know whether a genuine change is
# available to prove. Every capability here landed between v0.4.0 and v0.5.0 (design 7a.8's
# revision record: phase 5 step 3 - Relay listeners become IPv4-only; phase 5 step 5 -
# packet_rate stops taking effect on TCP and the CLI starts saying so; phase 6 step 5 - `rule ls`
# starts printing a flow budget line), so v0.4.0 is the only release lacking any of them; v0.5.0
# and v0.5.1 have all three already. Extend this table, not the call sites, if a future default
# OLD_VERSION again lacks one of these.
old_has() {
  case "$OLD_VERSION:$1" in
    0.4.0:*) return 1 ;;
    *) return 0 ;;
  esac
}

# wait_until <timeout-seconds> <command...>: wall-clock poll, same idiom (and same reasoning
# about slow predicates under CPU contention) as lab/lifecycle.sh and lab/version-skew.sh's.
wait_until() {
  local timeout=$1; shift
  local deadline=$((SECONDS + timeout))
  while :; do
    "$@" >/dev/null 2>&1 && return 0
    (( SECONDS >= deadline )) && return 1
    sleep 0.2
  done
}

vps() { ip netns exec "$NS_VPS" "$@"; }
client() { ip netns exec "$NS_CLIENT" bash -c "$1"; }
home() { ip netns exec "$NS_HOME" "$@"; }
lan() { ip netns exec "$NS_LAN" "$@"; }

# --- process tracking: tracked pids only, never a VM-wide pkill/pgrep by name --------------------
# Every start_* function below launches its command as "cmd > log 2>&1 < /dev/null & pid=$!;
# disown" without setsid, so bash puts it in its OWN process group (standard job-control
# behaviour for any "&"ed pipeline) whose pgid equals that $!. term_group signals that whole
# group by pid, which reaches "ip netns exec" and everything it execs/forks (runuser, wgft)
# without needing to know which of them is the "real" pid, and without scanning the process
# table for anything by name.
SERVER_PID=""; AGENT_PID=""; LAN_ECHO_PID=""; PPECHO_PID=""
proc_gone() { ! kill -0 "$1" 2>/dev/null; }
term_group() { # term_group <pid>: SIGTERM the tracked job's whole process group, falling back to
  # a plain single-pid signal (harmless no-op if the group signal already reached it).
  local pid=$1
  [ -n "$pid" ] || return 0
  kill -- "-$pid" 2>/dev/null
  kill "$pid" 2>/dev/null
}
# leaf_pid <wrapper-pid>: the deepest single-child descendant of <wrapper-pid>, via
# /proc/<pid>/task/<pid>/children - a lookup scoped to one pid this script itself started, never
# a VM-wide process-table scan. $! for "vps CMD &" (vps is a shell function) is the pid of the
# bash forks to run a backgrounded function call, not CMD's own pid: measured in the lab,
# that wrapper can exit up to tens of milliseconds before the real "wgft" process underneath it
# (ip netns exec -> [runuser ->] wgft) actually does. proc_gone on the wrapper alone can therefore
# report "stopped" while the real process (and any SQLite flock it still holds) is still exiting;
# once in the lab this raced a same-second restart into "PRAGMA journal_mode=WAL: database is
# locked (SQLITE_BUSY)" even though the wrapper's own pid was already confirmed gone. Bounded to 5
# hops so a stuck /proc read can never spin; falls back to <wrapper-pid> itself when it has no
# child at all (start_agent backgrounds a plain "ip netns exec ... &" with no function in the
# way, which the lab showed can sometimes skip the extra fork entirely) or the tree is ambiguous
# (0 or 2+ children at some hop). Only ever called on a pid this same script instance holds in a
# variable right now (SERVER_PID and friends, or a just-verified stale_cleanup record below), so
# there is no separate reuse risk here: the pid is known-live an instant before this reads it.
leaf_pid() {
  local pid=$1 children i
  for i in 1 2 3 4 5; do
    children=$(cat "/proc/$pid/task/$pid/children" 2>/dev/null)
    [ "$(wc -w <<< "$children")" -eq 1 ] || break
    pid=$(tr -d ' \t\n' <<< "$children")
  done
  echo "$pid"
}

# --- pid identity: what makes a recorded pid file trustworthy across a script restart ------------
# A bare pid number is not enough to identify a *specific* process once real time has passed: PIDs
# wrap around and get reused. stop_server/stop_agent/stop_targets never have this problem because
# they only ever act on SERVER_PID and friends, in-memory variables of the one script instance
# that just started that exact process a few seconds earlier - there is no restart, no file, and
# no gap for reuse. stale_cleanup is different: it reads pids that a *previous, possibly long-dead*
# run of this script left in $WORK/pid.*, so before reporting one it must verify that pid is still
# the exact process this tooling started, not a stranger that happens to have the same number now.
# The two facts that make a pid this specific are the kernel boot id (a pid space is only reused
# within one boot) and the process's own start time in clock ticks since boot (a field the kernel
# assigns once at fork and never reuses for a different process within the same boot, unlike the
# pid number itself). record_pid writes both, for the backgrounded job's own pid AND (when
# different) its leaf_pid, since a job that goes through a wrapper - "vps CMD &" backgrounds a
# bash function call, which forks a subshell before CMD - can exit that wrapper on its own,
# independently of the real process underneath, leaving nothing at the wrapper's pid to verify
# while the real process is still running (seen in the lab: the leftover this check exists for).
# read_pid_record reads both back; proc_start_time is how both sides compute the same value.
boot_id() { cat /proc/sys/kernel/random/boot_id 2>/dev/null; }
# proc_start_time <pid>: field 22 (starttime) of /proc/<pid>/stat, in clock ticks since boot.
# Parsed robustly: comm (field 2) is whatever the process named itself and can itself contain
# spaces or unbalanced parentheses, so field-splitting from the front is unsafe; cut everything
# up to and including the LAST ")" instead (comm is always parenthesised and pid/comm are always
# exactly the first two fields), then starttime is the 20th field of what remains (fields 3..22
# of the original line become fields 1..20 once pid and "(comm)" are removed).
proc_start_time() {
  local pid=$1 stat rest
  stat=$(cat "/proc/$pid/stat" 2>/dev/null) || return 1
  rest=${stat##*)}
  set -- $rest
  [ "$#" -ge 20 ] || return 1
  echo "${20}"
}
# record_pid <file> <pid>: writes <pid>, its boot id and start time (lines 1-3), then - only when
# leaf_pid resolves to something other than <pid> itself - the same three facts for the leaf (lines
# 4-6). The leaf is given a moment to stabilise first (leaf_pid immediately after fork can still
# see an incomplete tree): poll until two reads agree, bounded, so this never blocks indefinitely.
# A process too short-lived to still exist by the time this reads /proc/<pid>/stat (should not
# happen) leaves that start-time line empty, which read_pid_record below treats the same as any
# other unverifiable record.
record_pid() {
  local file=$1 pid=$2 prev cur i
  prev=$(leaf_pid "$pid")
  for i in 1 2 3 4 5; do
    sleep 0.2
    cur=$(leaf_pid "$pid")
    [ "$cur" = "$prev" ] && break
    prev=$cur
  done
  { echo "$pid"; boot_id; proc_start_time "$pid" 2>/dev/null; } > "$file"
  if [ -n "$cur" ] && [ "$cur" != "$pid" ]; then
    { echo "$cur"; boot_id; proc_start_time "$cur" 2>/dev/null; } >> "$file"
  fi
}
# read_pid_record <file>: on success, sets REC_PID/REC_BOOT/REC_START (the wrapper) and returns 0;
# otherwise (missing file, fewer than 3 lines, or any of the three empty - including a pid file in
# the pid-only format this script used before this identity check existed) returns 1 with all
# three unset, which the caller must treat as "cannot verify, so do not act on it". A record with a
# separately-recorded leaf (lines 4-6; see record_pid) additionally sets REC_LEAF_PID/
# REC_LEAF_BOOT/REC_LEAF_START; a record with no leaf lines (no extra fork happened, or this file
# predates leaf recording) leaves all three empty, which the caller treats as "no leaf to check".
read_pid_record() {
  REC_PID=""; REC_BOOT=""; REC_START=""
  REC_LEAF_PID=""; REC_LEAF_BOOT=""; REC_LEAF_START=""
  local file=$1
  [ -f "$file" ] || return 1
  { read -r REC_PID; read -r REC_BOOT; read -r REC_START
    read -r REC_LEAF_PID; read -r REC_LEAF_BOOT; read -r REC_LEAF_START; } < "$file" 2>/dev/null
  [ -n "$REC_PID" ] && [ -n "$REC_BOOT" ] && [ -n "$REC_START" ]
}

# stale_cleanup: on entry, NEVER signals or waits on anything (the owner's call: even a
# fully-verified leftover only gets reported, never killed, by this script). It checks two
# independent kinds of leftover from an earlier run of this exact script: report_stale verifies
# each $WORK/pid.* record's wrapper AND leaf identity (see record_pid/report_stale); resource_check
# looks for the kernel/network state that outlives any process by design (the WireGuard interface
# and nftables table a clean vpsd stop deliberately leaves behind, plus anything already listening
# on a port this run needs). If neither finds anything, $WORK is rebuilt empty. If either does,
# this refuses to continue: it prints exactly what to run to remove it and exits 3, leaving $WORK
# and the records in place so every rerun refuses again until the leftover is actually gone.
# Removing the records before refusing would make the next rerun see nothing, start, and collide.
# The reason this stops instead of just reporting and carrying on: the vps/home/lan namespaces and
# every port/address this script uses (the admin API at $ADMIN, the agent API, the WireGuard
# interface and port, every P_*/T_* target port) are fixed constants in a VM-wide shared namespace
# (not sandboxed; see the header comment). A leftover holding any of them would make this run's own
# start_server/start_agent/start_targets either fail to bind, or silently succeed by binding
# nothing while the leftover keeps answering - letting this run's checks read the leftover's state
# instead of its own, and pass or fail for the wrong reason. A fresh run cannot tell that apart from
# a real regression, so this stops rather than risk it quietly.
stale_cleanup() {
  local f found=0
  if [ -d "$WORK" ]; then
    for f in "$WORK"/pid.*; do
      [ -e "$f" ] || continue
      report_stale "$f" || found=1
    done
  fi
  resource_check || found=1
  if [ "$found" = 1 ]; then
    echo "stale_cleanup: refusing to start: at least one leftover reported above would collide with this run's own server/agent/targets in the shared vps/home/lan namespaces (see this function's own comment for why). Remove it with the command(s) printed above, then rerun." >&2
    exit 3
  fi
  rm -rf "$WORK"
  mkdir -p "$WORK" "$CACHE"
}
# verify_identity <pid> <boot> <start>: echoes one of "alive" (pid still exists, same boot, exact
# same start time - this IS the recorded process), "gone" (pid no longer exists), "reused" (pid
# exists but its start time differs: an unrelated process now has that number), or "rebooted" (the
# recorded boot id is not this boot, so the pid number means nothing here regardless of the pid's
# current state). Purely a read; never signals anything.
verify_identity() {
  local pid=$1 boot=$2 start=$3 cur_start
  [ "$boot" = "$(boot_id)" ] || { echo rebooted; return; }
  cur_start=$(proc_start_time "$pid")
  [ -n "$cur_start" ] || { echo gone; return; }
  [ "$cur_start" = "$start" ] && echo alive || echo reused
}
# report_stale <pid-file>: the one place a pid read back from a file (rather than an in-memory
# variable of this running script) is ever even looked at; it only ever reports, never signals or
# waits on it. A record holds two identities to check independently (see record_pid): the wrapper
# ("vps CMD &"'s own $!) and, when the fork underneath it was resolved at record time, the leaf.
# Checking them independently matters because the wrapper can exit on its own well before the leaf
# does (seen in the lab: a SIGKILL'd server's wrapper was already gone while the real "server run"
# process it had forked was still up, still holding the WireGuard interface, the admin API and the
# agent API) - a leftover leaf with a dead wrapper is still a leftover. Returns 1 if either
# verifies alive, so the caller knows not to continue; returns 0 only when both are gone, reused or
# from a previous boot, which is safe to ignore.
report_stale() {
  local file=$1 wstatus lstatus cmdline
  if ! read_pid_record "$file"; then
    echo "stale_cleanup: $file has no verifiable pid record (missing, unreadable, or the old pid-only format); nothing to report, removing the record"
    return 0
  fi
  wstatus=$(verify_identity "$REC_PID" "$REC_BOOT" "$REC_START")
  lstatus=""
  [ -n "$REC_LEAF_PID" ] && lstatus=$(verify_identity "$REC_LEAF_PID" "$REC_LEAF_BOOT" "$REC_LEAF_START")

  if [ "$wstatus" != alive ] && [ "$lstatus" != alive ]; then
    echo "stale_cleanup: $file: wrapper pid $REC_PID is $wstatus${REC_LEAF_PID:+, leaf pid $REC_LEAF_PID is ${lstatus:-gone}}; nothing to report"
    return 0
  fi

  echo "stale_cleanup: LEFTOVER - $file is still running from an earlier run of this script"
  if [ "$wstatus" = alive ]; then
    cmdline=$(tr '\0' ' ' < "/proc/$REC_PID/cmdline" 2>/dev/null)
    echo "  wrapper pid $REC_PID is alive (boot id and start time verified); cmdline: ${cmdline:-<unreadable>}"
  elif [ -n "$REC_LEAF_PID" ]; then
    echo "  wrapper pid $REC_PID is $wstatus (its group leader is gone)"
  fi
  if [ "$lstatus" = alive ]; then
    cmdline=$(tr '\0' ' ' < "/proc/$REC_LEAF_PID/cmdline" 2>/dev/null)
    echo "  real process pid $REC_LEAF_PID is alive (boot id and start time verified); cmdline: ${cmdline:-<unreadable>}"
  elif [ -n "$REC_LEAF_PID" ]; then
    echo "  real process pid $REC_LEAF_PID is $lstatus"
  fi

  if [ "$wstatus" = alive ]; then
    # the wrapper itself verified alive, so it is genuinely still the group leader: a group kill
    # reaches it and everything it forked, including the leaf, in one signal.
    echo "  to stop it yourself: kill -- -$REC_PID   (falls back to a plain 'kill $REC_PID' if that pid is not its own process group leader)"
  else
    # the wrapper is gone; only the leaf verified alive, orphaned and no longer any process's
    # group leader (see this function's own comment), so a group kill would signal nothing or the
    # wrong group. A plain kill of the specific verified pid is the correct, unambiguous command.
    echo "  the group leader (the wrapper) is gone; to stop it yourself: kill $REC_LEAF_PID"
  fi
  return 1
}
# resource_check: what stale_cleanup's pid-based checks above cannot see, because it outlives every
# process by design or was never this script's own process to begin with. Kernel mode's WireGuard
# interface and nftables table are deliberately left running through a clean vpsd stop (design 9,
# 10.3), so no pid, however verified, ever points at them; a leftover on any port this run binds is
# equally invisible to a pid check if it was started some other way. All three are checked with
# ip/nft/ss run INSIDE the netns (never a VM-wide process lookup), using this script's own
# variables for every name and port so this can never drift from what start_server/start_targets
# actually use. Returns 1 (having printed what to remove) if anything is found; 0 on a clean
# vps/lan.
resource_check() {
  local found=0
  if vps ip link show "$WG_INTERFACE" >/dev/null 2>&1; then
    echo "stale_cleanup: LEFTOVER - WireGuard interface $WG_INTERFACE exists in $NS_VPS (outlives vpsd by design; not tied to any pid)"
    echo "  to remove it yourself: ip -n $NS_VPS link del $WG_INTERFACE"
    found=1
  fi
  if vps nft list table inet wgft >/dev/null 2>&1; then
    echo "stale_cleanup: LEFTOVER - nftables table inet wgft exists in $NS_VPS (outlives vpsd by design; not tied to any pid)"
    echo "  to remove it yourself: ip netns exec $NS_VPS nft delete table inet wgft"
    found=1
  fi
  local spec ns proto port
  for spec in \
    "$NS_VPS tcp ${ADMIN##*:} the admin API" \
    "$NS_VPS tcp ${AGENT_API##*:} the agent API" \
    "$NS_VPS udp $WG_PORT the WireGuard port" \
    "$NS_LAN tcp $T_TCP a target port" "$NS_LAN tcp $T_ACL a target port" \
    "$NS_LAN tcp $T_RATES a target port" "$NS_LAN tcp $T_DISABLED a target port" \
    "$NS_LAN tcp $T_RELAY a target port" \
    "$NS_LAN udp $T_UDP a target port" "$NS_LAN udp $T_RANGE_LO a target port" \
    "$NS_LAN udp $((T_RANGE_LO + 1)) a target port" "$NS_LAN udp $((T_RANGE_LO + 2)) a target port"
  do
    set -- $spec; ns=$1 proto=$2 port=$3
    if port_listening "$ns" "$proto" "$port"; then
      echo "stale_cleanup: LEFTOVER - something is already listening on $ns:$proto/$port ($4 $5 $6), not started by this run"
      echo "  to inspect and stop it yourself: ip netns exec $ns ss -${proto:0:1}lnp | grep ':$port ' ; then stop that process, or reset the lab VM (lab/lab reset)"
      found=1
    fi
  done
  [ "$found" = 0 ]
}
# port_listening <ns> <tcp|udp> <port>: true if something is bound to <port> inside <ns>, checked
# with ss run inside that one namespace only (never a VM-wide process lookup).
port_listening() {
  local ns=$1 proto=$2 port=$3 flag=tln
  [ "$proto" = udp ] && flag=uln
  ip netns exec "$ns" ss "-$flag" "( sport = :$port )" 2>/dev/null | tail -n +2 | grep -q .
}

ensure_wgftlab() { id wgftlab >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin wgftlab; }

# start_server <bin> <data-dir> <log-file>: same flags the old release and the current build both
# accept unchanged (design 7a.6's external-contract table; verified by diffing both v0.4.0..HEAD
# and v0.5.0..HEAD's cmd/wgft/server.go, agent.go, config.go - see this script's header comment).
start_server() {
  local bin=$1 data=$2 log=$3
  : > "$log"
  if [ "$mode" = userspace ]; then
    ensure_wgftlab
    chown wgftlab "$data"
    vps runuser -u wgftlab -- "$bin" server run --mode "$mode" --data-dir "$data" --wg-endpoint "$WG_ENDPOINT" --admin "$ADMIN" \
      --wg-interface "$WG_INTERFACE" --wg-port "$WG_PORT" --agent-api "$AGENT_API" \
      > "$log" 2>&1 < /dev/null &
  else
    vps "$bin" server run --mode "$mode" --data-dir "$data" --wg-endpoint "$WG_ENDPOINT" --admin "$ADMIN" \
      --wg-interface "$WG_INTERFACE" --wg-port "$WG_PORT" --agent-api "$AGENT_API" \
      > "$log" 2>&1 < /dev/null &
  fi
  SERVER_PID=$!
  disown
  record_pid "$WORK/pid.server" "$SERVER_PID"
}
stop_server() {
  [ -n "$SERVER_PID" ] || return 0
  local real; real=$(leaf_pid "$SERVER_PID")  # resolved now, not at start: by the time we stop
  # something, it has been running and settled for a while, so this is never racing the fork
  # itself (unlike resolving it right after start_server, before the tree exists yet).
  term_group "$SERVER_PID"
  wait_until 10 proc_gone "$real"
  wait_until 10 proc_gone "$SERVER_PID"
  SERVER_PID=""
  rm -f "$WORK/pid.server"
}
start_agent() { # start_agent <bin> <data-dir> <log-file> [join-string]: no join string means
  # "reconnect with whatever is already in <data-dir>/agent.json" (the no-re-enrolment path).
  local bin=$1 data=$2 log=$3 join=${4:-}
  : > "$log"
  WGFT_JOIN="$join" ip netns exec "$NS_HOME" "$bin" agent run --data-dir "$data" \
    > "$log" 2>&1 < /dev/null &
  AGENT_PID=$!
  disown
  record_pid "$WORK/pid.agent" "$AGENT_PID"
}
stop_agent() {
  [ -n "$AGENT_PID" ] || return 0
  local real; real=$(leaf_pid "$AGENT_PID")  # see stop_server's comment on why this is resolved
  # here, at stop time, rather than cached from start time
  term_group "$AGENT_PID"
  wait_until 10 proc_gone "$real"
  wait_until 10 proc_gone "$AGENT_PID"
  AGENT_PID=""
  rm -f "$WORK/pid.agent"
}
start_targets() { # the LAN-side echo (plain rules) and ppecho (the Relay/PROXY-protocol rule).
  lan echo -bind "$LAN_ADDR" \
    -tcp "$T_TCP,$T_ACL,$T_RATES,$T_DISABLED" \
    -udp "$T_UDP,$T_RANGE_LO,$((T_RANGE_LO + 1)),$((T_RANGE_LO + 2))" \
    > "$WORK/lan-echo.log" 2>&1 < /dev/null &
  LAN_ECHO_PID=$!
  disown
  record_pid "$WORK/pid.lan" "$LAN_ECHO_PID"
  lan ppecho -addr "$LAN_ADDR:$T_RELAY" > "$WORK/ppecho.log" 2>&1 < /dev/null &
  PPECHO_PID=$!
  disown
  record_pid "$WORK/pid.ppecho" "$PPECHO_PID"
}
stop_targets() {
  local real_lan real_pp
  real_lan=$(leaf_pid "$LAN_ECHO_PID"); real_pp=$(leaf_pid "$PPECHO_PID")
  term_group "$LAN_ECHO_PID"; term_group "$PPECHO_PID"
  wait_until 10 bash -c "$(printf 'proc_gone %q && proc_gone %q' "$real_lan" "$real_pp")" || true
  LAN_ECHO_PID=""; PPECHO_PID=""
  rm -f "$WORK/pid.lan" "$WORK/pid.ppecho"
}

admin_up() { vps wgft agent ls --admin "$ADMIN" >/dev/null 2>&1; }  # any binary answers the same API; "wgft" (current build) is always on PATH
wait_admin() { wait_until 45 admin_up; }  # 45s, not 15: userspace mode's runuser+wireguard-go
  # startup measured noticeably slower than kernel mode's in the lab, and step4a/4b (a second
  # start_server call in the same run, on a freshly copied data dir) occasionally needed more
  # than 30s under host load in repeat runs; lab/lifecycle.sh's own wait_admin uses 30s for the
  # same base reason, and this adds extra margin for the second start in one script.
# tunnel_reset/tunnel_up/tunnel_state_text: identical idiom (and identical reasoning about why
# tunnel_reset must be awaited BEFORE tunnel_up around a restart, to avoid matching a stale "ok"
# left over from the pre-restart connection) to lab/version-skew.sh's functions of the same name.
tunnel_reset() {
  vps wgft agent ls --admin "$ADMIN" --json 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if d and 'last_heartbeat' not in d[-1] else 1)
"
}
tunnel_up() {
  vps wgft agent ls --admin "$ADMIN" --json 2>/dev/null | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
sys.exit(0 if d and d[-1].get('tunnel', {}).get('state') == 'ok' else 1)
"
}
tunnel_state_text() {
  vps wgft agent ls --admin "$ADMIN" --json 2>/dev/null | python3 -c "
import json, sys
d = json.load(sys.stdin)
t = d[-1].get('tunnel', {}) if d else {}
print('state=%s reason=%s' % (t.get('state'), t.get('reason', '')))
"
}
agent_registered() { vps wgft agent ls --admin "$ADMIN" 2>/dev/null | tail -1 | grep -q home; }
# wait_reconnected <timeout>: the shared "did the agent actually come back up" wait used after
# every start_server/start_agent pairing below (register, THEN reset, THEN up - see tunnel_reset's
# comment on why the reset must be awaited first).
wait_reconnected() {
  wait_until "${1:-40}" agent_registered
  wait_until 20 tunnel_reset
  wait_until 100 tunnel_up
}
tcp_probe_ok() { [[ "$(client "echo hi | timeout -k 5 20 socat -t 1 -T 10 - TCP:198.51.100.1:$1" 2>/dev/null)" == *tcp-echo* ]]; }
udp_probe_ok() { [[ "$(client "echo hi | timeout -k 5 20 socat -t 1 -T 10 - UDP:198.51.100.1:$1" 2>/dev/null)" == *udp-echo* ]]; }
tcp_probe() { client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - TCP:198.51.100.1:$1" 2>/dev/null; }
udp_probe() { client "echo hi | timeout -k 5 20 socat -t 3 -T 10 - UDP:198.51.100.1:$1" 2>/dev/null; }
port_refused() { ! tcp_probe_ok "$1"; }  # wait_until predicate: true once a port that used to
  # forward stops matching tcp-echo. Reuses tcp_probe_ok's exact socat invocation (same timeout
  # -k 5 20 form the harness requires everywhere), so a poll attempt can itself take up to ~10s
  # on a silently-dropped (not RST'd) connection; wait_until's own wall-clock deadline already
  # tolerates a slow predicate, so this is given a generous budget at the call site.

# --- rule creation, one of each representative shape, via <bin>'s own CLI ------------------------
# add_rules <bin>: prints the seven rule ids, one per line, in creation order, for the caller to
# read with `read`.
add_rules() {
  local bin=$1 r
  r=$(vps "$bin" rule add --agent home --tcp "$P_TCP" --to "$LAN_ADDR:$T_TCP" --group upgrade --note "plain tcp" --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+'); echo "$r"
  r=$(vps "$bin" rule add --agent home --udp "$P_UDP" --to "$LAN_ADDR:$T_UDP" --group upgrade --note "plain udp" --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+'); echo "$r"
  r=$(vps "$bin" rule add --agent home --udp "$P_RANGE_LO-$P_RANGE_HI" --to "$LAN_ADDR:$T_RANGE_LO" --group upgrade --note "port range" --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+'); echo "$r"
  r=$(vps "$bin" rule add --agent home --tcp "$P_ACL" --to "$LAN_ADDR:$T_ACL" --group upgrade --note "deny+allow" --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  vps "$bin" rule allow add "$r" 198.51.100.0/24 --admin "$ADMIN" >/dev/null
  vps "$bin" rule deny add "$r" 203.0.113.5/32 --admin "$ADMIN" >/dev/null
  echo "$r"
  r=$(vps "$bin" rule add --agent home --tcp "$P_RATES" --to "$LAN_ADDR:$T_RATES" --group upgrade --note "all three rates" --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
  vps "$bin" rule rate new-flow "$r" 100/second --admin "$ADMIN" >/dev/null
  vps "$bin" rule rate packet "$r" 500/second --admin "$ADMIN" >/dev/null 2>&1  # TCP + packet_rate; output discarded, checked later via the old release's own `rule ls` (old_has)
  vps "$bin" rule rate per-source "$r" 50/second --admin "$ADMIN" >/dev/null
  echo "$r"
  r=$(vps "$bin" rule add --agent home --tcp "$P_DISABLED" --to "$LAN_ADDR:$T_DISABLED" --disabled --group upgrade --note "disabled" --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+'); echo "$r"
  r=$(vps "$bin" rule add --agent home --tcp "$P_RELAY" --to "$LAN_ADDR:$T_RELAY" --proxy --proxy-protocol --group upgrade --note "relay" --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+'); echo "$r"
}

# --- comparison helpers (python3, same convention as lab/lifecycle.sh's $PY dir) -----------------
# stale_cleanup runs first (before anything is written under $WORK): it wipes $WORK, including
# any pid files a previous, aborted run left there, so it must come before PYDIR below writes
# into a $WORK that is about to be wiped out from under it.
stale_cleanup
PYDIR="$WORK/py"
mkdir -p "$PYDIR"
cat > "$PYDIR/compare_rules.py" <<'PYEOF'
# compare_rules.py <old-rules.json> <new-rules.json>: exact field-by-field comparison of the
# "rules" array from `rule ls --json` before and after the upgrade. proto.Rule itself is
# byte-for-byte the same struct in the old release and the current build, for both v0.4.0 and
# v0.5.0 (checked by diffing proto/rule.go across each old tag and HEAD), so no per-rule field
# tolerance is needed or applied here: every field must match exactly, for every rule id present
# on either side. The fields the current build ADDS live one level up, on the list response
# itself (desired_generation, active_generation, rule_states, drift, apply_error, flow_budget,
# resource_refusals - all present in the current build's response, but only some of them absent
# from the old release's own response; see old_has/upgrade.sh's own step3 checks below for which),
# not on individual rules; upgrade.sh's own PASS/FAIL lines report those separately, not through
# this script.
import json
import sys

FIELDS = ["id", "agent", "group", "note", "proto", "listen_port", "target", "vps_mode",
          "proxy_protocol", "source_allow", "source_deny", "new_flow_rate", "packet_rate",
          "per_source_rate", "enabled"]

with open(sys.argv[1]) as f:
    old = {r["id"]: r for r in json.load(f)["rules"]}
with open(sys.argv[2]) as f:
    new = {r["id"]: r for r in json.load(f)["rules"]}

problems = []
if set(old) != set(new):
    problems.append("rule id sets differ: only-before=%s only-after=%s" % (
        sorted(set(old) - set(new)), sorted(set(new) - set(old))))
for rid in sorted(set(old) & set(new)):
    o, n = old[rid], new[rid]
    for field in FIELDS:
        if o.get(field) != n.get(field):
            problems.append("%s.%s: before=%r after=%r" % (rid, field, o.get(field), n.get(field)))

if problems:
    print("\n".join(problems))
    sys.exit(1)
print("%d rules identical across the upgrade" % len(old))
PYEOF
cat > "$PYDIR/stable_cred_hash.py" <<'PYEOF'
# stable_cred_hash.py <agent.json>: sha256 of the credentials fields that must survive an
# upgrade unchanged (name, endpoint, cert hash, permanent token, used join-token hash, wg private
# key - internal/agent/credentials.Credentials' fields other than LastState). LastState is
# excluded on purpose: it is the agent's last-applied full state and is expected to be rewritten
# the moment the agent reconnects and receives a fresh one, so hashing the whole file would always
# differ after a reconnect even with zero re-enrolment; hashing everything BUT LastState isolates
# the actual "same credentials, no rotate-key, no re-registration" claim.
import hashlib
import json
import sys

with open(sys.argv[1]) as f:
    d = json.load(f)
d.pop("last_state", None)
print(hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest())
PYEOF
stable_cred_hash() { python3 "$PYDIR/stable_cred_hash.py" "$1"; }
compare_rules() { python3 "$PYDIR/compare_rules.py" "$1" "$2"; }

# --- teardown (data purge with whichever binary is on hand; either reads the DB fine) ------------
teardown_data() { # teardown_data <bin> <data-dir> <agent-data-dir>
  local bin=$1 data=$2 adata=$3
  vps "$bin" server teardown --data-dir "$data" --purge --yes >/dev/null 2>&1
  vps ip link del wgft0 2>/dev/null
  vps nft delete table inet wgft 2>/dev/null
  rm -rf "$data" "$adata"
}

# ===================================================================================================
# step 1: old release server + agent on fresh data; representative configuration; baseline capture
# ===================================================================================================
fetch_release "$OLD_VERSION" "$CACHE/wgft-v$OLD_VERSION" \
  || { echo "FAIL  setup: could not obtain v$OLD_VERSION (see lab/version-skew.sh's header comment on pre-staging for a VM with no outbound IPv4)"; exit 1; }
OLD_BIN="$CACHE/wgft-v$OLD_VERSION"

DATA="$WORK/server-data"; ADATA="$WORK/agent-data"
mkdir -p "$DATA"

echo "== $mode: step 1: v$OLD_VERSION server + agent, representative configuration"
start_server "$OLD_BIN" "$DATA" "$WORK/step1-server.log"
if ! wait_admin; then
  echo "FAIL  step1: v$OLD_VERSION admin api never came up"; fail=1
  echo "   --- $WORK/step1-server.log ---"; cat "$WORK/step1-server.log"
fi
JOIN=$(vps "$OLD_BIN" agent join-string --name home --admin "$ADMIN" 2>/dev/null | head -1)
start_targets
start_agent "$OLD_BIN" "$ADATA" "$WORK/step1-agent.log" "$JOIN"
if ! wait_until 30 agent_registered; then echo "FAIL  step1: v$OLD_VERSION agent never registered"; fail=1; fi
wait_until 100 tunnel_up
check "step1: tunnel up before any rule" "state=ok" "$(tunnel_state_text)"

mapfile -t RULE_IDS < <(add_rules "$OLD_BIN")
r_tcp=${RULE_IDS[0]}; r_udp=${RULE_IDS[1]}; r_range=${RULE_IDS[2]}; r_acl=${RULE_IDS[3]}
r_rates=${RULE_IDS[4]}; r_disabled=${RULE_IDS[5]}; r_relay=${RULE_IDS[6]}
for id in "${RULE_IDS[@]}"; do
  if [ -z "$id" ]; then echo "FAIL  step1: a rule add did not return an id (see $WORK/step1-*.log)"; fail=1; fi
done

wait_until 15 tcp_probe_ok "$P_TCP"; wait_until 10 udp_probe_ok "$P_UDP"
wait_until 15 tcp_probe_ok "$P_ACL"; wait_until 15 tcp_probe_ok "$P_RATES"
wait_until 15 tcp_probe_ok "$P_RELAY"
wait_until 10 udp_probe_ok "$P_RANGE_LO"
check "step1: plain tcp rule forwards" "tcp-echo" "$(tcp_probe "$P_TCP")"
check "step1: plain udp rule forwards" "udp-echo" "$(udp_probe "$P_UDP")"
check "step1: port-range rule forwards (first port)" "udp-echo" "$(udp_probe "$P_RANGE_LO")"
check "step1: port-range rule forwards (last port)" "udp-echo" "$(udp_probe "$P_RANGE_HI")"
check "step1: deny+allow rule forwards from the allowed source" "tcp-echo" "$(tcp_probe "$P_ACL")"
check "step1: all-three-rates rule forwards" "tcp-echo" "$(tcp_probe "$P_RATES")"
check "step1: relay rule carries the client ip via PROXY protocol" "198.51.100.2" "$(tcp_probe "$P_RELAY")"

# The v0.4.0 dual-stack bug (design.md's revision record): before phase 5 step 3, Relay listeners
# bound both IPv4 and IPv6, so an IPv6 source reached the target instead of being refused. Only
# meaningful to demonstrate when the old release actually still has the bug (old_has false); once
# fixed (v0.5.0 onward) there is nothing left to show on the OLD side, so this half is a stated
# SKIP rather than a repeat of step 5's current-build check below.
if old_has relay_ipv4_only; then
  skip "step1: v$OLD_VERSION's own relay listener is already IPv4-only (phase 5 step 3 predates it in v$OLD_VERSION); no dual-stack bug left to demonstrate on the old side"
elif client "ip -6 addr show dev eth0 | grep -q $CLIENT6" >/dev/null 2>&1; then
  old_relay_v6=$(client "timeout -k 2 3 socat -t 1 -T 2 - TCP6:[$VPS6]:$P_RELAY 2>&1 || true")
  check "step1: v$OLD_VERSION's own relay listener DOES accept an IPv6 source (the dual-stack bug this upgrade fixes)" "client=" "$old_relay_v6"
else
  skip "step1: v$OLD_VERSION dual-stack relay check (client namespace has no IPv6 address configured)"
fi

# baseline: what the old release itself reports (docs/testing.md D4's step 1). Both --json (for
# compare_rules.py, step 3) and plain (for old_has's before/after checks, step 5) are captured,
# since the packet_rate notice and the flow budget line are plain-`rule ls` text, not JSON fields.
vps "$OLD_BIN" rule ls --admin "$ADMIN" --json > "$WORK/old-rules.json"
vps "$OLD_BIN" rule ls --admin "$ADMIN" > "$WORK/old-rulels.stdout" 2>"$WORK/old-rulels.stderr"
vps "$OLD_BIN" agent ls --admin "$ADMIN" --json > "$WORK/old-agents.json"
old_agent_pubkey=$(home "$OLD_BIN" agent pubkey --data-dir "$ADATA")
old_cred_full_sha=$(sha256sum "$ADATA/agent.json" | awk '{print $1}')
old_cred_stable_sha=$(stable_cred_hash "$ADATA/agent.json")
old_server_pubkey=""
if [ "$mode" = kernel ]; then
  old_server_pubkey=$(vps wg show wgft0 public-key)
fi
echo "   baseline: v$OLD_VERSION credentials file sha256 $old_cred_full_sha (whole file; see stable_cred_hash.py for why the post-upgrade check below hashes everything but last_state)"

echo "== $mode: stop v$OLD_VERSION cleanly and snapshot its data (for step 4's partial upgrades)"
stop_agent
stop_server
DATA_SNAPSHOT="$WORK/data-snapshot"; ADATA_SNAPSHOT="$WORK/adata-snapshot"
cp -a "$DATA" "$DATA_SNAPSHOT"
cp -a "$ADATA" "$ADATA_SNAPSHOT"

# ===================================================================================================
# step 2+3: swap ONLY the binaries; start the current build on the SAME data; assert the promises
# ===================================================================================================
# No settings changed between the old release and the current build: `git diff v0.4.0..HEAD` and
# `git diff v0.5.0..HEAD -- cmd/wgft/server.go cmd/wgft/agent.go cmd/wgft/config.go` both show
# only additions (WGFT_AGENT_ALLOW_TARGETS and later flags, and internal-only refactors such as
# perSourceLimitsFromConfig's return shape); every WGFT_* name and flag the old release used is
# still accepted with the same meaning (design 7a.6's external-contract table). So the current
# build below is started with the exact same flags step 1 used.
echo "== $mode: step 2: swap to the current build on v$OLD_VERSION's data"
start_server wgft "$DATA" "$WORK/upgraded-server.log"
okcheck "step2: new server comes up with no extra step (admin api answers)" "$(wait_admin && echo 1 || echo 0)"
absent "step2: no schema/migration error in the new server's log" "applying schema version" "$(cat "$WORK/upgraded-server.log")"
absent "step2: no newer-schema refusal in the new server's log" "is newer than this binary" "$(cat "$WORK/upgraded-server.log")"

start_agent wgft "$ADATA" "$WORK/upgraded-agent.log"  # no join string: existing credentials only
if ! wait_until 40 agent_registered; then
  echo "FAIL  step2: agent never reconnected after the upgrade"; fail=1
  echo "   --- $WORK/upgraded-agent.log ---"; cat "$WORK/upgraded-agent.log"
fi
absent "step3: agent did not need re-enrolment (no \"not registered\" error)" "not registered and no join string" "$(cat "$WORK/upgraded-agent.log")"
wait_until 20 tunnel_reset; wait_until 100 tunnel_up
check "step3: wg tunnel re-establishes after the upgrade" "state=ok" "$(tunnel_state_text)"

vps wgft rule ls --admin "$ADMIN" --json > "$WORK/new-rules.json"
vps wgft agent ls --admin "$ADMIN" --json > "$WORK/new-agents.json"

rules_diff=$(compare_rules "$WORK/old-rules.json" "$WORK/new-rules.json"); rules_rc=$?
okcheck "step3: every rule survives the upgrade, field by field, same id/target/mode/lists/rates/enabled" \
  "$([ "$rules_rc" = 0 ] && echo 1 || echo 0)"
echo "   $rules_diff"

# the fields the new version ADDS live one level up, on the list response, not on individual
# rules (compare_rules.py's own comment has the full list); spot-check that they are actually
# there post-upgrade, rather than only asserting by omission. This much is true of the current
# build regardless of $OLD_VERSION, so it is unconditional.
added_fields_seen=$(python3 -c "
import json
d = json.load(open('$WORK/new-rules.json'))
added = [k for k in ('desired_generation','active_generation','rule_states','drift','flow_budget','resource_refusals') if k in d]
print(','.join(added))
")
check "step3: the post-upgrade response has the generation/drift/budget fields" "active_generation" "$added_fields_seen"
echo "   fields present in the current build's list response (not per rule): $added_fields_seen"

# Whether these fields are actually NEW (absent from the old release's own response) depends on
# $OLD_VERSION: v0.4.0 predates all of them (design 7a.8's phase 4/6 steps), but v0.5.0 already
# has them, so asserting their absence from v0.5.0's own response would be a false claim, not a
# stricter one. old_has gates this the way it gates step 5's checks below.
if old_has generation_fields; then
  skip "step3: v$OLD_VERSION's own rule ls --json already had the generation/drift/budget fields before the upgrade (phase 4/6 predate them in v$OLD_VERSION); not new after this particular upgrade"
else
  old_added_seen=$(python3 -c "
import json
d = json.load(open('$WORK/old-rules.json'))
added = [k for k in ('desired_generation','active_generation','rule_states','drift','flow_budget','resource_refusals') if k in d]
print(','.join(added))
")
  if [ -z "$old_added_seen" ]; then
    echo "PASS  step3: v$OLD_VERSION's own pre-upgrade response had none of those fields (confirms they are genuinely new)"
  else
    echo "FAIL  step3: v$OLD_VERSION's own pre-upgrade response already had: $old_added_seen"; fail=1
  fi
fi

new_agent_pubkey=$(home wgft agent pubkey --data-dir "$ADATA")
strcheck "step3: agent's WireGuard public key is unchanged" "$old_agent_pubkey" "$new_agent_pubkey"
new_cred_stable_sha=$(stable_cred_hash "$ADATA/agent.json")
strcheck "step3: agent's credentials (name/endpoint/cert/token/wg key) are byte-identical, no re-enrolment" \
  "$old_cred_stable_sha" "$new_cred_stable_sha"
new_cred_full_sha=$(sha256sum "$ADATA/agent.json" | awk '{print $1}')
echo "   post-upgrade credentials file sha256 $new_cred_full_sha (differs from the baseline's $old_cred_full_sha because last_state is rewritten on reconnect; see stable_cred_hash.py)"
if [ "$mode" = kernel ]; then
  new_server_pubkey=$(vps wg show wgft0 public-key)
  strcheck "step3: server's WireGuard public key is unchanged" "$old_server_pubkey" "$new_server_pubkey"
else
  skip "step3: server's WireGuard public key (userspace mode has no wgft0 kernel device and no CLI/API exposes the userspace server's own key; only the agent's own key, checked above, is observable)"
fi

check "step3: server log shows the negotiated protocol" "protocol v1" "$(cat "$WORK/upgraded-server.log")"
check "step3: agent log shows the negotiated protocol" "server selected protocol v1" "$(cat "$WORK/upgraded-agent.log")"

wait_until 15 tcp_probe_ok "$P_TCP"; wait_until 10 udp_probe_ok "$P_UDP"
wait_until 15 tcp_probe_ok "$P_ACL"; wait_until 15 tcp_probe_ok "$P_RATES"
wait_until 15 tcp_probe_ok "$P_RELAY"
wait_until 10 udp_probe_ok "$P_RANGE_LO"
check "step3: plain tcp rule forwards again" "tcp-echo" "$(tcp_probe "$P_TCP")"
check "step3: plain udp rule forwards again" "udp-echo" "$(udp_probe "$P_UDP")"
check "step3: port-range rule forwards again (first port)" "udp-echo" "$(udp_probe "$P_RANGE_LO")"
check "step3: port-range rule forwards again (last port)" "udp-echo" "$(udp_probe "$P_RANGE_HI")"
check "step3: deny+allow rule forwards again from the allowed source" "tcp-echo" "$(tcp_probe "$P_ACL")"
check "step3: all-three-rates rule forwards again" "tcp-echo" "$(tcp_probe "$P_RATES")"
check "step3: relay rule still carries the client ip via PROXY protocol" "198.51.100.2" "$(tcp_probe "$P_RELAY")"
disabled_out=$(client "timeout -k 2 3 socat -t 1 -T 2 - TCP:198.51.100.1:$P_DISABLED" 2>&1)
absent "step3: disabled rule still has no listener (no tcp-echo)" "tcp-echo" "$disabled_out"
eqcheck "step3: disabled rule's enabled flag is still false" 0 "$(python3 -c "
import json
d = json.load(open('$WORK/new-rules.json'))
print(1 if any(r['id'] == '$r_disabled' and r['enabled'] for r in d['rules']) else 0)
")"

echo "== $mode: step 3 (deny/allow still bite): two throwaway rules, removed right after"
# Each rule gets a positive control BEFORE its list is added (proves the rule actually forwards,
# so a later "not forwarding" reading cannot be mistaken for "the rule never arrived"), then the
# list, waited for with a wall-clock deadline (not a fixed sleep) until it actually takes effect,
# then the refusal itself, then the list is removed and forwarding is shown to return - proving
# the list, not a dying rule, was the reason it stopped. Without the positive control and the
# "comes back after removal" step, an "absent tcp-echo" reading alone cannot tell a real refusal
# apart from a rule that simply never reached the agent (design's rule-ops delivery path failing
# would look identical to a working deny/allow otherwise).
r_deny_test=$(vps wgft rule add --agent home --tcp 39980 --to "$LAN_ADDR:$T_TCP" --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
wait_until 15 tcp_probe_ok 39980
check "step3: deny-test rule forwards before any deny (positive control, proves delivery)" "tcp-echo" "$(tcp_probe 39980)"
vps wgft rule deny add "$r_deny_test" 198.51.100.0/24 --admin "$ADMIN" >/dev/null
wait_until 40 port_refused 39980
absent "step3: source_deny still bites after the upgrade" "tcp-echo" "$(tcp_probe 39980)"
vps wgft rule deny rm "$r_deny_test" 198.51.100.0/24 --admin "$ADMIN" >/dev/null
wait_until 15 tcp_probe_ok 39980
check "step3: deny-test rule forwards again once the deny is removed (the deny, not a dying rule, was refusing)" "tcp-echo" "$(tcp_probe 39980)"

r_allow_test=$(vps wgft rule add --agent home --tcp 39981 --to "$LAN_ADDR:$T_TCP" --admin "$ADMIN" | grep -oE 'r_[A-Za-z0-9]+')
wait_until 15 tcp_probe_ok 39981
check "step3: allow-test rule forwards before any allow list (positive control, proves delivery)" "tcp-echo" "$(tcp_probe 39981)"
vps wgft rule allow add "$r_allow_test" 203.0.113.0/24 --admin "$ADMIN" >/dev/null  # excludes our client
wait_until 40 port_refused 39981
absent "step3: source_allow still excludes an unlisted source after the upgrade" "tcp-echo" "$(tcp_probe 39981)"
vps wgft rule allow rm "$r_allow_test" 203.0.113.0/24 --admin "$ADMIN" >/dev/null
wait_until 15 tcp_probe_ok 39981
check "step3: allow-test rule forwards again once the excluding allow is removed" "tcp-echo" "$(tcp_probe 39981)"

vps wgft rule rm "$r_deny_test" "$r_allow_test" --admin "$ADMIN" >/dev/null

echo "== $mode: step 3 (file modes and owners, design 9 section)"
db_stat=$(vps stat -c '%a %U' "$DATA/wgft.sqlite")
cred_stat=$(home stat -c '%a %U' "$ADATA/agent.json")
want_db_owner=root; [ "$mode" = userspace ] && want_db_owner=wgftlab
strcheck "step3: server database is 0600" "600" "$(echo "$db_stat" | cut -d' ' -f1)"
strcheck "step3: server database owner is $want_db_owner" "$want_db_owner" "$(echo "$db_stat" | cut -d' ' -f2)"
strcheck "step3: agent credentials file is 0600" "600" "$(echo "$cred_stat" | cut -d' ' -f1)"

# ===================================================================================================
# step 5: behaviour changes an upgrade makes visible (asserted where cheap and robust)
# ===================================================================================================
echo "== $mode: step 5: visible behaviour changes"
rls_out=$(vps wgft rule ls --admin "$ADMIN" 2>"$WORK/rulels.stderr")
check "step5: packet_rate on the TCP rule is kept but the CLI now says it has no effect" \
  "note: packet_rate is stored but has no effect on TCP rules" "$(cat "$WORK/rulels.stderr")"
check "step5: rule ls now reports a flow budget line (Resource Guard, design 7a.10)" "flow budget:" "$rls_out"

# Both checks above are unconditionally true of the CURRENT build, so they hold regardless of
# $OLD_VERSION. Whether that is actually a CHANGE this upgrade made visible - as opposed to
# something the old release already showed on its own, before any upgrade happened - depends on
# $OLD_VERSION: v0.4.0 predates both (phase 5 step 5, phase 6 step 5), v0.5.0 already has both.
if old_has packet_rate_notice; then
  skip "step5: v$OLD_VERSION's own rule ls already showed the packet_rate notice before the upgrade (phase 5 step 5 predates it in v$OLD_VERSION); not a change this upgrade makes visible"
else
  absent "step5: v$OLD_VERSION's own rule ls had NO packet_rate notice before the upgrade (confirms the CLI notice above is genuinely new)" \
    "note: packet_rate is stored but has no effect on TCP rules" "$(cat "$WORK/old-rulels.stderr")"
fi
if old_has flow_budget_line; then
  skip "step5: v$OLD_VERSION's own rule ls already reported a flow budget line before the upgrade (phase 6 step 5 predates it in v$OLD_VERSION); not a change this upgrade makes visible"
else
  absent "step5: v$OLD_VERSION's own rule ls had NO flow budget line before the upgrade (confirms the budget line above is genuinely new)" \
    "flow budget:" "$(cat "$WORK/old-rulels.stdout")"
fi

# a single rule may now use the whole flow budget under flood (design 7a.10, phase 6): not
# re-verified here (that is docs/testing.md L8's job, in the lab suite proper); listed as not
# asserted in this script's own report.

if client "ip -6 addr show dev eth0 | grep -q $CLIENT6" >/dev/null 2>&1; then
  # TCP6:, not TCP: with a bracketed literal - lab/ipv6.sh (L13) uses the same explicit address
  # type for the same reason: an early version of this check used "TCP:[addr]:port" and got a
  # real connection back (through IPv4, not IPv6 - socat's generic TCP: picked a different
  # resolution than intended), which would have been a false FAIL of a correct refusal.
  relay_v6=$(client "timeout -k 2 3 socat -t 1 -T 2 - TCP6:[$VPS6]:$P_RELAY 2>&1 || true")
  absent "step5: relay listener still refuses an IPv6 source after the upgrade" "client=" "$relay_v6"
else
  skip "step5: relay listener IPv4-only check (client namespace has no IPv6 address configured)"
fi

# ===================================================================================================
# step 4: partial upgrades in both orders, on a COPY of step 1's old-release data (not fresh data
# - lab/version-skew.sh already proves the negotiation mechanics with fresh data on both sides)
# ===================================================================================================
echo "== $mode: cleaning up the fully-upgraded instance before the partial-upgrade scenarios"
stop_agent
stop_server
stop_targets

echo "== $mode: step 4a: new server + still-v$OLD_VERSION agent, on a copy of step 1's data"
DATA_A="$WORK/data-a"; ADATA_A="$WORK/adata-a"
cp -a "$DATA_SNAPSHOT" "$DATA_A"; cp -a "$ADATA_SNAPSHOT" "$ADATA_A"
start_targets
start_server "$OLD_BIN" "$DATA_A" "$WORK/step4a-old-server.log"
if wait_admin; then
  start_agent "$OLD_BIN" "$ADATA_A" "$WORK/step4a-old-agent.log"
  wait_reconnected 40
  check "step4a: v$OLD_VERSION+v$OLD_VERSION resumes from the snapshot before the partial upgrade" "state=ok" "$(tunnel_state_text)"
  stop_server  # server side upgrades; the old-release agent (step4a-old-agent) keeps running, untouched
  start_server wgft "$DATA_A" "$WORK/step4a-new-server.log"
  if wait_admin; then
    wait_reconnected 40
    check "step4a: still-v$OLD_VERSION agent reconnects to the upgraded server" "state=ok" "$(tunnel_state_text)"
    wait_until 15 tcp_probe_ok "$P_TCP"; wait_until 10 udp_probe_ok "$P_UDP"
    check "step4a: tcp forwards (new server, old agent, old data)" "tcp-echo" "$(tcp_probe "$P_TCP")"
    check "step4a: udp forwards (new server, old agent, old data)" "udp-echo" "$(udp_probe "$P_UDP")"
  else
    echo "FAIL  step4a: upgraded server's admin api never came up"; fail=1
    echo "   --- $WORK/step4a-new-server.log ---"; cat "$WORK/step4a-new-server.log"
  fi
else
  echo "FAIL  step4a: v$OLD_VERSION server never resumed from the snapshot"; fail=1
  echo "   --- $WORK/step4a-old-server.log ---"; cat "$WORK/step4a-old-server.log"
fi
stop_agent; stop_server; stop_targets
teardown_data wgft "$DATA_A" "$ADATA_A"

echo "== $mode: step 4b: still-v$OLD_VERSION server + new agent, on a copy of step 1's data"
DATA_B="$WORK/data-b"; ADATA_B="$WORK/adata-b"
cp -a "$DATA_SNAPSHOT" "$DATA_B"; cp -a "$ADATA_SNAPSHOT" "$ADATA_B"
start_targets
start_server "$OLD_BIN" "$DATA_B" "$WORK/step4b-old-server.log"
if wait_admin; then
  start_agent "$OLD_BIN" "$ADATA_B" "$WORK/step4b-old-agent.log"
  wait_reconnected 40
  check "step4b: v$OLD_VERSION+v$OLD_VERSION resumes from the snapshot before the partial upgrade" "state=ok" "$(tunnel_state_text)"
  stop_agent  # agent side upgrades; the old-release server keeps running, untouched
  start_agent wgft "$ADATA_B" "$WORK/step4b-new-agent.log"
  wait_reconnected 40
  check "step4b: new agent reconnects to the still-v$OLD_VERSION server" "state=ok" "$(tunnel_state_text)"
  wait_until 15 tcp_probe_ok "$P_TCP"; wait_until 10 udp_probe_ok "$P_UDP"
  check "step4b: tcp forwards (old server, new agent, old data)" "tcp-echo" "$(tcp_probe "$P_TCP")"
  check "step4b: udp forwards (old server, new agent, old data)" "udp-echo" "$(udp_probe "$P_UDP")"
else
  echo "FAIL  step4b: v$OLD_VERSION server never resumed from the snapshot"; fail=1
  echo "   --- $WORK/step4b-old-server.log ---"; cat "$WORK/step4b-old-server.log"
fi
stop_agent; stop_server; stop_targets
teardown_data "$OLD_BIN" "$DATA_B" "$ADATA_B"

# ===================================================================================================
# final cleanup
# ===================================================================================================
teardown_data wgft "$DATA" "$ADATA"
rm -rf "$DATA_SNAPSHOT" "$ADATA_SNAPSHOT"

if [ "$fail" = 0 ]; then echo "== $mode: upgrade: ALL PASS"; else echo "== $mode: upgrade: FAILURES"; fi
exit "$fail"
