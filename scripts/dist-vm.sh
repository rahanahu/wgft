#!/usr/bin/env bash
# dist-vm.sh is B9 in docs/testing.md: the VM test of the DISTRIBUTED artefacts. It creates two
# throwaway Incus VMs (a "server" VM and an "agent" VM, on the same Incus network), installs
# wgft on each exactly as docs/setup.md instructs a user to (the release binary, the shipped
# systemd units in deploy/, the documented env files, ownership and modes), and checks:
#
#   1. the server and the agent start from the SHIPPED units and env files
#   2. a TCP and a UDP rule forward end to end
#   3. forwarding comes back after rebooting each VM (server alone, agent alone, then both),
#      with no manual step
#   4. a configuration error exits 3 and does NOT restart-loop (RestartPreventExitStatus=3)
#   5. the file modes and owners docs/setup.md and docs/design.md section 11a promise
#
# Check 1 currently follows docs/setup.md LITERALLY first, with no modprobe up front: on a
# from-scratch VM this exposes a known, already-reported product defect (nf_conntrack is not
# loaded yet, and the server reads a conntrack sysctl before it ever applies its nftables table,
# which is what would make the kernel auto-load the module; being fixed on fix/server-conntrack-
# start). That literal-procedure failure is recorded as a real, visible FAIL with the exact
# ExecMainStatus/NRestarts evidence, then a clearly labelled "== WORKAROUND: modprobe ==" line
# unblocks the rest of this run's checks. The final summary line says which of three things
# happened: "ALL PASS" (nothing needed, docs/setup.md worked as written - what a fixed product
# should give), "PASS WITH WORKAROUND APPLIED (N times)" (only the known defect fired, N times;
# still a non-zero exit, since the literal procedure did fail), or "FAILURES" (something else,
# unrelated to that known defect, also went wrong). Once fix/server-conntrack-start lands, a
# clean run should say "ALL PASS" with workaround_count staying 0.
#
# Usage:
#   scripts/dist-vm.sh                          # Debian 12 (the default, already cached locally)
#   scripts/dist-vm.sh --image images:ubuntu/24.04
#   scripts/dist-vm.sh --image images:fedora/44
#   scripts/dist-vm.sh --keep-failed            # leave the VMs behind for inspection on failure
#   scripts/dist-vm.sh --upgrade                # also run the upgrade-from-a-previous-release phase
#
# docs/testing.md calls for one distribution per PR and three per release candidate; this script
# takes the distribution as a parameter instead of hard-coding a loop, so a release candidate runs
# it three times.
#
# --upgrade (docs/testing.md D4's own "remaining item" note, the previous-release upgrade this VM
# test did not yet cover): an OPTIONAL, additional phase appended after every check above still
# runs unchanged - the checks above and their duration are the same whether
# or not --upgrade is given. lab/upgrade.sh already proves the in-place upgrade at the netns/process
# level, on both kernel and userspace mode; what it cannot reach is the part that only exists at the
# VM level: a PREVIOUS release installed exactly as docs/setup.md instructed AT THE TIME (its own
# shipped deploy/server.service and deploy/agent.service, not necessarily today's), a binary-only
# swap the way a package upgrade actually happens (overwrite /usr/local/bin/wgft, systemctl restart,
# nothing else touched), and a VM reboot on top of that. This phase reuses the two VMs, the static
# IP, the shipped-unit install and the retry/check/probe/reboot helpers already set up and defined
# above for exactly that reason - a sibling script would either duplicate all of that or have to
# source dist-vm.sh as a library, which it is not written to be (it execs a host-wide flock and a
# capacity check as soon as it is invoked, not on a function call); appending an optional phase here
# keeps the one already-paid-for VM pair and every helper function in scope with no new plumbing.
#
# The previous release defaults to the newest tag reachable from HEAD (WGFT_DIST_VM_UPGRADE_OLD_VERSION
# overrides it, unprefixed, e.g. "0.4.0" - the same convention as lab/upgrade.sh's
# WGFT_UPGRADE_OLD_VERSION); its linux-amd64 binary is fetched and sha256-verified on the HOST (this
# host reaches GitHub; the VMs are not assumed to, same reasoning as lab/oldrelease.sh, whose
# fetch_release this sources and reuses rather than copying) and pushed into both VMs with
# "incus file push", the same way the current build already is above.
#
# Scenario, against the SAME two VMs and the SAME two data directories throughout: install the old
# release fresh (its own tag's units, a fresh join, a representative rule of every shape
# lab/upgrade.sh uses: plain TCP, plain UDP, a UDP port range, a source_deny+source_allow rule, a TCP
# rule with all three rates, a disabled rule, a Relay/PROXY-protocol rule) and prove it forwards; back
# up the data directory as v0.5.1's release notes' "Upgrading" section tells operators to; swap ONLY
# the server binary and restart, and check the rules survive field by field (ignoring the fields the
# new build adds to the list response, never to a rule itself), the agent reconnects with no
# re-enrolment, forwarding still works, and "wgft server check" is clean; swap the agent binary the
# same way; reboot the server VM, then the agent VM, and check forwarding comes back unaided. Each
# restart's forwarding outage is measured and printed - an informative number, not an assertion; the
# project makes no numeric promise about it (docs/testing.md's "update and rollback promise"
# section). Whether an operator
# who ALSO updates the unit files ends up anywhere different is decided at runtime by diffing the old
# tag's units against deploy/*.service with comments stripped: identical (the case for v0.5.1, checked
# when this was written) means the binary-only swap already covers it and that second case is not run
# separately; a real difference is reported instead of silently skipped. Downgrading is not promised
# and not exercised here. A single pass only (old server + old agent, then server-first, then
# agent-first swap order); the reverse swap order (agent first) is not run - see the report for why.
#
# Topology (2 VMs, not 3): the "server" VM runs wgft server (kernel mode). The "agent" VM runs
# wgft agent and also hosts the target service (tools/echo, bound to 127.0.0.1 on the agent VM,
# standing in for a LAN game server next to the agent). The "client" is this HOST for TCP: the
# Incus bridge (incusbr0) puts the host on the same L2 network as both VMs, so a TCP probe sent
# from the host to the server VM's address arrives over a real network interface and is genuinely
# DNATed by the server's nftables/kernel WireGuard data plane, the same path a real internet
# client's packet would take. What this topology does NOT prove: real internet-facing NAT, a real
# public IP, or the agent's own LAN reachability beyond its own loopback (the target is local to
# the agent VM, not a separate LAN host).
#
# UDP is probed from the AGENT VM instead, not the host (judgement call, see the report to the
# caller for the full diagnostic trail). Diagnosed with a dedicated, isolated VM pair: a
# host-originated UDP probe consistently failed (the encrypted WireGuard packet demonstrably
# reached the agent VM's own kernel UDP socket with zero errors - confirmed via
# /proc/net/nf_conntrack showing the DNAT'd reply tuple and via /proc/net/snmp's Udp: InDatagrams
# incrementing - but the agent's own process never sent anything onward, confirmed via
# OutDatagrams staying flat and tools/echo's target logging no "udp ... from=" line at all), while
# the identical rule, probed from the agent VM itself to the server's address (a VM-to-VM packet
# that never originates on the host), got a correct reply on the first try. TCP from the host
# works reliably in every run. This points at the HOST's own environment (this host runs Docker
# with br_netfilter, firewalld, and cannot even do DHCPv4 on this bridge - see the
# "Networking workaround" note below; incusbr0's bridge devices show nf_call_iptables=0, meaning
# VM-to-VM bridged traffic skips the host's iptables/nftables entirely, while host-originated
# traffic does not), not at wgft: a host-originated UDP round trip depends on the host's own
# firewall correctly tracking and admitting the reply, and TCP vs. UDP conntrack/firewall handling
# commonly differs in exactly this way. This is a test-environment limitation, not a product
# finding, and the agent-VM-as-client probe still genuinely exercises the DNAT/tunnel/relay path
# end to end (the client and the final target happen to be the same VM, which the wall of
# encryption and the two independent DNAT/un-DNAT translations do not shortcut).
#
# Networking workaround (judgement call, see the report to the caller): this host's Incus bridge
# fails DHCPv4 entirely (lab/README.md, "VM が IPv4 で外に出られない"; confirmed here: VMs get no
# IPv4 address at all, only IPv6, even for local bridge traffic). wgft is IPv4-only, so this
# script assigns each VM a static IPv4 address on the bridge's own subnet (allowed by this test's
# brief: "the Incus bridge's own addresses"). The assignment is written to a persistent network
# config file (systemd-networkd or NetworkManager, whichever the image runs), not applied ad hoc,
# so it survives the reboots that check 3 requires without the script re-poking the network after
# each boot - that would look like the script recovering the environment instead of wgft/systemd
# recovering on their own.
#
# No package is installed inside a VM: wgft applies nftables and WireGuard over netlink itself
# (internal/dataplane/linuxkernel), not by shelling out to nft(8)/wg(8), so the base VM images
# need nothing extra for the product under test. Only useradd(8) (core, always present) is used,
# to create the agent's system user exactly as docs/setup.md's systemd section instructs. The
# wgft binary, the two shipped unit files, and two disposable test-only helpers (tools/echo as
# the target, and the new tools/probe as the client run from the host) are all pushed from the
# host with "incus file push"; nothing is downloaded inside a VM.
#
# Artefacts: built the way a release does, with GoReleaser in snapshot mode
# ("goreleaser release --snapshot --clean --skip=publish", CI's release-snapshot job), if a
# `goreleaser` binary is on PATH. This host has no such binary installed (only a `go run
# .../goreleaser/v2@latest`, which needs a newer Go toolchain than is pinned locally and would
# have this script silently fetch one over the network on every run), so by default this script
# falls back to `go build` with the same ldflags/trimpath/CGO_ENABLED=0 .goreleaser.yaml uses, and
# says so. Either way dist/wgft-linux-amd64 is installed from its own archive-shaped output
# (binary + a self-computed sha256 file, verified with "sha256sum -c" inside each VM exactly as
# docs/setup.md step 1 shows), not from the source tree.
#
# One run at a time, host-wide: a host lock (see the "host-wide mutual exclusion" section below,
# right after the -h/--help handling) refuses a second concurrent dist-vm.sh outright, with no
# wait, before it creates anything. This is separate from, and not bypassed by, --force.
#
# VM budget: creates at most 2 VMs, named wgft-dist-<id>-server / -agent (a prefix distinct from
# lab/'s wgft-eph- ephemeral VMs and the shared wgft-lab* dev VMs), and never touches an instance
# it did not create. Before launching, it checks the host's total running instance count (shared
# with everyone else's lab VMs, not just this script's own) and its 1-minute load average, and
# REFUSES to start (exit 2) if the host is at or over 15 running instances or a load average of
# 16, after a short wait-and-recheck window; --force skips only this capacity check and starts
# anyway. Cleans up on exit, INT and TERM; --keep-failed leaves the two VMs behind (undeleted)
# whenever this run's own exit code is non-zero, for inspection - not just when a check inside the
# run explicitly failed, so an early failure (a VM that never finished launching, for example)
# is kept too.
set -u
cd "$(dirname "$0")/.."
REPO=$(pwd)

IMAGE=images:debian/12
KEEP_FAILED=0
FORCE=0
UPGRADE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --image) IMAGE=$2; shift 2 ;;
    --image=*) IMAGE=${1#--image=}; shift ;;
    --keep-failed) KEEP_FAILED=1; shift ;;
    --force) FORCE=1; shift ;;
    --upgrade) UPGRADE=1; shift ;;
    -h | --help)
      sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *) echo "dist-vm: unknown argument: $1" >&2; exit 2 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "dist-vm: '$1' not found" >&2; exit 2; }; }
need incus
need go
need ping
need flock

# --- host-wide mutual exclusion: only one dist-vm.sh run at a time -------------------------------
# Serialises the whole of B9 per host. Static IP selection below picks a free address by pinging
# for one (a TOCTOU race), so two concurrent runs could pick the same address; the simplest fix is
# to never let two runs overlap at all. Acquired here, before the capacity check and the artefact
# build, so a refused run costs nothing (no tmp dir, no build, no VM). Held open for this
# process's entire lifetime and only ever released by the kernel closing the fd, which happens on
# any exit path, including SIGKILL, so there is no stale-lock state to clean up and no pid file
# that needs to be trusted for the locking decision itself (the pid this script writes into the
# lock file below is for a human to read with `cat`, nothing more; a second flock(2) call is what
# actually decides "in use", so a stale value there cannot cause a false "in use" reading).
# --force bypasses only the capacity check below, never this lock: a second concurrent run would
# still race on IP addresses regardless of host load, which --force says nothing about.
#
# Fd inheritance: bash does not mark fds opened with `exec {var}<>file` close-on-exec (checked
# empirically; no fcntl/CLOEXEC builtin exists to change that), so EVERY external command this
# script runs (sleep, incus, ping, ...) inherits LOCK_FD by default. That is harmless as long as
# this script is the one waiting for each of those commands to finish, which is true everywhere
# except: the two `reboot_and_wait ... &` background jobs in check 3c, which explicitly close
# their inherited copy first (they could otherwise keep running, and keep the lock, well after a
# killed parent is gone); and the three sleeps of 20s or 60s (in check_capacity and check 4), which
# do the same with a per-command `{LOCK_FD}>&-` redirection, since those are long enough to matter.
# The many remaining short waits (1-5s, mostly one `sleep 1` per iteration of retry() and similar
# loops) are left alone: if this script is killed with SIGKILL at the exact instant one of them is
# running, that one process becomes a harmless orphan holding a copy of the lock for at most a few
# seconds until it exits on its own, after which the lock is genuinely free - a documented, bounded
# trade-off rather than an unbounded stale lock, and not worth chasing down every call site for.
#
# Lock path: ${XDG_RUNTIME_DIR:-/tmp}/wgft-dist-vm.lock. XDG_RUNTIME_DIR is per-user (mode 0700,
# usually tmpfs, cleared at logout), so two DIFFERENT users on this host running dist-vm.sh at the
# same time would each get their own lock file and would NOT exclude each other. Accepted: this
# host's B9 runs are all done by developers and agents operating as the same Unix user (see
# lab/README.md's account model), so a second, different user racing this one on static IP
# selection is already an unsupported scenario this script does not otherwise guard against
# either (see the "Networking workaround" note above). A single fixed /tmp path shared by every
# user would over-serialise unrelated users' runs instead, which is worse for the common case here.
LOCK_PATH="${XDG_RUNTIME_DIR:-/tmp}/wgft-dist-vm.lock"
# <> (not >): must not truncate a file another, currently-lock-holding run might read from or
# write to; this process only ever writes to it after flock below proves it is the sole holder.
exec {LOCK_FD}<>"$LOCK_PATH" || { echo "dist-vm: cannot open lock file $LOCK_PATH" >&2; exit 2; }
if ! flock -n "$LOCK_FD"; then
  holder=$(cat "$LOCK_PATH" 2>/dev/null)
  echo "dist-vm: another dist-vm.sh run holds the lock ($LOCK_PATH)${holder:+, pid $holder}; refusing to start (this run does not wait for it to finish)." >&2
  exit 4
fi
printf '%s\n' "$$" >"$LOCK_PATH"

# Leftover wgft-dist-* VMs from a run that was killed with SIGKILL (which cannot run its own
# cleanup trap, so its VMs outlive it) do not stale-lock the run above - the flock already proved
# no dist-vm.sh is currently running - but they do sit around consuming the shared VM budget.
# Report them by name; never delete them here automatically, since a name match alone is not proof
# by itself. The pid embedded in the name (wgft-dist-<timestamp>-<pid>-server/agent) is: if that
# pid is not running, the VM is provably not owned by any live dist-vm.sh (pid reuse by the OS
# aside, which is rare enough not to guard against here).
for leftover in $(incus list -c n -f csv 2>/dev/null | grep -E '^wgft-dist-[0-9]+-[0-9]+-(server|agent)$'); do
  leftover_pid=${leftover%-server}
  leftover_pid=${leftover_pid%-agent}
  leftover_pid=${leftover_pid##*-}
  if ! kill -0 "$leftover_pid" 2>/dev/null; then
    echo "dist-vm: warning: leftover VM '$leftover' from a dist-vm.sh run whose pid $leftover_pid is no longer running (likely killed with SIGKILL); delete it with: incus delete -f $leftover" >&2
  fi
done

id="$(date +%Y%m%d%H%M%S)-$$"
server_vm="wgft-dist-$id-server"
agent_vm="wgft-dist-$id-agent"
tmp=$(mktemp -d)
started=$(date +%s)

fail=0
# workaround_count: incremented by bring_up_server() each time it had to apply the nf_conntrack
# modprobe workaround (see its own comment). unexpected_fail: any FAIL other than that known,
# already-reported product defect (fix/server-conntrack-start). Together these let the final
# summary tell a truly clean run apart from one that only passed because the workaround papered
# over the still-open defect, and both apart from a genuinely unexpected regression.
workaround_count=0
unexpected_fail=0
check() { # check <label> <expected-substring> <actual>: returns 1 on FAIL so callers can react
  # (e.g. dump extra diagnostics), in addition to setting $fail for the run's final exit code.
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug)"; fail=1; unexpected_fail=1; return 1; fi
  case "$3" in
    *"$2"*) echo "PASS  $1"; return 0 ;;
    *) echo "FAIL  $1: got '$3'"; fail=1; unexpected_fail=1; return 1 ;;
  esac
}
eqcheck() { # eqcheck <label> <want> <got>: exact integer comparison.
  if [ "$2" -eq "$3" ] 2>/dev/null; then echo "PASS  $1 ($2)"; else echo "FAIL  $1: got '$3', want '$2'"; fail=1; unexpected_fail=1; fi
}
# absent/strcheck: only used by the --upgrade phase (below), same idiom as lab/upgrade.sh's
# functions of the same name. Defined here with the other check helpers so every check function
# lives in one place; harmless and unused when --upgrade is not given.
absent() { # absent <label> <substring-that-must-not-appear> <actual>
  if [ -z "$2" ]; then echo "FAIL  $1: empty substring (test bug)"; fail=1; unexpected_fail=1; return 1; fi
  case "$3" in
    *"$2"*) echo "FAIL  $1: got '$3'"; fail=1; unexpected_fail=1; return 1 ;;
    *) echo "PASS  $1"; return 0 ;;
  esac
}
strcheck() { # strcheck <label> <want> <got>: exact string equality (keys, hashes, ids - check()'s
  # substring match would let one value that is a prefix of another slip through).
  if [ -z "$2" ]; then echo "FAIL  $1: empty expectation (test bug or a capture that returned nothing)"; fail=1; unexpected_fail=1; return 1; fi
  if [ "$2" = "$3" ]; then echo "PASS  $1"; return 0; else echo "FAIL  $1: got '$3', want '$2'"; fail=1; unexpected_fail=1; return 1; fi
}
teeth_pass() { echo "PASS  teeth: $1"; }
teeth_fail() { echo "FAIL  teeth: $1"; fail=1; unexpected_fail=1; }

retry() { # retry <timeout-seconds> <command...>: polls once a second up to the deadline.
  local timeout=$1 i=0
  shift
  until "$@" >/dev/null 2>&1; do
    i=$((i + 1))
    [ "$i" -ge "$timeout" ] && return 1
    sleep 1
  done
  return 0
}

# cleanup runs on EXIT, INT and TERM. It never deletes a VM this run did not create, and it never
# backgrounds the VMs' owning shell (bash ignores SIGINT in a background job), so INT/TERM here
# hits this script's own trap directly. --keep-failed triggers on $rc (this run's actual exit
# code), not just $fail: several early failures (a VM failing to launch, the incus agent never
# coming up, no free static IP, and others) exit 1 directly, before $fail is ever touched, so
# checking $fail alone would silently drop --keep-failed for exactly the early-failure case it is
# most useful for (inspecting a VM that failed between creation and a full install).
cleanup() {
  local rc=$?
  if { [ "$fail" != 0 ] || [ "$rc" != 0 ]; } && [ "$KEEP_FAILED" = 1 ]; then
    echo "dist-vm: --keep-failed: leaving $server_vm and $agent_vm for inspection" >&2
  else
    incus delete -f "$server_vm" "$agent_vm" >/dev/null 2>&1
  fi
  rm -rf "$tmp"
  return "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "== dist-vm: image=$IMAGE server=$server_vm agent=$agent_vm"

# --- host capacity: shared with everyone else's VMs, so check before creating any ---------------
# Hard rule (the host's owner set an explicit ceiling of 16 running instances in total, shared
# across concurrent developers and agents): refuse to start at 15 or more running instances, or a
# 1-minute load average above 16, rather than silently queuing. A short wait-and-recheck window
# (5 minutes) covers an instance that is about to finish; past that, this run gets out of the way
# instead of piling on. --force bypasses the check entirely for an operator who has confirmed by
# hand that starting anyway is fine.
check_capacity() {
  if [ "$FORCE" = 1 ]; then
    echo "dist-vm: --force: skipping the host capacity check" >&2
    return 0
  fi
  local waited=0
  while :; do
    local n load1 busy
    n=$(incus list -c s -f csv 2>/dev/null | grep -c '^RUNNING$')
    load1=$(cut -d' ' -f1 /proc/loadavg)
    busy=$(awk -v l="$load1" 'BEGIN{print (l>16)?1:0}')
    if [ "$n" -lt 15 ] && [ "$busy" = 0 ]; then return 0; fi
    if [ "$waited" -ge 300 ]; then
      echo "dist-vm: refusing to start: host at $n running instances (limit 15) or load1=$load1 (limit 16)." >&2
      echo "dist-vm: this host's total instance budget is shared; wait for other work to finish and retry, or pass --force." >&2
      return 1
    fi
    echo "dist-vm: host busy (running=$n load1=$load1); waiting 60s and rechecking (up to $((300 - waited))s more)..." >&2
    # {LOCK_FD}>&- here (and on the two other long sleeps below): sleep(1) is a separate forked
    # process that would otherwise inherit LOCK_FD and, if this script were killed with SIGKILL
    # while it is running, would keep the host lock held on its own for up to its own duration.
    # Closing the fd just for this one command keeps the main shell's own copy (and the lock)
    # untouched. See the header comment for why the many short (1-5s) sleeps elsewhere are not
    # worth doing this for.
    sleep 60 {LOCK_FD}>&-
    waited=$((waited + 60))
  done
}
check_capacity || exit 2

# --- build the product artefact the way a release does, or say why not --------------------------
version="v0.0.0-dist-test-$(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo dev)"
if command -v goreleaser >/dev/null 2>&1; then
  echo "== build: goreleaser (installed on this host, snapshot mode)"
  ( cd "$REPO" && goreleaser release --snapshot --clean --skip=publish ) >"$tmp/build.log" 2>&1
  build_rc=$?
  if [ "$build_rc" -ne 0 ] || [ ! -f "$REPO/dist/wgft-linux-amd64" ]; then
    tail -n 60 "$tmp/build.log" >&2
    echo "FAIL  build wgft via goreleaser"
    exit 1
  fi
  server_bin="$REPO/dist/wgft-linux-amd64"
  server_sum="$REPO/dist/wgft-linux-amd64.sha256"
else
  echo "== build: goreleaser not installed on this host; falling back to 'go build' with the"
  echo "   same flags .goreleaser.yaml uses (CGO_ENABLED=0, -trimpath, matching -ldflags)"
  mkdir -p "$tmp/dist"
  if ! ( cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
      -ldflags "-s -w -X github.com/rahanahu/wgft/internal/buildinfo.Version=$version" \
      -o "$tmp/dist/wgft-linux-amd64" ./cmd/wgft ) >"$tmp/build.log" 2>&1; then
    cat "$tmp/build.log" >&2
    echo "FAIL  build wgft via go build"
    exit 1
  fi
  ( cd "$tmp/dist" && sha256sum wgft-linux-amd64 >wgft-linux-amd64.sha256 )
  server_bin="$tmp/dist/wgft-linux-amd64"
  server_sum="$tmp/dist/wgft-linux-amd64.sha256"
fi
echo "PASS  build product artefact ($server_bin)"

# Two disposable test-only helpers, built the same way scripts/docker-smoke.sh builds tools/echo:
# plain `go build`, never part of a release archive. tools/probe (new, alongside tools/echo and
# tools/ppecho) is a tiny static TCP/UDP client, needed because a fresh VM image has no socat or
# python3 and this test must not apt-get anything into one.
if ! ( cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$tmp/echo" ./tools/echo ) >"$tmp/echo-build.log" 2>&1; then
  cat "$tmp/echo-build.log" >&2
  echo "FAIL  build tools/echo"
  exit 1
fi
if ! ( cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$tmp/probe" ./tools/probe ) >"$tmp/probe-build.log" 2>&1; then
  cat "$tmp/probe-build.log" >&2
  echo "FAIL  build tools/probe"
  exit 1
fi
echo "PASS  build tools/echo and tools/probe (test-only helpers, not release artefacts)"

# --- launch the two VMs ---------------------------------------------------------------------
echo "== launch $server_vm and $agent_vm ($IMAGE)"
if ! incus launch "$IMAGE" "$server_vm" --vm -c limits.cpu=1 -c limits.memory=1GiB >"$tmp/launch.log" 2>&1; then
  cat "$tmp/launch.log" >&2
  echo "FAIL  launch $server_vm"
  exit 1
fi
if ! incus launch "$IMAGE" "$agent_vm" --vm -c limits.cpu=1 -c limits.memory=1GiB >>"$tmp/launch.log" 2>&1; then
  cat "$tmp/launch.log" >&2
  echo "FAIL  launch $agent_vm"
  exit 1
fi

wait_ready() { # wait_ready <vm>: the incus-agent inside a freshly created VM needs a moment.
  retry 180 incus exec "$1" -- true
}
wait_ready "$server_vm" || { echo "FAIL  $server_vm: incus agent never became ready"; exit 1; }
wait_ready "$agent_vm" || { echo "FAIL  $agent_vm: incus agent never became ready"; exit 1; }
echo "PASS  both VMs booted and reachable via incus exec"

# --- static IPv4 on the Incus bridge's own subnet (see the header comment) ----------------------
bridge_net=incusbr0
bridge_cidr=$(incus network get "$bridge_net" ipv4.address 2>/dev/null)
[ -n "$bridge_cidr" ] || { echo "FAIL  could not read ipv4.address of $bridge_net"; exit 1; }
net_base=${bridge_cidr%.*}          # e.g. 10.151.78 from 10.151.78.1/24
net_prefix=${bridge_cidr#*/}        # e.g. 24

pick_ip() { # pick_ip <start>: first address in [start,250] on this subnet that does not answer a ping.
  local i
  for i in $(seq "$1" 250); do
    local cand="$net_base.$i"
    ping -c1 -W1 "$cand" >/dev/null 2>&1 || { echo "$cand"; return 0; }
  done
  return 1
}
server_ip=$(pick_ip 200) || { echo "FAIL  no free address for $server_vm on $bridge_cidr"; exit 1; }
agent_ip=$(pick_ip $((${server_ip##*.} + 1))) || { echo "FAIL  no free address for $agent_vm on $bridge_cidr"; exit 1; }

cat >"$tmp/netstatic.sh" <<'NETEOF'
#!/bin/sh
# Applied once per VM by dist-vm.sh: give the VM a persistent static IPv4 address on its own
# subnet, because this host's Incus bridge cannot hand out DHCPv4 (see dist-vm.sh's header
# comment). Persistent (survives reboot) so check 3 does not need the script to re-touch the
# network after each reboot.
set -eu
ip=$1
prefix=$2
iface=$(ip -o link show up | awk -F': ' '$2 != "lo" { print $2; exit }')
[ -n "$iface" ] || { echo "netstatic: no non-loopback interface found" >&2; exit 1; }
if systemctl is-active --quiet NetworkManager 2>/dev/null; then
  nmcli con add type ethernet ifname "$iface" con-name wgft-dist-static \
    ipv4.method manual ipv4.addresses "$ip/$prefix" ipv6.method ignore autoconnect yes >/dev/null
  nmcli con up wgft-dist-static >/dev/null
else
  mkdir -p /etc/systemd/network
  printf '[Match]\nName=%s\n\n[Network]\nAddress=%s/%s\nDHCP=no\n' "$iface" "$ip" "$prefix" \
    >/etc/systemd/network/00-wgft-dist-static.network
  systemctl restart systemd-networkd
fi
echo "netstatic: $iface -> $ip/$prefix"
NETEOF

incus file push "$tmp/netstatic.sh" "$server_vm/root/netstatic.sh" --mode 0755 >/dev/null
incus file push "$tmp/netstatic.sh" "$agent_vm/root/netstatic.sh" --mode 0755 >/dev/null
incus exec "$server_vm" -- /root/netstatic.sh "$server_ip" "$net_prefix" >"$tmp/netstatic.server.log" 2>&1
incus exec "$agent_vm" -- /root/netstatic.sh "$agent_ip" "$net_prefix" >"$tmp/netstatic.agent.log" 2>&1
retry 30 ping -c1 -W1 "$server_ip" || { cat "$tmp/netstatic.server.log" >&2; echo "FAIL  $server_vm: static IP $server_ip never came up"; exit 1; }
retry 30 ping -c1 -W1 "$agent_ip" || { cat "$tmp/netstatic.agent.log" >&2; echo "FAIL  $agent_vm: static IP $agent_ip never came up"; exit 1; }
echo "PASS  static IPv4 on $bridge_cidr: server=$server_ip agent=$agent_ip"

# Open firewalld's ports if the image has it active; never installed, only configured with the
# tool already on the image, exactly as docs/setup.md's firewalld example shows. A Fedora Server
# or Workstation install has firewalld active by default, but the Incus image images:fedora/44
# that this script launches ships neither firewalld (`rpm -q firewalld` finds nothing) nor an
# SELinux policy (getenforce: Disabled; no selinux-policy package, though /sys/fs/selinux is
# mounted). On that image this function does nothing, so a host with firewalld active and a host
# with SELinux enforcing are both UNVERIFIED by this script.
open_firewall() { # open_firewall <vm> <port-flags...>
  if incus exec "$1" -- systemctl is-active -q firewalld 2>/dev/null; then
    shift
    incus exec "$1" -- firewall-cmd --permanent "$@" >/dev/null 2>&1
    incus exec "$1" -- firewall-cmd --reload >/dev/null 2>&1
  fi
}

# --- install and start the server from the shipped unit (docs/setup.md "Configure the VPS") -----
echo "== install server: kernel mode, from the archive contents and deploy/server.service"
incus file push "$server_bin" "$server_vm/root/wgft-linux-amd64" --mode 0644 >/dev/null
incus file push "$server_sum" "$server_vm/root/wgft-linux-amd64.sha256" --mode 0644 >/dev/null
incus file push "$REPO/deploy/server.service" "$server_vm/root/server.service" --mode 0644 >/dev/null
incus file push "$tmp/probe" "$server_vm/root/probe" --mode 0755 >/dev/null

sumcheck=$(incus exec "$server_vm" --cwd /root -- sha256sum -c wgft-linux-amd64.sha256 2>&1)
check "server: sha256sum -c on the pushed archive contents (docs/setup.md step 1)" "OK" "$sumcheck"

incus exec "$server_vm" -- install -m 0755 /root/wgft-linux-amd64 /usr/local/bin/wgft
incus exec "$server_vm" -- mkdir -p /etc/wgft
printf 'WGFT_MODE=kernel\nWGFT_WG_ENDPOINT=%s:51820\n' "$server_ip" >"$tmp/server.env"
incus file push "$tmp/server.env" "$server_vm/etc/wgft/server.env" --mode 0644 >/dev/null

# 'wgft server check' before the first start, exactly as docs/setup.md's kernel-mode section
# shows. On a from-scratch VM this currently prints a conntrack warning (nf_conntrack not loaded
# yet; see the report to the caller) but still exits 0, so record that fact without failing on it.
check_out=$(incus exec "$server_vm" -- wgft server check 2>&1)
check_rc=$?
eqcheck "server: 'wgft server check' exits 0 on a clean VM" "0" "$check_rc"
case "$check_out" in
  *"is the nf_conntrack module loaded"*) echo "dist-vm: note: 'wgft server check' already warned about nf_conntrack before the first start" ;;
esac
open_firewall "$server_vm" --add-port=51820/udp --add-port=8443/tcp

incus exec "$server_vm" -- install -m 0644 /root/server.service /etc/systemd/system/wgft.service
incus exec "$server_vm" -- systemctl daemon-reload

# wait_for_log_since/-boot scope the journal so a STALE line from an earlier successful start in
# the same boot cannot make a later wait trivially pass (journald keeps a unit's whole history
# across systemctl restarts within one boot; a naive unscoped grep for "server started" would
# match the very first start forever, even after later checks deliberately break the unit).
wait_for_log_since() { # wait_for_log_since <vm> <unit> <since-epoch> <needle>
  incus exec "$1" -- journalctl -u "$2" -b --no-pager -q --since "@$3" 2>/dev/null | grep -q "$4"
}
wait_for_log_boot() { # wait_for_log_boot <vm> <unit> <needle>: anywhere in the CURRENT boot; used
  # right after a VM reboot, where the current boot cannot contain a stale line from before it.
  incus exec "$1" -- journalctl -u "$2" -b --no-pager -q 2>/dev/null | grep -q "$3"
}

# bring_up_server <label>: assumes 'systemctl enable --now wgft' or 'systemctl restart wgft' (or a
# VM reboot with the unit enabled) was JUST done. Waits, unaided, for "server started". docs/setup.md
# is followed LITERALLY here: no modprobe up front. On a from-scratch boot this currently times out
# (nf_conntrack is not loaded yet, and wgft reads a conntrack sysctl before it ever applies its
# nftables table, which is what would make the kernel auto-load the module - confirmed against the
# code and reproduced live in this lab; reported to the caller as a product startup-ordering
# question, not settled here as a docs-only issue). That is recorded as a genuine, visible FAIL,
# matching what check 1 exists to catch. An explicit, clearly-labelled workaround then loads the
# module so the REST of this run's checks can still exercise the server; the run's exit code still
# reflects the literal-procedure failure via $fail.
# <mode> is "since" (default; a restart this call itself just issued) or "boot" (right after a VM
# reboot, where the unit auto-starts on its own and "since" could race the very first attempt).
bring_up_server() {
  local label=$1 mode=${2:-since} since nrestarts execstatus started=0
  if [ "$mode" = boot ]; then
    retry 20 wait_for_log_boot "$server_vm" wgft "server started" && started=1
  else
    since=$(incus exec "$server_vm" -- date +%s)
    retry 20 wait_for_log_since "$server_vm" wgft "$since" "server started" && started=1
  fi
  if [ "$started" = 1 ]; then
    echo "PASS  $label: server starts unaided from the shipped unit and env"
    return 0
  fi
  nrestarts=$(incus exec "$server_vm" -- systemctl show -p NRestarts --value wgft 2>&1)
  execstatus=$(incus exec "$server_vm" -- systemctl show -p ExecMainStatus --value wgft 2>&1)
  echo "FAIL  $label: server does not start unaided (ExecMainStatus=$execstatus NRestarts=$nrestarts and climbing; nf_conntrack not loaded, see the report)"
  fail=1
  workaround_count=$((workaround_count + 1))
  echo "== WORKAROUND: modprobe nf_conntrack so the rest of this run's checks can still exercise the server (docs/setup.md interim note; a product fix is under discussion) =="
  incus exec "$server_vm" -- modprobe nf_conntrack
  incus exec "$server_vm" -- systemctl reset-failed wgft >/dev/null 2>&1
  since=$(incus exec "$server_vm" -- date +%s)
  incus exec "$server_vm" -- systemctl restart wgft
  if retry 30 wait_for_log_since "$server_vm" wgft "$since" "server started"; then
    echo "PASS  $label (after the modprobe workaround): server starts once nf_conntrack is loaded"
    return 0
  fi
  echo "FAIL  $label (after the modprobe workaround): server still does not start; this run cannot continue meaningfully"
  unexpected_fail=1 # the known workaround itself failing is well beyond the expected defect
  return 1
}

incus exec "$server_vm" -- systemctl enable --now wgft
bring_up_server "check1: server starts from the shipped server.service" || exit 1

# --- install and start the agent from the shipped unit (docs/setup.md "Run the agent with systemd") ---
echo "== install agent: from the archive contents and deploy/agent.service"
join=$(incus exec "$server_vm" -- wgft agent join-string --name home 2>/dev/null | head -1)
check "server: join string issued" "wgft://" "$join"

incus file push "$server_bin" "$agent_vm/root/wgft-linux-amd64" --mode 0644 >/dev/null
incus file push "$server_sum" "$agent_vm/root/wgft-linux-amd64.sha256" --mode 0644 >/dev/null
incus file push "$REPO/deploy/agent.service" "$agent_vm/root/agent.service" --mode 0644 >/dev/null
incus file push "$tmp/echo" "$agent_vm/root/echo" --mode 0755 >/dev/null
# Also on the agent VM: UDP is probed from here, not from the host (see the header comment).
incus file push "$tmp/probe" "$agent_vm/root/probe" --mode 0755 >/dev/null

sumcheck=$(incus exec "$agent_vm" --cwd /root -- sha256sum -c wgft-linux-amd64.sha256 2>&1)
check "agent: sha256sum -c on the pushed archive contents (docs/setup.md step 1)" "OK" "$sumcheck"

incus exec "$agent_vm" -- install -m 0755 /root/wgft-linux-amd64 /usr/local/bin/wgft
incus exec "$agent_vm" -- useradd --system --home-dir /var/lib/wgft --shell /usr/sbin/nologin wgft
incus exec "$agent_vm" -- mkdir -p /etc/wgft
printf 'WGFT_JOIN=%s\n' "$join" >"$tmp/agent.env"
incus file push "$tmp/agent.env" "$agent_vm/etc/wgft/agent.env" --mode 0640 >/dev/null
incus exec "$agent_vm" -- chown root:wgft /etc/wgft/agent.env
incus exec "$agent_vm" -- chmod 0640 /etc/wgft/agent.env

incus exec "$agent_vm" -- install -m 0644 /root/agent.service /etc/systemd/system/wgft-agent.service
incus exec "$agent_vm" -- systemctl daemon-reload
since=$(incus exec "$agent_vm" -- date +%s)
incus exec "$agent_vm" -- systemctl enable --now wgft-agent

if retry 30 wait_for_log_since "$agent_vm" wgft-agent "$since" "registered as agent"; then
  check "check1: agent starts from the shipped agent.service and registers" "active" "$(incus exec "$agent_vm" -- systemctl is-active wgft-agent)"
else
  incus exec "$agent_vm" -- journalctl -u wgft-agent --no-pager | tail -n 40 >&2
  echo "FAIL  check1: agent never logged 'registered as agent'"
  fail=1; unexpected_fail=1
fi

# The target service: a disposable stand-in for a LAN game server next to the agent, not part of
# wgft. Installed as its own unit (not just a backgrounded process) so it, too, survives a reboot
# without a manual step - otherwise check 3 could not tell "wgft recovered" from "the test's own
# target happened to still be running".
cat >"$tmp/wgft-dist-echo.service" <<EOF
[Unit]
Description=wgft-dist-vm disposable test target (not part of wgft)
After=network.target

[Service]
ExecStart=/root/echo -bind 127.0.0.1 -tcp 25565 -udp 25566
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF
incus file push "$tmp/wgft-dist-echo.service" "$agent_vm/etc/systemd/system/wgft-dist-echo.service" --mode 0644 >/dev/null
incus exec "$agent_vm" -- systemctl daemon-reload
incus exec "$agent_vm" -- systemctl enable --now wgft-dist-echo
retry 10 wait_for_log_boot "$agent_vm" wgft-dist-echo "tcp 127.0.0.1:25565" || echo "dist-vm: warning: target service log line not seen yet" >&2

tunnel_ok() {
  # 'wgft agent ls' aligns its columns with text/tabwriter, which pads with spaces (>=2) on
  # output, not literal tabs; split on runs of 2+ spaces instead of -F'\t'.
  incus exec "$server_vm" -- wgft agent ls 2>/dev/null | awk -F'  +' 'NR>1 && $1=="home" && $6=="ok" { found=1 } END { exit !found }'
}
if retry 40 tunnel_ok; then
  echo "PASS  check1: agent tunnel comes up (TUNNEL=ok in 'wgft agent ls')"
else
  incus exec "$server_vm" -- wgft agent ls >&2
  echo "FAIL  check1: agent tunnel never reached ok"
  fail=1; unexpected_fail=1
fi

# --- check 2: a TCP and a UDP rule forward end to end --------------------------------------------
echo "== check 2: add a tcp and a udp rule, probe from the host"
t=$(incus exec "$server_vm" -- wgft rule add --agent home --tcp 39971 --to 127.0.0.1:25565 2>/dev/null | grep -oE 'r_[A-Z0-9]+')
u=$(incus exec "$server_vm" -- wgft rule add --agent home --udp 27015 --to 127.0.0.1:25566 2>/dev/null | grep -oE 'r_[A-Z0-9]+')
check "server: tcp rule added" "r_" "$t"
check "server: udp rule added" "r_" "$u"
open_firewall "$server_vm" --add-port=39971/tcp --add-port=27015/udp

# Rule delivery over the stream is asynchronous; wait for 'wgft agent ls' to actually report both
# rules ok (RULES column) instead of a blind sleep, with a bounded wall-clock deadline.
rules_delivered() { # rules_delivered <n>
  incus exec "$server_vm" -- wgft agent ls 2>/dev/null | awk -F'  +' -v want="$1 ok" 'NR>1 && $1=="home" && $9==want { f=1 } END { exit !f }'
}
if retry 15 rules_delivered 2; then
  echo "PASS  check2: both rules delivered to the agent (RULES=2 ok)"
else
  echo "dist-vm: warning: rules not confirmed delivered within 15s (continuing to probe anyway)" >&2
  incus exec "$server_vm" -- wgft agent ls >&2
fi

# probe_until <proto> <addr> <marker> <deadline-seconds> [from-vm]: a wall-clock deadline, not a
# fixed iteration count, with a short per-attempt timeout so more attempts fit the budget. Prints
# the last response seen (matching or not) so check()/the caller can report it. Runs from the host
# by default; with [from-vm], runs the probe binary inside that VM instead (see the UDP note
# above bring_up_server's caller below for why UDP uses this).
probe_until() {
  local proto=$1 addr=$2 marker=$3 deadline=$4 vm=${5:-} out deadline_at
  deadline_at=$((SECONDS + deadline))
  while :; do
    if [ -n "$vm" ]; then
      out=$(incus exec "$vm" -- /root/probe -proto "$proto" -addr "$addr" -timeout 2s 2>&1)
    else
      out=$("$tmp/probe" -proto "$proto" -addr "$addr" -timeout 2s 2>&1)
    fi
    case "$out" in *"$marker"*) echo "$out"; return 0 ;; esac
    [ "$SECONDS" -ge "$deadline_at" ] && { echo "$out"; return 1; }
    sleep 1
  done
}
# dump_forwarding_diagnostics: printed to stderr only when a probe fails, so a passing run stays
# quiet but a failing one is self-diagnosing (server/agent journals and the live agent/rule state
# at the moment of failure), per the request to look at both journals for that moment.
dump_forwarding_diagnostics() {
  echo "---- diagnostics: wgft agent ls ----" >&2
  incus exec "$server_vm" -- wgft agent ls >&2 2>&1
  echo "---- diagnostics: server journal (last 30 lines) ----" >&2
  incus exec "$server_vm" -- journalctl -u wgft --no-pager -n 30 >&2 2>&1
  echo "---- diagnostics: agent journal (last 30 lines) ----" >&2
  incus exec "$agent_vm" -- journalctl -u wgft-agent --no-pager -n 30 >&2 2>&1
}

tcp_out=$(probe_until tcp "$server_ip:39971" tcp-echo 30)
udp_out=$(probe_until udp "$server_ip:27015" udp-echo 30 "$agent_vm")
check "check2: tcp forwards end to end (host -> server VM -> tunnel -> agent VM's target)" "tcp-echo" "$tcp_out" || dump_forwarding_diagnostics
check "check2: udp forwards end to end (agent VM -> server VM -> tunnel -> back to the agent VM's target; see the header comment on why UDP is not probed from the host)" "udp-echo" "$udp_out" || dump_forwarding_diagnostics

# --- check 5: file modes and owners docs/setup.md and design.md 11a promise ---------------------
echo "== check 5: file modes and owners"
check "modes: server.env is 0644 (no secrets, DynamicUser must read it)" "644" "$(incus exec "$server_vm" -- stat -c '%a' /etc/wgft/server.env)"
check "modes: agent.env is 0640 root:wgft (holds WGFT_JOIN)" "640 root:wgft" "$(incus exec "$agent_vm" -- stat -c '%a %U:%G' /etc/wgft/agent.env)"
check "modes: server StateDirectory (DynamicUser, /var/lib/wgft) is 0700" "700" "$(incus exec "$server_vm" -- stat -L -c '%a' /var/lib/wgft)"
check "modes: agent StateDirectory (/var/lib/wgft) is 0700" "700" "$(incus exec "$agent_vm" -- stat -c '%a' /var/lib/wgft)"
check "modes: agent.json is 0600" "600" "$(incus exec "$agent_vm" -- stat -c '%a' /var/lib/wgft/agent.json)"

echo "== teeth: agent.env world-readable must make the mode check above fail"
incus exec "$agent_vm" -- chmod 0644 /etc/wgft/agent.env
mode_now=$(incus exec "$agent_vm" -- stat -c '%a' /etc/wgft/agent.env)
if [ "$mode_now" = "640" ]; then teeth_fail "chmod 0644 did not change agent.env's mode (test env broken)"; else teeth_pass "agent.env at $mode_now no longer matches the 0640 check ($mode_now != 640)"; fi
incus exec "$agent_vm" -- chmod 0640 /etc/wgft/agent.env
check "modes: agent.env restored to 0640" "640" "$(incus exec "$agent_vm" -- stat -c '%a' /etc/wgft/agent.env)"

# --- teeth for check 1 / check 3: a broken ExecStart must fail the startup check -----------------
echo "== teeth: a broken server.service ExecStart must fail the startup check"
sed 's#/usr/local/bin/wgft server run#/usr/local/bin/wgft-missing server run#' "$REPO/deploy/server.service" >"$tmp/server.broken.service"
incus file push "$tmp/server.broken.service" "$server_vm/etc/systemd/system/wgft.service" --mode 0644 >/dev/null
incus exec "$server_vm" -- systemctl daemon-reload
incus exec "$server_vm" -- systemctl restart wgft
sleep 3
broken_state=$(incus exec "$server_vm" -- systemctl is-active wgft 2>&1)
if [ "$broken_state" = "active" ]; then
  teeth_fail "server stayed active with a nonexistent ExecStart binary (no teeth)"
else
  teeth_pass "broken ExecStart leaves the unit '$broken_state', which check1/check3 would report as FAIL"
fi
incus file push "$REPO/deploy/server.service" "$server_vm/etc/systemd/system/wgft.service" --mode 0644 >/dev/null
incus exec "$server_vm" -- systemctl daemon-reload
incus exec "$server_vm" -- systemctl reset-failed wgft >/dev/null 2>&1
since=$(incus exec "$server_vm" -- date +%s)
incus exec "$server_vm" -- systemctl restart wgft
retry 30 wait_for_log_since "$server_vm" wgft "$since" "server started" || { echo "FAIL  could not bring the server back up after the ExecStart teeth test"; fail=1; unexpected_fail=1; }
check "teeth: server unit restored and starts again" "active" "$(incus exec "$server_vm" -- systemctl is-active wgft)"

# --- check 3: forwarding resumes after a reboot, server alone / agent alone / both ---------------
boot_id() { incus exec "$1" -- cat /proc/sys/kernel/random/boot_id 2>/dev/null; }
reboot_and_wait() { # reboot_and_wait <vm> <timeout-seconds>
  local vm=$1 timeout=$2 before after i=0
  before=$(boot_id "$vm")
  incus exec "$vm" -- systemctl reboot >/dev/null 2>&1
  sleep 3
  while :; do
    after=$(boot_id "$vm" 2>/dev/null)
    [ -n "$after" ] && [ "$after" != "$before" ] && return 0
    i=$((i + 2))
    [ "$i" -ge "$timeout" ] && return 1
    sleep 2
  done
}
agent_healthy() { tunnel_ok && [ "$(incus exec "$agent_vm" -- systemctl is-active wgft-agent)" = active ]; }
verify_forwarding_after_reboot() { # verify_forwarding_after_reboot <label>
  local label=$1 tcp_out udp_out
  tcp_out=$(probe_until tcp "$server_ip:39971" tcp-echo 30)
  udp_out=$(probe_until udp "$server_ip:27015" udp-echo 30 "$agent_vm")
  check "check3: tcp forwards again after $label (no manual step)" "tcp-echo" "$tcp_out" || dump_forwarding_diagnostics
  check "check3: udp forwards again after $label (no manual step)" "udp-echo" "$udp_out" || dump_forwarding_diagnostics
}

echo "== check 3a: reboot the server VM alone"
if reboot_and_wait "$server_vm" 120; then
  bring_up_server "check3a: server VM rebooted and wgft.service comes back" boot
else
  echo "FAIL  check3: server VM did not reboot within the timeout"
  fail=1; unexpected_fail=1
fi
retry 40 tunnel_ok || { echo "FAIL  check3: agent tunnel did not reconnect after the server VM rebooted"; fail=1; unexpected_fail=1; }
verify_forwarding_after_reboot "rebooting the server VM alone"

echo "== check 3b: reboot the agent VM alone"
if reboot_and_wait "$agent_vm" 120 && retry 60 agent_healthy; then
  echo "PASS  check3: agent VM rebooted and wgft-agent.service is active again, unattended"
else
  echo "FAIL  check3: agent VM did not come back healthy after reboot"
  fail=1; unexpected_fail=1
fi
verify_forwarding_after_reboot "rebooting the agent VM alone"

echo "== check 3c: reboot both VMs"
# Each backgrounded call forks this shell, inheriting LOCK_FD; close that copy immediately so an
# orphaned child (if this script were killed before the "wait"s below return) could never keep the
# host lock held after the main process is gone.
{ exec {LOCK_FD}>&-; reboot_and_wait "$server_vm" 120; } &
p1=$!
{ exec {LOCK_FD}>&-; reboot_and_wait "$agent_vm" 120; } &
p2=$!
# A plain "wait $p1; wait $p2" here would block for up to 120s with this script's own INT/TERM
# traps NOT firing: per POSIX, a shell defers a pending trap until "wait" for an asynchronous list
# returns (checked empirically against this bash too - not a bug, standard behaviour), so Ctrl-C
# during this specific check would otherwise go unnoticed for up to two minutes. Poll instead: each
# `sleep 1` is itself a plain foreground child that terminates immediately on SIGINT/SIGTERM (both
# are sent to this whole process group), which hands control straight back to this shell and lets
# the pending trap run right away.
while kill -0 "$p1" 2>/dev/null || kill -0 "$p2" 2>/dev/null; do sleep 1; done
r1=0; r2=0
wait "$p1" || r1=$?
wait "$p2" || r2=$?
if [ "$r1" = 0 ] && [ "$r2" = 0 ]; then
  bring_up_server "check3c: server VM (of both) comes back" boot
  if retry 60 agent_healthy; then
    echo "PASS  check3c: agent VM (of both) comes back"
  else
    echo "FAIL  check3c: agent VM did not come back healthy after rebooting both"
    fail=1; unexpected_fail=1
  fi
else
  echo "FAIL  check3: one or both VMs did not reboot within the timeout"
  fail=1; unexpected_fail=1
fi
verify_forwarding_after_reboot "rebooting both VMs"

# --- check 4: a configuration error exits 3 and does not restart-loop ---------------------------
echo "== teeth: run the exit-3 assertion against the current, VALID config first"
incus exec "$server_vm" -- systemctl restart wgft
sleep 3
if [ "$(incus exec "$server_vm" -- systemctl is-active wgft)" = active ]; then
  teeth_pass "a valid config keeps the unit active; the exit-3 assertion below would correctly find nothing to report"
else
  teeth_fail "the server did not stay active on a valid config (test env broken)"
fi

echo "== check 4: an invalid config value exits 3 and does not restart-loop"
printf 'WGFT_MODE=kernel\nWGFT_WG_ENDPOINT=%s:51820\nWGFT_MTU=not-a-number\n' "$server_ip" >"$tmp/server.bad.env"
incus file push "$tmp/server.bad.env" "$server_vm/etc/wgft/server.env" --mode 0644 >/dev/null
incus exec "$server_vm" -- systemctl reset-failed wgft >/dev/null 2>&1
incus exec "$server_vm" -- systemctl restart wgft
sleep 5
active=$(incus exec "$server_vm" -- systemctl is-active wgft 2>&1)
exitstatus=$(incus exec "$server_vm" -- systemctl show -p ExecMainStatus --value wgft 2>&1)
check "check4: invalid config leaves the unit failed, not active" "failed" "$active"
eqcheck "check4: invalid config exits with code 3" "3" "$exitstatus"
before=$(incus exec "$server_vm" -- systemctl show -p NRestarts --value wgft 2>&1)
sleep 60 {LOCK_FD}>&- # see the comment on the same pattern in check_capacity above
after=$(incus exec "$server_vm" -- systemctl show -p NRestarts --value wgft 2>&1)
eqcheck "check4: no restart loop over 1 minute (NRestarts unchanged)" "$before" "$after"

echo "== teeth: without RestartPreventExitStatus=3, the same bad config would loop"
sed '/RestartPreventExitStatus=3/d' "$REPO/deploy/server.service" >"$tmp/server.noguard.service"
incus file push "$tmp/server.noguard.service" "$server_vm/etc/systemd/system/wgft.service" --mode 0644 >/dev/null
incus exec "$server_vm" -- systemctl daemon-reload
incus exec "$server_vm" -- systemctl reset-failed wgft >/dev/null 2>&1
before=$(incus exec "$server_vm" -- systemctl show -p NRestarts --value wgft 2>&1)
incus exec "$server_vm" -- systemctl restart wgft
sleep 20 {LOCK_FD}>&- # see the comment on the same pattern in check_capacity above
after=$(incus exec "$server_vm" -- systemctl show -p NRestarts --value wgft 2>&1)
if [ "$after" -gt "$before" ] 2>/dev/null; then
  teeth_pass "removing RestartPreventExitStatus=3 loops on the same bad config ($before -> $after restarts in 20s)"
else
  teeth_fail "removing the guard did not loop as expected ($before -> $after)"
fi

echo "== restore: valid config and the shipped unit"
incus file push "$REPO/deploy/server.service" "$server_vm/etc/systemd/system/wgft.service" --mode 0644 >/dev/null
printf 'WGFT_MODE=kernel\nWGFT_WG_ENDPOINT=%s:51820\n' "$server_ip" >"$tmp/server.env"
incus file push "$tmp/server.env" "$server_vm/etc/wgft/server.env" --mode 0644 >/dev/null
incus exec "$server_vm" -- systemctl daemon-reload
incus exec "$server_vm" -- systemctl reset-failed wgft >/dev/null 2>&1
since=$(incus exec "$server_vm" -- date +%s)
incus exec "$server_vm" -- systemctl restart wgft
if retry 30 wait_for_log_since "$server_vm" wgft "$since" "server started" && retry 40 tunnel_ok; then
  echo "PASS  restore: server healthy again with the shipped unit and a valid config"
else
  echo "FAIL  restore: server did not come back healthy after the check4 teeth tests"
  fail=1; unexpected_fail=1
fi

# =================================================================================================
# optional phase: upgrade from a previous release (--upgrade; docs/testing.md D4's remaining item)
# =================================================================================================
# Everything above this point already ran, unmodified, whether or not --upgrade was given; this
# phase only reuses the same two VMs from here on, starting from whatever check4's restore just left
# (the current build, valid config, both units healthy) and immediately replacing it with a fresh
# install of the OLD release, so nothing above needed to change to make room for it.
if [ "$UPGRADE" = 1 ]; then
  upgrade_started=$(date +%s)
  echo "== upgrade: starting the optional upgrade-from-a-previous-release phase (--upgrade)"
  need curl
  need python3

  OLD_VERSION=${WGFT_DIST_VM_UPGRADE_OLD_VERSION:-}
  if [ -z "$OLD_VERSION" ]; then
    old_tag=$(git -C "$REPO" describe --tags --abbrev=0 --match 'v*' HEAD 2>/dev/null)
    OLD_VERSION=${old_tag#v}
  fi
  head_tag=$(git -C "$REPO" describe --tags --exact-match HEAD 2>/dev/null)

  if [ -z "$OLD_VERSION" ]; then
    echo "FAIL  upgrade: could not determine a previous release (no v* tag reachable from HEAD); set WGFT_DIST_VM_UPGRADE_OLD_VERSION=X.Y.Z"
    fail=1; unexpected_fail=1
  elif [ "$head_tag" = "v$OLD_VERSION" ]; then
    echo "FAIL  upgrade: HEAD is exactly tagged v$OLD_VERSION, so there is no newer build to upgrade TO; set WGFT_DIST_VM_UPGRADE_OLD_VERSION to an older release"
    fail=1; unexpected_fail=1
  else
    echo "== upgrade: previous release v$OLD_VERSION -> current build ($version)"

    # --- fetch and verify the old release's binary on the HOST (lab/oldrelease.sh's fetch_release,
    # sourced and reused, not copied - same contract lab/upgrade.sh and lab/version-skew.sh rely on:
    # cached, sha256-verified, safe if another sandbox fetches the same version concurrently) --------
    GH_REPO=rahanahu/wgft
    # shellcheck source=lab/oldrelease.sh
    . "$REPO/lab/oldrelease.sh"
    OLD_CACHE=${WGFT_DIST_VM_OLDRELEASE_CACHE:-/tmp/wgft-dist-vm-oldrelease-cache}
    mkdir -p "$OLD_CACHE"
    OLD_BIN="$OLD_CACHE/wgft-v$OLD_VERSION-linux-amd64"
    if fetch_release "$OLD_VERSION" "$OLD_BIN"; then
      echo "PASS  upgrade: fetched and sha256-verified v$OLD_VERSION ($OLD_BIN)"
    else
      echo "FAIL  upgrade: could not fetch/verify v$OLD_VERSION from GitHub Releases (see lab/oldrelease.sh; the VMs are never asked to reach GitHub themselves)"
      fail=1; unexpected_fail=1
    fi

    # --- the old release's OWN shipped units, fetched from its tag, not today's deploy/ -------------
    # An operator who installed v$OLD_VERSION at the time got THAT release's units. Whether those
    # differ from today's in anything other than comments decides whether "swap the binary" and
    # "also update the unit" are actually two different cases worth running separately.
    git -C "$REPO" show "v$OLD_VERSION:deploy/server.service" >"$tmp/old-server.service" 2>/dev/null
    old_server_unit_rc=$?
    git -C "$REPO" show "v$OLD_VERSION:deploy/agent.service" >"$tmp/old-agent.service" 2>/dev/null
    old_agent_unit_rc=$?
    if [ "$old_server_unit_rc" -ne 0 ] || [ "$old_agent_unit_rc" -ne 0 ]; then
      echo "FAIL  upgrade: could not read deploy/server.service and/or deploy/agent.service from tag v$OLD_VERSION"
      fail=1; unexpected_fail=1
    fi
    grep -v '^[[:space:]]*#' "$tmp/old-server.service" >"$tmp/old-server.nocomment" 2>/dev/null
    grep -v '^[[:space:]]*#' "$REPO/deploy/server.service" >"$tmp/new-server.nocomment"
    grep -v '^[[:space:]]*#' "$tmp/old-agent.service" >"$tmp/old-agent.nocomment" 2>/dev/null
    grep -v '^[[:space:]]*#' "$REPO/deploy/agent.service" >"$tmp/new-agent.nocomment"
    unit_directive_diff=$(diff "$tmp/old-server.nocomment" "$tmp/new-server.nocomment"; diff "$tmp/old-agent.nocomment" "$tmp/new-agent.nocomment")
    if [ -z "$unit_directive_diff" ]; then
      echo "== upgrade: deploy/server.service and deploy/agent.service have no directive changes since v$OLD_VERSION (comments aside), so a binary-only swap already leaves the operator in the same place an updated unit would; that second case is not run separately"
    else
      echo "== upgrade: deploy/server.service and/or deploy/agent.service changed a real directive since v$OLD_VERSION, not just a comment:"
      echo "$unit_directive_diff"
      echo "== upgrade: NOTE: this phase only exercises the binary-only swap (the old units stay installed); the 'operator also updates the unit' case above is NOT run and is reported as not covered"
    fi

    # --- build the two extra disposable test-only helpers this phase's rule shapes need --------------
    if ! ( cd "$REPO" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$tmp/ppecho" ./tools/ppecho ) >"$tmp/ppecho-build.log" 2>&1; then
      cat "$tmp/ppecho-build.log" >&2
      echo "FAIL  upgrade: build tools/ppecho"
      fail=1; unexpected_fail=1
    fi

    # representative rule shapes and ports (lab/upgrade.sh's own list), on the agent VM's own
    # loopback like the existing check1/check2 target, but on ports distinct from those (39971/27015)
    # so both target services can run side by side without a collision.
    UP_P_TCP=39991;      UP_T_TCP=25631
    UP_P_UDP=27021;      UP_T_UDP=19191
    UP_P_RANGE_LO=39993; UP_P_RANGE_HI=39995; UP_T_RANGE_LO=20031
    UP_P_ACL=39996;      UP_T_ACL=25632
    UP_P_RATES=39997;    UP_T_RATES=25633
    UP_P_DISABLED=39998; UP_T_DISABLED=25634
    UP_P_RELAY=39999;    UP_T_RELAY=8462

    # python3 helpers, host-side only (never assumed inside a VM - see the header comment on why the
    # VMs get no package installed): mirrors lab/upgrade.sh's compare_rules.py and
    # stable_cred_hash.py, adapted to read from files this script already captures with plain
    # "incus exec ... > file" redirections, the same idiom the rest of this script already uses.
    cat >"$tmp/compare_rules.py" <<'PYEOF'
import json, sys
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
    print("\n".join(problems)); sys.exit(1)
print("%d rules identical across the upgrade" % len(old))
PYEOF
    cat >"$tmp/stable_cred_hash.py" <<'PYEOF'
import hashlib, json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
d.pop("last_state", None)  # rewritten on every reconnect; excluded so this isolates "same
                            # credentials, no rotate-key, no re-enrolment" (see lab/upgrade.sh)
print(hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest())
PYEOF

    # ===============================================================================================
    # step 1: install v$OLD_VERSION fresh on both VMs, exactly as docs/setup.md instructs, with that
    # release's OWN units; a representative rule of every shape; prove forwarding; capture the
    # baseline v$OLD_VERSION itself reports.
    # ===============================================================================================
    echo "== upgrade: step 1: install v$OLD_VERSION fresh (docs/setup.md's steps, that release's own units)"
    incus exec "$server_vm" -- systemctl stop wgft
    incus exec "$agent_vm" -- systemctl stop wgft-agent
    teardown_out=$(incus exec "$server_vm" -- wgft server teardown --purge --yes 2>&1)
    check "upgrade: step1: current-build state purged for a fresh v$OLD_VERSION install" "removing" "$teardown_out"
    incus exec "$agent_vm" -- rm -f /var/lib/wgft/agent.json

    incus file push "$OLD_BIN" "$server_vm/root/wgft-old-linux-amd64" --mode 0644 >/dev/null
    incus file push "$OLD_BIN" "$agent_vm/root/wgft-old-linux-amd64" --mode 0644 >/dev/null
    incus exec "$server_vm" -- install -m 0755 /root/wgft-old-linux-amd64 /usr/local/bin/wgft
    incus exec "$agent_vm" -- install -m 0755 /root/wgft-old-linux-amd64 /usr/local/bin/wgft
    incus file push "$tmp/old-server.service" "$server_vm/etc/systemd/system/wgft.service" --mode 0644 >/dev/null
    incus file push "$tmp/old-agent.service" "$agent_vm/etc/systemd/system/wgft-agent.service" --mode 0644 >/dev/null
    incus exec "$server_vm" -- systemctl daemon-reload
    incus exec "$agent_vm" -- systemctl daemon-reload

    # /etc/wgft/server.env and /etc/wgft/agent.env are left exactly as they already are: WGFT_MODE,
    # WGFT_WG_ENDPOINT and WGFT_JOIN are accepted unchanged by v$OLD_VERSION (checked above: only
    # additions between v$OLD_VERSION and this build's cmd/wgft/{server,agent,config}.go).
    incus exec "$server_vm" -- systemctl reset-failed wgft >/dev/null 2>&1
    incus exec "$server_vm" -- systemctl restart wgft
    bring_up_server "upgrade: step1: v$OLD_VERSION" || { fail=1; unexpected_fail=1; }

    old_join=$(incus exec "$server_vm" -- wgft agent join-string --name home 2>/dev/null | head -1)
    check "upgrade: step1: v$OLD_VERSION join string issued" "wgft://" "$old_join"
    printf 'WGFT_JOIN=%s\n' "$old_join" >"$tmp/upgrade-agent.env"
    incus file push "$tmp/upgrade-agent.env" "$agent_vm/etc/wgft/agent.env" --mode 0640 >/dev/null
    incus exec "$agent_vm" -- chown root:wgft /etc/wgft/agent.env
    incus exec "$agent_vm" -- chmod 0640 /etc/wgft/agent.env

    since=$(incus exec "$agent_vm" -- date +%s)
    incus exec "$agent_vm" -- systemctl reset-failed wgft-agent >/dev/null 2>&1
    incus exec "$agent_vm" -- systemctl restart wgft-agent
    if retry 30 wait_for_log_since "$agent_vm" wgft-agent "$since" "registered as agent"; then
      echo "PASS  upgrade: step1: v$OLD_VERSION agent registers fresh"
    else
      incus exec "$agent_vm" -- journalctl -u wgft-agent --no-pager | tail -n 40 >&2
      echo "FAIL  upgrade: step1: v$OLD_VERSION agent never registered"
      fail=1; unexpected_fail=1
    fi
    retry 40 tunnel_ok || { echo "FAIL  upgrade: step1: tunnel never reached ok"; fail=1; unexpected_fail=1; }

    # target listeners for the new rule shapes, alongside (not instead of) check1/check2's own
    # wgft-dist-echo on 25565/25566 - both keep running side by side, on different ports. /root/echo
    # is already there from earlier in this script (check1); NOT re-pushed here - check2's own
    # wgft-dist-echo.service still has it open, and "incus file push" onto a running executable
    # fails with "text file busy" (harmless, but this avoids the noise and the pointless retry).
    incus file push "$tmp/ppecho" "$agent_vm/root/ppecho" --mode 0755 >/dev/null
    cat >"$tmp/wgft-dist-upgrade-echo.service" <<EOF
[Unit]
Description=wgft-dist-vm upgrade-phase disposable test target (not part of wgft)
After=network.target

[Service]
ExecStart=/root/echo -bind 127.0.0.1 -tcp $UP_T_TCP,$UP_T_ACL,$UP_T_RATES,$UP_T_DISABLED -udp $UP_T_UDP,$UP_T_RANGE_LO,$((UP_T_RANGE_LO + 1)),$((UP_T_RANGE_LO + 2))
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF
    cat >"$tmp/wgft-dist-upgrade-ppecho.service" <<EOF
[Unit]
Description=wgft-dist-vm upgrade-phase PROXY-protocol test target (not part of wgft)
After=network.target

[Service]
ExecStart=/root/ppecho -addr 127.0.0.1:$UP_T_RELAY
Restart=always
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF
    incus file push "$tmp/wgft-dist-upgrade-echo.service" "$agent_vm/etc/systemd/system/wgft-dist-upgrade-echo.service" --mode 0644 >/dev/null
    incus file push "$tmp/wgft-dist-upgrade-ppecho.service" "$agent_vm/etc/systemd/system/wgft-dist-upgrade-ppecho.service" --mode 0644 >/dev/null
    incus exec "$agent_vm" -- systemctl daemon-reload
    incus exec "$agent_vm" -- systemctl enable --now wgft-dist-upgrade-echo wgft-dist-upgrade-ppecho

    up_r_tcp=$(incus exec "$server_vm" -- wgft rule add --agent home --tcp "$UP_P_TCP" --to "127.0.0.1:$UP_T_TCP" --group upgrade --note "plain tcp" 2>/dev/null | grep -oE 'r_[A-Za-z0-9]+')
    up_r_udp=$(incus exec "$server_vm" -- wgft rule add --agent home --udp "$UP_P_UDP" --to "127.0.0.1:$UP_T_UDP" --group upgrade --note "plain udp" 2>/dev/null | grep -oE 'r_[A-Za-z0-9]+')
    up_r_range=$(incus exec "$server_vm" -- wgft rule add --agent home --udp "$UP_P_RANGE_LO-$UP_P_RANGE_HI" --to "127.0.0.1:$UP_T_RANGE_LO" --group upgrade --note "port range" 2>/dev/null | grep -oE 'r_[A-Za-z0-9]+')
    up_r_acl=$(incus exec "$server_vm" -- wgft rule add --agent home --tcp "$UP_P_ACL" --to "127.0.0.1:$UP_T_ACL" --group upgrade --note "deny+allow" 2>/dev/null | grep -oE 'r_[A-Za-z0-9]+')
    incus exec "$server_vm" -- wgft rule allow add "$up_r_acl" "$net_base.0/$net_prefix" >/dev/null 2>&1
    incus exec "$server_vm" -- wgft rule deny add "$up_r_acl" 203.0.113.5/32 >/dev/null 2>&1
    up_r_rates=$(incus exec "$server_vm" -- wgft rule add --agent home --tcp "$UP_P_RATES" --to "127.0.0.1:$UP_T_RATES" --group upgrade --note "all three rates" 2>/dev/null | grep -oE 'r_[A-Za-z0-9]+')
    incus exec "$server_vm" -- wgft rule rate new-flow "$up_r_rates" 100/second >/dev/null 2>&1
    incus exec "$server_vm" -- wgft rule rate packet "$up_r_rates" 500/second >/dev/null 2>&1
    incus exec "$server_vm" -- wgft rule rate per-source "$up_r_rates" 50/second >/dev/null 2>&1
    up_r_disabled=$(incus exec "$server_vm" -- wgft rule add --agent home --tcp "$UP_P_DISABLED" --to "127.0.0.1:$UP_T_DISABLED" --disabled --group upgrade --note "disabled" 2>/dev/null | grep -oE 'r_[A-Za-z0-9]+')
    up_r_relay=$(incus exec "$server_vm" -- wgft rule add --agent home --tcp "$UP_P_RELAY" --to "127.0.0.1:$UP_T_RELAY" --proxy --proxy-protocol --group upgrade --note "relay" 2>/dev/null | grep -oE 'r_[A-Za-z0-9]+')
    for rid in "$up_r_tcp" "$up_r_udp" "$up_r_range" "$up_r_acl" "$up_r_rates" "$up_r_disabled" "$up_r_relay"; do
      check "upgrade: step1: rule id issued ($rid)" "r_" "$rid"
    done
    open_firewall "$server_vm" --add-port="$UP_P_TCP/tcp" --add-port="$UP_P_UDP/udp" \
      --add-port="$UP_P_RANGE_LO-$UP_P_RANGE_HI/udp" --add-port="$UP_P_ACL/tcp" \
      --add-port="$UP_P_RATES/tcp" --add-port="$UP_P_DISABLED/tcp" --add-port="$UP_P_RELAY/tcp"

    upgrade_probe_all() { # upgrade_probe_all <label-suffix>: probes every enabled rule shape, called
      # identically after step1's fresh install and after each swap below.
      local suf=$1 out
      out=$(probe_until tcp "$server_ip:$UP_P_TCP" tcp-echo 30); check "upgrade: $suf: plain tcp forwards" "tcp-echo" "$out" || dump_forwarding_diagnostics
      out=$(probe_until udp "$server_ip:$UP_P_UDP" udp-echo 30 "$agent_vm"); check "upgrade: $suf: plain udp forwards" "udp-echo" "$out" || dump_forwarding_diagnostics
      out=$(probe_until udp "$server_ip:$UP_P_RANGE_LO" udp-echo 20 "$agent_vm"); check "upgrade: $suf: port-range rule forwards (first port)" "udp-echo" "$out"
      out=$(probe_until tcp "$server_ip:$UP_P_ACL" tcp-echo 20); check "upgrade: $suf: deny+allow rule forwards from the allowed source" "tcp-echo" "$out"
      out=$(probe_until tcp "$server_ip:$UP_P_RATES" tcp-echo 20); check "upgrade: $suf: all-three-rates rule forwards" "tcp-echo" "$out"
      out=$(probe_until tcp "$server_ip:$UP_P_RELAY" "client=" 20); check "upgrade: $suf: relay rule carries the client via PROXY protocol" "client=" "$out"
    }
    upgrade_probe_all "step1 (v$OLD_VERSION)"

    incus exec "$server_vm" -- wgft rule ls --json >"$tmp/upgrade-old-rules.json"
    incus exec "$server_vm" -- wgft rule ls >"$tmp/upgrade-old-rulels.stdout" 2>"$tmp/upgrade-old-rulels.stderr"
    incus exec "$agent_vm" -- cat /var/lib/wgft/agent.json >"$tmp/upgrade-old-agent.json" 2>/dev/null
    old_agent_pubkey=$(incus exec "$agent_vm" -- wgft agent pubkey --data-dir /var/lib/wgft 2>/dev/null)
    if [ -n "$old_agent_pubkey" ]; then echo "PASS  upgrade: step1: v$OLD_VERSION agent public key read"; else echo "FAIL  upgrade: step1: v$OLD_VERSION agent public key empty"; fail=1; unexpected_fail=1; fi
    old_cred_hash=$(python3 "$tmp/stable_cred_hash.py" "$tmp/upgrade-old-agent.json" 2>/dev/null)
    # server's own WireGuard public key (kernel mode): unlike lab/upgrade.sh, which runs inside a lab
    # image that has wireguard-tools installed, these VMs deliberately have neither wg(8) nor nft(8)
    # (header comment: wgft talks to the kernel over netlink itself, so the base image needs neither,
    # and this script never apt-get's anything into a VM). There is also no "wgft server pubkey"
    # command (only "agent pubkey" exists). So the server's key is checked INDIRECTLY: WireGuard
    # pins the peer's key at both ends, so if the server's private key changed, the agent's already-
    # provisioned peer entry for the OLD server key would fail the handshake and tunnel_ok would
    # never return to "ok" after the swap below - which every step below already checks. A changed
    # server key would therefore surface as a tunnel failure, not silently pass.
    echo "== upgrade: step1: server's own WireGuard key is checked indirectly (tunnel_ok after each swap), not read directly - see the comment above this line for why"

    # --- step 2: back up the data directory, as v0.5.1's release notes' "Upgrading" section tells
    # operators to do before replacing the binary --------------------------------------------------
    echo "== upgrade: step 2: back up the data directory before the binary swap"
    incus exec "$server_vm" -- tar czf /root/wgft-server-data-backup.tar.gz -C /var/lib/wgft .
    backup1=$(incus exec "$server_vm" -- sh -c 'test -s /root/wgft-server-data-backup.tar.gz && echo present')
    check "upgrade: step2: server data directory backed up" "present" "$backup1"
    incus exec "$agent_vm" -- tar czf /root/wgft-agent-data-backup.tar.gz -C /var/lib/wgft .
    backup2=$(incus exec "$agent_vm" -- sh -c 'test -s /root/wgft-agent-data-backup.tar.gz && echo present')
    check "upgrade: step2: agent data directory backed up" "present" "$backup2"

    # ===============================================================================================
    # step 3: swap ONLY the server binary (the v$OLD_VERSION units stay installed - the case an
    # operator who "just swaps the binary" actually ends up in), restart, and check the promises.
    # ===============================================================================================
    echo "== upgrade: step 3: swap the server binary only, restart"
    incus exec "$server_vm" -- install -m 0755 /root/wgft-linux-amd64 /usr/local/bin/wgft
    server_restart_t0=$SECONDS
    incus exec "$server_vm" -- systemctl reset-failed wgft >/dev/null 2>&1
    incus exec "$server_vm" -- systemctl restart wgft
    bring_up_server "upgrade: step3: current build on v$OLD_VERSION's data" || { fail=1; unexpected_fail=1; }
    server_log=$(incus exec "$server_vm" -- journalctl -u wgft -b --no-pager -q 2>/dev/null)
    absent "upgrade: step3: no schema/migration error in the server log" "applying schema version" "$server_log"
    absent "upgrade: step3: no newer-schema refusal in the server log" "is newer than this binary" "$server_log"
    retry 40 tunnel_ok || { echo "FAIL  upgrade: step3: tunnel did not return to ok after the server swap"; fail=1; unexpected_fail=1; }
    server_outage=$((SECONDS - server_restart_t0))
    echo "== upgrade: measured outage after the SERVER restart: tunnel back to ok after ${server_outage}s (informative measurement, not asserted - docs/testing.md makes no numeric promise here)"

    incus exec "$server_vm" -- wgft rule ls --json >"$tmp/upgrade-new-rules.json"
    rules_diff=$(python3 "$tmp/compare_rules.py" "$tmp/upgrade-old-rules.json" "$tmp/upgrade-new-rules.json"); rules_rc=$?
    if [ "$rules_rc" = 0 ]; then echo "PASS  upgrade: step3: $rules_diff"; else echo "FAIL  upgrade: step3: rules changed across the server swap: $rules_diff"; fail=1; unexpected_fail=1; fi

    check_out=$(incus exec "$server_vm" -- wgft server check 2>&1); check_rc=$?
    eqcheck "upgrade: step3: 'wgft server check' exits 0 after the swap" "0" "$check_rc"
    absent "upgrade: step3: 'wgft server check' finds nothing needing attention" "needs attention" "$check_out"
    absent "upgrade: step3: 'wgft server check' can open the server database" "cannot open" "$check_out"

    upgrade_probe_all "step3 (after the server swap)"
    disabled_out=$("$tmp/probe" -proto tcp -addr "$server_ip:$UP_P_DISABLED" -timeout 2s 2>&1)
    absent "upgrade: step3: the disabled rule still has no listener" "tcp-echo" "$disabled_out"

    # ===============================================================================================
    # step 4: swap the agent binary, restart, and check the agent needed no re-enrolment.
    # ===============================================================================================
    echo "== upgrade: step 4: swap the agent binary, restart"
    incus exec "$agent_vm" -- install -m 0755 /root/wgft-linux-amd64 /usr/local/bin/wgft
    agent_restart_t0=$SECONDS
    since=$(incus exec "$agent_vm" -- date +%s)
    incus exec "$agent_vm" -- systemctl reset-failed wgft-agent >/dev/null 2>&1
    incus exec "$agent_vm" -- systemctl restart wgft-agent
    retry 40 tunnel_ok || { echo "FAIL  upgrade: step4: tunnel did not return to ok after the agent swap"; fail=1; unexpected_fail=1; }
    agent_log_since=$(incus exec "$agent_vm" -- journalctl -u wgft-agent --no-pager -q --since "@$since" 2>/dev/null)
    # a spent WGFT_JOIN is deliberately still sitting in /etc/wgft/agent.env from step 1 (docs/
    # setup.md: "A used WGFT_JOIN left in ... an agent that is already registered is ignored"); left
    # in place on purpose, not cleared, so this exercises exactly that real-world leftover.
    absent "upgrade: step4: agent needed no re-enrolment (no 'not registered' error, spent WGFT_JOIN notwithstanding)" "not registered and no join string" "$agent_log_since"
    agent_outage=$((SECONDS - agent_restart_t0))
    echo "== upgrade: measured outage after the AGENT restart: tunnel back to ok after ${agent_outage}s (informative measurement, not asserted)"

    incus exec "$agent_vm" -- cat /var/lib/wgft/agent.json >"$tmp/upgrade-new-agent.json" 2>/dev/null
    new_cred_hash=$(python3 "$tmp/stable_cred_hash.py" "$tmp/upgrade-new-agent.json" 2>/dev/null)
    strcheck "upgrade: step4: agent credentials (name/endpoint/cert/token/wg key) unchanged, no re-enrolment" "$old_cred_hash" "$new_cred_hash"
    new_agent_pubkey=$(incus exec "$agent_vm" -- wgft agent pubkey --data-dir /var/lib/wgft 2>/dev/null)
    strcheck "upgrade: step4: agent's WireGuard public key is unchanged" "$old_agent_pubkey" "$new_agent_pubkey"

    upgrade_probe_all "step4 (after the agent swap)"

    # ===============================================================================================
    # step 5: reboot the server VM, then the agent VM; forwarding must come back with no manual step.
    # ===============================================================================================
    echo "== upgrade: step 5: reboot the server VM, then the agent VM"
    if reboot_and_wait "$server_vm" 120; then
      bring_up_server "upgrade: step5: server VM rebooted" boot || { fail=1; unexpected_fail=1; }
    else
      echo "FAIL  upgrade: step5: server VM did not reboot within the timeout"; fail=1; unexpected_fail=1
    fi
    retry 40 tunnel_ok || { echo "FAIL  upgrade: step5: tunnel did not reconnect after the server VM rebooted"; fail=1; unexpected_fail=1; }
    upgrade_probe_all "step5 (after rebooting the server VM)"

    if reboot_and_wait "$agent_vm" 120 && retry 60 agent_healthy; then
      echo "PASS  upgrade: step5: agent VM rebooted and wgft-agent.service is active again, unattended"
    else
      echo "FAIL  upgrade: step5: agent VM did not come back healthy after reboot"; fail=1; unexpected_fail=1
    fi
    upgrade_probe_all "step5 (after rebooting the agent VM)"

    # ===============================================================================================
    # teeth: a data directory the service's user cannot read must fail the restart with a clear
    # message, not silently keep the old binary's behaviour or fail unintelligibly. Simulated exactly
    # as the task asks: chmod the data directory unreadable before the restart.
    # ===============================================================================================
    echo "== upgrade: teeth: a database file the service's user cannot read must fail the restart with a clear message"
    # NOT chmod'd on the StateDirectory itself (/var/lib/wgft, a symlink to /var/lib/private/wgft
    # under DynamicUser=yes): tried first, and found to be no teeth at all - systemd re-provisions a
    # DynamicUser unit's StateDirectory to StateDirectoryMode (0700) and the dynamic user's own
    # ownership on every unit start, silently undoing a chmod on the directory before ExecStart ever
    # runs (confirmed live: 'stat -L /var/lib/wgft' read back 0700 owned by the dynamic user right
    # after a chmod 000 plus a restart). The database FILE inside it is not re-provisioned that way,
    # so chmod/chown the file itself, saving its current owner first (a numeric uid:gid - the dynamic
    # user's name only resolves via NSS while the unit is active, not while it is stopped for this).
    db_owner=$(incus exec "$server_vm" -- stat -L -c '%u:%g' /var/lib/wgft)
    incus exec "$server_vm" -- chown 0:0 /var/lib/wgft/wgft.sqlite
    incus exec "$server_vm" -- chmod 000 /var/lib/wgft/wgft.sqlite
    incus exec "$server_vm" -- systemctl reset-failed wgft >/dev/null 2>&1
    incus exec "$server_vm" -- systemctl restart wgft
    sleep 8
    teeth_active=$(incus exec "$server_vm" -- systemctl is-active wgft 2>&1)
    teeth_log=$(incus exec "$server_vm" -- journalctl -u wgft -b --no-pager -q -n 40 2>&1)
    if [ "$teeth_active" = active ]; then
      teeth_fail "server stayed active with an unreadable database file (no teeth)"
    else
      case "$teeth_log" in
        *"server database"*"unable to open database file"*) teeth_pass "an unreadable database file leaves the unit '$teeth_active', with a clear message naming the database: $(echo "$teeth_log" | grep -m1 'server database')" ;;
        *"server database"*) teeth_pass "an unreadable database file leaves the unit '$teeth_active', with a clear database error in the journal" ;;
        *) teeth_fail "unit is '$teeth_active' but the journal does not clearly name the database as the cause: $teeth_log" ;;
      esac
    fi
    echo "== upgrade: restore: database file ownership and a healthy server"
    incus exec "$server_vm" -- chown "$db_owner" /var/lib/wgft/wgft.sqlite
    incus exec "$server_vm" -- chmod 0600 /var/lib/wgft/wgft.sqlite
    incus exec "$server_vm" -- systemctl reset-failed wgft >/dev/null 2>&1
    since=$(incus exec "$server_vm" -- date +%s)
    incus exec "$server_vm" -- systemctl restart wgft
    if retry 30 wait_for_log_since "$server_vm" wgft "$since" "server started" && retry 40 tunnel_ok; then
      echo "PASS  upgrade: restore: server healthy again once the data directory is readable"
    else
      echo "FAIL  upgrade: restore: server did not recover after restoring data directory permissions"; fail=1; unexpected_fail=1
    fi

    upgrade_elapsed=$(( $(date +%s) - upgrade_started ))
    echo "== upgrade phase (v$OLD_VERSION -> current): elapsed ${upgrade_elapsed}s"
  fi
fi

elapsed=$(( $(date +%s) - started ))
echo "== dist-vm ($IMAGE): elapsed ${elapsed}s"
# unexpected_fail wins: any FAIL other than the known, already-reported nf_conntrack defect means
# a genuine regression (in the product or in this script), regardless of whether the workaround
# also fired. Otherwise, a workaround having fired at all means the literal docs/setup.md
# procedure failed on its own (the known startup-ordering defect, fix/server-conntrack-start),
# reported distinctly from a truly clean run even though every individual check still passed once
# the workaround was applied. All three non-ALL-PASS outcomes exit non-zero.
if [ "$unexpected_fail" != 0 ]; then
  echo "== FAILURES"
  fail=1
elif [ "$workaround_count" -gt 0 ]; then
  echo "== PASS WITH WORKAROUND APPLIED ($workaround_count times): literal docs/setup.md procedure failed (nf_conntrack), see the WORKAROUND lines above"
  fail=1
else
  echo "== ALL PASS"
fi
exit "$fail"
