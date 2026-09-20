# sandbox.sh is sourced by the lab scenarios. It gives them the values of the sandbox they run in,
# so that several independent copies of a scenario can run at once inside one lab VM (tools/labhost
# creates the sandboxes and sets the variables). With the variables unset the values are exactly
# today's shared topology and /tmp paths, and every helper below falls back to the VM-wide pkill and
# pgrep the scenarios used before, so `lab/lab exec vm bash /wgft/lab/<scenario>.sh <mode>`
# behaves as it did.
#
# What a network namespace already isolates, and what therefore needs no separation per sandbox:
# interface names (wgft0, eth0, pub0), addresses, listening ports, 127.0.0.1:8686, the WireGuard
# port, `table inet wgft` and the conntrack table. What it does not isolate, and is separated here:
# the workdir holding data dirs, logs and scratch files, and the ownership of processes.
CLIENT_NS=${WGFT_LAB_CLIENT_NS:-client}
VPS_NS=${WGFT_LAB_VPS_NS:-vps}
ROUTER_NS=${WGFT_LAB_ROUTER_NS:-homerouter}
HOME_NS=${WGFT_LAB_HOME_NS:-home}
LAN_NS=${WGFT_LAB_LAN_NS:-lan}
W=${WGFT_LAB_WORKDIR:-/tmp}
SANDBOX=${WGFT_LAB_SANDBOX:-}
mkdir -p "$W"

# sandbox_pids: every process running in this sandbox's namespaces. `ip netns pids` compares
# /proc/<pid>/ns/net against the namespace, so it also finds the grandchildren the scenarios detach
# with `setsid nohup`, without cgroups and without bookkeeping of its own. `ip netns exec` does not
# create a PID namespace, which is why plain pgrep and pkill see the whole VM and this is needed.
sandbox_pids() {
  local ns
  for ns in "$CLIENT_NS" "$VPS_NS" "$ROUTER_NS" "$HOME_NS" "$LAN_NS"; do
    ip netns pids "$ns" 2>/dev/null
  done | sort -u
}

# sandbox_pids_named <name>...: the PIDs whose comm is one of <name>..., inside this sandbox.
# Outside a sandbox it is `pgrep -x` over the whole VM, as before.
sandbox_pids_named() {
  local p n m
  if [ -z "$SANDBOX" ]; then
    for n in "$@"; do pgrep -x "$n"; done
    return 0
  fi
  for p in $(sandbox_pids); do
    n=$(cat "/proc/$p/comm" 2>/dev/null) || continue
    for m in "$@"; do
      if [ "$n" = "$m" ]; then echo "$p"; break; fi
    done
  done
}

# sandbox_any_named <name>...: true while at least one such process is running in this sandbox.
sandbox_any_named() { [ -n "$(sandbox_pids_named "$@")" ]; }

# sandbox_kill_named [-SIGNAL] <name>...: stop those processes, this sandbox only. The default
# signal is the SIGTERM that `pkill -x` sends.
sandbox_kill_named() {
  local sig=TERM p n
  case "${1:-}" in -*) sig=${1#-}; shift ;; esac
  if [ -z "$SANDBOX" ]; then
    for n in "$@"; do pkill -"$sig" -x "$n"; done
    return 0
  fi
  for p in $(sandbox_pids_named "$@"); do kill -"$sig" "$p" 2>/dev/null; done
  return 0
}

# sandbox_kill_cmdline <substring>: stop the processes whose command line contains <substring>,
# this sandbox only. Outside a sandbox it is `pkill -f`, as before.
sandbox_kill_cmdline() {
  local p
  if [ -z "$SANDBOX" ]; then
    pkill -f -- "$1"
    return 0
  fi
  for p in $(sandbox_pids); do
    if tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q -- "$1"; then kill "$p" 2>/dev/null; fi
  done
  return 0
}

# sandbox_wgft_pids: the PIDs a scenario looks at to find its own wgft process.
sandbox_wgft_pids() { sandbox_pids_named wgft; }
