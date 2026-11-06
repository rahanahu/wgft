#!/usr/bin/env bash
# tqagent.sh is the agent VM's side of lab/tcpquality.sh under `lab/lab paired --split`: the agent
# runs in a VM of its own, which holds only the home namespace (lab/netns.sh up-split-agent), and
# tcpquality.sh in the peer VM calls this script there through `tcpquality.py agentd`.
#
#   tqagent.sh gso on|off|show            UDP segmentation offload of home's eth0
#   tqagent.sh start <mode> <adata> <log> start the agent of <mode> (kernel, rust, gvisor, wgstack) in
#                                         home; WGFT_JOIN, WGFT_AGENT_ALLOW_TARGETS, WGFT_MODE and
#                                         WGFT_AGENT_NETSTACK come in the environment, WGFT_BIN_DIR
#                                         selects another build as in tcpquality.sh, and AGENT_CPUS,
#                                         a CPU list, runs a userspace-mode agent under taskset
#   tqagent.sh own <adata> <cgroup root>  the agent's PID and its own cgroup: "pid=<pid> cg=<dir>"
#   tqagent.sh stop <adata> <cgroup root> stop the agent and every other process in home, and remove
#                                         what the agent left there
#   tqagent.sh own-lan <cmdline> <cgroup root>  with the LAN host in home (TARGET_LOCAL): that
#                                         process's PID and own cgroup
#   tqagent.sh cpu <pid> <cgroup>         a process's CPU time so far in microseconds
#   tqagent.sh cpus <pid>                 the CPUs a process may run on (its Cpus_allowed_list)
#   tqagent.sh pin-threads <pid> <dp cpus> <worker cpus>
#                                         lab/lab paired --placement apart-mt: put the thread
#                                         wgft-dataplane on <dp cpus> and the wgft-crypto workers one
#                                         each on the CPUs of the comma list <worker cpus>, then check
#                                         them as check-threads does; prints crypto_threads=<count>
#   tqagent.sh check-threads <pid> <dp cpus> <worker cpus>
#                                         print each thread as comm/tid=cpus and fail when the
#                                         data-plane thread is missing or a thread named above is
#                                         not on its CPUs; workers started after pin-threads inherit
#                                         the data-plane thread's CPUs, which this catches
#   tqagent.sh killlan                    stop tcpquality.py's processes in home
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/sandbox.sh"
if [ -n "${WGFT_BIN_DIR:-}" ]; then
  PATH=$WGFT_BIN_DIR:$PATH
  export PATH
fi
RUST_AGENT=${WGFT_BIN_DIR:+$WGFT_BIN_DIR/rust/wgft}
RUST_AGENT=${RUST_AGENT:-$RUST_WGFT}
Q="python3 $HERE/tcpquality.py"

home_pid() { # home_pid <cmdline substring>: the first process in home whose command line has it
  local p
  for p in $(ip netns pids "$HOME_NS" 2>/dev/null); do
    tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q -- "$1" && { echo "$p"; return 0; }
  done
  return 1
}
agent_pid() { home_pid "agent run --data-dir $1"; }
own_cg() { # own_cg <pid> <dir>: move the process into the cgroup dir; prints "pid=<pid> cg=<dir or empty>"
  local cg=
  if [ -e /sys/fs/cgroup/cgroup.controllers ] && mkdir -p "$2" 2>/dev/null && echo "$1" > "$2/cgroup.procs" 2>/dev/null; then
    cg=$2
  fi
  echo "pid=$1 cg=$cg"
}

case "${1:-}" in
  gso)
    exec ip netns exec "$HOME_NS" $Q udpgso eth0 "${2:?gso on|off|show}"
    ;;
  start)
    mode=${2:?start <mode> <adata> <log>} adata=${3:?} log=${4:?}
    mkdir -p "$(dirname "$log")"
    # AGENT_CPUS (lab/lab paired --placement): a userspace-mode agent runs on those CPUs only; the
    # kernel mode's data plane is kernel WireGuard, which has no process to place
    pin=()
    if [ -n "${AGENT_CPUS:-}" ] && [ "$mode" != kernel ]; then
      pin=(taskset -c "$AGENT_CPUS")
    fi
    if [ "$mode" = rust ]; then
      [ -x "$RUST_AGENT" ] || { echo "tqagent.sh: no Rust agent at $RUST_AGENT" >&2; exit 2; }
      ip netns exec "$HOME_NS" setsid nohup "${pin[@]}" "$RUST_AGENT" agent run --data-dir "$adata" > "$log" 2>&1 < /dev/null &
    else
      ip netns exec "$HOME_NS" setsid nohup "${pin[@]}" wgft agent run --data-dir "$adata" > "$log" 2>&1 < /dev/null &  # lab: go agent
    fi
    disown
    ;;
  own)
    adata=${2:?own <adata> <cgroup root>} cgroot=${3:?}
    pid=$(agent_pid "$adata") || { echo "pid= cg="; exit 1; }
    own_cg "$pid" "$cgroot-agent"
    ;;
  own-lan)
    pid=$(home_pid "${2:?own-lan <cmdline> <cgroup root>}") || { echo "pid= cg="; exit 1; }
    own_cg "$pid" "${3:?}-lan"
    ;;
  cpus)
    # the CPUs a process may run on (Cpus_allowed_list), to check a pin
    awk '$1 == "Cpus_allowed_list:" { print $2 }' "/proc/${2:?cpus <pid>}/status"
    ;;
  pin-threads | check-threads)
    # <worker cpus> is a comma list; the k-th wgft-crypto thread, by thread id, goes on its k-th CPU
    # (round robin), so that each worker has a CPU of its own
    pid=${2:?$1 <pid> <dp cpus> <worker cpus> [<partition cpus>]} dp=${3:?} wk=${4:?} part=${5:-}
    IFS=, read -ra wcpus <<<"$wk"
    rc=0 seen_dp=0 nwk=0 out=
    for tid in $(ls /proc/"$pid"/task 2>/dev/null | sort -n); do
      t=/proc/$pid/task/$tid
      comm=$(cat "$t/comm" 2>/dev/null) || continue
      case $comm in
        wgft-dataplane) want=$dp seen_dp=1 ;;
        wgft-crypto) want=${wcpus[nwk % ${#wcpus[@]}]} nwk=$((nwk + 1)) ;;
        wgft-dp-part*) want=$part ;;
        *) want= ;;
      esac
      if [ -n "$want" ] && [ "$1" = pin-threads ]; then taskset -pc "$want" "$tid" >/dev/null || rc=1; fi
      have=$(awk '$1 == "Cpus_allowed_list:" { print $2 }' "$t/status" 2>/dev/null)
      out="$out $comm/$tid=$have"
      if [ -n "$want" ] && [ "$have" != "$want" ]; then
        echo "tqagent.sh: thread $comm $tid runs on CPUs $have, not $want" >&2
        rc=1
      fi
    done
    [ "$seen_dp" = 1 ] || { echo "tqagent.sh: process $pid has no thread wgft-dataplane" >&2; rc=1; }
    echo "crypto_threads=$nwk threads:${out:- none}"
    exit "$rc"
    ;;
  cpu)
    pid=${2:-} cg=${3:-}
    if [ -n "$cg" ]; then
      awk '$1 == "usage_usec" { print $2 }' "$cg/cpu.stat"
    elif [ -n "$pid" ]; then
      sed 's/.*) //' "/proc/$pid/stat" | awk -v hz="$(getconf CLK_TCK)" '{ printf "%d\n", ($12 + $13) * 1000000 / hz }'
    fi
    ;;
  killlan)
    for p in $(ip netns pids "$HOME_NS" 2>/dev/null); do
      tr '\0' ' ' < "/proc/$p/cmdline" 2>/dev/null | grep -q -- '/tcpquality.py ' && kill "$p" 2>/dev/null
    done
    exit 0
    ;;
  stop)
    adata=${2:?stop <adata> <cgroup root>} cgroot=${3:?}
    # everything in home: the agent, and with the LAN host there (TARGET_LOCAL) its servers too
    for p in $(ip netns pids "$HOME_NS" 2>/dev/null); do kill "$p" 2>/dev/null; done
    for _ in $(seq 1 50); do [ -z "$(ip netns pids "$HOME_NS" 2>/dev/null)" ] && break; sleep 0.2; done
    for p in $(ip netns pids "$HOME_NS" 2>/dev/null); do kill -9 "$p" 2>/dev/null; done
    ip netns exec "$HOME_NS" ip link del wgft0 2>/dev/null
    ip netns exec "$HOME_NS" nft delete table inet wgft_agent 2>/dev/null
    rmdir "$cgroot"-* 2>/dev/null
    rm -rf "$adata"
    exit 0
    ;;
  *)
    echo "usage: tqagent.sh gso|start|own|stop ..." >&2
    exit 2
    ;;
esac
