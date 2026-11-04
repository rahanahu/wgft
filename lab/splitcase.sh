#!/usr/bin/env bash
# splitcase.sh puts a VM of `lab/lab paired --split --cases` back into the state its setup left, so
# that the next case runs in the same VM pair as if it were the first. It runs in each of the two VMs
# and acts on the lab namespaces that VM holds: home in the agent VM; client, vps, homerouter and lan
# in the peer VM.
#
#   splitcase.sh save            record the TCP buffer sysctls of the lab namespaces and the VM's
#                                tcp_mem, once after setup
#   splitcase.sh reset           stop every process in the lab namespaces and, in the peer VM, any
#                                tcpquality run a timed-out case left behind; remove the agent's
#                                interface and table in home and the netem qdiscs of the peer's
#                                vps-homerouter link; put the recorded sysctls and tcp_mem back
#   splitcase.sh target lan|local  move the LAN host's address as `--target` sets it up: local puts
#                                192.168.50.3 on home's lo (agent VM) and takes it off lan's eth0
#                                (peer VM); lan does the reverse
#
# tcpquality.sh itself undoes at exit what a run changes (netem, the server, the agent, UDP GSO and
# KERNEL_RMEM_MAX), except TCP_BUF_MAX, which raises tcp_rmem and tcp_wmem in client and in the LAN
# host's namespace (lan, or home with --target local) and leaves them raised. tcp_mem, which
# tcpquality.sh raises for TCP_BUF_MAX and puts back at exit, is put back here too, for a run that
# was killed before its exit. agentd runs in the root namespace of the agent VM and is left alone.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/sandbox.sh"
STATE=/run/wgft-split-case.state
TCPMEM_STATE=/run/wgft-split-case.tcp_mem
LAN_ADDR=192.168.50.3  # lab/netns.sh LAN_ADDR
HR_LAN=192.168.50.1    # lab/netns.sh HR_LAN

lab_ns() { # the lab namespaces in this VM
  local ns
  for ns in "$HOME_NS" "$CLIENT_NS" "$VPS_NS" "$ROUTER_NS" "$LAN_NS"; do
    ip netns list 2>/dev/null | awk '{ print $1 }' | grep -qx "$ns" && echo "$ns"
  done
}
has_ns() { lab_ns | grep -qx "$1"; }

case "${1:-}" in
  save)
    : > "$STATE"
    for ns in $(lab_ns); do
      echo "$ns $(ip netns exec "$ns" sysctl -n net.ipv4.tcp_rmem | tr -s ' \t' ' ')|$(ip netns exec "$ns" sysctl -n net.ipv4.tcp_wmem | tr -s ' \t' ' ')" >> "$STATE"
    done
    sysctl -n net.ipv4.tcp_mem | tr -s ' \t' ' ' > "$TCPMEM_STATE"
    cat "$STATE"
    echo "tcp_mem $(cat "$TCPMEM_STATE")"
    ;;
  reset)
    [ -s "$STATE" ] || { echo "splitcase.sh: no saved state in $STATE; run save after the setup" >&2; exit 1; }
    rc=0
    stale=0
    # a case that timed out can leave its tcpquality-cpu.sh, tcpquality.sh or tcpquality.py running in
    # the peer VM's root namespace, agentx clients among them; agentd lives only in the agent VM, so
    # in the peer VM every such process goes
    if has_ns "$VPS_NS"; then
      for p in /proc/[0-9]*; do
        pid=${p#/proc/}
        [ "$pid" = $$ ] && continue
        args=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
        case $args in
          *"/lab/tcpquality-cpu.sh"* | *"/lab/tcpquality.sh"* | *"/lab/tcpquality.py"*) kill -9 "$pid" 2>/dev/null && stale=$((stale + 1)) ;;
        esac
      done
    fi
    for ns in $(lab_ns); do
      for pid in $(ip netns pids "$ns" 2>/dev/null); do kill -9 "$pid" 2>/dev/null && stale=$((stale + 1)); done
    done
    for _ in $(seq 1 50); do
      left=0
      for ns in $(lab_ns); do [ -z "$(ip netns pids "$ns" 2>/dev/null)" ] || left=1; done
      [ "$left" = 0 ] && break
      sleep 0.1
    done
    [ "$left" = 0 ] || { echo "splitcase.sh: processes stay in the lab namespaces"; rc=1; }
    if has_ns "$HOME_NS"; then
      ip netns exec "$HOME_NS" ip link del wgft0 2>/dev/null
      ip netns exec "$HOME_NS" nft delete table inet wgft_agent 2>/dev/null
    fi
    if has_ns "$VPS_NS"; then
      ip netns exec "$VPS_NS" tc qdisc del dev pub1 root 2>/dev/null
      ip netns exec "$ROUTER_NS" tc qdisc del dev wan0 root 2>/dev/null
    fi
    while read -r ns vals; do
      r=${vals%|*} w=${vals#*|}
      ip netns exec "$ns" sysctl -qw net.ipv4.tcp_rmem="$r" net.ipv4.tcp_wmem="$w" || rc=1
      [ "$(ip netns exec "$ns" sysctl -n net.ipv4.tcp_rmem | tr -s ' \t' ' ')" = "$r" ] || { echo "splitcase.sh: tcp_rmem of $ns stays changed"; rc=1; }
      [ "$(ip netns exec "$ns" sysctl -n net.ipv4.tcp_wmem | tr -s ' \t' ' ')" = "$w" ] || { echo "splitcase.sh: tcp_wmem of $ns stays changed"; rc=1; }
    done < "$STATE"
    if [ -s "$TCPMEM_STATE" ]; then
      m=$(cat "$TCPMEM_STATE")
      sysctl -qw net.ipv4.tcp_mem="$m" || rc=1
      [ "$(sysctl -n net.ipv4.tcp_mem | tr -s ' \t' ' ')" = "$m" ] || { echo "splitcase.sh: tcp_mem stays changed"; rc=1; }
    fi
    # sockets left over, orphaned or in TIME_WAIT, keep TCP memory, which matters with 64 MiB buffers;
    # the counts per namespace go to the log
    for ns in $(lab_ns); do
      echo "splitcase.sh: sockstat $ns: $(ip netns exec "$ns" grep -E '^(TCP|UDP):' /proc/net/sockstat | tr '\n' ' ')"
    done
    echo "splitcase.sh: reset $(lab_ns | tr '\n' ' ')processes stopped: $stale, rc=$rc"
    exit "$rc"
    ;;
  target)
    want=${2:-}
    case $want in lan | local) ;; *) echo "usage: splitcase.sh target lan|local" >&2; exit 2 ;; esac
    if has_ns "$HOME_NS"; then
      if [ "$want" = local ]; then
        ip -n "$HOME_NS" addr replace "$LAN_ADDR/32" dev lo || exit 1
      else
        ip -n "$HOME_NS" addr del "$LAN_ADDR/32" dev lo 2>/dev/null
      fi
    fi
    if has_ns "$LAN_NS"; then
      if [ "$want" = local ]; then
        ip -n "$LAN_NS" addr flush dev eth0 || exit 1
      else
        ip -n "$LAN_NS" addr replace "$LAN_ADDR/24" dev eth0 || exit 1
        ip -n "$LAN_NS" route replace default via "$HR_LAN" || exit 1
      fi
    fi
    echo "splitcase.sh: target $want in $(lab_ns | tr '\n' ' ')"
    ;;
  *)
    echo "usage: splitcase.sh save|reset|target lan|local" >&2
    exit 2
    ;;
esac
