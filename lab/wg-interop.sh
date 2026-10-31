#!/usr/bin/env bash
# wg-interop.sh checks that the v2 Rust WireGuard device (crates/wgft-wireguard, run over a TUN
# device by crates/wgft-wireguard-tun) interoperates with Linux kernel WireGuard and with
# wireguard-go, the two WireGuard implementations the Go v1 server uses.
#
#   WGFT_LAB_RUST=1 lab/lab build
#   lab/lab exec vm bash /wgft/lab/wg-interop.sh [kernel|wggo|all] [quick]
#
# The Rust side plays the agent: it knows the peer's endpoint, keeps a persistent keepalive and
# allows only the peer's /32. The peer plays the server: it knows only the agent's key and /32 and
# learns the endpoint from the handshake. The two sit in their own network namespaces, wgi-<peer>-a
# and wgi-<peer>-b, joined by a veth pair; the lab's shared topology is not used.
#
# Checks, in order, for each peer: the handshake; the routing the shell installs (the tunnel
# address as a /32, no route of the main table on the TUN, the peer's /32 only for traffic from the
# tunnel address, and a blackhole for anything forwarded from the TUN, with strict reverse-path
# filtering on); ping in both directions; a TCP transfer of 8 MiB each way compared by SHA-256; the
# Rust side roaming to a new UDP port; the peer moving to a new listen port; packets for another
# address dropped and counted; the peer restarting with the same key; the Rust side restarting,
# with its rules gone while it is stopped; and, unless
# `quick` is given, a rekey after REKEY_AFTER_TIME, 120 s, under steady ping. Last, the final status
# must show no dropped invalid inner packet and no refused TUN write. The rekey wait is fixed by the
# protocol; sanstun does not let it be shortened.
#
# Needs root in the VM, wireguard-tools, socat, and the wgft-wireguard-tun and wireguard-go
# binaries that `lab/lab build` builds into bin/rust/ and installs when WGFT_LAB_RUST=1 is set on the host.
set -u
peers=${1:-all}
quick=${2:-}
case "$peers" in kernel|wggo) ;; all) peers="kernel wggo" ;; *) echo "usage: wg-interop.sh [kernel|wggo|all] [quick]" >&2; exit 2;; esac
case "$quick" in ""|quick) ;; *) echo "usage: wg-interop.sh [kernel|wggo|all] [quick]" >&2; exit 2;; esac

. "$(dirname "$0")/sandbox.sh"   # W, the workdir

for bin in wgft-wireguard-tun wireguard-go wg socat; do
  command -v "$bin" >/dev/null || { echo "wg-interop: $bin not found; run WGFT_LAB_RUST=1 lab/lab build first" >&2; exit 2; }
done

A_IP=10.200.0.2      # Rust device, agent side
B_IP=10.200.0.1      # peer, server side
A_UDP=192.0.2.1
B_UDP=192.0.2.2
B_PORT=51820
failures=0

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; failures=$((failures + 1)); }

# wait_for <seconds> <command...>: retries the command every 0.5 s until it succeeds.
wait_for() {
  local deadline=$((SECONDS + $1)); shift
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < deadline)) || return 1
    sleep 0.5
  done
}

run_peer() {
  local kind=$1
  local na=wgi-$kind-a nb=wgi-$kind-b dir=$W/wgi-$kind
  local ifb shell_pid="" peer_pid=""
  case "$kind" in kernel) ifb=wgk0 ;; wggo) ifb=wggo0 ;; esac
  rm -rf "$dir"; mkdir -p "$dir"
  local log=$dir/shell.log

  cleanup() {
    [[ -n $shell_pid ]] && kill "$shell_pid" 2>/dev/null
    [[ -n $peer_pid ]] && kill "$peer_pid" 2>/dev/null
    wait 2>/dev/null
    ip netns del "$na" 2>/dev/null
    ip netns del "$nb" 2>/dev/null
    rm -f "/var/run/wireguard/$ifb.sock"
  }
  cleanup

  ip netns add "$na"; ip netns add "$nb"
  ip link add wgi-a netns "$na" type veth peer name wgi-b netns "$nb"
  ip -n "$na" addr add "$A_UDP/24" dev wgi-a; ip -n "$na" link set wgi-a up; ip -n "$na" link set lo up
  # strict reverse-path filtering is the harshest case for the shell's rules
  ip netns exec "$na" sysctl -qw net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1
  ip -n "$nb" addr add "$B_UDP/24" dev wgi-b; ip -n "$nb" link set wgi-b up; ip -n "$nb" link set lo up

  wg genkey > "$dir/a.key"; wg pubkey < "$dir/a.key" > "$dir/a.pub"
  wg genkey > "$dir/b.key"; wg pubkey < "$dir/b.key" > "$dir/b.pub"

  start_peer() {
    case "$kind" in
      kernel)
        ip -n "$nb" link add "$ifb" type wireguard
        ;;
      wggo)
        rm -f "/var/run/wireguard/$ifb.sock"
        # wireguard-go refuses to run on Linux without this variable, since Linux has its own WireGuard
        WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1 ip netns exec "$nb" wireguard-go -f "$ifb" >"$dir/wggo.log" 2>&1 &
        peer_pid=$!
        wait_for 10 test -S "/var/run/wireguard/$ifb.sock" || { fail "$kind: wireguard-go did not start"; return 1; }
        ;;
    esac
    ip netns exec "$nb" wg set "$ifb" listen-port "$B_PORT" private-key "$dir/b.key" \
      peer "$(cat "$dir/a.pub")" allowed-ips "$A_IP/32"
    ip -n "$nb" addr add "$B_IP/24" dev "$ifb"
    ip -n "$nb" link set "$ifb" mtu 1420 up
  }

  stop_peer() {
    case "$kind" in
      kernel) ip -n "$nb" link del "$ifb" ;;
      wggo) kill "$peer_pid" 2>/dev/null; wait "$peer_pid" 2>/dev/null; peer_pid="" ;;
    esac
  }

  start_shell() {
    ip netns exec "$na" wgft-wireguard-tun --tun wgft-rs0 --address "$A_IP" \
      --private-key-file "$dir/a.key" --peer-public-key "$(cat "$dir/b.pub")" \
      --endpoint "$B_UDP:$B_PORT" --allowed-ip "$B_IP/32" --keepalive 25 >>"$log" 2>&1 &
    shell_pid=$!
  }

  stop_shell() { kill "$shell_pid" 2>/dev/null; wait "$shell_pid" 2>/dev/null; shell_pid=""; }

  # The shell routes the tunnel only for traffic from the tunnel address, so the Rust side pings
  # from it, as the agent's ping socket does.
  pings() {
    local src=()
    [[ $1 == "$na" ]] && src=(-I "$A_IP")
    ip netns exec "$1" ping "${src[@]}" -c "${3:-3}" -i 0.2 -W 2 -q "$2"
  }
  established_count() { grep -c 'session-established' "$log" 2>/dev/null || true; }
  established_since() { (($(established_count) > $1)); }
  peer_endpoint() { ip netns exec "$nb" wg show "$ifb" endpoints | awk '{print $2}'; }
  peer_handshake() { ip netns exec "$nb" wg show "$ifb" latest-handshakes | awk '{print $2}'; }

  echo "--- peer $kind"
  start_peer || { cleanup; return; }
  start_shell

  # 1. handshake
  if wait_for 10 grep -q 'session-established' "$log"; then pass "$kind: handshake"; else fail "$kind: handshake"; fi

  # 2. routing: no route of the main table goes to the TUN, the server's /32 is reached only from
  #    the tunnel address, and packets arriving on the TUN for anything but this host are
  #    blackholed even with forwarding on
  local rules route_main route_other route_from route_fwd
  rules=$(ip -n "$na" rule show)
  route_main=$(ip -n "$na" route show table main)
  route_other=$(ip -n "$na" route get 10.200.0.3 2>&1)
  route_from=$(ip -n "$na" route get "$B_IP" from "$A_IP" 2>&1)
  ip netns exec "$na" sysctl -qw net.ipv4.ip_forward=1
  route_fwd=$(ip -n "$na" route get "$B_UDP" from "$B_IP" iif wgft-rs0 2>&1)
  ip netns exec "$na" sysctl -qw net.ipv4.ip_forward=0
  if [[ $rules == *"from $A_IP lookup 51820"* && $rules == *"iif wgft-rs0"*blackhole* \
        && $route_main != *wgft-rs0* && $route_other != *wgft-rs0* \
        && $route_from == *"dev wgft-rs0"* && $route_fwd != *"dev wgi-a"* ]]; then
    pass "$kind: routing stays inside the tunnel's own table"
  else
    fail "$kind: routing; rules [$rules] main [$route_main] other [$route_other] from [$route_from] forwarded [$route_fwd]"
  fi

  # 2b. ping both ways
  if pings "$na" "$B_IP" 5; then pass "$kind: ping to the peer"; else fail "$kind: ping to the peer"; fi
  if pings "$nb" "$A_IP" 5; then pass "$kind: ping from the peer"; else fail "$kind: ping from the peer"; fi

  # 3. TCP 8 MiB each way with SHA-256
  head -c 8M /dev/urandom > "$dir/send"
  local want got
  want=$(sha256sum < "$dir/send" | cut -d' ' -f1)
  ip netns exec "$nb" timeout 60 socat -u TCP-LISTEN:5001,bind="$B_IP",reuseaddr OPEN:"$dir/recv-b",creat,trunc &
  local lp=$!
  sleep 0.5
  ip netns exec "$na" timeout 60 socat -u OPEN:"$dir/send" TCP:"$B_IP":5001,bind="$A_IP"
  wait "$lp"
  got=$(sha256sum < "$dir/recv-b" | cut -d' ' -f1)
  if [[ $got == "$want" ]]; then pass "$kind: TCP 8 MiB to the peer"; else fail "$kind: TCP 8 MiB to the peer, sha256 $got want $want"; fi
  ip netns exec "$na" timeout 60 socat -u TCP-LISTEN:5002,bind="$A_IP",reuseaddr OPEN:"$dir/recv-a",creat,trunc &
  lp=$!
  sleep 0.5
  ip netns exec "$nb" timeout 60 socat -u OPEN:"$dir/send" TCP:"$A_IP":5002
  wait "$lp"
  got=$(sha256sum < "$dir/recv-a" | cut -d' ' -f1)
  if [[ $got == "$want" ]]; then pass "$kind: TCP 8 MiB from the peer"; else fail "$kind: TCP 8 MiB from the peer, sha256 $got want $want"; fi

  # 4. the Rust side roams to a new UDP port; the peer follows after authenticated traffic
  local before after
  before=$(peer_endpoint)
  kill -USR2 "$shell_pid"
  wait_for 5 grep -q '^rebound' "$log"
  pings "$na" "$B_IP" 3 >/dev/null
  after=$(peer_endpoint)
  if [[ -n $after && $after != "$before" ]] && pings "$nb" "$A_IP" 3; then
    pass "$kind: Rust side roamed $before to $after"
  else
    fail "$kind: Rust side roaming, peer endpoint $before then $after"
  fi

  # 5. the peer moves to a new listen port; the Rust device follows after authenticated traffic
  ip netns exec "$nb" wg set "$ifb" listen-port $((B_PORT + 1))
  pings "$nb" "$A_IP" 3 >/dev/null
  if grep -q "endpoint-changed .*endpoint=$B_UDP:$((B_PORT + 1))" "$log" && pings "$na" "$B_IP" 3; then
    pass "$kind: peer roamed to port $((B_PORT + 1))"
  else
    fail "$kind: peer roaming to port $((B_PORT + 1))"
  fi
  ip netns exec "$nb" wg set "$ifb" listen-port "$B_PORT"
  pings "$nb" "$A_IP" 3 >/dev/null

  # 5b. packets to an address other than the tunnel address are dropped before the kernel and
  #     counted: let the peer route a neighbour address to the Rust side for a moment
  ip netns exec "$nb" wg set "$ifb" peer "$(cat "$dir/a.pub")" allowed-ips "10.200.0.0/24"
  ip -n "$nb" route replace 10.200.0.9/32 dev "$ifb"
  ip netns exec "$nb" ping -c 2 -i 0.2 -W 1 -q 10.200.0.9 >/dev/null 2>&1
  ip -n "$nb" route del 10.200.0.9/32 dev "$ifb"
  ip netns exec "$nb" wg set "$ifb" peer "$(cat "$dir/a.pub")" allowed-ips "$A_IP/32"
  kill -USR1 "$shell_pid"; sleep 0.3
  if grep '^status' "$log" | tail -1 | grep -q 'wrong_destination=[1-9]'; then
    pass "$kind: packets for another address are dropped and counted"
  else
    fail "$kind: wrong destination, $(grep '^status' "$log" | tail -1)"
  fi

  # 6. the peer restarts with the same key and no endpoint. Data without a reply starts a new
  #    handshake after KEEPALIVE_TIMEOUT + REKEY_TIMEOUT, 15 s, so ping until it answers.
  stop_peer; start_peer
  local t0=$SECONDS
  if wait_for 40 pings "$na" "$B_IP" 1; then pass "$kind: peer restart, back after $((SECONDS - t0)) s"; else fail "$kind: peer restart"; fi

  # 7. the Rust side restarts; its later wall clock makes the new initiation acceptable
  local n0
  n0=$(established_count)
  stop_shell
  if ip -n "$na" rule show | grep -q 'lookup 51820\|iif wgft-rs0'; then
    fail "$kind: the stopped shell left its rules: $(ip -n "$na" rule show | tr '\n' ';')"
  else
    pass "$kind: the stopped shell removed its rules"
  fi
  start_shell
  if wait_for 10 established_since "$n0" && pings "$na" "$B_IP" 3; then
    pass "$kind: Rust side restart"
  else
    fail "$kind: Rust side restart"
  fi

  # 8. rekey under steady ping
  if [[ $quick != quick ]]; then
    local h0 h1 accepted0 accepted1
    h0=$(peer_handshake)
    accepted0=$(grep -c 'handshake-accepted' "$log")
    ip netns exec "$na" ping -I "$A_IP" -c 135 -i 1 -W 2 -q "$B_IP" > "$dir/rekey-ping.txt" 2>&1
    h1=$(peer_handshake)
    accepted1=$(grep -c 'handshake-accepted' "$log")
    local loss
    loss=$(grep -o '[0-9.]*% packet loss' "$dir/rekey-ping.txt")
    if [[ $h1 -gt $h0 && $accepted1 -gt $accepted0 && $loss == "0% packet loss" ]]; then
      pass "$kind: rekey under ping, $loss"
    else
      fail "$kind: rekey, peer handshake $h0 then $h1, Rust handshakes $accepted0 then $accepted1, $loss"
    fi
  fi

  # 9. the kernel sends nothing but IPv4 into the TUN, so the device dropped no invalid inner packet
  kill -USR1 "$shell_pid"; sleep 0.3
  local status
  status=$(grep '^status' "$log" | tail -1)
  echo "$status"
  if [[ -n $status && $status != *drop_invalid-inner-packet* && $status != *tun_write_errors=[1-9]* ]]; then
    pass "$kind: no invalid inner packets or TUN write errors"
  else
    fail "$kind: final status $status"
  fi
  if ((failures > 0)); then
    echo "--- Rust shell log for $kind"; tail -40 "$log"
  fi
  cleanup
}

for kind in $peers; do
  run_peer "$kind"
done

if ((failures > 0)); then
  echo "wg-interop: $failures checks failed"
  exit 1
fi
echo "wg-interop: all checks passed"
