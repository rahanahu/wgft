#!/usr/bin/env bash
# wgft ラボのトポロジを netns で組む。VM 内で root として実行する(Incus には依存しないが、CI では流していない。docs/testing.md の「CI とラボの関係」)。
#
#   client ── vps ── homerouter(NAT) ─┬─ home(エージェント)
#                                     └─ lan(自宅 LAN 上の別ホスト。ゲームサーバ役)
#
# home と lan は homerouter の中の 1 つのブリッジ(br0)にぶら下がる、同じ自宅 LAN セグメント。
#
# 使い方: netns.sh up | down | status
#         netns.sh up-split-peer <IF> | up-split-agent <IF>
#
# up-split-* は `lab/lab paired --split` の 2 台の VM の片方を組む。agent の VM は home だけを持ち、VM の NIC <IF> を
# home の eth0 にする。相手の VM は home 以外の 4 つを持ち、VM の NIC <IF> を homerouter の lan0 にして br0 に繋ぐ。
# 2 台の NIC はホストの専用のブリッジで繋がるので、home は今と同じアドレスで同じ LAN セグメントに乗る。
# 1 台の VM の netns と違い、agent の VM の CPU は agent と、その NIC とカーネルの仕事だけが使う。
# カーネルモードの WireGuard の暗号の kworker はその VM の全 CPU に配られるので、CPU を分けるには VM を分ける
set -euo pipefail

# netns の名前は環境変数で差し替えられる。未設定なら今までと同じ名前を使うので、共有の
# トポロジを組む使い方 (lab/lab net up) は変わらない。名前を変えると、同じトポロジを 1 台の VM の
# 中に何組でも並べられる (netns の中ではインタフェース名もアドレスもポートも使い回せる)。
CLIENT_NS=${WGFT_LAB_CLIENT_NS:-client}
VPS_NS=${WGFT_LAB_VPS_NS:-vps}
ROUTER_NS=${WGFT_LAB_ROUTER_NS:-homerouter}
HOME_NS=${WGFT_LAB_HOME_NS:-home}
LAN_NS=${WGFT_LAB_LAN_NS:-lan}
NAMESPACES=("$CLIENT_NS" "$VPS_NS" "$ROUTER_NS" "$HOME_NS" "$LAN_NS")

# アドレス(ドキュメント用のアドレス帯を使い、実在の経路と衝突させない)
CLIENT_ADDR=198.51.100.2   # client の eth0
VPS_PUB0=198.51.100.1      # vps の client 側(公開 IF)
VPS_PUB1=203.0.113.1       # vps の homerouter 側(公開 IF。WireGuard とエージェント API の宛先)
HR_WAN=203.0.113.2         # homerouter の WAN(home の通信はこのアドレスに masquerade される)
HR_LAN=192.168.50.1        # homerouter の LAN(br0)
HOME_ADDR=192.168.50.2     # home の eth0(エージェント)
LAN_ADDR=192.168.50.3      # lan の eth0(LAN 上の別ホスト。ゲートウェイは homerouter)

# client - vps の間だけ IPv6 を持たせる(ドキュメント用のプレフィクス 2001:db8::/32。L13:
# wgft は v1 では IPv4 だけを扱い、IPv6 の送信元を拒む。設計文書 7a.9 節)。homerouter より先には
# IPv6 の経路も宛先も無いので、home と lan には加えない。
CLIENT_ADDR6=2001:db8::2   # client の eth0
VPS_PUB0_6=2001:db8::1     # vps の client 側(公開 IF)

# Fixed ports the vps namespace binds that fall inside the kernel's default ephemeral range
# (32768-60999, see /proc/sys/net/ipv4/ip_local_port_range): the rule ports lifecycle.sh,
# upgrade.sh, e2e.sh, ipv6.sh and version-skew.sh use as --tcp/--udp targets (39900-39999) and
# the WireGuard endpoint port (51820, from --wg-endpoint 203.0.113.1:51820). Every admin CLI call
# in this namespace (`wgft rule add/ls/rm ... --admin 127.0.0.1:8686`) is an outbound loopback
# TCP connection that takes an ephemeral source port and leaves it in TIME_WAIT for 60s; the
# kernel can hand out a contiguous band that covers one of the ports above, and the server's own
# bind/listen on it then fails with "address already in use" until its next 30s reconcile. This
# is the single place that lists these ports. net.ipv4.ip_local_reserved_ports is namespaced, so
# reserving them only in vps (below, once the namespace exists) leaves client/home/lan/homerouter
# untouched and keeps the kernel from ever handing one of these ports out as an ephemeral source
# port here.
RESERVED_PORTS=39900-39999,51820

die() { echo "netns.sh: $*" >&2; exit 1; }

# veth の両端を別々の ns に置いて up する: link <ns1> <if1> <ns2> <if2>
link() {
  ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
  ip -n "$1" link set "$2" up
  ip -n "$3" link set "$4" up
}

down() {
  for ns in "${NAMESPACES[@]}"; do
    ip netns del "$ns" 2>/dev/null || true
  done
}

up() {
  down
  for ns in "${NAMESPACES[@]}"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  ip netns exec "$VPS_NS" sysctl -qw net.ipv4.ip_local_reserved_ports="$RESERVED_PORTS"

  link "$CLIENT_NS" eth0 "$VPS_NS" pub0
  ip -n "$CLIENT_NS" addr add "$CLIENT_ADDR/24" dev eth0
  ip -n "$VPS_NS" addr add "$VPS_PUB0/24" dev pub0
  ip -n "$CLIENT_NS" route add default via "$VPS_PUB0"
  # nodad: skip duplicate address detection. The link has exactly the 2 peers we assign here, so
  # DAD only adds a race between this script's own check() (right below) and the ~1s the address
  # would otherwise sit tentative.
  ip -n "$CLIENT_NS" addr add "$CLIENT_ADDR6/64" dev eth0 nodad
  ip -n "$VPS_NS" addr add "$VPS_PUB0_6/64" dev pub0 nodad

  link "$VPS_NS" pub1 "$ROUTER_NS" wan0
  ip -n "$VPS_NS" addr add "$VPS_PUB1/24" dev pub1
  ip -n "$ROUTER_NS" addr add "$HR_WAN/24" dev wan0
  ip -n "$ROUTER_NS" route add default via "$VPS_PUB1"

  # homerouter の LAN 側はブリッジ(br0)。home(エージェント)と lan(別ホスト)を同じセグメントに乗せる
  link "$ROUTER_NS" lan0 "$HOME_NS" eth0
  link "$ROUTER_NS" lan1 "$LAN_NS" eth0
  ip -n "$ROUTER_NS" link add br0 type bridge
  ip -n "$ROUTER_NS" link set lan0 master br0
  ip -n "$ROUTER_NS" link set lan1 master br0
  ip -n "$ROUTER_NS" link set br0 up
  ip -n "$ROUTER_NS" addr add "$HR_LAN/24" dev br0
  ip -n "$HOME_NS" addr add "$HOME_ADDR/24" dev eth0
  ip -n "$HOME_NS" route add default via "$HR_LAN"
  ip -n "$LAN_NS" addr add "$LAN_ADDR/24" dev eth0
  ip -n "$LAN_NS" route add default via "$HR_LAN"

  ip netns exec "$ROUTER_NS" sysctl -qw net.ipv4.ip_forward=1
  # nft 1.0.6(Debian 12)は入れ子を 1 行で書くと構文エラーになるので複数行で書く
  ip netns exec "$ROUTER_NS" nft -f - <<'NFT'
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname "wan0" masquerade
  }
}
NFT

  # vps の ip_forward は vpsd が起動時に設定する(仕様 6.1 節)ので、ここでは触らない
  check
}

check() {
  ip netns exec "$CLIENT_NS" ping -c1 -W2 "$VPS_PUB0" >/dev/null || die "client -> vps に届かない"
  ip netns exec "$CLIENT_NS" ping -6 -c1 -W2 "$VPS_PUB0_6" >/dev/null || die "client -> vps に ipv6 で届かない"
  ip netns exec "$HOME_NS" ping -c1 -W2 "$HR_LAN" >/dev/null || die "home -> homerouter に届かない"
  ip netns exec "$LAN_NS" ping -c1 -W2 "$HR_LAN" >/dev/null || die "lan -> homerouter に届かない"
  ip netns exec "$LAN_NS" ping -c1 -W2 "$HOME_ADDR" >/dev/null || die "lan -> home に届かない(br0 のブリッジ)"
  ip netns exec "$ROUTER_NS" ping -c1 -W2 "$VPS_PUB1" >/dev/null || die "homerouter -> vps に届かない"
  echo "lab topology is up"
}

# move_if <IF> <ns> <name>:VM の NIC を netns に移して名前を変え、up する
move_if() {
  ip link show "$1" >/dev/null 2>&1 || die "no interface $1 in this VM"
  ip link set "$1" netns "$2"
  ip -n "$2" link set "$1" name "$3"
  ip -n "$2" link set "$3" up
}

up_split_peer() {
  local nic=$1
  down
  NAMESPACES=("$CLIENT_NS" "$VPS_NS" "$ROUTER_NS" "$LAN_NS")
  for ns in "${NAMESPACES[@]}"; do
    ip netns add "$ns"
    ip -n "$ns" link set lo up
  done
  ip netns exec "$VPS_NS" sysctl -qw net.ipv4.ip_local_reserved_ports="$RESERVED_PORTS"
  link "$CLIENT_NS" eth0 "$VPS_NS" pub0
  ip -n "$CLIENT_NS" addr add "$CLIENT_ADDR/24" dev eth0
  ip -n "$VPS_NS" addr add "$VPS_PUB0/24" dev pub0
  ip -n "$CLIENT_NS" route add default via "$VPS_PUB0"
  ip -n "$CLIENT_NS" addr add "$CLIENT_ADDR6/64" dev eth0 nodad
  ip -n "$VPS_NS" addr add "$VPS_PUB0_6/64" dev pub0 nodad
  link "$VPS_NS" pub1 "$ROUTER_NS" wan0
  ip -n "$VPS_NS" addr add "$VPS_PUB1/24" dev pub1
  ip -n "$ROUTER_NS" addr add "$HR_WAN/24" dev wan0
  ip -n "$ROUTER_NS" route add default via "$VPS_PUB1"
  move_if "$nic" "$ROUTER_NS" lan0
  link "$ROUTER_NS" lan1 "$LAN_NS" eth0
  ip -n "$ROUTER_NS" link add br0 type bridge
  ip -n "$ROUTER_NS" link set lan0 master br0
  ip -n "$ROUTER_NS" link set lan1 master br0
  ip -n "$ROUTER_NS" link set br0 up
  ip -n "$ROUTER_NS" addr add "$HR_LAN/24" dev br0
  ip -n "$LAN_NS" addr add "$LAN_ADDR/24" dev eth0
  ip -n "$LAN_NS" route add default via "$HR_LAN"
  ip netns exec "$ROUTER_NS" sysctl -qw net.ipv4.ip_forward=1
  ip netns exec "$ROUTER_NS" nft -f - <<'NFT'
table ip nat {
  chain postrouting {
    type nat hook postrouting priority srcnat;
    oifname "wan0" masquerade
  }
}
NFT
  ip netns exec "$CLIENT_NS" ping -c1 -W2 "$VPS_PUB0" >/dev/null || die "client -> vps に届かない"
  ip netns exec "$LAN_NS" ping -c1 -W2 "$HR_LAN" >/dev/null || die "lan -> homerouter に届かない"
  ip netns exec "$ROUTER_NS" ping -c1 -W2 "$VPS_PUB1" >/dev/null || die "homerouter -> vps に届かない"
  # veth は送ったスレッドの CPU の backlog に積むので、送り手 (iperf3 など) が CPU を移ると、同じ flow の packet が 2 つの
  # CPU で並行に処理されて順が崩れる。8 vCPU の相手の VM では LAN のホストから agent への TCP で 1 実行に千から数万件の
  # out-of-order が出た (2026-11-04)。全 veth の受信に RPS を掛け、flow ごとに受ける CPU を 1 つにして順を保つ
  local all ns dev
  all=$(printf '%x' $(( (1 << $(nproc)) - 1 )))
  for ns in "${NAMESPACES[@]}"; do
    for dev in $(ip -n "$ns" -o link show type veth | awk -F': ' '{ sub(/@.*/, "", $2); print $2 }'); do
      ip netns exec "$ns" sh -c "echo $all > /sys/class/net/$dev/queues/rx-0/rps_cpus" || die "cannot set RPS on $dev in $ns"
    done
  done
  # RPS で 1 つの CPU に流れを寄せると、既定の netdev_max_backlog (1000) を溢れることがあった (1 実行に 23 packet)
  sysctl -qw net.core.netdev_max_backlog=10000
  echo "lab split topology (peer) is up; home is in the agent VM; RPS on every veth over CPUs $all; netdev_max_backlog 10000"
}

# split_peer_rps <16 進の mask>:相手の VM の全 veth の RPS を mask の CPU に絞る (lab/lab paired --placement apart が
# CPU 0 を外し、1 つの flow の受信の softirq が NIC の割り込みの vCPU に載らないようにする)
split_peer_rps() {
  local ns dev
  for ns in "$CLIENT_NS" "$VPS_NS" "$ROUTER_NS" "$LAN_NS"; do
    for dev in $(ip -n "$ns" -o link show type veth | awk -F': ' '{ sub(/@.*/, "", $2); print $2 }'); do
      ip netns exec "$ns" sh -c "echo $1 > /sys/class/net/$dev/queues/rx-0/rps_cpus" || die "cannot set RPS on $dev in $ns"
    done
  done
  echo "RPS on every veth of the peer VM over the CPU mask $1"
}

up_split_agent() {
  local nic=$1
  down
  NAMESPACES=("$HOME_NS")
  ip netns add "$HOME_NS"
  ip -n "$HOME_NS" link set lo up
  move_if "$nic" "$HOME_NS" eth0
  ip -n "$HOME_NS" addr add "$HOME_ADDR/24" dev eth0
  ip -n "$HOME_NS" route add default via "$HR_LAN"
  echo "lab split topology (agent) is up; the router is in the peer VM"
}

status() {
  for ns in "${NAMESPACES[@]}"; do
    if ip netns list | grep -qw "^$ns"; then
      echo "== $ns"
      ip -n "$ns" -br addr | grep -v '^lo '
    else
      echo "== $ns (absent)"
    fi
  done
}

[[ $EUID -eq 0 ]] || die "root で実行する"
case "${1:-}" in
  up) up ;;
  down) down ;;
  status) status ;;
  up-split-peer) up_split_peer "${2:?up-split-peer <IF>}" ;;
  up-split-agent) up_split_agent "${2:?up-split-agent <IF>}" ;;
  split-peer-rps) split_peer_rps "${2:?split-peer-rps <HEXMASK>}" ;;
  *) echo "usage: $0 up|down|status|up-split-peer <IF>|up-split-agent <IF>|split-peer-rps <HEXMASK>" >&2; exit 2 ;;
esac
