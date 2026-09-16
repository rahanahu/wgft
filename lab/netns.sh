#!/usr/bin/env bash
# wgft ラボのトポロジを netns で組む。VM 内か CI 上で root として実行する(Incus には依存しない)。
#
#   client ── vps ── homerouter(NAT) ── home
#
# 使い方: netns.sh up | down | status
set -euo pipefail

NAMESPACES=(client vps homerouter home)

# アドレス(ドキュメント用のアドレス帯を使い、実在の経路と衝突させない)
CLIENT_ADDR=198.51.100.2   # client の eth0
VPS_PUB0=198.51.100.1      # vps の client 側(公開 IF)
VPS_PUB1=203.0.113.1       # vps の homerouter 側(公開 IF。WireGuard とエージェント API の宛先)
HR_WAN=203.0.113.2         # homerouter の WAN(home の通信はこのアドレスに masquerade される)
HR_LAN=192.168.50.1        # homerouter の LAN
HOME_ADDR=192.168.50.2     # home の eth0

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

  link client eth0 vps pub0
  ip -n client addr add "$CLIENT_ADDR/24" dev eth0
  ip -n vps addr add "$VPS_PUB0/24" dev pub0
  ip -n client route add default via "$VPS_PUB0"

  link vps pub1 homerouter wan0
  ip -n vps addr add "$VPS_PUB1/24" dev pub1
  ip -n homerouter addr add "$HR_WAN/24" dev wan0
  ip -n homerouter route add default via "$VPS_PUB1"

  link homerouter lan0 home eth0
  ip -n homerouter addr add "$HR_LAN/24" dev lan0
  ip -n home addr add "$HOME_ADDR/24" dev eth0
  ip -n home route add default via "$HR_LAN"

  ip netns exec homerouter sysctl -qw net.ipv4.ip_forward=1
  # nft 1.0.6(Debian 12)は入れ子を 1 行で書くと構文エラーになるので複数行で書く
  ip netns exec homerouter nft -f - <<'NFT'
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
  ip netns exec client ping -c1 -W2 "$VPS_PUB0" >/dev/null || die "client -> vps に届かない"
  ip netns exec home ping -c1 -W2 "$HR_LAN" >/dev/null || die "home -> homerouter に届かない"
  ip netns exec homerouter ping -c1 -W2 "$VPS_PUB1" >/dev/null || die "homerouter -> vps に届かない"
  echo "lab topology is up"
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
  *) echo "usage: $0 up|down|status" >&2; exit 2 ;;
esac
