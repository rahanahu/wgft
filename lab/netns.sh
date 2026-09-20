#!/usr/bin/env bash
# wgft ラボのトポロジを netns で組む。VM 内か CI 上で root として実行する(Incus には依存しない)。
#
#   client ── vps ── homerouter(NAT) ─┬─ home(エージェント)
#                                     └─ lan(自宅 LAN 上の別ホスト。ゲームサーバ役)
#
# home と lan は homerouter の中の 1 つのブリッジ(br0)にぶら下がる、同じ自宅 LAN セグメント。
#
# 使い方: netns.sh up | down | status
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
