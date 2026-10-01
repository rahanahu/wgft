//go:build linux

package tailnet

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os/exec"
	"strings"
	"time"
)

// adminTailscalePort は --admin-tailscale での待ち受けポート(TCP)。
const adminTailscalePort = "8686"

// ifaceAddrs はネットワークインタフェース 1 つぶんの名前とアドレス一覧。
// pickTailscaleAddr を実際のインタフェースなしに単体テストするための型。
type ifaceAddrs struct {
	name  string
	addrs []net.Addr
}

// pickTailscaleAddr は、名前が "tailscale" で始まるインタフェースにある
// 100.64.0.0/10 の最初の IPv4 アドレスを選ぶ(iface, ip)。
// CGNAT 帯は Tailscale 専用ではなく VPS 事業者の内部網にも使われ得るため、
// インタフェース名で絞る(仕様 11 節)。該当がないとき、CGNAT アドレスを
// 持つ他のインタフェースがあれば、その名前を other に入れる(なければ空)。
func pickTailscaleAddr(ifaces []ifaceAddrs) (iface, ip string, other string) {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	firstCGNAT := func(f ifaceAddrs) (string, bool) {
		for _, a := range f.addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is4() && cgnat.Contains(addr) {
				return addr.String(), true
			}
		}
		return "", false
	}
	for _, f := range ifaces {
		if !strings.HasPrefix(f.name, "tailscale") {
			continue
		}
		if a, ok := firstCGNAT(f); ok {
			return f.name, a, ""
		}
	}
	for _, f := range ifaces {
		if strings.HasPrefix(f.name, "tailscale") {
			continue
		}
		if _, ok := firstCGNAT(f); ok {
			return "", "", f.name
		}
	}
	return "", "", ""
}

// tailscaleIP は稼働中のインタフェースから pickTailscaleAddr で選んだ結果を返す。
func tailscaleIP() (iface, ip, other string) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", "", ""
	}
	list := make([]ifaceAddrs, 0, len(ifs))
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		list = append(list, ifaceAddrs{name: i.Name, addrs: addrs})
	}
	return pickTailscaleAddr(list)
}

// tailscaleStatusSelf は `tailscale status --json` の出力のうち使う部分だけ。
type tailscaleStatusSelf struct {
	Self struct {
		TailscaleIPs []string `json:"TailscaleIPs"`
		DNSName      string   `json:"DNSName"`
	} `json:"Self"`
}

// parseTailscaleStatus は `tailscale status --json` の出力から、Self.TailscaleIPs の
// 最初の IPv4 アドレスと Self.DNSName(MagicDNS 名。末尾のドットを外す)を取り出す。
// IPv4 のアドレスが 1 つもなければ ok は偽。
func parseTailscaleStatus(data []byte) (ip, dnsName string, ok bool) {
	var st tailscaleStatusSelf
	if err := json.Unmarshal(data, &st); err != nil {
		return "", "", false
	}
	for _, s := range st.Self.TailscaleIPs {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is4() {
			continue
		}
		return addr.String(), strings.TrimSuffix(st.Self.DNSName, "."), true
	}
	return "", "", false
}

// runTailscaleStatus は `tailscale status --json` を実行し、その標準出力を返す。
// tailscale コマンドが PATH になければ、それも失敗として err に返る。
func runTailscaleStatus(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "tailscale", "status", "--json").Output()
}

// detectAdminTailscale は --admin-tailscale の待ち受け先を選ぶ。
// まず `tailscale status --json` の Self から選び、コマンドがない・失敗する・
// 使えるアドレスがないときは、tailscale で始まる名前のインタフェースから選ぶ
// (tailscaleIP、仕様 11 節)。detail はログに添える出どころの説明。
// どちらからも選べず、CGNAT アドレスを持つ他のインタフェースがあれば other に入れる。
// fromStatus は選んだアドレスが `tailscale status` の答えであることを表す。偽なら dnsName は分からない。
func detectAdminTailscale(ctx context.Context) (ip, dnsName, detail, other string, fromStatus bool) {
	if out, err := runTailscaleStatus(ctx); err == nil {
		if sip, sdns, ok := parseTailscaleStatus(out); ok {
			d := "from tailscale status"
			if sdns != "" {
				d = sdns + ", from tailscale status"
			}
			return sip, sdns, d, "", true
		}
	}
	iface, iip, iother := tailscaleIP()
	if iip != "" {
		return iip, "", "from interface " + iface, "", false
	}
	return "", "", "", iother, false
}
