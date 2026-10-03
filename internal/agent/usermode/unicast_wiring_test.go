package usermode

import (
	"net/netip"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// hostDirectedBroadcast は、このホストのインタフェースの IPv4 の帯のうち、ブロードキャストのアドレスを
// 持つもの(/30 以下)の末尾のアドレスを 1 つ返す。無ければ偽を返す。
func hostDirectedBroadcast(t *testing.T) (netip.Addr, bool) {
	t.Helper()
	ps, err := allowtargets.HostPrefixes()
	if err != nil {
		return netip.Addr{}, false
	}
	for _, p := range ps {
		if !p.Addr().Is4() || p.Bits() > 30 {
			continue
		}
		b := p.Masked().Addr().As4()
		v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]) | ^uint32(0)>>p.Bits()
		return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
	}
	return netip.Addr{}, false
}

// New は、このホストのインタフェースの一覧を読む判定を中継に渡す(設計文書 7 節)。一覧を読まない判定に
// 置き換わると、ホストの帯のブロードキャストのアドレスを拒まなくなるので、この試験が落ちる。
func TestNewInstallsTheHostInterfaceReader(t *testing.T) {
	b, ok := hostDirectedBroadcast(t)
	if !ok {
		t.Skip("this host has no IPv4 network of /30 or wider")
	}
	refuse := New(nil, resource.Limits{}).RelayOptions(proto.WGConfig{}).RefuseTarget
	if refuse == nil {
		t.Fatal("RelayOptions passes no RefuseTarget")
	}
	if got := refuse(b); got == "" {
		t.Errorf("the broadcast address %s of a network on this host is not refused; New must read this host's interfaces", b)
	}
}
