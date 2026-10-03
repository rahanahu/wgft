//go:build linux

package kernelmode

import (
	"context"
	"net/netip"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// NewWithOps(本番の New も同じ)は、このホストのインタフェースの一覧を読む判定を表の組み立てに渡す
// (設計文書 7 節、7b.2 節)。一覧を読まない判定に置き換わると、ホストの帯のブロードキャストのアドレスを
// 拒まなくなるので、この試験が落ちる。
func TestNewWithOpsInstallsTheHostInterfaceReader(t *testing.T) {
	ps, err := allowtargets.HostPrefixes()
	if err != nil {
		t.Skipf("cannot read interface addresses here: %v", err)
	}
	var b netip.Addr
	for _, p := range ps {
		if p.Addr().Is4() && p.Bits() <= 30 {
			a := p.Masked().Addr().As4()
			v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]) | ^uint32(0)>>p.Bits()
			b = netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
			break
		}
	}
	if !b.IsValid() {
		t.Skip("this host has no IPv4 network of /30 or wider")
	}
	k := &fakeKernel{forwardOn: true, dns: map[string][]netip.Addr{}}
	d := NewWithOps(context.Background(), "wgft0", nil, &credentials.Credentials{}, nil, k.ops())
	refuse := d.nftConfig().RefuseTarget
	if refuse == nil {
		t.Fatal("nftConfig passes no RefuseTarget")
	}
	if got := refuse(b); got == "" {
		t.Errorf("the broadcast address %s of a network on this host is not refused; NewWithOps must read this host's interfaces", b)
	}
}
