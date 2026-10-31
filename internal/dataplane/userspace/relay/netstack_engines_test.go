package relay

import (
	"net"
	"net/netip"
	"testing"

	"github.com/rahanahu/wgft/internal/nettun"
	"github.com/rahanahu/wgft/internal/wgstack"
)

// エージェントの netstack の 2 つの実装(設計文書 wgstack.md の「退行の確認」)。netstack の接続を使う中継の試験は、
// エージェントの側の Device をこの関数で作り、両方の実装に流す。

var agentEngines = []string{"gvisor", "wgstack"}

// agentDev は試験が使うエージェントの側の Device の面。
type agentDev interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
	ListenTCP(netip.AddrPort) (net.Listener, error)
	ListenUDP(netip.AddrPort) (net.PacketConn, error)
}

type gvisorAgent struct{ *nettun.Device }

func (g gvisorAgent) ListenTCP(ap netip.AddrPort) (net.Listener, error) {
	l, err := g.Device.ListenTCP(ap)
	if err != nil {
		return nil, err
	}
	return l, nil
}

type wgstackAgent struct{ *wgstack.Device }

func (w wgstackAgent) ListenTCP(ap netip.AddrPort) (net.Listener, error) {
	l, err := w.Device.ListenTCP(ap)
	if err != nil {
		return nil, err
	}
	return l, nil
}

// newAgentDev は実装 engine のエージェントの側の Device を作り、試験の後に閉じる。
func newAgentDev(t *testing.T, engine string, addr netip.Addr) agentDev {
	t.Helper()
	switch engine {
	case "gvisor":
		d, err := nettun.Create(addr, 1420)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			d.Close()
			d.Wait()
		})
		return gvisorAgent{d}
	case "wgstack":
		d, err := wgstack.Create(addr, 1420)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			d.Close()
			d.Wait()
		})
		return wgstackAgent{d}
	}
	t.Fatalf("unknown engine %q", engine)
	return nil
}

// forEachAgentEngine は試験 f を両方の実装で流す。
func forEachAgentEngine(t *testing.T, f func(t *testing.T, engine string)) {
	for _, e := range agentEngines {
		t.Run(e, func(t *testing.T) { f(t, e) })
	}
}
