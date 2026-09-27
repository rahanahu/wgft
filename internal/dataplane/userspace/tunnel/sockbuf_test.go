package tunnel

import (
	"net/netip"
	"runtime"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// トンネルは立てるたびに、自分の WireGuard の UDP ソケットを測る(設計文書 7 節の「ソケットのバッファの
// 条件」)。エージェントは作り直しのたびに新しいソケットを開くので、2 回目の New は 2 回目のソケットを
// 測る。測る手段を持つのは Linux だけである。
func TestNewMeasuresItsOwnSockets(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		PrivateKey: key, ServerPublicKey: key.PublicKey(),
		Endpoint:      "127.0.0.1:9",
		Address:       netip.MustParseAddr("10.200.0.2"),
		ServerAddress: netip.MustParseAddr("10.200.0.1"),
		MTU:           1420,
		Keepalive:     time.Second,
		Logf:          func(string, ...any) {},
	}
	var ports []uint16
	for i := 0; i < 2; i++ {
		tun, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		r := tun.SocketBuffers()
		tun.Close()
		if runtime.GOOS != "linux" {
			if r.Supported {
				t.Errorf("measured on %s: %+v", runtime.GOOS, r)
			}
			return
		}
		if !r.Measured() || r.Port == 0 || r.Recv <= 0 || r.Send <= 0 {
			t.Fatalf("build %d: SocketBuffers = %+v, want a measurement of the tunnel's own sockets", i+1, r)
		}
		ports = append(ports, r.Port)
	}
	if ports[0] == ports[1] {
		t.Logf("both builds measured port %d; the OS chose the same ephemeral port twice", ports[0])
	}
}
