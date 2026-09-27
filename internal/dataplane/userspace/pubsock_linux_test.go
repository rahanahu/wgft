package userspace

import (
	"net"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/lograte"
)

// 公開側の待ち受けを開くと、ソケットの実効の送信バッファは、要求と net.core.wmem_max の小さい方の
// 2 倍になる(socket(7))。要求を渡さなければ既定の net.core.wmem_default のままである。
func TestHostNetworkRequestsThePublicSendBuffer(t *testing.T) {
	raw, err := os.ReadFile("/proc/sys/net/core/wmem_max")
	if err != nil {
		t.Skip("no /proc/sys/net/core/wmem_max")
	}
	wmemMax, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	want := 2 * min(publicSendBufferRequest, wmemMax)
	var g lograte.Gate
	var lines []string
	pc, err := hostNetwork{logf: func(f string, a ...any) { lines = append(lines, f) }, warnGate: &g}.ListenUDP(0)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	if got := readSendBuffer(pc.(*net.UDPConn)); got != want {
		t.Fatalf("effective send buffer = %d, want %d for a request of %d with wmem_max %d", got, want, publicSendBufferRequest, wmemMax)
	}
	if short := want < publicSendBufferExpected; short != (len(lines) == 1) {
		t.Errorf("short grant = %v but warned %d times", short, len(lines))
	}
}
