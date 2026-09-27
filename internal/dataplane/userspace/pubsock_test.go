package userspace

import (
	"fmt"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/lograte"
)

// 公開側の UDP ソケットに要求する送信バッファは 2 MiB の定数で、Linux の実効の値はその 2 倍である
// (設計文書 7 節)。
func TestPublicSendBufferRequestIsTwoMiB(t *testing.T) {
	if publicSendBufferRequest != 2<<20 {
		t.Fatalf("request = %d, want %d", publicSendBufferRequest, 2<<20)
	}
	if publicSendBufferExpected != 2*publicSendBufferRequest {
		t.Fatalf("expected effective = %d, want twice the request", publicSendBufferExpected)
	}
}

// 実効の値が要求の 2 倍に届かないときだけ警告し、読めなかった(0)ときと届いたときは何も出さない。
// 行は要求と実効の値の両方を持ち、丸括弧を使わない。
func TestShortSendBufferText(t *testing.T) {
	if got := shortSendBufferText(27015, 0); got != "" {
		t.Errorf("unreadable effective value must not warn, got %q", got)
	}
	if got := shortSendBufferText(27015, publicSendBufferExpected); got != "" {
		t.Errorf("a full grant must not warn, got %q", got)
	}
	got := shortSendBufferText(27015, 425984)
	for _, want := range []string{"port 27015", "425984 bytes", fmt.Sprintf("requested %d bytes", publicSendBufferRequest), "net.core.wmem_max"} {
		if !strings.Contains(got, want) {
			t.Errorf("warning %q lacks %q", got, want)
		}
	}
	if strings.ContainsAny(got, "()") {
		t.Errorf("warning must not use parentheses: %q", got)
	}
}

// 警告は Backend の門で 1 分に 1 回までで、ルールの本数だけ待ち受けを開いても行は並ばない。
func TestWarnShortSendBufferIsRateLimited(t *testing.T) {
	var g lograte.Gate
	var lines int
	logf := func(string, ...any) { lines++ }
	for port := uint16(1); port <= 5; port++ {
		warnShortSendBuffer(&g, port, 425984, logf)
	}
	if lines != 1 {
		t.Errorf("warned %d times for 5 short sockets, want 1", lines)
	}
	warnShortSendBuffer(&g, 6, publicSendBufferExpected, logf)
	warnShortSendBuffer(nil, 7, 425984, logf)
	if lines != 1 {
		t.Errorf("a full grant or a nil gate must not warn, got %d lines", lines)
	}
}

// Backend が relay に渡す公開側の Network は、警告の門とログを持つ。門が無ければ警告は黙って消える。
func TestBackendWiresTheSendBufferWarning(t *testing.T) {
	var lines int
	b := New(Options{Logf: func(string, ...any) { lines++ }})
	if b.hostNet.warnGate != &b.sendBufWarn || b.hostNet.logf == nil {
		t.Fatal("the public Network must carry the Backend's warning gate and log")
	}
	warnShortSendBuffer(b.hostNet.warnGate, 27015, 425984, b.hostNet.logf)
	if lines != 1 {
		t.Errorf("warned %d times through the Backend's log, want 1", lines)
	}
}
