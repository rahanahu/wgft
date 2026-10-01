package sockbuf

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/lograte"
)

// 条件は受信と送信の両方が Linux の実効の値で 14680064 以上であることである(設計文書 7 節)。
// sysctl に書く値はその半分である。
func TestRequirementValues(t *testing.T) {
	if Requested != 7340032 || Required != 14680064 {
		t.Errorf("Requested %d Required %d, want 7340032 and 14680064", Requested, Required)
	}
}

func TestMet(t *testing.T) {
	cases := []struct {
		name string
		r    Reading
		want bool
	}{
		{"both at the requirement", Reading{Supported: true, Sockets: 2, Recv: Required, Send: Required}, true},
		{"receive one byte short", Reading{Supported: true, Sockets: 2, Recv: Required - 2, Send: Required}, false},
		{"send short", Reading{Supported: true, Sockets: 2, Recv: Required, Send: 8388608}, false},
		{"not measured on this os", Reading{Recv: Required, Send: Required, Sockets: 2}, false},
		{"measurement failed", Reading{Supported: true, Err: errors.New("x"), Recv: Required, Send: Required, Sockets: 2}, false},
		{"no socket", Reading{Supported: true, Recv: Required, Send: Required}, false},
	}
	for _, tc := range cases {
		if got := tc.r.Met(); got != tc.want {
			t.Errorf("%s: Met() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// 警告は英語の 1 行で、丸括弧を使わない。測った値、条件、sysctl に書く値、コンテナのホストで
// 設定することを含む。
func TestWarningText(t *testing.T) {
	short := WarningText(Reading{Supported: true, Port: 35454, Sockets: 2, Recv: 425984, Send: 425984})
	for _, w := range []string{"warning: ", "port 35454", "receive buffer of 425984 bytes", "send buffer of 425984 bytes",
		"requires 14680064 bytes each", "net.core.rmem_max and net.core.wmem_max to 7340032 or more", "container host", "never changes these sysctls"} {
		if !strings.Contains(short, w) {
			t.Errorf("warning lacks %q: %s", w, short)
		}
	}
	failed := WarningText(Reading{Supported: true, Port: 35454, Err: errors.New("list this process's file descriptors: denied")})
	if !strings.Contains(failed, "cannot measure") || !strings.Contains(failed, "denied") {
		t.Errorf("unmeasured warning: %s", failed)
	}
	for _, msg := range []string{short, failed} {
		if strings.ContainsAny(msg, "()\n") {
			t.Errorf("warning must be one line without parentheses: %q", msg)
		}
	}
	if s := WarningText(Reading{Supported: true, Port: 1, Sockets: 2, Recv: Required, Send: Required}); s != "" {
		t.Errorf("a met requirement warns: %s", s)
	}
	if s := WarningText(Reading{Port: 1}); s != "" {
		t.Errorf("an OS without a measurement warns: %s", s)
	}
}

// 警告は 1 分に 1 回までである。トンネルを続けて作り直しても行が並ばない。
func TestWarnIsRateLimited(t *testing.T) {
	var g lograte.Gate
	var lines []string
	logf := func(format string, args ...any) { lines = append(lines, fmt.Sprintf(format, args...)) }
	short := Reading{Supported: true, Port: 35454, Sockets: 2, Recv: 425984, Send: 425984}
	warn(&g, short, logf)
	warn(&g, short, logf)
	if len(lines) != 1 {
		t.Errorf("got %d lines, want 1: %q", len(lines), lines)
	}
	// 条件を満たす測定は門を使わない
	var g2 lograte.Gate
	warn(&g2, Reading{Supported: true, Sockets: 2, Recv: Required, Send: Required}, logf)
	warn(&g2, short, logf)
	if len(lines) != 2 {
		t.Errorf("a met reading used up the gate: %q", lines)
	}
}

func TestMeasureDeviceReadError(t *testing.T) {
	r := MeasureDevice(func() (string, error) { return "", errors.New("device closed") })
	if !supported {
		if r.Supported {
			t.Error("an OS without a measurement reports Supported")
		}
		return
	}
	if r.Err == nil || !strings.Contains(r.Err.Error(), "device closed") {
		t.Errorf("Err = %v, want the IpcGet error", r.Err)
	}
}
