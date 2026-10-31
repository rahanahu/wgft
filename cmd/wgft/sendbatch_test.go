package main

import (
	"bytes"
	"log"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/internal/startup"
)

func batchConfig(t *testing.T, v string, set bool) *config {
	t.Helper()
	if set {
		t.Setenv("WGFT_AGENT_BATCH_MIB", v)
	}
	c, err := loadConfig(&cobra.Command{}, agentSpecs(), filepath.Join(t.TempDir(), "none.env"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// WGFT_AGENT_BATCH_MIB の値と P_max(wgstack-batching.md の「P_max の決め方」)。
func TestSendBatchFromConfig(t *testing.T) {
	s, upper := tunnel.SendBatchBufferBytes(), tunnel.SendBatchCap()
	def := upper
	if runtime.GOOS != "windows" {
		def = int(min(resource.Limits{}.MemoryLimit()/4/s, int64(upper)))
	}
	if runtime.GOOS == "linux" && s == 64<<10 && def != 864 && upper >= 864 {
		t.Errorf("default P_max on Linux with the default caps = %d, want 864", def)
	}
	upperMiB := int64(upper) * s >> 20
	for _, tc := range []struct {
		name    string
		v       string
		set     bool
		packets int
		capped  bool
	}{
		{"unset", "", false, def, false},
		{"empty", "", true, def, false},
		{"zero", "0", true, 0, false},
		{"one MiB", "1", true, int(1 << 20 / s), false},
		{"at the cap", itoa(upperMiB), true, int(min(upperMiB<<20/s, int64(upper))), false},
		{"above the cap", itoa(upperMiB + 1), true, upper, true},
		{"huge", "99999999999999999999999", true, upper, true},
		{"max int64", itoa(math.MaxInt64), true, upper, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := sendBatchFromConfig(batchConfig(t, tc.v, tc.set), resource.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			if b.packets != tc.packets || b.capped != tc.capped {
				t.Fatalf("P_max %d capped %v, want %d and %v", b.packets, b.capped, tc.packets, tc.capped)
			}
		})
	}
	for _, v := range []string{"-1", "1.5", "one", " 8", "0x10", "-99999999999999999999999"} {
		_, err := sendBatchFromConfig(batchConfig(t, v, true), resource.Limits{})
		if got := exitCode(err); err == nil || got != exitRefusal {
			t.Errorf("WGFT_AGENT_BATCH_MIB=%q: err=%v exitCode=%d, want %d", v, err, got, exitRefusal)
			continue
		}
		if r := startup.Of(err); r == nil || r.Subject != "WGFT_AGENT_BATCH_MIB" {
			t.Errorf("WGFT_AGENT_BATCH_MIB=%q: refusal %v does not name the setting", v, r)
		}
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// 起動ログ:wgstack では有効な値と出所を、使わないモードと netstack では値があるときだけ使わない旨を出す。
func TestLogSendBatch(t *testing.T) {
	for _, tc := range []struct {
		name, mode, netstack string
		b                    sendBatch
		want                 string
	}{
		{"wgstack default", "", "wgstack", sendBatch{packets: 864}, "send batch budget: "},
		{"wgstack set", "userspace", "wgstack", sendBatch{packets: 16, set: true, requestedMiB: 1}, "buffers, from WGFT_AGENT_BATCH_MIB\n"},
		{"wgstack capped", "", "wgstack", sendBatch{packets: 100, set: true, capped: true}, "lowered to the cap for this host's"},
		{"wgstack off", "", "wgstack", sendBatch{set: true}, "WGFT_AGENT_BATCH_MIB=0 turns send batching off"},
		{"gvisor set", "", "", sendBatch{packets: 16, set: true}, "WGFT_AGENT_BATCH_MIB: unused with the gvisor network stack"},
		{"gvisor unset", "", "gvisor", sendBatch{packets: 864}, ""},
		{"kernel set", "kernel", "wgstack", sendBatch{packets: 16, set: true}, "WGFT_AGENT_BATCH_MIB: unused in kernel mode"},
		{"kernel unset", "kernel", "wgstack", sendBatch{packets: 864}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			log.SetOutput(&buf)
			defer log.SetOutput(os.Stderr)
			logSendBatch(&buf, tc.mode, tc.netstack, tc.b)
			if tc.want == "" && buf.Len() != 0 {
				t.Fatalf("logged %q, want nothing", buf.String())
			}
			if !strings.Contains(buf.String(), tc.want) {
				t.Fatalf("logged %q, want %q", buf.String(), tc.want)
			}
			if strings.ContainsAny(buf.String(), "()") {
				t.Fatalf("logged %q with parentheses", buf.String())
			}
		})
	}
}
