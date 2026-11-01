package relay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// specTunnelDir は、仕様の fixture(docs/design/spec/tunnel.md)の置き場所である。
const specTunnelDir = "../../../../testdata/spec/tunnel"

func specTunnelRead(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(specTunnelDir, name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

type specTunnelListener struct {
	Proto  proto.Proto `json:"proto"`
	Port   uint16      `json:"port"`
	Target string      `json:"target"`
	Rule   string      `json:"rule"`
}

// TestSpecTunnelListeners は、全体状態のルールから開く待ち受けと実効宛先が、仕様の fixture と同じで
// あることを確かめる(docs/design/spec/tunnel.md)。
func TestSpecTunnelListeners(t *testing.T) {
	var f struct {
		Cases []struct {
			Name      string               `json:"name"`
			Rules     []proto.AgentRule    `json:"rules"`
			Listeners []specTunnelListener `json:"listeners"`
		} `json:"cases"`
	}
	specTunnelRead(t, "listeners.json", &f)
	if len(f.Cases) == 0 {
		t.Fatal("fixture has no cases")
	}
	for _, c := range f.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := []specTunnelListener{}
			for k, d := range DesiredFromRules(c.Rules) {
				got = append(got, specTunnelListener{Proto: k.Proto, Port: k.Port, Target: d.Target, Rule: d.RuleID})
			}
			sort.Slice(got, func(i, j int) bool {
				if got[i].Proto != got[j].Proto {
					return got[i].Proto < got[j].Proto
				}
				return got[i].Port < got[j].Port
			})
			if len(got) != len(c.Listeners) {
				t.Fatalf("listeners = %+v, want %+v", got, c.Listeners)
			}
			for i := range got {
				if got[i] != c.Listeners[i] {
					t.Errorf("listener %d = %+v, want %+v", i, got[i], c.Listeners[i])
				}
			}
		})
	}
}

// TestSpecTunnelRelayTiming は、中継の期限と同時の数が、仕様の fixture と同じであることを確かめる
// (docs/design/spec/tunnel.md)。
func TestSpecTunnelRelayTiming(t *testing.T) {
	var f struct {
		TargetDialTimeoutMS    int64 `json:"target_dial_timeout_ms"`
		TargetProbeTimeoutMS   int64 `json:"target_probe_timeout_ms"`
		TargetProbeConcurrency int   `json:"target_probe_concurrency"`
		TargetLookupTimeoutMS  int64 `json:"target_lookup_timeout_ms"`
		TargetFallbackDelayMS  int64 `json:"target_fallback_delay_ms"`
		DefaultUDPIdleSeconds  int64 `json:"default_udp_idle_seconds"`
		UDPSweepDivisor        int64 `json:"udp_sweep_divisor"`
	}
	specTunnelRead(t, "relay-timing.json", &f)
	ms := func(n int64) time.Duration { return time.Duration(n) * time.Millisecond }
	if TargetDialTimeout != ms(f.TargetDialTimeoutMS) {
		t.Errorf("target dial timeout = %v, want %v", TargetDialTimeout, ms(f.TargetDialTimeoutMS))
	}
	m := New(nil, Options{})
	if m.dialTimeout != ms(f.TargetDialTimeoutMS) {
		t.Errorf("manager dial timeout = %v, want %v", m.dialTimeout, ms(f.TargetDialTimeoutMS))
	}
	if m.probeTimeout != ms(f.TargetProbeTimeoutMS) {
		t.Errorf("probe timeout = %v, want %v", m.probeTimeout, ms(f.TargetProbeTimeoutMS))
	}
	if targetProbeConcurrency != f.TargetProbeConcurrency {
		t.Errorf("probe concurrency = %d, want %d", targetProbeConcurrency, f.TargetProbeConcurrency)
	}
	if targetLookupTimeout != ms(f.TargetLookupTimeoutMS) {
		t.Errorf("target lookup timeout = %v, want %v", targetLookupTimeout, ms(f.TargetLookupTimeoutMS))
	}
	if targetFallbackDelay != ms(f.TargetFallbackDelayMS) {
		t.Errorf("target fallback delay = %v, want %v", targetFallbackDelay, ms(f.TargetFallbackDelayMS))
	}
	idle := time.Duration(f.DefaultUDPIdleSeconds) * time.Second
	if m.opts.UDPIdleTimeout != idle {
		t.Errorf("default UDP idle timeout = %v, want %v", m.opts.UDPIdleTimeout, idle)
	}
	if got, want := sweepInterval(idle), idle/time.Duration(f.UDPSweepDivisor); got != want {
		t.Errorf("UDP idle sweep interval = %v, want %v", got, want)
	}
}
