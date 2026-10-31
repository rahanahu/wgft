//go:build labmemprobe

package tunnel

import (
	"encoding/json"
	"os"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rahanahu/wgft/internal/wgstack"
)

// この file はラボの測定専用の hook で、build tag labmemprobe を付けた build だけに入る(lab/lab build の
// WGFT_LAB_BUILD_TAGS、lab/agentmem.sh)。環境変数 WGFT_LAB_MEMPROBE にパスがあれば、0.5 秒ごとに Go の
// ランタイムの生きているヒープ、ヒープの物体、プロセスの RSS と最大の RSS、wgstack の Device の Stats を
// JSON の 1 行で追記する。製品の build には入らず、Stats を管理用 API や status に載せる約束(wgstack.md)は
// 変えない。

var (
	probeOnce sync.Once
	probeDev  atomic.Pointer[wgstack.Device]
)

func startMemProbe(ns netstack) {
	path := os.Getenv("WGFT_LAB_MEMPROBE")
	if path == "" {
		return
	}
	if w, ok := ns.(wgstackNetstack); ok {
		probeDev.Store(w.Device)
	}
	probeOnce.Do(func() { go probeLoop(path) })
}

func procKiB(status, key string) int64 {
	for _, l := range strings.Split(status, "\n") {
		if strings.HasPrefix(l, key+":") {
			f := strings.Fields(l[len(key)+1:])
			if len(f) > 0 {
				v, _ := strconv.ParseInt(f[0], 10, 64)
				return v
			}
		}
	}
	return 0
}

func probeLoop(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	samples := []metrics.Sample{
		{Name: "/gc/heap/live:bytes"},
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/total:bytes"},
	}
	enc := json.NewEncoder(f)
	var boundDone bool
	for range time.Tick(500 * time.Millisecond) {
		metrics.Read(samples)
		st, _ := os.ReadFile("/proc/self/status")
		rec := map[string]any{
			"t":     time.Now().UnixMilli(),
			"live":  int64(samples[0].Value.Uint64()),
			"heap":  int64(samples[1].Value.Uint64()),
			"total": int64(samples[2].Value.Uint64()),
			"rss":   procKiB(string(st), "VmRSS") << 10,
			"hwm":   procKiB(string(st), "VmHWM") << 10,
		}
		if d := probeDev.Load(); d != nil {
			rec["stats"] = d.Stats()
			if !boundDone {
				rec["bound"] = d.Bound()
				boundDone = true
			}
		}
		_ = enc.Encode(rec)
	}
}
