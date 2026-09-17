package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"

	"github.com/spf13/pflag"

	"github.com/rahanahu/wgft/internal/flowcap"
)

// limitSpecs は同時フロー数のプロセス全体の上限(仕様 7 節、11a 節)。server と agent が共有する。
func limitSpecs() []spec {
	return []spec{
		{Env: "WGFT_MAX_UDP_FLOWS", Flag: "max-udp-flows", Default: strconv.Itoa(flowcap.UDPTotal)},
		{Env: "WGFT_MAX_TCP_FLOWS", Flag: "max-tcp-flows", Default: strconv.Itoa(flowcap.TCPTotal)},
	}
}

func registerLimitFlags(fl *pflag.FlagSet) {
	fl.Int("max-udp-flows", flowcap.UDPTotal, "process-wide cap on concurrent UDP sessions, env WGFT_MAX_UDP_FLOWS; lower it on hosts with little memory")
	fl.Int("max-tcp-flows", flowcap.TCPTotal, "process-wide cap on concurrent TCP connections, env WGFT_MAX_TCP_FLOWS; lower it on hosts with little memory")
}

// limitsFromConfig は設定値を読み、範囲を確かめる。
func limitsFromConfig(c *config) (flowcap.Limits, error) {
	var l flowcap.Limits
	for _, f := range []struct {
		env string
		dst *int
	}{{"WGFT_MAX_UDP_FLOWS", &l.UDPTotal}, {"WGFT_MAX_TCP_FLOWS", &l.TCPTotal}} {
		n, err := strconv.Atoi(c.str(f.env))
		if err != nil || n < flowcap.TotalMin || n > flowcap.TotalMax {
			return l, fmt.Errorf("%s: %q is not an integer between %d and %d", f.env, c.str(f.env), flowcap.TotalMin, flowcap.TotalMax)
		}
		*f.dst = n
	}
	return l, nil
}

// applyMemoryLimit は、上限から計算したメモリのソフト上限を Go のランタイムに設定する(仕様 7 節)。
// 運用者が GOMEMLIMIT を設定していれば、ランタイムが既にその値を使っているので触らない。
// apply が偽なら値を印字するだけ(server check)。
func applyMemoryLimit(w io.Writer, l flowcap.Limits, apply bool) {
	if v := os.Getenv("GOMEMLIMIT"); v != "" {
		fmt.Fprintf(w, "memory soft limit: GOMEMLIMIT=%s (set by the environment)\n", v)
		return
	}
	n := l.MemoryLimit()
	if apply {
		debug.SetMemoryLimit(n)
	}
	fmt.Fprintf(w, "memory soft limit: %d MiB (derived from the flow caps; set GOMEMLIMIT to override)\n", n>>20)
}
