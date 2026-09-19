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
			return l, configErrorf("%s: %q is not an integer between %d and %d", f.env, c.str(f.env), flowcap.TotalMin, flowcap.TotalMax)
		}
		*f.dst = n
	}
	return l, nil
}

// perSourceLimitSpecs は接続元 IP ごとの同時フロー数の上限(仕様 7, 11a 節)。server だけの設定で、
// agentSpecs には加えない。エージェントから見た接続元は常に 10.200.0.1 なので、エージェントでは
// 接続元ごとに数えず、この設定を持たない。
func perSourceLimitSpecs() []spec {
	return []spec{
		{Env: "WGFT_MAX_UDP_FLOWS_PER_SOURCE", Flag: "max-udp-flows-per-source", Default: strconv.Itoa(flowcap.UDPPerSource)},
		{Env: "WGFT_MAX_TCP_FLOWS_PER_SOURCE", Flag: "max-tcp-flows-per-source", Default: strconv.Itoa(flowcap.TCPPerSource)},
	}
}

func registerPerSourceLimitFlags(fl *pflag.FlagSet) {
	fl.Int("max-udp-flows-per-source", flowcap.UDPPerSource,
		"cap on concurrent UDP sessions from one source address, summed over all rules, env WGFT_MAX_UDP_FLOWS_PER_SOURCE; 0 disables the per-source cap")
	fl.Int("max-tcp-flows-per-source", flowcap.TCPPerSource,
		"cap on concurrent TCP connections from one source address, summed over all rules, env WGFT_MAX_TCP_FLOWS_PER_SOURCE; 0 disables the per-source cap")
}

// perSourceLimitsFromConfig reads and validates WGFT_MAX_*_FLOWS_PER_SOURCE. Unlike the
// process-wide caps, 0 is a valid value here: it disables the per-source cap for that protocol.
// It is returned as flowcap.PerSourceOff, because a zero Limits field means the default.
// Anything else must be between 1 and flowcap.TotalMax; negative values are a config error.
func perSourceLimitsFromConfig(c *config) (udpPerSource, tcpPerSource int, err error) {
	for _, f := range []struct {
		env string
		dst *int
	}{{"WGFT_MAX_UDP_FLOWS_PER_SOURCE", &udpPerSource}, {"WGFT_MAX_TCP_FLOWS_PER_SOURCE", &tcpPerSource}} {
		n, err := strconv.Atoi(c.str(f.env))
		if err != nil || n < 0 || n > flowcap.TotalMax {
			return 0, 0, configErrorf("%s: %q is not an integer between 0 and %d (0 disables the per-source cap)", f.env, c.str(f.env), flowcap.TotalMax)
		}
		if n == 0 {
			n = flowcap.PerSourceOff
		}
		*f.dst = n
	}
	return udpPerSource, tcpPerSource, nil
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
