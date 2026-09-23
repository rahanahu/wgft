package main

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strconv"

	"github.com/spf13/pflag"

	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/internal/resource"
)

// limitSpecs は同時フロー数のプロセス全体の上限(仕様 7 節、11a 節)。server と agent が共有する。
func limitSpecs() []spec {
	return []spec{
		{Env: "WGFT_MAX_UDP_FLOWS", Flag: "max-udp-flows", Default: strconv.Itoa(resource.UDPTotal)},
		{Env: "WGFT_MAX_TCP_FLOWS", Flag: "max-tcp-flows", Default: strconv.Itoa(resource.TCPTotal)},
	}
}

func registerLimitFlags(fl *pflag.FlagSet) {
	fl.Int("max-udp-flows", resource.UDPTotal, "process-wide cap on concurrent UDP sessions, env WGFT_MAX_UDP_FLOWS; lower it on hosts with little memory")
	fl.Int("max-tcp-flows", resource.TCPTotal, "process-wide cap on concurrent TCP connections, env WGFT_MAX_TCP_FLOWS; lower it on hosts with little memory")
}

// limitsFromConfig は設定値を読み、範囲を確かめる。
func limitsFromConfig(c *config) (resource.Limits, error) {
	var l resource.Limits
	for _, f := range []struct {
		env string
		dst *int
	}{{"WGFT_MAX_UDP_FLOWS", &l.UDPTotal}, {"WGFT_MAX_TCP_FLOWS", &l.TCPTotal}} {
		n, err := strconv.Atoi(c.str(f.env))
		if err != nil || n < resource.TotalMin || n > resource.TotalMax {
			return l, configErrorf(f.env, "%q is not an integer between %d and %d", c.str(f.env), resource.TotalMin, resource.TotalMax)
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
		{Env: "WGFT_MAX_UDP_FLOWS_PER_SOURCE", Flag: "max-udp-flows-per-source", Default: strconv.Itoa(policy.UDPPerSource)},
		{Env: "WGFT_MAX_TCP_FLOWS_PER_SOURCE", Flag: "max-tcp-flows-per-source", Default: strconv.Itoa(policy.TCPPerSource)},
	}
}

func registerPerSourceLimitFlags(fl *pflag.FlagSet) {
	fl.Int("max-udp-flows-per-source", policy.UDPPerSource,
		"cap on concurrent UDP sessions from one source address, summed over all rules, env WGFT_MAX_UDP_FLOWS_PER_SOURCE; 0 disables the per-source cap")
	fl.Int("max-tcp-flows-per-source", policy.TCPPerSource,
		"cap on concurrent TCP connections from one source address, summed over all rules, env WGFT_MAX_TCP_FLOWS_PER_SOURCE; 0 disables the per-source cap")
}

// perSourceLimitsFromConfig reads and validates WGFT_MAX_*_FLOWS_PER_SOURCE. Unlike the
// process-wide caps, 0 is a valid value here: it disables the per-source cap for that protocol.
// It is returned as policy.PerSourceOff, because a zero AdmissionLimits field means the default.
// Anything else must be between 1 and resource.TotalMax; negative values are a config error. That
// upper bound is the process-wide budget's maximum: the two settings have shared one bound since
// the per-source cap was introduced, and a per-source cap above the whole budget has no effect.
func perSourceLimitsFromConfig(c *config) (policy.AdmissionLimits, error) {
	var l policy.AdmissionLimits
	for _, f := range []struct {
		env string
		dst *int
	}{{"WGFT_MAX_UDP_FLOWS_PER_SOURCE", &l.UDPPerSource}, {"WGFT_MAX_TCP_FLOWS_PER_SOURCE", &l.TCPPerSource}} {
		n, err := strconv.Atoi(c.str(f.env))
		if err != nil || n < 0 || n > resource.TotalMax {
			return policy.AdmissionLimits{}, configErrorf(f.env, "%q is not an integer between 0 and %d; 0 disables the per-source cap", c.str(f.env), resource.TotalMax)
		}
		if n == 0 {
			n = policy.PerSourceOff
		}
		*f.dst = n
	}
	return l, nil
}

// applyMemoryLimit は、上限から計算したメモリのソフト上限を Go のランタイムに設定する(仕様 7 節)。
// 運用者が GOMEMLIMIT を設定していれば、ランタイムが既にその値を使っているので触らない。
// apply が偽なら値を印字するだけ(server check)。
func applyMemoryLimit(w io.Writer, l resource.Limits, apply bool) {
	if v := os.Getenv("GOMEMLIMIT"); v != "" {
		fmt.Fprintf(w, "memory soft limit: GOMEMLIMIT=%s; set by the environment\n", v)
		return
	}
	n := l.MemoryLimit()
	if apply {
		debug.SetMemoryLimit(n)
	}
	fmt.Fprintf(w, "memory soft limit: %d MiB, derived from the flow caps; set GOMEMLIMIT to override\n", n>>20)
}
