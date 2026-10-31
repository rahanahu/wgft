package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/internal/resource"
)

// limitSpecs は同時フロー数のプロセス全体の上限(仕様 7 節、11a 節)。server と agent が共有する。
func limitSpecs() []spec {
	return []spec{
		{Env: "WGFT_MAX_UDP_FLOWS", Flag: "max-udp-flows", Default: strconv.Itoa(resource.UDPTotal), Kind: flagInt,
			Usage: "process-wide cap on concurrent UDP sessions, env WGFT_MAX_UDP_FLOWS; lower it on hosts with little memory"},
		{Env: "WGFT_MAX_TCP_FLOWS", Flag: "max-tcp-flows", Default: strconv.Itoa(resource.TCPTotal), Kind: flagInt,
			Usage: "process-wide cap on concurrent TCP connections, env WGFT_MAX_TCP_FLOWS; lower it on hosts with little memory"},
	}
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
		{Env: "WGFT_MAX_UDP_FLOWS_PER_SOURCE", Flag: "max-udp-flows-per-source", Default: strconv.Itoa(policy.UDPPerSource), Kind: flagInt,
			Usage: "cap on concurrent UDP sessions from one source address, summed over all rules, env WGFT_MAX_UDP_FLOWS_PER_SOURCE; 0 disables the per-source cap"},
		{Env: "WGFT_MAX_TCP_FLOWS_PER_SOURCE", Flag: "max-tcp-flows-per-source", Default: strconv.Itoa(policy.TCPPerSource), Kind: flagInt,
			Usage: "cap on concurrent TCP connections from one source address, summed over all rules, env WGFT_MAX_TCP_FLOWS_PER_SOURCE; 0 disables the per-source cap"},
	}
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

// agentBatchSpec は wgstack の送信の向きのバッチの予算(設計文書 wgstack-batching.md の「P_max の決め方」)。
// エージェントだけの設定で、ユーザー空間モードで wgstack を使うときだけ使う。
func agentBatchSpec() spec {
	return spec{Env: "WGFT_AGENT_BATCH_MIB", Flag: "agent-batch-mib", Default: "",
		Usage: "send batching budget of the wgstack network stack in MiB, env WGFT_AGENT_BATCH_MIB; unset derives it from the flow caps, and 0 turns batching off"}
}

// sendBatchShare は β の逆数で、メモリのソフト上限のうち送信の向きの予算に当てる割合を 1/4 にする。β は
// P_max を変えた測定の後に所有者が決める値で、それまでの仮の値である(wgstack-batching.md)。
const sendBatchShare = 4

// sendBatch は WGFT_AGENT_BATCH_MIB から求めた予算である。
type sendBatch struct {
	packets      int   // P_max:2 個以上の packet の入れ物が持てる buffer の数。0 はバッチを使わない
	set          bool  // 値が設定されている。偽なら既定の式の値である
	requestedMiB int64 // 設定された MiB の値
	capped       bool  // 設定された値が P_upper を超え、P_upper に丸めた
}

// sendBatchFromConfig は WGFT_AGENT_BATCH_MIB を読み、P_max を求める。省略と空の値は既定の式で、Linux と
// macOS では ⌊β × M_soft / S⌋ と P_upper の小さい方、Windows では P_upper である。値は MiB で、
// P_max = ⌊値 × 1 MiB / S⌋ を P_upper で丸める。P_upper は CPU の数で決まるので、同じ設定をどのホストでも
// 受け付けるために、超える値を誤りにせず丸める。整数でない値と負の値は設定の誤りである。
func sendBatchFromConfig(c *config, l resource.Limits) (sendBatch, error) {
	s, upper := tunnel.SendBatchBufferBytes(), tunnel.SendBatchCap()
	v := c.str("WGFT_AGENT_BATCH_MIB")
	if v == "" {
		p := upper
		if runtime.GOOS != "windows" {
			p = int(min(l.MemoryLimit()/sendBatchShare/s, int64(upper)))
		}
		return sendBatch{packets: p}, nil
	}
	b := sendBatch{set: true}
	n, err := strconv.ParseInt(v, 10, 64)
	switch {
	case err == nil && n >= 0:
		b.requestedMiB = n
		if n > int64(upper)*s>>20 {
			b.packets, b.capped = upper, true
		} else {
			b.packets = int(min(n<<20/s, int64(upper)))
		}
	case errors.Is(err, strconv.ErrRange) && v[0] != '-':
		b.requestedMiB, b.packets, b.capped = math.MaxInt64, upper, true
	default:
		return sendBatch{}, configErrorf("WGFT_AGENT_BATCH_MIB", "%q is not a whole number of MiB of at least 0; 0 turns send batching off", v)
	}
	return b, nil
}

// logSendBatch は送信の向きの予算の有効な値と出所を 1 行出す。wgstack を使わないモードと netstack では、値が
// 設定されていれば使わない旨を出す(WGFT_AGENT_NETSTACK と同じ扱い)。
func logSendBatch(w io.Writer, mode, netstack string, b sendBatch) {
	switch {
	case mode == "kernel":
		if b.set {
			log.Print("WGFT_AGENT_BATCH_MIB: unused in kernel mode, which runs no network stack in the process; the setting is kept so the same agent.env works in both modes")
		}
		return
	case netstack != "wgstack":
		if b.set {
			log.Print("WGFT_AGENT_BATCH_MIB: unused with the gvisor network stack, which sends one packet at a time; the setting is kept so the same agent.env works with both stacks")
		}
		return
	}
	if b.packets == 0 {
		fmt.Fprintln(w, "send batch budget: 0 MiB; WGFT_AGENT_BATCH_MIB=0 turns send batching off")
		return
	}
	mib := float64(int64(b.packets)*tunnel.SendBatchBufferBytes()) / (1 << 20)
	var src string
	switch {
	case b.capped:
		src = fmt.Sprintf("from WGFT_AGENT_BATCH_MIB lowered to the cap for this host's %d CPUs", runtime.NumCPU())
	case b.set:
		src = "from WGFT_AGENT_BATCH_MIB"
	case runtime.GOOS == "windows":
		src = fmt.Sprintf("the cap for this host's %d CPUs; set WGFT_AGENT_BATCH_MIB to override", runtime.NumCPU())
	default:
		src = "derived from the flow caps; set WGFT_AGENT_BATCH_MIB to override"
	}
	// k_eff が 2 より小さい予算では Device はバッチを使わない(wgstack-batching.md の「下限」)
	if floor := tunnel.SendBatchMin(); b.packets < floor {
		fmt.Fprintf(w, "send batch budget: %.1f MiB, %d buffers, %s; send batching is off because this host's %d CPUs need at least %d buffers, %.1f MiB\n",
			mib, b.packets, src, runtime.NumCPU(), floor, float64(int64(floor)*tunnel.SendBatchBufferBytes())/(1<<20))
		return
	}
	fmt.Fprintf(w, "send batch budget: %.1f MiB, %d buffers, %s\n", mib, b.packets, src)
}
