//go:build linux && (amd64 || arm64)

package wgstack

import (
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"unsafe"
)

// docs/design/userspace/wgstack-bound-table.md は Device.Bound と構造の大きさから生成する。上界の式の項、
// 構造の大きさ、表の大きさを変えたら次で書き直す:
//
//	go test ./internal/wgstack -run TestBoundDocUpToDate -update
var updateBoundDoc = flag.Bool("update", false, "rewrite docs/design/userspace/wgstack-bound-table.md from Device.Bound")

const boundDocPath = "../../docs/design/userspace/wgstack-bound-table.md"

// boundConfig は生成する表の 1 列で、Device の設定 1 つである。列を足すときは boundConfigs に足す。
type boundConfig struct {
	id   string // 列の名前。文書の錨は config-<id> になる
	desc string // 構成の説明。文書に載せる
	cfg  Config
}

// agentBatch は、エージェントが Linux で WGFT_AGENT_BATCH_MIB を省いたときに渡す送信の向きのバッチの設定で、
// CPU が 4 個のときの値である(internal/dataplane/userspace/tunnel の sendBatchConfig)。pmax は
// cmd/wgft の sendBatchFromConfig の既定の式 ⌊0.15 × M_soft / 64 KiB⌋ の値で、M_soft は
// internal/resource の MemoryLimit(32 MiB + U × 12 KiB + K × 44 KiB)である。台帳の輪(⌊P_max / 2⌋ 行)だけが
// M_fix に入る。
func agentBatch(pmax int) SendBatch {
	return SendBatch{Packets: pmax, Size: 32, Callers: 4 + 6, BufferSize: 65535}
}

// boundConfigs は文書に載せる構成である。エージェントの MTU は server の WGFT_MTU の既定値である。
var boundConfigs = []boundConfig{
	{"agent-k2048", "エージェントの既定。K は 2048、U は 8192 で、P_max は 518 です", Config{MTU: 1420, MaxFlows: 2048, SendBatch: agentBatch(518)}},
	{"agent-k1024", "エージェントで K を 1024 にした構成。U は 8192 で、P_max は 412 です", Config{MTU: 1420, MaxFlows: 1024, SendBatch: agentBatch(412)}},
	{"agent-k512", "エージェントで K を 512 にした構成。U は 8192 で、P_max は 360 です", Config{MTU: 1420, MaxFlows: 512, SendBatch: agentBatch(360)}},
	{"agent-k256", "エージェントで K を 256 にした構成。U は 8192 で、P_max は 333 です", Config{MTU: 1420, MaxFlows: 256, SendBatch: agentBatch(333)}},
}

// 構造の大きさとヒープの切り上げは build で決まるので、生成と照合は 64 bit の Linux でだけ行う(このファイルの
// ビルドタグ)。公開する target で大きさが同じことは設計文書の「上界の式」にある。
func TestBoundDocUpToDate(t *testing.T) {
	got := renderBoundDoc(t)
	if *updateBoundDoc {
		if err := os.WriteFile(boundDocPath, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(boundDocPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(want) != got {
		t.Fatalf("%s is out of date; run: go test ./internal/wgstack -run TestBoundDocUpToDate -update", boundDocPath)
	}
}

// TestBoundDocConfigs は、表の構成の id が重ならず、Device がその設定で送信の向きのバッチを使うことを確かめる。
// バッチを使わない設定では台帳の輪が M_fix に入らず、表がエージェントの値より小さくなる。
func TestBoundDocConfigs(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range boundConfigs {
		if seen[c.id] {
			t.Errorf("config id %q appears twice", c.id)
		}
		seen[c.id] = true
		d := newBoundDevice(t, c.cfg)
		if c.cfg.SendBatch.Packets > 0 && !d.Batching() {
			t.Errorf("config %s: the device does not batch", c.id)
		}
	}
}

func newBoundDevice(t *testing.T, cfg Config) *Device {
	t.Helper()
	cfg.Addr = netip.MustParseAddr("10.0.0.1")
	cfg.Clock = NewManualClock()
	d, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func renderBoundDoc(t *testing.T) string {
	var b strings.Builder
	b.WriteString("# wgstack の上界の表\n\n")
	b.WriteString("この文書は `internal/wgstack` の `TestBoundDocUpToDate` が `Device.Bound` と構造の大きさから生成します。\n")
	b.WriteString("手で直しません。\n")
	b.WriteString("上界の式の項、構造の大きさ、表の大きさを変えたら次のコマンドで生成し直し、同じコミットに含めます。\n\n")
	b.WriteString("```sh\ngo test ./internal/wgstack -run TestBoundDocUpToDate -update\n```\n\n")
	b.WriteString("式と項の意味は[上界の式](wgstack.md#上界の式)にあります。\n")
	b.WriteString("値は 64 bit の Linux の build で求めます。\n")
	b.WriteString("公開する target のどれでも構造の大きさが同じことは、[上界の式](wgstack.md#上界の式)の節にあります。\n")
	b.WriteString("MiB は 1,048,576 byte です。\n")

	b.WriteString("\n## 構造の大きさ\n\n")
	b.WriteString("| 記号 | 意味 | byte |\n|---|---|---|\n")
	sizes := []struct {
		id, sym, what string
		n             int64
	}{
		{"size-conn", "c_conn", "接続の枠 1 つの構造", int64(unsafe.Sizeof(tcb{}))},
		{"size-record", "", "送信の記録 1 件", int64(unsafe.Sizeof(record{}))},
		{"size-interval", "", "順序外の区間 1 つ", int64(unsafe.Sizeof(interval{}))},
		{"size-syn", "c_syn", "握手の途中の表の 1 行", int64(unsafe.Sizeof(synRow{}))},
		{"size-tw", "c_tw", "TIME_WAIT の表の 1 行", int64(unsafe.Sizeof(twRow{}))},
		{"size-index", "", "握手の途中と TIME_WAIT の hash の表の 1 項目", int64(unsafe.Sizeof(indexEnt{}))},
		{"size-conn-index", "", "接続の hash の表の 1 項目(世代を含みます)", int64(unsafe.Sizeof(indexEnt{})) + int64(unsafe.Sizeof(uint64(0)))},
		{"size-slot-runtime", "", "接続の枠 1 つが表の外に持つ構造として数える量", slotRuntime},
	}
	for _, s := range sizes {
		fmt.Fprintf(&b, "| <a id=\"%s\"></a>%s | %s | %s |\n", s.id, s.sym, s.what, commas(s.n))
	}

	tm := terms()
	b.WriteString("\n## 枠 1 つの項\n\n")
	b.WriteString("値は確保の丸めを含めた byte の数です。\n\n")
	b.WriteString("| 項 | 意味 | byte |\n|---|---|---|\n")
	slots := []struct {
		id, sym, what string
		n             int64
	}{
		{"slot-fs", "f_s", "送信の floor", tm.fs},
		{"slot-fr", "f_r", "受信の floor", tm.fr},
		{"slot-rf", "r_f", "floor の送信の記録の輪", tm.rf},
		{"slot-hf", "h_f", "floor の順序外の区間の表", tm.hf},
		{"slot-floor", "f_s + f_r + r_f + h_f", "接続の枠 1 つの floor の和", tm.floor()},
		{"slot-ds", "d_s", "boost が送信の floor に加える分", tm.ds},
		{"slot-dr", "d_r", "boost が受信の floor に加える分", tm.dr},
		{"slot-drec", "d_rec", "boost の送信の記録の輪の全体", tm.drec},
		{"slot-dh", "d_h", "boost の順序外の区間の表の全体", tm.dh},
		{"slot-boost", "d_s + d_r + d_rec + d_h", "boost の枠 1 つの和", tm.boost()},
	}
	for _, s := range slots {
		fmt.Fprintf(&b, "| <a id=\"%s\"></a>%s | %s | %s |\n", s.id, s.sym, s.what, commas(s.n))
	}

	b.WriteString("\n## 構成\n\n")
	b.WriteString("| 構成 | 説明 |\n|---|---|\n")
	bounds := make([]Bound, len(boundConfigs))
	ncs := make([]int, len(boundConfigs))
	for i, c := range boundConfigs {
		d := newBoundDevice(t, c.cfg)
		bounds[i] = d.Bound()
		ncs[i] = d.s.lim.conns()
		fmt.Fprintf(&b, "| <a id=\"config-%s\"></a>`%s` | %s |\n", c.id, c.id, c.desc)
	}

	b.WriteString("\n## 構成ごとの上界\n\n")
	b.WriteString("値は `Device.Bound` の欄で、単位は MiB です。\n")
	b.WriteString("M_fix は、式の N_c × c_conn、N_syn × c_syn、M × c_tw、Q_ctl × s_ctl を含みます。\n")
	b.WriteString("boost の項は、プロセスの boost の枠のすべてを 1 つの Device が持つとして数えます。\n\n")
	b.WriteString("| 項 | 欄 |")
	for _, c := range boundConfigs {
		fmt.Fprintf(&b, " `%s` |", c.id)
	}
	b.WriteString("\n|---|---|")
	for range boundConfigs {
		b.WriteString("---|")
	}
	b.WriteString("\n")
	row := func(id, name, field string, f func(i int) string) {
		fmt.Fprintf(&b, "| <a id=\"%s\"></a>%s | %s |", id, name, field)
		for i := range boundConfigs {
			fmt.Fprintf(&b, " %s |", f(i))
		}
		b.WriteString("\n")
	}
	row("bound-k", "K", "", func(i int) string { return commas(int64(boundConfigs[i].cfg.MaxFlows)) })
	row("bound-nc", "N_c", "", func(i int) string { return commas(int64(ncs[i])) })
	mib := func(get func(Bound) int64) func(int) string {
		return func(i int) string { return mebi(get(bounds[i])) }
	}
	row("bound-fix", "M_fix", "`Fix`", mib(func(x Bound) int64 { return x.Fix }))
	row("bound-floor", "N_c × (f_s + f_r + r_f + h_f)", "`FloorConn`", mib(func(x Bound) int64 { return x.FloorConn }))
	row("bound-boost", "B × (d_s + d_r + d_rec + d_h)", "`Boost`", mib(func(x Bound) int64 { return x.Boost }))
	row("bound-udp-rx", "M_udp_rx", "`UDPRx`", mib(func(x Bound) int64 { return x.UDPRx }))
	row("bound-udp-tx", "M_udp_tx", "`UDPTx`", mib(func(x Bound) int64 { return x.UDPTx }))
	row("bound-frag", "M_frag", "`Frag`", mib(func(x Bound) int64 { return x.Frag }))
	row("bound-ping", "N_ping × c_ping", "`Ping`", mib(func(x Bound) int64 { return x.Ping }))
	row("bound-total", "和", "`Total`", mib(func(x Bound) int64 { return x.Total }))
	row("bound-transient", "式の外の一時の保持 B × (f_s + f_r)", "`Transient`", mib(func(x Bound) int64 { return x.Transient }))
	return b.String()
}

// mebi は n byte を MiB で小数第 1 位まで、3 桁ごとの区切りを付けて返す。0.1 MiB に満たない値は小数第 3 位まで
// 返す。
func mebi(n int64) string {
	if n < 1<<20/10 {
		return fmt.Sprintf("%.3f", float64(n)/(1<<20))
	}
	tenths := (n*10 + 1<<19) >> 20 // 0.1 MiB の単位で四捨五入
	return fmt.Sprintf("%s.%d", commas(tenths/10), tenths%10)
}

// commas は n を 3 桁ごとの区切りを付けて返す。
func commas(n int64) string {
	s := fmt.Sprint(n)
	if n < 0 {
		return "-" + commas(-n)
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}
