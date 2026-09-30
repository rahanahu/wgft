package relay

// 設計文書 7a.10 節のルールの登録と帰属の規則を、適用の経路 (Staged.Commit と Apply) の中の操作の
// 順で確かめる。退役した登録のフローの帰属の規則が 2 か所で発火し、各場面の帰属と c_g が判定の式どおりで
// あること、C を c_g、予約の部分の入口を x_g で判定する形が分割で効くことを確かめる。T=64 で
// f=4、C=32、N=2 で m=30、N=3 で m=15。

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

type scenesRig struct {
	t      *testing.T
	m      *Manager
	pool   *resource.Pool
	lb     *loopback
	target string
	mu     sync.Mutex
	logs   []string
	conns  []net.Conn
	steps  []string
}

func newScenesRig(t *testing.T, total int) *scenesRig {
	r := &scenesRig{t: t, pool: resource.NewPool(total), lb: &loopback{}, target: tcpEcho(t)}
	logf := testLogf(t)
	r.m = New(r.lb, Options{TCPPool: r.pool, Logf: func(format string, args ...any) {
		r.mu.Lock()
		r.logs = append(r.logs, fmt.Sprintf(format, args...))
		r.mu.Unlock()
		logf(format, args...)
	}})
	r.m.testHookCommitStep = func(k Key, op string) {
		r.mu.Lock()
		r.steps = append(r.steps, fmt.Sprintf("%s:%d", op, k.Port))
		r.mu.Unlock()
	}
	t.Cleanup(func() {
		r.mu.Lock()
		for _, c := range r.conns {
			c.Close()
		}
		r.mu.Unlock()
		r.m.Close()
	})
	return r
}

func (r *scenesRig) port() uint16 { return reserveTCP(r.t, r.lb) }

func (r *scenesRig) commit(desired map[uint16]string) {
	r.t.Helper()
	d := map[Key]Desired{}
	for port, rule := range desired {
		d[Key{proto.TCP, port}] = Desired{r.target, rule}
	}
	r.mu.Lock()
	r.steps = nil
	r.mu.Unlock()
	r.m.Prepare(d).Commit(nil)
	r.check("commit")
}

func (r *scenesRig) apply(desired map[uint16]string) []Action {
	r.t.Helper()
	d := map[Key]Desired{}
	for port, rule := range desired {
		d[Key{proto.TCP, port}] = Desired{r.target, rule}
	}
	acts := r.m.Apply(d)
	r.check("apply")
	return acts
}

// check は各 Commit と Apply の後の不変条件: 帳簿を作り直した値と照合し、受け付けている待ち受けが
// 運ぶフローが退役した登録に無いこと。
func (r *scenesRig) check(op string) resource.Ledger {
	r.t.Helper()
	if err := r.pool.CheckLedger(); err != nil {
		r.t.Fatalf("after %s: %v", op, err)
	}
	lg := r.pool.Ledger()
	if lg.Orphans != 0 || lg.DoubleReleases != 0 {
		r.t.Fatalf("after %s: orphans %d double %d", op, lg.Orphans, lg.DoubleReleases)
	}
	return lg
}

// open は 1 本の接続を開き、中継を通って宛先に届いたか (echo が返ったか) を返す。届いた接続は
// 開いたまま持つ。
func (r *scenesRig) open(port uint16) bool {
	c, err := dialLoopback(port)
	if err != nil {
		return false
	}
	if got, err := echoLine(c, "x"); err != nil || got != "x\n" {
		c.Close()
		return false
	}
	c.SetDeadline(time.Time{})
	r.mu.Lock()
	r.conns = append(r.conns, c)
	r.mu.Unlock()
	return true
}

// openN は拒まれるまで (最大 n 本) 開き、通った数を返す。
func (r *scenesRig) openN(port uint16, n int) int {
	got := 0
	for i := 0; i < n; i++ {
		if !r.open(port) {
			break
		}
		got++
	}
	r.waitSettled()
	return got
}

// waitSettled は拒んだ接続の後始末 (Admission の手形の返却など) が済むまで少し待つ。
func (r *scenesRig) waitSettled() { time.Sleep(20 * time.Millisecond) }

func (r *scenesRig) lastLog(sub string) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i := len(r.logs) - 1; i >= 0; i-- {
		if strings.Contains(r.logs[i], sub) {
			return r.logs[i]
		}
	}
	return ""
}

func (r *scenesRig) refusals(rule string) map[resource.Reason]uint64 { return r.pool.Refusals()[rule] }

// 統合 (Commit の付け替えで B の最後の待ち受けが A へ移る) で B の登録が退役し、B の
// フローは統合先の登録へ移る。UDP の再開は TestUDPResumeJoinMovesSessions が確かめる。
func TestLedgerMergeMovesToTarget(t *testing.T) {
	r := newScenesRig(t, 64)
	pa, pb, px := r.port(), r.port(), r.port()
	r.commit(map[uint16]string{pa: "A", pb: "B", px: "X"})
	// N=3、m=15: B は T-P-(N-1)m = 30 本まで (spare)
	if n := r.openN(pb, 100); n != 30 {
		t.Fatalf("B held %d, want 30", n)
	}
	r.commit(map[uint16]string{pa: "A", pb: "A", px: "X"})
	lg := r.check("merge")
	if lg.RegFlows["A"] != 30 || lg.RegCarried["A"] != 30 || lg.RetiredFlows != 0 || lg.Rules != 2 {
		t.Fatalf("after merge %+v", lg)
	}
}

// 範囲のルール B (p1、p2) を分割して p2 を D にした Commit の後、B を削除する Commit。
// p2 が運ぶ B のフローは D の登録へ移り、閉じた p1 のフローは移らない。
func TestLedgerSplitThenDeleteHead(t *testing.T) {
	r := newScenesRig(t, 64)
	p1, p2, px := r.port(), r.port(), r.port()
	r.commit(map[uint16]string{p1: "B", p2: "B", px: "X"})
	if n := r.openN(p1, 3); n != 3 {
		t.Fatal(n)
	}
	if n := r.openN(p2, 10); n != 10 {
		t.Fatal(n)
	}
	r.commit(map[uint16]string{p1: "B", p2: "D", px: "X"})
	lg := r.check("split")
	if lg.RegFlows["B"] != 13 || lg.RegCarried["B"] != 3 || lg.RegFlows["D"] != 0 || lg.RegCarried["D"] != 10 {
		t.Fatalf("after split %+v", lg)
	}
	r.commit(map[uint16]string{p2: "D", px: "X"})
	lg = r.check("delete head")
	// p1 の 3 本は closeF が切り、中継の終わりに返る。退役した B に残るのはそれだけで、D へは移らない
	if lg.RegFlows["D"] != 10 || lg.RegCarried["D"] != 10 || lg.RetiredFlows > 3 {
		t.Fatalf("after delete head %+v", lg)
	}
	deadline := time.Now().Add(3 * time.Second)
	for r.pool.Ledger().RetiredFlows != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if lg = r.check("cut"); lg.RetiredFlows != 0 || lg.InUse != 10 {
		t.Fatalf("after the head's conns were cut %+v", lg)
	}
}

// 分割先の C。B だけのときに p2 が 33 本を運び、p2 を D へ分割すると、D は a_D=0 でも
// c_D=33 ≥ C=32 で rule_cap。文言の数は c_g。
func TestLedgerSplitTargetRuleCap(t *testing.T) {
	r := newScenesRig(t, 64)
	p1, p2 := r.port(), r.port()
	r.commit(map[uint16]string{p1: "B", p2: "B"})
	if n := r.openN(p2, 33); n != 33 {
		t.Fatal(n)
	}
	r.commit(map[uint16]string{p1: "B", p2: "D"})
	if lg := r.check("split"); lg.RegFlows["D"] != 0 || lg.RegCarried["D"] != 33 {
		t.Fatalf("%+v", lg)
	}
	if r.open(p2) {
		t.Fatal("D admitted a flow while its listener carries C")
	}
	r.waitSettled()
	if r.refusals("D")[resource.ReasonRuleCap] != 1 {
		t.Fatalf("refusals %v", r.pool.Refusals())
	}
	if l := r.lastLog("rule D holds"); !strings.Contains(l, "rule D holds 33 flows and the rest of the budget is reserved for 1 other rule") {
		t.Fatalf("log %q", l)
	}
}

// 分割先の門。B だけのときに p1 が 25 本、p2 が 20 本を運び、p2 を D へ分割して X を加える
// (N=3、m=15)。D は下限の部分で 4 本を取った後、x_D=24 ≥ m なので予約の部分を使えず、共有分の
// 判定で reserve。門が無ければ予約の部分の条件 u+1+S_f+P ≤ T で通る状態である。
func TestLedgerSplitTargetGate(t *testing.T) {
	r := newScenesRig(t, 64)
	p1, p2, px := r.port(), r.port(), r.port()
	r.commit(map[uint16]string{p1: "B", p2: "B"})
	if n := r.openN(p1, 25); n != 25 {
		t.Fatal(n)
	}
	if n := r.openN(p2, 20); n != 20 {
		t.Fatal(n)
	}
	r.commit(map[uint16]string{p1: "B", p2: "D", px: "X"})
	if n := r.openN(p2, 50); n != 4 {
		t.Fatalf("D admitted %d new flows, want f=4", n)
	}
	lg := r.check("gate")
	if lg.RegFlows["D"] != 4 || lg.RegCarried["D"] != 24 || lg.InUse != 49 {
		t.Fatalf("%+v", lg)
	}
	if got := r.refusals("D"); got[resource.ReasonReserve] != 1 || len(got) != 1 {
		t.Fatalf("refusals %v", got)
	}
	want := "rule D holds 24 flows, at or above its minimum of 15, and the free part of the budget, 15 of 64, is held for the unfilled minimums of this rule and 1 other rule, 26 flows"
	if l := r.lastLog("rule D holds"); !strings.Contains(l, want) {
		t.Fatalf("log %q\nwant %q", l, want)
	}
}

// 分割元に残ったポート。B (p1、p2) と X。p1 が 2 本、p2 がフラッドで B は m=30 まで。p2 を
// D へ分割すると (N=3、m=15)、B の a_B=30 は p2 の旧い接続を含むので p1 の新しい接続は spare で
// 0 本。B を別の ID に名前を変える (同じポートの B の削除と新しい ID の追加を 1 回の Commit で行う)
// と、B の登録が退役して p2 の旧い接続は D へ移り、p1 は最低分まで通せる。p1 の既存の接続は切れない。
func TestLedgerSplitRemainderAndRename(t *testing.T) {
	r := newScenesRig(t, 64)
	p1, p2, px := r.port(), r.port(), r.port()
	r.commit(map[uint16]string{p1: "B", p2: "B", px: "X"})
	if n := r.openN(p1, 2); n != 2 {
		t.Fatal(n)
	}
	p1conns := append([]net.Conn(nil), r.conns...)
	if n := r.openN(p2, 100); n != 28 {
		t.Fatalf("p2 flood held %d, want 28", n)
	}
	r.commit(map[uint16]string{p1: "B", p2: "D", px: "X"})
	lg := r.check("split")
	if lg.RegFlows["B"] != 30 || lg.RegCarried["B"] != 2 || lg.RegCarried["D"] != 28 || lg.Minimum != 15 {
		t.Fatalf("after split %+v", lg)
	}
	if n := r.openN(p1, 10); n != 0 {
		t.Fatalf("p1 admitted %d after the split, want 0", n)
	}
	// 分割の前の p2 のフラッドの 1 件と、分割の後の p1 の 1 件
	if got := r.refusals("B"); got[resource.ReasonSpare] != 2 {
		t.Fatalf("refusals %v", got)
	}
	t.Logf("p1 refusal: %s", r.lastLog("rule B holds"))
	// 名前の変更: 宣言の上では B の削除と B2 の追加。同じポートと宛先なので Commit は付け替えになる
	r.commit(map[uint16]string{p1: "B2", p2: "D", px: "X"})
	lg = r.check("rename")
	if lg.RegFlows["D"] != 28 || lg.RegFlows["B2"] != 2 || lg.RetiredFlows != 0 || lg.Rules != 3 {
		t.Fatalf("after rename %+v", lg)
	}
	for i, c := range p1conns {
		if got, err := echoLine(c, "still"); err != nil || got != "still\n" {
			t.Fatalf("p1 conn %d was cut by the rename: %q %v", i, got, err)
		}
	}
	nb := r.openN(p1, 100)
	nx := r.openN(px, 100)
	t.Logf("after rename: p1 new %d (holds %d), x %d; %+v", nb, nb+2, nx, r.pool.Ledger())
	// 名前の変更の後は E = 62 で余りが 2 あるので、p1 は m=15 と共有分の 2 本
	if nb+2 != 17 || nx != 15 {
		t.Fatalf("after rename p1 holds %d, x %d; want 17 and 15", nb+2, nx)
	}
}

// 1 回の Commit に、分割元の最後の待ち受けの閉鎖と、分割したポートの別のルールへの付け替え
// を入れる (B (p1、p2)、D (pd)、E (pe)、X。p2 を D へ分割し、同じ Commit で p1 を
// 閉じて p2 を E へ付け替える。D は pd で続く)。map の順で 2 通りの順が起きることと、どちらの順でも
// 受け付けている待ち受けが運ぶフローが退役した登録に残らないことを、繰り返して確かめる。閉鎖が先
// なら p2 の旧い接続は B の退役で D へ移り、その後の付け替えでは動かない。付け替えが先なら B の退役
// で E へ移る。
func TestLedgerOneCommitOrder(t *testing.T) {
	n := 300
	if testing.Short() {
		n = 30
	}
	seen := map[string]int{}
	finals := map[string]map[string]int{}
	for i := 0; i < n; i++ {
		order, final := oneCommitOnce(t)
		seen[order]++
		if finals[order] == nil {
			finals[order] = map[string]int{}
		}
		finals[order][final]++
	}
	t.Logf("orders over %d runs: %v; final by order: %v", n, seen, finals)
	if len(seen) != 2 {
		t.Fatalf("orders seen %v, want both", seen)
	}
}

func oneCommitOnce(t *testing.T) (order, final string) {
	r := newScenesRig(t, 64)
	p1, p2, pd, pe, px := r.port(), r.port(), r.port(), r.port(), r.port()
	r.commit(map[uint16]string{p1: "B", p2: "B", pd: "D", pe: "E", px: "X"})
	if n := r.openN(p1, 1); n != 1 {
		t.Fatal(n)
	}
	if n := r.openN(p2, 3); n != 3 {
		t.Fatal(n)
	}
	r.commit(map[uint16]string{p1: "B", p2: "D", pd: "D", pe: "E", px: "X"})
	r.commit(map[uint16]string{p2: "E", pd: "D", pe: "E", px: "X"})
	r.mu.Lock()
	steps := strings.Join(r.steps, ",")
	r.mu.Unlock()
	if strings.HasPrefix(steps, "close") {
		order = "close-first"
	} else {
		order = "relabel-first"
	}
	lg := r.check("one commit")
	if lg.RegFlows["D"]+lg.RegFlows["E"] != 3 || lg.RegCarried["E"] != 3 || lg.RetiredFlows > 1 {
		t.Fatalf("%s (%s): %+v", order, steps, lg)
	}
	final = fmt.Sprintf("D=%d E=%d", lg.RegFlows["D"], lg.RegFlows["E"])
	r.mu.Lock()
	for _, c := range r.conns {
		c.Close()
	}
	r.conns = nil
	r.mu.Unlock()
	r.m.Close()
	return order, final
}

// agent の Apply はポートの順に操作する。ルール R を高いポートから低いポートへ移す宣言では
// 低いポートの open が高いポートの close より先になり、R の登録は退役しない (帰属の規則は発火しない)。
// 逆向きでは close が先で、R は退役して新しい登録になり、旧い接続は退役した登録に残る。
func TestLedgerApplyPortOrder(t *testing.T) {
	for _, dir := range []string{"open-first", "close-first"} {
		t.Run(dir, func(t *testing.T) {
			r := newScenesRig(t, 64)
			a, b := r.port(), r.port()
			lo, hi := min(a, b), max(a, b)
			from, to := hi, lo
			if dir == "close-first" {
				from, to = lo, hi
			}
			px := r.port()
			r.apply(map[uint16]string{from: "R", px: "X"})
			if n := r.openN(from, 5); n != 5 {
				t.Fatal(n)
			}
			serial := r.pool.Ledger().RegSerial["R"]
			acts := r.apply(map[uint16]string{to: "R", px: "X"})
			lg := r.check("move")
			t.Logf("%s: actions %v; ledger %+v", dir, acts, lg)
			retired := lg.RegSerial["R"] != serial
			if dir == "open-first" && (retired || lg.RegFlows["R"] > 5) {
				t.Fatalf("open-first: R retired %v", retired)
			}
			if dir == "close-first" && (!retired || lg.RegFlows["R"] != 0) {
				t.Fatalf("close-first: R retired %v, a_R %d", retired, lg.RegFlows["R"])
			}
		})
	}
}
