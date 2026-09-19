// Package interp は、internal/policy/nftables の行の列を実行するテスト専用の解釈器である
// (設計文書 7a.9 節「fixture の形式と等価性の検査」)。
//
// 解釈器は IR(internal/policy)を読まず、行の列(nftables.Program)だけを入力にする。IR から
// 期待する判定を作るのは fixture の役目なので、コンパイラが行の順序を誤る、行を抜かす、
// ct state new を付け忘れる、コメントを誤る、といった誤りは fixture との食い違いとして現れる。
//
// 解釈器は table inet wgft の filter_pre チェーンの模型であり、次を模す。
//
//   - 行の一致:プロトコル、宛先ポートの範囲、ct state new(conntrack に確定したエントリが無い
//     フローのパケットだけが一致する)。ip saddr を読む行は IPv4 のパケットにだけ一致する
//   - interval の set の照合(ip saddr @set と ip saddr != @set)
//   - 動的 set への add と要素ごとの limit(meter):要素は add で作った時点から set の timeout で
//     消え、add は期限を延ばさない(カーネルでの確認は未確認で、7a.9 節の許容差「送信元ごとの表の
//     期限と溢れ」の前提と同じ)。set が size まで埋まると新しい要素の add が失敗し、その行は
//     一致しない
//   - ct count:送信元ごとに、そのフローを含む生きたフローの数が上限を超えれば一致する。フローの
//     end で数から抜ける。行が一致してパケットを落としたフローや、後の行が落としたフローは、
//     conntrack に確定しないので数から抜く(カーネルでは次の gc で抜ける)
//   - limit rate over:カーネルの nft_limit と同じ整数のナノ秒のトークンバケット(容量は
//     burst 個ぶん、満杯から始まり、1 個ぶんを unit/rate ナノ秒で補充する)
//   - counter:行が一致してパケットを落とすたびに 1 増える
//
// 次は模さない。
//
//   - バイト数(fixture はパケット数だけを比べる)
//   - DNAT、nat_pre 以降のチェーン、conntrack の timeout(フローはテストが end で閉じるまで生きる)
//   - ct count の要素の gc の遅れ(落としたフローはすぐ数から抜く)
//   - 応答前の UDP の 2 つ目以降のパケット(conntrack が確定した後のパケットは new ではない)
//   - テーブルの差し替え(解釈器は 1 つのテーブルの一生だけを扱う)
package interp

import (
	"fmt"
	"net/netip"
	"time"

	polnft "github.com/rahanahu/wgft/internal/policy/nftables"
	"github.com/rahanahu/wgft/proto"
)

// Packet は filter_pre に入るパケット 1 つ。
type Packet struct {
	Proto   proto.Proto
	DstPort uint16
	Src     netip.Addr
	// Flow は conntrack のエントリの識別子(5 タプルの代わり)。同じ Flow のパケットは同じフローに属する。
	Flow string
}

// Verdict は 1 つのパケットの判定。
type Verdict struct {
	Dropped bool
	Comment string // 落とした行のコメント(Dropped のときだけ)
}

// Interpreter は 1 つのテーブルの状態(set の要素、トークンバケット、conntrack、カウンタ)を持つ。
// 時刻はテーブルを読み込んだ時点を 0 とする仮想の時計で、呼び出し側が単調に進める。
type Interpreter struct {
	prog     polnft.Program
	interval map[string][]netip.Prefix
	meters   map[string]*meter
	flowSets map[string]*flowSet
	limits   map[int]*bucket // 行の添字 → 集約のトークンバケット
	counters []uint64        // 行の添字 → 落としたパケット数
	conns    map[string]*conn
}

type conn struct {
	src      netip.Addr
	flowSets []string // このフローを数えている ct count の set
}

// New は行の列を読み込む。行が宣言の無い set を参照していれば誤りを返す。
func New(prog polnft.Program) (*Interpreter, error) {
	in := &Interpreter{
		prog: prog, interval: map[string][]netip.Prefix{}, meters: map[string]*meter{},
		flowSets: map[string]*flowSet{}, limits: map[int]*bucket{},
		counters: make([]uint64, len(prog.Rows)), conns: map[string]*conn{},
	}
	for _, s := range prog.Sets {
		switch s.Kind {
		case polnft.SetInterval:
			in.interval[s.Name] = s.Elements
		case polnft.SetMeter:
			in.meters[s.Name] = &meter{timeout: s.Timeout, size: s.Size, elems: map[netip.Addr]*meterElem{}}
		case polnft.SetFlowCount:
			in.flowSets[s.Name] = &flowSet{size: s.Size, elems: map[netip.Addr]map[string]bool{}}
		default:
			return nil, fmt.Errorf("set %s: unknown kind %d", s.Name, s.Kind)
		}
	}
	for i, r := range prog.Rows {
		var ok bool
		switch r.Stmt.Kind {
		case polnft.StmtSourceInSet, polnft.StmtSourceNotInSet:
			_, ok = in.interval[r.Stmt.Set]
		case polnft.StmtPerSourceLimit:
			_, ok = in.meters[r.Stmt.Set]
		case polnft.StmtPerSourceCtCount:
			_, ok = in.flowSets[r.Stmt.Set]
		case polnft.StmtLimit:
			b, err := newBucket(r.Stmt.Rate, r.Stmt.Burst, 0)
			if err != nil {
				return nil, fmt.Errorf("row %s: %w", r.Comment, err)
			}
			in.limits[i] = b
			ok = true
		}
		if !ok {
			return nil, fmt.Errorf("row %s: statement %d refers to set %q of the wrong kind or no set", r.Comment, r.Stmt.Kind, r.Stmt.Set)
		}
	}
	return in, nil
}

// Eval は時刻 now に p を filter_pre に通す。どの行も落とさなければ、フローは conntrack に確定する。
func (in *Interpreter) Eval(now time.Duration, p Packet) (Verdict, error) {
	_, established := in.conns[p.Flow]
	isNew := !established
	var added []string // この評価で p.Flow を加えた ct count の set
	undo := func() {
		for _, name := range added {
			in.flowSets[name].remove(p.Src, p.Flow)
		}
	}
	for i, r := range in.prog.Rows {
		if r.Match.Proto != p.Proto || p.DstPort < r.Match.Ports.Lo || p.DstPort > r.Match.Ports.Hi {
			continue
		}
		if r.Match.CtStateNew && !isNew {
			continue
		}
		if (r.Match.IPv4 || r.Stmt.UsesSource()) && !p.Src.Is4() {
			continue // meta nfproto ipv4 に一致しない
		}
		hit, err := in.stmt(i, r.Stmt, now, p, isNew, &added)
		if err != nil {
			undo()
			return Verdict{}, fmt.Errorf("row %s: %w", r.Comment, err)
		}
		if hit {
			in.counters[i]++
			undo()
			return Verdict{Dropped: true, Comment: r.Comment}, nil
		}
	}
	if isNew {
		in.conns[p.Flow] = &conn{src: p.Src, flowSets: added}
	}
	return Verdict{}, nil
}

func (in *Interpreter) stmt(i int, st polnft.Stmt, now time.Duration, p Packet, isNew bool, added *[]string) (bool, error) {
	switch st.Kind {
	case polnft.StmtSourceInSet:
		return contains(in.interval[st.Set], p.Src), nil
	case polnft.StmtSourceNotInSet:
		return !contains(in.interval[st.Set], p.Src), nil
	case polnft.StmtPerSourceLimit:
		e, err := in.meters[st.Set].add(now, p.Src, st.Rate, st.Burst)
		if err != nil {
			return false, err
		}
		if e == nil {
			return false, nil // set が埋まっていて add が失敗した。行は一致しない
		}
		return e.bucket.over(now), nil
	case polnft.StmtPerSourceCtCount:
		fs := in.flowSets[st.Set]
		if !isNew {
			// ct count の行は ct state new を伴うので、ここには来ない。来たら行の列の誤りである
			return false, fmt.Errorf("ct count evaluated for an established flow")
		}
		n, ok := fs.add(p.Src, p.Flow)
		if !ok {
			return false, nil // set が埋まっていて add が失敗した
		}
		*added = append(*added, st.Set)
		return n > int(st.Count), nil
	case polnft.StmtLimit:
		return in.limits[i].over(now), nil
	default:
		return false, fmt.Errorf("unknown statement %d", st.Kind)
	}
}

// End はフローを終える。conntrack のエントリが消え、ct count の数から抜ける。
func (in *Interpreter) End(flow string) {
	c, ok := in.conns[flow]
	if !ok {
		return
	}
	for _, name := range c.flowSets {
		in.flowSets[name].remove(c.src, flow)
	}
	delete(in.conns, flow)
}

// Counter は 1 つの行のカウンタ。
type Counter struct {
	Comment string
	Packets uint64
}

// Counters は行ごとのカウンタを行の順に返す。
func (in *Interpreter) Counters() []Counter {
	out := make([]Counter, len(in.prog.Rows))
	for i, r := range in.prog.Rows {
		out[i] = Counter{Comment: r.Comment, Packets: in.counters[i]}
	}
	return out
}

func contains(prefixes []netip.Prefix, a netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// meter は `flags dynamic; timeout; size` の set で、要素ごとに limit を持つ。
type meter struct {
	timeout time.Duration
	size    int
	elems   map[netip.Addr]*meterElem
}

type meterElem struct {
	expires time.Duration
	bucket  *bucket
}

// add は `add @meter { ip saddr limit ... }` の要素を返す。要素が無ければ満杯のバケットで作る。
// 期限の切れた要素は無いものとして扱う。set が埋まっていれば nil を返す。
func (m *meter) add(now time.Duration, src netip.Addr, r proto.Rate, burst uint32) (*meterElem, error) {
	for a, e := range m.elems {
		if now >= e.expires {
			delete(m.elems, a)
		}
	}
	if e, ok := m.elems[src]; ok {
		return e, nil
	}
	if len(m.elems) >= m.size {
		return nil, nil
	}
	b, err := newBucket(r, burst, now)
	if err != nil {
		return nil, err
	}
	e := &meterElem{expires: now + m.timeout, bucket: b}
	m.elems[src] = e
	return e, nil
}

// flowSet は ct count の set。送信元ごとに、数えている生きたフローの集合を持つ。
type flowSet struct {
	size  int
	elems map[netip.Addr]map[string]bool
}

// add は flow を src の数に加え、加えた後の数を返す。src の要素が無く set が埋まっていれば
// false を返す。同じフローを 2 度加えても数は増えない(conncount はタプルで重複を除く)。
func (f *flowSet) add(src netip.Addr, flow string) (int, bool) {
	e, ok := f.elems[src]
	if !ok {
		if len(f.elems) >= f.size {
			return 0, false
		}
		e = map[string]bool{}
		f.elems[src] = e
	}
	e[flow] = true
	return len(e), true
}

func (f *flowSet) remove(src netip.Addr, flow string) {
	e, ok := f.elems[src]
	if !ok {
		return
	}
	delete(e, flow)
	if len(e) == 0 {
		delete(f.elems, src)
	}
}

// bucket はカーネルの nft_limit(パケット単位)と同じトークンバケットである。トークンは
// ナノ秒で持ち、1 パケットの費用は unit/rate ナノ秒(整数の割り算)、容量は費用の burst 倍で、
// 満杯から始まる。判定のたびに経過時間だけトークンを増やし(容量で頭打ち)、費用を払えれば
// 通し、払えなければ `over` に一致する。
type bucket struct {
	cost, max, tokens int64
	last              time.Duration
}

func newBucket(r proto.Rate, burst uint32, now time.Duration) (*bucket, error) {
	unit, ok := map[proto.RateUnit]time.Duration{
		proto.PerSecond: time.Second, proto.PerMinute: time.Minute, proto.PerHour: time.Hour,
		proto.PerDay: 24 * time.Hour, proto.PerWeek: 7 * 24 * time.Hour,
	}[r.Unit]
	if !ok || r.Count == 0 {
		return nil, fmt.Errorf("rate %s cannot be a token bucket", r)
	}
	if burst == 0 {
		return nil, fmt.Errorf("rate %s has burst 0", r)
	}
	cost := int64(unit) / int64(r.Count)
	return &bucket{cost: cost, max: cost * int64(burst), tokens: cost * int64(burst), last: now}, nil
}

func (b *bucket) over(now time.Duration) bool {
	tokens := b.tokens + int64(now-b.last)
	if tokens > b.max {
		tokens = b.max
	}
	b.last = now
	if tokens >= b.cost {
		b.tokens = tokens - b.cost
		return false
	}
	b.tokens = tokens
	return true
}
