package wgstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"testing"
	"time"
)

// 送信の向きの予算(wgstack-batching.md の「送信の向きの予算」)の純粋な単体の試験。台帳、門、印、1 回遅れの
// 知らせを、wireguard-go を使わずに確かめる。

const testBuf = 128 // 単体の試験の buffer の大きさ。印の 16 byte と message の 33 byte が収まる

func newTestLedger(t *testing.T, pmax, size, callers int) *sendLedger {
	t.Helper()
	l := &sendLedger{}
	l.init(SendBatch{Packets: pmax, Size: size, Callers: callers, BufferSize: 1 << 16}, 1420)
	if !l.on {
		t.Fatalf("ledger with P_max %d, k_tx %d, C %d is off", pmax, size, callers)
	}
	return l
}

// tagged は seq の印を書いた buffer の、data の message に当たる slice を返す。message は buffer の先頭から
// 始まり、容量は buffer の末尾までである(wireguard-go の Seal と同じ形)。
func tagged(l *sendLedger, seq uint64) []byte {
	buf := make([]byte, testBuf)
	l.writeTag(buf, seq)
	binary.LittleEndian.PutUint32(buf, transportType)
	return buf[:keepaliveSize+1]
}

func TestSendBatchInit(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  SendBatch
		mtu  int
		on   bool
		keff int
	}{
		{"zero value", SendBatch{}, 1420, false, 0},
		{"P_max 0", SendBatch{Packets: 0, Size: 32, Callers: 14, BufferSize: 65535}, 1420, false, 0},
		{"k_tx 1", SendBatch{Packets: 1000, Size: 1, Callers: 14, BufferSize: 65535}, 1420, false, 0},
		{"k_eff below 2", SendBatch{Packets: 4*13 - 1, Size: 32, Callers: 14, BufferSize: 65535}, 1420, false, 0},
		{"k_eff exactly 2", SendBatch{Packets: 4 * 13, Size: 32, Callers: 14, BufferSize: 65535}, 1420, true, 2},
		{"default Linux", SendBatch{Packets: 864, Size: 32, Callers: 14, BufferSize: 65535}, 1420, true, 32},
		{"many CPUs", SendBatch{Packets: 864, Size: 32, Callers: 70, BufferSize: 65535}, 1420, true, 6},
		{"k_tx above 128", SendBatch{Packets: 1 << 20, Size: 1000, Callers: 14, BufferSize: 65535}, 1420, true, 128},
		// Windows の 2,016 byte の buffer では 32 + MTU + 15 ≤ 2000 で、MTU が 1,953 以下なら印を書ける
		{"Windows MTU 1953", SendBatch{Packets: 40000, Size: 32, Callers: 14, BufferSize: 2016}, 1953, true, 32},
		{"Windows MTU 1954", SendBatch{Packets: 40000, Size: 32, Callers: 14, BufferSize: 2016}, 1954, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var l sendLedger
			l.init(tc.cfg, tc.mtu)
			if l.on != tc.on {
				t.Fatalf("on = %v, want %v", l.on, tc.on)
			}
			if !l.on {
				if l.size != 1 {
					t.Fatalf("BatchSize %d with batching off, want 1", l.size)
				}
				return
			}
			if l.keff != tc.keff {
				t.Fatalf("k_eff = %d, want %d", l.keff, tc.keff)
			}
			if want := int64(tc.cfg.Callers-1) * int64(tc.keff); l.reserve != want {
				t.Fatalf("R = %d, want %d", l.reserve, want)
			}
			if 2*l.reserve > l.pmax {
				t.Fatalf("R %d is more than half of P_max %d", l.reserve, l.pmax)
			}
			if len(l.rows) != tc.cfg.Packets/2 {
				t.Fatalf("ring of %d rows, want %d", len(l.rows), tc.cfg.Packets/2)
			}
			if l.next != 1 || l.issued.Load() != 0 || l.acked.Load() != 0 || l.pending.Load() != 0 || l.held != 0 {
				t.Fatalf("initial values s %d issued %d W %d pending %d held %d", l.next, l.issued.Load(), l.acked.Load(), l.pending.Load(), l.held)
			}
		})
	}
}

// Read が buffer ごとに確かめる印を書ける条件は、offset + MTU + 詰め物 + 認証の tag ≤ 長さ - 16 の境で
// 切り替わる。
func TestSendBatchFitsBoundary(t *testing.T) {
	l := newTestLedger(t, 864, 32, 14)
	const offset = 16
	edge := offset + l.mtu + sealOverhead + tagSize
	if !l.fits(make([]byte, edge), offset) {
		t.Fatalf("a %d-byte buffer at offset %d must fit MTU %d", edge, offset, l.mtu)
	}
	if l.fits(make([]byte, edge-1), offset) {
		t.Fatalf("a %d-byte buffer at offset %d must not fit MTU %d", edge-1, offset, l.mtu)
	}
	if l.fits(make([]byte, edge), -1) {
		t.Fatal("a negative offset must not fit")
	}
}

// 門は L + R + n ≤ P_max を守り、2 より小さければ 1 個だけを許す。
func TestSendBatchGate(t *testing.T) {
	// C = 3、k_tx = 8、P_max = 40:k_eff = min(8, 40/4) = 8、R = 16
	l := newTestLedger(t, 40, 8, 3)
	if got := l.limit(100); got != 8 {
		t.Fatalf("first limit %d, want k_eff 8", got)
	}
	if got := l.limit(5); got != 5 {
		t.Fatalf("limit with 5 buffers %d, want 5", got)
	}
	l.publish(l.commit(8)) // L = 8
	l.publish(l.commit(8)) // L = 16:残りは 40 - 16 - 16 = 8
	if got := l.limit(100); got != 8 {
		t.Fatalf("limit at L 16 = %d, want 8", got)
	}
	l.publish(l.commit(7)) // L = 23:残りは 1
	if got := l.limit(100); got != 1 {
		t.Fatalf("limit at L 23 = %d, want 1", got)
	}
	seq := l.commit(1) // 1 個の Read は台帳に足さない
	l.publish(seq)
	if l.held != 23 || l.count != 3 {
		t.Fatalf("a 1-packet Read changed the ledger: L %d rows %d", l.held, l.count)
	}
	if seq != 4 {
		t.Fatalf("seq of the 4th Read = %d, want 4", seq)
	}
	// W = 2 で最初の 2 行が外れ、L は 7 になる
	l.acked.Store(2)
	if got := l.limit(100); got != 8 || l.held != 7 || l.count != 1 {
		t.Fatalf("after W 2: limit %d L %d rows %d, want 8, 7, 1", got, l.held, l.count)
	}
	// W は 1 個の Read の番号でも進み、それより前の行を外す
	l.acked.Store(4)
	if got := l.limit(100); got != 8 || l.held != 0 || l.count != 0 {
		t.Fatalf("after W 4: limit %d L %d rows %d, want 8, 0, 0", got, l.held, l.count)
	}
}

// 輪が満杯なら行を足せないので 1 個だけを許す。R が 0 の C = 1 で、2 個の行だけで輪を埋める。
func TestSendBatchRingFull(t *testing.T) {
	l := newTestLedger(t, 9, 8, 1) // 輪は 4 行
	for range 4 {
		if got := l.limit(2); got != 2 {
			t.Fatalf("limit %d, want 2", got)
		}
		l.publish(l.commit(2))
	}
	if l.count != len(l.rows) {
		t.Fatalf("ring holds %d of %d rows", l.count, len(l.rows))
	}
	if got := l.limit(2); got != 1 {
		t.Fatalf("limit with a full ring = %d, want 1", got)
	}
	// 輪を回り込んでも行を正しく外す
	l.acked.Store(2)
	if got := l.limit(8); got != 5 || l.held != 4 || l.count != 2 {
		t.Fatalf("after W 2: limit %d L %d rows %d, want 5, 4, 2", got, l.held, l.count)
	}
	l.publish(l.commit(5)) // 輪の先頭に回り込む
	if got := l.limit(8); got != 1 || l.held != 9 {
		t.Fatalf("at L 9: limit %d L %d, want 1 and 9", got, l.held)
	}
	l.publish(l.commit(1))
	l.acked.Store(4)
	if got := l.limit(8); got != 4 || l.held != 5 || l.count != 1 || l.head != 0 {
		t.Fatalf("after W 4: limit %d L %d rows %d head %d, want 4, 5, 1, 0", got, l.held, l.count, l.head)
	}
	l.acked.Store(5)
	if got := l.limit(8); got != 8 || l.held != 0 || l.count != 0 {
		t.Fatalf("after W 5: limit %d L %d rows %d, want 8, 0, 0", got, l.held, l.count)
	}
}

// 知らせは 1 回遅れで、最初の data の Send は W を動かさない。data の message を持たない Send は手元の番号も
// W も変えない。
func TestSendBatchOneCallLag(t *testing.T) {
	l := newTestLedger(t, 864, 32, 14)
	s1 := l.commit(4)
	l.publish(s1)
	if s1 != 1 {
		t.Fatalf("first seq %d, want 1", s1)
	}
	l.observe([][]byte{tagged(l, s1), tagged(l, s1)})
	if l.acked.Load() != 0 || l.pending.Load() != 1 {
		t.Fatalf("after the first data Send: W %d pending %d, want 0 and 1", l.acked.Load(), l.pending.Load())
	}
	if l.limit(32); l.held != 4 {
		t.Fatalf("the first Read's row left before its container was sent: L %d", l.held)
	}
	// keepalive、ハンドシェイク、cookie、短い message だけの Send は何も変えない
	keepalive := make([]byte, keepaliveSize, testBuf)
	binary.LittleEndian.PutUint32(keepalive, transportType)
	handshake := tagged(l, s1)
	binary.LittleEndian.PutUint32(handshake, 1)
	cookie := tagged(l, s1)
	binary.LittleEndian.PutUint32(cookie, 3)
	l.observe([][]byte{keepalive})
	l.observe([][]byte{handshake})
	l.observe([][]byte{cookie, keepalive})
	l.observe(nil)
	if l.acked.Load() != 0 || l.pending.Load() != 1 {
		t.Fatalf("a Send with no data message changed W %d or pending %d", l.acked.Load(), l.pending.Load())
	}
	s2 := l.commit(1)
	l.publish(s2)
	l.observe([][]byte{tagged(l, s2)})
	if l.acked.Load() != 1 || l.pending.Load() != 2 {
		t.Fatalf("after the second data Send: W %d pending %d, want 1 and 2", l.acked.Load(), l.pending.Load())
	}
	if l.limit(32); l.held != 0 {
		t.Fatalf("row of seq 1 stayed after W 1: L %d", l.held)
	}
	// 有効な印を持たない data の Send も、前の番号を知らせる
	stale := make([]byte, keepaliveSize+1, testBuf)
	binary.LittleEndian.PutUint32(stale, transportType)
	l.observe([][]byte{stale})
	if l.acked.Load() != 2 || l.pending.Load() != 0 {
		t.Fatalf("a data Send with no valid tag: W %d pending %d, want 2 and 0", l.acked.Load(), l.pending.Load())
	}
}

// 番号は入れ物の中の最大を使い、古い印で W は減らない。
func TestSendBatchMaxAndMonotone(t *testing.T) {
	l := newTestLedger(t, 864, 32, 14)
	for range 9 {
		l.publish(l.commit(2))
	}
	l.observe([][]byte{tagged(l, 3), tagged(l, 7), tagged(l, 5)})
	l.observe([][]byte{tagged(l, 2)}) // 古い印:7 を知らせ、手元は 2
	if l.acked.Load() != 7 {
		t.Fatalf("W %d, want 7", l.acked.Load())
	}
	l.observe([][]byte{tagged(l, 9)}) // 手元の 2 を知らせても W は 7 のまま
	if l.acked.Load() != 7 || l.pending.Load() != 9 {
		t.Fatalf("W %d pending %d, want 7 and 9", l.acked.Load(), l.pending.Load())
	}
}

// 偽の印、最後に出した番号より大きい印、末尾に余地の無い message は使わない。
func TestSendBatchForgedTags(t *testing.T) {
	l := newTestLedger(t, 864, 32, 14)
	l.publish(l.commit(2))
	l.publish(l.commit(2)) // issued = 2
	other := newTestLedger(t, 864, 32, 14)
	if other.key == l.key {
		t.Fatal("two devices drew the same tag key")
	}
	ahead := tagged(l, 3) // 正しい鍵の、まだ出していない番号
	foreign := tagged(other, 2)
	flipped := tagged(l, 2)
	flipped[:cap(flipped)][testBuf-1] ^= 1
	zero := tagged(l, 0)
	// 容量が長さより 16 byte 以上大きくない message は、印の位置が message に重なる
	full := tagged(l, 2)
	full = full[:cap(full)-tagSize+1]
	for _, tc := range []struct {
		name string
		msg  []byte
	}{{"seq ahead of issued", ahead}, {"another device's key", foreign}, {"bad check value", flipped}, {"seq 0", zero}, {"no room for a tag", full}} {
		if got := l.readTag(tc.msg); got != 0 && tc.name != "seq ahead of issued" {
			t.Errorf("%s: readTag = %d, want 0", tc.name, got)
		}
		l.observe([][]byte{tc.msg})
		l.observe([][]byte{tc.msg})
		if l.acked.Load() != 0 || l.pending.Load() != 0 {
			t.Fatalf("%s moved W %d or pending %d", tc.name, l.acked.Load(), l.pending.Load())
		}
	}
	// 本物の印は同じ列の中でも使う
	l.observe([][]byte{ahead, foreign, tagged(l, 2), flipped})
	l.observe([][]byte{full})
	if l.acked.Load() != 2 {
		t.Fatalf("W %d, want 2", l.acked.Load())
	}
}

// 送信の goroutine が入れ替わっても手元の番号は引き継がれ、新しい goroutine の最初の data の Send で知らせる。
func TestSendBatchSenderRestartHandoff(t *testing.T) {
	l := newTestLedger(t, 864, 32, 14)
	for range 3 {
		l.publish(l.commit(4))
	}
	done := make(chan struct{})
	go func() { // 古い送信の goroutine
		defer close(done)
		l.observe([][]byte{tagged(l, 1)})
		l.observe([][]byte{tagged(l, 2)})
	}()
	<-done // peer.Stop は古い goroutine の終了を待ってから新しい goroutine を始める
	if l.acked.Load() != 1 || l.pending.Load() != 2 {
		t.Fatalf("old sender left W %d pending %d", l.acked.Load(), l.pending.Load())
	}
	done = make(chan struct{})
	go func() {
		defer close(done)
		l.observe([][]byte{tagged(l, 3)})
	}()
	<-done
	if l.acked.Load() != 2 {
		t.Fatalf("new sender's first data Send left W at %d, want the old sender's 2", l.acked.Load())
	}
}

// pipelineModel は wireguard-go の送信の経路の、上界の主張が頼る部分の模型である(wgstack-batching.md の
// 「同期が上界を崩さないこと」)。staged のキューは先頭から取り出し、満杯なら先頭を捨てる。SendStagedPackets
// の呼び出しは C 個で、1 つが持つ入れ物は 1 つ。送信のキューは順に 1 つの送信の goroutine が取り出し、Send
// を見る層を通して送り、Send から戻った後に buffer を返す。ピアの停止は送らずに捨て、ハンドシェイクを
// 諦めると staged のキューを捨てる。どの段の順も乱数で選び、本当に持たれている 2 個以上の入れ物の buffer の
// 数が P_max を超えないことを毎段で確かめる。
type pipelineModel struct {
	l          *sendLedger
	rng        *rand.Rand
	stagedCap  int
	outCap     int
	staged     []*modelContainer
	callers    []*modelContainer // 呼び出しごとに持つ入れ物。nil は持たない。0 番は TUN の読み取り
	callerBusy []bool
	out        []*modelContainer
	sending    *modelContainer // Send の中か、Send から戻って buffer を返す前
	running    bool
	keypair    bool
	stalled    bool                       // 送信の goroutine が Send から戻らない(遅い UDP の送信)
	pushed     map[uint64]*modelContainer // 送信のキューに入れた入れ物
	held       int64                      // 本当に持たれている 2 個以上の入れ物の buffer
	maxHeld    int64
	reads      int
	multi      int
}

type modelContainer struct {
	msgs []([]byte)
	n    int
	seq  uint64
	// older は、この入れ物を送信のキューに入れた時点でほかの呼び出しが持っていた入れ物の番号である
	older map[uint64]bool
}

func (m *pipelineModel) free(c *modelContainer) {
	if c.n >= 2 {
		m.held -= int64(c.n)
	}
}

// read は TUN の読み取りの 1 回で、Read、StagePackets を行い、続けて SendStagedPackets の呼び出しになる。
func (m *pipelineModel) read() {
	l := m.l
	n := l.limit(l.size)
	if n > 1 && m.rng.IntN(2) == 0 {
		n = 1 + m.rng.IntN(n) // 送るものが尽きて少なく返す Read を混ぜる
	}
	seq := l.commit(n)
	c := &modelContainer{n: n, seq: seq}
	for range n {
		c.msgs = append(c.msgs, tagged(l, seq))
	}
	l.publish(seq)
	if n >= 2 {
		m.held += int64(n)
		m.multi++
	}
	m.reads++
	m.stage(c)
	m.callerBusy[0] = true
}

func (m *pipelineModel) stage(c *modelContainer) {
	if len(m.staged) == m.stagedCap {
		m.free(m.staged[0])
		m.staged = m.staged[1:]
	}
	m.staged = append(m.staged, c)
}

// keepalive はタイマーが keepalive の入れ物を staged のキューに入れる。
func (m *pipelineModel) keepalive() {
	buf := make([]byte, keepaliveSize, testBuf)
	binary.LittleEndian.PutUint32(buf, transportType)
	m.stage(&modelContainer{msgs: [][]byte{buf}, n: 1})
}

// callerStep は呼び出し i の 1 段を進める。
func (m *pipelineModel) callerStep(i int) {
	if c := m.callers[i]; c != nil {
		if !m.running {
			m.free(c)
			m.callers[i] = nil
			return
		}
		if len(m.out) == m.outCap {
			return // 送信のキューの空きを待つ
		}
		c.older = map[uint64]bool{}
		for j, o := range m.callers {
			if j != i && o != nil {
				c.older[o.seq] = true
			}
		}
		m.pushed[c.seq] = c
		m.out = append(m.out, c)
		m.callers[i] = nil
		return
	}
	if !m.callerBusy[i] {
		m.callerBusy[i] = true // 呼び出しを始める
		return
	}
	if len(m.staged) == 0 || !m.keypair {
		m.callerBusy[i] = false
		return
	}
	m.callers[i] = m.staged[0]
	m.staged = m.staged[1:]
}

func (m *pipelineModel) senderStep() {
	if m.stalled {
		return
	}
	if c := m.sending; c != nil {
		m.free(c) // Send から戻った後に buffer を返す
		m.sending = nil
		return
	}
	if len(m.out) == 0 {
		return
	}
	c := m.out[0]
	m.out = m.out[1:]
	if !m.running {
		m.free(c)
		return
	}
	m.l.observe(c.msgs)
	m.sending = c
}

func (m *pipelineModel) step() {
	switch r := m.rng.IntN(100); {
	case r < 20:
		if !m.callerBusy[0] && m.callers[0] == nil {
			m.read()
		} else {
			m.callerStep(0)
		}
	case r < 60:
		m.callerStep(m.rng.IntN(len(m.callers)))
	case r < 90:
		m.senderStep()
	case r < 93:
		m.keepalive()
	case r < 95: // ハンドシェイクを諦めて staged のキューを捨てる(FlushStagedPackets)
		for _, c := range m.staged {
			m.free(c)
		}
		m.staged = m.staged[:0]
	case r < 97:
		m.keypair = !m.keypair
	case r < 99:
		if m.sending == nil {
			m.running = !m.running // ピアの停止と開始。送信の goroutine は Send の外で入れ替わる
		}
	default:
		m.stalled = !m.stalled // 送信が詰まると、キューが埋まるまで Read と呼び出しが進む
	}
	m.maxHeld = max(m.maxHeld, m.held)
}

func runPipelineModel(t *testing.T, seed uint64, pmax, size, callers, stagedCap, outCap, steps int) *pipelineModel {
	t.Helper()
	m := &pipelineModel{
		l:          newTestLedger(t, pmax, size, callers),
		rng:        rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
		stagedCap:  stagedCap,
		outCap:     outCap,
		callers:    make([]*modelContainer, callers),
		callerBusy: make([]bool, callers),
		running:    true,
		keypair:    true,
		pushed:     map[uint64]*modelContainer{},
	}
	for range steps {
		m.step()
		if m.held > int64(pmax) {
			t.Fatalf("seed %d: %d buffers held in multi-packet containers, P_max %d; L %d R %d W %d", seed, m.held, pmax, m.l.held, m.l.reserve, m.l.acked.Load())
		}
		if err := m.checkClaim(); err != "" {
			t.Fatalf("seed %d: %s", seed, err)
		}
	}
	return m
}

// checkClaim は上界の主張の形を確かめる(wgstack-batching.md の「同期が上界を崩さないこと」)。持たれている
// 2 個以上の入れ物のうち、番号が W より後のものは台帳の行にある。W 以下のものは、番号 W の入れ物が送信の
// キューに入った時点で別の呼び出しが持っていたものだけなので、staged のキューには無く、C - 1 個以下で、
// buffer は R 以下である。その後に送信のキューへ移っても、送信の goroutine が送る途中でも数える。
func (m *pipelineModel) checkClaim() string {
	l := m.l
	w := l.acked.Load()
	rows := map[uint64]bool{}
	for i := range l.count {
		rows[l.rows[(l.head+i)%len(l.rows)].seq] = true
	}
	var old, oldBufs int64
	check := func(where string, c *modelContainer, staged bool) string {
		if c == nil || c.n < 2 {
			return ""
		}
		if c.seq > w {
			if !rows[c.seq] {
				return fmt.Sprintf("held container %d after W %d %s has no ledger row", c.seq, w, where)
			}
			return ""
		}
		if staged {
			return fmt.Sprintf("container %d at or before W %d is still in the staged queue", c.seq, w)
		}
		if wc := m.pushed[w]; wc != nil && !wc.older[c.seq] {
			return fmt.Sprintf("container %d at or before W %d is held %s, but no other caller held it when container %d was queued", c.seq, w, where, w)
		}
		old++
		oldBufs += int64(c.n)
		return ""
	}
	for _, c := range m.staged {
		if e := check("in the staged queue", c, true); e != "" {
			return e
		}
	}
	for _, c := range m.out {
		if e := check("in the outbound queue", c, false); e != "" {
			return e
		}
	}
	if e := check("by the sender", m.sending, false); e != "" {
		return e
	}
	for _, c := range m.callers {
		if e := check("by a caller", c, false); e != "" {
			return e
		}
	}
	if old > int64(len(m.callers)-1) || oldBufs > l.reserve {
		return fmt.Sprintf("%d containers with %d buffers at or before W %d are held, over C - 1 = %d or R = %d", old, oldBufs, w, len(m.callers)-1, l.reserve)
	}
	return ""
}

func TestSendBatchPipelineModelNeverExceedsBudget(t *testing.T) {
	seeds := 200
	if testing.Short() {
		seeds = 40
	}
	for seed := range uint64(seeds) {
		// 小さな予算で門を何度も閉じ、回り込みと漏れの回復を多く起こす
		m := runPipelineModel(t, seed, 4*3*4, 4, 4, 12, 6, 20000)
		if m.multi == 0 {
			t.Fatalf("seed %d: no multi-packet Read in %d Reads", seed, m.reads)
		}
	}
	// 既定に近い大きさ
	for seed := range uint64(seeds / 10) {
		runPipelineModel(t, 1000+seed, 864, 32, 14, 128, 64, 20000)
	}
}

// 送り続ければ、漏れの後も件数が戻る。staged のキューを溢れさせ、鍵の無い間に台帳を埋めてから、鍵を戻して
// 流す。
func TestSendBatchRecoversAfterLeaks(t *testing.T) {
	m := &pipelineModel{
		l:          newTestLedger(t, 48, 4, 4),
		rng:        rand.New(rand.NewPCG(7, 7)),
		stagedCap:  6,
		outCap:     3,
		callers:    make([]*modelContainer, 4),
		callerBusy: make([]bool, 4),
		running:    true,
		pushed:     map[uint64]*modelContainer{},
	}
	// 鍵の無い間は staged のキューに溜まり、溢れた分は捨てる。台帳は外れないので門が閉じる
	for range 100 {
		m.read()
		m.callerBusy[0] = false
	}
	if got := m.l.limit(4); got != 1 {
		t.Fatalf("gate open %d with no Send for 100 Reads; L %d", got, m.l.held)
	}
	m.keypair = true
	sawBatch := false
	for range 2000 {
		m.step()
		if m.held > 48 {
			t.Fatalf("held %d over P_max 48", m.held)
		}
		if m.l.limit(4) >= 2 {
			sawBatch = true
		}
	}
	if !sawBatch {
		t.Fatalf("gate never reopened after the leaks; L %d W %d issued %d", m.l.held, m.l.acked.Load(), m.l.issued.Load())
	}
}

// Read の経路は packet ごとに確保しない(wgstack-batching.md の「確保しない計画」)。UDP の datagram を k_tx 個
// 作る Read と、Send を見る層の 2 回を数える。datagram を書く WriteTo も確保しない。
func TestSendBatchReadAllocs(t *testing.T) {
	const k = 32
	n := newTestNet(t, smallLimits())
	d := n.d
	d.s.txb = sendLedger{}
	d.s.txb.init(SendBatch{Packets: 1 << 14, Size: k, Callers: 14, BufferSize: 65535}, d.s.mtu)
	if !d.Batching() || d.BatchSize() != k {
		t.Fatalf("Batching %v BatchSize %d", d.Batching(), d.BatchSize())
	}
	pc, err := d.ListenUDP(netip.AddrPortFrom(dutAddr, 5000))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerAddr, 6000))
	bufs := make([][]byte, k)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, k)
	payload := make([]byte, 100)
	msgs := make([][]byte, k)
	round := func() {
		for range k {
			if _, err := pc.WriteTo(payload, to); err != nil {
				panic(err)
			}
		}
		got, err := d.Read(bufs, sizes, 16)
		if err != nil || got != k {
			panic(fmt.Sprintf("Read = %d, %v; want %d packets", got, err, k))
		}
		for i := range got {
			binary.LittleEndian.PutUint32(bufs[i], transportType)
			msgs[i] = bufs[i][:keepaliveSize+1]
		}
		d.ObserveSend(msgs)
		d.ObserveSend(msgs)
	}
	round()
	if allocs := testing.AllocsPerRun(100, round); allocs != 0 {
		t.Fatalf("%.1f allocations per round of %d WriteTo, one Read of %d packets and two Send observations, want 0", allocs, k, k)
	}
}

// 確立した接続の data の segment を k_tx 個まで作る Read も確保しない。相手の ACK は使い回す buffer に作る。
func TestSendBatchReadAllocsTCP(t *testing.T) {
	const k = 32
	n := newTestNet(t, smallLimits())
	d := n.d
	d.s.txb = sendLedger{}
	d.s.txb.init(SendBatch{Packets: 1 << 14, Size: k, Callers: 14, BufferSize: 65535}, d.s.mtu)
	c, p := n.accepted(false, false)
	bufs := make([][]byte, k)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, k)
	chunk := make([]byte, k*1380)
	ackBuf := make([]byte, 128)
	in := [][]byte{nil}
	var sent int
	round := func() {
		if _, err := c.Write(chunk); err != nil {
			panic(err)
		}
		got, err := d.Read(bufs, sizes, 16)
		if err != nil || got < 1 {
			panic(fmt.Sprintf("Read = %d, %v", got, err))
		}
		for i := range got {
			sent += sizes[i] - ipHeaderLen - tcpHeaderLen
		}
		var o optWriter
		h := tcpHeader{tup: tuple{laddr: addrBits(peerAddr), raddr: addrBits(dutAddr), lport: p.sport, rport: p.dport},
			seq: p.snd, ack: p.rcv + uint32(sent), flags: flagACK, wnd: 65535}
		writeTCP(ackBuf, 1, h, &o, 0)
		in[0] = ackBuf[:finishTCP(ackBuf)]
		if _, err := d.Write(in, 0); err != nil {
			panic(err)
		}
		n.clk.Advance(time.Millisecond)
	}
	for range 50 { // 輻輳の窓を k_tx より大きくする
		round()
	}
	before := sent
	allocs := testing.AllocsPerRun(100, round)
	if per := (sent - before) / 101 / 1380; per < k/2 {
		t.Fatalf("only %d segments per Read; the window did not open", per)
	}
	if allocs != 0 {
		t.Fatalf("%.1f allocations per round of one Write, one Read of up to %d segments and one ACK, want 0", allocs, k)
	}
}

// Read は印を書いた番号を戻る前に出すので、Send を見る層はその Read の入れ物の印をすぐ使える。
func TestSendBatchReadPublishesItsSeq(t *testing.T) {
	const k = 8
	n := newTestNet(t, smallLimits())
	d := n.d
	d.s.txb = sendLedger{}
	d.s.txb.init(SendBatch{Packets: 1 << 10, Size: k, Callers: 3, BufferSize: 65535}, d.s.mtu)
	pc, err := d.ListenUDP(netip.AddrPortFrom(dutAddr, 5000))
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerAddr, 6000))
	bufs := make([][]byte, k)
	for i := range bufs {
		bufs[i] = make([]byte, 65535)
	}
	sizes := make([]int, k)
	for round := uint64(1); round <= 3; round++ {
		for range k {
			if _, err := pc.WriteTo(make([]byte, 100), to); err != nil {
				t.Fatal(err)
			}
		}
		got, err := d.Read(bufs, sizes, 16)
		if err != nil || got != k {
			t.Fatalf("Read = %d, %v", got, err)
		}
		msgs := make([][]byte, got)
		for i := range got {
			if seq := binary.LittleEndian.Uint64(bufs[i][len(bufs[i])-tagSize:]); seq != round {
				t.Fatalf("Read %d tagged buffer %d with seq %d", round, i, seq)
			}
			binary.LittleEndian.PutUint32(bufs[i], transportType)
			msgs[i] = bufs[i][:keepaliveSize+1]
		}
		if issued := d.s.txb.issued.Load(); issued != round {
			t.Fatalf("issued %d after Read %d", issued, round)
		}
		d.ObserveSend(msgs)
		if p := d.s.txb.pending.Load(); p != round {
			t.Fatalf("pending %d after the Send of Read %d", p, round)
		}
	}
}

// Read の約束(wgstack-batching.md の「Device の約束」と「印を書ける条件」)を Device の Read で確かめる。
// 件数は min(len(bufs), len(sizes), k_eff) と作れる packet の数で決まり、印の余地の無い後の buffer の手前で
// 止まり、最初の buffer に余地が無ければ印を書かずに 1 個だけ作る。台帳の L は返した個数だけ増える。
func TestSendBatchReadContract(t *testing.T) {
	const k = 8
	for _, tc := range []struct {
		name      string
		queued    int // 送る UDP の datagram の数
		nbufs     int
		nsizes    int
		short     int // 印の余地より 1 byte 短い buffer の位置。-1 は無し
		want      int
		wantTag   bool
		wantHeldL int64
	}{
		{"full batch", k, k, k, -1, k, true, k},
		{"fewer packets than the limit", 5, k, k, -1, 5, true, 5},
		{"short later buffer", k, k, k, 3, 3, true, 3},
		{"short first buffer", k, k, k, 0, 1, false, 0},
		{"fewer sizes than buffers", k, k, 3, -1, 3, true, 3},
		{"one packet", 1, k, k, -1, 1, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n := newTestNet(t, smallLimits())
			d := n.d
			d.s.txb = sendLedger{}
			d.s.txb.init(SendBatch{Packets: 1 << 10, Size: k, Callers: 3, BufferSize: 65535}, d.s.mtu)
			if !d.Batching() {
				t.Fatal("batching is off")
			}
			pc := listenUDP(t, n, 5000)
			to := net.UDPAddrFromAddrPort(netip.AddrPortFrom(peerAddr, 6000))
			for range tc.queued {
				if _, err := pc.WriteTo(make([]byte, 100), to); err != nil {
					t.Fatal(err)
				}
			}
			const offset = 16
			edge := offset + d.s.mtu + sealOverhead + tagSize
			bufs := make([][]byte, tc.nbufs)
			for i := range bufs {
				size := 65535
				if i == tc.short {
					size = edge - 1
				}
				bufs[i] = make([]byte, size)
			}
			sizes := make([]int, tc.nsizes)
			got, err := d.Read(bufs, sizes, offset)
			if err != nil || got != tc.want {
				t.Fatalf("Read = %d, %v; want %d packets", got, err, tc.want)
			}
			for i := range got {
				if sizes[i] == 0 {
					t.Fatalf("sizes[%d] is 0", i)
				}
				tail := bufs[i][len(bufs[i])-tagSize:]
				seq := binary.LittleEndian.Uint64(tail)
				if tc.wantTag && seq != 1 {
					t.Fatalf("buffer %d carries seq %d, want 1", i, seq)
				}
				if !tc.wantTag && (seq != 0 || binary.LittleEndian.Uint64(tail[8:]) != 0) {
					t.Fatalf("buffer %d without room for the tag carries one", i)
				}
			}
			l := &d.s.txb
			if l.held != tc.wantHeldL {
				t.Fatalf("L = %d after a Read of %d packets, want %d", l.held, got, tc.wantHeldL)
			}
			wantIssued := uint64(0)
			if tc.wantTag {
				wantIssued = 1
			}
			if l.issued.Load() != wantIssued {
				t.Fatalf("issued %d, want %d", l.issued.Load(), wantIssued)
			}
		})
	}
}

// UDP の送信の予約の空きを待つ書き手は、Read が datagram を送って予約を返すと起き、期限を変えても起きる。
// 待つ書き手がいなければ channel を作り直さない(wakeTx)。
func TestUDPBlockedWriterWakes(t *testing.T) {
	n := newTestNet(t, smallLimits())
	pc := listenUDP(t, n, 53)
	to := net.UDPAddrFromAddrPort(peerUDP)
	for range udpTxDatagrams / udpEndpointShare {
		if _, err := pc.WriteTo(make([]byte, 10), to); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() {
		_, err := pc.WriteTo(make([]byte, 10), to)
		done <- err
	}()
	waitWaited := func() {
		for i := 0; ; i++ {
			n.d.s.udp.mu.Lock()
			w := n.d.s.udp.txWaited
			n.d.s.udp.mu.Unlock()
			if w {
				return
			}
			if i > 2000 {
				t.Fatal("the writer did not wait for space")
			}
			time.Sleep(time.Millisecond)
		}
	}
	waitWaited()
	if n.d.Poll(n.buf) == 0 {
		t.Fatal("nothing to send")
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WriteTo after the space returned: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the writer was not woken when a reservation returned")
	}
	// 起こした後は待つ書き手がいないので、次に予約を返しても channel を作り直さない
	n.d.s.udp.mu.Lock()
	waited, space := n.d.s.udp.txWaited, n.d.s.udp.txSpace
	n.d.s.udp.mu.Unlock()
	if waited {
		t.Fatal("txWaited is still set after the waiting writer was woken")
	}
	if n.d.Poll(n.buf) == 0 {
		t.Fatal("nothing to send after the woken write")
	}
	n.d.s.udp.mu.Lock()
	same := n.d.s.udp.txSpace == space
	n.d.s.udp.mu.Unlock()
	if !same {
		t.Fatal("a returned reservation recreated the wake channel with no writer waiting")
	}
	// 返した予約を埋め直し、次の書き手がまた空きを待つようにする
	if _, err := pc.WriteTo(make([]byte, 10), to); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, err := pc.WriteTo(make([]byte, 10), to)
		done <- err
	}()
	waitWaited()
	pc.SetWriteDeadline(time.Now().Add(-time.Second))
	select {
	case err := <-done:
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("WriteTo after the deadline passed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the writer was not woken by the deadline change")
	}
}

// 受ける向きの速い経路も確保しない(wgstack-batching.md の「確保しない計画」)。確立した接続への順序どおりの data
// の segment を 1 回の Write に 1 個ずつ渡し、Poll で ACK を作り、アプリケーションが Conn.Read で読む。相手の
// segment は測る前に作る。どの回も ACK を少なくとも 1 つ作ることも確かめる。
func TestReceiveFastPathAllocs(t *testing.T) {
	const perRound, rounds = 8, 120
	n := newTestNet(t, smallLimits())
	d := n.d
	c, p := n.accepted(true, true)
	payload := make([]byte, 1368)
	pkts := make([][][]byte, rounds)
	for j := range pkts {
		pkts[j] = make([][]byte, perRound)
		for i := range pkts[j] {
			pkts[j][i] = buildPeer(p.seg(flagACK, payload))
			p.snd += uint32(len(payload))
		}
	}
	out := make([]byte, 65535)
	rd := make([]byte, perRound*len(payload))
	in := [][]byte{nil}
	acks, j := 0, 0
	round := func() {
		for _, pkt := range pkts[j] {
			in[0] = pkt
			if _, err := d.Write(in, 0); err != nil {
				panic(err)
			}
		}
		j++
		for d.Poll(out) > 0 {
			acks++
		}
		for read := 0; read < len(rd); {
			m, err := c.Read(rd[read:])
			if err != nil {
				panic(err)
			}
			read += m
		}
	}
	round()
	allocs := testing.AllocsPerRun(rounds-2, round)
	if acks < rounds {
		t.Fatalf("the receiver sent %d ACKs over %d rounds, want at least one a round", acks, rounds)
	}
	if allocs != 0 {
		t.Fatalf("%.1f allocations per round of %d in-order segments, their ACKs and the application's reads, want 0", allocs, perRound)
	}
}
