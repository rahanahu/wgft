package nettun

// netstack の TCP の送信と受信のバッファの上限(設計文書 7 節の「netstack の TCP のバッファ」)。
// 全接続に小さな最低分(floor)を保証し、大きなバッファ(boost)はプロセスあたり同時に
// tcpBoostSlots 本までの枠で貸す。枠は接続を閉じて CLOSED か ERROR か TIME_WAIT に入った後に返し、
// 空きが無いときだけ、需要の無い保有者から回収して floor に戻す。どちらも取得の要求の
// ついでに調べ、タイマーと goroutine は持たない。

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// 値はどれも設定項目にしない(設計文書 7 節)。
const (
	tcpSendFloor  = 256 << 10 // 接続ごとに保証する送信のバッファ
	tcpRecvFloor  = 256 << 10 // 接続ごとに保証する受信のバッファ
	tcpBoostSize  = 4 << 20   // 枠を得た接続の送信と受信のバッファ
	tcpBoostSlots = 16        // プロセスあたりの枠の数

	// tcpDemandWindow の区間に tcpDemandBytes 以上を読めたか受け入れられた接続が枠を求める。
	tcpDemandWindow = 250 * time.Millisecond
	tcpDemandBytes  = 64 << 10
	// tcpIdleReclaim の間どちらの向きにも需要の無い保有者は、空きが無いときに回収できる。
	tcpIdleReclaim = time.Second

	// 送信のキューに残る書き込みの数の上限は、送信のバッファ tcpWriteUnit あたり 1 回。
	tcpWriteUnit = 1 << 10
	floorHist    = tcpSendFloor/tcpWriteUnit - 1 // floor で確かめる直前の書き込みの回数
	boostHist    = tcpBoostSize/tcpWriteUnit - 1 // boost で確かめる直前の書き込みの回数
)

// processTCPBoost は、プロセスのすべての Device が分け合う枠の集まり。
var processTCPBoost = newBoostPool(tcpBoostSlots)

// setTCPBufferRanges は、stack が TCP の endpoint を作る前に、送信と受信のバッファの範囲を
// 設定する。受信の上限を boost の大きさにするのは、握手のときの窓の scale を gVisor が受信の
// 上限から決めるためである。floor は握手の後に newTCPConn が固定する。
func setTCPBufferRanges(s *stack.Stack) error {
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcpSendFloor, Max: tcpSendFloor}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd); err != nil {
		return errors.New("could not set the TCP send buffer range: " + err.String())
	}
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcp.MinBufferSize, Default: tcpRecvFloor, Max: tcpBoostSize}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv); err != nil {
		return errors.New("could not set the TCP receive buffer range: " + err.String())
	}
	return nil
}

// boostPool は枠の集まり。slots は固定長で、nil が空きの枠である。1 本の接続が一時的に 2 つの
// 枠に載ることはあるが、枠の数そのものは len(slots) を超えない。
type boostPool struct {
	mu    sync.Mutex
	slots []*tcpConn

	// writeHook は、試験が書き込みの途中で止めるためのもの。製品では nil。
	writeHook func(*tcpConn)
	// recvMemHook は、試験が受信のメモリの読み取りを差し替えるためのもの。製品では nil。
	recvMemHook func(tcpip.Endpoint) (int, bool)
}

// recvMem は、gVisor の TCP endpoint が受信の segment に使っているメモリ(非公開の rcvMemUsed)の
// 位置である。gVisor はこの値を公開しない。回収で受信のバッファを縮めてよいかを決めるのに要る
// (demote を見よ)。名前と型は go.mod の固定の版のもので、起動時に endpoint の型から確かめる。
// 合わなければ ok は偽で、回収をしない。読むだけで書かない。
var recvMem = lookupRecvMem(reflect.TypeFor[tcp.Endpoint]())

type recvMemLayout struct {
	off uintptr
	ok  bool
}

// lookupRecvMem は、型 t の直下に atomicbitops.Int32 の rcvMemUsed があればその位置を返す。
func lookupRecvMem(t reflect.Type) recvMemLayout {
	f, ok := t.FieldByName("rcvMemUsed")
	if !ok || len(f.Index) != 1 || f.Type != reflect.TypeFor[atomicbitops.Int32]() {
		return recvMemLayout{}
	}
	return recvMemLayout{off: f.Offset, ok: true}
}

var recvMemWarn sync.Once

// receiveMemUsed は ep の rcvMemUsed を原子的に読む。gVisor はこの値を atomicbitops.Int32 の
// Load と Add だけで読み書きし、錠を使わないので、同じ Load で競合なく読める。
func (p *boostPool) receiveMemUsed(ep tcpip.Endpoint) (int, bool) {
	if h := p.recvMemHook; h != nil {
		return h(ep)
	}
	e, ok := ep.(*tcp.Endpoint)
	if !ok || !recvMem.ok {
		recvMemWarn.Do(func() {
			logf("tcp buffers: the gVisor endpoint does not have the layout this build expects, so idle boost holders are not reclaimed")
		})
		return 0, false
	}
	return int((*atomicbitops.Int32)(unsafe.Add(unsafe.Pointer(e), recvMem.off)).Load()), true
}

func newBoostPool(q int) *boostPool {
	return &boostPool{slots: make([]*tcpConn, q)}
}

// acquire は c に枠を 1 つ貸す。空きがあればそれを使う。無ければ枠の写しを取り、返せる枠を
// すべて空け、その 1 つを c に渡す。返せる枠も無ければ、需要の無い保有者から 1 つ回収する。
// endpoint の操作は枠の排他の外で行う。
func (p *boostPool) acquire(c *tcpConn) bool {
	p.mu.Lock()
	if i := slices.Index(p.slots, nil); i >= 0 {
		p.slots[i] = c
		p.mu.Unlock()
		return true
	}
	snap := slices.Clone(p.slots)
	p.mu.Unlock()
	if p.takeReturnable(snap, c) {
		return true
	}
	return p.reclaimIdle(snap, c)
}

// takeReturnable は snap のうち返せる保有者の枠を空け、最初の 1 つを c に渡す。枠が写しを
// 取った後に変わっていれば(同じポインタでなければ)触らない。
func (p *boostPool) takeReturnable(snap []*tcpConn, c *tcpConn) bool {
	ret := make([]bool, len(snap))
	found := false
	for i, s := range snap {
		if s != nil && s.returnable() {
			ret[i], found = true, true
		}
	}
	if !found {
		return false
	}
	given := false
	p.mu.Lock()
	for i, s := range snap {
		if ret[i] && p.slots[i] == s {
			p.slots[i] = nil
			if !given && c != nil {
				p.slots[i] = c
				given = true
			}
		}
	}
	p.mu.Unlock()
	return given
}

// reclaimIdle は、空きも返せる枠も無いときだけ呼ばれる。tcpIdleReclaim の間需要の無い保有者を
// snap の順に試し、floor に戻せた最初の 1 本の枠を c に渡す。
func (p *boostPool) reclaimIdle(snap []*tcpConn, c *tcpConn) bool {
	now := time.Now()
	for _, s := range snap {
		if s == nil || s == c || !s.idleSince(now) || !s.demote(now) {
			continue
		}
		p.mu.Lock()
		i := slices.Index(p.slots, s)
		if i < 0 { // 別の要求が先に空けた
			i = slices.Index(p.slots, nil)
		}
		if i >= 0 {
			p.slots[i] = c
		}
		p.mu.Unlock()
		if i >= 0 {
			return true
		}
	}
	return false
}

// demandWindow は 1 つの向きの需要の区間。区間は入出力が成功したときに時計を読んで区切る。
type demandWindow struct {
	start time.Time
	n     int
	hit   bool
}

// add は now に n byte を記録し、この区間で初めて tcpDemandBytes に届いたときに真を返す。
func (d *demandWindow) add(now time.Time, n int) bool {
	if now.Sub(d.start) > tcpDemandWindow {
		d.start, d.n, d.hit = now, 0, false
	}
	d.n += n
	if d.n >= tcpDemandBytes && !d.hit {
		d.hit = true
		return true
	}
	return false
}

// writeHistory は、gVisor が受け入れた書き込みの長さを新しい順に持つ。長さだけを持ち、データは
// 持たない。ring の長さは、boost を持たない間は floorHist、boost の間は boostHist である。
// 広げた直後の覚えていない古い長さは 0 とする。和を小さく見積もるので、Write の確かめは
// 成り立ちにくくなる側にだけずれる。
type writeHistory struct {
	ring []uint32
	i    int   // 次に書く位置。ring[i] は len(ring) 回前の長さ
	n    int64 // 記録した書き込みの総数
	sumF int64 // 直前の floorHist 回の和
	sumB int64 // ring 全体の和
}

func (h *writeHistory) add(v int) {
	if h.ring == nil {
		h.ring = make([]uint32, floorHist)
	}
	m := len(h.ring)
	j := (h.i - floorHist + m) % m // floorHist 回前の長さの位置
	h.sumF += int64(v) - int64(h.ring[j])
	h.sumB += int64(v) - int64(h.ring[h.i])
	h.ring[h.i] = uint32(v)
	h.i = (h.i + 1) % m
	h.n++
}

// resize は ring を size 回分にし、新しい順に最大 floorHist 回分を移す。
func (h *writeHistory) resize(size int) {
	if len(h.ring) == size {
		return
	}
	if h.ring == nil {
		if size != floorHist { // floor の ring は最初の add が作る
			h.ring = make([]uint32, size)
		}
		return
	}
	m := len(h.ring)
	r := make([]uint32, size)
	for k := 0; k < floorHist; k++ { // 古い順
		r[k] = h.ring[(h.i-floorHist+k+m)%m]
	}
	h.ring, h.i, h.sumB = r, floorHist%size, h.sumF
}

// sum は、送信のバッファ s に対応する直前 s/tcpWriteUnit-1 回の長さの和と、それだけの回数を
// 記録済みかを返す。boost の和は ring を広げた後に呼ぶ。
func (h *writeHistory) sum(s int64) (int64, bool) {
	if s == tcpSendFloor {
		return h.sumF, h.n >= floorHist
	}
	return h.sumB, h.n >= boostHist
}

// tcpConn は、floor と boost の上限を守る netstack の TCP 接続。読み取り、ハーフクローズ、アドレス、
// 読み取りの期限は gonet.TCPConn に任せ、書き込みは書き込みの数の上限のために自分で行う。
//
// 接続の錠は wmu、cmu、rmu、dlmu で、枠の集まりの錠は boostPool.mu である。同じ接続の
// 中の順は wmu -> cmu で、逆には取らない。Write は書き込みの間ずっと wmu を持ち、その中の
// noteDemand が cmu を取る。rmu、dlmu、boostPool.mu は末端で、持ったまま他の錠を取らない。
// noteDemand は cmu を放してから acquire を呼ぶ。
//
// 2 つの接続の錠を同時に持つのは、枠を求める接続 X が空きの無いときに reclaimIdle から別の接続 S の
// demote を呼ぶ経路だけである。X が Write の中にいれば X.wmu を持ったままなので、demote は S.wmu を
// TryLock でだけ取り、取れなければ回収をやめる。2 つの書き手が互いを回収しようとしても待ち合わない。
// 順は X.wmu -> S.wmu(TryLock)-> S.cmu である。
//
// OnBoost で登録した関数 onBoost は、登録のときの 1 回も含めて cmu の中で呼ぶ。noteDemand から
// 呼ぶときは X.cmu を持ち、Write の中なら X.wmu も持つ。demote から呼ぶときは S.wmu と S.cmu を持ち、
// X が Write の中なら X.wmu も持つ。
// 今の登録元は netpipe.FollowBoost だけで、その関数は組にしたカーネルのソケットのオプションを
// RawConn.Control の中で読み書きするだけで、wgft の錠を取らない。
type tcpConn struct {
	gc   *gonet.TCPConn
	ep   tcpip.Endpoint
	wq   *waiter.Queue
	pool *boostPool

	cmu     sync.Mutex // バッファの設定と閉じ始めの短い排他
	closing bool
	sndShut bool // CloseWrite で送信の向きを閉じた
	// onBoost は OnBoost で登録した関数。枠を得たときと floor に戻るときに cmu の中で呼ぶ
	onBoost func(boosted bool) bool

	boosted    atomic.Bool
	acquiring  atomic.Bool  // 読み取りと書き込みが同時に枠を求めないため
	closed     atomic.Bool  // 最後の Close か Abort が戻った
	inflight   atomic.Int32 // 実行中の読み取りと書き込み
	lastDemand atomic.Int64 // 最後に需要の条件を満たした時刻(Unix ナノ秒)

	rmu  sync.Mutex
	rdem demandWindow

	wmu  sync.Mutex // 書き込みを直列にする。待つ間も持つ
	wdem demandWindow
	hist writeHistory

	dlmu      sync.Mutex
	wdl       time.Time
	wdlCh     chan struct{} // 書き込みの期限が変わると閉じる
	closeCh   chan struct{}
	closeOnce sync.Once
}

// TCPConn は ListenTCP の Accept と DialTCP が返す接続。拒む接続と中継が切る接続を、グレース
// フルクローズ(FIN の後、既定で 60 秒の tcp.DefaultTCPTimeWaitTimeout の TIME_WAIT)ではなく
// Abort(RST)で終えられる。relay パッケージでの Abort の使用と、GitHub issue #25、仕様 6.2 節と
// 7 節を見よ。
type TCPConn struct{ *tcpConn }

// Abort は RST を送り、Close が行うグレースフルシャットダウン(とその結果の TIME_WAIT)を
// 経ずに、接続の資源を即座に解放する。
func (c *TCPConn) Abort() { c.abort() }

// newTCPConn は握手を終えた endpoint に floor を固定して読み返し、接続を作る。固定すると gVisor の
// 自動調整が止まる。握手の間は自動調整を残すので、窓の scale は受信の上限(boost)から決まる。
// 呼び出し側は、最初の読み取りの前にこれを通す(gVisor は読み取りのときにだけ受信のバッファを
// 広げる)。失敗したら呼び出し側が endpoint を閉じる。
func newTCPConn(wq *waiter.Queue, ep tcpip.Endpoint, pool *boostPool) (*tcpConn, error) {
	so := ep.SocketOptions()
	so.SetReceiveBufferSize(tcpRecvFloor, true)
	so.SetSendBufferSize(tcpSendFloor, true)
	if so.GetReceiveBufferSize() != tcpRecvFloor || so.GetSendBufferSize() != tcpSendFloor {
		return nil, errors.New("could not set the TCP buffer floor")
	}
	return &tcpConn{
		gc:      gonet.NewTCPConn(wq, ep),
		ep:      ep,
		wq:      wq,
		pool:    pool,
		wdlCh:   make(chan struct{}),
		closeCh: make(chan struct{}),
	}, nil
}

// returnable は枠を返せるかを返す。最後の Close か Abort が戻り、読み取りと書き込みが実行中でなく、
// endpoint が CLOSED か ERROR、または TIME_WAIT で受信のキューが空のとき。固定版の gVisor は、
// 自分の FIN が確認されたときにだけ TIME_WAIT に入り(送った byte はすべて確認済み)、相手の FIN で
// 順序外の受信のキューを捨て、読み取りを閉じた後に届いたデータでは接続を中断する。受信のキューが
// 空という条件は、固定版の gVisor では Close が受信のキューを捨てるので常に成り立ち、試験で外しても
// 落ちない。gVisor の更新で Close の後に受信のデータが残るようになっても、枠を返した後にデータを
// 残さないために置いている。FIN_WAIT_2 は返さない。Close の前に届いた順序外の受信のデータが
// 残りうるためで、gVisor の期限の後に CLOSED になってから返す。
func (c *tcpConn) returnable() bool {
	if !c.closed.Load() || c.inflight.Load() != 0 {
		return false
	}
	switch tcp.EndpointState(c.ep.State()) {
	case tcp.StateClose, tcp.StateError:
		return true
	case tcp.StateTimeWait:
		n, err := c.ep.GetSockOptInt(tcpip.ReceiveQueueSizeOption)
		return err == nil && n == 0
	}
	return false
}

// idleSince は、tcpIdleReclaim の間どちらの向きにも需要が無かったかを返す。
func (c *tcpConn) idleSince(now time.Time) bool {
	return now.Sub(time.Unix(0, c.lastDemand.Load())) >= tcpIdleReclaim
}

// demote は需要の無い保有者を floor に戻せたかを返す。待たない。書き込みが実行中なら(wmu を
// 持っていれば)戻さない。書き込みは確かめと gVisor への書き込みの間に送信のバッファを設定するので、
// 並行して floor に戻すと、boost を返した接続に boost の大きさの送信のバッファが残りうる。
// wmu を持つ間は新しい書き込みがキューに入らない。受信は先にバッファを floor に縮め、その後に
// 受信のメモリが floor 以下であることを求める(下の段落)。送信は、キューに残る byte が floor と直前の
// floorHist 回の長さの和の小さい方より少ないことを、Write と同じ方法で確かめる。最後に、OnBoost で
// 登録した関数が floor への戻りを受け入れることを求める。どれかが成り立たなければ boost の大きさに
// 戻し、枠を持たせたままにする。
//
// 受信は、縮めた後に endpoint の受信のメモリ(順序外の segment と処理待ちの segment を含む)が
// floor 以下であることも求める。gVisor は、データのある segment を受信のメモリが受信のバッファ
// 以下のときだけ受け入れる(segment_queue.go の enqueue)。順序外が floor を超えたまま縮めると、
// 穴を埋める再送も受け入れず、接続が止まる。floor 以下なら、縮めた後に積める順序外は
// 「PendingBufUsed + 長さ < floor の 3/4」の分だけで(rcv.go)、処理待ちの segment が処理されれば
// 受信のメモリは floor 以下に戻り、穴を埋める segment は大きさによらず受け入れられる。
// 受信のメモリを読めないときは回収しない。送信の向きを閉じた保有者は
// 戻さない。固定版の gVisor の Readiness は、送信を閉じた endpoint を、キューにデータが残って
// いても書き込める状態と答えるので、送信の確かめが何も示さないためである。そのような保有者は、
// 返せる状態になるまで枠を持つ。CloseWrite は cmu の中で印を付けてから閉じるので、この確かめの
// 途中で送信の向きが閉じることはない。
func (c *tcpConn) demote(now time.Time) bool {
	if !c.wmu.TryLock() {
		return false
	}
	defer c.wmu.Unlock()
	c.cmu.Lock()
	defer c.cmu.Unlock()
	if c.closing || c.sndShut || !c.boosted.Load() || !c.idleSince(now) {
		return false
	}
	so := c.ep.SocketOptions()
	so.SetReceiveBufferSize(tcpRecvFloor, true)
	// 縮めた後に読む。縮める前に読むと、その間に古い大きさで受け入れた segment を見落とす。
	// このメモリは受信のキューの byte も含む
	if m, ok := c.pool.receiveMemUsed(c.ep); !ok || m > tcpRecvFloor {
		so.SetReceiveBufferSize(tcpBoostSize, true)
		return false
	}
	probe := int64(tcpSendFloor)
	if x, full := c.hist.sum(tcpSendFloor); full && x < probe {
		probe = x
	}
	so.SetSendBufferSize(probe, true)
	ready := c.ep.Readiness(waiter.WritableEvents)&waiter.WritableEvents != 0
	// 中継の組のカーネルのソケットも floor に戻せたときだけ枠を返す。カーネルのソケットが floor を
	// 超える受信のデータを持つ間は、戻せない(設計文書 7 節)
	if so.GetSendBufferSize() != probe || !ready || (c.onBoost != nil && !c.onBoost(false)) {
		so.SetSendBufferSize(tcpBoostSize, true)
		so.SetReceiveBufferSize(tcpBoostSize, true)
		return false
	}
	so.SetSendBufferSize(tcpSendFloor, true)
	c.hist.resize(floorHist)
	c.boosted.Store(false)
	return true
}

// noteDemand は、需要の条件を満たした時刻を記録し、boost を持たなければ枠を求める。
func (c *tcpConn) noteDemand(now time.Time) {
	c.lastDemand.Store(now.UnixNano())
	if c.boosted.Load() || !c.acquiring.CompareAndSwap(false, true) {
		return
	}
	defer c.acquiring.Store(false)
	c.cmu.Lock()
	skip := c.closing || c.boosted.Load()
	c.cmu.Unlock()
	if skip || !c.pool.acquire(c) {
		return
	}
	c.cmu.Lock()
	if !c.closing {
		c.ep.SocketOptions().SetReceiveBufferSize(tcpBoostSize, true)
		if c.onBoost != nil {
			c.onBoost(true)
		}
	}
	c.boosted.Store(true) // 送信のバッファは次の Write が広げる
	c.cmu.Unlock()
}

// OnBoost は、この接続が枠を得たときに f(true) を、需要の無い保有者として floor に戻るときに
// f(false) を呼ぶよう登録し、今の状態で 1 回呼ぶ。中継は、この接続と組にしたカーネルのソケットの
// 受信のバッファを枠に合わせるのに使う(設計文書 7 節)。floor に戻るときの f が偽を返すと、この接続は
// boost に戻って枠を持ち続け、次に別の接続が枠を求めたときに改めて試される。それ以外の f の値は
// 使わない。閉じた接続の枠を返す時機には呼ばない。そのとき接続は閉じているためである。f は接続の
// 排他の中で呼ぶので、待たずに戻り、この接続を呼ばないこと。
func (c *tcpConn) OnBoost(f func(boosted bool) bool) {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	c.onBoost = f
	f(c.boosted.Load())
}

func (c *tcpConn) Read(b []byte) (int, error) {
	c.inflight.Add(1)
	defer c.inflight.Add(-1)
	n, err := c.gc.Read(b)
	if n > 0 {
		now := time.Now()
		c.rmu.Lock()
		hit := c.rdem.add(now, n)
		c.rmu.Unlock()
		if hit {
			c.noteDemand(now)
		}
	}
	return n, err
}

func (c *tcpConn) opError(op string, err error) error {
	return &net.OpError{Op: op, Net: "tcp", Source: c.LocalAddr(), Addr: c.RemoteAddr(), Err: err}
}

func (c *tcpConn) writeDeadline() (time.Time, <-chan struct{}) {
	c.dlmu.Lock()
	defer c.dlmu.Unlock()
	return c.wdl, c.wdlCh
}

// SetWriteDeadline は net.Conn の実装。待っている書き込みは新しい期限で待ち直す。
func (c *tcpConn) SetWriteDeadline(t time.Time) error {
	c.dlmu.Lock()
	c.wdl = t
	close(c.wdlCh)
	c.wdlCh = make(chan struct{})
	c.dlmu.Unlock()
	return nil
}

func (c *tcpConn) SetReadDeadline(t time.Time) error { return c.gc.SetReadDeadline(t) }

func (c *tcpConn) SetDeadline(t time.Time) error {
	c.gc.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

// wait は ch が発火するか、書き込みの期限が過ぎるか変わるか、接続を閉じ始めるまで待つ。
func (c *tcpConn) wait(ch <-chan struct{}) error {
	dl, dch := c.writeDeadline()
	var tc <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return c.opError("write", os.ErrDeadlineExceeded)
		}
		t := time.NewTimer(d)
		defer t.Stop()
		tc = t.C
	}
	select {
	case <-ch:
	case <-dch:
	case <-tc:
		return c.opError("write", os.ErrDeadlineExceeded)
	case <-c.closeCh:
		// 固定版の gVisor は Close と Abort のときに書き込みの待ち手へ通知するので、closeCh が無くても
		// 待ちは解ける(試験で closeCh を外しても落ちない)。gVisor の通知に頼らずに解くために置く
		return c.opError("write", net.ErrClosed)
	}
	return nil
}

// Write は byte の上限 S と、確認されていない書き込みの数の上限 W = S/tcpWriteUnit を守る。
// gVisor に書く前に、キューに残る byte が直前 W-1 回に受け入れた長さの和 X より少ないことを
// 確かめる。キューは送った byte の列の末尾なので、それより前の書き込みはすべて確認済みで、
// 残る書き込みは今回を含めて W 回以内になる。確かめ方は、送信のバッファを X にし、書き込める
// 状態かを見て読み返し、成り立てば min(S, X+残り) に開いて 1 回だけ書くことである。記録が
// W-1 回に満たないか X >= S なら、確かめるまでもなく成り立つ。
func (c *tcpConn) Write(b []byte) (int, error) {
	c.inflight.Add(1)
	defer c.inflight.Add(-1)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if dl, _ := c.writeDeadline(); !dl.IsZero() && !time.Now().Before(dl) {
		return 0, c.opError("write", os.ErrDeadlineExceeded)
	}
	so := c.ep.SocketOptions()
	var (
		r       bytes.Reader
		total   int
		entry   waiter.Entry
		ch      <-chan struct{}
		retries int
	)
	// waitWritable は、初回は通知を登録するだけで戻り、状態を見直させる(登録の前の変化を逃さない)。
	waitWritable := func() error {
		if ch == nil {
			entry, ch = waiter.NewChannelEntry(waiter.WritableEvents)
			c.wq.EventRegister(&entry)
			return nil
		}
		return c.wait(ch)
	}
	defer func() {
		if ch != nil {
			c.wq.EventUnregister(&entry)
		}
	}()
	for total < len(b) {
		s := int64(tcpSendFloor)
		if c.boosted.Load() {
			s = tcpBoostSize
			c.hist.resize(boostHist)
		}
		if h := c.pool.writeHook; h != nil {
			h(c)
		}
		x, full := c.hist.sum(s)
		rest := int64(len(b) - total)
		if !full || x >= s {
			if so.GetSendBufferSize() != s {
				so.SetSendBufferSize(s, true)
			}
		} else {
			// 送信の向きを閉じた後は Readiness が常に書き込める状態を返し、確かめは何も示さないが、
			// そのときは続く gVisor の書き込みが失敗してキューに何も入らないので、上限は崩れない
			so.SetSendBufferSize(x, true)
			ready := c.ep.Readiness(waiter.WritableEvents)&waiter.WritableEvents != 0
			if so.GetSendBufferSize() != x {
				// 読み返しが違うのは、並行する設定が値を変えたとき。数回試し、だめなら通知を待つ
				if retries++; retries < 4 {
					continue
				}
				retries = 0
				if err := waitWritable(); err != nil {
					return total, err
				}
				continue
			}
			if !ready {
				if err := waitWritable(); err != nil {
					return total, err
				}
				continue
			}
			so.SetSendBufferSize(min(s, x+rest), true)
		}
		r.Reset(b[total:])
		n, err := c.ep.Write(&r, tcpip.WriteOptions{})
		if n > 0 {
			c.hist.add(int(n))
			total += int(n)
			now := time.Now()
			if c.wdem.add(now, int(n)) {
				c.noteDemand(now)
			}
		}
		switch err.(type) {
		case nil:
		case *tcpip.ErrWouldBlock:
			if werr := waitWritable(); werr != nil {
				return total, werr
			}
		default:
			return total, c.opError("write", errors.New(err.String()))
		}
	}
	return total, nil
}

func (c *tcpConn) CloseRead() error     { return c.gc.CloseRead() }
func (c *tcpConn) LocalAddr() net.Addr  { return c.gc.LocalAddr() }
func (c *tcpConn) RemoteAddr() net.Addr { return c.gc.RemoteAddr() }

// CloseWrite は送信の向きを閉じる。閉じる前に印を付け、demote が送信の確かめに頼らないようにする。
func (c *tcpConn) CloseWrite() error {
	c.cmu.Lock()
	defer c.cmu.Unlock()
	c.sndShut = true
	return c.gc.CloseWrite()
}

// markClosing は以後の boost を止め、待っている書き込みを解く。
func (c *tcpConn) markClosing() {
	c.cmu.Lock()
	c.closing = true
	c.cmu.Unlock()
	c.closeOnce.Do(func() { close(c.closeCh) })
}

// Close は net.Conn の実装。待っている書き込みを解いてから endpoint を閉じる。
func (c *tcpConn) Close() error {
	c.markClosing()
	err := c.gc.Close()
	c.closed.Store(true)
	return err
}

func (c *tcpConn) abort() {
	c.markClosing()
	c.ep.Abort()
	c.closed.Store(true)
}

// DialTCP は、この device の stack 越しに ap へつなぐ(仕様 6.3 節:vpsd からエージェントへの dial)。
// 返す接続は ListenTCP の Accept と同じ *TCPConn で、中継が切るときは Abort の RST で切れる
// (仕様 6.2 節)。gonet の dial は endpoint を公開しないので、endpoint を自分で持って接続し、
// 握手の後に floor を設定してから返す。取り消しと失敗のどの出口でも endpoint を 1 回だけ閉じる。
func (t *Device) DialTCP(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	var wq waiter.Queue
	ep, terr := t.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if terr != nil {
		return nil, errors.New(terr.String())
	}
	entry, notify := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&entry)
	defer wq.EventUnregister(&entry)
	if err := ctx.Err(); err != nil {
		ep.Close()
		return nil, err
	}
	terr = ep.Connect(fullAddr(ap))
	if _, ok := terr.(*tcpip.ErrConnectStarted); ok {
		// 通知は成功の証明にしない。誤りが無く、まだ接続の途中なら待ち直す
		for {
			select {
			case <-ctx.Done():
				ep.Close()
				return nil, ctx.Err()
			case <-notify:
			}
			terr = ep.LastError()
			if st := tcp.EndpointState(ep.State()); terr != nil || (st != tcp.StateSynSent && st != tcp.StateConnecting) {
				break
			}
		}
	}
	if terr != nil {
		ep.Close()
		return nil, &net.OpError{Op: "connect", Net: "tcp", Addr: net.TCPAddrFromAddrPort(ap), Err: errors.New(terr.String())}
	}
	c, err := newTCPConn(&wq, ep, t.pool)
	if err != nil {
		ep.Abort()
		return nil, err
	}
	return &TCPConn{c}, nil
}
