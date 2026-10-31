package wgstack

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// Config は Device を作る値。
type Config struct {
	// Addr は Device のアドレス(IPv4)。受け付ける宛先の集合は今は Addr の /32 の 1 つである。
	Addr netip.Addr
	// MTU はトンネルの MTU。Device を作るときに固定する。
	MTU int
	// MaxFlows は同時フロー数のプロセス全体の上限 K(WGFT_MAX_TCP_FLOWS)。接続の枠の数は K + Q である。
	// 0 なら既定の 2048 を使う。
	MaxFlows int
	// Clock は核の時計。nil なら単調な時計を使い、Device はタイマーを動かす goroutine を 1 つ持つ。nil で
	// なければ Device は goroutine を作らず、呼び出し側が時計を進めた後に Tick を呼ぶ。
	Clock Clock
	// Rand は ISN の鍵、表の hash の種、challenge ACK の揺らぎなどの乱数の種を読む元。nil なら
	// crypto/rand を使う。試験は固定の byte の列を渡す。
	Rand io.Reader
	// Trace は試験と性能の測定だけが設定する観測の関数。nil でなければ、接続が ACK を 1 つ処理するたびと
	// RTO のたびに、接続の錠を持ったまま呼ぶ。関数は Device を呼び返さず、panic しない(panic は接続の錠を
	// 持ったまま巻き戻る)。本番は nil のままにする。
	Trace func(TraceEvent)
	// TestBoost は試験と性能の測定だけが使う boost の与え方。本番は既定の BoostOnDemand のままにする。
	TestBoost BoostPolicy
	// TestCongestion は試験と性能の測定だけが使う輻輳の制御。本番は既定の CongestionCubic のままにする。
	TestCongestion CongestionControl
}

// processStart は本番の時計の起点。プロセスのすべての Device が同じ起点を使うので、boost の回収が
// 別の Device の接続の時刻を比べられる。
var processStart = time.Now()

// Device は wgstack を wireguard-go の tun.Device として動かす。入力は wireguard-go が呼ぶ Write の中で
// 同期して処理し、出力は Read の中でその場で作る(設計文書の「並行性と時計」)。
type Device struct {
	s      *stack
	clock  Clock
	manual bool
	events chan tun.Event

	readMu    sync.Mutex
	closeOnce sync.Once
	kick      chan struct{}
	stop      chan struct{}
	done      chan struct{}
}

// Create は addr を唯一のアドレスとする Device を、K の既定値と本番の時計と乱数で作る。
// internal/nettun.Create と同じ形である。
func Create(addr netip.Addr, mtu int) (*Device, error) {
	return New(Config{Addr: addr, MTU: mtu})
}

// New は cfg の Device を作る。表と固定の配列はここで確保する。
func New(cfg Config) (*Device, error) {
	return newDevice(cfg, defaultLimits(cfg.MaxFlows), processBoost)
}

func newDevice(cfg Config, lim limits, pool *boostPool) (*Device, error) {
	if !cfg.Addr.Is4() {
		return nil, errors.New("wgstack: tunnel address " + cfg.Addr.String() + " is not IPv4")
	}
	d := &Device{
		clock:  cfg.Clock,
		events: make(chan tun.Event, 1),
		kick:   make(chan struct{}, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
	if d.clock == nil {
		d.clock = monoClock{start: processStart}
	} else {
		d.manual = true
	}
	clock := d.clock
	s, err := newStack([]netip.Prefix{netip.PrefixFrom(cfg.Addr, 32)}, cfg.MTU, lim, func() int64 { return int64(clock.Now()) }, cfg.Rand, pool)
	if err != nil {
		return nil, errors.New("wgstack: " + err.Error())
	}
	d.s = s
	s.trace = cfg.Trace
	s.boostPolicy = cfg.TestBoost
	s.ccPolicy = cfg.TestCongestion
	if d.manual {
		close(d.done)
	} else {
		s.kick = func() {
			select {
			case d.kick <- struct{}{}:
			default:
			}
		}
		go d.timers()
	}
	d.events <- tun.EventUp
	return d, nil
}

// timers は Device の唯一の goroutine。タイマーと行の期限を進める。
func (d *Device) timers() {
	defer close(d.done)
	t := time.NewTimer(time.Hour)
	defer t.Stop()
	for {
		// 期限を求め終えるまでに入った期限は、sleepUntil が 0 の間 kick を残すので見落とさない
		d.s.sleepUntil.Store(0)
		now := int64(d.clock.Now())
		d.s.advance(now)
		next := d.s.nextDeadline()
		wait := time.Hour
		if next != 0 {
			wait = time.Duration(max(next-now, int64(time.Millisecond)))
			d.s.sleepUntil.Store(next)
		} else {
			d.s.sleepUntil.Store(now + int64(time.Hour))
		}
		t.Reset(wait)
		select {
		case <-t.C:
		case <-d.kick:
			if !t.Stop() {
				select {
				case <-t.C:
				default:
				}
			}
		case <-d.stop:
			return
		}
	}
}

// Tick は、Config.Clock を渡した Device で、時計の今の時刻までタイマーと行の期限を進める。
func (d *Device) Tick() {
	d.s.advance(int64(d.clock.Now()))
}

// Wait は Device の goroutine の終了を待つ。Close の後に呼ぶ。
func (d *Device) Wait() { <-d.done }

func (d *Device) Name() (string, error)    { return "wgstack", nil }
func (d *Device) File() *os.File           { return nil }
func (d *Device) Events() <-chan tun.Event { return d.events }
func (d *Device) MTU() (int, error)        { return d.s.mtu, nil }
func (d *Device) BatchSize() int           { return 1 }

func (d *Device) isClosed() bool {
	select {
	case <-d.s.done:
		return true
	default:
		return false
	}
}

// Read は次に送る packet を 1 つ作って bufs[0][offset:] に書く。送るものが無ければ待つ。誤りを返すのは
// Close の後の os.ErrClosed だけで、packet を作れなかったときは誤りにせず次を待つ。wireguard-go は Read が
// ほかの誤りを返すと device を閉じるためである。
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 {
		return 0, nil
	}
	for {
		if d.isClosed() {
			return 0, os.ErrClosed
		}
		d.readMu.Lock()
		n := d.s.poll(bufs[0][offset:], int64(d.clock.Now()))
		d.readMu.Unlock()
		if n > 0 {
			sizes[0] = n
			return 1, nil
		}
		select {
		case <-d.s.out.notify:
		case <-d.s.done:
		}
	}
}

// Poll は待たずに次の packet を 1 つ作り、その長さを返す。送るものが無ければ 0 を返す。試験と、Config.Clock を
// 渡した Device の呼び出し側が使う。
func (d *Device) Poll(buf []byte) int {
	if d.isClosed() {
		return 0
	}
	d.readMu.Lock()
	defer d.readMu.Unlock()
	return d.s.poll(buf, int64(d.clock.Now()))
}

// Write はバッチの各 packet を同期して処理する。1 件が失敗しても残りを処理し、受け取った件数と最初の誤りを
// 返す。長さ 0 の packet は受け取った件数に数えて何もしない。誤りにするのは閉じた後の Write と IPv4 で
// ない packet だけで、捨てた packet は誤りにしない(packet-validation.md の TUN の Write の誤り)。
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	accepted := 0
	var first error
	for _, b := range bufs {
		pkt := b[offset:]
		if len(pkt) == 0 {
			accepted++
			continue
		}
		if pkt[0]>>4 != 4 {
			if first == nil {
				first = syscall.EAFNOSUPPORT
			}
			continue
		}
		if d.isClosed() {
			if first == nil {
				first = os.ErrClosed
			}
			continue
		}
		d.s.input(pkt, int64(d.clock.Now()))
		accepted++
	}
	return accepted, first
}

// Close は Device を閉じる。待っている操作を net.ErrClosed で解き、すべての予約を返し、Events を閉じる。
// タイマーの goroutine の終了を待つ。2 回目以降は何もしない。
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		close(d.stop)
		<-d.done
		d.s.close()
		close(d.events)
	})
	return nil
}

var _ tun.Device = (*Device)(nil)

// close は核を閉じる。待っている操作を解き、接続の枠、行、boost の枠をすべて返す。
func (s *stack) close() {
	s.tmu.Lock()
	if s.closed {
		s.tmu.Unlock()
		return
	}
	s.closed = true
	close(s.done)
	for _, l := range s.listeners {
		l.closed = true
		close(l.closeCh)
	}
	clear(s.listeners)
	for id := range s.syn.rows {
		if s.syn.rows[id].used {
			s.syn.rows[id].promoting = false
			s.removeSynRow(int32(id))
		}
	}
	for s.tw.head >= 0 {
		s.removeTWRow(s.tw.head)
	}
	s.tmu.Unlock()
	s.udpClose()
	s.frag.Close()
	for i := range s.conns {
		c := &s.conns[i]
		c.mu.Lock()
		if c.state != stFree {
			c.signalRead()
			c.signalWrite()
			c.release()
		}
		c.floorRecs = nil
		c.floorIv = nil
		c.rcv.iv = nil
		c.recs.recs = nil
		c.mu.Unlock()
	}
	s.out.mu.Lock()
	s.out.ctl.n = 0
	s.out.mu.Unlock()
	s.chunks.mu.Lock()
	s.chunks.closed = true
	s.chunks.free = nil
	s.chunks.mu.Unlock()
}
