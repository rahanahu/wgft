package tunnel

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/tuntest"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/wgbind"
	"github.com/rahanahu/wgft/internal/wgstack"
)

// 送信の向きのバッチ(wgstack-batching.md)の、wireguard-go の依存の前提の試験と、wgstack を wireguard-go の
// device に組み込んだ結合の試験。結合の試験は wireguard-go の試験用のバインド(bindtest)と TUN(tuntest)で、
// 2 つの device をプロセスの中でつなぐ。標準のバインドは message ごとに endpoint を確保し、実のソケットを
// 使うので使わない。

// 依存の前提:上界の表とバッチの門が使う wireguard-go の値。依存の更新でこれが変わると失敗するので、
// wgstack-batching.md の「wireguard-go との境目」を読み直してから値を直す。
func TestWireGuardBatchAssumptions(t *testing.T) {
	wantMax := 65535
	if runtime.GOOS == "windows" {
		wantMax = 2016
	}
	for _, c := range []struct {
		name      string
		got, want int
	}{
		{"device.QueueStagedSize", device.QueueStagedSize, 128},
		{"device.QueueOutboundSize", device.QueueOutboundSize, 1024},
		{"device.QueueInboundSize", device.QueueInboundSize, 1024},
		{"device.MaxMessageSize", device.MaxMessageSize, wantMax},
		{"conn.IdealBatchSize, the length of the Send message array", conn.IdealBatchSize, 128},
		{"wgstack.MaxSendBatch", wgstack.MaxSendBatch, conn.IdealBatchSize},
		{"device.MessageTransportHeaderSize, the Read offset", device.MessageTransportHeaderSize, 16},
		{"device.MessageKeepaliveSize", device.MessageKeepaliveSize, 32},
		{"device.MessageTransportType", device.MessageTransportType, 4},
		{"device.PaddingMultiple", device.PaddingMultiple, 16},
	} {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if sendBatchSize > wgstack.MaxSendBatch || sendBatchSize > conn.IdealBatchSize {
		t.Errorf("k_tx %d is above the Send message array of %d", sendBatchSize, conn.IdealBatchSize)
	}
	wantStd := 1
	if runtime.GOOS == "linux" {
		wantStd = 128
	}
	if got := conn.NewStdNetBind().BatchSize(); got != wantStd {
		t.Errorf("StdNetBind.BatchSize() = %d on %s, want %d", got, runtime.GOOS, wantStd)
	}
	// S はヒープの区分:Linux と macOS は 64 KiB、Windows は 2 KiB
	wantS := int64(64 << 10)
	if runtime.GOOS == "windows" {
		wantS = 2 << 10
	}
	if got := SendBatchBufferBytes(); got != wantS {
		t.Errorf("S = %d, want %d", got, wantS)
	}
	if got, want := sendBatchSingles(), 1153+runtime.NumCPU()+6; got != want {
		t.Errorf("N_tx = %d, want 1153 + C = %d", got, want)
	}
}

// 標準のバインドの Send は 128 個の buffer を 1 回で送れる。wgstack の k_tx はこの数を超えない。
func TestStdNetBindSendsAFullBatch(t *testing.T) {
	rx, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("no loopback UDP: %v", err)
	}
	defer rx.Close()
	b := conn.NewStdNetBind()
	if _, _, err := b.Open(0); err != nil {
		t.Skipf("open the standard bind: %v", err)
	}
	defer b.Close()
	ep, err := b.ParseEndpoint(rx.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	bufs := make([][]byte, conn.IdealBatchSize)
	for i := range bufs {
		bufs[i] = make([]byte, 64)
	}
	if err := b.Send(bufs, ep); err != nil {
		t.Fatalf("Send of %d buffers: %v", len(bufs), err)
	}
}

// 予算の値:sendBatchConfig は P_upper で丸め、0 ならバッチを使わない。
func TestSendBatchConfig(t *testing.T) {
	if c := sendBatchConfig(0); c != (wgstack.SendBatch{}) {
		t.Fatalf("P_max 0 gives %+v, want no batching", c)
	}
	c := sendBatchConfig(1 << 30)
	if c.Packets != SendBatchCap() || c.Size != sendBatchSize || c.Callers != runtime.NumCPU()+6 || c.BufferSize != device.MaxMessageSize {
		t.Fatalf("config %+v", c)
	}
	if SendBatchCap() != sendBatchSingles()*sendBatchSize {
		t.Fatalf("P_upper %d, want N_tx x k_tx", SendBatchCap())
	}
}

// batchRecorder は、wgstack の Read が返した入れ物と、Send を見る層の外側で見た Send を照らし合わせる。
// 2 個以上の入れ物の buffer のうち、返したと確かに言えない分(held)を数える。送信の goroutine は Send から
// 戻った後に前の入れ物の buffer を返してから次の入れ物を取るので、transport の message を持つ次の Send が
// 始まった時点で、前の Send の入れ物は返し終えている。held は本当に持たれている数以上で、捨てた入れ物が
// 無い間は L + R 以下、したがって P_max 以下である(wgstack-batching.md の「同期が上界を崩さないこと」)。
type batchRecorder struct {
	mu        sync.Mutex
	pmax      int
	check     bool // held を P_max と比べる。入れ物を捨てる試験では偽にする
	counts    map[uint64]int
	sent      map[uint64]bool
	prevMulti int // 前の transport の Send の入れ物が 2 個以上なら、その個数
	held      int
	maxHeld   int
	reads     int
	multi     int // 2 個以上の Read の数
	multiPkts int // 2 個以上の Read の packet の数
	failure   string
}

func (r *batchRecorder) fail(format string, args ...any) {
	if r.failure == "" {
		r.failure = fmt.Sprintf(format, args...)
	}
}

// noCheck は held を P_max と比べるのをやめる。入れ物を捨てる試験で使う。
func (r *batchRecorder) noCheck() {
	r.mu.Lock()
	r.check = false
	r.mu.Unlock()
}

func tagSeq(full []byte) uint64 { return binary.LittleEndian.Uint64(full[len(full)-16:]) }

func (r *batchRecorder) onRead(bufs [][]byte, n int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	seq := tagSeq(bufs[0])
	for i := 1; i < n; i++ {
		if s := tagSeq(bufs[i]); s != seq {
			r.fail("one Read wrote seqs %d and %d", seq, s)
		}
	}
	if _, dup := r.counts[seq]; dup || seq == 0 {
		r.fail("Read reused seq %d", seq)
	}
	r.counts[seq] = n
	r.reads++
	if n >= 2 {
		r.multi++
		r.multiPkts += n
		r.held += n
		r.maxHeld = max(r.maxHeld, r.held)
		if r.check && r.held > r.pmax {
			r.fail("%d buffers may be held in multi-packet containers, over P_max %d", r.held, r.pmax)
		}
	}
}

func (r *batchRecorder) onSend(bufs [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	transport, data := 0, 0
	var seq uint64
	for _, b := range bufs {
		if len(b) < 4 || binary.LittleEndian.Uint32(b) != device.MessageTransportType {
			continue
		}
		transport++
		if len(b) <= device.MessageKeepaliveSize {
			continue
		}
		data++
		s := tagSeq(b[:cap(b)])
		if data == 1 {
			seq = s
		} else if s != seq {
			r.fail("one Send carries seqs %d and %d", seq, s)
		}
	}
	if transport == 0 {
		return // ハンドシェイクと cookie は別の goroutine が送る
	}
	// 送信の goroutine の Send:前の入れ物は返し終えている
	r.held -= r.prevMulti
	r.prevMulti = 0
	if data == 0 {
		return
	}
	if data != transport {
		r.fail("a Send mixes %d data messages with %d keepalives", data, transport-data)
	}
	want, ok := r.counts[seq]
	switch {
	case !ok:
		r.fail("Send carries seq %d that no Read wrote; the tag did not survive", seq)
	case r.sent[seq]:
		r.fail("seq %d sent twice", seq)
	case want != data:
		r.fail("Send of seq %d carries %d messages, the Read made %d", seq, data, want)
	}
	r.sent[seq] = true
	if want >= 2 {
		r.prevMulti = want
	}
}

func (r *batchRecorder) snapshot() (reads, multi, multiPkts, held int, failure string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reads, r.multi, r.multiPkts, r.held, r.failure
}

type recordingTun struct {
	tun.Device
	r *batchRecorder
}

func (d recordingTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	if n > 0 {
		d.r.onRead(bufs, n)
	}
	return n, err
}

type recordingBind struct {
	conn.Bind
	r *batchRecorder
}

func (b recordingBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.r.onSend(bufs)
	return b.Bind.Send(bufs, ep)
}

// faultyBind は Send を遅らせ、捨て、途中で誤りにする内側のバインド。
type faultyBind struct {
	conn.Bind
	blackhole atomic.Bool // すべての datagram を捨てる
	slow      atomic.Bool // Send ごとに少し待ち、ときどき入れ物の途中で誤りを返す
	mu        sync.Mutex
	rng       *rand.Rand
}

var errInjected = errors.New("injected send error")

func (b *faultyBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b.blackhole.Load() {
		return nil
	}
	if b.slow.Load() {
		b.mu.Lock()
		d := time.Duration(b.rng.IntN(300)) * time.Microsecond
		cut := b.rng.IntN(20) == 0 && len(bufs) > 1
		b.mu.Unlock()
		time.Sleep(d)
		if cut { // Linux 以外の標準のバインドと同じく、最初の誤りで残りを送らない
			if err := b.Bind.Send(bufs[:1], ep); err != nil {
				return err
			}
			return errInjected
		}
	}
	return b.Bind.Send(bufs, ep)
}

var (
	rigAgentAddr  = netip.MustParseAddr("10.200.0.2")
	rigServerAddr = netip.MustParseAddr("10.200.0.1")
)

// batchRig は wgstack を使うエージェントの device(a)と、素の wireguard-go の device(b)をつないだもの。
// a のバインドは tunnel.New と同じく deviceBind が Send を見る層を置き、その外側で recordingBind が見る。
type batchRig struct {
	t     *testing.T
	a, b  *device.Device
	ns    netstack
	rec   *batchRecorder
	inner *faultyBind
	udp   net.PacketConn
	to    net.Addr
	got   atomic.Int64 // b の TUN に届いた packet
}

func newBatchRig(t *testing.T, pmax int, blackhole bool) *batchRig {
	t.Helper()
	ns, err := newNetstack(Config{Netstack: NetstackWgstack, Address: rigAgentAddr, MTU: 1420, SendBatchPackets: pmax})
	if err != nil {
		t.Fatal(err)
	}
	w := ns.(wgstackNetstack)
	if !w.Batching() || w.BatchSize() != sendBatchSize {
		t.Fatalf("Batching %v BatchSize %d with P_max %d", w.Batching(), w.BatchSize(), pmax)
	}
	binds := bindtest.NewChannelBinds()
	rec := &batchRecorder{pmax: pmax, check: true, counts: map[uint64]int{}, sent: map[uint64]bool{}}
	inner := &faultyBind{Bind: binds[0], rng: rand.New(rand.NewPCG(1, 2))}
	inner.blackhole.Store(blackhole) // device を起こす前に置き、最初のハンドシェイクも捨てる
	r := &batchRig{t: t, ns: ns, rec: rec, inner: inner}
	quiet := device.NewLogger(device.LogLevelSilent, "")
	r.a = wgbind.NewDevice(recordingTun{ns, rec}, recordingBind{deviceBind(ns, inner), rec}, quiet)
	bt := tuntest.NewChannelTUN()
	r.b = device.NewDevice(bt.TUN(), binds[1], quiet)
	go func() {
		for range bt.Inbound {
			r.got.Add(1)
		}
	}()
	ka, _ := wgtypes.GeneratePrivateKey()
	kb, _ := wgtypes.GeneratePrivateKey()
	ipc := func(d *device.Device, priv, peer wgtypes.Key, allowed netip.Addr, ep string) {
		cfg := fmt.Sprintf("private_key=%s\npublic_key=%s\nallowed_ip=%s/32\nendpoint=%s\npersistent_keepalive_interval=1\n",
			hex.EncodeToString(priv[:]), hex.EncodeToString(peer[:]), allowed, ep)
		if err := d.IpcSet(cfg); err != nil {
			t.Fatal(err)
		}
		if err := d.Up(); err != nil {
			t.Fatal(err)
		}
	}
	ipc(r.b, kb, ka.PublicKey(), rigAgentAddr, "127.0.0.1:2")
	ipc(r.a, ka, kb.PublicKey(), rigServerAddr, "127.0.0.1:1")
	t.Cleanup(func() {
		r.a.Close()
		r.b.Close()
	})
	pc, err := ns.ListenUDP(netip.AddrPortFrom(rigAgentAddr, 5000))
	if err != nil {
		t.Fatal(err)
	}
	r.udp = pc
	r.to = net.UDPAddrFromAddrPort(netip.AddrPortFrom(rigServerAddr, 6000))
	return r
}

// blast は writers 個の goroutine から d の間 UDP を書く。
func (r *batchRig) blast(writers int, d time.Duration) {
	var wg sync.WaitGroup
	stop := time.Now().Add(d)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload := make([]byte, 1000)
			for time.Now().Before(stop) {
				r.udp.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
				if _, err := r.udp.WriteTo(payload, r.to); err != nil && !errors.Is(err, net.ErrClosed) {
					var ne net.Error
					if errors.As(err, &ne) && ne.Timeout() {
						continue
					}
					return
				}
			}
		}()
	}
	wg.Wait()
}

// waitDelivered は b に届く packet が増えるまで UDP を少しずつ書く。ハンドシェイクの成立を待つのに使う。
func (r *batchRig) waitDelivered(budget time.Duration) {
	r.t.Helper()
	start := r.got.Load()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		r.udp.WriteTo([]byte("probe"), r.to)
		time.Sleep(50 * time.Millisecond)
		if r.got.Load() > start {
			return
		}
	}
	r.t.Fatalf("no packet reached the peer within %s", budget)
}

func (r *batchRig) mustNotFail() {
	r.t.Helper()
	if _, _, _, _, f := r.rec.snapshot(); f != "" {
		r.t.Fatal(f)
	}
}

// keff と reserve は試験の P_max での k_eff と R。
func rigReserve(pmax int) (keff, reserve int) {
	c := runtime.NumCPU() + 6
	keff = min(sendBatchSize, pmax/(2*(c-1)))
	return keff, (c - 1) * keff
}

// 印が Send まで残り、Read の入れ物 1 つが Send 1 回で送られ、Send を遅らせて誤りを混ぜても、返したと
// 言えない 2 個以上の入れ物の buffer が P_max を超えない。W が進まなければ 2 個以上の Read は P_max - R の
// packet で止まるので、それを大きく超えて続くことが同期の働きを示す。
func TestBatchHoldsWithinBudgetUnderLoad(t *testing.T) {
	pmax := 8 * (runtime.NumCPU() + 5) // k_eff = 4、R = P_max / 2
	r := newBatchRig(t, pmax, false)
	r.waitDelivered(10 * time.Second)
	// 速い Send で流した後、Send を遅らせて誤りを混ぜる。遅い間は送信のキューが深くなり、門が閉じては開く
	dur := time.Second
	if testing.Short() {
		dur = 300 * time.Millisecond
	}
	r.blast(8, dur)
	r.inner.slow.Store(true)
	r.blast(8, dur)
	r.mustNotFail()
	reads, multi, multiPkts, _, _ := r.rec.snapshot()
	_, reserve := rigReserve(pmax)
	t.Logf("P_max %d R %d: %d Reads, %d multi-packet Reads with %d packets, max held %d", pmax, reserve, reads, multi, multiPkts, r.rec.maxHeld)
	if multiPkts <= 2*pmax {
		t.Fatalf("only %d packets in multi-packet Reads; with W stuck the gate closes after %d", multiPkts, pmax-reserve)
	}
}

// staged のキューの溢れで捨てた入れ物は台帳に残るが、鍵ができて送り始めると W が追い越し、件数が戻る。
func TestBatchRecoversAfterStagedOverflow(t *testing.T) {
	pmax := 8 * (runtime.NumCPU() + 5)
	_, reserve := rigReserve(pmax)
	r := newBatchRig(t, pmax, true)
	r.rec.noCheck()                  // 捨てた入れ物は Send に現れないので、held は数えすぎる
	r.blast(4, 300*time.Millisecond) // ハンドシェイクが成立しないので staged のキューに溜まり、溢れる
	reads, multi, multiPkts, _, _ := r.rec.snapshot()
	if reads <= device.QueueStagedSize || multiPkts > pmax-reserve {
		t.Fatalf("before the handshake: %d Reads, %d packets in %d multi-packet Reads; want more than %d Reads and at most P_max - R = %d packets",
			reads, multiPkts, multi, device.QueueStagedSize, pmax-reserve)
	}
	before := multiPkts
	r.inner.blackhole.Store(false)
	r.waitDelivered(15 * time.Second) // ハンドシェイクの再送は 5 秒ごと
	r.blast(8, time.Second)
	r.mustNotFail()
	_, _, multiPkts, _, _ = r.rec.snapshot()
	if multiPkts-before <= pmax {
		t.Fatalf("after the handshake only %d more packets in multi-packet Reads; W did not pass the dropped containers", multiPkts-before)
	}
}

// ピアの停止で捨てた入れ物も、開始の後に送り始めれば W が追い越す。送信の goroutine は入れ替わり、古い
// goroutine の手元の番号を新しい goroutine が知らせる。
func TestBatchRecoversAfterPeerStop(t *testing.T) {
	pmax := 8 * (runtime.NumCPU() + 5)
	r := newBatchRig(t, pmax, false)
	r.waitDelivered(10 * time.Second)
	r.blast(8, 300*time.Millisecond)
	r.rec.noCheck()
	r.a.Down()
	r.blast(4, 300*time.Millisecond) // 止まったピアへの入れ物は TUN の読み取りが捨てる
	if err := r.a.Up(); err != nil {
		t.Fatal(err)
	}
	_, _, before, _, _ := r.rec.snapshot()
	r.waitDelivered(15 * time.Second)
	r.blast(8, time.Second)
	r.mustNotFail()
	_, _, after, _, _ := r.rec.snapshot()
	if after-before <= pmax {
		t.Fatalf("after the restart only %d more packets in multi-packet Reads", after-before)
	}
}

// バッチを使わない設定では Send を見る層を置かず、BatchSize は 1 である。gVisor でも置かない。
func TestDeviceBindWatchesOnlyBatchingWgstack(t *testing.T) {
	inner := bindtest.NewChannelBinds()[0]
	off, err := newNetstack(Config{Netstack: NetstackWgstack, Address: rigAgentAddr, MTU: 1420})
	if err != nil {
		t.Fatal(err)
	}
	defer off.Close()
	if off.BatchSize() != 1 || deviceBind(off, inner) != inner {
		t.Fatalf("wgstack with P_max 0: BatchSize %d, bind wrapped %v", off.BatchSize(), deviceBind(off, inner) != inner)
	}
	gv, err := newNetstack(Config{Netstack: NetstackGVisor, Address: rigAgentAddr, MTU: 1420, SendBatchPackets: 1000})
	if err != nil {
		t.Fatal(err)
	}
	defer gv.Close()
	if gv.BatchSize() != 1 || deviceBind(gv, inner) != inner {
		t.Fatalf("gVisor: BatchSize %d, bind wrapped %v", gv.BatchSize(), deviceBind(gv, inner) != inner)
	}
	on, err := newNetstack(Config{Netstack: NetstackWgstack, Address: rigAgentAddr, MTU: 1420, SendBatchPackets: 1000})
	if err != nil {
		t.Fatal(err)
	}
	defer on.Close()
	if on.BatchSize() != sendBatchSize || deviceBind(on, inner) == inner {
		t.Fatalf("wgstack with P_max 1000: BatchSize %d, bind wrapped %v", on.BatchSize(), deviceBind(on, inner) != inner)
	}
	if got := deviceBind(on, inner).BatchSize(); got != inner.BatchSize() {
		t.Fatalf("the Send watch changed the receive batch to %d", got)
	}
}
