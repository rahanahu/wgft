package wgbind

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ratelimiter"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/nettun"
)

// pinnedWireGuard は、送信元の bucket の上限を確かめた wireguard-go の版。版を上げるときは、
// 受信した endpoint の DstIP を limiter のキーにだけ使い、handshake のキューに入るのが下の
// 大きさの initiation と response だけであることを、新しい版のソースで確かめ直す。
const pinnedWireGuard = "golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446"

func TestPinnedSourceBucketFacts(t *testing.T) {
	if device.QueueHandshakeSize != 1024 || device.MessageInitiationType != 1 ||
		device.MessageResponseType != 2 || device.MessageInitiationSize != 148 || device.MessageResponseSize != 92 {
		t.Fatal("WireGuard queue or packet constants changed; review the source bucket bound")
	}
	f, err := os.Open(filepath.Join("..", "..", "..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	found := false
	for s := bufio.NewScanner(f); s.Scan(); {
		line := strings.TrimSpace(s.Text())
		if line == pinnedWireGuard {
			found = true
		}
		// replace は require の版と別のソースを使わせる。wgctrl は別の module なので対象外。
		if strings.Contains(line, "=>") && strings.Contains(strings.TrimPrefix(line, "replace "), "golang.zx2c4.com/wireguard ") {
			t.Fatalf("go.mod replaces wireguard-go: %q; review how the replacement uses Endpoint.DstIP", line)
		}
	}
	if !found {
		t.Fatalf("go.mod no longer requires %q; review how the new version uses Endpoint.DstIP before updating this pin", pinnedWireGuard)
	}
	if sourceBuckets&(sourceBuckets-1) != 0 {
		t.Fatal("bucket count is not a power of two")
	}
	w := runtime.NumCPU()
	t.Logf("CPU workers=%d, planning bytes=%d", w,
		64*1024+256*(sourceBuckets+w+1)+48*(device.QueueHandshakeSize+w+2))
}

type gatePacket struct {
	data []byte
	ep   conn.Endpoint
}

// gateBind は 1 回の受信で 1 件の packet を返す内側のバインド。
type gateBind struct {
	*fakeBind
	packets     []gatePacket
	functions   int
	nilFunction bool
}

func (b *gateBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.opened++
	n := b.functions
	if n == 0 {
		n = 1
	}
	fns := make([]conn.ReceiveFunc, n)
	for i := range fns {
		if !b.nilFunction {
			fns[i] = b.receive
		}
	}
	return fns, port, nil
}

func (b *gateBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if len(b.packets) == 0 {
		return 0, net.ErrClosed
	}
	p := b.packets[0]
	b.packets = b.packets[1:]
	sizes[0] = copy(bufs[0], p.data)
	eps[0] = p.ep
	return 1, nil
}

func handshake(typ uint32, size int) []byte {
	p := make([]byte, size)
	if size >= 4 {
		binary.LittleEndian.PutUint32(p, typ)
	}
	return p
}

func stdEndpoint(ip netip.Addr) *conn.StdNetEndpoint {
	return &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(ip, 12345)}
}

func fixtureIP(i int) netip.Addr {
	if i%2 == 0 {
		return netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})
	}
	// IPv6 は /64 ごとに 1 つの送信元になるので、prefix の側を変える。
	var a [16]byte
	a[0], a[1] = 0x20, 0x01
	binary.BigEndian.PutUint32(a[4:], uint32(i))
	a[15] = 1
	return netip.AddrFrom16(a)
}

var bucketSet = func() map[netip.Addr]bool {
	m := make(map[netip.Addr]bool, sourceBuckets)
	for _, a := range bucketAddrs {
		m[a] = true
	}
	return m
}()

func TestSourceGateWrapsOnlyHandshakeCandidates(t *testing.T) {
	for _, batch := range []int{1, 4} {
		t.Run(fmt.Sprint(batch), func(t *testing.T) {
			ep := stdEndpoint(netip.MustParseAddr("192.0.2.7"))
			counting := &clearCountingEndpoint{}
			cases := []struct {
				typ  uint32
				size int
				ep   conn.Endpoint
				wrap bool
			}{
				{1, 148, ep, true}, {2, 92, ep, true}, {1, 148, fakeEndpoint{id: 3}, true}, {2, 92, counting, true},
				{1, 147, ep, false}, {2, 93, ep, false}, {3, 64, ep, false}, {4, 148, ep, false},
				{4, 32, ep, false}, {99, 92, ep, false}, {1, 3, ep, false},
			}
			b := &gateBind{fakeBind: &fakeBind{batch: batch}}
			for _, c := range cases {
				b.packets = append(b.packets, gatePacket{handshake(c.typ, c.size), c.ep})
			}
			g := newSourceGate(b)
			if g.BatchSize() != 1 {
				t.Fatal("gate is not single-item")
			}
			fns, _, err := g.Open(0)
			if err != nil {
				t.Fatal(err)
			}
			for i, c := range cases {
				data, got, err := one(t, fns[0])
				if err != nil {
					t.Fatal(err)
				}
				if data != string(handshake(c.typ, c.size)) {
					t.Fatalf("case %d: datagram changed", i)
				}
				w, wrapped := got.(*bucketEndpoint)
				if wrapped != c.wrap {
					t.Fatalf("case %d: wrapped=%v, want %v", i, wrapped, c.wrap)
				}
				if !wrapped {
					if got != c.ep {
						t.Fatalf("case %d: endpoint replaced", i)
					}
					continue
				}
				if w.Endpoint != c.ep || !bucketSet[got.DstIP()] {
					t.Fatalf("case %d: wrapper inner=%v bucket=%v", i, w.Endpoint, got.DstIP())
				}
				if string(got.DstToBytes()) != string(c.ep.DstToBytes()) || got.DstToString() != c.ep.DstToString() ||
					got.SrcIP() != c.ep.SrcIP() || got.SrcToString() != c.ep.SrcToString() {
					t.Fatalf("case %d: wrapper changed a passthrough method", i)
				}
				if c.ep == conn.Endpoint(counting) {
					got.ClearSrc()
					if counting.clears != 1 {
						t.Fatalf("ClearSrc reached the inner endpoint %d times, want 1", counting.clears)
					}
				}
			}
		})
	}
	if candidate([]byte{1}, 148) || candidate(handshake(1, 148), -1) {
		t.Fatal("unsafe slice boundary classified")
	}
}

// clearCountingEndpoint は ClearSrc の呼び出しを数える。
type clearCountingEndpoint struct {
	fakeEndpoint
	clears int
}

func (e *clearCountingEndpoint) ClearSrc() { e.clears++ }

func TestSourceGateSendUnwraps(t *testing.T) {
	f := &fakeBind{batch: 1}
	g := newSourceGate(f)
	inner := stdEndpoint(netip.MustParseAddr("2001:db8::9"))
	w := g.wrap(inner)
	if err := g.Send([][]byte{{1}}, w); err != nil {
		t.Fatal(err)
	}
	if f.sentTo != conn.Endpoint(inner) {
		t.Fatalf("Send passed %T, want the inner endpoint", f.sentTo)
	}
	plain := fakeEndpoint{id: 1}
	_ = g.Send(nil, plain)
	if f.sentTo != conn.Endpoint(plain) {
		t.Fatal("Send changed a plain endpoint")
	}
	if g.wrap(w).(*bucketEndpoint).Endpoint != conn.Endpoint(inner) {
		t.Fatal("wrapping twice nested the wrapper")
	}
}

func TestSourceGateReceiveLayout(t *testing.T) {
	b := &gateBind{fakeBind: &fakeBind{batch: 1}, nilFunction: true}
	if _, _, err := newSourceGate(b).Open(0); err != errReceiveLayout || b.closed != 1 {
		t.Fatalf("nil function error=%v closes=%d", err, b.closed)
	}
	b = &gateBind{fakeBind: &fakeBind{batch: 1}, functions: 2}
	fns, _, err := newSourceGate(b).Open(0)
	if err != nil || len(fns) != 2 {
		t.Fatalf("two receive functions: %v", err)
	}
	over := func([][]byte, []int, []conn.Endpoint) (int, error) { return 2, nil }
	ob := &funcBind{fakeBind: &fakeBind{batch: 1}, fn: over}
	fns, _, err = newSourceGate(ob).Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fns[0](make([][]byte, 1), make([]int, 1), make([]conn.Endpoint, 1)); err != errReceiveLayout {
		t.Fatal("count beyond the slices was accepted")
	}
	sentinel := permanentError{}
	g := newSourceGate(&fakeBind{batch: 1, script: []fakeResult{{err: sentinel}}})
	fns, _, err = g.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := one(t, fns[0]); err != error(sentinel) {
		t.Fatal("inner error wrapped or changed")
	}
}

type funcBind struct {
	*fakeBind
	fn conn.ReceiveFunc
}

func (b *funcBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.fn}, port, nil
}

// 送信元をいくら入れ替えても、limiter に渡るキーは K 個の合成のアドレスに収まる。
func TestSourceBucketsBoundUnderChurn(t *testing.T) {
	g := newSourceGate(&fakeBind{batch: 1})
	seen := make(map[netip.Addr]int)
	const sources = 200000
	for i := 0; i < sources; i++ {
		ip := fixtureIP(i)
		key := g.wrap(stdEndpoint(ip)).DstIP()
		if !bucketSet[key] {
			t.Fatalf("source %v produced a key outside the buckets: %v", ip, key)
		}
		seen[key]++
	}
	mapped := netip.AddrFrom16(netip.MustParseAddr("192.0.2.1").As16())
	for _, ip := range []netip.Addr{{}, netip.MustParseAddr("192.0.2.1"), mapped, netip.MustParseAddr("fe80::1%eth0")} {
		if !bucketSet[g.wrap(stdEndpoint(ip)).DstIP()] {
			t.Fatalf("%v produced a key outside the buckets", ip)
		}
	}
	if len(seen) != sourceBuckets {
		t.Fatalf("%d sources used %d buckets, want all %d", sources, len(seen), sourceBuckets)
	}
	largest := 0
	for _, n := range seen {
		largest = max(largest, n)
	}
	if mean := sources / sourceBuckets; largest > 2*mean {
		t.Fatalf("largest bucket %d is over twice the mean %d", largest, mean)
	}
	// IPv6 は /64 ごとに 1 つの bucket に入る。IPv4 はアドレスごとに分かれる。
	samePrefix := map[int]bool{}
	for _, s := range []string{"2001:db8:1:2::1", "2001:db8:1:2::ffff", "2001:db8:1:2:dead:beef:1:2"} {
		samePrefix[g.bucketOf(netip.MustParseAddr(s))] = true
	}
	if len(samePrefix) != 1 {
		t.Fatal("addresses in one IPv6 /64 used different buckets")
	}
	v4 := map[int]bool{}
	for i := 0; i < 64; i++ {
		v4[g.bucketOf(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}))] = true
	}
	if len(v4) < 32 {
		t.Fatalf("64 IPv4 addresses in one /24 used only %d buckets", len(v4))
	}
	// IPv4-mapped IPv6 はアドレス全体でまとめる。/64 でまとめると全部が 1 つの bucket に入る。
	mappedSpread := map[int]bool{}
	for i := 0; i < 64; i++ {
		mappedSpread[g.bucketOf(netip.AddrFrom16(netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}).As16()))] = true
	}
	if len(mappedSpread) < 32 {
		t.Fatalf("64 IPv4-mapped addresses used only %d buckets", len(mappedSpread))
	}
	// 同じ送信元は同じ bucket に入り、Device ごとに対応が変わる。
	other := newSourceGate(&fakeBind{batch: 1})
	differs := false
	for i := 0; i < 64; i++ {
		ip := fixtureIP(i)
		first := g.wrap(stdEndpoint(ip)).DstIP()
		if again := g.wrap(stdEndpoint(ip)).DstIP(); again != first {
			t.Fatal("bucket is not stable")
		}
		differs = differs || g.bucketOf(ip) != other.bucketOf(ip)
	}
	if !differs {
		t.Fatal("two Devices map 64 sources identically; the hash is not keyed")
	}
}

// 実際の limiter を、Device と同じく包みの DstIP で引く。洪水の送信元と bucket を共有しない
// ピアは通り、共有するピアは洪水と同じトークンバケットで絞られる。
func TestSourceBucketsLegitimatePeersAndSharedBucket(t *testing.T) {
	var r ratelimiter.Ratelimiter
	r.Init()
	t.Cleanup(r.Close)
	g := newSourceGate(&fakeBind{batch: 1})
	flooded := make(map[netip.Addr]bool)
	const attackers = 256
	for i := 0; i < attackers; i++ {
		flooded[g.wrap(stdEndpoint(fixtureIP(i))).DstIP()] = true
	}
	var separate, shared netip.Addr
	for i := attackers; !separate.IsValid() || !shared.IsValid(); i++ {
		ip := fixtureIP(i)
		if flooded[g.wrap(stdEndpoint(ip)).DstIP()] {
			if !shared.IsValid() {
				shared = ip
			}
		} else if !separate.IsValid() {
			separate = ip
		}
	}
	for round := 0; round < 10; round++ {
		for i := 0; i < attackers; i++ {
			r.Allow(g.wrap(stdEndpoint(fixtureIP(i))).DstIP())
		}
	}
	if !r.Allow(g.wrap(stdEndpoint(separate)).DstIP()) {
		t.Fatal("a peer outside the flooded buckets was throttled")
	}
	// 洪水は shared と bucket を共有する送信元から送り、確かめるのは shared の包みの DstIP で引く
	var peers []netip.Addr
	for i := 0; i < attackers; i++ {
		if g.wrap(stdEndpoint(fixtureIP(i))).DstIP() == g.wrap(stdEndpoint(shared)).DstIP() {
			peers = append(peers, fixtureIP(i))
		}
	}
	flood := func(i int) bool { return r.Allow(g.wrap(stdEndpoint(peers[i%len(peers)])).DstIP()) }
	check := func() bool { return r.Allow(g.wrap(stdEndpoint(shared)).DstIP()) }
	if !sharedPeerThrottled(t, flood, check) {
		t.Fatal("a peer sharing a flooded bucket was not throttled; the shared-bucket trade-off changed")
	}
}

// limiterPacketCost は wireguard-go の ratelimiter が 1 packet に使う時間(毎秒 20 packet)。バケットは
// 経過時間の分だけ補充され、残りがこの値を超えるときだけ通す。
const limiterPacketCost = time.Second / 20

// sharedPeerThrottled は、flood が洪水を送る bucket で check が絞られるかを返す。バケットは時間で補充
// されるので、答えは洪水からいつ確かめたかで変わる。通らなくなったバケットはちょうど 1 packet 分の
// 残りで止まり(通すのは 1 packet 分を超えるときだけ)、時計が 15.6 ms 刻みで進む Windows の runner では、
// 確かめる前に時計が 1 刻み進んだだけで 1 packet 通す。そこで、洪水を続けてバケットがまた 1 packet
// 通した直後に check を呼ぶ。そのときの残りは、直前の洪水の呼び出しから check までの補充分を超えない。
// その時間が 1 packet 分の半分より短いと時計で確かめられたときだけ答えにし、長ければやり直す。
func sharedPeerThrottled(t *testing.T, flood func(int) bool, check func() bool) bool {
	t.Helper()
	n := 0
	for attempt := 0; attempt < 20; attempt++ {
		// 通らなくなるまで洪水を続け、また 1 packet 通したところで止める。last は最後に通らなかった
		// 呼び出しの前の時刻
		var last time.Time
		for deadline := time.Now().Add(2 * time.Second); ; n++ {
			at := time.Now()
			ok := flood(n)
			if ok && !last.IsZero() {
				break
			}
			if !ok {
				last = at
			}
			if at.After(deadline) {
				t.Fatal("the flooded bucket did not drain and refill within 2s")
			}
		}
		n++
		throttled := !check()
		elapsed := time.Since(last)
		if elapsed < limiterPacketCost/2 {
			return throttled
		}
		t.Logf("attempt %d: %v from the flood's last refused packet to the check; trying again", attempt, elapsed)
	}
	t.Fatal("no attempt checked the shared peer within half a packet's time of the flood")
	return false
}

// 2 本の受信と送信を同時に動かす。-race で包みと鍵の共有を確かめる。
func TestSourceGateConcurrentReceiveAndSend(t *testing.T) {
	var sends atomic.Int64
	b := &concurrentBind{fakeBind: &fakeBind{batch: 1}, sends: &sends}
	g := newSourceGate(b)
	fns, _, err := g.Open(0)
	if err != nil || len(fns) != 2 {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, fn := range fns {
		wg.Add(1)
		go func(fn conn.ReceiveFunc) {
			defer wg.Done()
			bufs, sizes, eps := [][]byte{make([]byte, 148)}, make([]int, 1), make([]conn.Endpoint, 1)
			for i := 0; i < 2000; i++ {
				if _, err := fn(bufs, sizes, eps); err != nil {
					t.Error(err)
					return
				}
				if !bucketSet[eps[0].DstIP()] {
					t.Error("key outside the buckets")
					return
				}
				if err := g.Send([][]byte{{0}}, eps[0]); err != nil {
					t.Error(err)
					return
				}
			}
		}(fn)
	}
	wg.Wait()
	if sends.Load() != 4000 {
		t.Fatalf("sends=%d", sends.Load())
	}
}

type concurrentBind struct {
	*fakeBind
	next  atomic.Uint32
	sends *atomic.Int64
}

func (b *concurrentBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	return []conn.ReceiveFunc{b.receive, b.receive}, port, nil
}

func (b *concurrentBind) receive(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	n := b.next.Add(1)
	sizes[0] = copy(bufs[0], handshake(1, 148))
	eps[0] = stdEndpoint(fixtureIP(int(n)))
	return 1, nil
}

func (b *concurrentBind) Send(_ [][]byte, ep conn.Endpoint) error {
	if _, ok := ep.(*conn.StdNetEndpoint); !ok {
		return fmt.Errorf("Send got %T", ep)
	}
	b.sends.Add(1)
	return nil
}

func BenchmarkSourceGateReceive(b *testing.B) {
	for _, c := range []struct {
		name string
		typ  uint32
		size int
	}{{"initiation", 1, 148}, {"transport", 4, 1420}} {
		b.Run(c.name, func(b *testing.B) {
			ep := stdEndpoint(netip.MustParseAddr("192.0.2.1"))
			packet := handshake(c.typ, c.size)
			inner := func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
				sizes[0] = len(packet)
				copy(bufs[0], packet[:8])
				eps[0] = ep
				return 1, nil
			}
			fns, _, err := newSourceGate(&funcBind{fakeBind: &fakeBind{batch: 1}, fn: inner}).Open(0)
			if err != nil {
				b.Fatal(err)
			}
			bufs, sizes, eps := [][]byte{make([]byte, maxDatagram)}, make([]int, 1), make([]conn.Endpoint, 1)
			b.ReportAllocs()
			for b.Loop() {
				_, _ = fns[0](bufs, sizes, eps)
			}
		})
	}
}

// 実際の Device 2 台を標準のバインドで向かい合わせ、IPv4 と IPv6 でハンドシェイク、UAPI の
// endpoint、送信元のポートの移動を確かめる。
func TestDevicesHandshakeAndRoamThroughGate(t *testing.T) {
	for _, family := range []string{"127.0.0.1", "::1"} {
		t.Run(family, func(t *testing.T) {
			loop := netip.MustParseAddr(family)
			if c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loop, 0))); err != nil {
				t.Skipf("loopback %s unavailable: %v", family, err)
			} else {
				c.Close()
			}
			keyA, keyB := newKey(t), newKey(t)
			a := testDevice(t, "192.0.2.1", keyA)
			portA := listenPort(t, a)
			b := testDevice(t, "192.0.2.2", keyB)
			portB := listenPort(t, b)
			mustSet(t, a, fmt.Sprintf("public_key=%s\nallowed_ip=192.0.2.2/32\n", hexKey(keyB.PublicKey())))
			mustSet(t, b, fmt.Sprintf("public_key=%s\nendpoint=%s\npersistent_keepalive_interval=1\nallowed_ip=192.0.2.1/32\n",
				hexKey(keyA.PublicKey()), netip.AddrPortFrom(loop, portA)))
			want := netip.AddrPortFrom(loop, portB).String()
			waitPeer(t, a, func(ep string, hs bool) bool { return hs && ep == want }, "handshake from "+want)
			waitPeer(t, b, func(_ string, hs bool) bool { return hs }, "handshake at the initiator")

			// B のポートを変える。A の UAPI の endpoint は本当の新しいアドレスに移る。
			mustSet(t, b, "listen_port=0\n")
			moved := netip.AddrPortFrom(loop, listenPort(t, b)).String()
			if moved == want {
				t.Skip("the new listen port equals the old one")
			}
			waitPeer(t, a, func(ep string, _ bool) bool { return ep == moved }, "roamed endpoint "+moved)
		})
	}
}

// 負荷の高い状態の cookie reply が本当の送信元へ届き、その cookie の MAC2 を付けた initiation が
// limiter に届くことを確かめる。MAC2 の正しい initiation を一度に送ると、bucket のトークンの分
// だけが limiter を通って中身の検査で記録を残し、残りは limiter が黙って捨てる。負荷の高い状態に
// ないときは limiter を使わず、すべてが記録を残す。
func TestDeviceCookieReplyUnderLoadThroughGate(t *testing.T) {
	if testing.Short() {
		t.Skip("floods the handshake queue")
	}
	for _, family := range []string{"127.0.0.1", "::1"} {
		t.Run(family, func(t *testing.T) {
			loop := netip.MustParseAddr(family)
			client, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.AddrPortFrom(loop, 0)))
			if err != nil {
				t.Skipf("loopback %s unavailable: %v", family, err)
			}
			defer client.Close()
			key := newKey(t)
			var passed, lastLog atomic.Int64
			src := client.LocalAddr().String()
			logger := &device.Logger{Verbosef: func(format string, args ...any) {
				lastLog.Store(time.Now().UnixNano())
				if strings.HasPrefix(format, "Received invalid initiation message from") && fmt.Sprint(args...) == src {
					passed.Add(1)
				}
			}, Errorf: device.DiscardLogf}
			d := testDevice(t, "192.0.2.1", key, logger)
			server := netip.AddrPortFrom(loop, listenPort(t, d))
			// handshake の worker が処理を終えるまで待つ。Device.Close は worker の終了を待たず、
			// 閉じた limiter に後から Allow が届くと依存ライブラリが panic する。
			quiet := func(gap, limit time.Duration) {
				end := time.Now().Add(limit)
				for time.Now().Before(end) && time.Since(time.Unix(0, lastLog.Load())) < gap {
					time.Sleep(gap / 4)
				}
			}
			defer quiet(300*time.Millisecond, 10*time.Second)

			flood := initiation(t, 1)
			const burst = 20
			var delta int64 = -1
			deadline := time.Now().Add(10 * time.Second)
			for time.Now().Before(deadline) {
				// 回ごとに作り直す。cookie reply は洪水の MAC1 で暗号化され、前の回の AddMacs で
				// 覚えた MAC1 では開けない。洪水の packet は同じ中身なので、MAC1 も毎回同じになる。
				var gen device.CookieGenerator
				gen.Init(device.NoisePublicKey(key.PublicKey()))
				gen.AddMacs(flood)
				for i := 0; i < 3000; i++ {
					if _, err := client.WriteToUDPAddrPort(flood, server); err != nil {
						t.Fatal(err)
					}
				}
				reply, ok := readCookieReply(client, 1, 500*time.Millisecond)
				if !ok {
					continue // まだ負荷の高い状態に入っていない
				}
				if !gen.ConsumeReply(reply) {
					t.Fatal("cookie reply did not decrypt")
				}
				// 洪水の分を処理し終えてから数え始める。負荷の高い状態は最後の検出から 1 秒続く。
				quiet(50*time.Millisecond, 500*time.Millisecond)
				before := passed.Load()
				for i := 0; i < burst; i++ {
					valid := initiation(t, uint32(2+i))
					gen.AddMacs(valid)
					if _, err := client.WriteToUDPAddrPort(valid, server); err != nil {
						t.Fatal(err)
					}
				}
				time.Sleep(200 * time.Millisecond)
				quiet(100*time.Millisecond, time.Second)
				delta = passed.Load() - before
				if delta >= 1 && delta <= burst/2 {
					t.Logf("%d of %d MAC2-valid initiations passed the limiter", delta, burst)
					return
				}
			}
			if raceEnabled && (delta < 0 || delta == burst) {
				// race detector は受信の経路を遅くし、洪水の速さが worker の処理を上回らないことや、
				// 負荷の高い状態が MAC2 の正しい initiation を処理する前に終わることがある。
				t.Skipf("the flood did not keep the Device under load under the race detector; last result %d of %d", delta, burst)
			}
			if delta < 0 {
				t.Fatal("the flood never put the Device under load; no cookie reply arrived")
			}
			t.Fatalf("%d of %d MAC2-valid initiations reached the handshake consumer; want between 1 and %d, throttled by the limiter", delta, burst, burst/2)
		})
	}
}

func initiation(t *testing.T, sender uint32) []byte {
	t.Helper()
	p := make([]byte, device.MessageInitiationSize)
	binary.LittleEndian.PutUint32(p[0:], device.MessageInitiationType)
	binary.LittleEndian.PutUint32(p[4:], sender)
	if _, err := rand.Read(p[8 : 8+device.NoisePublicKeySize]); err != nil {
		t.Fatal(err)
	}
	return p
}

// readCookieReply は、受信者の番号が receiver の cookie reply を待つ。
func readCookieReply(c *net.UDPConn, receiver uint32, wait time.Duration) (*device.MessageCookieReply, bool) {
	buf := make([]byte, 2048)
	end := time.Now().Add(wait)
	for {
		_ = c.SetReadDeadline(end)
		n, _, err := c.ReadFromUDPAddrPort(buf)
		if err != nil {
			return nil, false
		}
		if n != device.MessageCookieReplySize || binary.LittleEndian.Uint32(buf) != device.MessageCookieReplyType ||
			binary.LittleEndian.Uint32(buf[4:]) != receiver {
			continue
		}
		r := &device.MessageCookieReply{Type: device.MessageCookieReplyType, Receiver: receiver}
		copy(r.Nonce[:], buf[8:32])
		copy(r.Cookie[:], buf[32:64])
		return r, true
	}
}

func newKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func hexKey(k wgtypes.Key) string { return hex.EncodeToString(k[:]) }

func testDevice(t *testing.T, addr string, key wgtypes.Key, logger ...*device.Logger) *device.Device {
	t.Helper()
	tnet, err := nettun.Create(netip.MustParseAddr(addr), 1420)
	if err != nil {
		t.Fatal(err)
	}
	l := device.NewLogger(device.LogLevelSilent, "")
	if len(logger) > 0 {
		l = logger[0]
	}
	var td tun.Device = tnet
	d := NewDevice(td, New(), l)
	t.Cleanup(d.Close)
	mustSet(t, d, fmt.Sprintf("private_key=%s\nlisten_port=0\n", hexKey(key)))
	if err := d.Up(); err != nil {
		t.Fatal(err)
	}
	return d
}

func mustSet(t *testing.T, d *device.Device, s string) {
	t.Helper()
	if err := d.IpcSet(s); err != nil {
		t.Fatal(err)
	}
}

func uapi(t *testing.T, d *device.Device) []string {
	t.Helper()
	s, err := d.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(s, "\n")
}

func listenPort(t *testing.T, d *device.Device) uint16 {
	t.Helper()
	for _, line := range uapi(t, d) {
		if v, ok := strings.CutPrefix(line, "listen_port="); ok {
			var p uint16
			fmt.Sscan(v, &p)
			return p
		}
	}
	t.Fatal("no listen_port")
	return 0
}

// waitPeer は、唯一のピアの UAPI の endpoint とハンドシェイクの有無が ok を満たすまで待つ。
func waitPeer(t *testing.T, d *device.Device, ok func(endpoint string, handshake bool) bool, what string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var ep string
	for time.Now().Before(deadline) {
		ep = ""
		hs := false
		for _, line := range uapi(t, d) {
			if v, found := strings.CutPrefix(line, "endpoint="); found {
				ep = v
			}
			if v, found := strings.CutPrefix(line, "last_handshake_time_sec="); found && v != "0" {
				hs = true
			}
		}
		if ok(ep, hs) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s; endpoint=%q", what, ep)
}
