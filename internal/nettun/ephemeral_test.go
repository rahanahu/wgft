package nettun

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// tcpInState は d の stack に登録された TCP の endpoint のうち st にあるものの数を返す。
func tcpInState(d *Device, st tcp.EndpointState) int {
	n := 0
	for _, ep := range d.stack.RegisteredEndpoints() {
		if e, ok := ep.(*tcp.Endpoint); ok && e.EndpointState() == st {
			n++
		}
	}
	return n
}

// narrowPorts は d の一時ポートを n 個に絞る。Create の設定の上から、同じ仕組みを小さな数で試す。
func narrowPorts(t *testing.T, d *Device, n uint16) {
	t.Helper()
	if terr := d.stack.SetPortRange(ephemeralFirst, ephemeralFirst+n-1); terr != nil {
		t.Fatalf("SetPortRange: %s", terr)
	}
}

func dialTo(d *Device, ap netip.AddrPort, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.DialTCP(ctx, ap)
}

// Create は、どの TCP の endpoint よりも前に、一時ポートの範囲と TIME_WAIT の再利用を設定する。
func TestEphemeralPortsConfigured(t *testing.T) {
	d, err := Create(netip.MustParseAddr("10.98.0.1"), 1420)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { d.Close(); d.Wait() }()
	if first, last := d.stack.PortRange(); first != 49152 || last != 65535 {
		t.Fatalf("ephemeral range %d-%d, want 49152-65535", first, last)
	}
	var reuse tcpip.TCPTimeWaitReuseOption
	if terr := d.stack.TransportProtocolOption(tcp.ProtocolNumber, &reuse); terr != nil {
		t.Fatal(terr)
	}
	if reuse != tcpip.TCPTimeWaitReuseGlobal {
		t.Fatalf("TIME_WAIT reuse %d, want Global", reuse)
	}
}

// dial した側が先に閉じると、その側の endpoint は TIME_WAIT に残り、宛先ごとの予約を持ち続ける。
// 一時ポートが n 個なら、同じ宛先への TIME_WAIT は n 本を超えない。最後の受信から 1 秒を過ぎた
// TIME_WAIT のポートは再利用され、同じ宛先へ n 本を超えて開閉を続けられる。1 秒未満のものは譲らない。
func TestTimeWaitReuseBoundsPerDestination(t *testing.T) {
	const n = 16
	p := newTCPPair(t, 1)
	narrowPorts(t, p.a, n)
	round := func(r int) {
		for i := 0; i < n; i++ {
			c, s := p.dial(t)
			c.Write([]byte("x"))
			if _, err := io.ReadFull(s, make([]byte, 1)); err != nil {
				t.Fatal(err)
			}
			c.Close()
			io.Copy(io.Discard, s)
			s.Close()
			if tw := tcpInState(p.a, tcp.StateTimeWait); tw > n {
				t.Fatalf("round %d: %d TIME-WAIT endpoints toward one destination, want at most %d", r, tw, n)
			}
		}
	}
	round(1)
	time.Sleep(200 * time.Millisecond)
	if tw := tcpInState(p.a, tcp.StateTimeWait); tw != n {
		t.Fatalf("setup: %d TIME-WAIT endpoints, want %d", tw, n)
	}
	// 1 秒未満の TIME_WAIT は譲らない。gVisor の 2 つの stack の間ではタイムスタンプが使われる
	if c, err := dialTo(p.a, netip.AddrPortFrom(p.b.local, 9000), 2*time.Second); err == nil {
		c.Close()
		t.Fatal("a TIME-WAIT port younger than one second was reused")
	}
	time.Sleep(time.Second)
	round(2)
	time.Sleep(200 * time.Millisecond)
	if tw := tcpInState(p.a, tcp.StateTimeWait); tw != n {
		t.Fatalf("after reuse: %d TIME-WAIT endpoints, want %d", tw, n)
	}
}

// 宛先の予約がすべて埋まると、その宛先への dial は待たずに失敗する。予約は宛先ごとなので、
// 同じ Device の別のポートへの dial は成功する。
func TestEphemeralExhaustionFailsOnlyThatDestination(t *testing.T) {
	const n = 8
	p := newTCPPair(t, 1)
	narrowPorts(t, p.a, n)
	ln2, err := p.b.ListenTCP(netip.AddrPortFrom(p.b.local, 9001))
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	go func() {
		for {
			c, err := ln2.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	var held []net.Conn
	defer func() {
		for _, c := range held {
			c.Close()
		}
	}()
	for i := 0; i < n; i++ {
		c, s := p.dial(t)
		held = append(held, c, s)
	}
	start := time.Now()
	c, err := dialTo(p.a, netip.AddrPortFrom(p.b.local, 9000), 5*time.Second)
	if err == nil {
		c.Close()
		t.Fatal("dial succeeded with every port toward the destination in use")
	}
	if !strings.Contains(err.Error(), "no ports are available") {
		t.Fatalf("dial error %q, want the port exhaustion error", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("the failing dial took %v, want an immediate failure", d)
	}
	other, err := dialTo(p.a, netip.AddrPortFrom(p.b.local, 9001), 5*time.Second)
	if err != nil {
		t.Fatalf("dial to another destination: %v", err)
	}
	other.Close()
}

// 受けた側が先に閉じると、受けた側の endpoint が TIME_WAIT に残る。4 つ組は一意なので、その数は
// dial した側の一時ポートの数を超えない。同じ 4 つ組への新しい SYN は、系列番号が前の接続より
// 進んでいれば TIME_WAIT から待ち受けへ渡り、SYN の再送を待たずに成立する。系列番号は時刻で
// 進むので、dial の間を空ける。Windows の単調な時計は刻みが粗く、間を空けないと同じ時刻に読めて
// 系列番号が進まず、SYN が捨てられる。
func TestTimeWaitOnAcceptedSideBoundedBySourcePorts(t *testing.T) {
	const n = 16
	p := newTCPPair(t, 1)
	narrowPorts(t, p.a, n)
	var slowest time.Duration
	for i := 0; i < 4*n; i++ {
		time.Sleep(20 * time.Millisecond)
		start := time.Now()
		c, s := p.dial(t)
		if d := time.Since(start); d > slowest {
			slowest = d
		}
		c.Write([]byte("x"))
		if _, err := io.ReadFull(s, make([]byte, 1)); err != nil {
			t.Fatal(err)
		}
		s.Close()
		io.Copy(io.Discard, c)
		c.Close()
		if tw := tcpInState(p.b, tcp.StateTimeWait); tw > n {
			t.Fatalf("%d TIME-WAIT endpoints on the accepting side, want at most %d", tw, n)
		}
	}
	// SYN が捨てられて再送を待つと、gVisor の最初の再送の間隔の 1 秒かかる
	if slowest >= 900*time.Millisecond {
		t.Fatalf("slowest dial %v, want no SYN retransmission", slowest)
	}
	if tcpInState(p.a, tcp.StateTimeWait) != 0 {
		t.Fatal("the dialing side entered TIME-WAIT although the accepting side closed first")
	}
}

// 固定版の gVisor は、TIME_WAIT の 4 つ組へ届いた SYN を、系列番号が前の接続の受信の位置より
// 進んでいるときだけ待ち受けへ渡し、そうでなければ黙って捨てる。比較は 32 ビットの循環の比較で、
// 同じ 4 つ組の初期の系列番号は 64 ns ごとに 1 進むので、受け入れられるのは、前の SYN からの
// 経過を 64 ns で数えた値から前の接続の受信の進み(データと SYN と FIN)を引いた差が、int32 として
// 正のときだけである(設計文書 7 節「TIME_WAIT の 4 つ組への SYN」)。捨てられると SYN の再送も
// 捨てられ、dial は期限まで成立しない。ここでは経過が短い場合だけを試す。一時ポートを 1 つにして
// 同じ 4 つ組を選ばせ、経過と送った量の比から成否を予測して確かめる。予測が境界に近い回は
// 判定しない。速さは環境で変わる(-race では遅い)。判定できた回が無ければ落とす。経過が約 137 秒
// を超える長い接続の場合は時間がかかるので試さない。gVisor の更新でこの性質が変われば落ちるので、
// 設計文書を直す。
func TestTimeWaitSYNAfterFastTransfer(t *testing.T) {
	judged := 0
	for _, size := range []int{1, 1 << 20, 8 << 20} {
		p := newTCPPair(t, 1)
		narrowPorts(t, p.a, 1)
		t0 := time.Now()
		c, s := p.dial(t)
		go c.Write(make([]byte, size))
		if _, err := io.ReadFull(s, make([]byte, size)); err != nil {
			t.Fatal(err)
		}
		s.Close()
		io.Copy(io.Discard, c)
		c.Close()
		// dial した側が LAST_ACK を抜け、ただ 1 つのポートが空くまで待つ
		for deadline := time.Now().Add(2 * time.Second); tcpInState(p.a, tcp.StateLastAck) != 0 || tcpInState(p.a, tcp.StateCloseWait) != 0; {
			if time.Now().After(deadline) {
				t.Fatal("setup: the dialing side did not reach CLOSED")
			}
			time.Sleep(time.Millisecond)
		}
		// 系列番号の進みと、前の接続の受信の位置の進み(データと SYN と FIN)の比
		ratio := float64(time.Since(t0).Nanoseconds()/64) / float64(size+2)
		c2, err := dialTo(p.a, netip.AddrPortFrom(p.b.local, 9000), 1500*time.Millisecond)
		if c2 != nil {
			c2.Close()
		}
		switch {
		case ratio > 1.3:
			if err != nil {
				t.Fatalf("after %d bytes at ratio %.2f: dial error %v, want success", size, ratio, err)
			}
			judged++
		case ratio < 0.7:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("after %d bytes at ratio %.2f: dial error %v, want the deadline to expire on dropped SYNs", size, ratio, err)
			}
			judged++
		default:
			t.Logf("after %d bytes: ratio %.2f is near the boundary, not judged", size, ratio)
		}
	}
	if judged == 0 {
		t.Fatal("no case was judged")
	}
}
