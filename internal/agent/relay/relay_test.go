package relay

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/proto"
)

// loopback はホストの 127.0.0.1 に開く Network。テスト用。
type loopback struct{}

func (loopback) ListenUDP(port uint16) (net.PacketConn, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err == nil {
		bigSendBuffer(c)
	}
	return c, err
}

func (loopback) ListenTCP(port uint16) (net.Listener, error) {
	return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
}

// bigSendBuffer はテスト側のソケットで 65535 バイトまでのデータグラムを書けるようにする。
// macOS の既定の SO_SNDBUF(9216 バイト)では大きい書き込みが EMSGSIZE で失敗し、
// relay の宛先側ではなくテスト側で落ちてしまう。production の公開側は netstack なので、この制限を受けない。
func bigSendBuffer(c *net.UDPConn) { c.SetWriteBuffer(udpBufMax) }

func pr(lo, hi uint16) proto.PortRange { return proto.PortRange{Lo: lo, Hi: hi} }

func TestDesiredFromRules(t *testing.T) {
	rules := []proto.AgentRule{
		{ID: "a", Proto: proto.UDP, ListenPort: pr(2456, 2458), Target: "192.168.1.20:3000", Enabled: true},
		{ID: "b", Proto: proto.TCP, ListenPort: pr(25565, 25565), Target: "nas.lan:25565", Enabled: true},
		{ID: "off", Proto: proto.TCP, ListenPort: pr(80, 80), Target: "h:80", Enabled: false},
	}
	want := map[Key]Desired{
		{proto.UDP, 2456}:  {"192.168.1.20:3000", "a"},
		{proto.UDP, 2457}:  {"192.168.1.20:3001", "a"},
		{proto.UDP, 2458}:  {"192.168.1.20:3002", "a"},
		{proto.TCP, 25565}: {"nas.lan:25565", "b"},
	}
	if got := DesiredFromRules(rules); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

// 仕様 7 節の操作別挙動。
func TestPlan(t *testing.T) {
	cur := func(entries ...string) map[Key]*listener { // "udp/2456 host:1 r1"
		m := map[Key]*listener{}
		for _, e := range entries {
			var proto_ string
			var port uint16
			var target, rule string
			fmt.Sscanf(e, "%3s/%d %s %s", &proto_, &port, &target, &rule)
			k := Key{proto.Proto(proto_), port}
			m[k] = &listener{key: k, target: target, ruleID: rule}
		}
		return m
	}
	des := func(entries ...string) map[Key]Desired {
		m := map[Key]Desired{}
		for _, e := range entries {
			var proto_ string
			var port uint16
			var target, rule string
			fmt.Sscanf(e, "%3s/%d %s %s", &proto_, &port, &target, &rule)
			m[Key{proto.Proto(proto_), port}] = Desired{target, rule}
		}
		return m
	}
	tests := []struct {
		name    string
		current map[Key]*listener
		desired map[Key]Desired
		want    []string
	}{
		{"初回", cur(), des("udp/2456 h:2456 r1", "udp/2457 h:2457 r1"), []string{"open udp/2456", "open udp/2457"}},
		{"enabled=false:全ポートが消える", cur("udp/2456 h:2456 r1", "udp/2457 h:2457 r1"), des(), []string{"close udp/2456", "close udp/2457"}},
		{"target の変更:閉じ直す", cur("udp/2456 h:2456 r1"), des("udp/2456 h2:2456 r1"), []string{"reopen udp/2456"}},
		{"範囲の伸長:差分だけ開く", cur("udp/2456 h:2456 r1"), des("udp/2456 h:2456 r1", "udp/2457 h:2457 r1"), []string{"open udp/2457"}},
		{"範囲のずらし:実効宛先が変わったポートだけ閉じ直す", cur("udp/2456 h:2456 r1", "udp/2457 h:2457 r1"),
			des("udp/2457 h:2456 r1", "udp/2458 h:2457 r1"), []string{"close udp/2456", "reopen udp/2457", "open udp/2458"}},
		{"分割:実効宛先が同じならルール ID だけ移る", cur("udp/2456 h:2456 r1", "udp/2457 h:2457 r1"),
			des("udp/2456 h:2456 r1", "udp/2457 h:2457 r2"), []string{"relabel udp/2457"}},
		{"同じポートでもプロトコルが違えば別", cur("udp/2456 h:2456 r1"), des("tcp/2456 h:2456 r1"), []string{"open tcp/2456", "close udp/2456"}},
		{"変化なし", cur("udp/2456 h:2456 r1"), des("udp/2456 h:2456 r1"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, a := range plan(tt.current, tt.desired) {
				got = append(got, a.Op+" "+a.Key.String())
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// udpEcho は受けたものをそのまま返す UDP サーバ(ループバック)。
func udpEcho(t *testing.T) (addr string, packets *atomic.Int64) {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	bigSendBuffer(pc)
	packets = new(atomic.Int64)
	go func() {
		b := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(b)
			if err != nil {
				return
			}
			packets.Add(1)
			pc.WriteTo(b[:n], from)
		}
	}()
	return pc.LocalAddr().String(), packets
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	l, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	p := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return uint16(p)
}

func TestUDPRelaySessionsAndIdle(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	port := freePort(t)
	m := New(loopback{}, Options{UDPIdleTimeout: 200 * time.Millisecond, UDPSessionsMax: 2, Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r1"}})

	dial := func() *net.UDPConn {
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if err != nil {
			t.Fatal(err)
		}
		c.SetDeadline(time.Now().Add(2 * time.Second))
		return c
	}
	roundtrip := func(c *net.UDPConn, msg string) (string, error) {
		if _, err := c.Write([]byte(msg)); err != nil {
			return "", err
		}
		b := make([]byte, 100)
		n, err := c.Read(b)
		return string(b[:n]), err
	}
	c1, c2, c3 := dial(), dial(), dial()
	for i, c := range []*net.UDPConn{c1, c2} {
		if got, err := roundtrip(c, fmt.Sprint("m", i)); err != nil || got != fmt.Sprint("m", i) {
			t.Fatalf("client %d: %q %v", i, got, err)
		}
	}
	if n := m.Status()[0].Sessions; n != 2 {
		t.Errorf("sessions = %d, want 2", n)
	}
	// 3 つ目はルールの上限(2)で捨てられる。既存は生きている
	c3.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := roundtrip(c3, "over"); err == nil {
		t.Error("third session should be dropped at limit")
	}
	if got, err := roundtrip(c1, "still"); err != nil || got != "still" {
		t.Errorf("existing session broken: %q %v", got, err)
	}
	// 無通信で閉じる
	time.Sleep(500 * time.Millisecond)
	if n := m.Status()[0].Sessions; n != 0 {
		t.Errorf("sessions after idle = %d, want 0", n)
	}
	// 閉じた後でも同じ送信元から送れば新しいセッションになる
	if got, err := roundtrip(c1, "again"); err != nil || got != "again" {
		t.Errorf("new session after idle: %q %v", got, err)
	}
}

// TCP:ハーフクローズが端から端まで伝わり、両方向が閉じたら解放される。
func TestTCPRelayHalfClose(t *testing.T) {
	srv, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	// サーバ:client の EOF まで読んでから、読んだバイト数を返して閉じる
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func() {
				n, _ := io.Copy(io.Discard, c)
				fmt.Fprintf(c, "got %d", n)
				c.Close()
			}()
		}
	}()
	port := freePort(t)
	m := New(loopback{}, Options{Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, port}: {srv.Addr().String(), "r1"}})

	c, err := net.DialTCP("tcp4", nil, &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(3 * time.Second))
	payload := strings.Repeat("x", 50000)
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	c.CloseWrite() // 送信側だけ閉じる。応答はこの後に来る
	reply, err := io.ReadAll(c)
	if err != nil || string(reply) != "got 50000" {
		t.Fatalf("reply = %q, %v", reply, err)
	}
	deadline := time.Now().Add(time.Second)
	for m.Status()[0].Sessions != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := m.Status()[0].Sessions; n != 0 {
		t.Errorf("connections after close = %d, want 0", n)
	}
}

// 開けないポート(使用中)は error として残り、Retry で開き直す。
func TestOpenFailureAndRetry(t *testing.T) {
	port := freePort(t)
	blocker, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	m := New(loopback{}, Options{Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.UDP, port}: {"127.0.0.1:9", "r1"}})
	if st := m.Status(); len(st) != 1 || st[0].Err == nil {
		t.Fatalf("status = %+v, want error", st)
	}
	blocker.Close()
	m.Retry()
	if st := m.Status(); st[0].Err != nil {
		t.Errorf("after retry: %v", st[0].Err)
	}
}

// TCP ルールは、bind できても target に接続できなければ error。target が復帰したら Retry で ok に戻る。
func TestTCPTargetCheck(t *testing.T) {
	// まだ誰も listen していないポートを target にする(接続拒否)
	targetPort := freePort(t)
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(targetPort)))
	listenPort := freePort(t)
	m := New(loopback{}, Options{Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, listenPort}: {target, "r1"}})

	// bind はできるが target に繋がらない → error
	st := m.Status()
	if len(st) != 1 || st[0].Err == nil {
		t.Fatalf("target 不通なら error のはず: %+v", st)
	}

	// target のサービスを起動 → Retry で ok に戻る
	srv, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(targetPort)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	m.Retry()
	if st := m.Status(); st[0].Err != nil {
		t.Errorf("target 復帰後は ok のはず: %v", st[0].Err)
	}

	// target を落とす → Retry で再び error(リスナー自体は開いたまま)
	srv.Close()
	m.Retry()
	if st := m.Status(); st[0].Err == nil {
		t.Error("target が落ちたら error に戻るはず")
	}
}

// UDP ルールは target への接続確認をしない(到達確認ができないので、bind できれば ok)。
func TestUDPNoTargetCheck(t *testing.T) {
	target := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(freePort(t)))) // 誰も listen していない UDP 宛先
	listenPort := freePort(t)
	m := New(loopback{}, Options{Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.UDP, listenPort}: {target, "r1"}})
	if st := m.Status(); st[0].Err != nil {
		t.Errorf("UDP は target 確認をしないので ok のはず: %v", st[0].Err)
	}
}

// UDP:セッションは待つ間バッファを持たないが、最大長に近い応答も最初の 1 個から欠けずに届く(仕様 7 節)。
func TestUDPRelayLargeReplyFromFirstDatagram(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	port := freePort(t)
	m := New(loopback{}, Options{Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r1"}})
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	bigSendBuffer(c)
	b := make([]byte, 65535)
	for _, size := range []int{60000, 3, 2048, 9000} {
		msg := bytes.Repeat([]byte{byte('a' + size%26)}, size)
		c.Write(msg)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Read(b)
		if err != nil || !bytes.Equal(b[:n], msg) {
			t.Fatalf("reply of %d bytes: n=%d err=%v", size, n, err)
		}
	}
}

// failWriteConn は書き込みが常に失敗する宛先側の接続。テスト用。
type failWriteConn struct{ net.Conn }

func (failWriteConn) Write([]byte) (int, error) { return 0, errors.New("injected write failure") }

// UDP:宛先への書き込みの失敗はセッションを閉じ、ログはリスナーごとに 1 分に 1 回までに絞る。
func TestUDPRelayWriteFailureLogged(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	port := freePort(t)
	var (
		mu    sync.Mutex
		lines []string
		dials atomic.Int64
	)
	logf := func(format string, a ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, a...))
	}
	dial := func(network, addr string) (net.Conn, error) {
		c, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}
		dials.Add(1)
		return failWriteConn{c}, nil
	}
	m := New(loopback{}, Options{Logf: logf, Dial: dial})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r1"}})
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// 失敗のたびにセッションが閉じるので、同じ送信元からの 3 個はそれぞれ新しいセッションを張る。
	// 3 回目の Dial が見えた時点で、1 回目の書き込みとそのログは済んでいる
	deadline := time.Now().Add(2 * time.Second)
	for dials.Load() < 3 && time.Now().Before(deadline) {
		c.Write([]byte("x"))
		time.Sleep(20 * time.Millisecond)
	}
	if dials.Load() < 3 {
		t.Fatalf("dials = %d, want a new session per failed write", dials.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	var n int
	for _, l := range lines {
		if strings.Contains(l, "injected write failure") && strings.Contains(l, "closing session") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("write failure logged %d times, want 1; log: %q", n, lines)
	}
}

// UDP:プロセス全体と接続元 IP ごとの上限。枠はセッションが閉じると戻る。
func TestUDPRelayTotalAndPerSourceCap(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	port := freePort(t)
	cnt := &flowcap.Counter{Total: 10, PerSource: 2}
	m := New(loopback{}, Options{UDPIdleTimeout: 200 * time.Millisecond, UDPCap: cnt, Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r1"}})
	ok := func() bool {
		c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		c.Write([]byte("hi"))
		c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		_, err = c.Read(make([]byte, 10))
		return err == nil
	}
	for i := 1; i <= 2; i++ {
		if !ok() {
			t.Fatalf("session %d must pass", i)
		}
	}
	if ok() {
		t.Error("third session from the same source must be dropped")
	}
	time.Sleep(500 * time.Millisecond)
	if cnt.Len() != 0 {
		t.Errorf("counter after idle = %d, want 0", cnt.Len())
	}
	if !ok() {
		t.Error("a new session must pass after the old ones expired")
	}
}

// TCP:ルールごとの上限を超えた接続はすぐ閉じられ、既存の接続は生きている。閉じれば枠が戻る。
func TestTCPRelayConnCap(t *testing.T) {
	srv, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	go func() {
		for {
			c, err := srv.Accept()
			if err != nil {
				return
			}
			go func() { defer c.Close(); io.Copy(c, c) }()
		}
	}()
	port := freePort(t)
	cnt := &flowcap.Counter{Total: 10}
	m := New(loopback{}, Options{TCPConnsMax: 2, TCPCap: cnt, Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, port}: {srv.Addr().String(), "r1"}})
	echo := func(c net.Conn) error {
		c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := c.Write([]byte("x")); err != nil {
			return err
		}
		_, err := io.ReadFull(c, make([]byte, 1))
		return err
	}
	dial := func() net.Conn {
		c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	c1, c2 := dial(), dial()
	if err := echo(c1); err != nil {
		t.Fatal(err)
	}
	if err := echo(c2); err != nil {
		t.Fatal(err)
	}
	if err := echo(dial()); err == nil {
		t.Error("third connection must be closed at the limit")
	}
	if err := echo(c1); err != nil {
		t.Errorf("existing connection broken: %v", err)
	}
	c2.Close()
	deadline := time.Now().Add(2 * time.Second)
	for cnt.Len() != 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if cnt.Len() != 1 {
		t.Fatalf("counter after close = %d, want 1", cnt.Len())
	}
	if err := echo(dial()); err != nil {
		t.Errorf("connection after a slot was freed: %v", err)
	}
}
