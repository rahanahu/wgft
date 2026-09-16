package relay

import (
	"fmt"
	"io"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// loopback はホストの 127.0.0.1 に開く Network。テスト用。
type loopback struct{}

func (loopback) ListenUDP(port uint16) (net.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
}
func (loopback) ListenTCP(port uint16) (net.Listener, error) {
	return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
}

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
