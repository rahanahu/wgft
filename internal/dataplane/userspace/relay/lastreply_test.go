package relay

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// freeUDPPort は、今どの UDP のソケットも使っていない 127.0.0.1 の番号を返す。freePort と同じく
// 閉じてから返すので、この番号と重なってはならないソケットは、呼ぶ前に開けておく。
func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// udpSink は受けたデータグラムを捨て、何も返さない UDP の宛先(ループバック)。
func udpSink(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			if _, _, err := pc.ReadFrom(b); err != nil {
				return
			}
		}
	}()
	return pc.LocalAddr().String()
}

// sendTo は公開側の待ち受けへデータグラムを 1 つ送り、返事を wait の間だけ待つ。返事が来たかを返す。
func sendTo(t *testing.T, port uint16, wait time.Duration) bool {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(wait))
	_, err = c.Read(make([]byte, 16))
	return err == nil
}

// 宛先が応答すると、その待ち受けのルールに最後の応答の時刻が付く。送るだけで応答の無い宛先と、
// ICMP の port unreachable で拒む閉じたポートの宛先には付かない(設計文書 10.2a 節「UDP の応答の
// 観測」)。
func TestLastRepliesOnlyCountsDatagramsFromTheTarget(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	sinkAddr := udpSink(t)
	lb := &loopback{}
	echoPort, sinkPort, closedPort := reserveUDP(t, lb), reserveUDP(t, lb), reserveUDP(t, lb)
	// 閉じたポートは、ほかの UDP のソケットをすべて開けた後に UDP で選ぶ。先に選ぶと、後の bind が
	// 同じ番号を受け取り、閉じているはずの宛先が echo や待ち受けになることがある。TCP の freePort
	// では、番号が UDP の側で使われているかを確かめられない
	closed := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(freeUDPPort(t))))
	m := New(lb, Options{Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{
		{proto.UDP, echoPort}:   {echoAddr, "r_echo"},
		{proto.UDP, sinkPort}:   {sinkAddr, "r_sink"},
		{proto.UDP, closedPort}: {closed, "r_closed"},
	})
	if len(m.LastReplies()) != 0 {
		t.Fatalf("before any traffic: %v, want none", m.LastReplies())
	}
	before := time.Now()
	if !sendTo(t, echoPort, 2*time.Second) {
		t.Fatal("the echo target did not answer through the relay")
	}
	sendTo(t, sinkPort, 200*time.Millisecond)
	// 閉じたポートへは 2 回送る。1 回目の ICMP が接続済みのソケットに誤りを残し、2 回目の後の
	// 読み取りまで含めて応答として数えないことを確かめる
	sendTo(t, closedPort, 200*time.Millisecond)
	sendTo(t, closedPort, 200*time.Millisecond)

	got := m.LastReplies()
	if at, ok := got["r_echo"]; !ok || at.Before(before.Add(-time.Second)) || at.After(time.Now()) {
		t.Errorf("r_echo last reply = %v (present %v), want about now", at, ok)
	}
	for _, id := range []string{"r_sink", "r_closed"} {
		if at, ok := got[id]; ok {
			t.Errorf("%s has a last reply %v; it never answered", id, at)
		}
	}
}

// 最後の応答の時刻は待ち受けとともに生まれて消える。所属ルール ID だけが変わる relabel では残り、
// 宛先が変わる reopen では捨てられる。
func TestLastRepliesFollowTheListener(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	otherEcho, _ := udpEcho(t)
	lb := &loopback{}
	port := reserveUDP(t, lb)
	k := Key{proto.UDP, port}
	m := New(lb, Options{Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{k: {echoAddr, "r_a"}})
	if !sendTo(t, port, 2*time.Second) {
		t.Fatal("no answer")
	}
	m.Apply(map[Key]Desired{k: {echoAddr, "r_b"}})
	if _, ok := m.LastReplies()["r_b"]; !ok {
		t.Errorf("after relabel: %v, want the listener's time under r_b", m.LastReplies())
	}
	m.Apply(map[Key]Desired{k: {otherEcho, "r_b"}})
	if got := m.LastReplies(); len(got) != 0 {
		t.Errorf("after reopen: %v, want none", got)
	}
}

// 多数のセッションが同じ待ち受けの時刻を書いても競合しない(go test -race で意味を持つ)。
// 書き込みは 1 秒に 1 回までに間引く。
func TestLastReplyMarkIsThrottled(t *testing.T) {
	echoAddr, _ := udpEcho(t)
	lb := &loopback{}
	port := reserveUDP(t, lb)
	m := New(lb, Options{Logf: t.Logf})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.UDP, port}: {echoAddr, "r_a"}})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sendTo(t, port, 2*time.Second)
		}()
	}
	wg.Wait()
	first := m.LastReplies()["r_a"]
	if first.IsZero() {
		t.Fatal("no reply marked")
	}
	// 1 秒以内の次の応答は時刻を書き直さない
	if !sendTo(t, port, 2*time.Second) {
		t.Fatal("no answer")
	}
	if got := m.LastReplies()["r_a"]; time.Since(first) < time.Second && !got.Equal(first) {
		t.Errorf("mark rewritten within a second: %v then %v", first, got)
	}
}
