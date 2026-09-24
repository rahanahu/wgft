package relay

import (
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// statusOf は指定したキーの状態を返す。Status() の並びはキーの文字列順なので、ポートの番号で
// 引き当てる。
func statusOf(t *testing.T, m *Manager, k Key) Status {
	t.Helper()
	for _, s := range m.Status() {
		if s.Key == k {
			return s
		}
	}
	t.Fatalf("status for %s is missing from %+v", k, m.Status())
	return Status{}
}

// bind に失敗した待ち受けと、bind は成功したが宛先に届かない待ち受けを、Status から区別して
// 読める(設計文書 10.2c 節の relay.listeners)。Err はどちらでも非 nil なので、Listening が
// 区別を持つ。
func TestStatusSeparatesBindFailureFromTargetFailure(t *testing.T) {
	target := tcpEcho(t)
	// blocker 自身を port 0 に bind して番号を読み戻す。番号だけを選んで一度閉じると、
	// Manager が bind するまでの隙間を他のプロセスに奪われる
	blocker, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer blocker.Close()
	blocked := uint16(blocker.Addr().(*net.TCPAddr).Port)

	lb := &loopback{}
	healthy := reserveTCP(t, lb)
	unreachable := reserveTCP(t, lb)
	deadTarget := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(freePort(t))))

	m := New(lb, Options{Logf: testLogf(t)})
	defer m.Close()
	m.Apply(map[Key]Desired{
		{proto.TCP, blocked}:     {target, "r1"},
		{proto.TCP, unreachable}: {deadTarget, "r2"},
		{proto.TCP, healthy}:     {target, "r3"},
	})

	bindFailed := statusOf(t, m, Key{proto.TCP, blocked})
	if bindFailed.Listening {
		t.Errorf("a listener that could not be bound must report Listening = false: %+v", bindFailed)
	}
	if bindFailed.Err == nil {
		t.Errorf("a bind failure must keep its reason in Err: %+v", bindFailed)
	}

	targetFailed := statusOf(t, m, Key{proto.TCP, unreachable})
	if !targetFailed.Listening {
		t.Errorf("a bound listener whose target is unreachable must report Listening = true: %+v", targetFailed)
	}
	if targetFailed.Err == nil {
		t.Errorf("an unreachable target must keep its reason in Err: %+v", targetFailed)
	}

	ok := statusOf(t, m, Key{proto.TCP, healthy})
	if !ok.Listening || ok.Err != nil {
		t.Errorf("a bound listener with a reachable target must be Listening with no error: %+v", ok)
	}

	// bind が通れば Listening は真に変わる。Err の意味は変えていないので、Retry の後も同じ経路で読める
	blocker.Close()
	m.Retry()
	rebound := statusOf(t, m, Key{proto.TCP, blocked})
	if !rebound.Listening || rebound.Err != nil {
		t.Errorf("after the port was freed and Retry ran: %+v", rebound)
	}
}

// 宛先が許可一覧の外にある IP リテラルのとき、中継は bind を試みず、待ち受けを持たない
// (設計文書 7 節)。Listening は待ち受けが開いているかどうかの項目なので、この場合も偽になる。
// 運用者の次の行動は 3 つ目、つまり WGFT_AGENT_ALLOW_TARGETS を直すことだが、その区別は
// Listening ではなく Err が持つ。
func TestStatusListeningIsFalseForATargetTheAllowListRefuses(t *testing.T) {
	var netw neverListen
	m := New(&netw, Options{
		Logf:              testLogf(t),
		AllowTarget:       allowList("192.168.1.20:25565"),
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		Dial:              func(network, addr string) (net.Conn, error) { t.Errorf("dialed %s", addr); return nil, nil },
	})
	defer m.Close()
	key := Key{proto.TCP, 39972}
	m.Apply(map[Key]Desired{key: {"192.168.1.1:22", "r1"}})

	st := statusOf(t, m, key)
	if st.Listening {
		t.Errorf("a target the allow list refuses leaves no listener open: %+v", st)
	}
	if !errors.Is(st.Err, ErrTargetNotAllowed) {
		t.Errorf("the reason must stay in Err: %v", st.Err)
	}
	if n := netw.opened.Load(); n != 0 {
		t.Errorf("tried to open a listener %d times, want 0 for a refused target", n)
	}
}
