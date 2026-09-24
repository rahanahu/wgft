package relay

import (
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// フロー予算はエージェントでも Manager から読める。エージェントは Pool を渡さないので、New が
// 作った Pool に届く経路はこの入口だけである(設計文書 10.2c 節の relay.refusals)。
func TestManagerExposesTheFlowBudgets(t *testing.T) {
	udp, tcp := resource.NewPool(4), resource.NewPool(4)
	m := New(&loopback{}, Options{UDPPool: udp, TCPPool: tcp, Logf: testLogf(t)})
	if m.UDPPool() != udp || m.TCPPool() != tcp {
		t.Error("a pool given through Options must be the one the accessors return")
	}

	m = New(&loopback{}, Options{Limits: resource.Limits{UDPTotal: 32, TCPTotal: 24}, Logf: testLogf(t)})
	if got := m.UDPPool(); got == nil || got.Total() != 32 {
		t.Errorf("derived UDP pool = %+v, want a pool with total 32", got)
	}
	if got := m.TCPPool(); got == nil || got.Total() != 24 {
		t.Errorf("derived TCP pool = %+v, want a pool with total 24", got)
	}
}

// 拒否の数は Manager から読める。Pool を渡さないエージェントの形で確かめる。
func TestManagerReportsFlowBudgetRefusals(t *testing.T) {
	target := tcpEcho(t)
	lb := &loopback{}
	port := reserveTCP(t, lb)
	// 予算 1 なので、2 本目の接続は予算で拒まれる
	m := New(lb, Options{Limits: resource.Limits{TCPTotal: 1}, Logf: testLogf(t)})
	defer m.Close()
	m.Apply(map[Key]Desired{{proto.TCP, port}: {target, "r1"}})

	addr := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	held, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	held.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := held.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(held, make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
	// 拒まれる接続は accept の直後に RST で終わる。ループバックでは connect が成功してから
	// 最初の読み取りで届くこともあるので、どちらの形も許す
	if refused, err := net.Dial("tcp4", addr); err == nil {
		refused.SetDeadline(time.Now().Add(2 * time.Second))
		io.ReadFull(refused, make([]byte, 1))
		refused.Close()
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		n := m.TCPPool().Refusals()["r1"][resource.ReasonBudget]
		if n >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no budget refusal was recorded for rule r1: %+v", m.TCPPool().Refusals())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
