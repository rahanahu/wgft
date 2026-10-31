package wgbind

import (
	"errors"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/conn/bindtest"
)

type orderBind struct {
	conn.Bind
	log *[]string
	err error
}

func (b orderBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	*b.log = append(*b.log, "send")
	return b.err
}

// WatchSend は内側の Send の前に、同じ message の列を observe に渡し、内側の誤りをそのまま返す。受信の件数は
// 内側のままである。
func TestWatchSendObservesBeforeTheInnerSend(t *testing.T) {
	var log []string
	want := errors.New("inner")
	inner := orderBind{Bind: bindtest.NewChannelBinds()[0], log: &log, err: want}
	bufs := [][]byte{make([]byte, 40, 64), make([]byte, 40, 64)}
	b := WatchSend(inner, func(got [][]byte) {
		if &got[0][0] != &bufs[0][0] || len(got) != len(bufs) {
			t.Error("observe did not get the Send's own message slices")
		}
		log = append(log, "observe")
	})
	if err := b.Send(bufs, nil); err != want {
		t.Fatalf("Send = %v, want the inner error", err)
	}
	if len(log) != 2 || log[0] != "observe" || log[1] != "send" {
		t.Fatalf("order %v, want observe then send", log)
	}
	if b.BatchSize() != inner.BatchSize() {
		t.Fatalf("BatchSize %d, want the inner %d", b.BatchSize(), inner.BatchSize())
	}
	if allocs := testing.AllocsPerRun(100, func() { _ = b.Send(bufs, nil); log = log[:0] }); allocs != 0 {
		t.Fatalf("%.0f allocations per Send", allocs)
	}
}
