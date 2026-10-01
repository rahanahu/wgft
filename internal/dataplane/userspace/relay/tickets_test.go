package relay

import (
	"sync/atomic"
	"testing"
	"time"
)

// ticketLedger は Admission Policy の枠(Options.Admit が返す release)の帳簿。出した枠の数、返した枠の
// 数、同じ枠を 2 回以上返した数を数える。Resource Guard の枠(resource.Lease)は Pool の帳簿が
// InUse と DoubleReleases で数えるので、2 つを合わせると、フロー 1 本の 2 つの枠の返し忘れと二重の
// 返却をどちらも検出できる。本物の goengine の Ticket は 2 回目の返却を黙って無視するので、ここで
// 数えないと policy の側の二重の返却は見えない。
type ticketLedger struct {
	issued, returned, doubles atomic.Int64
}

// issue は枠を 1 つ出し、その枠を返す関数を返す。
func (k *ticketLedger) issue() func() {
	k.issued.Add(1)
	var done atomic.Bool
	return func() {
		if !done.CompareAndSwap(false, true) {
			k.doubles.Add(1)
			return
		}
		k.returned.Add(1)
	}
}

func (k *ticketLedger) outstanding() int64 { return k.issued.Load() - k.returned.Load() }

// settle は返していない枠が 0 になるのを待ってから、全部を返し、どれも 2 回返していないことを確かめる。
// 待った後にも少し待ち、遅れて来る二重の返却を拾う。
func (k *ticketLedger) settle(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for k.outstanding() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(30 * time.Millisecond)
	if out := k.outstanding(); out != 0 {
		t.Errorf("policy tickets: %d of %d not returned", out, k.issued.Load())
	}
	if d := k.doubles.Load(); d != 0 {
		t.Errorf("policy tickets: %d returned twice", d)
	}
}
