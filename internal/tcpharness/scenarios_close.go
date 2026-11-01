package tcpharness

// The helpers of the close family, whose scenarios are scripts under scripts/.

import (
	"time"
)

func isFIN(s Segment) bool { return s.Has(FlagFIN) }
func isRST(s Segment) bool { return s.Has(FlagRST) }

// acks returns a matcher for an ACK that covers everything up to seq.
func acks(seq uint32) func(Segment) bool {
	return func(s Segment) bool { return s.Has(FlagACK) && !s.Has(FlagRST) && s.Ack == seq }
}

// delivered checks Deliverer where the engine offers it: after the close, the connection reports
// within 1 s that it has delivered everything.
func delivered(h *H, id string, c Conn) {
	h.T.Helper()
	d, ok := c.(Deliverer)
	if !ok {
		return
	}
	deadline := time.Now().Add(time.Second)
	for !d.Delivered() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	h.Check(id, d.Delivered(), "Delivered reports the closed connection as delivered", yesNo(d.Delivered(), "delivered", "not delivered"))
}
