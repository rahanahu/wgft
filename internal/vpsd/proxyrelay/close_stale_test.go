package proxyrelay

import (
	"net"
	"testing"
)

// Close より前に Prepare した Prepared を Close の後に Commit しても、待ち受けは公開されず、Prepare で
// 開いた待ち受けは閉じる。公開すると、Close の後にその待ち受けを閉じる経路が無い。
func TestCommitAfterCloseReleasesPrepared(t *testing.T) {
	ln := newAdmissionListener()
	m := New(Options{Listen: func(uint16) (net.Listener, error) { return ln, nil }, Logf: func(string, ...any) {}})
	p := m.Prepare([]Rule{admissionRule("r", 1)})
	m.Close()
	p.Commit(nil)
	admissionWait(t, ln.closed)
	m.mu.Lock()
	n := len(m.ls)
	m.mu.Unlock()
	if n != 0 {
		t.Errorf("Commit after Close published %d listeners", n)
	}
	if got := m.Pool().InUse(); got != 0 {
		t.Errorf("pool in use %d after Close", got)
	}
}
