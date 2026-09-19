package proxyrelay

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
)

// A port that keeps failing to bind is logged once, not on every retry, and once more when it
// finally opens (design.md 7a.3 節: the data plane is retried every 30 s).
func TestBindFailureLoggedOnceAndRecovery(t *testing.T) {
	var mu sync.Mutex
	var lines []string
	busy := true
	m := New(Options{
		Listen: func(uint16) (net.Listener, error) {
			mu.Lock()
			defer mu.Unlock()
			if busy {
				return nil, errors.New("address already in use")
			}
			return net.Listen("tcp4", "127.0.0.1:0")
		},
		Logf: func(f string, a ...any) { mu.Lock(); lines = append(lines, fmt.Sprintf(f, a...)); mu.Unlock() },
	})
	t.Cleanup(m.Close)
	count := func(sub string) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for _, l := range lines {
			if strings.Contains(l, sub) {
				n++
			}
		}
		return n
	}
	for i := 0; i < 5; i++ {
		p := m.Prepare([]Rule{ruleOn("r", 8461)})
		if p.Failed()["r"] == nil {
			t.Fatal("want the bind to fail")
		}
		p.Commit(nil)
	}
	if n := count("cannot open listener for 8461"); n != 1 {
		t.Errorf("failure logged %d times over 5 attempts, want 1", n)
	}
	mu.Lock()
	busy = false
	mu.Unlock()
	m.Prepare([]Rule{ruleOn("r", 8461)}).Commit(nil)
	if n := count("8461: listener opened after 5 failed attempts"); n != 1 {
		t.Errorf("recovery logged %d times, want 1; log: %v", n, lines)
	}
	// a new failure after the recovery is logged again
	mu.Lock()
	busy = true
	mu.Unlock()
	m.Prepare(nil).Commit(nil)
	m.Prepare([]Rule{ruleOn("r", 8461)}).Commit(nil)
	if n := count("cannot open listener for 8461"); n != 2 {
		t.Errorf("a failure starting again was logged %d times in total, want 2", n)
	}
}
