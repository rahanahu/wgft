package relay

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/rahanahu/wgft/proto"
)

// A key that keeps failing to bind on the staged path is logged once, not on every retry, and
// once more when it opens.
func TestStagedBindFailureLoggedOnce(t *testing.T) {
	// bind the blocker itself on port 0 and read back the assigned port, instead of picking a
	// number with freePort and then binding it: nothing else can ever steal a number that was
	// never released.
	blocker, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(blocker.Addr().(*net.TCPAddr).Port)
	var mu sync.Mutex
	var lines []string
	m := New(&loopback{}, Options{Logf: func(f string, a ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(f, a...))
		mu.Unlock()
	}})
	defer m.Close()
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
	desired := map[Key]Desired{{proto.TCP, port}: {"127.0.0.1:9", "r_x"}}
	key := Key{proto.TCP, port}.String()
	for i := 0; i < 4; i++ {
		s := m.Prepare(desired)
		if s.Failed()["r_x"] == nil {
			t.Fatal("want the bind to fail")
		}
		s.Commit(nil)
	}
	if n := count("listener " + key + ": listen"); n != 1 {
		t.Errorf("failure logged %d times over 4 attempts, want 1; log: %v", n, lines)
	}
	blocker.Close()
	m.Prepare(desired).Commit(nil)
	if n := count("listener " + key + ": opened after 4 failed attempts"); n != 1 {
		t.Errorf("recovery logged %d times, want 1; log: %v", n, lines)
	}
}
