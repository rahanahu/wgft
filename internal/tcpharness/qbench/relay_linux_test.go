//go:build qbench && linux

package qbench

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"
)

// TestQBenchRelayStage measures the one stage the wgstack-rs engine adds to every connection,
// the relay between the engine's connection and the Unix socket the rig reads
// (docs/design/v2/test-tooling.md section 5): wgstack-dut --relay copies between two Unix
// sockets with the same relay, without the engine. It prints the thin stream's latency through
// the relay and through a direct Unix socket, and the relay's CPU time per byte of a bulk copy.
// It needs WGFT_TEST_WGSTACK_DUT and prints, without judging.
func TestQBenchRelayStage(t *testing.T) {
	bin := os.Getenv(wgstackRSEnv)
	if bin == "" {
		t.Skipf("set %s to the wgstack-dut binary", wgstackRSEnv)
	}
	direct := func() (net.Conn, net.Conn, func() time.Duration, func()) {
		a, b := unixPair(t)
		return a, b, func() time.Duration { return -1 }, func() {}
	}
	relayed := func() (net.Conn, net.Conn, func() time.Duration, func()) {
		return relayPair(t, bin)
	}
	for _, way := range []struct {
		name string
		open func() (net.Conn, net.Conn, func() time.Duration, func())
	}{{"direct", direct}, {"relay", relayed}} {
		for run := range envInt("QBENCH_RUNS", 5) {
			a, b, cpu, done := way.open()
			lat := thinThrough(t, a, b, thinLen)
			a.Close()
			b.Close()
			done()
			a, b, cpu, done = way.open()
			n, d := bulkThrough(t, a, b, 256<<20)
			c := cpu()
			a.Close()
			b.Close()
			done()
			ns := "-"
			if c > 0 {
				ns = strconv.FormatFloat(float64(c)/float64(n), 'f', 3, 64)
			}
			fmt.Printf("QBENCH-RELAY way=%s run=%d thin_p50=%s thin_p99=%s thin_max=%s bulk_bytes=%d bulk_mbps=%.0f cpu=%s cpu_ns_per_byte=%s\n",
				way.name, run, quantile(lat, 0.5), quantile(lat, 0.99), lat[len(lat)-1], n, float64(n)*8/d.Seconds()/1e6, dur(c), ns)
		}
	}
}

// unixPair is a connected pair of Unix stream sockets.
func unixPair(t *testing.T) (net.Conn, net.Conn) {
	path := filepath.Join(t.TempDir(), "p")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		acc <- c
	}()
	a, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return a, <-acc
}

// relayPair starts wgstack-dut --relay between two Unix sockets and returns the rig's ends of
// both, the relay process's CPU time so far, and a function that waits for the process to end.
func relayPair(t *testing.T, bin string) (net.Conn, net.Conn, func() time.Duration, func()) {
	dir := t.TempDir()
	var lns [2]net.Listener
	for i := range lns {
		ln, err := net.Listen("unix", filepath.Join(dir, strconv.Itoa(i)))
		if err != nil {
			t.Fatal(err)
		}
		lns[i] = ln
	}
	cmd := exec.Command(bin, "--relay", lns[0].Addr().String(), lns[1].Addr().String())
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var ends [2]net.Conn
	for i, ln := range lns {
		c, err := ln.Accept()
		ln.Close()
		if err != nil {
			t.Fatal(err)
		}
		ends[i] = c
	}
	p := &rsProc{cmd: cmd}
	return ends[0], ends[1], p.cpu, func() { cmd.Wait() }
}

// thinThrough writes 200 bytes every 20 ms into a for d and returns, per message, the time from
// its slot to the read on b that completes it, sorted.
func thinThrough(t *testing.T, a, b net.Conn, d time.Duration) []time.Duration {
	slots := int(d / thinEvery)
	start := time.Now()
	go func() {
		msg := make([]byte, thinSize)
		for i := range slots {
			time.Sleep(time.Until(start.Add(time.Duration(i) * thinEvery)))
			if _, err := a.Write(msg); err != nil {
				return
			}
		}
	}()
	b.SetReadDeadline(start.Add(d + 5*time.Second))
	buf := make([]byte, 64<<10)
	var lat []time.Duration
	got := 0
	for len(lat) < slots {
		n, err := b.Read(buf)
		now := time.Now()
		got += n
		for len(lat) < slots && (len(lat)+1)*thinSize <= got {
			lat = append(lat, now.Sub(start.Add(time.Duration(len(lat))*thinEvery)))
		}
		if err != nil {
			t.Fatalf("thin read after %d of %d messages: %v", len(lat), slots, err)
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	return lat
}

// bulkThrough writes size bytes into a as fast as b reads them and returns the bytes read and
// the time it took.
func bulkThrough(t *testing.T, a, b net.Conn, size int) (int64, time.Duration) {
	start := time.Now()
	go func() {
		buf := make([]byte, 32<<10)
		for left := size; left > 0; left -= len(buf) {
			if _, err := a.Write(buf[:min(len(buf), left)]); err != nil {
				return
			}
		}
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}()
	n, err := io.Copy(io.Discard, b)
	if err != nil || n != int64(size) {
		t.Fatalf("bulk copy: %d of %d bytes: %v", n, size, err)
	}
	return n, time.Since(start)
}
