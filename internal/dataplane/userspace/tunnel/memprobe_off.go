//go:build !labmemprobe

package tunnel

// startMemProbe は通常の build では何もしない。メモリの測定の hook は build tag labmemprobe の build だけが持つ
// (memprobe_on.go、lab/agentmem.sh)。
func startMemProbe(netstack) {}
