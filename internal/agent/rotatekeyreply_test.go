package agent

import (
	"bufio"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 稼働中の rotate-key が読む応答には上限がある。制御ソケットの相手が改行を送らずに書き続けても、root の
// CLI は上限まで読んだところで諦める。上限が無いと、応答の期限まで読み続けてメモリを使う(仕様 11 節)。
func TestRotateKeyRunningStopsReadingAtTheReplyLimit(t *testing.T) {
	// sun_path に収まるよう、短い一時ディレクトリを使う
	dir, err := os.MkdirTemp("", "rk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "agent.json")
	ln, err := net.Listen("unix", ControlPath(path))
	if err != nil {
		t.Skipf("cannot listen on a Unix socket here: %v", err)
	}
	defer ln.Close()
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		bufio.NewReader(c).ReadString('\n')
		chunk := []byte(strings.Repeat("a", 64<<10))
		for range 4 * rotateKeyReplyLimit / len(chunk) {
			if _, err := c.Write(chunk); err != nil {
				return
			}
		}
		<-stop
	}()
	done := make(chan error, 1)
	go func() {
		_, err := rotateKeyRunning(path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("rotateKeyRunning accepted a reply with no line end")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rotateKeyRunning kept reading a reply with no line end past the limit")
	}
}
