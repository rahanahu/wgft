package relay

import (
	"net"
	"sync"

	"github.com/rahanahu/wgft/internal/netpipe"
)

func (m *Manager) startTCP(l *listener) error {
	ln, err := m.net.ListenTCP(l.key.Port)
	if err != nil {
		return err
	}
	var (
		mu    sync.Mutex
		conns = map[net.Conn]struct{}{}
		done  = make(chan struct{})
	)
	l.sessions = func() int { mu.Lock(); defer mu.Unlock(); return len(conns) }
	l.closeF = func() {
		close(done)
		ln.Close()
		// 中継中の TCP 接続もすべて閉じる(仕様 7 節:ポートが宣言から消えたとき)
		mu.Lock()
		for c := range conns {
			c.Close()
		}
		mu.Unlock()
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
				default:
					m.opts.Logf("tcp %s: accept: %v", l.key, err)
				}
				return
			}
			mu.Lock()
			conns[c] = struct{}{}
			mu.Unlock()
			go func() {
				defer func() {
					mu.Lock()
					delete(conns, c)
					mu.Unlock()
				}()
				t, err := m.opts.Dial("tcp", l.target)
				if err != nil {
					m.opts.Logf("tcp %s: dial %s: %v", l.key, l.target, err)
					c.Close()
					return
				}
				mu.Lock()
				conns[t] = struct{}{}
				mu.Unlock()
				defer func() {
					mu.Lock()
					delete(conns, t)
					mu.Unlock()
				}()
				netpipe.Pipe(c, t)
			}()
		}
	}()
	return nil
}
