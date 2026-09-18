package relay

import (
	"net"
	"net/netip"
	"sync"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/netpipe"
)

func (m *Manager) startTCP(l *listener) error {
	ln, err := m.net.ListenTCP(l.key.Port)
	if err != nil {
		return err
	}
	var (
		mu    sync.Mutex
		conns = map[net.Conn]netip.Addr{} // 公開側の接続はその接続元、target 側はゼロ値
		done  = make(chan struct{})
		// public は公開側の接続の数(同時フロー数の上限の対象。conns は target 側も含む)
		public  int
		capLog  flowcap.LogGate // 上限で拒んだログの頻度
		dialLog flowcap.LogGate // target への dial 失敗のログの頻度(target が落ちている間、接続のたびに鳴らさない)
	)
	l.flows = func() int { mu.Lock(); defer mu.Unlock(); return public }
	l.sessions = func() int { mu.Lock(); defer mu.Unlock(); return len(conns) }
	l.sweep = func(keep func(src netip.Addr) bool) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for c, src := range conns {
			if src.IsValid() && !keep(src) {
				c.Close()
				n++
			}
		}
		return n
	}
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
			src := addrOf(c.RemoteAddr())
			if m.opts.Admit != nil && !m.opts.Admit(m.ruleOf(l), src) {
				c.Close()
				continue
			}
			// 同時フロー数の上限(仕様 7 節)。超えた接続はすぐ閉じる(既存の接続は追い出さない)
			if m.ruleFlows(m.ruleOf(l)) >= m.opts.TCPConnsMax || !m.opts.TCPCap.Acquire(src) {
				c.Close()
				if capLog.Allow() {
					m.opts.Logf("tcp %s: connection limit reached; refusing new connections", l.key)
				}
				continue
			}
			mu.Lock()
			conns[c] = src
			public++
			mu.Unlock()
			go func() {
				defer func() {
					mu.Lock()
					delete(conns, c)
					public--
					mu.Unlock()
					m.opts.TCPCap.Release(src)
				}()
				t, err := m.opts.Dial("tcp", l.target)
				if err != nil {
					if dialLog.Allow() {
						m.opts.Logf("tcp %s: dial %s: %v", l.key, l.target, err)
					}
					c.Close()
					return
				}
				mu.Lock()
				conns[t] = netip.Addr{}
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
