package relay

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// udpSession は (送信元 IP, 送信元ポート) ごとの、target への接続。
// エージェントから見た送信元は VPS の masquerade により常に 10.200.0.1 なので、実質は送信元ポートで区別される。
type udpSession struct {
	conn     net.Conn
	lastSeen atomic.Int64 // UnixNano
}

func (m *Manager) startUDP(l *listener) error {
	pc, err := m.net.ListenUDP(l.key.Port)
	if err != nil {
		return err
	}
	var (
		mu       sync.Mutex
		sessions = map[string]*udpSession{}
		done     = make(chan struct{})
	)
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(sessions) }
	l.sessions = count
	closeSession := func(k string, s *udpSession) {
		mu.Lock()
		if sessions[k] == s {
			delete(sessions, k)
		}
		mu.Unlock()
		s.conn.Close()
	}
	l.closeF = func() {
		close(done)
		pc.Close()
		mu.Lock()
		all := sessions
		sessions = map[string]*udpSession{}
		mu.Unlock()
		for _, s := range all {
			s.conn.Close()
		}
	}

	// 無通信のセッションを閉じる
	go func() {
		t := time.NewTicker(m.opts.UDPIdleTimeout / 4)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				cutoff := time.Now().Add(-m.opts.UDPIdleTimeout).UnixNano()
				mu.Lock()
				var expired []string
				for k, s := range sessions {
					if s.lastSeen.Load() < cutoff {
						expired = append(expired, k)
					}
				}
				var victims []*udpSession
				for _, k := range expired {
					victims = append(victims, sessions[k])
					delete(sessions, k)
				}
				mu.Unlock()
				for _, s := range victims {
					s.conn.Close()
				}
			}
		}
	}()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				select {
				case <-done:
				default:
					m.opts.Logf("udp %s: read: %v", l.key, err)
				}
				return
			}
			k := from.String()
			mu.Lock()
			s := sessions[k]
			mu.Unlock()
			if s == nil {
				// ルールごとの上限。超えた新規パケットは捨てる(既存セッションは追い出さない)
				if m.ruleSessions(m.ruleOf(l)) >= m.opts.UDPSessionsMax {
					continue
				}
				// target のホスト名はセッション確立時に解決する(DNS の変更は新規セッションだけに効く)
				c, err := m.opts.Dial("udp", l.target)
				if err != nil {
					m.opts.Logf("udp %s: dial %s: %v", l.key, l.target, err)
					continue
				}
				s = &udpSession{conn: c}
				s.lastSeen.Store(time.Now().UnixNano())
				mu.Lock()
				if existing := sessions[k]; existing != nil {
					s.conn.Close()
					s = existing
				} else {
					sessions[k] = s
				}
				mu.Unlock()
				go func(k string, s *udpSession, from net.Addr) {
					defer closeSession(k, s)
					rb := make([]byte, 65535)
					for {
						rn, err := s.conn.Read(rb)
						if err != nil {
							return
						}
						s.lastSeen.Store(time.Now().UnixNano())
						if _, err := pc.WriteTo(rb[:rn], from); err != nil {
							return
						}
					}
				}(k, s, from)
			}
			s.lastSeen.Store(time.Now().UnixNano())
			if _, err := s.conn.Write(buf[:n]); err != nil {
				closeSession(k, s)
			}
		}
	}()
	return nil
}
