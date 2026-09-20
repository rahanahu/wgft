package relay

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rahanahu/wgft/internal/lograte"
)

const udpBufMax = 65535

// udpSession は (送信元 IP, 送信元ポート) ごとの、target への接続。
// エージェントから見た送信元は VPS の masquerade により常に 10.200.0.1 なので、実質は送信元ポートで区別される。
type udpSession struct {
	conn     net.Conn
	lastSeen atomic.Int64 // UnixNano
}

// ReadWaiter は、バッファを持たずに次のデータグラムの到着を待てる接続。
// Dial が返す接続がこれを満たせば(vpsd の netstack の接続)、relay はそれを使う。
// カーネルのソケットは unix なら relay が自前で待つ。
type ReadWaiter interface {
	// WaitReadable は次の Read が待たずに戻る状態になるまで待つ。接続が閉じたら誤りを返す
	WaitReadable() error
}

func readWaiterOf(c net.Conn) ReadWaiter {
	if w, ok := c.(ReadWaiter); ok {
		return w
	}
	return kernelReadWaiter(c)
}

var udpBufPool = sync.Pool{New: func() any { b := make([]byte, udpBufMax); return &b }}

// forwardReply は target からの応答を 1 個読んで公開側へ返す。own が nil ならプールのバッファを借りる。
func forwardReply(s *udpSession, pc net.PacketConn, from net.Addr, own []byte) bool {
	rb := own
	if rb == nil {
		bp := udpBufPool.Get().(*[]byte)
		defer udpBufPool.Put(bp)
		rb = *bp
	}
	rn, err := s.conn.Read(rb)
	if err != nil {
		return false
	}
	s.lastSeen.Store(time.Now().UnixNano())
	_, err = pc.WriteTo(rb[:rn], from)
	return err == nil
}

func (m *Manager) startUDP(l *listener) error {
	pc, err := m.net.ListenUDP(l.key.Port)
	if err != nil {
		return err
	}
	m.serveUDP(l, pc)
	return nil
}

// serveUDP は開いたソケット pc で中継を始める。Prepare で開いたソケットは Commit でここに渡る。
func (m *Manager) serveUDP(l *listener, pc net.PacketConn) {
	var (
		mu       sync.Mutex
		sessions = map[string]*udpSession{}
		done     = make(chan struct{})
		capLog   lograte.Gate // 上限で拒んだログの頻度
		writeLog lograte.Gate // 宛先への書き込み失敗。上限のログとは別に 1 分に 1 回まで
		dialLog  lograte.Gate // target への dial 失敗のログの頻度(target が落ちている間、新規セッションのたびに鳴らさない)
	)
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(sessions) }
	l.sessions = count
	l.flows = count
	closeSession := func(k string, s *udpSession) {
		mu.Lock()
		if sessions[k] == s {
			delete(sessions, k)
		}
		mu.Unlock()
		s.conn.Close()
	}
	l.sweep = func(keep func(src netip.Addr) bool) int {
		mu.Lock()
		var victims []*udpSession
		for k, s := range sessions {
			if ap, err := netip.ParseAddrPort(k); err == nil && !keep(ap.Addr().Unmap()) {
				victims = append(victims, s)
				delete(sessions, k)
			}
		}
		mu.Unlock()
		for _, s := range victims {
			s.conn.Close()
		}
		return len(victims)
	}
	// UDP には待ち受けと成立済みのフローの区別が無く、セッションの応答も同じソケットから返すので、
	// stopAccept はソケットを閉じず、新しい送信元からのデータグラムを捨てるだけにする(設計文書 7a.3 節)。
	l.accepting.Store(true)
	l.stopAccept = func() { l.accepting.Store(false) }
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
		buf := make([]byte, udpBufMax)
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
				if !l.accepting.Load() {
					continue
				}
				// 新しいセッションの最初のデータグラムは、Admission Policy のすべての段(packet_rate を
				// 含む)で判定する。送信元の拒否と許可で落としたデータグラムは、後の段のトークンを使わない
				// (設計文書 7a.9 節)
				src := addrOf(from)
				ruleID := m.ruleOf(l)
				release := func() {}
				if m.opts.Admit != nil {
					rel, ok := m.opts.Admit(ruleID, src, n)
					if !ok {
						continue
					}
					release = rel
				}
				// 同時フロー数の上限(仕様 7 節、Resource Guard)。超えた新規パケットは捨てる(既存セッションは追い出さない)
				if m.ruleFlows(ruleID) >= m.opts.UDPSessionsMax || !m.opts.UDPCap.Acquire() {
					release()
					if capLog.Allow() {
						m.opts.Logf("udp %s: session limit reached; dropping new flows", l.key)
					}
					continue
				}
				// target のホスト名はセッション確立時に解決する(DNS の変更は新規セッションだけに効く)
				target := m.targetOf(l)
				c, err := m.opts.Dial("udp", target)
				if err != nil {
					m.opts.UDPCap.Release()
					release()
					if dialLog.Allow() {
						m.opts.Logf("udp %s: dial %s: %v", l.key, target, err)
					}
					continue
				}
				raiseUDPSendBuffer(c)
				s = &udpSession{conn: c}
				s.lastSeen.Store(time.Now().UnixNano())
				mu.Lock()
				sessions[k] = s
				mu.Unlock()
				go func(k string, s *udpSession, from net.Addr) {
					defer release()
					defer m.opts.UDPCap.Release()
					defer closeSession(k, s)
					// 応答は、届いてからプールのバッファを借りて読む(仕様 7 節)。待つ間はバッファを持たない。
					// 待てない接続(unix でも windows でもないカーネルのソケット)は、最大長のバッファを持ち続ける
					w := readWaiterOf(s.conn)
					var own []byte
					if w == nil {
						own = make([]byte, udpBufMax)
					}
					for {
						if w != nil {
							if err := w.WaitReadable(); err != nil {
								return
							}
						}
						if !forwardReply(s, pc, from, own) {
							return
						}
					}
				}(k, s, from)
			} else if m.opts.AdmitPacket != nil && l.accepting.Load() && !m.opts.AdmitPacket(m.ruleOf(l), n) {
				// 成立済みのセッションのデータグラムは packet_rate だけで判定する。Retiring の待ち受け
				// (accepting が偽)のルールは公開した方針に無いので判定しない。kernel モードでも、
				// fail-closed にしたルールの成立済みのフローは、そのルールの行が無いテーブルを通る
				continue
			}
			s.lastSeen.Store(time.Now().UnixNano())
			if _, err := s.conn.Write(buf[:n]); err != nil {
				if writeLog.Allow() {
					m.opts.Logf("udp %s: write %d bytes to %s: %v; closing session", l.key, n, m.targetOf(l), err)
				}
				closeSession(k, s)
			}
		}
	}()
}
