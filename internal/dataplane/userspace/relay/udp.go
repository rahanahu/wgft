package relay

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rahanahu/wgft/internal/lograte"
	"github.com/rahanahu/wgft/internal/resource"
)

const udpBufMax = 65535

// minSweepInterval is a floor on the idle-sweep ticker below, independent of
// Options.UDPIdleTimeout. The VPS-sent seconds value that UDPIdleTimeout is built from is
// already bounded before it reaches here (internal/agent secondsToDuration), but this floor
// keeps the ticker from spinning the host's CPU should that bound ever be bypassed, an
// overflowing multiplication wrap it to a tiny or negative duration, or a future caller pass
// through an unvalidated value. It is far below any interval a real UDPIdleTimeout (whole
// seconds, minimum useful value around a second) produces, so it never changes behavior for
// a legitimate value or the sub-second values existing tests use for fast idle timeouts.
const minSweepInterval = 20 * time.Millisecond

// sweepInterval is the idle-sweep ticker's period for a given UDPIdleTimeout: a quarter of
// it, floored at minSweepInterval.
func sweepInterval(idle time.Duration) time.Duration {
	if iv := idle / 4; iv >= minSweepInterval {
		return iv
	}
	return minSweepInterval
}

// udpSession は (送信元 IP, 送信元ポート) ごとの、target への接続。
// エージェントから見た送信元は VPS の masquerade により常に 10.200.0.1 なので、実質は送信元ポートで区別される。
type udpSession struct {
	conn     net.Conn
	lastSeen atomic.Int64 // UnixNano
	// closed は、このセッションを閉じたときに閉じる。応答のバッファの枠の待ちを取り消す
	closed    chan struct{}
	closeOnce sync.Once
}

func newUDPSession(c net.Conn) *udpSession {
	s := &udpSession{conn: c, closed: make(chan struct{})}
	s.lastSeen.Store(time.Now().UnixNano())
	return s
}

// close は接続を閉じ、枠の待ちを取り消す。2 回目以降は何もしない。
func (s *udpSession) close() {
	s.closeOnce.Do(func() {
		close(s.closed)
		s.conn.Close()
	})
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

// replySender は 1 つのセッションの応答を公開側へ送る。full は、公開側のソケットの送信バッファが
// 満杯で、そのデータグラムを捨てたことを表す(設計文書 7 節)。err は送信の失敗で、セッションを閉じる。
type replySender interface {
	send(b []byte) (full bool, err error)
}

// waitingSender は WriteTo で送る。netstack の待ち受け(エージェント)と、カーネルのソケットでない
// 公開側がこれになる。netstack の WriteTo(nettun の adapter)は、endpoint の送信バッファ(gVisor の既定 212 KiB)が
// 使われている間は書けるようになるまで待つ。使われたままになるのは、出力のキューにパケットが
// 留まっている間、つまりトンネルの送信が止まっているときで、そのときは全ルールの応答が同じく
// 止まるので、枠がルール間の新しい飢餓を作ることは無い(設計文書 7 節)。
type waitingSender struct {
	pc net.PacketConn
	to net.Addr
}

func (s waitingSender) send(b []byte) (bool, error) {
	_, err := s.pc.WriteTo(b, s.to)
	return false, err
}

// replyMarkEvery は、待ち受けの最後の応答の時刻(listener.lastReply)を書き直す最短の間隔である。
// 1 つの待ち受けの多数のセッションの goroutine が、応答のたびに同じ値へ書き込むことを避ける。
// 表示の粒度は秒なので、間引いても失う情報は無い(設計文書 10.2a 節「UDP の応答の観測」)。
const replyMarkEvery = int64(time.Second)

// replyDropReport は、公開側の送信バッファの満杯で応答を捨てたことの累計と、そのログの門である。
// Manager が 1 つ持ち、ログは 1 分に 1 回までにする(設計文書 7 節)。
type replyDropReport struct {
	drops atomic.Uint64
	log   lograte.Gate
}

// forwardReply は target からの応答を 1 個読んで公開側へ返す。own が nil なら、応答のバッファの枠を
// 取ってプールのバッファを借りる。枠が無ければ、空くか、セッションが閉じるまで待つ。
// 読めた応答は、セッションの無通信の判定(lastSeen)と同じ時刻で、待ち受けの最後の応答の時刻 reply
// にも記す。reply への書き込みは replyMarkEvery に 1 回までにする。読み取りの誤り(宛先が ICMP で
// 拒んだ場合の ECONNREFUSED を含む)は応答ではないので記さない。公開側の送信バッファが満杯で捨てた
// 応答は数えて、ログに 1 分に 1 回まで出し、セッションは続ける。それ以外の送信の失敗はセッションを閉じる。
// 偽を返すのはセッションを終えるときである。
func (m *Manager) forwardReply(s *udpSession, l *listener, sender replySender, own []byte) bool {
	rb := own
	if rb == nil {
		lease, ok := m.replies.acquire(s.closed)
		if !ok {
			return false
		}
		defer lease.release()
		rb = *lease.buf()
	}
	rn, err := s.conn.Read(rb)
	if err != nil {
		return false
	}
	now := time.Now().UnixNano()
	s.lastSeen.Store(now)
	if now-l.lastReply.Load() >= replyMarkEvery {
		l.lastReply.Store(now)
	}
	full, err := sender.send(rb[:rn])
	if err != nil {
		return false
	}
	if full {
		n := m.replyDrops.drops.Add(1)
		if m.replyDrops.log.Allow() {
			m.opts.Logf("%s: dropped a reply of %d bytes because the send buffer of the public socket is full; %d replies dropped this way since this relay started", l.key, rn, n)
		}
	}
	return true
}

// udpServer は UDP の待ち受け 1 つの中継の状態である。serveUDP が作り、メソッド count、sweep、
// stopAccept、close を listenerOps の欄 sessions、sweep、stopAccept、closeF に差し込む。delivering には
// 0 を返す関数を入れる。無通信の
// セッションを閉じる goroutine(expireIdle)、読み取りのループ(readLoop)、セッションごとの
// goroutine(serveSession)もこの型のメソッドである。
type udpServer struct {
	m  *Manager
	l  *listener
	pc net.PacketConn

	mu       sync.Mutex
	sessions map[string]*udpSession
	done     chan struct{}
	doneOnce sync.Once    // closeF の 2 回目の呼び出しで done を二重に閉じない
	capLog   lograte.Gate // 上限で拒んだログの頻度
	writeLog lograte.Gate // 宛先への書き込み失敗。上限のログとは別に 1 分に 1 回まで
	dialLog  lograte.Gate // target への dial 失敗のログの頻度(target が落ちている間、新規セッションのたびに鳴らさない)
	// pending は、読み取りのループが作っている途中の新しいセッションの送信元である。セッションは
	// 宛先への dial の後に表へ入るので、判定から登録までの間に走った sweep は表からそれを見ない。
	// sweep はその送信元を閉じる判定をしたら cut を立て、ループは登録の時点でそれを見て捨てる
	// (TCP の tcpEntry.cut と同じ役割)。読み取りのループは 1 つなので、途中のセッションは同時に
	// 1 つしかない。mu で守る。
	pending struct {
		src         netip.Addr
		active, cut bool
	}
}

// serveUDP は開いたソケット pc で中継を始める。bind は呼び出し側(Apply の経路の openLocked と、
// Prepare/Commit の経路の Prepare)が済ませてある。
func (m *Manager) serveUDP(l *listener, pc net.PacketConn) {
	u := &udpServer{
		m:        m,
		l:        l,
		pc:       pc,
		sessions: map[string]*udpSession{},
		done:     make(chan struct{}),
	}
	// UDP には待ち受けと成立済みのフローの区別が無く、セッションの応答も同じソケットから返すので、
	// stopAccept はソケットを閉じず、新しい送信元からのデータグラムを捨てるだけにする(設計文書 7a.3 節)。
	l.listenerOps = listenerOps{
		closeF:     u.close,
		stopAccept: u.stopAccept,
		sweep:      u.sweep,
		sessions:   u.count,
		delivering: func() int { return 0 },
	}
	l.accepting.Store(true)

	// 無通信のセッションを閉じる
	go u.expireIdle()

	go u.readLoop()
}

// count は中継中のセッションの数を返す。listener の sessions である。
func (u *udpServer) count() int { u.mu.Lock(); defer u.mu.Unlock(); return len(u.sessions) }

// closeSession はセッション s を表から外して閉じる。表の k が別のセッションに替わっていれば、表には触れない。
func (u *udpServer) closeSession(k string, s *udpSession) {
	u.mu.Lock()
	if u.sessions[k] == s {
		delete(u.sessions, k)
	}
	u.mu.Unlock()
	s.close()
}

// sweep は keep が偽を返す送信元のセッションを閉じ、閉じた数を返す。作っている途中のセッションの
// 送信元がそれに当たれば、pending.cut を立てて登録させない。
func (u *udpServer) sweep(keep func(src netip.Addr) bool) int {
	u.mu.Lock()
	var victims []*udpSession
	for k, s := range u.sessions {
		if src, ok := udpSessionSource(k); ok && !keep(src) {
			victims = append(victims, s)
			delete(u.sessions, k)
		}
	}
	if u.pending.active && !keep(u.pending.src) {
		u.pending.cut = true
	}
	u.mu.Unlock()
	for _, s := range victims {
		s.close()
	}
	return len(victims)
}

// stopAccept は受け付けの印を下ろす。ソケットとセッションには触れない。
func (u *udpServer) stopAccept() { u.l.accepting.Store(false) }

// close はソケットとすべてのセッションを閉じる。listener の closeF である。
func (u *udpServer) close() {
	u.doneOnce.Do(func() { close(u.done) })
	u.pc.Close()
	u.mu.Lock()
	all := u.sessions
	u.sessions = map[string]*udpSession{}
	u.mu.Unlock()
	for _, s := range all {
		s.close()
	}
}

// expireIdle は UDPIdleTimeout の間に通信の無いセッションを閉じる。serveUDP が goroutine で 1 つ
// 始め、done が閉じると戻る。
func (u *udpServer) expireIdle() {
	t := time.NewTicker(sweepInterval(u.m.opts.UDPIdleTimeout))
	defer t.Stop()
	for {
		select {
		case <-u.done:
			return
		case <-t.C:
			cutoff := time.Now().Add(-u.m.opts.UDPIdleTimeout).UnixNano()
			u.mu.Lock()
			var expired []string
			for k, s := range u.sessions {
				if s.lastSeen.Load() < cutoff {
					expired = append(expired, k)
				}
			}
			var victims []*udpSession
			for _, k := range expired {
				victims = append(victims, u.sessions[k])
				delete(u.sessions, k)
			}
			u.mu.Unlock()
			for _, s := range victims {
				s.close()
			}
		}
	}
}

// readLoop はソケットの読み取りのループである。serveUDP が goroutine で 1 つ始め、done が閉じると
// 戻る。新しい送信元のデータグラムで判定、枠の取得、宛先への dial、登録を行い、セッションごとの
// goroutine(serveSession)を始める。
func (u *udpServer) readLoop() {
	buf := make([]byte, udpBufMax)
	var (
		delay   time.Duration
		readLog lograte.Gate
	)
	for {
		n, from, err := u.pc.ReadFrom(buf)
		if err != nil {
			select {
			case <-u.done:
				return
			default:
			}
			// 待ち受けを閉じた以外の失敗では、TCP の accept と同じく、ソケットを開いたまま後退して
			// 試し直す。戻ってしまうと、ソケットは bind されたまま読まない状態で残り、Apply も
			// Prepare も開き直さない。Linux のホストのソケットでは、管理者がソケットを破棄したとき
			// (sock_diag の SOCK_DESTROY、ss -K)の ECONNABORTED がこれに当たる。ソケットは
			// bind したポートを持ったままなので、次の読み取りから元に戻る(設計文書 6.3 節)
			if readLog.Allow() {
				u.m.opts.Logf("%s: read failed: %v; the listener stays open and retries", u.l.key, err)
			}
			delay = nextRetry(delay)
			select {
			case <-u.done:
				return
			case <-time.After(delay):
			}
			continue
		}
		delay = 0
		k := from.String()
		u.mu.Lock()
		s := u.sessions[k]
		if s == nil {
			// 判定の前に途中のセッションとして記す。この後に走る sweep が、判定に使った方針と
			// 読んだ宛先で作るこのセッションを閉じる判定をすれば、登録の時点で分かる。
			// 前のデータグラムの途中のセッションが捨てられて記録が残っていても、ここで上書きする
			u.pending.src, u.pending.active = udpSessionSource(k)
			u.pending.cut = false
		}
		u.mu.Unlock()
		if s == nil {
			if !u.l.accepting.Load() {
				continue
			}
			// 新しいセッションの最初のデータグラムは、Admission Policy のすべての段(packet_rate を
			// 含む)で判定する。送信元の拒否と許可で落としたデータグラムは、後の段のトークンを使わない
			// (設計文書 7a.9 節)
			src := addrOf(from)
			ruleID := u.m.ruleOf(u.l)
			// charge はこのセッションの 2 つの枠(Admission Policy の送信元ごとの枠と Pool の枠)を
			// 持ち、捨てる分岐か、登録の後はセッションの goroutine の終わりで、両方をまとめて返す
			var charge resource.Charge
			if u.m.opts.Admit != nil {
				rel, ok := u.m.opts.Admit(ruleID, src, n)
				if !ok {
					continue
				}
				charge.HoldPolicy(rel)
			}
			// 判定の間に待ち受けが Retiring になっていれば(fail-closed。設計文書 7a.3 節)、枠を取らず、
			// 宛先へ dial もせずに捨てる。この後に Retiring になる場合は、下の登録の確認が捨てる
			if !u.l.accepting.Load() {
				charge.Release()
				continue
			}
			// 同時フロー数の上限(仕様 7 節、Resource Guard)。プロセス全体の予算、ルール 1 本の
			// 上限、ルールの登録ごとの最低分と予備を Pool が 1 つの排他の中で判定する。拒んだ新規パケットは
			// 捨てる(既存セッションは追い出さない)
			lease, ref, outcome := u.l.budget.Take()
			switch outcome {
			case resource.NotAccepting:
				// 受け付けの印を見た後に、この待ち受けが Retiring になったか閉じられた。データグラムを
				// 捨て、拒否の数にもログにも入れない(設計文書 7a.10 節)
				charge.Release()
				continue
			case resource.Refused:
				charge.Release()
				if u.capLog.Allow() {
					u.m.opts.Logf("%s: %s; dropping new flows", u.l.key, ref)
				}
				continue
			}
			charge.HoldLease(lease)
			if h := u.m.testHookAfterTake; h != nil {
				h(u.l)
			}
			// target のホスト名はセッション確立時に解決する(DNS の変更は新規セッションだけに効く)。
			// 許可一覧があれば、解決したアドレスで判定し、一覧の外ならデータグラムを捨てる(設計文書 7 節)
			target := u.m.targetOf(u.l)
			c, err := u.m.dialTarget("udp", target)
			u.m.noteTargetAllowErr(u.l, err)
			if err != nil {
				charge.Release()
				if u.dialLog.Allow() {
					u.m.opts.Logf("%s: dial %s: %v", u.l.key, target, err)
				}
				continue
			}
			raiseUDPSendBuffer(c)
			s = newUDPSession(c)
			// 読み取りから登録までの間に closeF が走っていれば(Apply が m.mu を持つ間、上の ruleOf と
			// targetOf が待たされる)、closeF はこのセッションを見ていない。無通信のセッションを閉じる
			// goroutine も done で戻っているので、登録すると誰にも閉じられず、枠と宛先へのソケットが
			// 残り続ける。登録せずにここで閉じ、データグラムも送らない。closeF は mu を取る前に done を
			// 閉じるので、done が閉じていなければ closeF はこの後に mu を取り、登録したセッションを閉じる
			// (TCP の accept のループと同じ)。
			// 読み取りから登録までの間に待ち受けが Retiring になっていれば、この送信元は Retiring の後に
			// 来た新しい送信元と同じなので、同じく登録せずに捨てる(設計文書 7a.3 節)。retireLocked は
			// stopAccept で受け付けの印を下ろしてから mu を取って sweep するので、mu の下で印が立って
			// いれば、登録したセッションはその sweep が接続元制限で判定する
			u.mu.Lock()
			if h := u.m.testUDPRegistering; h != nil {
				h()
			}
			stopped := !u.l.accepting.Load()
			select {
			case <-u.done:
				stopped = true
			default:
			}
			// 判定から登録までの間に、宛先の付け替え(Staged.Commit)か接続元制限の変更
			// (CloseSessions)の sweep がこの送信元を閉じる判定をしていれば、登録せずに捨てる。
			// 登録すると、付け替えでは旧い宛先へ、接続元制限では拒むようになった送信元のまま
			// 中継を続け、送り続ける送信元のセッションは無通信の期限でも閉じない(設計文書 6.3 節)
			if u.pending.cut {
				stopped = true
			}
			u.pending.active = false
			if stopped {
				u.mu.Unlock()
				s.close()
				charge.Release()
				continue
			}
			u.sessions[k] = s
			u.mu.Unlock()
			go u.serveSession(k, s, from, &charge)
		} else if u.m.opts.AdmitPacket != nil && u.l.accepting.Load() && !u.m.opts.AdmitPacket(u.m.ruleOf(u.l), n) {
			// 成立済みのセッションのデータグラムは packet_rate だけで判定する。Retiring の待ち受け
			// (accepting が偽)のルールは公開した方針に無いので判定しない。kernel モードでも、
			// fail-closed にしたルールの成立済みのフローは、そのルールの行が無いテーブルを通る
			continue
		}
		s.lastSeen.Store(time.Now().UnixNano())
		if _, err := s.conn.Write(buf[:n]); err != nil {
			if u.writeLog.Allow() {
				u.m.opts.Logf("%s: write %d bytes to %s: %v; closing session", u.l.key, n, u.m.targetOf(u.l), err)
			}
			u.closeSession(k, s)
		}
	}
}

// serveSession は 1 つのセッションの応答を公開側の from へ返す goroutine である。戻るときに
// セッションを閉じ、charge の枠を返す。charge は readLoop の変数を指す。
func (u *udpServer) serveSession(k string, s *udpSession, from net.Addr, charge *resource.Charge) {
	defer charge.Release()
	defer u.closeSession(k, s)
	// 応答は、届いてから応答のバッファの枠を取り、プールのバッファを借りて読む(仕様 7 節)。
	// 待つ間はバッファを持たない。待てない接続(unix でも windows でもないカーネルのソケット)は、
	// 枠の外で最大長のバッファを持ち続ける
	w := readWaiterOf(s.conn)
	var own []byte
	if w == nil {
		own = make([]byte, udpBufMax)
	}
	sender := newReplySender(u.pc, from)
	for {
		if w != nil {
			if err := w.WaitReadable(); err != nil {
				return
			}
		}
		if !u.m.forwardReply(s, u.l, sender, own) {
			return
		}
	}
}

// udpSessionSource はセッションの表の鍵(送信元の "IP:ポート")から、sweep の判定に渡す送信元の
// IP を取り出す。読めない鍵のセッションは sweep の対象にしない。
func udpSessionSource(k string) (netip.Addr, bool) {
	ap, err := netip.ParseAddrPort(k)
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}
