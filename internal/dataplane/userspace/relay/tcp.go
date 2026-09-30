package relay

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rahanahu/wgft/internal/lograte"
	"github.com/rahanahu/wgft/internal/netpipe"
)

// aborter は、通常の Close(グレースフルクローズ。FIN の後 TIME_WAIT)の代わりに、
// 即座に RST を送れる接続が満たす。nettun.TCPConn.Abort を見よ。
type aborter interface{ Abort() }

// abortRefused は、accept の直後、まだデータをやり取りしていない接続を拒むときに使う(同時フロー
// 数の上限、接続元の拒否)。netstack 上で通常の Close を使うと、graceful shutdown を経て
// 既定の TIME_WAIT(gVisor では 60 秒)にエンドポイントが残り、毎秒数千の拒否ではその分だけ
// 保持していないはずのフローがソフト上限を超えてメモリを押し上げる(仕様 7 節、GitHub issue #25)。
// Abort は代わりに RST を送り、エンドポイントを即座に解放する。実ソケット(vpsd のユーザー空間
// モードの公開側 accept は netstack ではなくホストのリスナー)には SetLinger(0) で同じ効果を持たせる。
// カーネルの TIME_WAIT の記帳は軽いが、ここで避ければフラッドの間にエフェメラルポートを浪費せず、
// 2 つの accept 経路の扱いも揃う。
func abortRefused(c net.Conn) {
	switch v := c.(type) {
	case aborter:
		v.Abort()
	case *net.TCPConn:
		v.SetLinger(0)
		v.Close()
	default:
		c.Close()
	}
}

// cutConn は、中継中の接続を中継の側から意図して切るときに使う(ポートが宣言から消えたとき、
// 実効宛先が変わって開き直すとき、Manager.Close、接続元制限の変更で切るとき、待ち受けを閉じた
// 後に accept のループが受け取った接続)。netstack の接続は Abort(RST)で
// 即座に解放する。通常の Close ではエンドポイントが TIME_WAIT(gVisor の既定で 60 秒)か、
// 相手が閉じなければ FIN_WAIT_2 に残り、その間は同じポートで待ち受けを開き直せない
// ("port is in use")。無効化の直後に有効に戻したルールや、宛先を変えたルールが、その間
// 転送できなくなる(設計文書 7 節)。どのみち切るセッションなので、クライアントに FIN ではなく
// RST が届いても失うものは無い。実ソケット(エージェントの宛先側、vpsd の公開側)は、
// 待ち受けのポートを塞がないので、今までどおり通常の Close にする。セッションが自然に終わる
// 経路(ハーフクローズ、EOF)は netpipe が扱い、この関数を通らない。その経路でエージェントが
// 先に閉じた接続は、conns から外れた後なので切れず、TIME_WAIT の間ポートを保持する(設計文書 7 節)。
func cutConn(c net.Conn) {
	if a, ok := c.(aborter); ok {
		a.Abort()
		return
	}
	c.Close()
}

// tcpEntry は中継中の接続 1 本の記録である。公開側の接続の記録は接続元 src を持ち、宛先への接続を
// 登録した後は peer にその接続を持つ。宛先への接続の記録は src がゼロ値で、peer に公開側の接続を持つ。
// cut は sweep がこの中継を切ったことを示す。公開側の記録にだけ立て、mu で守る。
type tcpEntry struct {
	src  netip.Addr
	peer net.Conn
	cut  bool
}

// cutPair は中継中の 1 組を切る。宛先への接続がまだ無ければ(dial の最中)公開側だけを切る。
// closeF と同じ理由で、netstack の側を先に Abort する。
func cutPair(c, t net.Conn) {
	if t == nil {
		cutConn(c)
		return
	}
	first, second := c, t
	if _, ok := t.(aborter); ok {
		first, second = t, c
	}
	cutConn(first)
	cutConn(second)
}

// retryMin と retryMax は、TCP の accept と UDP の読み取りが、待ち受けを閉じた以外の理由で失敗した
// ときの待ち時間の下限と上限。プロキシモードの中継(internal/vpsd/proxyrelay)と同じく、閉じた場合
// 以外の誤りはすべて試し直す。値は net/http.Server.Serve の後退と同じだが、net/http が試し直すのは
// Temporary() が真の誤りだけで、ENOBUFS や ENOMEM は試し直さない点が違う。
const (
	retryMin = 5 * time.Millisecond
	retryMax = time.Second
)

// nextRetry は、失敗が続いたときの次の待ち時間である。最初は retryMin で、倍々に retryMax まで
// 広げる。成功したら呼び出し側が 0 に戻す。
func nextRetry(d time.Duration) time.Duration { return min(max(2*d, retryMin), retryMax) }

// serveTCP は開いた待ち受け ln で中継を始める。bind は呼び出し側(Apply の経路の openLocked と、
// Prepare/Commit の経路の Prepare)が済ませてある。
func (m *Manager) serveTCP(l *listener, ln net.Listener) {
	var (
		mu    sync.Mutex
		conns = map[net.Conn]*tcpEntry{} // 公開側の接続と宛先への接続の両方を持つ
		done  = make(chan struct{})
		once  sync.Once
		// closed は closeF が中継中の接続を切った後に真になる。mu で守る。done は stopAccept でも
		// 閉じる(Retiring の待ち受けは成立済みの接続を残す)ので、宛先への接続の登録は done ではなく
		// これで判定する
		closed bool
		// 同時フロー数の上限の対象は公開側の接続だけで、conns は target 側も含むため一致しない。
		// 上限の対象の数を数えるのは l.budget で、Status.Flows がその数を返す
		capLog  lograte.Gate // 上限で拒んだログの頻度
		dialLog lograte.Gate // target への dial 失敗のログの頻度(target が落ちている間、接続のたびに鳴らさない)
	)
	l.sessions = func() int { mu.Lock(); defer mu.Unlock(); return len(conns) }
	l.sweep = func(keep func(src netip.Addr) bool) int {
		mu.Lock()
		defer mu.Unlock()
		n := 0
		for c, e := range conns {
			if !e.src.IsValid() || keep(e.src) {
				continue
			}
			// 組の両側を切り、記録からも外す。公開側だけを切ると、netpipe はその読み取りの失敗を受けて
			// 宛先への接続を通常の Close で閉じる。宛先への接続が netstack の接続(vpsd のユーザー空間
			// モードでエージェントへ張った接続)なら、エージェントには RST ではなく FIN が届き、エージェントの
			// 中継はハーフクローズとして宛先への接続と枠を持ち続ける(設計文書 6.2 節)。
			// 外すのは、直後に sessions を見る Retiring の判定(Commit)が、切った中継を数えないため。
			// dial の最中なら cut を見た接続の goroutine が宛先への接続を登録せずに切る
			e.cut = true
			cutPair(c, e.peer)
			delete(conns, c)
			if e.peer != nil {
				delete(conns, e.peer)
			}
			n++
		}
		return n
	}
	// stopAccept は待ち受けソケットだけを閉じ、中継中の接続には触れない(fail-closed にしたルールの
	// Retiring。設計文書 7a.3 節)。
	l.stopAccept = func() {
		once.Do(func() { close(done) })
		ln.Close()
	}
	l.closeF = func() {
		once.Do(func() { close(done) })
		ln.Close()
		// 中継中の TCP 接続もすべて切る(仕様 7 節:ポートが宣言から消えたとき、開き直すとき)。
		// netstack の側を先に Abort する。実ソケットの側を先に閉じると、netpipe がその読み取りの失敗を
		// 受けて netstack の側を通常の Close で閉じ、RST の前に FIN が出ることがあるため
		mu.Lock()
		closed = true
		for c := range conns {
			if _, ok := c.(aborter); ok {
				cutConn(c)
			}
		}
		for c := range conns {
			if _, ok := c.(aborter); !ok {
				cutConn(c)
			}
		}
		mu.Unlock()
	}
	go func() {
		var (
			delay     time.Duration
			acceptLog lograte.Gate
			peerLog   lograte.Gate // 相手のアドレスが分からない接続を拒んだログの頻度
		)
		for {
			c, err := ln.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				// 待ち受けを閉じた以外の失敗、例えばホストのソケットでのファイル記述子の枯渇(EMFILE、
				// ENFILE)では、待ち受けを開いたまま後退して試し直す。戻ってしまうと、ソケットは bind
				// されたまま accept しない状態で残り、Apply も Prepare も開いている待ち受けを開き直さない
				// ので、プロセスを再起動するまでそのポートの中継が止まる(設計文書 6.3、7 節)
				if acceptLog.Allow() {
					m.opts.Logf("tcp %s: accept failed: %v; the listener stays open and retries", l.key, err)
				}
				delay = nextRetry(delay)
				select {
				case <-done:
					return
				case <-time.After(delay):
				}
				continue
			}
			delay = 0
			// 相手のアドレスが分からない接続は、accept の前か直後に相手が RST で切った接続である。
			// gVisor は accept の待ち行列にある接続が RST を受けても待ち行列に残して Accept で返し、
			// その RemoteAddr は nil になる。接続元を判定できないので、Admission Policy にも同時フロー数の
			// 上限にも数えず、枠を取る前に拒む
			src := addrOf(c.RemoteAddr())
			if !src.IsValid() {
				abortRefused(c)
				if peerLog.Allow() {
					m.opts.Logf("tcp %s: refused a connection whose remote address is unknown; the client likely reset it before it was accepted", l.key)
				}
				continue
			}
			ruleID := m.ruleOf(l)
			release := func() {}
			if m.opts.Admit != nil {
				rel, ok := m.opts.Admit(ruleID, src, 0)
				if !ok {
					abortRefused(c)
					continue
				}
				release = rel
			}
			// 同時フロー数の上限(仕様 7 節、Resource Guard)。プロセス全体の予算、ルール 1 本の上限、
			// 他のルールの隔離予約を Pool が 1 つの排他の中で判定する。拒んだ接続はすぐ閉じる
			// (既存の接続は追い出さない)
			if ref, ok := l.budget.Acquire(); !ok {
				release()
				abortRefused(c)
				if capLog.Allow() {
					m.opts.Logf("%s: %s; refusing new connections", l.key, ref)
				}
				continue
			}
			// accept から登録までの間に closeF が走っていれば(Apply が m.mu を持つ間、上の ruleOf が
			// 待たされる)、closeF はこの接続を見ていない。登録せずにここで切り、ポートを保持させない。
			// closeF は mu を取る前に done を閉じるので、done が閉じていなければ closeF はこの後に mu を
			// 取り、登録した接続を切る
			mu.Lock()
			select {
			case <-done:
				mu.Unlock()
				l.budget.Release()
				release()
				cutConn(c)
				continue
			default:
			}
			entry := &tcpEntry{src: src}
			conns[c] = entry
			mu.Unlock()
			go func() {
				defer func() {
					mu.Lock()
					delete(conns, c)
					mu.Unlock()
					l.budget.Release()
					release()
				}()
				target := m.targetOf(l)
				t, err := m.dialTarget("tcp", target)
				m.noteTargetAllowErr(l, err)
				if err != nil {
					if dialLog.Allow() {
						m.opts.Logf("tcp %s: dial %s: %v", l.key, target, err)
					}
					// 許可一覧による拒否は、上限や接続元の拒否と同じく RST で即座に終える。
					// 宛先が落ちているなどの失敗は今までどおり通常の close にする
					if errors.Is(err, ErrTargetNotAllowed) {
						abortRefused(c)
					} else {
						c.Close()
					}
					return
				}
				// dial の間に closeF か sweep が走っていれば、どちらも公開側の接続 c を切ったが、まだ登録
				// していない t を見ていない。中継を始めると、netpipe は c の読み取りの失敗を受けて t を通常の
				// Close で閉じるので、t が netstack の接続なら相手に RST ではなく FIN が届く。登録せずに
				// ここで cutConn で切り、中継も始めない。c は closeF か sweep が切っており、枠は上の defer が返す
				mu.Lock()
				if closed || entry.cut {
					mu.Unlock()
					cutConn(t)
					return
				}
				entry.peer = t
				conns[t] = &tcpEntry{peer: c}
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
}
