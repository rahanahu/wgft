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
		conns = map[net.Conn]netip.Addr{} // 公開側の接続はその接続元、target 側はゼロ値
		done  = make(chan struct{})
		once  sync.Once
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
		for c, src := range conns {
			if src.IsValid() && !keep(src) {
				cutConn(c)
				n++
			}
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
		// netstack の側を先に Abort する。実ソケットの側を先に閉じると、netpipe がその EOF を
		// netstack の側へ FIN として伝え、RST の前に FIN が出ることがあるため
		mu.Lock()
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
			src := addrOf(c.RemoteAddr())
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
			conns[c] = src
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
}
