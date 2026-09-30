package agentapi

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/rahanahu/wgft/internal/lograte"
)

// maxPreAuthConnsPerSource は、1 つの送信元(IPv4 はアドレス、IPv6 は /64。レート制限と同じ鍵)が
// 同時に持てる、まだ認証を通っていない接続の数の上限である(仕様 11 節)。認証を通った stream は
// この数から外れるので、同じ NAT の後ろにいるエージェントの台数はこの値に縛られない。未認証の
// 接続は、TLS のハンドシェイクと 1 つのリクエストの間だけ枠を持つ(keep-alive は使わない。
// newHTTPServer)。正規のエージェントは送信元ごとのレート制限(1 秒に 1 回、まとめて 5 回)より
// 速くは試行しないので、16 は正規の同時の試行に対して十分に大きい。設定項目にはしない。
const maxPreAuthConnsPerSource = 16

// sourceLimitListener は、送信元ごとの未認証の接続の数を accept の時点で数え、上限を超えた接続を
// TLS のハンドシェイクより前に閉じる。上限を超えた接続は accept を待たせずに RST で閉じる。1 つの
// 送信元が netutil.LimitListener の全体の枠(maxAgentConns)を埋めて、他の送信元の登録と stream の
// 再接続を止めることを防ぐ。
type sourceLimitListener struct {
	net.Listener
	max int

	mu   sync.Mutex
	open map[string]int // 送信元の鍵 → 未認証として数えている接続の数

	refusedLog lograte.Gate
}

func newSourceLimitListener(ln net.Listener, max int) *sourceLimitListener {
	return &sourceLimitListener{Listener: ln, max: max, open: map[string]int{}}
}

// Accept は上限の内の接続を返す。上限を超えた接続は閉じて、次の接続を待つ。
func (l *sourceLimitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		key := sourceKey(c.RemoteAddr())
		l.mu.Lock()
		if l.open[key] >= l.max {
			l.mu.Unlock()
			if tc, ok := c.(*net.TCPConn); ok {
				tc.SetLinger(0)
			}
			c.Close()
			if l.refusedLog.Allow() {
				log.Printf("agent api: refusing connections from %s: it already holds %d unauthenticated connections", key, l.max)
			}
			continue
		}
		l.open[key]++
		l.mu.Unlock()
		return &sourceConn{Conn: c, l: l, key: key}, nil
	}
}

func (l *sourceLimitListener) release(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.open[key] <= 1 {
		delete(l.open, key)
		return
	}
	l.open[key]--
}

// count は key の送信元が今数えられている接続の数である(テスト用)。
func (l *sourceLimitListener) count(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.open[key]
}

// sourceKey は接続の相手のアドレスから送信元の鍵を作る。レート制限と同じ規則(ipLimiterKey)である。
func sourceKey(a net.Addr) string { return ipLimiterKey(a.String()) }

// sourceConn は、送信元の数から外れるまで(認証を通るか、閉じるまで)数えられる接続である。
type sourceConn struct {
	net.Conn
	l    *sourceLimitListener
	key  string
	once sync.Once
}

// release は、この接続を送信元の未認証の数から外す。何度呼んでもよい。
func (c *sourceConn) release() { c.once.Do(func() { c.l.release(c.key) }) }

func (c *sourceConn) Close() error {
	c.release()
	return c.Conn.Close()
}

type sourceConnKey struct{}

// withSourceConn は http.Server.ConnContext として、接続の context に sourceConn を置く。ハンドラは
// Authenticated で、その接続を送信元の数から外す。c は TLS で包んだ接続なので、その下の接続を見る。
func withSourceConn(ctx context.Context, c net.Conn) context.Context {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	if sc, ok := c.(*sourceConn); ok {
		return context.WithValue(ctx, sourceConnKey{}, sc)
	}
	return ctx
}

// Authenticated は、r の接続が認証を通ったことを記す。その接続は、以後その送信元の未認証の接続の
// 数に入らない(仕様 11 節)。stream のハンドラが恒久トークンの確認の直後に呼ぶ。
func (s *Server) Authenticated(r *http.Request) {
	if sc, ok := r.Context().Value(sourceConnKey{}).(*sourceConn); ok {
		sc.release()
	}
}
