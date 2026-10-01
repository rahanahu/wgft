package agentapi

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/rahanahu/wgft/internal/lograte"
)

// 未認証の接続の上限(仕様 11 節)。未認証の接続は、TLS のハンドシェイクと 1 つのリクエストの間だけ
// 枠を持つ(keep-alive は使わない。newHTTPServer)。認証を通った stream はどの数からも外れるので、
// 同じ NAT やプレフィクスの後ろにいるエージェントの台数はこれらの値に縛られない。どれも設定項目にはしない。
const (
	// maxPreAuthConns は、プロセス全体で同時に数える未認証の接続の上限である。全体の同時接続数の
	// 上限(maxAgentConns)の内側に置き、残りの枠を認証を通った stream に残す。数百台のエージェントが
	// server の再起動の後に一斉につなぎ直しても、1 本が未認証でいるのはハンドシェイクと 1 つの
	// リクエストの間だけなので足りる。
	maxPreAuthConns = 1024
	// maxPreAuthConnsPerSource は、1 つの送信元(IPv4 はアドレス、IPv6 は /64。レート制限と同じ鍵)の
	// 上限である。正規のエージェントは送信元ごとのレート制限(1 秒に 1 回、まとめて 5 回)より速くは
	// 試行しないので、16 は正規の同時の試行に対して十分に大きい。
	maxPreAuthConnsPerSource = 16
	// maxPreAuthConnsPer56 と maxPreAuthConnsPer48 は、IPv6 の /56 と /48 の上限である。/64 だけで
	// 数えると、/56(/64 が 256 個)を持つ 1 人が 256 × 16 本を持ててしまう。/56 は家庭の回線に、
	// /48 は拠点やトンネルのサービスに払い出される大きさである。/56 には /64 の 4 つ分、/48 には
	// /56 の 4 つ分を置き、/48 の 1 つが持てるのは全体の上限の 4 分の 1 までにする。
	maxPreAuthConnsPer56 = 64
	maxPreAuthConnsPer48 = 256
)

// sourceTier は、送信元のアドレスをまとめる幅の 1 段と、その幅の 1 つが同時に持てる未認証の接続の数
// である。v4Bits か v6Bits が 0 の段は、そのアドレスの種類を数えない。
type sourceTier struct {
	v4Bits, v6Bits int
	max            int
}

// preAuthLimits は未認証の接続の上限の組である。テストは小さい値を注入する。
type preAuthLimits struct {
	total int          // プロセス全体
	tiers []sourceTier // 送信元の段。最初の段はレート制限と同じ鍵(IPv4 のアドレスか IPv6 の /64)で数える
}

// defaultPreAuthLimits は本番の上限である。IPv4 はアドレスだけで数え、/24 のような段は置かない。
// IPv4 のアドレスは IPv6 の /64 と違って 1 人が安く多数を持てず、/24 で数えると、同じ範囲から
// 払い出される CGNAT の後ろの正規のエージェントを巻き込むためである。
var defaultPreAuthLimits = preAuthLimits{
	total: maxPreAuthConns,
	tiers: []sourceTier{
		{v4Bits: 32, v6Bits: 64, max: maxPreAuthConnsPerSource},
		{v6Bits: 56, max: maxPreAuthConnsPer56},
		{v6Bits: 48, max: maxPreAuthConnsPer48},
	},
}

// sourceLimitListener は、未認証の接続の数を accept の時点で送信元の段ごとと全体で数え、どれかの
// 上限に達していれば、その接続を TLS のハンドシェイクより前に閉じる。上限を超えた接続は accept を
// 待たせずに閉じる。少数の送信元や 1 つの IPv6 のブロックが netutil.LimitListener の全体の枠
// (maxAgentConns)を埋めて、他の送信元の登録と stream の再接続を止めることを防ぐ。
type sourceLimitListener struct {
	net.Listener
	limits preAuthLimits

	mu    sync.Mutex
	open  map[string]int // 送信元の段の鍵 → 未認証として数えている接続の数
	total int            // 未認証として数えている接続の全体の数

	refusedLog lograte.Gate // 送信元の段の上限で断った行
	fullLog    lograte.Gate // 全体の上限で断った行
}

func newSourceLimitListener(ln net.Listener, limits preAuthLimits) *sourceLimitListener {
	return &sourceLimitListener{Listener: ln, limits: limits, open: map[string]int{}}
}

// sourceKeyMax は、ある接続が数えられる送信元の段の鍵と、その段の上限である。
type sourceKeyMax struct {
	key string
	max int
}

// keys は、接続の相手のアドレスが数えられる段の鍵を返す。鍵は段ごとに書式が違い(アドレスと
// プレフィクス)、同じ map に置いても衝突しない。
func (l *sourceLimitListener) keys(a net.Addr) []sourceKeyMax {
	addr, ok := remoteAddr(a)
	if !ok {
		// TCP の待ち受けでは起きない。起きたら最初の段だけで文字列そのものを数える
		if len(l.limits.tiers) == 0 {
			return nil
		}
		return []sourceKeyMax{{key: sourceKey(a), max: l.limits.tiers[0].max}}
	}
	keys := make([]sourceKeyMax, 0, len(l.limits.tiers))
	for i, t := range l.limits.tiers {
		bits := t.v6Bits
		if addr.Is4() {
			bits = t.v4Bits
		}
		if bits == 0 {
			continue
		}
		key := netip.PrefixFrom(addr, bits).Masked().String()
		if i == 0 {
			key = ipLimiterKeyForAddr(addr) // ログとレート制限と同じ書式
		}
		keys = append(keys, sourceKeyMax{key: key, max: t.max})
	}
	return keys
}

// remoteAddr は接続の相手のアドレスを取り出す。IPv4 射影の IPv6 アドレスは IPv4 に戻す。既定の
// 待ち受けは IPv6 にも応じ(Listen)、IPv4 の相手は IPv4 射影のアドレスで届きうるためである。
func remoteAddr(a net.Addr) (netip.Addr, bool) {
	if ta, ok := a.(*net.TCPAddr); ok {
		if addr, ok := netip.AddrFromSlice(ta.IP); ok {
			return addr.Unmap(), true
		}
	}
	ap, err := netip.ParseAddrPort(a.String())
	if err != nil {
		return netip.Addr{}, false
	}
	return ap.Addr().Unmap(), true
}

// Accept は上限の内の接続を返す。上限を超えた接続は閉じて、次の接続を待つ。
func (l *sourceLimitListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		keys := l.keys(c.RemoteAddr())
		l.mu.Lock()
		if l.total >= l.limits.total {
			l.mu.Unlock()
			c.Close()
			if l.fullLog.Allow() {
				log.Printf("agent api: refusing new connections: %d unauthenticated connections are already open", l.limits.total)
			}
			continue
		}
		if full, ok := l.fullTierLocked(keys); ok {
			l.mu.Unlock()
			c.Close()
			if l.refusedLog.Allow() {
				log.Printf("agent api: refusing connections from %s: it already holds %d unauthenticated connections", full.key, full.max)
			}
			continue
		}
		l.total++
		for _, k := range keys {
			l.open[k.key]++
		}
		l.mu.Unlock()
		return &sourceConn{Conn: c, l: l, keys: keys}, nil
	}
}

// fullTierLocked は、上限に達している段があればそれを返す。l.mu を持って呼ぶ。
func (l *sourceLimitListener) fullTierLocked(keys []sourceKeyMax) (sourceKeyMax, bool) {
	for _, k := range keys {
		if l.open[k.key] >= k.max {
			return k, true
		}
	}
	return sourceKeyMax{}, false
}

func (l *sourceLimitListener) release(keys []sourceKeyMax) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	for _, k := range keys {
		if l.open[k.key] <= 1 {
			delete(l.open, k.key)
			continue
		}
		l.open[k.key]--
	}
}

// sourceKey は接続の相手のアドレスから最初の段の鍵を作る。レート制限と同じ規則(ipLimiterKey)である。
func sourceKey(a net.Addr) string { return ipLimiterKey(a.String()) }

// sourceConn は、送信元の数から外れるまで(認証を通るか、閉じるまで)数えられる接続である。
type sourceConn struct {
	net.Conn
	l    *sourceLimitListener
	keys []sourceKeyMax
	once sync.Once
}

// release は、この接続を送信元の未認証の数から外す。何度呼んでもよい。
func (c *sourceConn) release() { c.once.Do(func() { c.l.release(c.keys) }) }

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
