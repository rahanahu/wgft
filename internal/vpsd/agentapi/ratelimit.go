package agentapi

import (
	"container/list"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiterCap は entries に保持する送信元の上限。IPv6 は /64 単位で鍵にしても
// 攻撃者は依然として多数の /64 を持ち得るため、上限を設けてメモリを抑える。
const ipLimiterCap = 4096

// ipLimiterTTL を過ぎて Allow を呼んでいない送信元は、期限切れとして一掃の対象にする。
const ipLimiterTTL = 10 * time.Minute

// ipLimiterSweepInterval は期限切れの一掃(entries 全体を走査する O(n) の処理)を
// 許す最短間隔。table が上限に達した状態で送信元が次々に来ても、この間隔より
// 短い周期では一掃をやり直さず、LRU の末尾を 1 件だけ追い出す O(1) の経路だけを
// 使う。これにより、定常状態(table が上限に張り付いたまま新しい送信元が来続ける
// 状況)での挿入コストは O(n) の一掃を挟まない O(1) に収まる。
const ipLimiterSweepInterval = time.Minute

// ipLimiter は送信元 IP ごとのトークンバケット(仕様 5.1 節:登録と stream の試行をレート制限する)。
//
// entries は ipLimiterCap 件を上限にする。上限に達した挿入は evictLocked を経由する。
// evictLocked は、前回の一掃から ipLimiterSweepInterval 以上経っていれば期限切れの
// 項目を 1 回の走査(O(n))で一掃し、そのうえでなお上限に達していれば order の末尾、
// つまり最も長く Allow を呼ばれていない項目を 1 件だけ O(1) で追い出す(LRU)。
// order は直近に Allow を呼ばれた項目を先頭に保つ doubly linked list で、既存項目への
// Allow は MoveToFront で先頭に移すだけなので O(1) で済む。一掃を間隔で間引くことで、
// 定常状態での挿入 1 回あたりの償却コストは O(1) になる。
//
// LRU の追い出しでも空きを作れない場合(cap を 0 以下にされた場合など、通常は
// 起こらない)は、新しい送信元を拒否する。公開 API のフラッド対策として、
// 未知の送信元を無条件に許すより fail closed の方が安全なため。
type ipLimiter struct {
	mu        sync.Mutex
	limit     rate.Limit
	burst     int
	cap       int
	entries   map[string]*list.Element // key -> *list.Element(値は *ipEntry)
	order     *list.List               // 先頭が最も新しく使われた項目、末尾が最も古い項目(LRU)
	lastSweep time.Time                // 期限切れの一掃を最後に行った時刻(ゼロ値なら未実施)
	now       func() time.Time         // テスト用の時計差し替え。nil なら time.Now
}

type ipEntry struct {
	key  string
	lim  *rate.Limiter
	seen time.Time
}

func newIPLimiter(perSecond float64, burst int) *ipLimiter {
	return &ipLimiter{
		limit:   rate.Limit(perSecond),
		burst:   burst,
		cap:     ipLimiterCap,
		entries: make(map[string]*list.Element),
		order:   list.New(),
	}
}

func (l *ipLimiter) clock() time.Time {
	if l.now != nil {
		return l.now()
	}
	return time.Now()
}

// Allow は remoteAddr(host:port)の送信元に対して 1 回分の試行を許すか。
// IPv4 の送信元はアドレスそのものを鍵にする。IPv6 の送信元は /64 を鍵にする。
// 家庭やクラウドの多くの環境では利用者に /64 単位で払い出されるため、1 台の
// ホストが /64 の中でアドレスを変えるだけで無数の鍵を作れてしまうのを防ぐ。
func (l *ipLimiter) Allow(remoteAddr string) bool {
	key := ipLimiterKey(remoteAddr)

	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()

	if el, ok := l.entries[key]; ok {
		l.order.MoveToFront(el)
		e := el.Value.(*ipEntry)
		e.seen = now
		return e.lim.Allow()
	}

	if len(l.entries) >= l.cap {
		if l.cap <= 0 {
			// 上限が 0 以下では新しい送信元を保持できない。fail closed で拒否する。
			return false
		}
		l.evictLocked(now)
		if len(l.entries) >= l.cap {
			// 一掃と LRU の追い出しでも空きが作れなかった(通常は起こらない)。
			// 未知の送信元を無条件に許すよりは、fail closed で拒否する方が安全。
			return false
		}
	}

	e := &ipEntry{key: key, lim: rate.NewLimiter(l.limit, l.burst), seen: now}
	el := l.order.PushFront(e)
	l.entries[key] = el
	return e.lim.Allow()
}

// evictLocked は新しい項目 1 件分の空きを作る。呼び出し側で l.mu を保持していること。
// 前回の一掃から ipLimiterSweepInterval 以上経っていれば、期限切れの項目を
// 1 回の走査(O(n))で一掃する。そのうえでまだ上限に達しているなら、
// order の末尾(最も長く使われていない項目)を 1 件だけ O(1) で追い出す。
func (l *ipLimiter) evictLocked(now time.Time) {
	if l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= ipLimiterSweepInterval {
		l.sweepExpiredLocked(now)
		l.lastSweep = now
	}
	if len(l.entries) < l.cap {
		return
	}
	back := l.order.Back()
	if back == nil {
		return
	}
	e := back.Value.(*ipEntry)
	l.order.Remove(back)
	delete(l.entries, e.key)
}

// sweepExpiredLocked は entries 全体を 1 回走査して、ipLimiterTTL を過ぎて
// Allow を呼ばれていない項目をすべて取り除く。呼び出し側で l.mu を保持していること。
func (l *ipLimiter) sweepExpiredLocked(now time.Time) {
	for key, el := range l.entries {
		e := el.Value.(*ipEntry)
		if now.Sub(e.seen) > ipLimiterTTL {
			l.order.Remove(el)
			delete(l.entries, key)
		}
	}
}

// ipLimiterKey は remoteAddr(host:port、あるいは裸のホスト)から entries の鍵を作る。
// IPv4(4-in-6 を含む)はアドレスそのもの、IPv6 は /64 のプレフィクスを返す。
// 解析できない入力は、以前の実装と同じく、文字列をそのまま鍵として使う。
func ipLimiterKey(remoteAddr string) string {
	if addrPort, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return ipLimiterKeyForAddr(addrPort.Addr())
	}

	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return ipLimiterKeyForAddr(addr)
	}
	return host
}

func ipLimiterKeyForAddr(addr netip.Addr) string {
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}
