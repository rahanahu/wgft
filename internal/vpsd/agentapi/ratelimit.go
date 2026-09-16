package agentapi

import (
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ipLimiter は送信元 IP ごとのトークンバケット(仕様 5.1 節:登録と stream の試行をレート制限する)。
type ipLimiter struct {
	mu      sync.Mutex
	limit   rate.Limit
	burst   int
	entries map[string]*ipEntry
}

type ipEntry struct {
	lim  *rate.Limiter
	seen time.Time
}

func newIPLimiter(perSecond float64, burst int) *ipLimiter {
	return &ipLimiter{limit: rate.Limit(perSecond), burst: burst, entries: map[string]*ipEntry{}}
}

// Allow は remoteAddr(host:port)の IP に対して 1 回分の試行を許すか。
func (l *ipLimiter) Allow(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e := l.entries[host]
	if e == nil {
		e = &ipEntry{lim: rate.NewLimiter(l.limit, l.burst)}
		l.entries[host] = e
		// たまに古い項目を捨てる(IP の数だけ増え続けないように)
		if len(l.entries) > 4096 {
			for k, v := range l.entries {
				if now.Sub(v.seen) > 10*time.Minute {
					delete(l.entries, k)
				}
			}
		}
	}
	e.seen = now
	return e.lim.Allow()
}
