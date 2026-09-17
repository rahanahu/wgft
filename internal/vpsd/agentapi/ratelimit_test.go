package agentapi

import (
	"container/list"
	"fmt"
	"testing"
	"time"
)

// TestIPLimiterKeyIPv4 は IPv4 の送信元をアドレスそのもので鍵にすることを確かめる。
func TestIPLimiterKeyIPv4(t *testing.T) {
	a := ipLimiterKey("203.0.113.1:5555")
	b := ipLimiterKey("203.0.113.1:9999")
	c := ipLimiterKey("203.0.113.2:5555")
	if a != b {
		t.Fatalf("same IPv4 host with different ports should share a key: %q != %q", a, b)
	}
	if a == c {
		t.Fatalf("different IPv4 hosts should not share a key: %q == %q", a, c)
	}
}

// TestIPLimiterKeyIPv6Aggregation は、同じ /64 に属する IPv6 アドレスが 1 つの鍵に
// まとまり、別の /64 のアドレスとは鍵が分かれることを確かめる(1 ホストが /64 の
// 中でアドレスを変えるだけで無数の鍵を作れないようにする要件)。
func TestIPLimiterKeyIPv6Aggregation(t *testing.T) {
	same1 := ipLimiterKey("[2001:db8:1234:5678::1]:5555")
	same2 := ipLimiterKey("[2001:db8:1234:5678:aaaa:bbbb:cccc:dddd]:6666")
	if same1 != same2 {
		t.Fatalf("addresses in the same /64 should share a key: %q != %q", same1, same2)
	}

	other := ipLimiterKey("[2001:db8:1234:5679::1]:5555")
	if same1 == other {
		t.Fatalf("addresses in different /64s should not share a key: %q == %q", same1, other)
	}

	// 期待どおりのプレフィクス文字列になっているかも確かめる。
	want := "2001:db8:1234:5678::/64"
	if same1 != want {
		t.Fatalf("key = %q, want %q", same1, want)
	}
}

// TestIPLimiterKeyIPv4In6 は ::ffff:a.b.c.d 形式の IPv4-mapped IPv6 アドレスを
// IPv4 として鍵にすることを確かめる(Unmap の確認)。
func TestIPLimiterKeyIPv4In6(t *testing.T) {
	mapped := ipLimiterKey("[::ffff:203.0.113.1]:5555")
	plain := ipLimiterKey("203.0.113.1:9999")
	if mapped != plain {
		t.Fatalf("4-in-6 address should key the same as the plain IPv4 address: %q != %q", mapped, plain)
	}
}

// TestIPLimiterCapBounded は、上限を超える数の別々の送信元から Allow を呼んでも、
// entries が cap を超えないことを確かめる。
func TestIPLimiterCapBounded(t *testing.T) {
	l := newIPLimiter(1000, 1000)
	l.cap = 8
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	l.now = func() time.Time { return clock }

	for i := 0; i < l.cap*4; i++ {
		addr := fmt.Sprintf("203.0.113.%d:1", i%256)
		l.Allow(addr)
		clock = clock.Add(time.Second)

		l.mu.Lock()
		n := len(l.entries)
		orderLen := l.order.Len()
		l.mu.Unlock()
		if n > l.cap {
			t.Fatalf("after inserting %d distinct sources, entries has %d items, want <= cap %d", i+1, n, l.cap)
		}
		if orderLen != n {
			t.Fatalf("order list has %d items, entries map has %d; they must stay in sync", orderLen, n)
		}
	}
}

// TestIPLimiterEvictsLeastRecentlySeen は、上限に達した状態で新しい送信元が来ると、
// 最も長く Allow を呼ばれていない送信元が追い出され、最近使った送信元は残ることを
// 確かめる(LRU の追い出し経路)。TTL 内に収まる短い時間しか進めないため、
// 期限切れによる一掃ではなく LRU の追い出しだけが働く。
func TestIPLimiterEvictsLeastRecentlySeen(t *testing.T) {
	l := newIPLimiter(1000, 1000)
	l.cap = 3
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	l.now = func() time.Time { return clock }

	// 3 件で table を満たす: a, b, c
	l.Allow("203.0.113.1:1") // a
	clock = clock.Add(time.Second)
	l.Allow("203.0.113.2:1") // b
	clock = clock.Add(time.Second)
	l.Allow("203.0.113.3:1") // c
	clock = clock.Add(time.Second)

	// a に触れて最近使ったことにする。
	l.Allow("203.0.113.1:1") // touch a
	clock = clock.Add(time.Second)

	// 新しい送信元 d を入れる。b が最も長く使われていないので追い出されるはず。
	l.Allow("203.0.113.4:1") // d

	l.mu.Lock()
	_, hasA := l.entries[ipLimiterKey("203.0.113.1:1")]
	_, hasB := l.entries[ipLimiterKey("203.0.113.2:1")]
	_, hasC := l.entries[ipLimiterKey("203.0.113.3:1")]
	_, hasD := l.entries[ipLimiterKey("203.0.113.4:1")]
	n := len(l.entries)
	l.mu.Unlock()

	if n != l.cap {
		t.Fatalf("entries has %d items, want cap %d", n, l.cap)
	}
	if hasB {
		t.Fatalf("b should have been evicted as the least recently seen entry")
	}
	if !hasA || !hasC || !hasD {
		t.Fatalf("a, c, d should remain: hasA=%v hasC=%v hasD=%v", hasA, hasC, hasD)
	}
}

// TestIPLimiterSweepsExpired は、上限に達した状態で ipLimiterTTL を過ぎた項目が
// あれば、次の一掃(cap を突いたとき)でそれが取り除かれることを確かめる。
func TestIPLimiterSweepsExpired(t *testing.T) {
	l := newIPLimiter(1000, 1000)
	l.cap = 3
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	l.now = func() time.Time { return clock }

	l.Allow("203.0.113.1:1")
	l.Allow("203.0.113.2:1")
	l.Allow("203.0.113.3:1")

	// TTL と一掃の間隔を両方超えるまで時計を進める。どの送信元にも触れていないので
	// 3 件とも期限切れになる。
	clock = clock.Add(ipLimiterTTL + ipLimiterSweepInterval + time.Second)

	l.Allow("203.0.113.4:1")

	l.mu.Lock()
	n := len(l.entries)
	_, hasD := l.entries[ipLimiterKey("203.0.113.4:1")]
	l.mu.Unlock()

	if n != 1 || !hasD {
		t.Fatalf("expired entries should have been swept, leaving only the new one; entries=%d hasD=%v", n, hasD)
	}
}

// TestIPLimiterFailsClosedWhenCapIsZero は、cap を 0 にした極端な設定でも、
// panic したり無制限に entries を増やしたりせず、新しい送信元を拒否する
// (fail closed)ことを確かめる。
func TestIPLimiterFailsClosedWhenCapIsZero(t *testing.T) {
	l := newIPLimiter(1000, 1000)
	l.cap = 0

	if l.Allow("203.0.113.1:1") {
		t.Fatalf("Allow should fail closed (return false) when cap is 0")
	}

	l.mu.Lock()
	n := len(l.entries)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("entries should stay empty when cap is 0, got %d", n)
	}
}

// TestIPLimiterKnownSourceUnaffectedByCap は、すでに entries にある送信元は、
// table が上限に達していても Allow を呼び続けられることを確かめる
// (上限は新しい送信元の追加だけを制限する)。
func TestIPLimiterKnownSourceUnaffectedByCap(t *testing.T) {
	l := newIPLimiter(1000, 1000)
	l.cap = 2
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	l.now = func() time.Time { return clock }

	l.Allow("203.0.113.1:1")
	l.Allow("203.0.113.2:1")

	for i := 0; i < 5; i++ {
		clock = clock.Add(time.Second)
		if !l.Allow("203.0.113.1:1") {
			// レート制限そのものは burst=1000 で十分緩いので、ここで false が
			// 返るなら容量の扱いに問題がある。
			t.Fatalf("known source should still be tracked while table is at capacity (iteration %d)", i)
		}
	}
}

// TestIPLimiterEvictionIsNotFullScan は、一掃の間隔内では LRU の追い出しが
// entries 全体を走査せず、doubly linked list の末尾を O(1) で操作するだけで
// 済むことを確かめる。container/list の Back/Remove 自体は定義上 O(1) なので、
// ここでは evictLocked が (一掃をスキップした場合に) entries をレンジしないこと、
// つまり order の操作だけで空きを作れることを、大きな table で挿入回数あたりの
// 時間がほぼ一定であることを測って示す。
func TestIPLimiterEvictionIsNotFullScan(t *testing.T) {
	l := newIPLimiter(1000, 1000)
	l.cap = 2000
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := base
	l.now = func() time.Time { return clock }

	// table を満たす。まだ一掃も LRU の追い出しも起きない。
	for i := 0; i < l.cap; i++ {
		l.Allow(fmt.Sprintf("10.%d.%d.%d:1", i/65536, (i/256)%256, i%256))
	}
	// 直後の一掃を起きなくするため、時計を進めずに次の一掃間隔をリセットする。
	l.mu.Lock()
	l.lastSweep = clock
	l.mu.Unlock()

	// 一掃間隔の外では evictLocked は sweepExpiredLocked を呼ばず、order.Back の
	// O(1) 除去だけで空きを作る。これを、一掃間隔の内側(スキップされる側)で
	// N 回追い出しにかかる時間を計測し、table の大きさに対してほぼ一定である
	// ことで裏付ける。
	const rounds = 20000
	start := time.Now()
	for i := 0; i < rounds; i++ {
		addr := fmt.Sprintf("10.%d.%d.%d:1", (l.cap+i)/65536, ((l.cap+i)/256)%256, (l.cap+i)%256)
		l.Allow(addr)
	}
	elapsed := time.Since(start)

	l.mu.Lock()
	n := len(l.entries)
	orderLen := l.order.Len()
	l.mu.Unlock()
	if n > l.cap {
		t.Fatalf("entries has %d items after %d evicting inserts, want <= cap %d", n, rounds, l.cap)
	}
	if orderLen != n {
		t.Fatalf("order list has %d items, entries map has %d", orderLen, n)
	}

	// rounds 回の追い出しつき挿入が O(cap) の全走査を毎回していれば、この量
	// (cap=2000 x rounds=20000 の内積規模の作業)は現実的な時間では終わらない。
	// O(1) の LRU 除去であれば十分速く終わる。上限は環境差を許した緩いもの。
	if elapsed > 5*time.Second {
		t.Fatalf("evicting inserts took %s for %d rounds at cap %d; eviction may be scanning the whole table", elapsed, rounds, l.cap)
	}
}

// BenchmarkIPLimiterAllowAtCapacity は、table が上限に張り付いた定常状態での
// Allow 1 回あたりのコストを測る。一掃が間引かれ、LRU の O(1) 除去だけが働く
// ことを確かめるためのベンチマーク。go test -bench '.' -benchtime=... で走らせ、
// N (table の大きさ)を変えても 1 回あたりの時間がほぼ変わらないことを見る。
func BenchmarkIPLimiterAllowAtCapacity(b *testing.B) {
	l := newIPLimiter(1e9, 1e9) // レート制限そのものはベンチの邪魔にしない
	l.cap = 4096
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }

	for i := 0; i < l.cap; i++ {
		l.Allow(fmt.Sprintf("10.%d.%d.%d:1", i/65536, (i/256)%256, i%256))
	}
	l.mu.Lock()
	l.lastSweep = clock // 直後の一掃を起きなくする
	l.mu.Unlock()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		addr := fmt.Sprintf("10.%d.%d.%d:1", (l.cap+i)/65536, ((l.cap+i)/256)%256, (l.cap+i)%256)
		l.Allow(addr)
	}
}

// TestIPLimiterOrderListStaysConsistent は、entries と order が常に同じ要素数を
// 保つこと(補助構造の整合性)を、様々な操作を混ぜて確かめる。
func TestIPLimiterOrderListStaysConsistent(t *testing.T) {
	l := newIPLimiter(1000, 1000)
	l.cap = 16
	clock := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }

	for i := 0; i < 200; i++ {
		addr := fmt.Sprintf("203.0.%d.%d:1", (i/256)%256, i%256)
		l.Allow(addr)
		if i%3 == 0 {
			// 既知の送信元に再度触れる。
			l.Allow("203.0.113.1:1")
		}
		clock = clock.Add(time.Second)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.entries) != l.order.Len() {
		t.Fatalf("entries has %d items, order has %d", len(l.entries), l.order.Len())
	}
	if len(l.entries) > l.cap {
		t.Fatalf("entries has %d items, want <= cap %d", len(l.entries), l.cap)
	}
	seen := map[*list.Element]bool{}
	for _, el := range l.entries {
		seen[el] = true
	}
	for el := l.order.Front(); el != nil; el = el.Next() {
		if !seen[el] {
			t.Fatalf("order contains an element not present in entries")
		}
	}
}
