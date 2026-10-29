package wgstack

import (
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stressPeer はトンネルの側の簡単な TCP の相手。Device の Read が返す packet に応え、順序どおりのデータを
// 確認し、時々 RST や FIN を送る。正しさではなく、核と Device の錠、通知、出力の選び方を並行に動かすための
// ものである。
type stressPeer struct {
	d     *Device
	mu    sync.Mutex
	conns map[uint16]*stressConn
	rng   *rand.Rand
}

type stressConn struct {
	snd, rcv uint32
	up       bool
	finSeen  bool
	finSent  bool
	reset    bool // RST を送った。RFC 5961 の challenge ACK には番号の合う RST で答える
	sent     int
	limit    int  // この量を送ったら止まる
	willFin  bool // 送り終えたら FIN を送る
}

func (p *stressPeer) write(s tseg) {
	p.d.Write([][]byte{buildPeer(s)}, 0)
}

func (p *stressPeer) open(port uint16, dport uint16) {
	p.mu.Lock()
	p.conns[port] = &stressConn{snd: 1000, limit: p.rng.IntN(256 << 10), willFin: p.rng.IntN(2) == 0}
	p.mu.Unlock()
	p.write(tseg{sport: port, dport: dport, seq: 999, flags: flagSYN, wnd: 65535, mss: 1380, ws: 7, sackOK: true, ts: true, tsVal: 1})
}

// handle は Device の packet 1 つに応える。
func (p *stressPeer) handle(pkt []byte) {
	ip, d := parseIPv4(pkt)
	if d != ipv4OK {
		return
	}
	seg, td := parseTCP(&ip)
	if td != tcpOK {
		return
	}
	if seg.tup.laddr != addrBits(peerAddr) {
		return // どの接続にも当たらない segment への RST
	}
	port := seg.tup.lport
	p.mu.Lock()
	c := p.conns[port]
	if c == nil {
		p.mu.Unlock()
		return
	}
	var reply []tseg
	base := tseg{sport: port, dport: seg.tup.rport, wnd: 65535, ws: -1, ts: true, tsVal: 2 + uint32(time.Since(stressStart).Milliseconds()), tsEcr: seg.opt.tsVal}
	if c.reset {
		if !seg.has(flagRST) {
			r := base
			r.seq, r.flags = seg.ack, flagRST
			reply = append(reply, r)
		}
		p.mu.Unlock()
		for _, r := range reply {
			p.write(r)
		}
		return
	}
	switch {
	case seg.has(flagRST):
		stressRSTs.Add(1)
		delete(p.conns, port)
	case seg.has(flagSYN):
		c.rcv, c.up = seg.seq+1, true
		r := base
		r.seq, r.ack, r.flags = c.snd, c.rcv, flagACK
		reply = append(reply, r)
	case len(seg.payload) > 0 && seg.seq != c.rcv:
		// 順序外か重複:今の累積の確認を返す
		r := base
		r.seq, r.ack, r.flags = c.snd, c.rcv, flagACK
		reply = append(reply, r)
	case seg.seq == c.rcv && (len(seg.payload) > 0 || seg.has(flagFIN)):
		c.rcv += uint32(len(seg.payload))
		r := base
		if seg.has(flagFIN) {
			c.rcv++
			c.finSeen = true
			stressDutFin.Add(1)
			if !c.finSent && p.rng.IntN(2) == 0 {
				r.flags = flagFIN
				c.finSent = true
			}
		}
		r.seq, r.ack, r.flags = c.snd, c.rcv, r.flags|flagACK
		if r.flags&flagFIN != 0 {
			c.snd++
		}
		reply = append(reply, r)
	}
	if c.up && c.willFin && !c.finSeen && !c.finSent && c.sent >= c.limit {
		// 送り終えた相手の半分は FIN を送り、残りは黙る
		r := base
		r.seq, r.ack, r.flags = c.snd, c.rcv, flagFIN|flagACK
		c.snd++
		c.finSent = true
		reply = append(reply, r)
	}
	// Device の窓の右端を守る
	edge := seg.ack + uint32(seg.wnd)<<rcvWindowShft
	size := 1 + p.rng.IntN(1300)
	if c.up && !c.finSeen && !c.finSent && c.sent < c.limit && seqLE(c.snd+uint32(size), edge) && p.rng.IntN(3) == 0 {
		r := base
		r.seq, r.ack, r.flags = c.snd, c.rcv, flagACK
		r.payload = make([]byte, size)
		c.snd += uint32(len(r.payload))
		c.sent += len(r.payload)
		reply = append(reply, r)
	}
	switch p.rng.IntN(5000) {
	case 0:
		r := base
		r.seq, r.ack, r.flags = c.snd, c.rcv, flagRST|flagACK
		reply = append(reply, r)
		c.reset = true
	}
	p.mu.Unlock()
	for _, r := range reply {
		p.write(r)
	}
}

// TestStressRace は、多数の接続への同時の読み書き、Close、Abort、CloseWrite、待ち受けの Close、Device の
// Close、boost の取得と回収、TIME_WAIT の表の追い出しを、入力と出力と並べて動かす。-race で流す。確かめるのは、
// 錠の待ちが止まらないことと、Device の Close の後に goroutine と予約が残らないことである。
func TestStressRace(t *testing.T) {
	before := runtime.NumGoroutine()
	pool := newBoostPool(2)
	lim := limits{maxFlows: 32, acceptQ: 16, synRows: 64, twRows: 4, ctlSlots: 32}
	var devs []*Device
	for i := 0; i < 2; i++ {
		d, err := newDevice(Config{Addr: dutAddr, MTU: testMTU}, lim, pool)
		if err != nil {
			t.Fatal(err)
		}
		devs = append(devs, d)
	}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	dur := 3 * time.Second
	if testing.Short() {
		dur = 300 * time.Millisecond
	}
	for di, d := range devs {
		p := &stressPeer{d: d, conns: map[uint16]*stressConn{}, rng: rand.New(rand.NewPCG(uint64(di), 1))}
		// 出力を読む
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, 2000)
			sizes := []int{0}
			for {
				if _, err := d.Read([][]byte{buf}, sizes, 0); err != nil {
					return
				}
				p.handle(buf[:sizes[0]])
			}
		}()
		// 待ち受けを開き直しながら受け付ける
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := rand.New(rand.NewPCG(uint64(di), 2))
			for {
				select {
				case <-stop:
					return
				default:
				}
				l, err := d.ListenTCP(netip.AddrPortFrom(dutAddr, 80))
				if err != nil {
					time.Sleep(time.Millisecond)
					continue
				}
				life := time.Duration(50+r.IntN(100)) * time.Millisecond
				go func() {
					time.Sleep(life)
					l.Close()
				}()
				for {
					nc, err := l.Accept()
					if err != nil {
						break
					}
					c := nc.(*Conn)
					wg.Add(1)
					go func(seed uint64) {
						defer wg.Done()
						serve(c, rand.New(rand.NewPCG(seed, 3)))
					}(r.Uint64())
				}
			}
		}()
		// 接続を開く
		wg.Add(1)
		go func() {
			defer wg.Done()
			port := uint16(1024)
			for {
				select {
				case <-stop:
					return
				default:
				}
				port++
				if port == 0 {
					port = 1025
				}
				p.open(port, 80)
				time.Sleep(200 * time.Microsecond)
			}
		}()
		// どの接続にも当たらない segment
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				p.write(tseg{src: spoofed(i), sport: uint16(i), dport: uint16(i % 7), seq: uint32(i), ack: 1, flags: flagACK, ws: -1})
				time.Sleep(100 * time.Microsecond)
			}
		}()
		// 数を読む
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				case <-time.After(10 * time.Millisecond):
					st := d.Stats()
					if int64(st.TWRows) > stressMaxTW.Load() {
						stressMaxTW.Store(int64(st.TWRows))
					}
				}
			}
		}()
	}
	time.Sleep(dur)
	close(stop)
	for _, d := range devs {
		d.Close()
	}
	waitDone := make(chan struct{})
	go func() { wg.Wait(); close(waitDone) }()
	select {
	case <-waitDone:
	case <-time.After(10 * time.Second):
		buf := make([]byte, 1<<20)
		t.Fatalf("goroutines did not finish:\n%s", buf[:runtime.Stack(buf, true)])
	}
	for _, d := range devs {
		st := d.s.stats()
		if st.Conns != 0 || st.SynRows != 0 || st.TWRows != 0 || st.ChunkBytes != 0 || st.HeldChunksInPool != 0 {
			t.Errorf("after Close %+v", st)
		}
		t.Logf("boost granted %d reclaimed %d, TIME_WAIT evicted %d, challenge limited %d", st.BoostGranted, st.BoostReclaimed, st.TWEvicted, st.ChallengeLimited)
	}
	t.Logf("accepted %d connections, read %d bytes, at most %d TIME_WAIT rows; %d FINs and %d RSTs from the Devices", stressAccepted.Load(), stressRead.Load(), stressMaxTW.Load(), stressDutFin.Load(), stressRSTs.Load())
	if pool.held() != 0 {
		t.Errorf("pool holds %d slots", pool.held())
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<20)
		t.Errorf("%d goroutines left, %d before:\n%s", n, before, buf[:runtime.Stack(buf, true)])
	}
}

// serve は中継のように接続を読み書きし、ばらばらの終わり方で閉じる。
var (
	stressAccepted, stressRead, stressMaxTW, stressIdle, stressDutFin, stressRSTs atomic.Int64
	stressStart                                                                   = time.Now()
)

func serve(c *Conn, r *rand.Rand) {
	stressAccepted.Add(1)
	refuse := r.IntN(4) == 0
	c.OnBoost(func(b bool) bool { return b || !refuse })
	wr := rand.New(rand.NewPCG(r.Uint64(), 4))
	go func() {
		buf := make([]byte, 64<<10)
		for i := 0; i < 50; i++ {
			c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
			if _, err := c.Write(buf[:1+wr.IntN(len(buf)-1)]); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 32<<10)
	quiet := 0
	for {
		c.SetReadDeadline(time.Now().Add(time.Duration(10+r.IntN(40)) * time.Millisecond))
		k, err := c.Read(buf)
		stressRead.Add(int64(k))
		if err == io.EOF {
			break
		}
		if k > 0 {
			quiet = 0
		}
		if err != nil {
			// 黙った相手は 3 回続けて期限を過ぎたら閉じる
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if quiet++; quiet < 3 {
					continue
				}
			}
			break
		}
	}
	c.c.mu.Lock()
	boosted := c.c.gen == c.gen && c.c.boosted
	c.c.mu.Unlock()
	if boosted {
		if stressIdle.Add(1) <= 2 {
			time.Sleep(1200 * time.Millisecond) // 需要の無い保有者として残り、回収の対象になる
		}
		stressIdle.Add(-1)
	}
	switch r.IntN(4) {
	case 0:
		c.Abort()
	case 1:
		c.CloseWrite()
		time.Sleep(time.Duration(r.IntN(20)) * time.Millisecond)
		c.Close()
	default:
		c.Close()
	}
	c.Delivered()
	if r.IntN(2) == 0 {
		c.Abort() // 古い接続の値の Abort
	}
}
