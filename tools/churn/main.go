// churn は短い TCP の接続を決まった速さで次々に開く負荷の道具で、lab/tcpquality.sh の TOOL=churn が使う。
// 1 本の接続は size byte の要求を送り、size byte の応答を読み、閉じる。速さは開く側の予定で決まり (開いた
// ループ)、応答を待たずに次の接続を開くので、相手が遅れても負荷は下がらない。遅れと断られた数がそのまま
// 測定の値になる。
//
//	churn serve -bind 192.168.50.3 -port 25800 -size 200 -close server
//	churn run -addr 198.51.100.1:41800 -rate 1000 -seconds 10 -size 200 -close server
//
// -close server は応答を書いた後に待ち受けの側が先に閉じ、-close client は開いた側が応答を読んだ後に先に
// 閉じる。先に閉じた側が TIME_WAIT を持つ。run は終わりに key=value の 1 行を出す。
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "run":
		os.Exit(run(os.Args[2:], os.Stdout))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: churn serve -bind ADDR -port PORT [-size N] [-close server|client]")
	fmt.Fprintln(os.Stderr, "       churn run -addr HOST:PORT -rate N [-seconds S] [-size N] [-close server|client] [-timeout D] [-max-inflight N]")
	os.Exit(2)
}

func closeFlag(fs *flag.FlagSet) *string {
	return fs.String("close", "server", "which end closes first: server or client")
}

func checkClose(s string) {
	if s != "server" && s != "client" {
		fmt.Fprintln(os.Stderr, "churn: -close is server or client")
		os.Exit(2)
	}
}

func serve(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	bind := fs.String("bind", "0.0.0.0", "listen address")
	port := fs.Int("port", 0, "listen port")
	size := fs.Int("size", 200, "bytes of each request and each response")
	closeBy := closeFlag(fs)
	fs.Parse(args)
	checkClose(*closeBy)
	ln, err := net.Listen("tcp4", net.JoinHostPort(*bind, fmt.Sprint(*port)))
	if err != nil {
		fmt.Fprintln(os.Stderr, "churn serve:", err)
		os.Exit(1)
	}
	fmt.Printf("churn serve: listening on %s\n", ln.Addr())
	serveOn(ln, *size, *closeBy)
}

// serveOn は ln の接続に応える。ln が閉じると戻る。
func serveOn(ln net.Listener, size int, closeBy string) {
	resp := make([]byte, size)
	for {
		c, err := ln.Accept()
		if errors.Is(err, net.ErrClosed) {
			return
		}
		if err != nil {
			// 一時的な誤り (fd の不足など) では止まらない
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go func() {
			defer c.Close()
			c.SetDeadline(time.Now().Add(30 * time.Second))
			req := make([]byte, size)
			if _, err := io.ReadFull(c, req); err != nil {
				return
			}
			if _, err := c.Write(resp); err != nil {
				return
			}
			if closeBy == "client" {
				io.Copy(io.Discard, c)
			}
		}()
	}
}

// outcome は 1 本の接続の結果の分類。
type outcome int

const (
	okOutcome outcome = iota
	refused
	reset
	dialTimeout
	xferTimeout
	short
	other
	// skipped は開いている接続が -max-inflight に達して、開かなかった予定の接続。
	// 「開いている」は開く側の数え方で、dial を始めてから自分で閉じ終えるまでを数える。SYN の再送を
	// 待つ接続、相手の accept の待ち行列にある接続、握手の後に RST で断られる途中の接続、相手の FIN を
	// 待つ接続も入るので、相手が保持する接続の数より大きくなりうる。
	skipped
	nOutcomes
)

var outcomeNames = [nOutcomes]string{"ok", "refused", "reset", "dial_timeout", "xfer_timeout", "short", "other", "skipped"}

func classify(err error, dialing bool) outcome {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return refused
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.EPIPE):
		return reset
	case errors.As(err, &ne) && ne.Timeout():
		if dialing {
			return dialTimeout
		}
		return xferTimeout
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return short
	}
	return other
}

type result struct {
	connect, total float64 // ms; 負なら値が無い
	out            outcome
}

func run(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	addr := fs.String("addr", "", "host:port to connect to")
	rate := fs.Float64("rate", 0, "new connections per second")
	seconds := fs.Float64("seconds", 10, "how long to open connections")
	size := fs.Int("size", 200, "bytes of each request and each response")
	timeout := fs.Duration("timeout", 5*time.Second, "limit on the connect and, separately, on the exchange")
	maxInflight := fs.Int64("max-inflight", 20000, "connections open at once; past it a planned connection is skipped and counted")
	closeBy := closeFlag(fs)
	fs.Parse(args)
	checkClose(*closeBy)
	if *addr == "" || *rate <= 0 || *seconds <= 0 || *size < 1 {
		usage()
	}
	planned := int(math.Round(*rate * *seconds))
	res := make([]result, planned)
	for i := range res {
		res[i] = result{-1, -1, other}
	}
	var inflight, inflightMax atomic.Int64
	var wg sync.WaitGroup
	req := make([]byte, *size)
	d := net.Dialer{Timeout: *timeout}
	one := func(i int) {
		defer wg.Done()
		defer inflight.Add(-1)
		t0 := time.Now()
		c, err := d.Dial("tcp4", *addr)
		if err != nil {
			res[i].out = classify(err, true)
			return
		}
		defer c.Close()
		res[i].connect = msSince(t0)
		c.SetDeadline(time.Now().Add(*timeout))
		buf := make([]byte, *size)
		if _, err = c.Write(req); err == nil {
			_, err = io.ReadFull(c, buf)
		}
		if err == nil && *closeBy == "server" {
			// 待ち受けの側が先に閉じるのを待つ。余分な byte は誤りとして数える
			var n int
			n, err = c.Read(buf[:1])
			if err == io.EOF {
				err = nil
			} else if err == nil && n > 0 {
				err = errors.New("unexpected data after the response")
			}
		}
		if err != nil {
			res[i].out = classify(err, false)
			return
		}
		res[i].total = msSince(t0)
		res[i].out = okOutcome
	}
	start := time.Now()
	for i := 0; i < planned; i++ {
		// i 本目の予定の時刻まで待つ。遅れた分は待たずにまとめて開き、平均の速さを保つ
		if wait := time.Until(start.Add(time.Duration(float64(i) / *rate * float64(time.Second)))); wait > 0 {
			time.Sleep(wait)
		}
		if inflight.Load() >= *maxInflight {
			res[i].out = skipped
			continue
		}
		n := inflight.Add(1)
		for {
			m := inflightMax.Load()
			if n <= m || inflightMax.CompareAndSwap(m, n) {
				break
			}
		}
		wg.Add(1)
		go one(i)
	}
	openEnd := time.Since(start).Seconds()
	wg.Wait()
	wall := time.Since(start).Seconds()
	fmt.Fprintln(w, summary(res, *rate, *seconds, *size, inflightMax.Load(), openEnd, wall))
	if count(res, okOutcome) == 0 {
		return 1
	}
	return 0
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Nanoseconds()) / 1e6 }

func count(res []result, o outcome) int {
	n := 0
	for _, r := range res {
		if r.out == o {
			n++
		}
	}
	return n
}

// quantile は昇順の値の q 分位 (最も近い順位) を返す。値が無ければ -1。
func quantile(sorted []float64, q float64) float64 {
	if len(sorted) == 0 {
		return -1
	}
	k := int(math.Ceil(q*float64(len(sorted)))) - 1
	if k < 0 {
		k = 0
	}
	return sorted[k]
}

// summary は run の結果の 1 行。received は相手と往復した中身の byte (要求と応答の和) で、lab/tcpquality.sh が
// byte あたりの CPU の分母に使う。
func summary(res []result, rate, seconds float64, size int, inflightMax int64, openEnd, wall float64) string {
	var counts [nOutcomes]int
	var conn, total []float64
	over1s := 0
	for _, r := range res {
		counts[r.out]++
		if r.connect >= 0 {
			conn = append(conn, r.connect)
			if r.connect >= 1000 {
				over1s++
			}
		}
		if r.total >= 0 {
			total = append(total, r.total)
		}
	}
	sort.Float64s(conn)
	sort.Float64s(total)
	ok := counts[okOutcome]
	var b strings.Builder
	fmt.Fprintf(&b, "received=%d churn_rate=%g churn_seconds=%g churn_size=%d churn_planned=%d",
		ok*2*size, rate, seconds, size, len(res))
	for o := okOutcome; o < nOutcomes; o++ {
		fmt.Fprintf(&b, " churn_%s=%d", outcomeNames[o], counts[o])
	}
	fmt.Fprintf(&b, " churn_ok_per_s=%.1f churn_open_s=%.3f churn_wall_s=%.3f churn_inflight_max=%d churn_connect_over_1s=%d",
		float64(ok)/seconds, openEnd, wall, inflightMax, over1s)
	for _, s := range []struct {
		name string
		v    []float64
	}{{"connect", conn}, {"rr", total}} {
		fmt.Fprintf(&b, " churn_%s_p50_ms=%.3f churn_%s_p99_ms=%.3f churn_%s_max_ms=%.3f",
			s.name, quantile(s.v, 0.5), s.name, quantile(s.v, 0.99), s.name, quantile(s.v, 1))
	}
	return b.String()
}
