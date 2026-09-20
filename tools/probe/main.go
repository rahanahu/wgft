// probe はテスト用の TCP/UDP クライアント。scripts/dist-vm.sh (B9) が、実機に近い VM の中で
// wgft を経由した転送を確かめるために使う。同じ VM に socat や python3 が入っている保証が無く、
// apt でも入れられない(lab/README.md の「VM が IPv4 で外に出られない」)ため、CGO 無しの静的
// バイナリとして自前で用意する。1 行送って、相手の応答を 1 回読み、標準出力にそのまま書く。
// tools/echo の応答("tcp-echo ..."、"udp-echo ...")をそのまま呼び出し側が照合できる。
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"
)

func main() {
	proto := flag.String("proto", "tcp", "tcp or udp")
	addr := flag.String("addr", "", "host:port")
	timeout := flag.Duration("timeout", 3*time.Second, "dial and read timeout")
	data := flag.String("data", "hi\n", "payload to send")
	flag.Parse()
	if *addr == "" {
		fmt.Fprintln(os.Stderr, "probe: -addr is required")
		os.Exit(2)
	}
	var network string
	switch *proto {
	case "tcp":
		network = "tcp4"
	case "udp":
		network = "udp4"
	default:
		fmt.Fprintln(os.Stderr, "probe: -proto must be tcp or udp")
		os.Exit(2)
	}

	conn, err := net.DialTimeout(network, *addr, *timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe: dial:", err)
		os.Exit(1)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(*data)); err != nil {
		fmt.Fprintln(os.Stderr, "probe: write:", err)
		os.Exit(1)
	}
	// tools/echo の TCP 側は相手の EOF を待ってから応答するので、送り終えたら書き込み側を閉じる。
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.CloseWrite()
	}

	conn.SetReadDeadline(time.Now().Add(*timeout))
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		fmt.Fprintln(os.Stderr, "probe: read:", err)
		os.Exit(1)
	}
	os.Stdout.Write(buf[:n])
}
