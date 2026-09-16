// echo はテスト用のエコーサーバ。UDP は受けたデータグラムの長さと送信元を返し、
// TCP は相手の EOF まで読んでからバイト数を返して CloseWrite する(ハーフクローズの確認用)。
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

func main() {
	bind := flag.String("bind", "0.0.0.0", "listen address")
	udp := flag.String("udp", "", "UDP ports, comma-separated")
	tcp := flag.String("tcp", "", "TCP ports, comma-separated")
	flag.Parse()
	for _, p := range ports(*udp) {
		go serveUDP(net.JoinHostPort(*bind, p))
	}
	for _, p := range ports(*tcp) {
		go serveTCP(net.JoinHostPort(*bind, p))
	}
	select {}
}

func serveUDP(addr string) {
	pc, err := net.ListenPacket("udp4", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("udp %s", addr)
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		log.Printf("udp %s from=%s len=%d", addr, from, n)
		pc.WriteTo([]byte(fmt.Sprintf("udp-echo %s from=%s len=%d\n", addr, from, n)), from)
	}
}

func serveTCP(addr string) {
	ln, err := net.Listen("tcp4", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tcp %s", addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			n, _ := io.Copy(io.Discard, c)
			log.Printf("tcp %s from=%s got=%d", addr, c.RemoteAddr(), n)
			fmt.Fprintf(c, "tcp-echo %s from=%s got=%d; sent after peer EOF\n", addr, c.RemoteAddr(), n)
			c.(*net.TCPConn).CloseWrite()
		}()
	}
}

func ports(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" {
			if _, err := strconv.ParseUint(f, 10, 16); err != nil {
				log.Fatalf("invalid port %q", f)
			}
			out = append(out, f)
		}
	}
	return out
}
