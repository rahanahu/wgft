// ppecho は PROXY protocol v2 を解する簡易受信側(テスト用の Caddy 代役)。
// 接続を受けたら、PROXY ヘッダから読み取った元クライアント IP を 1 行返す。
package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

func main() {
	addr := flag.String("addr", "0.0.0.0:25565", "listen address")
	flag.Parse()
	raw, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	ln := &proxyproto.Listener{Listener: raw, Policy: func(net.Addr) (proxyproto.Policy, error) { return proxyproto.USE, nil }}
	log.Printf("ppecho listening on %s", *addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			fmt.Fprintf(c, "client=%s\n", c.RemoteAddr())
		}(c)
	}
}
