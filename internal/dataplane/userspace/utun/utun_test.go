package utun

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
)

// プロセス内でサーバ側トンネルと、エージェント側の tunnel を実 UDP(127.0.0.1)で繋ぐ。
// ピアの動的な追加と削除、IpcGet の状態、netstack 越しの dial(TCP、UDP、3,000 バイトの UDP)を見る。
func TestServerTunnelWithAgentTunnel(t *testing.T) {
	sk, _ := wgtypes.GeneratePrivateKey()
	ck, _ := wgtypes.GeneratePrivateKey()
	quiet := func(string, ...any) {}

	// listen_port は空いているものを探す
	var srv *Tunnel
	var port uint16
	for p := uint16(51900); p < 51950; p++ {
		s, err := New(Config{PrivateKey: sk, ListenPort: p, Address: netip.MustParseAddr("10.200.0.1"), Logf: quiet})
		if err == nil {
			srv, port = s, p
			break
		}
	}
	if srv == nil {
		t.Fatal("no free port for the server tunnel")
	}
	defer srv.Close()

	client, err := tunnel.New(tunnel.Config{
		PrivateKey: ck, ServerPublicKey: sk.PublicKey(), Endpoint: fmt.Sprintf("127.0.0.1:%d", port),
		Address: netip.MustParseAddr("10.200.0.2"), ServerAddress: netip.MustParseAddr("10.200.0.1"),
		MTU: 1420, Keepalive: time.Second, Logf: quiet,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// エージェント側のリスナー(echo)。実効宛先への中継の代わり
	ln, err := client.ListenTCP(2456)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 4096)
				n, _ := c.Read(buf)
				fmt.Fprintf(c, "%s from %s", buf[:n], c.RemoteAddr())
			}()
		}
	}()
	pc, err := client.ListenUDP(2456)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(buf[:n], from)
		}
	}()

	// 1. ピアを足す → エージェントの握手(再送は 5 秒後)を待つ
	if _, err := srv.SetPeers([]dataplane.Peer{{PublicKey: ck.PublicKey(), Address: netip.MustParseAddr("10.200.0.2")}}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	var st PeerStatus
	for time.Now().Before(deadline) {
		peers, err := srv.Peers()
		if err != nil {
			t.Fatal(err)
		}
		if st = peers[ck.PublicKey()]; !st.LastHandshake.IsZero() {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if st.LastHandshake.IsZero() {
		t.Fatal("no handshake with the agent tunnel within 20s")
	}
	if !st.Endpoint.IsValid() || st.Endpoint.Addr() != netip.MustParseAddr("127.0.0.1") {
		t.Fatalf("endpoint not learned: %v", st.Endpoint)
	}

	// 2. netstack 越しの TCP と UDP。エージェントから見た送信元は 10.200.0.1
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := srv.DialContext(ctx, "tcp", "10.200.0.2:2456")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(c, "hi")
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); len(got) < len("hi from 10.200.0.1:") || got[:len("hi from 10.200.0.1:")] != "hi from 10.200.0.1:" {
		t.Fatalf("tcp reply %q", got)
	}
	u, err := srv.DialUDP(netip.MustParseAddrPort("10.200.0.2:2456"))
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	u.SetDeadline(time.Now().Add(5 * time.Second))
	big := make([]byte, 3000)
	for i := range big {
		big[i] = byte(i)
	}
	// UDP の接続は、届くまでバッファを持たずに待てる(仕様 7 節)。届く前は戻らず、届いたら戻る
	w, ok := u.(interface{ WaitReadable() error })
	if !ok {
		t.Fatal("udp conn of the tunnel must implement WaitReadable")
	}
	ready := make(chan error, 1)
	go func() { ready <- w.WaitReadable() }()
	select {
	case err := <-ready:
		t.Fatalf("WaitReadable returned before any datagram: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	if _, err := u.Write(big); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ready:
		if err != nil {
			t.Fatalf("WaitReadable: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("WaitReadable did not return after the reply arrived")
	}
	n, err = u.Read(buf)
	if err != nil {
		t.Fatalf("3000-byte udp: %v", err)
	}
	if n != 3000 || string(buf[:n]) != string(big) {
		t.Fatalf("3000-byte udp: got %d bytes", n)
	}

	// 3. ピアを消すと届かなくなる
	if _, err := srv.SetPeers(nil); err != nil {
		t.Fatal(err)
	}
	peers, _ := srv.Peers()
	if len(peers) != 0 {
		t.Fatalf("peers after removal: %d", len(peers))
	}
	u2, _ := srv.DialUDP(netip.MustParseAddrPort("10.200.0.2:2456"))
	defer u2.Close()
	u2.SetDeadline(time.Now().Add(2 * time.Second))
	u2.Write([]byte("x"))
	if _, err := u2.Read(buf); err == nil {
		t.Fatal("agent still reachable after the peer was removed")
	}
	// 閉じた接続の WaitReadable は誤りで戻る(relay の読み手の goroutine が終われる)
	go func() { ready <- u2.(interface{ WaitReadable() error }).WaitReadable() }()
	time.Sleep(100 * time.Millisecond)
	u2.Close()
	select {
	case err := <-ready:
		if err == nil {
			t.Fatal("WaitReadable on a closed conn must fail")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitReadable did not return after Close")
	}
	_ = net.IPv4zero
}
