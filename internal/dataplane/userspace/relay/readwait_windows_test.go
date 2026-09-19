//go:build windows

package relay

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// WaitReadable はデータグラムが届くまでは戻らず、届いたら戻る。続く Read は最初の 1 個を欠けずに読む。
// 60000 バイトという大きめのデータグラムで、途中の zero-byte MSG_PEEK が中身を取り出さないことを確かめる。
func TestWindowsRawWaiterWaitsForDatagram(t *testing.T) {
	target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	session, err := net.DialUDP("udp4", nil, target.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	w := kernelReadWaiter(session)
	if w == nil {
		t.Fatal("kernelReadWaiter returned nil on windows")
	}

	// target に自分のアドレスを覚えさせる(実際の中継と同じく、応答は session の送信元へ返る)
	if _, err := session.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	target.SetReadDeadline(time.Now().Add(2 * time.Second))
	greetBuf := make([]byte, 16)
	_, from, err := target.ReadFrom(greetBuf)
	if err != nil {
		t.Fatalf("target did not see the greeting: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- w.WaitReadable() }()

	// まだ何も送っていないので、WaitReadable はすぐには戻らないはず
	select {
	case err := <-done:
		t.Fatalf("WaitReadable returned before any datagram arrived (err=%v)", err)
	case <-time.After(200 * time.Millisecond):
	}

	msg := bytes.Repeat([]byte{'z'}, 60000)
	if _, err := target.WriteTo(msg, from); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitReadable: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitReadable did not return after the datagram arrived")
	}

	buf := make([]byte, 65535)
	session.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := session.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], msg) {
		t.Fatalf("got %d bytes, want the whole %d-byte datagram unmodified", n, len(msg))
	}
}

// 接続済みの UDP ソケットへ、待ち受けの無い loopback のポートへ送ると ICMP port unreachable が
// カーネルからは返る。しかし Go の net パッケージは、Windows の UDP ソケットを作るたびに
// SIO_UDP_CONNRESET で WSAECONNRESET の通知そのものを無効にしている
// (GOROOT/src/net/fd_windows.go の netFD.init、https://go.dev/issue/5834)。したがって
// net.Dial で作った接続済み UDP ソケットでは、ICMP port unreachable は誤りとして現れず、
// 応答の無い相手と見分けが付かない。この待ちは busy loop ではなく(IOCP の完了通知任せ)、
// Close で確実に解ける(本番では udp.go の無通信タイムアウトがセッションを閉じることでこれに当たる)
// ことを確かめる。
func TestWindowsRawWaiterIgnoresICMPPortUnreachableAndUnblocksOnClose(t *testing.T) {
	port := freePort(t) // 誰も listen していない UDP の宛先(TestUDPNoTargetCheck と同じ流儀)
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		t.Fatal(err)
	}

	w := kernelReadWaiter(conn)
	if w == nil {
		t.Fatal("kernelReadWaiter returned nil on windows")
	}

	if _, err := conn.Write([]byte("hi")); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- w.WaitReadable() }()

	select {
	case err := <-done:
		t.Fatalf("WaitReadable returned before Close (err=%v); ICMP port unreachable must not surface as an error on Windows (SIO_UDP_CONNRESET is disabled by net)", err)
	case <-time.After(1 * time.Second):
		// 期待どおり:ICMP が届いていても誤りにならず、待ち続けている
	}

	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("WaitReadable should return an error once the connection is closed")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WaitReadable did not unblock after Close (hang)")
	}
}
