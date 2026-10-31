package wgstack

import (
	"errors"
	"net"
	"testing"
	"time"
)

// 枠を返すと世代を進めるので、枠を使い直した次の接続の中身を、前の接続の値(古い handle)からは読めない。
// 接続 A を Abort で終え、同じ枠を使う接続 B に相手が書いた byte を、A の handle の Read が net.ErrClosed で
// 拒むことを確かめる。
func TestStaleHandleDoesNotReadTheNextConnection(t *testing.T) {
	n := newTestNet(t, smallLimits())
	l := listen(t, n, 80)
	n.handshake(40000, 80, true, true, true)
	a := acceptOne(t, l)
	n.drain()
	slot := a.c.id
	a.Abort()
	n.drain()
	pb := n.handshake(40001, 80, true, true, true)
	b := acceptOne(t, l)
	n.drain()
	if b.c.id != slot {
		t.Fatalf("the second connection took slot %d, not the freed slot %d; the test needs the slot reused", b.c.id, slot)
	}
	secret := []byte("secret-of-b")
	pb.ack(secret)
	n.drain()
	buf := make([]byte, 64)
	if k, err := readWithin(t, a, buf); k != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Read on the aborted connection's handle = %d %q, %v; want 0 and net.ErrClosed", k, buf[:k], err)
	}
	if _, err := a.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write on the aborted connection's handle: %v, want net.ErrClosed", err)
	}
	if !a.Delivered() {
		t.Fatal("the aborted connection's handle is not Delivered")
	}
	k, err := readWithin(t, b, buf)
	if err != nil || string(buf[:k]) != string(secret) {
		t.Fatalf("the second connection read %q, %v", buf[:k], err)
	}
}

// readWithin は c.Read を呼び、5 秒以内に戻らなければ試験を失敗にする。退行で読み取りが待ち続けても、試験が
// 止まらずに失敗するためである。待ち続けた読み取りは、試験の後の Device の Close が解く。
func readWithin(t *testing.T, c *Conn, buf []byte) (int, error) {
	t.Helper()
	type res struct {
		n   int
		err error
	}
	ch := make(chan res, 1)
	go func() {
		k, err := c.Read(buf)
		ch <- res{k, err}
	}()
	select {
	case r := <-ch:
		return r.n, r.err
	case <-time.After(5 * time.Second):
		t.Fatal("Read did not return within 5 s")
		return 0, nil
	}
}

// 枠を返した直後(出力を読む前)に、空きの枠はタイマーの節も、接続の組の出力の list の節も、4 つ組の hash の表の
// 項も持たない(checkHeld が確かめる)。再送のタイマーを張り、送る ACK を出力の list に持つ接続を Abort と Close で
// 終える。
func TestFreedSlotHoldsNoTimerOutputOrIndexEntry(t *testing.T) {
	for _, how := range []string{"Abort", "Close with unread data"} {
		t.Run(how, func(t *testing.T) {
			n := newTestNet(t, smallLimits())
			c, p := n.accepted(true, true)
			if _, err := c.Write(make([]byte, 20000)); err != nil {
				t.Fatal(err)
			}
			n.drain()                // 送った data が再送のタイマーを張る
			p.ack(make([]byte, 100)) // 返す ACK が接続を出力の list に入れ、未読のデータが残る
			cs := &n.d.s.conns[c.c.id]
			cs.mu.Lock()
			armed := cs.tdl[tmrRetrans] != 0
			cs.mu.Unlock()
			n.d.s.out.mu.Lock()
			queued := n.d.s.out.conns.in[c.c.id]
			n.d.s.out.mu.Unlock()
			if !armed || !queued {
				t.Fatalf("before closing: timer armed %v, output queued %v; the test needs both", armed, queued)
			}
			if how == "Abort" {
				c.Abort()
			} else {
				c.Close() // 未読のデータを持つので RST で終えて枠を返す
			}
			if st := checkHeld(t, n); st.Conns != 0 {
				t.Fatalf("%d connections after %s", st.Conns, how)
			}
		})
	}
}

// アプリケーションの Close の後に自分の FIN の確認を処理する接続と、Device の Close が競っても、閉じた Device の
// TIME_WAIT の表に行を作らない(tryRetire の !s.closed)。相手の ACK を接続の錠の中で処理している間に Device の
// Close が表を閉じ、その後に接続が行に移る条件を満たす順を、錠で作る。
func TestRetireRacingDeviceCloseAddsNoRow(t *testing.T) {
	n := newTestNet(t, smallLimits())
	c, p := n.accepted(true, true)
	if err := c.Close(); err != nil { // FIN を送り、FIN_WAIT_1 になる
		t.Fatal(err)
	}
	outs := n.drain()
	p.absorb(outs)
	// 相手の FIN の確認。接続の錠を取る前に作る(錠を持ったまま試験を止めると、Device の Close が待ち続ける)
	pkt := buildPeer(p.seg(flagACK, nil))
	ip, d := parseIPv4(pkt)
	if d != ipv4OK {
		t.Fatal(d)
	}
	seg, td := parseTCP(&ip)
	if td != tcpOK {
		t.Fatal(td)
	}
	s := n.d.s
	cs := &s.conns[c.c.id]
	cs.mu.Lock()
	if cs.state != stFinWait1 {
		cs.mu.Unlock()
		t.Fatalf("state %v after Close, want FIN_WAIT_1", cs.state)
	}
	done := make(chan struct{})
	go func() {
		n.d.Close() // 表を閉じた後、この接続の錠を待つ
		close(done)
	}()
	for i := 0; ; i++ {
		s.tmu.Lock()
		closed := s.closed
		s.tmu.Unlock()
		if closed {
			break
		}
		if i > 5000 {
			cs.mu.Unlock()
			t.Fatal("the Device did not start closing")
		}
		time.Sleep(time.Millisecond)
	}
	// 相手の FIN の確認で FIN_WAIT_2 になり、受信のバッファは空なので行に移る条件を満たす
	var reuse reuseISS
	cs.input(&seg, int64(n.clk.Now()), &reuse)
	state := cs.state
	cs.mu.Unlock()
	<-done
	if state != stFree {
		t.Fatalf("state %v after the FIN's ACK, want the slot returned", state)
	}
	if st := n.d.Stats(); st.TWRows != 0 || st.Conns != 0 {
		t.Fatalf("after the Device closed: %d TIME_WAIT rows, %d connections", st.TWRows, st.Conns)
	}
}
