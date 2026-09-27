package nettun

import (
	"fmt"
	"net/netip"
	"testing"
	"time"
)

// icmpRegistrations は stack の demuxer に登録された ICMP の endpoint の数を返す。
// 登録が残っている限り、その endpoint と identifier は解放されない。
func icmpRegistrations(d *Device) int {
	n := 0
	for _, ep := range d.stack.RegisteredEndpoints() {
		if fmt.Sprintf("%T", ep) == "*icmp.endpoint" {
			n++
		}
	}
	return n
}

// 固定版の gVisor の ICMP の endpoint は、bind で登録した identifier を接続でも Close でも解放しない
// (仕様 7 節「keepalive の ping の endpoint」)。identifier の範囲を 10 個に絞り、その何倍もの ping を
// 往復させる。ping ごとに 1 つ残る作りなら 11 回目の DialPing が identifier を取れずに失敗する。
func TestDialPingReleasesIdentifier(t *testing.T) {
	p := newSaturationPair(t)
	p.startResponses()
	if terr := p.requester.stack.SetPortRange(16000, 16009); terr != nil {
		t.Fatalf("SetPortRange: %s", terr)
	}
	local := netip.MustParseAddr("10.99.0.1")
	remote := netip.MustParseAddr("10.99.0.2")

	c, err := p.requester.DialPing(local, remote)
	if err != nil {
		t.Fatal(err)
	}
	if n := icmpRegistrations(p.requester); n != 1 {
		t.Fatalf("an open ping holds %d ICMP registrations, want 1", n)
	}
	c.Close()
	if n := icmpRegistrations(p.requester); n != 0 {
		t.Fatalf("a closed ping left %d ICMP registrations", n)
	}

	for i := 0; i < 50; i++ {
		if err := pingOnce(p, 2*time.Second); err != nil {
			t.Fatalf("ping %d: %v", i, err)
		}
		if n := icmpRegistrations(p.requester); n != 0 {
			t.Fatalf("after ping %d the stack holds %d ICMP registrations, want 0", i, n)
		}
		drainEchoRequests(t, p, local)
	}
}

// drainEchoRequests は requester が送った echo request を読み、送信元がトンネルのアドレスであることを確かめる。
func drainEchoRequests(t *testing.T, p *saturationPair, local netip.Addr) {
	t.Helper()
	seen := false
	for {
		select {
		case packet := <-p.requestPackets:
			if !isICMP(packet, 8, 0) {
				continue
			}
			seen = true
			if src := netip.AddrFrom4([4]byte(packet[12:16])); src != local {
				t.Fatalf("echo request left from %v, want %v", src, local)
			}
		default:
			if !seen {
				t.Fatal("no echo request left the requester")
			}
			return
		}
	}
}

// DialPing は送信元を接続の経路に選ばせるので、それが渡されたアドレスと違う場合は endpoint を閉じて誤りを返す。
func TestDialPingRejectsOtherSource(t *testing.T) {
	d := ingressDevice(t)
	if _, err := d.DialPing(netip.MustParseAddr("10.99.0.9"), ingressRemote); err == nil {
		t.Fatal("DialPing accepted a source address the device does not have")
	}
	if n := icmpRegistrations(d); n != 0 {
		t.Fatalf("a rejected ping left %d ICMP registrations", n)
	}
	c, err := d.DialPing(ingressLocal, ingressRemote)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
