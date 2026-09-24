package nettun

import (
	"net/netip"
	"strings"
	"testing"
)

// TestListenTCPTwiceReportsBindTCP と TestListenUDPTwiceReportsBindUDP は、gVisor の netstack の
// bind の失敗が、internal/vpsd/doctor の looksLikeBindFailure(checks.go)が当てにする
// "bind tcp <addr>: <err>" / "bind udp <addr>: <err>" の形になることを、実際に nettun.Device を
// 2 回同じアドレスへ bind させて固定する。ソースコードを読んだ判定(ListenTCP の net.OpError の
// 組み立て、gonet.DialUDP の同じ組み立て)を、実際の gVisor の挙動と付き合わせるための試験であり、
// nettun か gVisor の文言が変わればここが落ちる。
func TestListenTCPTwiceReportsBindTCP(t *testing.T) {
	dev, err := Create(netip.MustParseAddr("10.200.0.9"), 1420)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer dev.Close()

	ap := netip.MustParseAddrPort("10.200.0.9:8461")
	ln, err := dev.ListenTCP(ap)
	if err != nil {
		t.Fatalf("first ListenTCP(%s): %v", ap, err)
	}
	defer ln.Close()

	_, err = dev.ListenTCP(ap)
	if err == nil {
		t.Fatalf("second ListenTCP(%s) on the same address: want an error, got none", ap)
	}
	got := err.Error()
	if !strings.Contains(got, "bind tcp ") {
		t.Errorf("error = %q, want it to contain %q", got, "bind tcp ")
	}
	if !strings.Contains(got, "port is in use") {
		t.Errorf("error = %q, want it to contain %q", got, "port is in use")
	}
}

func TestListenUDPTwiceReportsBindUDP(t *testing.T) {
	dev, err := Create(netip.MustParseAddr("10.200.0.9"), 1420)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defer dev.Close()

	ap := netip.MustParseAddrPort("10.200.0.9:8462")
	pc, err := dev.ListenUDP(ap)
	if err != nil {
		t.Fatalf("first ListenUDP(%s): %v", ap, err)
	}
	defer pc.Close()

	_, err = dev.ListenUDP(ap)
	if err == nil {
		t.Fatalf("second ListenUDP(%s) on the same address: want an error, got none", ap)
	}
	got := err.Error()
	if !strings.Contains(got, "bind udp ") {
		t.Errorf("error = %q, want it to contain %q", got, "bind udp ")
	}
	if !strings.Contains(got, "port is in use") {
		t.Errorf("error = %q, want it to contain %q", got, "port is in use")
	}
}
