package wgipc

import (
	"encoding/hex"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestListenPort(t *testing.T) {
	p, err := ListenPort("private_key=00\nlisten_port=35454\npublic_key=11\n")
	if err != nil || p != 35454 {
		t.Errorf("ListenPort = %d, %v; want 35454", p, err)
	}
	if _, err := ListenPort("private_key=00\n"); err == nil {
		t.Error("an IpcGet output without listen_port must be an error")
	}
	if _, err := ListenPort("listen_port=70000\n"); err == nil {
		t.Error("a listen_port past 65535 must be an error")
	}
}

func key(b byte) wgtypes.Key {
	var k wgtypes.Key
	for i := range k {
		k[i] = b
	}
	return k
}

// peerLines は wireguard-go の IpcGetOperation と同じ順で 1 つのピアの節を書く。
func peerLines(k wgtypes.Key, endpoint string, sec, tx, rx int64) string {
	var b strings.Builder
	b.WriteString("public_key=" + hex.EncodeToString(k[:]) + "\n")
	b.WriteString("preshared_key=" + strings.Repeat("0", 64) + "\n")
	b.WriteString("protocol_version=1\n")
	if endpoint != "" {
		b.WriteString("endpoint=" + endpoint + "\n")
	}
	b.WriteString("last_handshake_time_sec=" + itoa(sec) + "\n")
	b.WriteString("last_handshake_time_nsec=5\n")
	b.WriteString("tx_bytes=" + itoa(tx) + "\n")
	b.WriteString("rx_bytes=" + itoa(rx) + "\n")
	b.WriteString("persistent_keepalive_interval=25\n")
	b.WriteString("allowed_ip=10.200.0.2/32\n")
	return b.String()
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func TestPeersReadsEachPeerSection(t *testing.T) {
	a, b := key(1), key(2)
	out := "private_key=" + strings.Repeat("ab", 32) + "\nlisten_port=51820\n" +
		peerLines(a, "192.0.2.10:40000", 1700000000, 300, 400) +
		peerLines(b, "", 0, 0, 0)
	got := Peers(out)
	if len(got) != 2 {
		t.Fatalf("Peers returned %d peers, want 2: %+v", len(got), got)
	}
	want := Peer{PublicKey: a, Endpoint: netip.MustParseAddrPort("192.0.2.10:40000"),
		LastHandshake: time.Unix(1700000000, 0), TxBytes: 300, RxBytes: 400}
	if got[a] != want {
		t.Errorf("peer a = %+v, want %+v", got[a], want)
	}
	if got[b] != (Peer{PublicKey: b}) {
		t.Errorf("peer b without a handshake = %+v, want only its key", got[b])
	}
}

// 値として読めない行は、その項目をゼロ値のまま残す。読めない公開鍵の節と、最初の public_key の
// 行より前の値は、どのピアにも入れない。
func TestPeersSkipsWhatItCannotRead(t *testing.T) {
	a := key(3)
	out := "rx_bytes=9\nlast_handshake_time_sec=9\n" +
		"public_key=zz\nrx_bytes=7\n" +
		"public_key=" + hex.EncodeToString(a[:]) + "\nendpoint=not-an-endpoint\n" +
		"last_handshake_time_sec=-1\nrx_bytes=x\ntx_bytes=12\nno-equals-sign\n"
	got := Peers(out)
	if len(got) != 1 {
		t.Fatalf("Peers returned %d peers, want 1: %+v", len(got), got)
	}
	if want := (Peer{PublicKey: a, TxBytes: 12}); got[a] != want {
		t.Errorf("peer = %+v, want %+v", got[a], want)
	}
	if len(Peers("")) != 0 {
		t.Error("an empty output must have no peers")
	}
}
