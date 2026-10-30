package wgstack

import (
	"encoding/binary"
	"testing"
	"time"
)

// splitIPv4 は option の無い IPv4 の packet を、中身 size byte ごとの断片に分ける。
func splitIPv4(pkt []byte, size int, id uint16) [][]byte {
	payload := pkt[ipHeaderLen:]
	var out [][]byte
	for off := 0; off < len(payload); off += size {
		end := min(off+size, len(payload))
		f := make([]byte, ipHeaderLen+end-off)
		copy(f, pkt[:ipHeaderLen])
		copy(f[ipHeaderLen:], payload[off:end])
		binary.BigEndian.PutUint16(f[2:4], uint16(len(f)))
		binary.BigEndian.PutUint16(f[4:6], id)
		fl := uint16(off / 8)
		if end < len(payload) {
			fl |= 0x2000
		}
		binary.BigEndian.PutUint16(f[6:8], fl)
		f[10], f[11] = 0, 0
		binary.BigEndian.PutUint16(f[10:12], ^checksum(0, f[:ipHeaderLen]))
		out = append(out, f)
	}
	return out
}

func TestFragmentedUDPIsReassembled(t *testing.T) {
	n := newTestNet(t, smallLimits())
	pc := listenUDP(t, n, 53)
	msg := make([]byte, 3000)
	for i := range msg {
		msg[i] = byte(i)
	}
	frags := splitIPv4(buildUDP(peerUDP, 53, msg), 1000, 77)
	for i := len(frags) - 1; i >= 0; i-- { // 逆の順で届く
		n.write(frags[i])
	}
	got, _ := readUDP(t, pc, 4000)
	if string(got) != string(msg) {
		t.Fatalf("reassembled %d bytes", len(got))
	}
}

func TestFragmentTimeoutSendsTimeExceeded(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listenUDP(t, n, 53)
	frags := splitIPv4(buildUDP(peerUDP, 53, make([]byte, 3000)), 1000, 78)
	n.write(frags[0])
	n.advance(31 * time.Second)
	pkts := n.drainRaw()
	if len(pkts) != 1 {
		t.Fatalf("%d packets after the reassembly timeout", len(pkts))
	}
	ip, _ := parseIPv4(pkts[0])
	if ip.proto != protoICMP || ip.payload[0] != icmpTimeExceeded || ip.payload[1] != 1 || string(ip.payload[8:8+28]) != string(frags[0][:28]) {
		t.Fatalf("Time Exceeded %x", pkts[0])
	}
	if _, entries, _ := n.d.s.frag.Usage(); entries != 0 {
		t.Fatalf("%d entries after the sweep", entries)
	}
}

func TestBoundFragmentFlood(t *testing.T) {
	n := newTestNet(t, smallLimits())
	listenUDP(t, n, 53)
	for i := 0; i < 2000; i++ {
		frags := splitIPv4(buildUDP(peerUDP, 53, make([]byte, 8000)), 1400, uint16(i))
		n.write(frags[0]) // 最初の断片だけを送り、datagram を完成させない
		n.write(frags[2])
	}
	snap := n.d.s.frag.Snapshot()
	if snap.Used > fragLimits.Bytes || snap.Entries > fragLimits.Entries || snap.Fragments > fragLimits.Fragments || snap.Evicted == 0 {
		t.Fatalf("reassembly table %+v", snap)
	}
	t.Logf("held %d bytes in %d entries and %d fragments, evicted %d", snap.Used, snap.Entries, snap.Fragments, snap.Evicted)
	for range 40 {
		n.advance(time.Second)
	}
	if snap := n.d.s.frag.Snapshot(); snap.Entries != 0 || snap.Fragments != 0 {
		t.Fatalf("after the lifetime %+v", snap)
	}
}
