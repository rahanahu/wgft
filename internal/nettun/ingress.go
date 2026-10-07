package nettun

// TUN の入口(wireguard-go から netstack への向き)。IPv4 の断片はすべて有限な再組み立て
// (reassembly.go)に渡し、完成した datagram だけを gVisor に渡す。gVisor の再組み立ては、
// 断片化された datagram ごとに取り消されない 30 秒のタイマーを残し、保持する量が到着の速さで
// 決まるので、断片を gVisor に一度も渡さない(設計文書 7 節)。この Device 宛ての完成した UDP は
// 登録表(udp_registry.go)を通し、受信の会計の予約を持って endpoint に届ける。ICMP の誤りは、
// 外側の送信元が引用の宛先と一致するものだけを gVisor に渡す(admitICMPv4Error)。TCP の SYN と
// SYN-ACK は、MSS の option が下限より小さいものを捨てる(tcpSynMSSBelowFloor)。

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"

	"github.com/rahanahu/wgft/internal/lograte"
)

// 再組み立ての表の上限。値は設計文書 7 節に書く。
const (
	reassemblyEntries   = 128
	reassemblyFragments = 512
	reassemblyBytes     = 4 << 20
	reassemblyLifetime  = 30 * time.Second
	reassemblySweep     = time.Second
)

// UDP の受信の予算。値は設計文書 7 節に書く。byte は UDP header 後の全 byte に 1 件あたり udpDatagramCharge を
// 足して数える。endpoint 1 つは、どちらの単位でも Device の予算の 1/udpEndpointShare までしか
// 持てない。gVisor の endpoint の受信のキューの上限は、会計の byte と件数の上限が先に効く値に
// 設定する(udp_registry.go の open)。
const (
	udpReceiveBytes     = 4 << 20
	udpReceiveDatagrams = 4096
	udpDatagramCharge   = 64
	udpEndpointShare    = 4
)

func (t *Device) initUDP() error {
	r, err := newUDPRegistry(t, t.local, udpReceiveBytes, udpReceiveDatagrams, udpDatagramCharge)
	if err != nil {
		return err
	}
	r.accounting.setEndpointLimits(udpReceiveBytes/udpEndpointShare, udpReceiveDatagrams/udpEndpointShare)
	if err := r.accounting.faultErr(); err != nil {
		return err
	}
	t.registry = r
	return nil
}

func (t *Device) initReassembly() error {
	fragments, err := newIPv4Reassembly(ipv4ReassemblyLimits{
		Entries: reassemblyEntries, Fragments: reassemblyFragments, Bytes: reassemblyBytes, Lifetime: reassemblyLifetime,
	})
	if err != nil {
		return err
	}
	t.reassembly = fragments
	t.sweepStop = make(chan struct{})
	t.sweepDone = make(chan struct{})
	go t.sweepReassembly()
	return nil
}

func (t *Device) sweepReassembly() {
	defer close(t.sweepDone)
	ticker := time.NewTicker(reassemblySweep)
	defer ticker.Stop()
	for {
		select {
		case <-t.sweepStop:
			return
		case now := <-ticker.C:
			// Sweep takes only the reassembly mutex; the timeout ICMP handoff
			// takes no lock. Close joins this goroutine before it closes the
			// stack, so no notice reaches a closing stack.
			for _, n := range t.reassembly.Sweep(now) {
				t.fragmentNotice(n, nil)
			}
			// 閉じた後の TCP の接続の表から、CLOSED か ERROR になった行を外す(postclose.go)
			t.postClose.sweep()
		}
	}
}

// fragmentNotice is the bounded handoff for timeout / option ICMP. Timeout
// delegates to pinned gVisor's callback; Parameter Problem is built here. No
// notice is re-injected as a fragment. A notice that yields no ICMP is dropped
// without a TUN error. It takes no lock: it reads only the immutable local
// address and the stack.
func (t *Device) fragmentNotice(n ipv4FragmentNotice, offending []byte) {
	if (n.Reason != ipv4ReasonExpired && n.Reason != ipv4ReasonOptions) ||
		(!n.HasFirst && n.Reason != ipv4ReasonOptions) {
		return
	}
	// A saved first quote does not make a later offending fragment eligible.
	if n.Reason == ipv4ReasonOptions && n.HasFirst && len(offending) >= 8 &&
		binary.BigEndian.Uint16(offending[6:8])&0x1fff != 0 {
		return
	}
	if n.Reason == ipv4ReasonExpired {
		if n.QuoteLen >= 20 && !bytes.Equal(n.Quote[16:20], t.local.AsSlice()) {
			return
		}
		t.emitReassemblyTimeout(n)
		return
	}
	t.emitOptionParameterProblem(n, offending)
}

func isIPv4Fragment(packet []byte) bool {
	if len(packet) < 8 {
		return false
	}
	flags := binary.BigEndian.Uint16(packet[6:8])
	return flags&0x3fff != 0 // MF or nonzero offset; DF alone is not a fragment.
}

// writeIPv4 hands one IPv4 packet to the netstack. A fragment goes to the
// reassembly table and never to gVisor; only a completed datagram does. It
// returns an error only when the Device is closed: a refused fragment is a
// network-layer drop, like gVisor's own, and wireguard-go logs every Write
// error once per batch without rate limiting.
func (t *Device) writeIPv4(packet []byte) error {
	if t.closed.Load() {
		return os.ErrClosed
	}
	// Bytes after the IPv4 Total Length are not part of the packet. wireguard-go
	// already cuts them off; the Device does it itself rather than rely on
	// that, because gVisor ignores them too and the UDP accounting reserves by
	// the length it hands to gVisor.
	if len(packet) >= header.IPv4MinimumSize {
		if n := int(binary.BigEndian.Uint16(packet[2:4])); n >= header.IPv4MinimumSize && n < len(packet) {
			packet = packet[:n]
		}
	}
	if isIPv4Fragment(packet) {
		result := t.reassembly.Process(packet, time.Now())
		if result.Status == ipv4FragmentRejected && result.Notice.Reason == ipv4ReasonExpired {
			t.fragmentNotice(result.Notice, nil)
			// Process rejects the new fragment after reporting a prior key's
			// expiration. Retry that one fragment against the cleared entry.
			result = t.reassembly.Process(packet, time.Now())
		}
		switch result.Status {
		case ipv4FragmentHeld, ipv4FragmentDuplicate:
			return nil
		case ipv4FragmentComplete:
			packet = result.Packet // sole completion copy until synchronous handoff
		case ipv4FragmentCapacity:
			// Only a datagram that alone fills the table reaches this; the
			// fragment is dropped without ICMP.
			return nil
		case ipv4FragmentClosed:
			return os.ErrClosed
		default:
			t.fragmentNotice(result.Notice, packet)
			return nil
		}
	}
	if !admitICMPv4Error(packet) {
		return nil
	}
	if tcpSynMSSBelowFloor(packet) {
		t.synMSS.drop(packet)
		return nil
	}
	if ipHeaderLen, err := parseLocalUDP(packet, t.local); err == nil {
		// A refusal by the receive budget and a stopped accounting are drops,
		// not Write errors, for the same reason as a refused fragment.
		if _, err := t.registry.injectLocal(packet, ipHeaderLen); errors.Is(err, os.ErrClosed) {
			return os.ErrClosed
		}
		return nil
	}
	injectInbound(t.ep, packet)
	return nil
}

// icmpv4FragNeededMinMTU は、Fragmentation Needed が示す next-hop MTU の下限。Linux の既定の
// min_pmtu (net.ipv4.route.min_pmtu) と同じ値で、カーネルモードの server のホストが受け入れる
// 範囲にそろえる(設計文書 7 節)。
const icmpv4FragNeededMinMTU = 552

// admitICMPv4Error reports whether packet may go on to gVisor as far as ICMP
// errors are concerned. An ICMP error (Destination Unreachable, Source Quench,
// Redirect, Time Exceeded, Parameter Problem) passes only when its outer
// source equals the destination of the datagram it quotes. Every peer shares
// one Device in vpsd's userspace mode and wireguard-go checks only that the
// outer source is in the sending peer's AllowedIPs, so without this check a
// peer could quote a flow between this Device and another peer; the pinned
// gVisor compares neither the outer source nor a TCP sequence number. A
// Fragmentation Needed also needs a next-hop MTU of at least
// icmpv4FragNeededMinMTU, since gVisor has no floor of its own. packet is a
// complete datagram: fragments are checked after reassembly. Anything that
// is not an ICMP error passes, and so does a packet too short to carry an
// ICMP header, which gVisor drops. An ICMP error too short to quote the
// destination is dropped. No ICMP is sent and nothing is logged for a drop.
func admitICMPv4Error(packet []byte) bool {
	if len(packet) < header.IPv4MinimumSize || packet[9] != uint8(header.ICMPv4ProtocolNumber) {
		return true
	}
	hlen := int(packet[0]&0x0f) * 4
	if hlen < header.IPv4MinimumSize || len(packet) < hlen+header.ICMPv4MinimumSize {
		return true
	}
	icmp := packet[hlen:]
	switch header.ICMPv4Type(icmp[0]) {
	case header.ICMPv4DstUnreachable, header.ICMPv4SrcQuench, header.ICMPv4Redirect,
		header.ICMPv4TimeExceeded, header.ICMPv4ParamProblem:
	default:
		return true
	}
	quote := icmp[header.ICMPv4MinimumSize:]
	if len(quote) < header.IPv4MinimumSize || !bytes.Equal(quote[16:20], packet[12:16]) {
		return false
	}
	if header.ICMPv4Type(icmp[0]) == header.ICMPv4DstUnreachable &&
		header.ICMPv4Code(icmp[1]) == header.ICMPv4FragmentationNeeded &&
		binary.BigEndian.Uint16(icmp[6:8]) < icmpv4FragNeededMinMTU {
		return false
	}
	return true
}

// tcpSynMinMSS は、TUN の入口が受け入れる SYN と SYN-ACK の MSS の下限。gVisor は送った segment を
// 確認されるまで 1 つずつ管理の構造ごと持ち、相手の MSS を 48 まで受け入れるので、小さい MSS の相手は
// 同じ送り残しの byte で保持を数十倍に増やせる。536 は MSS の option が無いときの既定値
// (RFC 1122、gVisor の header.TCPDefaultMSS)で、wgft の MTU の下限 576 の netstack が示す値でもある。
// 値は設定項目にしない(設計文書 7 節)。
const tcpSynMinMSS = 536

// tcpSynMSSBelowFloor reports whether packet is a TCP segment with SYN set,
// a SYN or a SYN-ACK, whose MSS is below tcpSynMinMSS as gVisor reads it.
// It parses the options with gVisor's own header.ParseSynOptions, which the
// pinned gVisor uses for every SYN it acts on, so the value checked is the
// value the endpoint would use: an absent, zero or malformed MSS option
// leaves gVisor's default of 536, and a value below 48 counts as 48. packet
// is a complete datagram, so a fragmented SYN is checked after reassembly.
// A packet whose IPv4 or TCP header is malformed passes, as gVisor drops it;
// the TCP checksum is not checked, since gVisor drops a bad one either way.
func tcpSynMSSBelowFloor(packet []byte) bool {
	ip := header.IPv4(packet)
	if !ip.IsValid(len(packet)) || ip.Protocol() != uint8(header.TCPProtocolNumber) {
		return false
	}
	hlen, tlen := int(ip.HeaderLength()), int(ip.TotalLength())
	if tlen-hlen < header.TCPMinimumSize {
		return false
	}
	tcp := header.TCP(packet[hlen:tlen])
	flags := tcp.Flags()
	if !flags.Contains(header.TCPFlagSyn) {
		return false
	}
	off := int(tcp.DataOffset())
	if off < header.TCPMinimumSize || off > len(tcp) {
		return false
	}
	return header.ParseSynOptions(tcp[header.TCPMinimumSize:off], flags.Contains(header.TCPFlagAck)).MSS < tcpSynMinMSS
}

// synMSSFloor counts the SYN and SYN-ACK segments the MSS floor drops and
// logs them at most once a minute. The zero value is ready to use.
type synMSSFloor struct {
	dropped atomic.Uint64
	log     lograte.Gate
}

// drop counts one dropped segment and may log it. packet has passed
// tcpSynMSSBelowFloor, so its IPv4 and TCP headers are whole.
func (f *synMSSFloor) drop(packet []byte) {
	n := f.dropped.Add(1)
	if !f.log.Allow() {
		return
	}
	ip := header.IPv4(packet)
	tcp := header.TCP(packet[ip.HeaderLength():])
	src := netip.AddrPortFrom(netip.AddrFrom4(ip.SourceAddress().As4()), tcp.SourcePort())
	logf("userspace tunnel: dropped TCP handshakes that advertise an MSS below %d; "+
		"%d dropped since the tunnel was built, the latest from %s; peers that advertise a smaller MSS cannot connect through this tunnel",
		tcpSynMinMSS, n, src)
}

// The reasons parseLocalUDP refuses a packet, in the order it checks them.
var (
	errIncompleteIPv4 = errors.New("incomplete IPv4 datagram")
	errNotWholeUDP    = errors.New("registry accepts only complete IPv4 UDP datagrams")
	errNotLocalUDP    = errors.New("registry accepts only local IPv4 unicast")
)

// parseLocalUDP decides whether packet is a complete IPv4 UDP datagram for
// local, the Device's own address: the only kind gVisor can deliver to a UDP
// endpoint, since every endpoint is bound to that address. It returns the IPv4
// header length of such a packet. Anything else goes to gVisor with no lock,
// and gVisor drops what it cannot parse. The UDP header itself is checked by
// the registry (localUDPPayload), which drops a datagram whose UDP length does
// not fit.
func parseLocalUDP(packet []byte, local netip.Addr) (ipHeaderLen int, err error) {
	if len(packet) < header.IPv4MinimumSize {
		return 0, errIncompleteIPv4
	}
	ip := header.IPv4(packet)
	if !ip.IsValid(len(packet)) || int(ip.TotalLength()) != len(packet) ||
		ip.More() || ip.FragmentOffset() != 0 || ip.Protocol() != uint8(udp.ProtocolNumber) ||
		int(ip.TotalLength()) < int(ip.HeaderLength())+header.UDPMinimumSize {
		return 0, errNotWholeUDP
	}
	dst := ip.DestinationAddress()
	if !bytes.Equal(dst.AsSlice(), local.AsSlice()) {
		return 0, errNotLocalUDP
	}
	return int(ip.HeaderLength()), nil
}

func injectInbound(ep *channel.Endpoint, packet []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
}

func (t *Device) closeIngress() {
	if t.sweepStop != nil {
		close(t.sweepStop)
		<-t.sweepDone // join before the stack closes; see sweepReassembly
	}
	if t.registry != nil {
		t.registry.closeAll() // marks the Device closed, then closes every UDP endpoint
	} else {
		t.closed.Store(true)
	}
	if t.reassembly != nil {
		t.reassembly.Close()
	}
}
