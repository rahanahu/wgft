package nettun

// TUN の入口(wireguard-go から netstack への向き)。IPv4 の断片はすべて有限な再組み立て
// (reassembly.go)に渡し、完成した datagram だけを gVisor に渡す。gVisor の再組み立ては、
// 断片化された datagram ごとに取り消されない 30 秒のタイマーを残し、保持する量が到着の速さで
// 決まるので、断片を gVisor に一度も渡さない(設計文書 7 節)。

import (
	"bytes"
	"encoding/binary"
	"os"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// 再組み立ての表の上限。値は設計文書 7 節に書く。
const (
	reassemblyEntries   = 128
	reassemblyFragments = 512
	reassemblyBytes     = 4 << 20
	reassemblyLifetime  = 30 * time.Second
	reassemblySweep     = time.Second
)

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
	injectInbound(t.ep, packet)
	return nil
}

func injectInbound(ep *channel.Endpoint, packet []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	ep.InjectInbound(header.IPv4ProtocolNumber, pkt)
	pkt.DecRef()
}

func (t *Device) closeReassembly() {
	if t.sweepStop != nil {
		close(t.sweepStop)
		<-t.sweepDone // join before the stack closes; see sweepReassembly
	}
	t.closed.Store(true)
	if t.reassembly != nil {
		t.reassembly.Close()
	}
}
