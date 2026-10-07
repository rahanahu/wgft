package nettun

// 中身の無い ACK の予算(設計文書の packet-validation.md の「中身の無い ACK の予算」)。固定版の gVisor は、
// 中身の無い segment を受信のメモリの判定の外で endpoint の処理待ちに入れる。SACK を使う接続では
// ACK を持つ segment 1 つの処理が送って確認を待つ segment の数に比例するので、相手が送り残しを
// 確認せずに中身の無い ACK を送り続けると、処理待ちが処理より速く増える。TUN の入口は、netstack の
// TCP の接続ごとに、中身の無い ACK を、その接続が TUN へ出した segment の数と固定の余裕までしか
// 渡さない。予算の上限は、送信のバッファの上限(boost の枠を持つ間は boost、ほかは floor)を segment の
// 中身の下限で割った数に余裕を足した値である。超えた分は捨てて数える。表の行は、DialTCP と Accept が返す接続だけで、Device の 1 秒の sweeper
// (ingress.go)が、公開の State() が CLOSED か ERROR になった行を外す。

import (
	"net/netip"
	"sync"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/rahanahu/wgft/internal/lograte"
)

// 値は設定項目にしない(設計文書)。
const (
	// ackSegmentFloor は、送り残しを分けた segment の中身の下限(packet-validation.md)。
	ackSegmentFloor = 472
	// ackBurst は、窓の更新のように送った segment に対応しない中身の無い ACK のための余裕。相手の
	// keepalive と窓の probe への応答は TUN へ出る segment なので、その分は予算に戻る。
	ackBurst = 64
)

type ackFlowKey struct {
	remote     [4]byte
	remotePort uint16
	localPort  uint16
}

// ackFlow は表の行。接続の endpoint と boost の印だけを持ち、接続(tcpConn)そのものは持たない。
// 行は endpoint が CLOSED になるまで残るので、閉じた後の接続の書き込みの記録などを持ち続けないためである。
type ackFlow struct {
	ep      tcpip.Endpoint
	boosted *atomic.Bool
	tokens  int
}

// ackBudgets は Device ごとの表。mu は末端の錠で、持ったまま endpoint の錠を取る操作をしない。
// ackLimit が読む boost の印と State() は原子的な読み取りで、錠を取らない。
type ackBudgets struct {
	local [4]byte // Device のアドレス
	mu    sync.Mutex
	flows map[ackFlowKey]*ackFlow

	dropped atomic.Uint64 // 捨てた数。Device を作ってからの累計
	log     lograte.Gate
}

func newAckBudgets(local netip.Addr) *ackBudgets {
	return &ackBudgets{local: local.As4(), flows: make(map[ackFlowKey]*ackFlow)}
}

// ackLimit は行の予算の上限。送信のバッファの上限が持てる segment の数の最大に余裕を足す。
// 送信のバッファの今の値は使わない。Write は確かめの間に送信のバッファを一時的に小さくするが、
// その間も前に送った segment は確認を待っているためである(tcpbuf.go)。boost の枠を持つ接続は、
// 自分の FIN が確認されるまで boost の上限を使う。FIN が確認された後(FIN_WAIT_2、TIME_WAIT、
// CLOSED、ERROR)は送ったデータがすべて確認済みで、floor に戻った後は送って確認を待つ byte が
// floor 以下なので、floor の上限を使う。
func ackLimit(ep tcpip.Endpoint, boosted *atomic.Bool) int {
	size := tcpSendFloor
	if boosted.Load() && !finAcked(ep) {
		size = tcpBoostSize
	}
	return size/ackSegmentFloor + ackBurst
}

// finAcked は ep の FIN が確認済みかを返す。
func finAcked(ep tcpip.Endpoint) bool {
	switch tcp.EndpointState(ep.State()) {
	case tcp.StateFinWait2, tcp.StateTimeWait, tcp.StateClose, tcp.StateError:
		return true
	}
	return false
}

func (f *ackFlow) limit() int { return ackLimit(f.ep, f.boosted) }

// register は握手を終えた c を表に入れる。予算は上限から始める。
func (b *ackBudgets) register(c *tcpConn) {
	ep := c.ep
	local, err := ep.GetLocalAddress()
	if err != nil {
		return
	}
	remote, err := ep.GetRemoteAddress()
	if err != nil || remote.Addr.Len() != 4 {
		return
	}
	k := ackFlowKey{remote: remote.Addr.As4(), remotePort: remote.Port, localPort: local.Port}
	f := &ackFlow{ep: ep, boosted: c.boosted, tokens: ackLimit(ep, c.boosted)}
	b.mu.Lock()
	b.flows[k] = f
	b.mu.Unlock()
}

// sweep は endpoint が CLOSED か ERROR になった行を外す。
func (b *ackBudgets) sweep() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, f := range b.flows {
		if finished(f.ep) {
			delete(b.flows, k)
		}
	}
}

// tcpHeader は packet が IPv4 の TCP の segment ならその TCP のヘッダーと中身の長さを返す。
func tcpHeader(packet []byte) (ip header.IPv4, tcp header.TCP, payload int, ok bool) {
	ip = header.IPv4(packet)
	if !ip.IsValid(len(packet)) || ip.Protocol() != uint8(header.TCPProtocolNumber) || ip.More() || ip.FragmentOffset() != 0 {
		return nil, nil, 0, false
	}
	hlen, tlen := int(ip.HeaderLength()), int(ip.TotalLength())
	if tlen > len(packet) || tlen-hlen < header.TCPMinimumSize {
		return nil, nil, 0, false
	}
	tcp = header.TCP(packet[hlen:tlen])
	off := int(tcp.DataOffset())
	if off < header.TCPMinimumSize || off > len(tcp) {
		return nil, nil, 0, false
	}
	return ip, tcp, len(tcp) - off, true
}

// outbound は netstack が TUN へ出した packet を見て、その接続の予算を上限まで 1 つ足す。
func (b *ackBudgets) outbound(packet []byte) {
	ip, tcp, _, ok := tcpHeader(packet)
	if !ok {
		return
	}
	k := ackFlowKey{remote: ip.DestinationAddress().As4(), remotePort: tcp.DestinationPort(), localPort: tcp.SourcePort()}
	b.mu.Lock()
	if f := b.flows[k]; f != nil {
		f.tokens = min(f.tokens+1, f.limit())
	}
	b.mu.Unlock()
}

// admit は TUN の入口の packet を netstack に渡してよいかを返す。予算を使うのは、表にある接続宛ての、
// ACK を持ち SYN と RST を持たない中身の無い segment だけで、ほかは常に渡す。packet は完成した
// datagram である。上限が下がった接続(floor に戻った接続、届け終えた接続)の予算は、ここで今の
// 上限まで減らす。
func (b *ackBudgets) admit(packet []byte) bool {
	ip, tcp, payload, ok := tcpHeader(packet)
	if !ok || payload != 0 || ip.DestinationAddress().As4() != b.local {
		return true
	}
	flags := tcp.Flags()
	if !flags.Contains(header.TCPFlagAck) || flags.Intersects(header.TCPFlagSyn|header.TCPFlagRst) {
		return true
	}
	k := ackFlowKey{remote: ip.SourceAddress().As4(), remotePort: tcp.SourcePort(), localPort: tcp.DestinationPort()}
	b.mu.Lock()
	f := b.flows[k]
	if f != nil {
		f.tokens = min(f.tokens, f.limit())
	}
	if f == nil || f.tokens > 0 {
		if f != nil {
			f.tokens--
		}
		b.mu.Unlock()
		return true
	}
	b.mu.Unlock()
	n := b.dropped.Add(1)
	if b.log.Allow() {
		logf("userspace tunnel: dropped TCP acknowledgments without data beyond the segments the connection sent; "+
			"%d dropped since the tunnel was built, the latest from %s", n, netip.AddrPortFrom(netip.AddrFrom4(k.remote), k.remotePort))
	}
	return false
}
