package wgbind

import (
	"encoding/binary"
	"errors"
	"hash/maphash"
	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// sourceBuckets は handshake の limiter が持てるキーの数 K。設計は
// docs/design/userspace/wireguard-sources.md。2 の冪にして、ハッシュの下位のビットで選ぶ。
const sourceBuckets = 1024

var errReceiveLayout = errors.New("unsupported WireGuard receive layout")

// bucketAddrs は K 個の合成のアドレスで、limiter のキーにだけ使う。送信の前には包みを外すので、
// 送信先にはならない。240.0.0.0/4 は予約済みで、誤って使われても実在の宛先に届かない。
var bucketAddrs = func() (a [sourceBuckets]netip.Addr) {
	for i := range a {
		a[i] = netip.AddrFrom4([4]byte{240, 0, byte(i >> 8), byte(i)})
	}
	return a
}()

// NewDevice は、handshake の packet の endpoint を包むバインドで wireguard-go の Device を作る。
// 固定した版の wireguard-go は、受信した endpoint の DstIP を handshake の limiter のキーにだけ
// 使う。包みの DstIP は K 個の合成のアドレスのどれかを返すので、limiter の表は K 件を超えない。
func NewDevice(tunDevice tun.Device, bind conn.Bind, logger *device.Logger) *device.Device {
	return device.NewDevice(tunDevice, newSourceGate(bind), logger)
}

// sourceGate は、受信した initiation と response の endpoint を bucketEndpoint に包み、送信の前に
// 包みを外す。packet は捨てず、送信元ごとの状態も持たない。
type sourceGate struct {
	conn.Bind
	seed maphash.Seed // Device ごとの鍵。どの送信元がどの bucket に入るかを外から予測させない
}

func newSourceGate(inner conn.Bind) *sourceGate {
	return &sourceGate{Bind: BatchOne(inner), seed: maphash.MakeSeed()}
}

// bucketEndpoint は DstIP だけを合成のアドレスに置き換える。MAC2 の検査と cookie reply が使う
// DstToBytes、UAPI の DstToString、ClearSrc などは内側の endpoint のものをそのまま使う。
type bucketEndpoint struct {
	conn.Endpoint
	bucket netip.Addr
}

func (e *bucketEndpoint) DstIP() netip.Addr { return e.bucket }

func (g *sourceGate) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := g.Bind.Open(port)
	if err != nil {
		return nil, actualPort, err
	}
	// nil の関数を包むと nil でない関数になり、呼んだときに panic する。
	for _, fn := range fns {
		if fn == nil {
			_ = g.Bind.Close()
			return nil, 0, errReceiveLayout
		}
	}
	for i, inner := range fns {
		fns[i] = func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
			n, err := inner(bufs, sizes, eps)
			if n > len(bufs) || n > len(sizes) || n > len(eps) {
				return 0, errReceiveLayout
			}
			for j := 0; j < n; j++ {
				if eps[j] != nil && candidate(bufs[j], sizes[j]) {
					eps[j] = g.wrap(eps[j])
				}
			}
			return n, err
		}
	}
	return fns, actualPort, nil
}

// Send は包みを外してから内側に渡す。peer は handshake の endpoint を包みのまま保存する。
// 標準のバインドは *conn.StdNetEndpoint を前提にし、DstIP で IPv4 と IPv6 のソケットを選ぶ。
func (g *sourceGate) Send(bufs [][]byte, ep conn.Endpoint) error {
	if b, ok := ep.(*bucketEndpoint); ok {
		ep = b.Endpoint
	}
	return g.Bind.Send(bufs, ep)
}

func (g *sourceGate) wrap(ep conn.Endpoint) conn.Endpoint {
	if b, ok := ep.(*bucketEndpoint); ok {
		ep = b.Endpoint
	}
	return &bucketEndpoint{Endpoint: ep, bucket: bucketAddrs[g.bucketOf(ep.DstIP())]}
}

// bucketOf は送信元の bucket を選ぶ。IPv6 は /64 の prefix を使い、1 台が持つ /64 の中のアドレスを
// 1 つの送信元として扱う (カーネルの WireGuard の limiter と同じ)。IPv4 と IPv4-mapped IPv6 は
// アドレス全体を使い、両者は別の入力になる。zone は使わない。
func (g *sourceGate) bucketOf(ip netip.Addr) int {
	var b [17]byte
	a := ip.As16()
	if ip.Is6() && !ip.Is4In6() {
		clear(a[8:])
	}
	copy(b[:16], a[:])
	b[16] = byte(ip.BitLen() >> 5) // 0: 無効、1: IPv4、4: IPv6
	return int(maphash.Bytes(g.seed, b[:]) & (sourceBuckets - 1))
}

// candidate は、wireguard-go が handshake のキューに入れて limiter に渡しうる packet を選ぶ。
// 受信の経路は、この大きさの initiation と response だけを handshake のキューに入れる。
func candidate(buf []byte, size int) bool {
	if size < 4 || size > len(buf) {
		return false
	}
	typ := binary.LittleEndian.Uint32(buf[:4])
	return typ == device.MessageInitiationType && size == device.MessageInitiationSize ||
		typ == device.MessageResponseType && size == device.MessageResponseSize
}
