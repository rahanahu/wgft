package wgstack

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"time"
)

// UDP(設計文書の「UDP、ICMP、再組み立て」)。受信と送信はそれぞれ Device の予算と endpoint 1 つの上限
// (予算の 1/4)を持つ。datagram の中身は、大きさの区分ごとの枠に分けた 16 KiB の chunk に置き、16 KiB を
// 超える datagram は chunk の列に置く。chunk は 1 つの endpoint だけが持ち、chunk の中に生きている枠が 1 つ
// でもある間は、その chunk 全体を endpoint と Device の予算に数える。会計は保持そのものなので、受け入れの
// 判定に別の帳簿は要らない。管理の情報は固定の数の配列に置く。錠は Device の UDP の錠 udp.mu で、出力の
// 錠と chunk の置き場の錠だけを中で取る。

// 値はどれも設定項目にしない(udp-accounting.md の UDP の受信の予算)。
const (
	udpRxBytes       = 4 << 20
	udpRxDatagrams   = 4096
	udpTxBytes       = 4 << 20
	udpTxDatagrams   = 1024
	udpEndpointShare = 4
	udpHeaderLen     = 8
	udpMaxPayload    = 65535 - ipHeaderLen - udpHeaderLen
)

// udpClasses は枠の大きさの区分。最後の区分を超える datagram は chunk の列に置く。
var udpClasses = [...]int{256, 2048, chunkSize}

const udpLarge = len(udpClasses) // 区分の番号のうち chunk の列を表す値

func udpClassOf(n int) int {
	for c, size := range udpClasses {
		if n <= size {
			return c
		}
	}
	return udpLarge
}

// udpBudget は 1 つの向きの byte と件数の予算。
type udpBudget struct {
	bytes, count       int64
	maxBytes, maxCount int64
}

func (b *udpBudget) fits(bytes, count int64) bool {
	return b.bytes+bytes <= b.maxBytes && b.count+count <= b.maxCount
}

// udpChunkRec は endpoint が持つ 1 つの chunk。live は使っている枠の数、next は次に使う枠の番号である。
type udpChunkRec struct {
	buf  *chunk
	live int
	next int
}

// udpDgram は 1 つの datagram の管理の情報。
type udpDgram struct {
	ep    *udpEndpoint
	peer  netip.AddrPort // 受信では送信元、送信では宛先
	n     int            // 中身の長さ
	class int
	ck    [4]int32 // 区分の枠では ck[0] だけ、chunk の列では使う chunk の数だけ
	off   int      // 区分の枠の chunk の中の位置
	next  int32    // 受信の FIFO か送信の FIFO の次
	sent  int      // 送信:断片に分けて送った UDP の byte(header を含む)
	ipID  uint16
	csum  uint16
}

const (
	dirRx = 0
	dirTx = 1
)

// udpEndpoint は ListenUDP の待ち受け。
type udpEndpoint struct {
	s      *stack
	local  netip.AddrPort
	closed bool
	budget [2]udpBudget
	cur    [2][len(udpClasses)]int32 // 向きと区分ごとの今の chunk。-1 は無し
	rxHead int32
	rxTail int32
	rch    chan struct{}
	rdl    deadline
	wdl    deadline
}

// udpState は Device の UDP の状態。
type udpState struct {
	mu       sync.Mutex
	eps      map[netip.AddrPort]*udpEndpoint
	dg       [2][]udpDgram
	dgFree   [2][]int32
	ck       []udpChunkRec
	ckFree   []int32
	budget   [2]udpBudget
	txHead   int32
	txTail   int32
	txSpace  chan struct{} // 送信の予約が返ったときに閉じて作り直す。待つ書き手がいるときだけ(txWaited)
	txWaited bool          // txSpace を待つ書き手がいる。偽なら閉じずに使い続け、datagram ごとに作り直さない
	fault    error
	closed   bool

	epDrops, devDrops, noPort uint64
	dropGate                  gate
}

// init は datagram の枠の数を決める。0 は本番の値で、小さな値は試験だけが渡す。
func (u *udpState) init(rxDgrams, txDgrams int) {
	if rxDgrams == 0 {
		rxDgrams = udpRxDatagrams
	}
	if txDgrams == 0 {
		txDgrams = udpTxDatagrams
	}
	u.eps = map[netip.AddrPort]*udpEndpoint{}
	u.txHead, u.txTail = -1, -1
	u.txSpace = make(chan struct{})
	sizes := [2]int{rxDgrams, txDgrams}
	for d := range 2 {
		u.dg[d] = make([]udpDgram, sizes[d])
		u.dgFree[d] = make([]int32, sizes[d])
		for i := range sizes[d] {
			u.dgFree[d][i] = int32(sizes[d] - 1 - i)
		}
	}
	u.budget[dirRx] = udpBudget{maxBytes: udpRxBytes, maxCount: int64(rxDgrams)}
	u.budget[dirTx] = udpBudget{maxBytes: udpTxBytes, maxCount: int64(txDgrams)}
	n := (udpRxBytes + udpTxBytes) / chunkSize
	u.ck = make([]udpChunkRec, n)
	u.ckFree = make([]int32, n)
	for i := range n {
		u.ckFree[i] = int32(n - 1 - i)
	}
}

// failLocked は会計の不整合を記録し、この Device の UDP を止める(udp-accounting.md の会計の不整合)。
// 最初の違反を保つ。udp.mu を持って呼ぶ。
func (s *stack) udpFailLocked(err error) {
	u := &s.udp
	if u.fault != nil {
		return
	}
	u.fault = err
	logf("wgstack: UDP accounting found an internal inconsistency and stopped all UDP on this tunnel: %v; restart the agent to recover", err)
}

// UDPReceiveFault は、UDP の会計が不変条件の違反を検出してこの Device の UDP を止めたときの誤りを返す。
// 健全な間は nil である。
func (d *Device) UDPReceiveFault() error {
	d.s.udp.mu.Lock()
	defer d.s.udp.mu.Unlock()
	return d.s.udp.fault
}

// reserve は endpoint ep の向き dir に n byte の datagram の置き場を予約し、datagram の番号を返す。
// 予約できなければ -1 と、Device の予算で拒んだかを返す。udp.mu を持って呼ぶ。
func (s *stack) udpReserve(ep *udpEndpoint, dir, n int) (int32, bool) {
	u := &s.udp
	dev, own := &u.budget[dir], &ep.budget[dir]
	if len(u.dgFree[dir]) == 0 || !dev.fits(0, 1) {
		return -1, true
	}
	if !own.fits(0, 1) {
		return -1, false
	}
	c := udpClassOf(n)
	var need int64
	switch {
	case c == udpLarge:
		need = int64((n + chunkSize - 1) / chunkSize * chunkSize)
	default:
		if cur := ep.cur[dir][c]; cur < 0 || u.ck[cur].next >= chunkSize/udpClasses[c] {
			need = chunkSize
		}
	}
	if need > 0 {
		if !dev.fits(need, 0) {
			return -1, true
		}
		if !own.fits(need, 0) {
			return -1, false
		}
		if int64(len(u.ckFree))*chunkSize < need {
			return -1, true
		}
	}
	id := u.dgFree[dir][len(u.dgFree[dir])-1]
	u.dgFree[dir] = u.dgFree[dir][:len(u.dgFree[dir])-1]
	g := &u.dg[dir][id]
	*g = udpDgram{ep: ep, n: n, class: c, next: -1}
	dev.count++
	own.count++
	dev.bytes += need
	own.bytes += need
	if c == udpLarge {
		for i := 0; i*chunkSize < n; i++ {
			g.ck[i] = s.udpNewChunk()
		}
		return id, false
	}
	if need > 0 {
		ep.cur[dir][c] = s.udpNewChunk()
	}
	cur := ep.cur[dir][c]
	rec := &u.ck[cur]
	g.ck[0] = cur
	g.off = rec.next * udpClasses[c]
	rec.next++
	rec.live++
	return id, false
}

func (s *stack) udpNewChunk() int32 {
	u := &s.udp
	i := u.ckFree[len(u.ckFree)-1]
	u.ckFree = u.ckFree[:len(u.ckFree)-1]
	u.ck[i] = udpChunkRec{buf: s.chunks.get()}
	return i
}

func (s *stack) udpFreeChunk(i int32) {
	u := &s.udp
	s.chunks.put(u.ck[i].buf)
	u.ck[i] = udpChunkRec{}
	u.ckFree = append(u.ckFree, i)
}

// udpRelease は datagram の予約を返す。udp.mu を持って呼ぶ。
func (s *stack) udpRelease(dir int, id int32) {
	u := &s.udp
	g := &u.dg[dir][id]
	ep := g.ep
	dev, own := &u.budget[dir], &ep.budget[dir]
	var freed int64
	if g.class == udpLarge {
		for i := 0; i*chunkSize < g.n; i++ {
			s.udpFreeChunk(g.ck[i])
			freed += chunkSize
		}
	} else {
		rec := &u.ck[g.ck[0]]
		rec.live--
		if rec.live < 0 {
			s.udpFailLocked(errors.New("UDP slot released twice"))
		}
		if rec.live == 0 {
			if ep.cur[dir][g.class] == g.ck[0] {
				ep.cur[dir][g.class] = -1
			}
			s.udpFreeChunk(g.ck[0])
			freed = chunkSize
		}
	}
	dev.count--
	own.count--
	dev.bytes -= freed
	own.bytes -= freed
	if dev.count < 0 || own.count < 0 || dev.bytes < 0 || own.bytes < 0 {
		s.udpFailLocked(fmt.Errorf("UDP budget went negative: %d bytes %d datagrams", dev.bytes, dev.count))
	}
	*g = udpDgram{}
	u.dgFree[dir] = append(u.dgFree[dir], id)
	if dir == dirTx {
		u.wakeTx()
	}
}

// wakeTx は送信の予約の空きを待つ書き手を起こす。待つ書き手がいなければ何もしないので、Read が datagram を
// 送るたびに channel を作らない。u.mu の中で呼ぶ。
func (u *udpState) wakeTx() {
	if !u.txWaited {
		return
	}
	u.txWaited = false
	close(u.txSpace)
	u.txSpace = make(chan struct{})
}

// udpWrite は datagram id の中身を data にする。
func (s *stack) udpPut(dir int, id int32, data []byte) {
	u := &s.udp
	g := &u.dg[dir][id]
	if g.class == udpLarge {
		for i := 0; len(data) > 0; i++ {
			k := copy(u.ck[g.ck[i]].buf[:], data)
			data = data[k:]
		}
		return
	}
	copy(u.ck[g.ck[0]].buf[g.off:], data)
}

// udpGet は datagram id の中身の off から dst に写す。
func (s *stack) udpGet(dir int, id int32, off int, dst []byte) int {
	u := &s.udp
	g := &u.dg[dir][id]
	n := min(len(dst), g.n-off)
	if n <= 0 {
		return 0
	}
	if g.class != udpLarge {
		return copy(dst[:n], u.ck[g.ck[0]].buf[g.off+off:])
	}
	done := 0
	for done < n {
		p := off + done
		k := copy(dst[done:n], u.ck[g.ck[p/chunkSize]].buf[p%chunkSize:])
		done += k
	}
	return done
}

// inputUDP はこの Device の宛先の完成した UDP の datagram を受ける。
func (s *stack) inputUDP(ip *ipv4, now int64) {
	b := ip.payload
	if len(b) < udpHeaderLen {
		s.udpDropped.Add(1)
		return
	}
	ulen := int(binary.BigEndian.Uint16(b[4:6]))
	if ulen < udpHeaderLen || ulen > len(b) {
		s.udpDropped.Add(1)
		return
	}
	b = b[:ulen]
	if cs := binary.BigEndian.Uint16(b[6:8]); cs != 0 && ^checksum(pseudoSum(ip.src, ip.dst, protoUDP, ulen), b) != 0 {
		s.badChecksum.Add(1)
		return
	}
	src := netip.AddrPortFrom(addrFrom(ip.src), binary.BigEndian.Uint16(b[0:2]))
	dst := netip.AddrPortFrom(addrFrom(ip.dst), binary.BigEndian.Uint16(b[2:4]))
	payload := b[udpHeaderLen:]
	u := &s.udp
	u.mu.Lock()
	if u.closed || u.fault != nil {
		u.mu.Unlock()
		s.udpDropped.Add(1)
		return
	}
	ep := u.eps[dst]
	if ep == nil || ep.closed {
		u.noPort++
		u.mu.Unlock()
		s.sendICMPError(ip, 3, 3, 0, now) // Port Unreachable
		return
	}
	id, device := s.udpReserve(ep, dirRx, len(payload))
	if id < 0 {
		if device {
			u.devDrops++
		} else {
			u.epDrops++
		}
		devDrops, epDrops := u.devDrops, u.epDrops
		u.mu.Unlock()
		s.udpDropped.Add(1)
		if u.dropGate.allow(now) {
			logf("wgstack: dropped UDP datagrams because receiving sockets are not read fast enough; %d over the per-socket limit of %d bytes and %d datagrams, %d over the tunnel budget of %d bytes and %d datagrams, since the tunnel was built",
				epDrops, udpRxBytes/udpEndpointShare, udpRxDatagrams/udpEndpointShare, devDrops, udpRxBytes, udpRxDatagrams)
		}
		return
	}
	g := &u.dg[dirRx][id]
	g.peer = src
	s.udpPut(dirRx, id, payload)
	if ep.rxTail >= 0 {
		u.dg[dirRx][ep.rxTail].next = id
	} else {
		ep.rxHead = id
	}
	ep.rxTail = id
	select {
	case ep.rch <- struct{}{}:
	default:
	}
	u.mu.Unlock()
}

// UDPConn は ListenUDP が返す、未接続の UDP の待ち受け。
type UDPConn struct {
	ep *udpEndpoint
}

var errDestinationRequired = errors.New("destination address required")

// ListenUDP は ap で UDP を待ち受ける。ap のアドレスは受け付ける宛先の集合に入ること。
func (d *Device) ListenUDP(ap netip.AddrPort) (net.PacketConn, error) {
	s := d.s
	addr := net.UDPAddrFromAddrPort(ap)
	if !ap.Addr().Is4() || !s.isLocal(addrBits(ap.Addr())) || ap.Port() == 0 {
		return nil, &net.OpError{Op: "listen", Net: "udp", Addr: addr, Err: errors.New("address is not a local address and port of this tunnel")}
	}
	u := &s.udp
	u.mu.Lock()
	defer u.mu.Unlock()
	switch {
	case u.closed:
		return nil, &net.OpError{Op: "listen", Net: "udp", Addr: addr, Err: net.ErrClosed}
	case u.fault != nil:
		return nil, &net.OpError{Op: "listen", Net: "udp", Addr: addr, Err: u.fault}
	case u.eps[ap] != nil:
		return nil, &net.OpError{Op: "listen", Net: "udp", Addr: addr, Err: syscall.EADDRINUSE}
	}
	ep := &udpEndpoint{s: s, local: ap, rxHead: -1, rxTail: -1, rch: make(chan struct{}, 1)}
	for d := range 2 {
		ep.budget[d] = udpBudget{maxBytes: u.budget[d].maxBytes / udpEndpointShare, maxCount: u.budget[d].maxCount / udpEndpointShare}
		for c := range ep.cur[d] {
			ep.cur[d][c] = -1
		}
	}
	u.eps[ap] = ep
	return &UDPConn{ep: ep}, nil
}

func (c *UDPConn) LocalAddr() net.Addr { return net.UDPAddrFromAddrPort(c.ep.local) }

func (c *UDPConn) opErr(op string, addr net.Addr, err error) error {
	if errors.Is(err, net.ErrClosed) {
		return net.ErrClosed
	}
	return &net.OpError{Op: op, Net: "udp", Source: c.LocalAddr(), Addr: addr, Err: err}
}

// ReadFrom は net.PacketConn の実装。届いた順に datagram を 1 つ返す。b より長い datagram は b の長さで
// 切り、残りを捨てる。送信元は *net.UDPAddr である。Close の後と、Close で解かれた待ちは net.ErrClosed を返す。
func (c *UDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	ep := c.ep
	s := ep.s
	u := &s.udp
	for {
		u.mu.Lock()
		if ep.closed || u.closed {
			u.mu.Unlock()
			return 0, nil, net.ErrClosed
		}
		if ep.rdl.expired() {
			u.mu.Unlock()
			return 0, nil, c.opErr("read", nil, os.ErrDeadlineExceeded)
		}
		if id := ep.rxHead; id >= 0 {
			g := &u.dg[dirRx][id]
			n := s.udpGet(dirRx, id, 0, b)
			from := net.UDPAddrFromAddrPort(g.peer)
			ep.rxHead = g.next
			if ep.rxHead < 0 {
				ep.rxTail = -1
			}
			s.udpRelease(dirRx, id)
			u.mu.Unlock()
			return n, from, nil
		}
		ch, dl := ep.rch, ep.rdl.wait()
		u.mu.Unlock()
		select {
		case <-ch:
		case <-dl:
		case <-s.done:
		}
	}
}

func (c *UDPConn) Read(b []byte) (int, error) {
	n, _, err := c.ReadFrom(b)
	return n, err
}

// Write は未接続の待ち受けでは宛先が要るので誤りを返す。
func (c *UDPConn) Write(b []byte) (int, error) {
	return 0, c.opErr("write", nil, errDestinationRequired)
}

// WriteTo は net.PacketConn の実装。送信の予算を予約できるまで待ち、期限と Close で解ける。
func (c *UDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua.Port <= 0 || ua.Port > 65535 || ua.IP.To4() == nil {
		return 0, c.opErr("write", addr, errors.New("invalid UDP address"))
	}
	if len(b) > udpMaxPayload {
		return 0, c.opErr("write", addr, syscall.EMSGSIZE)
	}
	to := netip.AddrPortFrom(netip.AddrFrom4([4]byte(ua.IP.To4())), uint16(ua.Port))
	ep := c.ep
	s := ep.s
	u := &s.udp
	for {
		u.mu.Lock()
		if ep.closed || u.closed {
			u.mu.Unlock()
			return 0, net.ErrClosed
		}
		if u.fault != nil {
			err := u.fault
			u.mu.Unlock()
			return 0, c.opErr("write", addr, err)
		}
		if ep.wdl.expired() {
			u.mu.Unlock()
			return 0, c.opErr("write", addr, os.ErrDeadlineExceeded)
		}
		if id, _ := s.udpReserve(ep, dirTx, len(b)); id >= 0 {
			g := &u.dg[dirTx][id]
			g.peer = to
			s.udpPut(dirTx, id, b)
			g.ipID = s.nextID()
			if g.ipID == 0 {
				g.ipID = s.nextID()
			}
			g.csum = s.udpChecksum(id, ep.local, to)
			if u.txTail >= 0 {
				u.dg[dirTx][u.txTail].next = id
			} else {
				u.txHead = id
			}
			u.txTail = id
			s.out.mu.Lock()
			s.out.udpQueued++
			s.out.mu.Unlock()
			u.mu.Unlock()
			s.out.kick()
			return len(b), nil
		}
		space, dl := u.txSpace, ep.wdl.wait()
		u.txWaited = true
		u.mu.Unlock()
		select {
		case <-space:
		case <-dl:
		case <-s.done:
		}
	}
}

// udpChecksum は送信の datagram id の UDP の checksum を求める。
func (s *stack) udpChecksum(id int32, from, to netip.AddrPort) uint16 {
	g := &s.udp.dg[dirTx][id]
	ulen := udpHeaderLen + g.n
	sum := pseudoSum(addrBits(from.Addr()), addrBits(to.Addr()), protoUDP, ulen)
	var h [udpHeaderLen]byte
	binary.BigEndian.PutUint16(h[0:2], from.Port())
	binary.BigEndian.PutUint16(h[2:4], to.Port())
	binary.BigEndian.PutUint16(h[4:6], uint16(ulen))
	sum += uint32(checksum(0, h[:]))
	var buf [1024]byte
	pos := 0
	for off := 0; off < g.n; {
		k := s.udpGet(dirTx, id, off, buf[:])
		for _, x := range buf[:k] {
			if pos&1 == 0 {
				sum += uint32(x) << 8
			} else {
				sum += uint32(x)
			}
			pos++
		}
		off += k
		for sum>>16 != 0 {
			sum = sum&0xffff + sum>>16
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	cs := ^uint16(sum)
	if cs == 0 {
		cs = 0xffff
	}
	return cs
}

// pollUDP は送信の FIFO の先頭の datagram の次の断片を b に作る。datagram を送り終えたら予約を返す。
func (s *stack) pollUDP(b []byte) int {
	u := &s.udp
	u.mu.Lock()
	defer u.mu.Unlock()
	id := u.txHead
	if id < 0 {
		return 0
	}
	g := &u.dg[dirTx][id]
	total := udpHeaderLen + g.n
	space := min(len(b), s.mtu) - ipHeaderLen
	if space < 8 {
		return 0
	}
	frag := total - g.sent
	more := false
	if frag > space {
		frag = space &^ 7
		more = true
	}
	src, dst := g.ep.local, g.peer
	p := b[:ipHeaderLen+frag]
	writeIPv4Header(p, len(p), g.ipID, protoUDP, addrBits(src.Addr()), addrBits(dst.Addr()))
	flags := uint16(g.sent / 8)
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(p[6:8], flags) // DF は立てない
	p[10], p[11] = 0, 0
	binary.BigEndian.PutUint16(p[10:12], ^checksum(0, p[:ipHeaderLen]))
	body := p[ipHeaderLen:]
	off := g.sent
	if off == 0 {
		binary.BigEndian.PutUint16(body[0:2], src.Port())
		binary.BigEndian.PutUint16(body[2:4], dst.Port())
		binary.BigEndian.PutUint16(body[4:6], uint16(total))
		binary.BigEndian.PutUint16(body[6:8], g.csum)
		s.udpGet(dirTx, id, 0, body[udpHeaderLen:])
	} else {
		s.udpGet(dirTx, id, off-udpHeaderLen, body)
	}
	g.sent += frag
	if g.sent >= total {
		u.txHead = g.next
		if u.txHead < 0 {
			u.txTail = -1
		}
		s.udpRelease(dirTx, id)
		s.out.mu.Lock()
		s.out.udpQueued--
		s.out.mu.Unlock()
	}
	return len(p)
}

// Close は待ち受けを閉じる。受けて読まれていない datagram の予約を返し、待っている読み書きを解く。
// 送信の FIFO にある datagram は送り終えたときに返す。
func (c *UDPConn) Close() error {
	ep := c.ep
	u := &ep.s.udp
	u.mu.Lock()
	defer u.mu.Unlock()
	if ep.closed {
		return nil
	}
	ep.s.udpCloseLocked(ep)
	return nil
}

func (s *stack) udpCloseLocked(ep *udpEndpoint) {
	u := &s.udp
	ep.closed = true
	if u.eps[ep.local] == ep {
		delete(u.eps, ep.local)
	}
	for id := ep.rxHead; id >= 0; {
		next := u.dg[dirRx][id].next
		s.udpRelease(dirRx, id)
		id = next
	}
	ep.rxHead, ep.rxTail = -1, -1
	close(ep.rch)
	ep.rch = make(chan struct{}, 1)
	u.wakeTx()
}

func (c *UDPConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *UDPConn) SetReadDeadline(t time.Time) error {
	c.ep.rdl.set(t)
	c.wake()
	return nil
}

func (c *UDPConn) SetWriteDeadline(t time.Time) error {
	c.ep.wdl.set(t)
	c.wake()
	return nil
}

// wake は待っている読み書きに期限の変化を知らせる。
func (c *UDPConn) wake() {
	u := &c.ep.s.udp
	u.mu.Lock()
	select {
	case c.ep.rch <- struct{}{}:
	default:
	}
	u.wakeTx()
	u.mu.Unlock()
}

// udpClose は Device の Close で UDP をすべて閉じる。
func (s *stack) udpClose() {
	u := &s.udp
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return
	}
	u.closed = true
	for _, ep := range u.eps {
		s.udpCloseLocked(ep)
	}
	for id := u.txHead; id >= 0; {
		next := u.dg[dirTx][id].next
		s.udpRelease(dirTx, id)
		id = next
	}
	u.txHead, u.txTail = -1, -1
	s.out.mu.Lock()
	s.out.udpQueued = 0
	s.out.mu.Unlock()
}

// udpHeld は UDP が今持つ chunk の byte と datagram の数を返す。
func (s *stack) udpHeld() (rxBytes, rxCount, txBytes, txCount int64) {
	u := &s.udp
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.budget[dirRx].bytes, u.budget[dirRx].count, u.budget[dirTx].bytes, u.budget[dirTx].count
}

var _ net.PacketConn = (*UDPConn)(nil)
