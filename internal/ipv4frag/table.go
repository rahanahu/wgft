// Package ipv4frag は IPv4 の断片の有限な再組み立ての表を持つ。internal/nettun と internal/wgstack の Device が
// 共有し、どちらも断片をすべてここへ渡す(設計文書 7 節と wgstack.md の「package の配置」)。モジュールの中の
// 何も import しない。表は項目、断片の枠、保持 byte の 3 つの上限を持つ固定の配列で、
// 満杯のときは今の鍵以外で最も古い未完成の項目を追い出す。呼び出し側は、packet が来ないときも
// 時計に合わせて Sweep を呼び、返った notice を ICMP の経路へ渡し、最後に Close を呼ぶ。
package ipv4frag

import (
	"bytes"
	"encoding/binary"
	"errors"
	"sync"
	"time"
	"unsafe"
)

type Limits struct {
	Entries, Fragments int
	Bytes              int // retained capacities, fixed slot metadata, and one completion copy
	Lifetime           time.Duration
}

type Status uint8

const (
	Held Status = iota
	Complete
	Duplicate
	Rejected
	Capacity
	Closed
)

type Reason uint8

const (
	ReasonNone Reason = iota
	ReasonMalformed
	ReasonOptions
	ReasonOverlap
	ReasonConflict
	ReasonExpired
	ReasonCapacity
)

// A notice is bounded to the original first header plus eight payload bytes.
// It carries what the Device needs to build ICMP, not an ICMP packet.
type Notice struct {
	Reason   Reason
	Pointer  uint8 // meaningful for malformed options when known
	Quote    [68]byte
	QuoteLen uint8
	HasFirst bool
}

type Result struct {
	Status Status
	Packet []byte // caller owns this one completed copy; not retained here
	Notice Notice
}

type ipv4AssemblyKey struct {
	src, dst [4]byte
	id       uint16
	protocol uint8
}

type ipv4Assembly struct {
	used      bool
	key       ipv4AssemblyKey
	deadline  time.Time
	total     int // -1 until the last fragment is seen
	covered   int
	parts     int
	firstLen  int
	first     [60]byte
	quote     [68]byte
	quoteLen  uint8
	copied    [40]byte
	copiedLen int
	copiedSet bool
	ecnMask   uint8
}

type ipv4Piece struct {
	used  bool
	owner int
	start int
	more  bool
	data  []byte // make(len), no spare slice capacity
}

type Table struct {
	mu       sync.Mutex
	limits   Limits
	entries  []ipv4Assembly
	pieces   []ipv4Piece
	baseCost int
	used     int // baseCost plus cap of every retained payload copy
	evicted  uint64
	closed   bool
}

func New(l Limits) (*Table, error) {
	if l.Entries <= 0 || l.Fragments <= 0 || l.Bytes <= 0 || l.Lifetime <= 0 || l.Entries > 4096 || l.Fragments > 65536 {
		return nil, errors.New("invalid IPv4 reassembly limits")
	}
	entryCost := int(unsafe.Sizeof(ipv4Assembly{}))
	pieceCost := int(unsafe.Sizeof(ipv4Piece{}))
	if l.Entries > (l.Bytes-int(unsafe.Sizeof(Table{})))/entryCost {
		return nil, errors.New("IPv4 reassembly metadata exceeds budget")
	}
	base := int(unsafe.Sizeof(Table{})) + l.Entries*entryCost
	if l.Fragments > (l.Bytes-base)/pieceCost {
		return nil, errors.New("IPv4 reassembly metadata exceeds budget")
	}
	base += l.Fragments * pieceCost
	// Sweep's returned notice slice is a bounded transient copy that can
	// coexist with all retained fragments and a completion packet.
	if l.Entries > (l.Bytes-base)/int(unsafe.Sizeof(Notice{})) {
		return nil, errors.New("IPv4 reassembly notice copy exceeds budget")
	}
	base += l.Entries * int(unsafe.Sizeof(Notice{}))
	return &Table{
		limits: l, entries: make([]ipv4Assembly, l.Entries), pieces: make([]ipv4Piece, l.Fragments),
		baseCost: base, used: base,
	}, nil
}

func ChecksumOK(h []byte) bool {
	var sum uint32
	for i := 0; i < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return sum == 0xffff
}

func SetChecksum(h []byte) {
	h[10], h[11] = 0, 0
	var sum uint32
	for i := 0; i < len(h); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(h[10:], ^uint16(sum))
}

// Return copied TLVs without padding. Non-first fragments may contain only
// copied options. Unknown copied options are preserved, not discarded.
func ipv4CopiedOptions(h []byte, first bool) ([40]byte, int, uint8, error) {
	var copied [40]byte
	n := 0
	for p := 20; p < len(h); {
		kind := h[p]
		if kind == 0 { // EOL: the rest must be padding.
			for q := p + 1; q < len(h); q++ {
				if h[q] != 0 {
					return copied, 0, uint8(q), errors.New("nonzero IPv4 option padding")
				}
			}
			break
		}
		if kind == 1 {
			p++
			continue
		}
		if p+2 > len(h) || h[p+1] < 2 || p+int(h[p+1]) > len(h) {
			return copied, 0, uint8(p), errors.New("invalid IPv4 option length")
		}
		length := int(h[p+1])
		if kind&0x80 == 0 && !first {
			return copied, 0, uint8(p), errors.New("non-copied option in later fragment")
		}
		if kind&0x80 != 0 {
			copy(copied[n:], h[p:p+length])
			n += length
		}
		p += length
	}
	return copied, n, 0, nil
}

func ipv4Notice(reason Reason, pointer uint8, packet []byte, first bool) Notice {
	n := Notice{Reason: reason, Pointer: pointer, HasFirst: first}
	if first {
		length := len(packet)
		if len(packet) >= 1 {
			h := int(packet[0]&15) * 4
			if h >= 20 && h <= 60 && length > h+8 {
				length = h + 8
			}
		}
		if length > len(n.Quote) {
			length = len(n.Quote)
		}
		copy(n.Quote[:], packet[:length])
		n.QuoteLen = uint8(length)
	}
	return n
}

func sameFirstIPv4Header(saved, incoming []byte) bool {
	if len(saved) != len(incoming) {
		return false
	}
	var normalized [20]byte
	copy(normalized[:], incoming[:20])
	// A duplicate may have different ECN, DSCP, TTL, checksum or mutable
	// option values. Require the fixed structure and option types/lengths.
	normalized[1], normalized[8] = saved[1], saved[8]
	normalized[10], normalized[11] = saved[10], saved[11]
	if !bytes.Equal(saved[:20], normalized[:]) {
		return false
	}
	for p := 20; p < len(saved); {
		if saved[p] != incoming[p] {
			return false
		}
		if saved[p] == 0 {
			return true
		}
		if saved[p] == 1 {
			p++
			continue
		}
		if saved[p+1] != incoming[p+1] {
			return false
		}
		p += int(saved[p+1])
	}
	return true
}

func sameCopiedOptionShape(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for p := 0; p < len(a); {
		if a[p] != b[p] || a[p+1] != b[p+1] {
			return false
		}
		p += int(a[p+1])
	}
	return true
}

func (t *Table) clearEntry(i int) {
	for p := range t.pieces {
		if t.pieces[p].used && t.pieces[p].owner == i {
			t.used -= cap(t.pieces[p].data)
			t.pieces[p] = ipv4Piece{}
		}
	}
	t.entries[i] = ipv4Assembly{}
}

// evictOldestLocked frees the entry with the earliest deadline other than
// keep (-1 keeps none) and returns its index, or -1 when no other entry
// exists. Every deadline is admission time plus the same lifetime, so the
// earliest deadline is the oldest entry; ties go to the lower index.
// Eviction is silent: no notice and no ICMP, matching pinned gVisor's
// release(tail, false) and Linux, where only the timer sends Time Exceeded.
func (t *Table) evictOldestLocked(keep int) int {
	victim := -1
	for i := range t.entries {
		e := &t.entries[i]
		if !e.used || i == keep {
			continue
		}
		if victim < 0 || e.deadline.Before(t.entries[victim].deadline) {
			victim = i
		}
	}
	if victim < 0 {
		return -1
	}
	t.clearEntry(victim)
	t.evicted++
	return victim
}

// Evicted returns the cumulative number of entries freed by evictOldestLocked.
func (t *Table) Evicted() uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.evicted
}

func (t *Table) noticeEntry(i int, reason Reason) Notice {
	e := &t.entries[i]
	n := Notice{Reason: reason, HasFirst: e.firstLen != 0, QuoteLen: e.quoteLen}
	copy(n.Quote[:], e.quote[:])
	return n
}

func (t *Table) Sweep(now time.Time) []Notice {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	var notices []Notice // allocated only if at least one expires
	for i := range t.entries {
		if t.entries[i].used && !now.Before(t.entries[i].deadline) {
			if notices == nil {
				notices = make([]Notice, 0, len(t.entries))
			}
			notices = append(notices, t.noticeEntry(i, ReasonExpired))
			t.clearEntry(i)
		}
	}
	return notices
}

func (t *Table) Close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	for i := range t.entries {
		if t.entries[i].used {
			t.clearEntry(i)
		}
	}
	t.closed = true
	// The fixed metadata arrays remain part of this closed object until it is
	// collected. No payload copy or quote remains referenced by the arrays.
}

// Snapshot は表の今の状態の写し。診断と試験が上限、固定の管理領域、保持 byte、項目と断片の数、追い出した数を読む。
type Snapshot struct {
	Limits    Limits
	BaseCost  int // 表の固定の管理領域、通知の写し、構造の byte
	Used      int // BaseCost と保持する断片の複製の容量の和
	Entries   int
	Fragments int
	Evicted   uint64
}

// Snapshot は今の状態の写しを返す。
func (t *Table) Snapshot() Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	used, entries, fragments := t.usageLocked()
	return Snapshot{Limits: t.limits, BaseCost: t.baseCost, Used: used, Entries: entries, Fragments: fragments, Evicted: t.evicted}
}

func (t *Table) Usage() (usedBytes, entries, fragments int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.usageLocked()
}

func (t *Table) usageLocked() (usedBytes, entries, fragments int) {
	for i := range t.entries {
		if t.entries[i].used {
			entries++
		}
	}
	for i := range t.pieces {
		if t.pieces[i].used {
			fragments++
		}
	}
	return t.used, entries, fragments
}

func (t *Table) Process(packet []byte, now time.Time) Result {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return Result{Status: Closed}
	}
	reject := func(reason Reason, ptr uint8, first bool) Result {
		return Result{Status: Rejected, Notice: ipv4Notice(reason, ptr, packet, first)}
	}
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return reject(ReasonMalformed, 0, false)
	}
	hlen := int(packet[0]&15) * 4
	if hlen < 20 || hlen > 60 || hlen > len(packet) || binary.BigEndian.Uint16(packet[2:]) != uint16(len(packet)) || len(packet) > 65535 {
		return reject(ReasonMalformed, 0, false)
	}
	flags := binary.BigEndian.Uint16(packet[6:])
	start := int(flags&0x1fff) * 8
	more := flags&0x2000 != 0
	first := start == 0
	if !ChecksumOK(packet[:hlen]) || flags&0x8000 != 0 || (flags&0x4000 != 0 && (more || start != 0)) || (!more && start == 0) {
		return reject(ReasonMalformed, 6, first)
	}
	copied, copiedLen, pointer, err := ipv4CopiedOptions(packet[:hlen], first)
	if err != nil {
		return reject(ReasonOptions, pointer, first)
	}
	payload := packet[hlen:]
	if len(payload) == 0 || (more && len(payload)%8 != 0) || start+len(payload) > 65535-20 {
		return reject(ReasonMalformed, 6, first)
	}
	key := ipv4AssemblyKey{id: binary.BigEndian.Uint16(packet[4:]), protocol: packet[9]}
	copy(key.src[:], packet[12:16])
	copy(key.dst[:], packet[16:20])
	index := -1
	free := -1
	for i := range t.entries {
		if t.entries[i].used && t.entries[i].key == key {
			index = i
			break
		}
		if !t.entries[i].used && free < 0 {
			free = i
		}
	}
	if index >= 0 && !now.Before(t.entries[index].deadline) {
		n := t.noticeEntry(index, ReasonExpired)
		t.clearEntry(index)
		// Do not silently consume the timeout notification while admitting a
		// new fragment with the same key. The caller can retry that fragment.
		return Result{Status: Rejected, Notice: n}
	}
	if index < 0 {
		if free < 0 {
			// A full key table always has another entry to evict.
			if free = t.evictOldestLocked(-1); free < 0 {
				return Result{Status: Capacity, Notice: ipv4Notice(ReasonCapacity, 0, packet, first)}
			}
		}
		index = free
		t.entries[index] = ipv4Assembly{used: true, key: key, deadline: now.Add(t.limits.Lifetime), total: -1}
	}
	e := &t.entries[index]
	conflict := func(reason Reason) Result {
		n := t.noticeEntry(index, reason)
		t.clearEntry(index)
		return Result{Status: Rejected, Notice: n}
	}
	if first {
		if e.firstLen != 0 && !sameFirstIPv4Header(e.first[:e.firstLen], packet[:hlen]) {
			return conflict(ReasonConflict)
		}
		if e.total >= 0 && e.total > 65535-hlen {
			return conflict(ReasonConflict)
		}
	}
	if e.firstLen != 0 && start+len(payload) > 65535-e.firstLen {
		return conflict(ReasonConflict)
	}
	if e.total >= 0 && (start+len(payload) > e.total || (!more && start+len(payload) != e.total)) {
		return conflict(ReasonConflict)
	}
	if e.copiedSet && !sameCopiedOptionShape(copied[:copiedLen], e.copied[:e.copiedLen]) {
		return conflict(ReasonOptions)
	}
	mask := e.ecnMask | (1 << (packet[1] & 3))
	if mask&1 != 0 && mask&8 != 0 {
		return conflict(ReasonConflict)
	} // CE + Not-ECT
	end := start + len(payload)
	duplicate := false
	for p := range t.pieces {
		part := &t.pieces[p]
		if !part.used || part.owner != index {
			continue
		}
		partEnd := part.start + len(part.data)
		if start == part.start && end == partEnd && bytes.Equal(payload, part.data) {
			if more != part.more {
				return conflict(ReasonConflict)
			}
			duplicate = true
			break
		}
		if start < partEnd && part.start < end {
			return conflict(ReasonOverlap)
		}
		if (!more && partEnd > end) || (first && partEnd > 65535-hlen) {
			return conflict(ReasonConflict)
		}
	}
	if duplicate {
		e.ecnMask = mask
		return Result{Status: Duplicate}
	}
	if !more && e.total >= 0 && e.total != end {
		return conflict(ReasonConflict)
	}
	if e.parts >= t.limits.Fragments {
		return Result{Status: Capacity, Notice: ipv4Notice(ReasonCapacity, 0, packet, first)}
	}
	capacity := func() Result {
		if e.parts == 0 {
			t.clearEntry(index)
		}
		return Result{Status: Capacity, Notice: ipv4Notice(ReasonCapacity, 0, packet, first)}
	}
	freePart := -1
	for {
		for p := range t.pieces {
			if !t.pieces[p].used {
				freePart = p
				break
			}
		}
		if freePart >= 0 && len(payload) <= t.limits.Bytes-t.used {
			break
		}
		if t.evictOldestLocked(index) < 0 {
			return capacity()
		}
	}
	// A completed copy may have to coexist with all retained fragments.
	newFirstLen := e.firstLen
	if first {
		newFirstLen = hlen
	}
	newTotal := e.total
	if !more {
		newTotal = end
	}
	newCovered := e.covered + len(payload)
	for newFirstLen != 0 && newTotal >= 0 && newCovered == newTotal && newFirstLen+newTotal > t.limits.Bytes-t.used-len(payload) {
		if t.evictOldestLocked(index) < 0 {
			return capacity()
		}
	}
	data := make([]byte, len(payload))
	copy(data, payload)
	t.pieces[freePart] = ipv4Piece{used: true, owner: index, start: start, more: more, data: data}
	t.used += cap(data)
	e.parts++
	e.covered = newCovered
	e.ecnMask = mask
	if !e.copiedSet {
		copy(e.copied[:], copied[:copiedLen])
		e.copiedLen, e.copiedSet = copiedLen, true
	}
	if first {
		copy(e.first[:], packet[:hlen])
		e.firstLen = hlen
		n := hlen + 8
		if n > len(packet) {
			n = len(packet)
		}
		copy(e.quote[:], packet[:n])
		e.quoteLen = uint8(n)
	}
	if !more {
		e.total = end
	}
	if e.firstLen == 0 || e.total < 0 || e.covered != e.total {
		return Result{Status: Held}
	}
	out := make([]byte, e.firstLen+e.total)
	copy(out, e.first[:e.firstLen])
	for p := range t.pieces {
		if t.pieces[p].used && t.pieces[p].owner == index {
			copy(out[e.firstLen+t.pieces[p].start:], t.pieces[p].data)
		}
	}
	binary.BigEndian.PutUint16(out[2:], uint16(len(out)))
	out[6], out[7] = 0, 0
	// RFC 3168 does not prescribe a result for mixed ECT(0)/ECT(1)
	// fragments. Preserve the first header's value (as the pinned stack does)
	// unless any fragment is CE, in which case congestion must survive.
	if e.ecnMask&8 != 0 {
		out[1] = (out[1] &^ 3) | 3
	}
	SetChecksum(out[:e.firstLen])
	t.clearEntry(index)
	return Result{Status: Complete, Packet: out}
}
