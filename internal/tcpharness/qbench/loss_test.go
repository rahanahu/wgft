//go:build qbench

package qbench

import (
	"encoding/binary"
	"math"
	"math/rand"
	"slices"
	"testing"
)

// The link tests send hand-made packets of one flow: the client is direction 0, the DUT direction
// 1, and the DUT sends the data, as in a send cell.
const (
	lossSeed  = 3430294
	clientISN = 1_000_000
	dutISN    = 4_000_000_000 // wraps within the first 300 MB of the stream
	testMSS   = 1380
	testBlock = testMSS - 12 // both SYNs carry the timestamp option
)

// tcpPacket builds an IPv4/TCP packet from the client's port 40000 to the DUT's port, or back for
// direction 1, with n bytes of payload. syn adds the MSS and timestamp options.
func tcpPacket(d int, seq, ack uint32, flags byte, n int, syn bool) []byte {
	var opts []byte
	if syn {
		opts = []byte{2, 4, testMSS >> 8, testMSS & 0xff, 1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 0}
	} else {
		opts = []byte{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 1}
	}
	thl := 20 + len(opts)
	p := make([]byte, 20+thl+n)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	p[8], p[9] = 64, 6
	t := p[20:]
	sport, dport := uint16(40000), uint16(port)
	if d == 1 {
		sport, dport = dport, sport
	}
	binary.BigEndian.PutUint16(t, sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	binary.BigEndian.PutUint32(t[4:], seq)
	binary.BigEndian.PutUint32(t[8:], ack)
	t[12] = byte(thl/4) << 4
	t[13] = flags
	binary.BigEndian.PutUint16(t[14:], 1024)
	copy(t[20:], opts)
	return p
}

// lossRig is a link with the handshake done and a way to tell whether it dropped a packet.
type lossRig struct{ l *Link }

func newLossRig(t *testing.T, imp Impair) *lossRig {
	l := NewLink(imp, lossSeed, func([]byte) {}, func([]byte) {})
	t.Cleanup(l.Close)
	r := &lossRig{l}
	r.send(0, tcpPacket(0, clientISN, 0, flagSYN, 0, true))
	r.send(1, tcpPacket(1, dutISN, clientISN+1, flagSYN|flagACK, 0, true))
	r.send(0, tcpPacket(0, clientISN+1, dutISN+1, flagACK, 0, false))
	return r
}

// send puts a packet into the link and reports whether its random loss dropped it: the tests
// set no rate limit and no outage, so every drop is random loss.
func (r *lossRig) send(d int, pkt []byte) bool {
	before := r.l.Stats(d).Dropped
	r.l.Send(d, pkt)
	return r.l.Stats(d).Dropped > before
}

// data sends the DUT's stream bytes [s, e) as one segment, s and e from the first data byte.
func (r *lossRig) data(s, e int) bool {
	return r.send(1, tcpPacket(1, dutISN+1+uint32(s), clientISN+1, flagACK, e-s, false))
}

// ack sends the client's pure ACK of the DUT's stream up to offset a.
func (r *lossRig) ack(a int) bool {
	return r.send(0, tcpPacket(0, clientISN+1, dutISN+1+uint32(a), flagACK, 0, false))
}

// segmentation cuts [0, total) into segments of the sizes size returns, in order.
type segmentation func(i, off int) int

// full is wgstack's and Linux's shape in a bulk run: full segments.
func full(int, int) int { return testBlock }

// gvisorLike is gVisor's shape in a bulk run: each 32 KiB write cut into 1340-byte segments and
// a 608-byte remainder.
func gvisorLike(_ int, off int) int {
	return min(1340, 32768-off%32768)
}

// randomSizes cuts segments of 1 byte to a block, a shape no engine has. No segment is longer
// than a block, so each carries at most one block start; TestContentLossCoalesced covers more.
func randomSizes(seed int64) segmentation {
	g := rand.New(rand.NewSource(seed))
	return func(int, int) int { return 1 + g.Intn(testBlock) }
}

// segments lists seg's segments over [0, total).
func segments(seg segmentation, total int) [][2]int {
	var out [][2]int
	for off, i := 0, 0; off < total; i++ {
		e := min(off+seg(i, off), total)
		out = append(out, [2]int{off, e})
		off = e
	}
	return out
}

// starts lists the block indexes whose first byte [s, e) carries.
func starts(s, e int) []int {
	var out []int
	for i := (s + testBlock - 1) / testBlock; i*testBlock < e; i++ {
		out = append(out, i)
	}
	return out
}

// transfer sends the stream with seg and resends what the link dropped, segment by segment, until
// everything arrived, with a pure ACK after every ackEvery segments sent. It returns, per block,
// how many transmissions of the block's first byte the link saw until one arrived.
func transfer(t *testing.T, imp Impair, seg segmentation, total, ackEvery int) map[int]int {
	r := newLossRig(t, imp)
	tries, done := map[int]int{}, map[int]bool{}
	pending := segments(seg, total)
	sent := 0
	for round := 0; len(pending) > 0; round++ {
		if round > 50 {
			t.Fatalf("%d segments still lost after 50 rounds", len(pending))
		}
		var lost [][2]int
		for _, sg := range pending {
			dropped := r.data(sg[0], sg[1])
			for _, b := range starts(sg[0], sg[1]) {
				if !done[b] {
					tries[b]++
				}
				done[b] = done[b] || !dropped
			}
			if dropped {
				lost = append(lost, sg)
			}
			if sent++; ackEvery > 0 && sent%ackEvery == 0 {
				r.ack(sg[0])
			}
		}
		pending = lost
	}
	return tries
}

// lostBlocks is the blocks whose first transmission seg's transfer lost.
func lostBlocks(tries map[int]int) []int {
	var out []int
	for b, n := range tries {
		if n > 1 {
			out = append(out, b)
		}
	}
	slices.Sort(out)
	return out
}

// sameFates transfers the same stream with three segmentations and different ACK patterns, and
// reports whether every block needed the same number of transmissions in all three.
func sameFates(t *testing.T, model LossModel, loss float64) (bool, []int) {
	imp := Impair{Loss: loss, LossModel: model}
	const total = 3000 * testBlock
	a := transfer(t, imp, full, total, 2)
	b := transfer(t, imp, gvisorLike, total, 1)
	c := transfer(t, imp, randomSizes(7), total, 3)
	return maps2Equal(a, b) && maps2Equal(a, c), lostBlocks(a)
}

func maps2Equal(a, b map[int]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// TestContentLossSameBlocks checks that the content-keyed loss drops the same blocks, and the
// same retransmissions of them, whatever the segment boundaries and the ACKs between them.
// The arrival model on the same input must differ: it is the mutation check that shows the test
// fails if the keying falls back to arrival order.
func TestContentLossSameBlocks(t *testing.T) {
	for _, loss := range []float64{0.01, 0.05} {
		same, lost := sameFates(t, LossContent, loss)
		if !same {
			t.Errorf("loss %g: the segmentations met different fates", loss)
		}
		// 3,000 blocks: about 30 and 150 lost on the first transmission
		want := loss * 3000
		if math.Abs(float64(len(lost))-want) > 5*math.Sqrt(want) {
			t.Errorf("loss %g: %d of 3000 blocks lost on the first transmission, want about %.0f", loss, len(lost), want)
		}
		if same, _ := sameFates(t, LossArrival, loss); same {
			t.Errorf("loss %g: the arrival model met the same fates, so the check cannot tell the models apart", loss)
		}
	}
}

// TestContentLossRetransmissionKeyed checks that a block's retransmissions are drawn by their
// count: a lost block is not lost forever, and the second transmissions are lost at the loss
// rate, independent of the first.
func TestContentLossRetransmissionKeyed(t *testing.T) {
	const blocks = 20000
	tries := transfer(t, Impair{Loss: 0.5}, full, blocks*testBlock, 0)
	var first, second, most int
	for _, n := range tries {
		if n > 1 {
			first++
		}
		if n > 2 {
			second++
		}
		most = max(most, n)
	}
	if most > 40 {
		t.Errorf("a block needed %d transmissions at loss 0.5", most)
	}
	if math.Abs(float64(first)/blocks-0.5) > 0.02 {
		t.Errorf("%d of %d first transmissions lost, want about half", first, blocks)
	}
	if math.Abs(float64(second)/float64(first)-0.5) > 0.03 {
		t.Errorf("%d of %d second transmissions lost, want about half", second, first)
	}
	// the same blocks in other segments, with ACKs between them, meet the same fates
	again := transfer(t, Impair{Loss: 0.5}, gvisorLike, blocks*testBlock, 5)
	if !maps2Equal(tries, again) {
		t.Errorf("the same stream in other segments met different fates")
	}
}

// TestContentLossRate checks the rate per block of a bulk stream and per message of a thin one.
func TestContentLossRate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		block int
		seg   int
		loss  float64
	}{
		{"bulk 1%", 0, testBlock, 0.01},
		{"bulk 5%", 0, testBlock, 0.05},
		{"thin 1%", thinSize, thinSize, 0.01},
		{"thin 5%", thinSize, thinSize, 0.05},
	} {
		r := newLossRig(t, Impair{Loss: tc.loss, LossBlock: tc.block})
		const n = 100000
		lost := 0
		for i := 0; i < n; i++ {
			if r.data(i*tc.seg, (i+1)*tc.seg) {
				lost++
			}
		}
		want := tc.loss * n
		if math.Abs(float64(lost)-want) > 5*math.Sqrt(want) {
			t.Errorf("%s: %d of %d segments lost, want about %.0f", tc.name, lost, n, want)
		}
	}
}

// TestContentLossAcks checks that a pure ACK's fate depends on the byte it acknowledges and on
// how many ACKs of that byte came before, not on the other packets between them, and that ACKs
// are lost at the loss rate.
func TestContentLossAcks(t *testing.T) {
	const n = 50000
	fates := func(extraEvery int) []bool {
		r := newLossRig(t, Impair{Loss: 0.05})
		var out []bool
		for i := 0; i < n; i++ {
			if extraEvery > 0 && i%extraEvery == 0 {
				// data, and an ACK of a byte no other ACK acknowledges, as another engine's
				// ACKs at other segment boundaries would be
				r.data(i*testBlock, (i+1)*testBlock)
				r.ack(i*testBlock + 7)
			}
			// every fourth ACK is a duplicate of the one before
			a := i * testBlock
			if i%4 == 3 {
				a -= testBlock
			}
			out = append(out, r.ack(a))
		}
		return out
	}
	a, b := fates(0), fates(3)
	if !slices.Equal(a, b) {
		t.Errorf("the ACKs met different fates with other packets between them")
	}
	lost := 0
	for _, x := range a {
		if x {
			lost++
		}
	}
	if want := 0.05 * n; math.Abs(float64(lost)-want) > 5*math.Sqrt(want) {
		t.Errorf("%d of %d ACKs lost, want about %.0f", lost, n, want)
	}
}

// TestContentLossCoalesced checks that a segment carrying several block starts, as an engine
// sends when it coalesces queued thin messages, is lost with probability Loss, not once per
// block it carries.
func TestContentLossCoalesced(t *testing.T) {
	for k := 2; k <= 7; k++ {
		r := newLossRig(t, Impair{Loss: 0.05, LossBlock: thinSize})
		const n = 40000
		lost := 0
		for i := 0; i < n; i++ {
			if r.data(i*k*thinSize, (i+1)*k*thinSize) {
				lost++
			}
		}
		if want := 0.05 * n; math.Abs(float64(lost)-want) > 5*math.Sqrt(want) {
			t.Errorf("segments of %d messages: %d of %d lost, want about %.0f", k, lost, n, want)
		}
	}
}

// TestContentLossDirections checks that the two directions draw independently: the same block
// offsets and the same acknowledgments meet unrelated fates in each direction.
func TestContentLossDirections(t *testing.T) {
	r := newLossRig(t, Impair{Loss: 0.05})
	const n = 40000
	var lost [2]int
	var dataBoth, ackBoth int
	for i := 0; i < n; i++ {
		c := r.send(0, tcpPacket(0, clientISN+1+uint32(i*testBlock), dutISN+1, flagACK, testBlock, false))
		dd := r.data(i*testBlock, (i+1)*testBlock)
		if c && dd {
			dataBoth++
		}
		// pure ACKs of the same offset of the other direction's stream
		a0 := r.send(0, tcpPacket(0, clientISN+1, dutISN+1+uint32(i*testBlock)+7, flagACK, 0, false))
		a1 := r.send(1, tcpPacket(1, dutISN+1, clientISN+1+uint32(i*testBlock)+7, flagACK, 0, false))
		if a0 && a1 {
			ackBoth++
		}
		if c {
			lost[0]++
		}
		if dd {
			lost[1]++
		}
	}
	// independent draws lose both about 0.05 x 0.05 x n = 100 times; shared draws about 2,000
	for name, both := range map[string]int{"data": dataBoth, "ACKs": ackBoth} {
		if both > 200 {
			t.Errorf("%s: %d of %d lost in both directions, want about 100 for independent draws", name, both, n)
		}
	}
	for d, l := range lost {
		if want := 0.05 * n; math.Abs(float64(l)-want) > 5*math.Sqrt(want) {
			t.Errorf("direction %d: %d of %d data segments lost, want about %.0f", d, l, n, want)
		}
	}
}

// TestContentLossDuplicateAcks checks that a duplicate of a lost ACK draws again: the second ACK
// of the same byte is lost with probability Loss whatever happened to the first, so a receiver
// can always get duplicate ACKs through.
func TestContentLossDuplicateAcks(t *testing.T) {
	r := newLossRig(t, Impair{Loss: 0.05})
	const n = 100000
	firstLost, bothLost := 0, 0
	for i := 0; i < n; i++ {
		a := i*testBlock + 3
		if r.ack(a) {
			firstLost++
			if r.ack(a) {
				bothLost++
			}
		}
	}
	// independent: about 0.05 x firstLost; keyed without the occurrence: all of them
	if want := 0.05 * float64(firstLost); math.Abs(float64(bothLost)-want) > 5*math.Sqrt(want)+1 {
		t.Errorf("%d of %d duplicates of a lost ACK lost, want about %.0f", bothLost, firstLost, want)
	}
}

// TestContentLossPast2GiB checks that stream offsets past 2 GiB, where the sequence offset no
// longer fits an int32, and past the 4 GiB sequence space are still lost at the loss rate.
func TestContentLossPast2GiB(t *testing.T) {
	r := newLossRig(t, Impair{Loss: 0.05})
	off := 0
	for _, at := range []int{3 << 30, 5 << 30} {
		// walk the stream forward in steps the link can unwrap
		for ; off+(1<<30) <= at; off += 1 << 30 {
			r.data(off, off+testBlock)
		}
		off = at / testBlock * testBlock
		const n = 40000
		lost := 0
		for i := 0; i < n; i++ {
			if r.data(off+i*testBlock, off+(i+1)*testBlock) {
				lost++
			}
		}
		off += n * testBlock
		if want := 0.05 * n; math.Abs(float64(lost)-want) > 5*math.Sqrt(want) {
			t.Errorf("at %d GiB: %d of %d segments lost, want about %.0f", at>>30, lost, n, want)
		}
	}
}

// TestArrivalLossUnchanged checks that LossArrival is the earlier model: the n-th packet of a
// direction is dropped when that direction's n-th draw from its seeded generator is below Loss.
func TestArrivalLossUnchanged(t *testing.T) {
	l := NewLink(Impair{Loss: 0.3, LossModel: LossArrival}, lossSeed, func([]byte) {}, func([]byte) {})
	defer l.Close()
	r := &lossRig{l}
	g := [2]*rand.Rand{rand.New(rand.NewSource(lossSeed)), rand.New(rand.NewSource(lossSeed ^ 0x5bd1e995))}
	pkts := [][2]any{
		{0, tcpPacket(0, clientISN, 0, flagSYN, 0, true)},
		{1, tcpPacket(1, dutISN, clientISN+1, flagSYN|flagACK, 0, true)},
	}
	for i := 0; i < 2000; i++ {
		pkts = append(pkts, [2]any{1, tcpPacket(1, dutISN+1+uint32(i*testBlock), clientISN+1, flagACK, testBlock, false)})
		if i%2 == 1 {
			pkts = append(pkts, [2]any{0, tcpPacket(0, clientISN+1, dutISN+1+uint32(i*testBlock), flagACK, 0, false)})
		}
	}
	for i, p := range pkts {
		d := p[0].(int)
		want := g[d].Float64() < 0.3
		if got := r.send(d, p[1].([]byte)); got != want {
			t.Fatalf("packet %d in direction %d: dropped %v, the arrival draw says %v", i, d, got, want)
		}
	}
}
