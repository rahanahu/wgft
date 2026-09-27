package nettun

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

func reasmIPv4Fragment(proto byte, id uint16, offset int, more bool, tos byte, options, data []byte) []byte {
	hlen := 20 + len(options)
	p := make([]byte, hlen+len(data))
	p[0] = 0x40 | byte(hlen/4)
	p[1] = tos
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:], id)
	flags := uint16(offset / 8)
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(p[6:], flags)
	p[8], p[9] = 64, proto
	copy(p[12:16], []byte{10, 1, 1, 1})
	copy(p[16:20], []byte{10, 1, 1, 2})
	copy(p[20:], options)
	copy(p[hlen:], data)
	ipv4SetChecksum(p[:hlen])
	return p
}

func reasmReassembler(t *testing.T, entries, pieces, budget int) *ipv4Reassembly {
	t.Helper()
	r, err := newIPv4Reassembly(ipv4ReassemblyLimits{Entries: entries, Fragments: pieces, Bytes: budget, Lifetime: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.Close)
	return r
}

func TestIPv4ReassemblyAllProtocolsOptionsAndECN(t *testing.T) {
	for _, proto := range []byte{1, 6, 17, 99} {
		t.Run(string(rune('A'+proto%26)), func(t *testing.T) {
			r := reasmReassembler(t, 2, 4, 2048)
			now := time.Unix(100, 0)
			// 0x82 is copied, 0x44 is not; the latter remains only in the first header.
			firstOpts := []byte{0x82, 4, 7, 8, 0x44, 4, 1, 2}
			laterOpts := []byte{0x82, 4, 7, 9} // copied TLV data may mutate in transit
			first := reasmIPv4Fragment(proto, 7, 0, true, 2, firstOpts, []byte("abcdefgh"))
			last := reasmIPv4Fragment(proto, 7, 8, false, 3, laterOpts, []byte("ijk"))
			if got := r.Process(last, now).Status; got != ipv4FragmentHeld {
				t.Fatalf("last first: %v", got)
			}
			if got := r.Process(last, now).Status; got != ipv4FragmentDuplicate {
				t.Fatalf("duplicate: %v", got)
			}
			res := r.Process(first, now)
			if res.Status != ipv4FragmentComplete {
				t.Fatalf("complete: %v / %+v", res.Status, res.Notice)
			}
			out := res.Packet
			if !bytes.Equal(out[20:28], firstOpts) || !bytes.Equal(out[28:], []byte("abcdefghijk")) || out[1]&3 != 3 || !ipv4ChecksumOK(out[:28]) || binary.BigEndian.Uint16(out[6:]) != 0 || binary.BigEndian.Uint16(out[2:]) != uint16(len(out)) || out[9] != proto {
				t.Fatalf("bad completed packet: %x", out)
			}
			used, entries, pieces := r.Usage()
			if used != r.baseCost || entries != 0 || pieces != 0 {
				t.Fatalf("retained: %d %d %d", used, entries, pieces)
			}
		})
	}
}

func TestIPv4ReassemblyMixedECTKeepsFirstOrCE(t *testing.T) {
	now := time.Unix(100, 0)
	for _, tc := range []struct{ first, later, want byte }{
		{1, 2, 1}, {2, 1, 2}, {1, 3, 3}, {2, 3, 3},
	} {
		r := reasmReassembler(t, 1, 2, 1024)
		first := reasmIPv4Fragment(6, 1, 0, true, tc.first, nil, []byte("abcdefgh"))
		last := reasmIPv4Fragment(6, 1, 8, false, tc.later, nil, []byte("i"))
		if got := r.Process(last, now).Status; got != ipv4FragmentHeld {
			t.Fatal(got)
		}
		res := r.Process(first, now)
		if res.Status != ipv4FragmentComplete || res.Packet[1]&3 != tc.want {
			t.Fatalf("ECN %d/%d: status %v, want %d", tc.first, tc.later, res.Status, tc.want)
		}
	}
}

func TestIPv4ReassemblyOverlapConflictAndDuplicate(t *testing.T) {
	now := time.Unix(100, 0)
	first := reasmIPv4Fragment(17, 1, 0, true, 2, []byte{0x82, 4, 7, 8}, []byte("abcdefghabcdefgh"))
	partial := reasmIPv4Fragment(17, 1, 8, false, 2, []byte{0x82, 4, 7, 9}, []byte("xxxxxxxx"))
	r := reasmReassembler(t, 1, 3, 2048)
	if got := r.Process(first, now).Status; got != ipv4FragmentHeld {
		t.Fatal(got)
	}
	if got := r.Process(first, now).Status; got != ipv4FragmentDuplicate {
		t.Fatal(got)
	}
	marked := append([]byte(nil), first...)
	marked[1] = (marked[1] &^ 3) | 3
	marked[23] = 9
	ipv4SetChecksum(marked[:24])
	if got := r.Process(marked, now).Status; got != ipv4FragmentDuplicate {
		t.Fatalf("CE-marked duplicate: %v", got)
	}
	if res := r.Process(partial, now); res.Status != ipv4FragmentRejected || res.Notice.Reason != ipv4ReasonOverlap {
		t.Fatalf("overlap: %+v", res)
	}
	if _, e, p := r.Usage(); e != 0 || p != 0 {
		t.Fatalf("overlap retained %d/%d", e, p)
	}
	first = reasmIPv4Fragment(17, 2, 0, true, 0, nil, []byte("abcdefgh"))
	last := reasmIPv4Fragment(17, 2, 8, false, 0, nil, []byte("ijk"))
	if got := r.Process(first, now).Status; got != ipv4FragmentHeld {
		t.Fatal(got)
	}
	if got := r.Process(last, now).Status; got != ipv4FragmentComplete {
		t.Fatal(got)
	}
}

func TestIPv4ReassemblyLateFirstLengthAndLastConflict(t *testing.T) {
	now := time.Unix(100, 0)
	r := reasmReassembler(t, 1, 3, 2048)
	far := reasmIPv4Fragment(6, 9, 65496, false, 0, []byte{0x82, 4, 7, 8}, []byte("abcdefghijklmnop"))
	if got := r.Process(far, now).Status; got != ipv4FragmentHeld {
		t.Fatal(got)
	}
	first := reasmIPv4Fragment(6, 9, 0, true, 0, []byte{0x82, 4, 7, 8, 0, 0, 0, 0}, []byte("abcdefgh"))
	if res := r.Process(first, now); res.Status != ipv4FragmentRejected || res.Notice.Reason != ipv4ReasonConflict {
		t.Fatalf("late IHL: %+v", res)
	}
	if _, e, p := r.Usage(); e != 0 || p != 0 {
		t.Fatalf("late IHL retained: %d/%d", e, p)
	}
	far = reasmIPv4Fragment(6, 10, 16, true, 0, nil, []byte("abcdefgh"))
	if got := r.Process(far, now).Status; got != ipv4FragmentHeld {
		t.Fatal(got)
	}
	last := reasmIPv4Fragment(6, 10, 8, false, 0, nil, []byte("12345678"))
	if res := r.Process(last, now); res.Status != ipv4FragmentRejected || res.Notice.Reason != ipv4ReasonConflict {
		t.Fatalf("last below prior part: %+v", res)
	}
}

func TestIPv4ReassemblyCapacityExpiryAndClose(t *testing.T) {
	now := time.Unix(100, 0)
	r := reasmReassembler(t, 1, 1, 1024)
	first := reasmIPv4Fragment(6, 1, 0, true, 0, nil, []byte("abcdefgh"))
	other := reasmIPv4Fragment(1, 2, 0, true, 0, nil, []byte("abcdefgh"))
	if got := r.Process(first, now).Status; got != ipv4FragmentHeld {
		t.Fatal(got)
	}
	// The one-key table is full: the new key evicts the older one instead of
	// being refused. The duplicate below is the retained (new) key.
	if res := r.Process(other, now); res.Status != ipv4FragmentHeld || res.Notice != (ipv4FragmentNotice{}) {
		t.Fatalf("second key: %+v", res)
	}
	if got := r.Evicted(); got != 1 {
		t.Fatalf("evicted = %d, want 1", got)
	}
	if got := r.Process(other, now).Status; got != ipv4FragmentDuplicate {
		t.Fatal(got)
	}
	if got := r.Sweep(now.Add(time.Second)); len(got) != 0 {
		t.Fatalf("early expiry: %+v", got)
	}
	got := r.Sweep(now.Add(2 * time.Second))
	if len(got) != 1 || !got[0].HasFirst || got[0].Reason != ipv4ReasonExpired || got[0].QuoteLen != 28 {
		t.Fatalf("expiry: %+v", got)
	}
	if used, e, p := r.Usage(); used != r.baseCost || e != 0 || p != 0 {
		t.Fatalf("expiry retained: %d/%d/%d", used, e, p)
	}
	if got := r.Process(first, now.Add(3*time.Second)).Status; got != ipv4FragmentHeld {
		t.Fatal(got)
	}
	r.Close()
	if _, e, p := r.Usage(); e != 0 || p != 0 {
		t.Fatalf("close retained: %d/%d", e, p)
	}
	if got := r.Process(first, now.Add(4*time.Second)).Status; got != ipv4FragmentClosed {
		t.Fatal(got)
	}
}

func TestIPv4ReassemblyMalformedOptionsAndLengths(t *testing.T) {
	now := time.Unix(100, 0)
	r := reasmReassembler(t, 1, 3, 2048)
	p := reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("abcdefgh"))
	p[10] ^= 1
	if res := r.Process(p, now); res.Status != ipv4FragmentRejected || res.Notice.Reason != ipv4ReasonMalformed {
		t.Fatalf("checksum: %+v", res)
	}
	p = reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("abcdefg"))
	if res := r.Process(p, now); res.Status != ipv4FragmentRejected {
		t.Fatalf("alignment: %+v", res)
	}
	p = reasmIPv4Fragment(17, 1, 8, false, 0, []byte{0x44, 4, 1, 2}, []byte("x"))
	if res := r.Process(p, now); res.Status != ipv4FragmentRejected || res.Notice.Reason != ipv4ReasonOptions {
		t.Fatalf("noncopied: %+v", res)
	}
	p = reasmIPv4Fragment(17, 1, 8, false, 0, []byte{0x82, 1, 0, 0}, []byte("x"))
	if res := r.Process(p, now); res.Status != ipv4FragmentRejected || res.Notice.Pointer != 20 {
		t.Fatalf("bad option: %+v", res)
	}
	first := reasmIPv4Fragment(17, 2, 0, true, 0, []byte{0x82, 4, 7, 8}, []byte("abcdefgh"))
	later := reasmIPv4Fragment(17, 2, 8, false, 0, []byte{0x83, 4, 7, 8}, []byte("x"))
	if got := r.Process(first, now).Status; got != ipv4FragmentHeld {
		t.Fatal(got)
	}
	if res := r.Process(later, now); res.Status != ipv4FragmentRejected || res.Notice.Reason != ipv4ReasonOptions {
		t.Fatalf("copied type mismatch: %+v", res)
	}
}

func TestIPv4ReassemblyCompletionCopyBudget(t *testing.T) {
	now := time.Unix(100, 0)
	limits := ipv4ReassemblyLimits{Entries: 1, Fragments: 2, Bytes: 1024, Lifetime: time.Second}
	r, err := newIPv4Reassembly(limits)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Leave room for both fragment payloads, but not the completed copy.
	r.limits.Bytes = r.baseCost + 8 + 3 + 31 - 1
	first := reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("abcdefgh"))
	last := reasmIPv4Fragment(17, 1, 8, false, 0, nil, []byte("ijk"))
	if got := r.Process(first, now).Status; got != ipv4FragmentHeld {
		t.Fatal(got)
	}
	if got := r.Process(last, now).Status; got != ipv4FragmentCapacity {
		t.Fatalf("copy reservation: %v", got)
	}
	if _, e, p := r.Usage(); e != 1 || p != 1 {
		t.Fatalf("capacity mutated retained state: %d/%d", e, p)
	}
}

// reasmHeldIDs returns the IDs of the keys the table currently retains.
func reasmHeldIDs(r *ipv4Reassembly) map[uint16]bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := map[uint16]bool{}
	for i := range r.entries {
		if r.entries[i].used {
			ids[r.entries[i].key.id] = true
		}
	}
	return ids
}

func reasmHold(t *testing.T, r *ipv4Reassembly, packet []byte, now time.Time) {
	t.Helper()
	if res := r.Process(packet, now); res.Status != ipv4FragmentHeld || res.Notice != (ipv4FragmentNotice{}) {
		t.Fatalf("hold: %+v", res)
	}
}

func reasmWantEvicted(t *testing.T, r *ipv4Reassembly, want uint64) {
	t.Helper()
	if got := r.Evicted(); got != want {
		t.Fatalf("evicted = %d, want %d", got, want)
	}
}

func reasmWantIDs(t *testing.T, r *ipv4Reassembly, want ...uint16) {
	t.Helper()
	got := reasmHeldIDs(r)
	if len(got) != len(want) {
		t.Fatalf("held IDs = %v, want %v", got, want)
	}
	for _, id := range want {
		if !got[id] {
			t.Fatalf("held IDs = %v, want %v", got, want)
		}
	}
}

func TestIPv4ReassemblyEvictsOldestForNewKey(t *testing.T) {
	t0 := time.Unix(100, 0)
	r := reasmReassembler(t, 2, 4, 4096)
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("aaaaaaaa")), t0)
	reasmHold(t, r, reasmIPv4Fragment(17, 2, 0, true, 0, nil, []byte("bbbbbbbb")), t0.Add(time.Millisecond))
	reasmHold(t, r, reasmIPv4Fragment(17, 3, 0, true, 0, nil, []byte("cccccccc")), t0.Add(2*time.Millisecond))
	reasmWantIDs(t, r, 2, 3)
	reasmWantEvicted(t, r, 1)
	if used, e, p := r.Usage(); used != r.baseCost+16 || e != 2 || p != 2 {
		t.Fatalf("usage after key eviction: %d/%d/%d", used-r.baseCost, e, p)
	}
}

func TestIPv4ReassemblyEvictsOldestForFragmentSlot(t *testing.T) {
	t0 := time.Unix(100, 0)
	r := reasmReassembler(t, 4, 3, 4096)
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("aaaaaaaa")), t0)
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 16, true, 0, nil, []byte("AAAAAAAA")), t0.Add(time.Millisecond))
	reasmHold(t, r, reasmIPv4Fragment(17, 2, 0, true, 0, nil, []byte("bbbbbbbb")), t0.Add(2*time.Millisecond))
	// Two keys remain free, but every fragment slot is taken.
	reasmHold(t, r, reasmIPv4Fragment(17, 3, 0, true, 0, nil, []byte("cccccccc")), t0.Add(3*time.Millisecond))
	reasmWantIDs(t, r, 2, 3)
	reasmWantEvicted(t, r, 1)
	if used, e, p := r.Usage(); used != r.baseCost+16 || e != 2 || p != 2 {
		t.Fatalf("usage after slot eviction: %d/%d/%d", used-r.baseCost, e, p)
	}
}

func TestIPv4ReassemblyEvictsOldestForBytes(t *testing.T) {
	t0 := time.Unix(100, 0)
	r := reasmReassembler(t, 4, 8, 4096)
	// Room for two 16-byte payloads but not a third.
	r.limits.Bytes = r.baseCost + 32 + 15
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("aaaaaaaaaaaaaaaa")), t0)
	reasmHold(t, r, reasmIPv4Fragment(17, 2, 0, true, 0, nil, []byte("bbbbbbbbbbbbbbbb")), t0.Add(time.Millisecond))
	reasmHold(t, r, reasmIPv4Fragment(17, 3, 0, true, 0, nil, []byte("cccccccccccccccc")), t0.Add(2*time.Millisecond))
	reasmWantIDs(t, r, 2, 3)
	reasmWantEvicted(t, r, 1)
	if used, e, p := r.Usage(); used != r.baseCost+32 || used > r.limits.Bytes || e != 2 || p != 2 {
		t.Fatalf("usage after byte eviction: %d/%d/%d", used-r.baseCost, e, p)
	}
}

func TestIPv4ReassemblyEvictsOldestForCompletionCopy(t *testing.T) {
	t0 := time.Unix(100, 0)
	limits := ipv4ReassemblyLimits{Entries: 2, Fragments: 3, Bytes: 1024, Lifetime: time.Second}
	r, err := newIPv4Reassembly(limits)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	// Same shape as TestIPv4ReassemblyCompletionCopyBudget plus one older
	// 8-byte key: both payloads fit, the completed copy fits only without it.
	r.limits.Bytes = r.baseCost + 8 + 3 + 31 - 1 + 8
	reasmHold(t, r, reasmIPv4Fragment(17, 9, 0, true, 0, nil, []byte("oldoldol")), t0)
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("abcdefgh")), t0.Add(time.Millisecond))
	res := r.Process(reasmIPv4Fragment(17, 1, 8, false, 0, nil, []byte("ijk")), t0.Add(2*time.Millisecond))
	if res.Status != ipv4FragmentComplete || !bytes.Equal(res.Packet[20:], []byte("abcdefghijk")) {
		t.Fatalf("completion after eviction: %+v", res)
	}
	reasmWantIDs(t, r)
	reasmWantEvicted(t, r, 1)
	if used, e, p := r.Usage(); used != r.baseCost || e != 0 || p != 0 {
		t.Fatalf("usage after completion: %d/%d/%d", used-r.baseCost, e, p)
	}
}

// Exact fits: the eviction loops evict only when the new payload or the
// completed copy does not fit. A payload that fits exactly evicts nothing.
func TestIPv4ReassemblyExactByteFitDoesNotEvict(t *testing.T) {
	t0 := time.Unix(100, 0)
	r := reasmReassembler(t, 4, 8, 4096)
	// Room for exactly three 16-byte payloads.
	r.limits.Bytes = r.baseCost + 48
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("aaaaaaaaaaaaaaaa")), t0)
	reasmHold(t, r, reasmIPv4Fragment(17, 2, 0, true, 0, nil, []byte("bbbbbbbbbbbbbbbb")), t0.Add(time.Millisecond))
	reasmHold(t, r, reasmIPv4Fragment(17, 3, 0, true, 0, nil, []byte("cccccccccccccccc")), t0.Add(2*time.Millisecond))
	reasmWantIDs(t, r, 1, 2, 3)
	reasmWantEvicted(t, r, 0)
	if used, e, p := r.Usage(); used != r.limits.Bytes || e != 3 || p != 3 {
		t.Fatalf("exact byte fit: %d/%d/%d", used-r.baseCost, e, p)
	}
}

// A completed copy that fits exactly evicts nothing, whether or not an older
// key could have been evicted.
func TestIPv4ReassemblyExactCompletionCopyFitDoesNotEvict(t *testing.T) {
	t0 := time.Unix(100, 0)
	first := reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("abcdefgh"))
	last := reasmIPv4Fragment(17, 1, 8, false, 0, nil, []byte("ijk"))
	t.Run("alone", func(t *testing.T) {
		r := reasmReassembler(t, 1, 2, 1024)
		// Both payloads and the 31-byte completed copy fit exactly.
		r.limits.Bytes = r.baseCost + 8 + 3 + 31
		reasmHold(t, r, first, t0)
		res := r.Process(last, t0)
		if res.Status != ipv4FragmentComplete || !bytes.Equal(res.Packet[20:], []byte("abcdefghijk")) {
			t.Fatalf("exact completion fit alone: %+v", res)
		}
		reasmWantEvicted(t, r, 0)
	})
	t.Run("with older key", func(t *testing.T) {
		r := reasmReassembler(t, 2, 3, 1024)
		r.limits.Bytes = r.baseCost + 8 + 8 + 3 + 31
		reasmHold(t, r, reasmIPv4Fragment(17, 9, 0, true, 0, nil, []byte("oldoldol")), t0)
		reasmHold(t, r, first, t0.Add(time.Millisecond))
		res := r.Process(last, t0.Add(2*time.Millisecond))
		if res.Status != ipv4FragmentComplete || !bytes.Equal(res.Packet[20:], []byte("abcdefghijk")) {
			t.Fatalf("exact completion fit with an older key: %+v", res)
		}
		reasmWantIDs(t, r, 9)
		reasmWantEvicted(t, r, 0)
	})
}

// Room for the completed copy is demanded only by the fragment that completes
// the datagram. A fragment that leaves a gap evicts nothing for the copy; the
// fragment that fills the gap evicts the older key and completes.
func TestIPv4ReassemblyNonCompletingFragmentDoesNotEvictForCopy(t *testing.T) {
	t0 := time.Unix(100, 0)
	r := reasmReassembler(t, 2, 4, 1024)
	// 16 (older key) + 8 + 3 retained payloads fit with 33 to spare; the
	// 39-byte completed copy fits only after the older key is gone.
	r.limits.Bytes = r.baseCost + 60
	reasmHold(t, r, reasmIPv4Fragment(17, 9, 0, true, 0, nil, []byte("oldoldoloooooooo")), t0)
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("abcdefgh")), t0.Add(time.Millisecond))
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 16, false, 0, nil, []byte("qrs")), t0.Add(2*time.Millisecond))
	reasmWantIDs(t, r, 9, 1)
	reasmWantEvicted(t, r, 0)
	res := r.Process(reasmIPv4Fragment(17, 1, 8, true, 0, nil, []byte("ijklmnop")), t0.Add(3*time.Millisecond))
	if res.Status != ipv4FragmentComplete || !bytes.Equal(res.Packet[20:], []byte("abcdefghijklmnopqrs")) {
		t.Fatalf("completing fragment: %+v", res)
	}
	reasmWantIDs(t, r)
	reasmWantEvicted(t, r, 1)
}

func TestIPv4ReassemblyNeverEvictsCurrentKey(t *testing.T) {
	t0 := time.Unix(100, 0)
	// The byte budget is short while the current key is alone in the table.
	r := reasmReassembler(t, 2, 4, 4096)
	r.limits.Bytes = r.baseCost + 8 + 4
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("aaaaaaaa")), t0)
	if res := r.Process(reasmIPv4Fragment(17, 1, 16, true, 0, nil, []byte("AAAAAAAA")), t0); res.Status != ipv4FragmentCapacity {
		t.Fatalf("current key alone: %+v", res)
	}
	reasmWantIDs(t, r, 1)
	reasmWantEvicted(t, r, 0)
	if used, e, p := r.Usage(); used != r.baseCost+8 || e != 1 || p != 1 {
		t.Fatalf("current key alone retained: %d/%d/%d", used-r.baseCost, e, p)
	}
	// The per-datagram fragment cap equals the whole table and stays a refusal.
	r = reasmReassembler(t, 1, 1, 4096)
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("aaaaaaaa")), t0)
	if res := r.Process(reasmIPv4Fragment(17, 1, 16, true, 0, nil, []byte("AAAAAAAA")), t0); res.Status != ipv4FragmentCapacity {
		t.Fatalf("one-slot table: %+v", res)
	}
	reasmWantIDs(t, r, 1)
	reasmWantEvicted(t, r, 0)
}

func TestIPv4ReassemblyNoEvictableEntry(t *testing.T) {
	t0 := time.Unix(100, 0)
	// A datagram that already owns every slot cannot grow; other keys have
	// nothing to give it, and nothing is evicted.
	r := reasmReassembler(t, 2, 2, 4096)
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("aaaaaaaa")), t0)
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 16, true, 0, nil, []byte("AAAAAAAA")), t0)
	if res := r.Process(reasmIPv4Fragment(17, 1, 32, true, 0, nil, []byte("xxxxxxxx")), t0); res.Status != ipv4FragmentCapacity || res.Notice.Reason != ipv4ReasonCapacity {
		t.Fatalf("slot-bound datagram: %+v", res)
	}
	reasmWantIDs(t, r, 1)
	reasmWantEvicted(t, r, 0)
	// A new key whose first fragment cannot fit an otherwise empty table is
	// refused and not retained.
	r = reasmReassembler(t, 2, 2, 4096)
	r.limits.Bytes = r.baseCost + 7
	if res := r.Process(reasmIPv4Fragment(17, 2, 0, true, 0, nil, []byte("bbbbbbbb")), t0); res.Status != ipv4FragmentCapacity {
		t.Fatalf("oversized new key: %+v", res)
	}
	reasmWantIDs(t, r)
	reasmWantEvicted(t, r, 0)
}

func TestIPv4ReassemblyEvictionOrder(t *testing.T) {
	t0 := time.Unix(100, 0)
	r := reasmReassembler(t, 3, 8, 4096)
	for i := uint16(1); i <= 3; i++ {
		reasmHold(t, r, reasmIPv4Fragment(17, i, 0, true, 0, nil, []byte("pppppppp")), t0.Add(time.Duration(i)*time.Millisecond))
	}
	// Key 4 reuses key 1's index, so the next victim is the oldest (key 2),
	// not the lowest index (key 4) or the newest (key 3).
	reasmHold(t, r, reasmIPv4Fragment(17, 4, 0, true, 0, nil, []byte("pppppppp")), t0.Add(4*time.Millisecond))
	reasmWantIDs(t, r, 2, 3, 4)
	reasmHold(t, r, reasmIPv4Fragment(17, 5, 0, true, 0, nil, []byte("pppppppp")), t0.Add(5*time.Millisecond))
	reasmWantIDs(t, r, 3, 4, 5)
	reasmWantEvicted(t, r, 2)
	// Equal deadlines evict the lower index.
	r = reasmReassembler(t, 3, 8, 4096)
	for i := uint16(1); i <= 3; i++ {
		reasmHold(t, r, reasmIPv4Fragment(17, i, 0, true, 0, nil, []byte("pppppppp")), t0)
	}
	reasmHold(t, r, reasmIPv4Fragment(17, 4, 0, true, 0, nil, []byte("pppppppp")), t0)
	reasmWantIDs(t, r, 2, 3, 4)
	reasmWantEvicted(t, r, 1)
}

func TestIPv4ReassemblyEvictedExpiredEntryIsSilent(t *testing.T) {
	t0 := time.Unix(100, 0)
	r := reasmReassembler(t, 1, 2, 4096) // lifetime 2s
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("aaaaaaaa")), t0)
	// Key 1 is past its deadline but not yet swept. Evicting it for key 2
	// drops its Time Exceeded notice, as the design documents.
	reasmHold(t, r, reasmIPv4Fragment(17, 2, 0, true, 0, nil, []byte("bbbbbbbb")), t0.Add(3*time.Second))
	reasmWantEvicted(t, r, 1)
	if got := r.Sweep(t0.Add(3 * time.Second)); len(got) != 0 {
		t.Fatalf("sweep reported the evicted entry: %+v", got)
	}
	reasmWantIDs(t, r, 2)
}

func TestIPv4ReassemblyRotationBreaksDistantFragments(t *testing.T) {
	t0 := time.Unix(100, 0)
	r := reasmReassembler(t, 4, 4, 4096)
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("abcdefgh")), t0)
	for i := uint16(10); i < 14; i++ {
		reasmHold(t, r, reasmIPv4Fragment(17, i, 0, true, 0, nil, []byte("pppppppp")), t0.Add(time.Duration(i)*time.Millisecond))
	}
	// Key 1's first fragment rotated out, so its last fragment starts over.
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 8, false, 0, nil, []byte("ijk")), t0.Add(time.Second))
	reasmWantEvicted(t, r, 2)
	reasmWantIDs(t, r, 1, 11, 12, 13)
}

func TestIPv4ReassemblyAdjacentFragmentsCompleteInFullTable(t *testing.T) {
	t0 := time.Unix(100, 0)
	r := reasmReassembler(t, 4, 4, 4096)
	for i := uint16(10); i < 14; i++ {
		reasmHold(t, r, reasmIPv4Fragment(17, i, 0, true, 0, nil, []byte("pppppppp")), t0.Add(time.Duration(i)*time.Millisecond))
	}
	reasmHold(t, r, reasmIPv4Fragment(17, 1, 0, true, 0, nil, []byte("abcdefgh")), t0.Add(time.Second))
	res := r.Process(reasmIPv4Fragment(17, 1, 8, false, 0, nil, []byte("ijk")), t0.Add(time.Second))
	if res.Status != ipv4FragmentComplete || !bytes.Equal(res.Packet[20:], []byte("abcdefghijk")) {
		t.Fatalf("adjacent fragments in a full table: %+v", res)
	}
	reasmWantEvicted(t, r, 2)
	reasmWantIDs(t, r, 12, 13)
	if used, e, p := r.Usage(); used != r.baseCost+16 || e != 2 || p != 2 {
		t.Fatalf("usage after completion: %d/%d/%d", used-r.baseCost, e, p)
	}
}

// reasmCheckLedger checks the structural invariants the eviction path must keep.
func reasmCheckLedger(t *testing.T, r *ipv4Reassembly, step int) {
	t.Helper()
	r.mu.Lock()
	sum, pieces, entries := 0, 0, 0
	owned := make([]int, len(r.entries))
	covered := make([]int, len(r.entries))
	for i := range r.pieces {
		p := &r.pieces[i]
		if !p.used {
			if p.data != nil {
				r.mu.Unlock()
				t.Fatalf("step %d: free piece %d keeps data", step, i)
			}
			continue
		}
		pieces++
		sum += cap(p.data)
		if p.owner < 0 || p.owner >= len(r.entries) || !r.entries[p.owner].used {
			r.mu.Unlock()
			t.Fatalf("step %d: piece %d owned by unused entry %d", step, i, p.owner)
		}
		owned[p.owner]++
		covered[p.owner] += len(p.data)
	}
	for i := range r.entries {
		e := &r.entries[i]
		if !e.used {
			continue
		}
		entries++
		if e.parts != owned[i] || e.covered != covered[i] {
			r.mu.Unlock()
			t.Fatalf("step %d: entry %d parts/covered %d/%d, pieces say %d/%d", step, i, e.parts, e.covered, owned[i], covered[i])
		}
	}
	used, base, limits := r.used, r.baseCost, r.limits
	r.mu.Unlock()
	if used != base+sum || used > limits.Bytes || pieces > limits.Fragments || entries > limits.Entries {
		t.Fatalf("step %d: used %d, base+sum %d, bytes limit %d, pieces %d/%d, entries %d/%d", step, used, base+sum, limits.Bytes, pieces, limits.Fragments, entries, limits.Entries)
	}
	if u, e, p := r.Usage(); u != used || e != entries || p != pieces {
		t.Fatalf("step %d: Usage %d/%d/%d, ledger %d/%d/%d", step, u, e, p, used, entries, pieces)
	}
}

func TestIPv4ReassemblyEvictionLedgerInvariant(t *testing.T) {
	rng := rand.New(rand.NewPCG(20260926, 1))
	r := reasmReassembler(t, 8, 24, 1<<16)
	r.limits.Bytes = r.baseCost + 900 // Tight enough to exercise byte eviction.
	now := time.Unix(100, 0)
	body := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(rng.IntN(256))
		}
		return b
	}
	var lastEvicted uint64
	counts := map[string]int{}
	var sent [][]byte
	for step := 0; step < 20000; step++ {
		now = now.Add(time.Duration(rng.IntN(200)) * time.Millisecond)
		id := uint16(rng.IntN(24))
		switch op := rng.IntN(8); op {
		case 0, 1: // A legitimate datagram whose fragments arrive back to back.
			id = uint16(1000 + step%60000)
			payload := body(8 * (1 + rng.IntN(8)))
			tail := body(1 + rng.IntN(40))
			first := reasmIPv4Fragment(17, id, 0, true, 0, nil, payload)
			last := reasmIPv4Fragment(17, id, len(payload), false, 0, nil, tail)
			if rng.IntN(2) == 0 {
				first, last = last, first
			}
			if res := r.Process(first, now); res.Status != ipv4FragmentHeld {
				t.Fatalf("step %d: legit first: %+v", step, res)
			}
			res := r.Process(last, now)
			want := append(append([]byte(nil), payload...), tail...)
			if res.Status != ipv4FragmentComplete || !bytes.Equal(res.Packet[20:], want) {
				t.Fatalf("step %d: legit datagram: %+v", step, res)
			}
			counts["complete"]++
		case 2: // An incomplete first fragment that is never finished.
			p := reasmIPv4Fragment(17, id, 0, true, 0, nil, body(8*(1+rng.IntN(6))))
			sent = append(sent, p)
			counts[statusName(r.Process(p, now).Status)]++
		case 3: // A middle fragment at a random aligned offset; may overlap.
			p := reasmIPv4Fragment(17, id, 8*(1+rng.IntN(12)), true, 0, nil, body(8*(1+rng.IntN(3))))
			sent = append(sent, p)
			counts[statusName(r.Process(p, now).Status)]++
		case 4: // A resend of an earlier fragment (duplicate, overlap or new).
			if len(sent) > 0 {
				counts[statusName(r.Process(sent[rng.IntN(len(sent))], now).Status)]++
			}
		case 5: // A last fragment that may complete, conflict or be held.
			p := reasmIPv4Fragment(17, id, 8*rng.IntN(14), false, 0, nil, body(1+rng.IntN(20)))
			sent = append(sent, p)
			counts[statusName(r.Process(p, now).Status)]++
		case 6: // Let deadlines pass and sweep.
			now = now.Add(time.Duration(rng.IntN(3000)) * time.Millisecond)
			counts["expired"] += len(r.Sweep(now))
		case 7: // A large fragment that forces byte eviction, or refusal when
			// its own key already holds too much.
			p := reasmIPv4Fragment(17, id, 8*rng.IntN(2)*(120+rng.IntN(10)), true, 0, nil, body(8*(20+rng.IntN(92))))
			counts[statusName(r.Process(p, now).Status)]++
		}
		reasmCheckLedger(t, r, step)
		ev := r.Evicted()
		if ev < lastEvicted {
			t.Fatalf("step %d: evicted went back from %d to %d", step, lastEvicted, ev)
		}
		lastEvicted = ev
	}
	if lastEvicted == 0 || counts["complete"] == 0 || counts["expired"] == 0 || counts["rejected"] == 0 || counts["duplicate"] == 0 || counts["capacity"] == 0 {
		t.Fatalf("mix did not exercise every path: evicted %d, counts %v", lastEvicted, counts)
	}
	t.Logf("evicted %d, counts %v", lastEvicted, counts)
}

func statusName(s ipv4FragmentStatus) string {
	return [...]string{"held", "complete", "duplicate", "rejected", "capacity", "closed"}[s]
}

// Process (with eviction), Sweep, Usage and Evicted may run concurrently;
// run under -race.
func TestIPv4ReassemblyConcurrentEviction(t *testing.T) {
	r := reasmReassembler(t, 4, 8, 1<<16)
	start := time.Unix(100, 0)
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				r.Process(reasmIPv4Fragment(17, uint16(g*1000+i), 0, true, 0, nil, []byte("pppppppp")), start.Add(time.Duration(i)*time.Millisecond))
			}
		}(g)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		var last uint64
		for i := 0; i < 500; i++ {
			r.Sweep(start.Add(time.Duration(i) * time.Millisecond))
			if _, e, p := r.Usage(); e > 4 || p > 8 {
				t.Errorf("usage over limits: %d/%d", e, p)
			}
			if ev := r.Evicted(); ev < last {
				t.Errorf("evicted went back: %d < %d", ev, last)
			} else {
				last = ev
			}
		}
	}()
	wg.Wait()
	if r.Evicted() == 0 {
		t.Fatal("no eviction under concurrent load")
	}
}
