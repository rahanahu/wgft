package policy

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// FuzzNormalizePrefixes feeds arbitrary bytes, decoded into an IPv4 prefix list, to
// NormalizePrefixes: the step Build (policy.go) runs on every rule's source_allow/source_deny
// before handing the Admission Policy IR to the nftables compiler or the Go evaluator (design.md
// 7a.9 節 "CIDR の正規化"). Its own doc comment states the safety property in prose -- "merging
// never changes which sources match" -- and this fuzzer checks that property directly instead of
// only checking for panics, because a normalizer that silently narrows or widens the effective
// source list would be a security bug in either direction: too wide re-admits a denied or
// unlisted source, too narrow drops a source the rule was meant to allow or deny.
//
// Each 5-byte chunk of the input decodes to one prefix: 4 bytes of address, 1 byte of prefix
// length (mod 33, so it is always in 0..32). The probe addresses checked afterward are every
// decoded prefix's own network address, its immediate neighbors, and the input-derived corners
// 0.0.0.0 and 255.255.255.255 -- the boundary points a merge bug is most likely to get wrong.
func FuzzNormalizePrefixes(f *testing.F) {
	f.Add([]byte{10, 0, 0, 0, 8, 10, 0, 0, 0, 8})         // two identical prefixes
	f.Add([]byte{10, 0, 0, 0, 24, 10, 0, 1, 0, 24})       // adjacent, mergeable
	f.Add([]byte{10, 0, 0, 0, 25, 10, 0, 0, 128, 25})     // adjacent halves of /24
	f.Add([]byte{0, 0, 0, 0, 0})                          // whole IPv4 space, bits=0
	f.Add([]byte{255, 255, 255, 255, 32})                 // single host at the top
	f.Add([]byte{10, 0, 0, 5, 32, 10, 0, 0, 0, 24})       // host inside a covering block
	f.Add([]byte{0, 0, 0, 0, 33, 255, 255, 255, 255, 33}) // bits=33, wraps mod 33 to 0
	f.Add([]byte{1, 2, 3, 4})                             // short trailing chunk, ignored
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		var prefixes []netip.Prefix
		for i := 0; i+5 <= len(data); i += 5 {
			var b [4]byte
			copy(b[:], data[i:i+4])
			bits := int(data[i+4]) % 33
			prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(b), bits).Masked())
		}
		if len(prefixes) == 0 {
			return
		}

		out := NormalizePrefixes(prefixes)

		// Build the probe set: every decoded prefix's network address and its two neighbors
		// (skipping wraparound at the address-space edges), plus the two corners.
		probes := map[netip.Addr]bool{
			netip.AddrFrom4([4]byte{0, 0, 0, 0}):         true,
			netip.AddrFrom4([4]byte{255, 255, 255, 255}): true,
		}
		for _, p := range prefixes {
			a := p.Addr()
			probes[a] = true
			n := binary.BigEndian.Uint32(a.AsSlice())
			if n > 0 {
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], n-1)
				probes[netip.AddrFrom4(b)] = true
			}
			if n < 0xffffffff {
				var b [4]byte
				binary.BigEndian.PutUint32(b[:], n+1)
				probes[netip.AddrFrom4(b)] = true
			}
		}

		for addr := range probes {
			want := containsAny(prefixes, addr)
			got := containsAny(out, addr)
			if got != want {
				t.Fatalf("NormalizePrefixes changed membership for %v: original %v -> %v, normalized %v -> %v", addr, prefixes, want, out, got)
			}
		}

		// NormalizePrefixes must be idempotent: normalizing an already-normalized list must not
		// change it further (a merge left un-merged, or one that could split, would show up here).
		out2 := NormalizePrefixes(out)
		if len(out) != len(out2) {
			t.Fatalf("NormalizePrefixes is not idempotent: %v -> %v -> %v", prefixes, out, out2)
		}
		for addr := range probes {
			if containsAny(out, addr) != containsAny(out2, addr) {
				t.Fatalf("NormalizePrefixes is not idempotent for %v: %v -> %v -> %v", addr, prefixes, out, out2)
			}
		}
	})
}

func containsAny(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
