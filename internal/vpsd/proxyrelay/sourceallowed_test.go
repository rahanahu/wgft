package proxyrelay

import (
	"net/netip"
	"testing"
)

// TestSourceAllowed pins today's behavior of sourceAllowed before design.md 7a.9 節's Phase 5
// migration step 1 replaces its deny/allow computation with policy.RulePolicy.SourceAllowed
// (design.md 7a.8 節「Phase 5 の移行の手順」1). These cases call the real sourceAllowed function
// directly (not a transcription of its logic), so re-running this same, unmodified test after the
// replacement is what shows the two implementations agree. The IPv4-mapped cases pin the same
// quirk locked down in internal/dataplane/linuxkernel/conntrack's TestSourceAllowed: bare
// netip.Prefix.Contains does not unmap an IPv4-in-IPv6 address before comparing it against an IPv4
// prefix, so it never matches one, on either side of the replacement.
func TestSourceAllowed(t *testing.T) {
	deny := []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	allow := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	src := func(s string) netip.Addr { return netip.MustParseAddr(s) }

	tests := []struct {
		name string
		src  netip.Addr
		r    Rule
		want bool
	}{
		{"no deny, no allow: everything admitted", src("192.0.2.1"), Rule{}, true},
		{"denied source is rejected", src("203.0.113.9"), Rule{SourceDeny: deny}, false},
		{"non-denied source with empty allow is admitted", src("192.0.2.1"), Rule{SourceDeny: deny}, true},
		{"allowed source is admitted", src("198.51.100.9"), Rule{SourceAllow: allow}, true},
		{"source outside a non-empty allow is rejected", src("192.0.2.1"), Rule{SourceAllow: allow}, false},
		{"deny wins when a source is in both deny and allow",
			src("198.51.100.9"), Rule{SourceDeny: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}, SourceAllow: allow}, false},
		{"IPv4-mapped source is not caught by an IPv4 deny prefix (Contains does not unmap)",
			netip.MustParseAddr("::ffff:203.0.113.9"), Rule{SourceDeny: deny}, true},
		{"IPv4-mapped source does not match an IPv4 allow prefix (Contains does not unmap)",
			netip.MustParseAddr("::ffff:198.51.100.9"), Rule{SourceAllow: allow}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sourceAllowed(tt.src, tt.r); got != tt.want {
				t.Errorf("sourceAllowed(%v, %+v) = %v, want %v", tt.src, tt.r, got, tt.want)
			}
		})
	}
}
