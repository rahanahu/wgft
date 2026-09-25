package allowtargets

import (
	"net/netip"
	"reflect"
	"testing"
)

// FuzzParse feeds arbitrary strings as WGFT_AGENT_ALLOW_TARGETS, the setting this package's own
// doc comment (allowtargets.go) describes as narrowing where a VPS-controlled attacker who has
// rewritten a rule's target can send the agent. This setting is local to the agent's own host, not
// attacker-controlled, but
// it is still an operator-supplied parser worth hardening: a crash here at startup is a denial of
// service against the agent, and a parse that is too permissive would silently widen exactly the
// list this package exists to narrow.
//
// The properties checked: Parse never panics; on success, the normalized String() reparses to an
// equal List (Parse/String round-trip, so the startup log's normalized echo means what it says);
// and Allows never panics for arbitrary probe addresses, with the reparsed list agreeing with the
// original for every entry boundary point derived from the parse itself -- the closest a fuzz
// harness can get to "does not accept targets outside the configured list" without hand-picking
// probes unrelated to the input.
func FuzzParse(f *testing.F) {
	f.Add("192.168.1.0/24")
	f.Add("192.168.1.20:25565")
	f.Add("192.168.1.0/24:2456-2458")
	f.Add(" 192.168.1.20:80 , 10.0.0.0/8 ")
	f.Add("2001:db8::1")
	f.Add("[2001:db8::/32]:8080")
	f.Add("[2001:db8::1]:8080-8081")
	f.Add("192.168.1.20:0")     // port 0 is invalid
	f.Add("192.168.1.20:65536") // port out of uint16 range
	f.Add("192.168.1.20:80-70") // reversed range
	f.Add("::ffff:192.168.1.1") // IPv4-mapped IPv6
	f.Add("192.168.1.20%eth0")  // zone on IPv4 (nonsensical but should not panic)
	f.Add("[::1")               // unterminated bracket
	f.Add("[::1]extra")         // trailing text after bracket
	f.Add(":::")
	f.Add(",,,")
	f.Add("")
	f.Add("   ")
	f.Add("192.168.1.0/24:1-2-3")

	f.Fuzz(func(t *testing.T, s string) {
		l, err := Parse(s)
		if err != nil {
			return
		}
		// A round-trip probe: for every entry, its own low port (or 0 if port-less) and its
		// prefix address must be judged the same way before and after a String/Parse round-trip.
		str := l.String()
		l2, err2 := Parse(str)
		if l == nil {
			if str != "" {
				t.Fatalf("Parse(%q) = nil (unrestricted), but String() = %q, not empty", s, str)
			}
			return
		}
		if err2 != nil {
			t.Fatalf("Parse(%q) = %v, but Parse(String()) = Parse(%q) failed: %v", s, l, str, err2)
		}
		if !reflect.DeepEqual(l, l2) {
			t.Fatalf("Parse/String round-trip changed the list: Parse(%q) = %+v, String() = %q, Parse(String()) = %+v", s, l, str, l2)
		}
		for _, e := range l.entries {
			addr := e.prefix.Addr()
			for _, port := range []uint16{0, e.lo, e.hi, 1, 65535} {
				ap := netip.AddrPortFrom(addr, port)
				if got, want := l2.Allows(ap), l.Allows(ap); got != want {
					t.Fatalf("Allows(%v) after round-trip: Parse(%q)=%v -> %v, Parse(String())=%v -> %v", ap, s, l, want, l2, got)
				}
			}
		}
	})
}
