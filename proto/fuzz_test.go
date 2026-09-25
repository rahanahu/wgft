package proto

import (
	"encoding/json"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
)

// FuzzRuleJSON feeds arbitrary bytes as the JSON body of a Rule (proto/rule.go), the shape a
// VPS-controlled attacker could try to push through the Web UI import (webui_import.go
// uiImportConfirm unmarshals an uploaded file straight into []proto.Rule) or, upstream, into
// vpsd's own store. The property under test is not "the rule is accepted" -- most fuzzed input
// is rightly rejected -- but that Unmarshal and Validate never panic on adversarial input, and
// that whatever Validate accepts is safe for TargetDisplay to format without panicking either.
func FuzzRuleJSON(f *testing.F) {
	f.Add([]byte(`{"id":"r1","agent":"a1","proto":"tcp","listen_port":"2456","target":"10.0.0.1:2456","vps_mode":"kernel","enabled":true}`))
	f.Add([]byte(`{"id":"r1","agent":"a1","proto":"udp","listen_port":"2456-2460","target":"10.0.0.1:65535","vps_mode":"proxy","proxy_protocol":true,"enabled":true}`))
	f.Add([]byte(`{"listen_port":123}`))            // wrong JSON type for a text-unmarshaler field
	f.Add([]byte(`{"listen_port":"99999-100000"}`)) // out-of-range ports
	f.Add([]byte(`{"source_allow":["::1/128"]}`))   // IPv6, only IPv4 is supported
	f.Add([]byte(`{"target":"[::1]:80"}`))          // IPv6 target
	f.Add([]byte(`{"target":"example.com:99999999999999999999"}`))
	f.Add([]byte(`{"new_flow_rate":"0/second"}`))
	f.Add([]byte(`not json at all`))
	f.Add([]byte(`{`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[]`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var r Rule
		if err := json.Unmarshal(data, &r); err != nil {
			return
		}
		// Validate must never panic, regardless of what made it through JSON unmarshaling.
		err := r.Validate()
		// TargetDisplay must never panic either, valid or not: the Web UI's rules list calls it
		// on every stored row, including rows that predate a later-added Validate check
		// (rule.go's own comment on ValidateUpsert describes exactly this scenario).
		_ = r.TargetDisplay()
		if err != nil {
			return
		}
		// A rule that Validate accepts must round-trip through JSON: re-marshaling and re-parsing
		// it must reproduce the identical JSON, not just agree on a few chosen fields.
		b, merr := json.Marshal(r)
		if merr != nil {
			t.Fatalf("Marshal a Validate-accepted rule: %v", merr)
		}
		var r2 Rule
		if err := json.Unmarshal(b, &r2); err != nil {
			t.Fatalf("Unmarshal a just-Marshaled rule: %v", err)
		}
		b2, merr := json.Marshal(r2)
		if merr != nil {
			t.Fatalf("Marshal the round-tripped rule: %v", merr)
		}
		if string(b) != string(b2) {
			t.Fatalf("Rule JSON round-trip changed the value:\n first  = %s\n second = %s", b, b2)
		}
		if err := r2.Validate(); err != nil {
			t.Fatalf("round-tripped rule fails Validate: %v (original: %+v)", err, r)
		}
	})
}

// FuzzMessageJSON feeds arbitrary bytes as a stream Message (proto/stream.go). This is exactly
// what internal/agent/stream.go's readJSON hands to json.Unmarshal on the agent side (state
// pushed by vpsd, which a compromised VPS controls) and what internal/vpsd/stream/hub.go's
// readJSON hands to it on the server side (heartbeats from an agent). Both directions share this
// one type, so one fuzz target covers both. The property is: never panic, and never let a State
// message's rules produce a panic when the agent walks them for the effective target of every
// port in range, the way internal/agent/dataplane_userspace.go does for every rule it applies (it
// calls internal/dataplane/userspace/relay.DesiredFromRules, which calls EffectiveTarget once per
// port in the rule's listen_port range).
func FuzzMessageJSON(f *testing.F) {
	f.Add([]byte(`{"type":"state","state":{"generation":1,"wg":{"address":"10.200.0.2/24"},"rules":[{"id":"r1","proto":"tcp","listen_port":"2456-2460","target":"127.0.0.1:2456","enabled":true}]}}`))
	f.Add([]byte(`{"type":"heartbeat","heartbeat":{"generation":1,"tunnel":{"state":"ok"},"rules":[{"id":"r1","state":"error","reason":"boom"}]}}`))
	f.Add([]byte(`{"type":"pubkey","public_key":"not-really-base64"}`))
	f.Add([]byte(`{"type":"state","state":{"rules":[{"listen_port":"1-65535","target":"h:65535"}]}}`))
	f.Add([]byte(`{"type":"","protocol_min":-1,"protocol_max":0}`))
	f.Add([]byte(`{"type":"state","state":null}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	f.Fuzz(func(t *testing.T, data []byte) {
		var m Message
		if err := json.Unmarshal(data, &m); err != nil {
			return
		}
		if m.State == nil {
			return
		}
		for _, ar := range m.State.Rules {
			// EffectiveTarget must not panic for any port in [0, 65535], not just the rule's own
			// declared range: an agent applying a maliciously-crafted State walks arbitrary
			// listen ports while wiring up listeners.
			for _, p := range []uint16{0, 1, ar.ListenPort.Lo, ar.ListenPort.Hi, 65535} {
				target, ok := ar.EffectiveTarget(p)
				if !ok {
					continue
				}
				// A target EffectiveTarget claims is usable must actually be host:port shaped,
				// or a downstream net.Dial call gets a value that looks valid but is not.
				host, portStr, err := net.SplitHostPort(target)
				if err != nil {
					t.Fatalf("EffectiveTarget(%d) on rule target %q returned a non host:port value %q: %v", p, ar.Target, target, err)
				}
				if host == "" {
					t.Fatalf("EffectiveTarget(%d) on rule target %q returned an empty host in %q", p, ar.Target, target)
				}
				if n, err := strconv.ParseUint(portStr, 10, 16); err != nil || n == 0 {
					t.Fatalf("EffectiveTarget(%d) on rule target %q returned a bad port %q in %q", p, ar.Target, portStr, target)
				}
			}
		}
	})
}

// FuzzAgentRuleEffectiveTarget drives EffectiveTarget directly with structured, adversarial
// inputs (rather than through JSON), including target strings crafted to look like host:port but
// carry extra colons, brackets or overflowing numbers -- the parser this depends on
// (splitTarget) is meant to reject IPv6 and oversized ports, and this checks that rejection holds
// under fuzzing, not just the handful of cases in proto_test.go's table.
func FuzzAgentRuleEffectiveTarget(f *testing.F) {
	f.Add("10.0.0.1:2456", uint16(2456), uint16(2460), uint16(2458))
	f.Add("host:65535", uint16(1), uint16(1), uint16(1))
	f.Add("[::1]:80", uint16(1), uint16(10), uint16(5))
	f.Add("a:b:c", uint16(1), uint16(1), uint16(1))
	f.Add("", uint16(0), uint16(0), uint16(0))
	f.Add("h:0", uint16(1), uint16(65535), uint16(65535))
	f.Add("h:65530", uint16(1), uint16(65535), uint16(65535)) // port + range width overflow
	f.Add("h:65535", uint16(1), uint16(1), uint16(1))         // exact boundary: eff==65535 must stay ok=true
	f.Add("h:65534", uint16(10), uint16(11), uint16(11))      // exact boundary reached through an offset

	f.Fuzz(func(t *testing.T, target string, a, b, p uint16) {
		lo, hi := a, b
		if lo > hi {
			lo, hi = hi, lo
		}
		ar := AgentRule{Target: target, ListenPort: PortRange{Lo: lo, Hi: hi}}
		out, ok := ar.EffectiveTarget(p)

		// The reverse direction: whenever the port is in range, the target itself parses, and the
		// resulting arithmetic does not overflow 65535, EffectiveTarget must accept it. Without this
		// check, every assertion below only runs when ok is already true, so a mutant that also
		// rejects some in-bounds ports (for example one that rejects the exact boundary eff==65535
		// along with eff>65535) would pass unnoticed.
		_, wantPort, werr := splitTarget(target)
		inRange := lo <= p && p <= hi
		if werr == nil && inRange {
			wantN := uint64(wantPort) + uint64(p-lo)
			if wantN <= 65535 && !ok {
				t.Fatalf("EffectiveTarget(target=%q, listen=%d-%d, p=%d) = ok=false, want true: splitTarget succeeds, p is in range, and the effective port %d is within 1-65535", target, lo, hi, p, wantN)
			}
		}
		if !ok {
			return
		}
		host, portStr, err := net.SplitHostPort(out)
		if err != nil || host == "" {
			t.Fatalf("EffectiveTarget(target=%q, listen=%d-%d, p=%d) = %q, not host:port: %v", target, lo, hi, p, out, err)
		}
		n, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			t.Fatalf("EffectiveTarget(target=%q, listen=%d-%d, p=%d) = %q, port not uint16: %v", target, lo, hi, p, out, err)
		}
		// EffectiveTarget must never silently wrap: the port it returns must equal the target's
		// own port plus the rule-relative offset, not something that overflowed past 65535.
		if werr != nil {
			t.Fatalf("EffectiveTarget(%q) succeeded but splitTarget(%q) now fails: %v", target, target, werr)
		}
		wantN := uint64(wantPort) + uint64(p-lo)
		if wantN > 65535 {
			t.Fatalf("EffectiveTarget(target=%q, listen=%d-%d, p=%d) = %q claims a port that overflows 65535 (wanted arithmetic %d)", target, lo, hi, p, out, wantN)
		}
		if n != wantN {
			t.Fatalf("EffectiveTarget(target=%q, listen=%d-%d, p=%d) = port %d, want %d", target, lo, hi, p, n, wantN)
		}
	})
}

// FuzzPortRangeText checks that PortRange's MarshalText/UnmarshalText (the JSON encoding rules
// use for listen_port, proto/port.go) round-trip: anything ParsePortRange accepts must, once
// re-formatted with String, parse back to the identical value. A break here would mean a rule
// silently changes its listen port range across a save/reload or an export/import cycle.
func FuzzPortRangeText(f *testing.F) {
	f.Add("2456")
	f.Add("2456-2457")
	f.Add("1-65535")
	f.Add("0")
	f.Add("65536")
	f.Add("2457-2456")
	f.Add("")
	f.Add(" 2456 ")
	f.Add("1-2-3")
	f.Add("-1")
	f.Add("+1")
	f.Add("0x10")

	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParsePortRange(s)
		if err != nil {
			return
		}
		if r.Lo == 0 || r.Hi == 0 || r.Lo > r.Hi {
			t.Fatalf("ParsePortRange(%q) = %+v, an invalid range slipped through", s, r)
		}
		s2 := r.String()
		r2, err := ParsePortRange(s2)
		if err != nil {
			t.Fatalf("ParsePortRange(%q) = %+v, but re-parsing its own String() %q failed: %v", s, r, s2, err)
		}
		if r2 != r {
			t.Fatalf("PortRange round-trip: ParsePortRange(%q) = %+v, String() = %q, re-parse = %+v", s, r, s2, r2)
		}
	})
}

// FuzzRateText is the same round-trip property as FuzzPortRangeText, for Rate
// (proto/rate.go, the JSON encoding of new_flow_rate/packet_rate/per_source_rate).
func FuzzRateText(f *testing.F) {
	f.Add("100/second")
	f.Add("0/second")
	f.Add("1/century")
	f.Add("/second")
	f.Add("100/")
	f.Add("18446744073709551616/second") // one past uint64 max
	f.Add(" 100 / second ")
	f.Add("100/second/extra")

	f.Fuzz(func(t *testing.T, s string) {
		r, err := ParseRate(s)
		if err != nil {
			return
		}
		if r.Count == 0 {
			t.Fatalf("ParseRate(%q) = %+v, a zero count slipped through", s, r)
		}
		s2 := r.String()
		r2, err := ParseRate(s2)
		if err != nil {
			t.Fatalf("ParseRate(%q) = %+v, but re-parsing its own String() %q failed: %v", s, r, s2, err)
		}
		if r2 != r {
			t.Fatalf("Rate round-trip: ParseRate(%q) = %+v, String() = %q, re-parse = %+v", s, r, s2, r2)
		}
	})
}

// FuzzParseSource checks ParseSource (proto/source.go), shared by the CLI and the Web UI for
// source_allow/source_deny entries: anything it accepts must, once re-formatted through
// netip.Prefix's own String, parse back to the identical masked prefix.
func FuzzParseSource(f *testing.F) {
	f.Add("10.0.0.0/8")
	f.Add("10.0.0.1")
	f.Add("::1")
	f.Add("::1/64")
	f.Add("10.0.0.1/33")
	f.Add("not-an-ip")
	f.Add("")
	f.Add("10.0.0.1%eth0")
	f.Add("fe80::1%eth0/64")
	f.Add("  10.0.0.1  ")

	f.Fuzz(func(t *testing.T, s string) {
		p, err := ParseSource(s)
		if err != nil {
			return
		}
		if !p.IsValid() {
			t.Fatalf("ParseSource(%q) = %v, ok but not IsValid", s, p)
		}
		s2 := p.String()
		p2, err := ParseSource(s2)
		if err != nil {
			t.Fatalf("ParseSource(%q) = %v, but re-parsing its own String() %q failed: %v", s, p, s2, err)
		}
		if p2 != p {
			t.Fatalf("ParseSource round-trip: ParseSource(%q) = %v, String() = %q, re-parse = %v", s, p, s2, p2)
		}
	})
}

// FuzzParseSourceLines checks the Web UI's multi-line source list parser (proto/source.go), which
// takes free-form textarea input. The property is: it must not panic on any input, and its output
// must match, value for value and in the same order, what parsing each non-blank line on its own
// with ParseSource produces -- either every such line parses that way, or the whole call fails on
// the first bad line, as the comment on ParseSourceLines promises.
func FuzzParseSourceLines(f *testing.F) {
	f.Add("10.0.0.0/8\n192.168.0.0/16\n")
	f.Add("\n\n  \n10.0.0.1\n")
	f.Add("10.0.0.1\r\nnot-an-ip\r\n")
	f.Add("")
	f.Add("10.0.0.1\x00")

	f.Fuzz(func(t *testing.T, text string) {
		out, err := ParseSourceLines(text)
		if err != nil {
			if out != nil {
				t.Fatalf("ParseSourceLines(%q) returned an error but also a non-nil slice %v", text, out)
			}
			return
		}
		var want []netip.Prefix
		for _, line := range strings.Split(text, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			p, err := ParseSource(line)
			if err != nil {
				t.Fatalf("ParseSourceLines(%q) succeeded but its own line %q fails ParseSource: %v", text, line, err)
			}
			want = append(want, p)
		}
		if len(out) != len(want) {
			t.Fatalf("ParseSourceLines(%q) = %d entries, want %d non-blank lines", text, len(out), len(want))
		}
		for i := range out {
			if out[i] != want[i] {
				t.Fatalf("ParseSourceLines(%q)[%d] = %v, want %v (order or value changed)", text, i, out[i], want[i])
			}
		}
	})
}
