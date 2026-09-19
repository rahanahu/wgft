package proto

import (
	"encoding/json"
	"testing"
)

func TestSelectProtocolVersion(t *testing.T) {
	tests := []struct {
		name        string
		local       ProtocolRange
		remote      ProtocolRange
		wantVersion int
		wantOK      bool
	}{
		{"identical single-version ranges", ProtocolRange{1, 1}, ProtocolRange{1, 1}, 1, true},
		{"remote ahead, overlap at server max", ProtocolRange{1, 2}, ProtocolRange{2, 3}, 2, true},
		{"remote ahead, overlap at agent max", ProtocolRange{2, 3}, ProtocolRange{2, 3}, 3, true},
		{"local wider than remote", ProtocolRange{1, 5}, ProtocolRange{3, 3}, 3, true},
		{"remote wider than local", ProtocolRange{3, 3}, ProtocolRange{1, 5}, 3, true},
		{"no overlap, remote strictly ahead", ProtocolRange{1, 1}, ProtocolRange{2, 3}, 0, false},
		{"no overlap, remote strictly behind", ProtocolRange{5, 6}, ProtocolRange{1, 2}, 0, false},
		{"malformed remote range (min > max) treated as no overlap", ProtocolRange{1, 1}, ProtocolRange{5, 2}, 0, false},
		// An invalid range must never be selected from, even when a naive interval
		// intersection would otherwise pick a version out of it (regression: {Min:0,Max:1}
		// intersected with {1,1} used to yield 1, silently accepting version 0 as in-range).
		{"invalid local range (min 0) never yields a version", ProtocolRange{0, 1}, ProtocolRange{1, 1}, 0, false},
		{"invalid remote range (min 0) never yields a version", ProtocolRange{1, 1}, ProtocolRange{0, 1}, 0, false},
		{"invalid local range (min > max) never yields a version", ProtocolRange{2, 1}, ProtocolRange{1, 2}, 0, false},
		{"both ranges invalid", ProtocolRange{0, 0}, ProtocolRange{-1, 0}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotVersion, gotOK := SelectProtocolVersion(tt.local, tt.remote)
			if gotVersion != tt.wantVersion || gotOK != tt.wantOK {
				t.Errorf("SelectProtocolVersion(%+v, %+v) = (%d, %v), want (%d, %v)",
					tt.local, tt.remote, gotVersion, gotOK, tt.wantVersion, tt.wantOK)
			}
		})
	}
}

func TestProtocolRangeValid(t *testing.T) {
	tests := []struct {
		name string
		r    ProtocolRange
		want bool
	}{
		{"single version at the floor", ProtocolRange{1, 1}, true},
		{"wider valid range", ProtocolRange{1, 5}, true},
		{"valid range not starting at 1", ProtocolRange{3, 5}, true},
		{"min below 1 (zero)", ProtocolRange{0, 1}, false},
		{"min below 1 (negative)", ProtocolRange{-1, 1}, false},
		{"min greater than max", ProtocolRange{2, 1}, false},
		{"both zero", ProtocolRange{0, 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.r.Valid(); got != tt.want {
				t.Errorf("%+v.Valid() = %v, want %v", tt.r, got, tt.want)
			}
		})
	}
}

// TestMessageProtocolFieldsAbsentVsEmpty confirms that a MsgPublicKey without
// protocol_min/protocol_max/capabilities (a legacy v0 agent) round-trips as nil pointers,
// while an explicit empty capabilities array round-trips as a non-nil pointer to an empty
// slice. Losing this distinction would make a v1 agent that advertises no capabilities
// indistinguishable from a legacy v0 agent (spec 7a.6).
func TestMessageProtocolFieldsAbsentVsEmpty(t *testing.T) {
	legacy := []byte(`{"type":"pubkey","public_key":"k"}`)
	var m Message
	if err := json.Unmarshal(legacy, &m); err != nil {
		t.Fatal(err)
	}
	if m.ProtocolMin != nil || m.ProtocolMax != nil || m.Capabilities != nil {
		t.Errorf("legacy message: want all three fields nil, got min=%v max=%v caps=%v", m.ProtocolMin, m.ProtocolMax, m.Capabilities)
	}

	withEmptyCaps := []byte(`{"type":"pubkey","public_key":"k","protocol_min":1,"protocol_max":1,"capabilities":[]}`)
	var m2 Message
	if err := json.Unmarshal(withEmptyCaps, &m2); err != nil {
		t.Fatal(err)
	}
	if m2.ProtocolMin == nil || *m2.ProtocolMin != 1 || m2.ProtocolMax == nil || *m2.ProtocolMax != 1 {
		t.Fatalf("versioned message: want min=max=1, got min=%v max=%v", m2.ProtocolMin, m2.ProtocolMax)
	}
	if m2.Capabilities == nil {
		t.Fatal("versioned message with an explicit empty array: want a non-nil pointer, got nil (indistinguishable from absence)")
	}
	if len(*m2.Capabilities) != 0 {
		t.Errorf("want an empty slice, got %v", *m2.Capabilities)
	}

	// round trip: marshaling a Message built with an explicit empty slice must produce
	// "capabilities":[] on the wire, not omit the key.
	empty := []string{}
	out := Message{Type: MsgPublicKey, PublicKey: "k", ProtocolMin: intPtr(1), ProtocolMax: intPtr(1), Capabilities: &empty}
	b, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]json.RawMessage
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if raw, ok := back["capabilities"]; !ok {
		t.Errorf("marshal: want a capabilities key for an explicit empty slice, got none (%s)", b)
	} else if string(raw) != "[]" {
		t.Errorf("marshal: want capabilities=[], got %s", raw)
	}

	// a nil Capabilities pointer must not appear on the wire at all.
	noCaps := Message{Type: MsgPublicKey, PublicKey: "k"}
	b2, err := json.Marshal(noCaps)
	if err != nil {
		t.Fatal(err)
	}
	var back2 map[string]json.RawMessage
	if err := json.Unmarshal(b2, &back2); err != nil {
		t.Fatal(err)
	}
	if _, ok := back2["capabilities"]; ok {
		t.Errorf("marshal: want no capabilities key when nil, got %s", b2)
	}
	if _, ok := back2["protocol_min"]; ok {
		t.Errorf("marshal: want no protocol_min key when nil, got %s", b2)
	}
}

// TestStateProtocolFieldsAbsentVsEmpty is the State-side (server -> agent) equivalent of
// TestMessageProtocolFieldsAbsentVsEmpty: a legacy state (no server_protocol_version) must
// round-trip as nil, and an explicit empty server_capabilities must round-trip as non-nil.
func TestStateProtocolFieldsAbsentVsEmpty(t *testing.T) {
	legacy := []byte(`{"generation":1,"wg":{},"rules":[]}`)
	var st State
	if err := json.Unmarshal(legacy, &st); err != nil {
		t.Fatal(err)
	}
	if st.ServerProtocolVersion != nil || st.ServerCapabilities != nil {
		t.Errorf("legacy state: want both fields nil, got version=%v caps=%v", st.ServerProtocolVersion, st.ServerCapabilities)
	}

	empty := []string{}
	versioned := State{Generation: 1, ServerProtocolVersion: intPtr(1), ServerCapabilities: &empty}
	b, err := json.Marshal(versioned)
	if err != nil {
		t.Fatal(err)
	}
	var back State
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.ServerProtocolVersion == nil || *back.ServerProtocolVersion != 1 {
		t.Fatalf("want server_protocol_version=1, got %v", back.ServerProtocolVersion)
	}
	if back.ServerCapabilities == nil || len(*back.ServerCapabilities) != 0 {
		t.Fatalf("want a non-nil empty server_capabilities, got %v", back.ServerCapabilities)
	}
}

func intPtr(i int) *int { return &i }
