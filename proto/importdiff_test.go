package proto

import (
	"net/netip"
	"testing"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDiffRulesAddedChangedDeletedUnchanged(t *testing.T) {
	current := []Rule{
		{ID: "r_keep", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 1, Hi: 1}, Target: "h:1", Enabled: true},
		{ID: "r_change", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 443, Hi: 443}, Target: "h:443", Enabled: true},
		{ID: "r_gone", Agent: "home", Proto: UDP, ListenPort: PortRange{Lo: 27015, Hi: 27015}, Target: "h:27015", Enabled: true},
	}
	desired := []Rule{
		{ID: "r_keep", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 1, Hi: 1}, Target: "h:1", Enabled: true},
		{ID: "r_change", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 443, Hi: 443}, Target: "h2:443", Enabled: true},
		{ID: "r_new", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 25565, Hi: 25565}, Target: "h:25565", Enabled: true},
	}

	diff := DiffRules(current, desired)
	if len(diff) != 4 {
		t.Fatalf("len(diff) = %d, want 4 (kept, changed, new, gone): %+v", len(diff), diff)
	}

	byID := map[string]RuleChange{}
	for _, c := range diff {
		byID[c.Rule.ID] = c
	}

	if c := byID["r_keep"]; c.Kind != ChangeUnchanged {
		t.Errorf("r_keep kind = %q, want unchanged", c.Kind)
	}
	if c := byID["r_new"]; c.Kind != ChangeAdded {
		t.Errorf("r_new kind = %q, want added", c.Kind)
	}
	if c := byID["r_gone"]; c.Kind != ChangeDeleted {
		t.Errorf("r_gone kind = %q, want deleted", c.Kind)
	}
	c, ok := byID["r_change"]
	if !ok || c.Kind != ChangeChanged {
		t.Fatalf("r_change kind = %+v, want changed", c)
	}
	if len(c.FieldChanges) != 1 || c.FieldChanges[0].Field != "target" || c.FieldChanges[0].Old != "h:443" || c.FieldChanges[0].New != "h2:443" {
		t.Errorf("r_change field changes = %+v, want a single target change h:443 -> h2:443", c.FieldChanges)
	}

	del := DeletedIDs(diff)
	if len(del) != 1 || del[0] != "r_gone" {
		t.Errorf("DeletedIDs = %v, want [r_gone]", del)
	}
}

// TestDiffRulesFieldChanges は各フィールドの変化が正しいキーと値で出ることを確かめる
// (仕様 10.1 節 の確認ページが列ごとの文にするための入力)。
func TestDiffRulesFieldChanges(t *testing.T) {
	base := Rule{
		ID: "r_a", Agent: "home", Group: "g1", Note: "n1", Proto: UDP,
		ListenPort: PortRange{Lo: 2456, Hi: 2457}, Target: "h:2456", VPSMode: ModeKernel,
		Enabled: true,
	}
	tenPerMin := Rate{Count: 10, Unit: PerMinute}

	cases := []struct {
		name      string
		mutate    func(r Rule) Rule
		wantField string
		wantOld   string
		wantNew   string
	}{
		{"agent", func(r Rule) Rule { r.Agent = "office"; return r }, "agent", "home", "office"},
		{"group", func(r Rule) Rule { r.Group = "g2"; return r }, "group", "g1", "g2"},
		{"note", func(r Rule) Rule { r.Note = "n2"; return r }, "note", "n1", "n2"},
		{"target", func(r Rule) Rule { r.Target = "h2:2456"; return r }, "target", "h:2456-2457", "h2:2456-2457"},
		{"vps_mode", func(r Rule) Rule { r.Proto = TCP; r.VPSMode = ModeProxy; return r }, "vps_mode", "kernel", "proxy"},
		{"proxy_protocol", func(r Rule) Rule { r.Proto = TCP; r.VPSMode = ModeProxy; r.ProxyProtocol = true; return r }, "proxy_protocol", "false", "true"},
		{"source_deny", func(r Rule) Rule { r.SourceDeny = []netip.Prefix{mustPrefix(t, "203.0.113.0/24")}; return r }, "source_deny", "", "203.0.113.0/24"},
		{"source_allow", func(r Rule) Rule { r.SourceAllow = []netip.Prefix{mustPrefix(t, "198.51.100.0/24")}; return r }, "source_allow", "", "198.51.100.0/24"},
		{"new_flow_rate", func(r Rule) Rule { r.NewFlowRate = &tenPerMin; return r }, "new_flow_rate", "", "10/minute"},
		{"enabled", func(r Rule) Rule { r.Enabled = false; return r }, "enabled", "true", "false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			next := tc.mutate(base)
			diff := DiffRules([]Rule{base}, []Rule{next})
			if len(diff) != 1 || diff[0].Kind != ChangeChanged {
				t.Fatalf("diff = %+v, want a single changed row", diff)
			}
			var found *FieldChange
			for i := range diff[0].FieldChanges {
				if diff[0].FieldChanges[i].Field == tc.wantField {
					found = &diff[0].FieldChanges[i]
				}
			}
			if found == nil {
				t.Fatalf("no field change for %q in %+v", tc.wantField, diff[0].FieldChanges)
			}
			if found.Old != tc.wantOld || found.New != tc.wantNew {
				t.Errorf("%s change = %q -> %q, want %q -> %q", tc.wantField, found.Old, found.New, tc.wantOld, tc.wantNew)
			}
		})
	}
}

func TestDiffRulesOrderDesiredThenDeleted(t *testing.T) {
	current := []Rule{
		{ID: "r_1", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 1, Hi: 1}, Target: "h:1", Enabled: true},
		{ID: "r_2", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 2, Hi: 2}, Target: "h:2", Enabled: true},
	}
	desired := []Rule{
		{ID: "r_3", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 3, Hi: 3}, Target: "h:3", Enabled: true},
	}
	diff := DiffRules(current, desired)
	if len(diff) != 3 {
		t.Fatalf("len(diff) = %d, want 3", len(diff))
	}
	if diff[0].Rule.ID != "r_3" || diff[0].Kind != ChangeAdded {
		t.Errorf("diff[0] = %+v, want added r_3 first (desired order)", diff[0])
	}
	if diff[1].Rule.ID != "r_1" || diff[2].Rule.ID != "r_2" {
		t.Errorf("deleted rows must follow in current order: %+v", diff[1:])
	}
}

func TestRulesDigestStableAcrossOrderAndChangesOnContent(t *testing.T) {
	a := Rule{ID: "r_a", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 1, Hi: 1}, Target: "h:1", Enabled: true}
	b := Rule{ID: "r_b", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 2, Hi: 2}, Target: "h:2", Enabled: true}

	d1 := RulesDigest([]Rule{a, b})
	d2 := RulesDigest([]Rule{b, a})
	if d1 != d2 {
		t.Errorf("digest depends on order: %q vs %q, want equal", d1, d2)
	}

	bChanged := b
	bChanged.Note = "changed"
	d3 := RulesDigest([]Rule{a, bChanged})
	if d3 == d1 {
		t.Error("digest did not change after a rule's content changed")
	}

	if RulesDigest(nil) != RulesDigest([]Rule{}) {
		t.Error("digest of nil and empty slice must match")
	}
}

// TestDiffRulesSourceSetReplaceSameCount は、拒否リストの CIDR を同じ件数のまま別のものに
// 差し替えても changed になり、Old/New に実際の CIDR(件数でなく)が入ることを確かめる
// (仕様 10.1 節の確認ページが内容を示すための入力)。件数だけを Old/New にしていた頃は、
// 件数が同じままなので add() の等値検査で FieldChange そのものが落ちていた。
func TestDiffRulesSourceSetReplaceSameCount(t *testing.T) {
	base := Rule{
		ID: "r_a", Agent: "home", Proto: TCP, ListenPort: PortRange{Lo: 443, Hi: 443}, Target: "h:443", Enabled: true,
		SourceDeny: []netip.Prefix{mustPrefix(t, "203.0.113.0/24")},
	}
	next := base
	next.SourceDeny = []netip.Prefix{mustPrefix(t, "198.51.100.0/24")}

	diff := DiffRules([]Rule{base}, []Rule{next})
	if len(diff) != 1 || diff[0].Kind != ChangeChanged {
		t.Fatalf("diff = %+v, want a single changed row even though the CIDR count is unchanged", diff)
	}
	var found *FieldChange
	for i := range diff[0].FieldChanges {
		if diff[0].FieldChanges[i].Field == "source_deny" {
			found = &diff[0].FieldChanges[i]
		}
	}
	if found == nil {
		t.Fatalf("no source_deny field change for a same-count CIDR replacement: %+v", diff[0].FieldChanges)
	}
	if found.Old != "203.0.113.0/24" || found.New != "198.51.100.0/24" {
		t.Errorf("source_deny change = %q -> %q, want the actual CIDRs, not counts", found.Old, found.New)
	}
}
