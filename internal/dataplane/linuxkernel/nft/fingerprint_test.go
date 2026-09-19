package nft

import (
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/google/nftables/userdata"
)

// testDump is a small table as Fingerprint reads it: one chain with a deny row (with a counter)
// and a DNAT row, and one static set.
func testDump(packets uint64, denyHandle uint64, denyElem byte) ([]chainDump, []setDump) {
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	ch := &nftables.Chain{Name: "filter_pre", Table: t, Type: nftables.ChainTypeFilter,
		Hooknum: nftables.ChainHookPrerouting, Priority: nftables.ChainPriorityRef(-150)}
	rules := []*nftables.Rule{
		{Handle: denyHandle, UserData: userdata.AppendString(nil, userdata.TypeComment, Comment("r_a", "deny")),
			Exprs: []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: "deny_1"}, &expr.Counter{Packets: packets, Bytes: packets * 60},
				&expr.Verdict{Kind: expr.VerdictDrop}}},
		{Handle: denyHandle + 1, Exprs: []expr.Any{&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{6}}}},
	}
	set := &nftables.Set{Table: t, Name: "deny_1", Interval: true}
	elems := []nftables.SetElement{{Key: []byte{203, 0, 113, denyElem}}, {Key: []byte{203, 0, 114, 0}, IntervalEnd: true}}
	return []chainDump{{chain: ch, rules: rules}}, []setDump{{set: set, elems: elems}}
}

// Traffic (counter values) does not change the fingerprint; a rule replaced (a new handle) or a
// static set edited does (design.md 7a.3 節: 実際の状態への収束).
func TestFingerprintOf(t *testing.T) {
	base := fingerprintOf(testDump(0, 4, 0))
	if got := fingerprintOf(testDump(12345, 4, 0)); got != base {
		t.Error("counter values changed the fingerprint")
	}
	if got := fingerprintOf(testDump(0, 9, 0)); got == base {
		t.Error("a rule with another handle kept the fingerprint")
	}
	if got := fingerprintOf(testDump(0, 4, 128)); got == base {
		t.Error("an edited deny set kept the fingerprint")
	}
	chains, sets := testDump(0, 4, 0)
	chains[0].rules = chains[0].rules[:1]
	if got := fingerprintOf(chains, sets); got == base {
		t.Error("a deleted rule kept the fingerprint")
	}
}
