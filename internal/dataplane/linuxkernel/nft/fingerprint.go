package nft

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Fingerprint reads table inet wgft back from the kernel and returns a digest of what wgft wrote
// into it (design.md 7a.3 節: 実際の状態への収束). present is false when the table does not exist.
//
// The digest covers, per chain (by name): its type, hook and priority, and per rule its handle,
// its comment and its expressions; plus the elements of every set wgft fills itself (deny_N,
// allow_N). It leaves out what changes while forwarding without the declaration changing: counter
// values (set to zero before hashing) and the elements of sets packets add to (meters and
// flows_udp/flows_tcp, flags dynamic). A rule deleted, added or replaced, a chain or set removed,
// or the table recreated with other contents therefore changes the digest; traffic does not.
//
// It is a handful of netlink dumps (tables, chains, one per chain for its rules, sets, one per
// static set for its elements), cheap enough to run after every Commit and on every Observe.
func Fingerprint() (fp string, present bool, err error) {
	c, err := nftables.New()
	if err != nil {
		return "", false, fmt.Errorf("cannot connect to nftables: %w", err)
	}
	tables, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return "", false, fmt.Errorf("listing tables: %w", err)
	}
	for _, t := range tables {
		if t.Name == TableName {
			present = true
		}
	}
	if !present {
		return "", false, nil
	}
	t := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
	all, err := c.ListChainsOfTableFamily(nftables.TableFamilyINet)
	if err != nil {
		return "", true, fmt.Errorf("listing chains: %w", err)
	}
	var chains []chainDump
	for _, ch := range all {
		if ch.Table == nil || ch.Table.Name != TableName {
			continue
		}
		rules, err := c.GetRules(t, &nftables.Chain{Name: ch.Name, Table: t})
		if err != nil {
			return "", true, fmt.Errorf("listing rules of chain %s: %w", ch.Name, err)
		}
		chains = append(chains, chainDump{chain: ch, rules: rules})
	}
	sets, err := c.GetSets(t)
	if err != nil {
		return "", true, fmt.Errorf("listing sets: %w", err)
	}
	var static []setDump
	for _, s := range sets {
		if s.Anonymous || s.Dynamic {
			continue
		}
		elems, err := c.GetSetElements(s)
		if err != nil {
			return "", true, fmt.Errorf("listing elements of set %s: %w", s.Name, err)
		}
		static = append(static, setDump{set: s, elems: elems})
	}
	return fingerprintOf(chains, static), true, nil
}

type chainDump struct {
	chain *nftables.Chain
	rules []*nftables.Rule
}

type setDump struct {
	set   *nftables.Set
	elems []nftables.SetElement
}

// fingerprintOf is Fingerprint's digest of what it read, split out for the unit tests.
func fingerprintOf(chains []chainDump, sets []setDump) string {
	h := sha256.New()
	sort.Slice(chains, func(i, j int) bool { return chains[i].chain.Name < chains[j].chain.Name })
	for _, cd := range chains {
		ch := cd.chain
		fmt.Fprintf(h, "chain %q type %q", ch.Name, ch.Type)
		if ch.Hooknum != nil {
			fmt.Fprintf(h, " hook %d", *ch.Hooknum)
		}
		if ch.Priority != nil {
			fmt.Fprintf(h, " prio %d", *ch.Priority)
		}
		if ch.Policy != nil {
			fmt.Fprintf(h, " policy %d", *ch.Policy)
		}
		h.Write([]byte{'\n'})
		for _, r := range cd.rules {
			fmt.Fprintf(h, "rule %d %x\n", r.Handle, r.UserData)
			for _, e := range r.Exprs {
				writeExpr(h, e)
			}
		}
	}
	sort.Slice(sets, func(i, j int) bool { return sets[i].set.Name < sets[j].set.Name })
	for _, sd := range sets {
		fmt.Fprintf(h, "set %q\n", sd.set.Name)
		keys := make([][]byte, 0, len(sd.elems))
		for _, e := range sd.elems {
			k := append(append([]byte(nil), e.Key...), e.KeyEnd...)
			if e.IntervalEnd {
				k = append(k, 1)
			}
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
		for _, k := range keys {
			fmt.Fprintf(h, "elem %x\n", k)
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

// writeExpr hashes one expression by its type and its netlink encoding, with a counter's values
// set to zero: they grow with traffic, which is not a change of the table.
func writeExpr(h hash.Hash, e expr.Any) {
	if _, ok := e.(*expr.Counter); ok {
		e = &expr.Counter{}
	}
	fmt.Fprintf(h, "%T ", e)
	// 符号化できない式は型だけで数える。同じテーブルを 2 回読めば同じ結果になるので、比較には足りる
	if b, err := expr.Marshal(byte(unix.NFPROTO_INET), e); err == nil {
		fmt.Fprintf(h, "%x", b)
	}
	h.Write([]byte{'\n'})
}
