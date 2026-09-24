//go:build linux

package nft

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/google/nftables"
)

// 差し替えの後の set の検査(設計文書 6.1 節)。netlink の属性の長さがあふれると、カーネルは要素の
// 欠けた set を誤りを返さずに受け入れる(batch.go の elemsPerMessage)。要素を分けて送る今の組み立て
// ではあふれないが、同じ種類の取りこぼしが別の経路で起きても黙って公開しないように、wgft が要素を
// 書く set(deny_N、allow_N)を差し替えの直後に読み直し、送った要素と比べる。食い違えば、差し替えは
// 失敗として返り、backend 全体の失敗になる。読み直した内容を基準(Fingerprint)にはしない。
// agent のテーブル(StageAgent)は set を記録しないので、読み直さない。

// sentSets は emitter を包んで、要素を wgft が書く set(flags interval)に送った要素を set の名前ごとに
// 残す。送る内容は変えない。
type sentSets struct {
	to    emitter
	elems map[string][]nftables.SetElement
}

var _ emitter = (*sentSets)(nil)

func (s *sentSets) AddTable(t *nftables.Table) *nftables.Table { return s.to.AddTable(t) }
func (s *sentSets) DelTable(t *nftables.Table)                 { s.to.DelTable(t) }
func (s *sentSets) AddChain(c *nftables.Chain) *nftables.Chain { return s.to.AddChain(c) }
func (s *sentSets) AddRule(r *nftables.Rule) *nftables.Rule    { return s.to.AddRule(r) }

func (s *sentSets) AddSet(set *nftables.Set, els []nftables.SetElement) error {
	if set.Interval {
		s.elems[set.Name] = append(s.elems[set.Name], els...)
	}
	return s.to.AddSet(set, els)
}

func (s *sentSets) SetAddElements(set *nftables.Set, els []nftables.SetElement) error {
	if set.Interval {
		s.elems[set.Name] = append(s.elems[set.Name], els...)
	}
	return s.to.SetAddElements(set, els)
}

// verify は、差し替えの後の table inet wgft の set を読み直し、送った要素と比べる。
func (s *Staged) verify() error {
	read := s.readSet
	if read == nil {
		t := &nftables.Table{Family: nftables.TableFamilyINet, Name: TableName}
		read = func(name string) ([]nftables.SetElement, error) {
			return s.conn.GetSetElements(&nftables.Set{Table: t, Name: name})
		}
	}
	return verifySets(s.sent, read)
}

// verifySets は、set ごとに read で読んだ要素が sent と同じ集合かを確かめる。数が違えば数を、数が
// 同じで中身が違えばそのことを、set の名前とともに返す。読めない set も食い違いとして扱う。
// 送った要素を確かめられない公開を、成功とはみなさないためである。
func verifySets(sent map[string][]nftables.SetElement, read func(name string) ([]nftables.SetElement, error)) error {
	names := make([]string, 0, len(sent))
	for name := range sent {
		names = append(names, name)
	}
	sort.Strings(names)
	var problems []string
	for _, name := range names {
		want := sent[name]
		got, err := read(name)
		switch {
		case err != nil:
			problems = append(problems, fmt.Sprintf("set %s cannot be read back: %v", name, err))
		case len(got) != len(want):
			problems = append(problems, fmt.Sprintf("set %s holds %d set elements, but %d were sent", name, len(got), len(want)))
		case !sameElements(got, want):
			problems = append(problems, fmt.Sprintf("set %s holds %d set elements, but not the ones sent", name, len(got)))
		}
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("table inet %s was replaced, but it does not hold what was sent: %s", TableName, strings.Join(problems, "; "))
}

// sameElements は、順序を問わずに a と b が同じ要素の列かを返す。要素はキー、区間の終わりのキー、
// 区間の終端の印で比べる(Fingerprint が set の要素を数えるのと同じ値)。
func sameElements(a, b []nftables.SetElement) bool {
	ka, kb := elemKeys(a), elemKeys(b)
	if len(ka) != len(kb) {
		return false
	}
	for i := range ka {
		if !bytes.Equal(ka[i], kb[i]) {
			return false
		}
	}
	return true
}

// elemKeys は、要素ごとの比較の値を昇順に並べて返す。
func elemKeys(els []nftables.SetElement) [][]byte {
	keys := make([][]byte, 0, len(els))
	for _, e := range els {
		keys = append(keys, elemKey(e))
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
	return keys
}

// elemKey は要素 1 つの比較の値である。キーと区間の終わりのキーをつなぎ、終端の印なら 1 を足す。
func elemKey(e nftables.SetElement) []byte {
	k := append(append([]byte(nil), e.Key...), e.KeyEnd...)
	if e.IntervalEnd {
		k = append(k, 1)
	}
	return k
}
