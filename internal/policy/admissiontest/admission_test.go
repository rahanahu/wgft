package admissiontest_test

import (
	"testing"

	"github.com/rahanahu/wgft/internal/policy/admissiontest"
	"github.com/rahanahu/wgft/internal/policy/nftables/interp"
)

// engines は共有 fixture を流す評価器の一覧。
var engines = []struct {
	name string
	new  admissiontest.NewEngine
}{
	{admissiontest.EngineNFTables, interp.NewEngine},
	{admissiontest.EngineGo, newGoEngine},
}

// TestAdmissionFixtures は、各 fixture を各評価器に流して want と want_drops に照らし、
// 評価器どうしの結果も照らす(設計文書 7a.9 節「fixture の形式と等価性の検査」)。root も
// ネットワーク名前空間も要らない。評価器を限った暫定の fixture は、その評価器にだけ流す。
func TestAdmissionFixtures(t *testing.T) {
	fixtures, err := admissiontest.Load("../testdata/admission")
	if err != nil {
		t.Fatal(err)
	}
	for _, fx := range fixtures {
		t.Run(fx.Name, func(t *testing.T) {
			type ran struct {
				name string
				res  admissiontest.Result
			}
			var results []ran
			for _, e := range engines {
				if !fx.AppliesTo(e.name) {
					continue
				}
				t.Run(e.name, func(t *testing.T) {
					results = append(results, ran{e.name, admissiontest.Run(t, fx, e.new)})
				})
			}
			if len(results) == 0 {
				t.Fatalf("no evaluator runs this fixture")
			}
			for _, r := range results[1:] {
				admissiontest.Compare(t, fx, results[0].name, results[0].res, r.name, r.res)
			}
		})
	}
}
