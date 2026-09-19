package admissiontest_test

import (
	"testing"

	"github.com/rahanahu/wgft/internal/policy/admissiontest"
	"github.com/rahanahu/wgft/internal/policy/nftables/interp"
)

// engines は共有 fixture を流す評価器の一覧。Go の評価器(移行の手順 3)はここに加える。
var engines = []struct {
	name string
	new  admissiontest.NewEngine
}{
	{"nftables", interp.NewEngine},
}

// TestAdmissionFixtures は、各 fixture を各評価器に流して want と want_drops に照らし、
// 評価器どうしの結果も照らす(設計文書 7a.9 節「fixture の形式と等価性の検査」)。root も
// ネットワーク名前空間も要らない。
func TestAdmissionFixtures(t *testing.T) {
	fixtures, err := admissiontest.Load("../testdata/admission")
	if err != nil {
		t.Fatal(err)
	}
	for _, fx := range fixtures {
		t.Run(fx.Name, func(t *testing.T) {
			results := make([]admissiontest.Result, len(engines))
			for i, e := range engines {
				t.Run(e.name, func(t *testing.T) {
					results[i] = admissiontest.Run(t, fx, e.new)
				})
			}
			for i := 1; i < len(engines); i++ {
				admissiontest.Compare(t, fx, engines[0].name, results[0], engines[i].name, results[i])
			}
		})
	}
}
