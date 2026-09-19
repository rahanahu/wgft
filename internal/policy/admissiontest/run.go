package admissiontest

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// Engine は fixture の出来事を流す評価器 1 つ。fixture 1 つにつき 1 つ作る。
type Engine interface {
	// Handle は時刻 at の出来事を処理し、flow と packet では Admit、Drop、DropOf(<種類>) の
	// どれかを返す。end では空を返す。
	Handle(at time.Duration, ev Event) (string, error)
	// Drops は最後に読む drop カウンタ(ルール ID と種類からパケット数への表)を返す。0 の項目は
	// 省いてよい。
	Drops() map[string]map[string]uint64
}

// NewEngine は fixture から Engine を作る。Plan と IR は fx.Plan() から得る。
type NewEngine func(fx *Fixture) (Engine, error)

// Result は 1 つの fixture を 1 つの Engine に流した結果。
type Result struct {
	Outcomes []string // 出来事ごとの結果(end では空)
	Drops    map[string]map[string]uint64
}

// Run は fx の出来事を時刻順に e へ流し、各出来事の結果を want に、drop カウンタを want_drops に
// 照らす。食い違いは t.Errorf で報告し、結果を返す。
func Run(t *testing.T, fx *Fixture, newEngine NewEngine) Result {
	t.Helper()
	e, err := newEngine(fx)
	if err != nil {
		t.Fatalf("%s: %v", fx.Name, err)
	}
	var res Result
	for i, ev := range fx.Events {
		got, err := e.Handle(time.Duration(ev.AtMS)*time.Millisecond, ev)
		if err != nil {
			t.Fatalf("%s: event %d (%s %s %s at %dms): %v", fx.Name, i, ev.Op, ev.Rule, ev.Flow, ev.AtMS, err)
		}
		res.Outcomes = append(res.Outcomes, got)
		if got != ev.Want {
			t.Errorf("%s: event %d (%s rule=%s src=%s flow=%s at %dms) = %q, want %q",
				fx.Name, i, ev.Op, ev.Rule, ev.Src, ev.Flow, ev.AtMS, got, ev.Want)
		}
	}
	res.Drops = nonZero(e.Drops())
	if want := nonZero(fx.WantDrops); !equalDrops(res.Drops, want) {
		t.Errorf("%s: drops = %s, want %s", fx.Name, formatDrops(res.Drops), formatDrops(want))
	}
	return res
}

// Compare は同じ fixture を 2 つの Engine に流した結果を互いに照らす(設計文書 7a.9 節の手順 3)。
// fixture は許容差が及ぶ出来事を書かない(7a.9 節「未決事項」を移行の手順 3 で決めた)ので、
// tolerances を挙げた fixture も照らす。tolerances は、その場面がどの許容差を避けて出来事を
// 置いたかを示す。
func Compare(t *testing.T, fx *Fixture, nameA string, a Result, nameB string, b Result) {
	t.Helper()
	if !slices.Equal(a.Outcomes, b.Outcomes) {
		t.Errorf("%s: outcomes differ\n%s: %v\n%s: %v", fx.Name, nameA, a.Outcomes, nameB, b.Outcomes)
	}
	if !equalDrops(a.Drops, b.Drops) {
		t.Errorf("%s: drops differ\n%s: %s\n%s: %s", fx.Name, nameA, formatDrops(a.Drops), nameB, formatDrops(b.Drops))
	}
}

func nonZero(in map[string]map[string]uint64) map[string]map[string]uint64 {
	out := map[string]map[string]uint64{}
	for rule, kinds := range in {
		for kind, n := range kinds {
			if n == 0 {
				continue
			}
			if out[rule] == nil {
				out[rule] = map[string]uint64{}
			}
			out[rule][kind] = n
		}
	}
	return out
}

func equalDrops(a, b map[string]map[string]uint64) bool {
	return maps.EqualFunc(a, b, func(x, y map[string]uint64) bool { return maps.Equal(x, y) })
}

func formatDrops(d map[string]map[string]uint64) string {
	var parts []string
	for _, rule := range slices.Sorted(maps.Keys(d)) {
		for _, kind := range slices.Sorted(maps.Keys(d[rule])) {
			parts = append(parts, fmt.Sprintf("%s:%s=%d", rule, kind, d[rule][kind]))
		}
	}
	return "{" + strings.Join(parts, " ") + "}"
}
