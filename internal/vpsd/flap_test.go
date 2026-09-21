//go:build linux

package vpsd

import (
	"testing"
	"time"
)

// flapStep:A→B は警告なし、A→B→A は往復、窓を超えた古い値への復帰は警告なし、
// 同一 IP の連続は何もしない(仕様 5.2 節の第 2 判定)。
func TestFlapStep(t *testing.T) {
	win := 10 * time.Minute
	t0 := time.Unix(0, 0)
	at := func(sec int) time.Time { return t0.Add(time.Duration(sec) * time.Second) }

	var h []ipObs
	var flapped bool
	var other string

	// A:初回、往復なし
	h, flapped, _ = flapStep(h, "A", at(0), win)
	if flapped {
		t.Fatal("初回 A で往復")
	}
	// A→B:新しい値、往復なし
	h, flapped, _ = flapStep(h, "B", at(10), win)
	if flapped {
		t.Fatal("A→B で往復")
	}
	// A→B→A:以前の値へ戻る=往復。other は直前の B
	h, flapped, other = flapStep(h, "A", at(20), win)
	if !flapped || other != "B" {
		t.Fatalf("A→B→A 往復せず: flapped=%v other=%q", flapped, other)
	}
	// さらに B に戻る=また往復
	h, flapped, other = flapStep(h, "B", at(30), win)
	if !flapped || other != "A" {
		t.Fatalf("→B 往復せず: flapped=%v other=%q", flapped, other)
	}

	// 同一 IP の連続は何もしない(最終観測時刻の更新のみ)
	before := len(h)
	h, flapped, _ = flapStep(h, "B", at(40), win)
	if flapped || len(h) != before {
		t.Fatalf("同一 IP 連続で変化: flapped=%v len %d→%d", flapped, before, len(h))
	}

	// 窓を超えた古い値への復帰は往復にしない(10 分より前の A は落ちている)
	h2 := []ipObs{{IP: "A", At: at(0)}, {IP: "B", At: at(30)}}
	_, flapped, _ = flapStep(h2, "A", at(0+700), win) // 700s 後、A は窓外
	if flapped {
		t.Fatal("窓外の古い値への復帰で往復")
	}
}
