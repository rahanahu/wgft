package lograte

import "testing"

func TestGateOpensOncePerMinute(t *testing.T) {
	var g Gate
	if !g.Allow() {
		t.Error("the first Allow on a zero-value gate must open")
	}
	if g.Allow() {
		t.Error("a second Allow within the minute must stay shut")
	}
}

// 門は 1 つの事象につき 1 つ持つので、別の門は互いの状態を見ない。
func TestGatesAreIndependent(t *testing.T) {
	var a, b Gate
	if !a.Allow() {
		t.Fatal("the first Allow on a must open")
	}
	if !b.Allow() {
		t.Error("a gate must not be closed by another gate")
	}
}
