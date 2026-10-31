package wgstack

import (
	"math/rand/v2"
	"testing"
)

var fuzzCoreSeeds = [][]byte{
	{0, 1, 3, 0, 1, 1, 0, 2, 5, 3, 1, 4, 2, 9, 3, 2, 1, 5, 6, 7},
	{0, 0, 0, 1, 1, 1, 1, 1, 2, 200, 4, 0, 1, 3, 3, 3, 0, 2, 255, 2, 255},
}

// opTB は 1 回分の本体の範囲を作る。Cleanup は回の終わりに実行し、Device を回ごとに解放する。
// Fatal は RunParallel の worker から呼べないので、Error にして panic で本体を抜ける。
type opTB struct {
	testing.TB
	cleanups []func()
}

type opFatal struct{}

func (o *opTB) Cleanup(f func()) { o.cleanups = append(o.cleanups, f) }
func (o *opTB) Fatal(a ...any)   { o.TB.Error(a...); panic(opFatal{}) }
func (o *opTB) Fatalf(f string, a ...any) {
	o.TB.Errorf(f, a...)
	panic(opFatal{})
}

func (o *opTB) run(prog []byte) {
	defer func() {
		for i := len(o.cleanups) - 1; i >= 0; i-- {
			o.cleanups[i]()
		}
		o.cleanups = nil
		if r := recover(); r != nil {
			if _, ok := r.(opFatal); !ok {
				panic(r)
			}
		}
	}()
	fuzzCoreBody(o, prog)
}

func BenchmarkFuzzCore(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		o := &opTB{TB: b}
		i := 0
		for pb.Next() {
			o.run(append([]byte(nil), fuzzCoreSeeds[i%2]...))
			i++
		}
	})
}

// BenchmarkFuzzCoreLong は固定の乱数で作った長い入力(500 step 前後)で本体を流す。fuzz が育てた後の入力に近い。
func BenchmarkFuzzCoreLong(b *testing.B) {
	b.ReportAllocs()
	r := rand.New(rand.NewPCG(1, 2))
	progs := make([][]byte, 16)
	for i := range progs {
		p := make([]byte, 600+r.IntN(400))
		for j := range p {
			p[j] = byte(r.IntN(256))
		}
		progs[i] = p
	}
	b.ResetTimer()
	o := &opTB{TB: b}
	for i := 0; i < b.N; i++ {
		o.run(append([]byte(nil), progs[i%len(progs)]...))
	}
}
