package wgstack

import "testing"

var fuzzCoreSeeds = [][]byte{
	{0, 1, 3, 0, 1, 1, 0, 2, 5, 3, 1, 4, 2, 9, 3, 2, 1, 5, 6, 7},
	{0, 0, 0, 1, 1, 1, 1, 1, 2, 200, 4, 0, 1, 3, 3, 3, 0, 2, 255, 2, 255},
}

func BenchmarkFuzzCore(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			fuzzCoreBody(b, append([]byte(nil), fuzzCoreSeeds[i%2]...))
			i++
		}
	})
}
