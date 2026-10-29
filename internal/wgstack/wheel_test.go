package wgstack

import (
	"math/rand/v2"
	"sort"
	"testing"
)

// タイマーの輪を、期限の表と比べる。早く発火しないこと、期限の後の最初の advance で発火すること、
// nextTick が次の期限より後にならないことを確かめる。
func TestWheelAgainstReference(t *testing.T) {
	for seed := uint64(0); seed < 200; seed++ {
		rng := rand.New(rand.NewPCG(seed, 1))
		const nodes = 64
		w := newWheel(nodes)
		ref := map[int32]int64{} // 期限(tick)
		now := int64(rng.IntN(1 << 20))
		w.advance(now*tickNs, nil)
		for step := 0; step < 3000; step++ {
			switch r := rng.IntN(10); {
			case r < 4:
				n := int32(rng.IntN(nodes))
				var d int64
				switch rng.IntN(4) {
				case 0:
					d = int64(rng.IntN(70))
				case 1:
					d = int64(rng.IntN(5000))
				case 2:
					d = int64(rng.IntN(300000))
				default:
					d = int64(rng.IntN(2000000))
				}
				at := (now + d) * tickNs
				w.set(n, at)
				ref[n] = max(toTick(at), w.tick+1)
			case r < 5:
				n := int32(rng.IntN(nodes))
				w.cancel(n)
				delete(ref, n)
			default:
				// nextTick は次の期限より後にならない
				if len(ref) > 0 {
					var ds []int64
					for _, d := range ref {
						ds = append(ds, d)
					}
					sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
					if nt := w.nextTick(); nt > ds[0] {
						t.Fatalf("seed %d: nextTick %d after the earliest deadline %d (tick %d)", seed, nt, ds[0], w.tick)
					}
				}
				var adv int64
				switch rng.IntN(3) {
				case 0:
					adv = int64(rng.IntN(100))
				case 1:
					adv = int64(rng.IntN(10000))
				default:
					adv = int64(rng.IntN(1000000))
				}
				now += adv
				fired := w.advance(now*tickNs, nil)
				got := map[int32]bool{}
				for _, f := range fired {
					if got[f] {
						t.Fatalf("seed %d: node %d fired twice", seed, f)
					}
					got[f] = true
					d, ok := ref[f]
					if !ok {
						t.Fatalf("seed %d: node %d fired but is not armed", seed, f)
					}
					if d > now {
						t.Fatalf("seed %d: node %d fired early: deadline %d now %d", seed, f, d, now)
					}
					delete(ref, f)
				}
				for n, d := range ref {
					if d <= now {
						t.Fatalf("seed %d: node %d deadline %d not fired at %d", seed, n, d, now)
					}
				}
			}
		}
	}
}
