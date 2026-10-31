package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseShard(t *testing.T) {
	for _, tc := range []struct {
		in   string
		k, n int
		ok   bool
	}{{"1/1", 1, 1, true}, {"2/3", 2, 3, true}, {"0/3", 0, 0, false}, {"4/3", 0, 0, false}, {"2", 0, 0, false}, {"a/b", 0, 0, false}, {"1/0", 0, 0, false}} {
		k, n, err := parseShard(tc.in)
		if (err == nil) != tc.ok || (tc.ok && (k != tc.k || n != tc.n)) {
			t.Errorf("parseShard(%q) = %d, %d, %v", tc.in, k, n, err)
		}
	}
}

type testJob struct {
	name string
	cls  class
	w    float64
	rate string
}

func testInput(n int, jobs ...testJob) shardInput {
	w, r := map[string]float64{}, map[string]string{}
	var plan []jobResult
	for _, j := range jobs {
		plan = append(plan, jobResult{Index: len(plan), Class: j.cls, Scenario: j.name})
		w[j.name], r[j.name] = j.w, j.rate
	}
	return shardInput{Plan: plan, N: n, Pool: 8, Margin: 30,
		Weight: func(j jobResult) float64 { return w[j.Scenario] },
		Rate:   func(j jobResult) string { return r[j.Scenario] }}
}

func testPlan(n int) shardInput {
	return testInput(n,
		testJob{"a", classParallel, 390, ""}, testJob{"b", classParallel, 240, ""}, testJob{"c", classParallel, 200, ""},
		testJob{"d", classParallel, 10, ""}, testJob{"e", classHeavy, 185, rateOverlap}, testJob{"f", classHeavy, 50, rateMeasure},
		testJob{"g", classGlobal, 50, rateGroup}, testJob{"h", classHeavy, 40, ""}, testJob{"i", classHeavy, 20, ""})
}

// Every job lands in exactly one shard, the same input gives the same answer, and the
// estimate of the slowest shard beats the one-VM estimate.
func TestAssignShards(t *testing.T) {
	l1 := assignShards(testPlan(3))
	l2 := assignShards(testPlan(3))
	for _, j := range testPlan(3).Plan {
		s, ok := l1.Assign[j.Index]
		if !ok || s < 0 || s > 2 {
			t.Errorf("job %d unassigned: %d", j.Index, s)
		}
		if l2.Assign[j.Index] != s {
			t.Errorf("job %d: not deterministic", j.Index)
		}
	}
	one := assignShards(testPlan(1))
	var max float64
	for _, e := range l1.Est {
		if e > max {
			max = e
		}
	}
	if max >= one.Est[0] {
		t.Errorf("3 shards estimate %.0f, 1 shard %.0f", max, one.Est[0])
	}
	// the longest parallel job bounds a shard: no layout beats it
	if max < 390 {
		t.Errorf("estimate %.0f is below the longest job", max)
	}
	if l1.Assign[5] != l1.Assign[6] || l1.RateVM != l1.Assign[5] {
		t.Errorf("rate=measure and rate=group must share a shard: %v, rate VM %d", l1.Assign, l1.RateVM)
	}
	if len(l1.Problems) != 0 || len(one.Problems) != 0 {
		t.Errorf("problems: %v %v", l1.Problems, one.Problems)
	}
}

// checkWindow fails the test if a guarded job of another shard is estimated to run within the
// margin of the rate window: an exclusive job without rate=overlap, in its own slot, or a
// rate=flood parallel job, anywhere in its shard's pool.
func checkWindow(t *testing.T, in shardInput, l shardLayout) {
	t.Helper()
	if l.RateVM < 0 {
		return
	}
	pm, ps := make([]float64, in.N), make([]float64, in.N)
	per := make([][]jobResult, in.N)
	for _, j := range in.Plan {
		s := l.Assign[j.Index]
		if j.Class.exclusive() {
			per[s] = append(per[s], j)
		} else {
			ps[s] += in.Weight(j)
			if in.Weight(j) > pm[s] {
				pm[s] = in.Weight(j)
			}
		}
	}
	near := func(a, b float64) bool { return a < l.Window[1]+in.Margin && b > l.Window[0]-in.Margin }
	for _, j := range in.Plan {
		s := l.Assign[j.Index]
		end := poolEstimate(pm[s], ps[s], in.Pool)
		if s != l.RateVM && !j.Class.exclusive() && in.Rate(j) == rateFlood && near(0, end) {
			t.Errorf("flood %s in shard %d pool 0..%.0f, window %.0f..%.0f", j.Scenario, s+1, end, l.Window[0], l.Window[1])
		}
	}
	for s := range per {
		if s == l.RateVM {
			continue
		}
		at := poolEstimate(pm[s], ps[s], in.Pool)
		for _, j := range shardOrder(per[s], in.Rate) {
			end := at + in.Weight(j)
			if in.Rate(j) != rateOverlap && near(at, end) {
				t.Errorf("%s in shard %d runs %.0f..%.0f, window %.0f..%.0f", j.Scenario, s+1, at, end, l.Window[0], l.Window[1])
			}
			at = end
		}
	}
}

// The greedy layout puts the flood f beside the rate window in another shard; the guard moves
// it into the window's shard, behind the measuring job. A rate=overlap job stays where it was.
func TestRateWindowGuard(t *testing.T) {
	jobs := []testJob{{"p", classParallel, 400, ""}, {"m", classHeavy, 50, rateMeasure}, {"g", classHeavy, 40, rateGroup}, {"f", classHeavy, 500, ""}}
	in := testInput(2, jobs...)
	l := assignShards(in)
	if l.RateVM < 0 || l.Assign[3] != l.RateVM || len(l.Problems) != 0 {
		t.Errorf("the flood must move into the rate window's shard: %+v", l)
	}
	checkWindow(t, in, l)
	if o := shardOrder([]jobResult{in.Plan[3], in.Plan[2], in.Plan[1], in.Plan[0]}, in.Rate); o[0].Scenario != "m" {
		t.Errorf("rate=measure must come first: %v", o)
	}

	jobs[3].rate = rateOverlap
	in = testInput(2, jobs...)
	l = assignShards(in)
	if l.Assign[3] == l.RateVM {
		t.Errorf("a rate=overlap job need not move: %+v", l)
	}

	// without the guard, the same input overlaps: the test above has teeth
	jobs[3].rate = ""
	in = testInput(2, jobs...)
	l = shardLayout{Assign: map[int]int{0: 1, 1: 1, 2: 1, 3: 0}}
	if bad := evalLayout(in, &l); len(bad) != 1 || bad[0].Job.Scenario != "f" || len(l.Problems) != 1 {
		t.Errorf("the greedy layout should break the window: %v %v", bad, l.Problems)
	}
}

// A rate=flood parallel job may run anywhere in its pool: in another shard whose pool reaches
// into the window, it moves into the window's shard, where the pool ends before the window.
func TestRateWindowGuardFlood(t *testing.T) {
	in := testInput(2,
		testJob{"p1", classParallel, 300, ""}, testJob{"p2", classParallel, 300, ""},
		testJob{"fl", classParallel, 20, rateFlood},
		testJob{"m", classHeavy, 50, rateMeasure}, testJob{"g", classHeavy, 10, rateGroup})
	l := assignShards(in)
	if l.RateVM < 0 || l.Assign[2] != l.RateVM || len(l.Problems) != 0 {
		t.Errorf("the flood must move into the rate window's shard: %+v", l)
	}
	checkWindow(t, in, l)
}

// The margin applies before the window too: an exclusive job of another shard that ends just
// before the window starts is too close.
func TestRateWindowMarginBefore(t *testing.T) {
	in := testInput(2,
		testJob{"m", classHeavy, 50, rateMeasure},
		testJob{"p", classParallel, 100, ""},
		testJob{"x", classHeavy, 20, ""})
	// shard 2 holds the window after its 100 s pool, 100..150; x runs 0..20 in shard 1
	l := shardLayout{Assign: map[int]int{0: 1, 1: 1, 2: 0}}
	if bad := evalLayout(in, &l); len(bad) != 0 {
		t.Errorf("a job 80 s before the window is fine: %v", l.Problems)
	}
	in.Margin = 90
	if bad := evalLayout(in, &l); len(bad) != 1 {
		t.Errorf("a job inside the margin before the window must break it: %v", l.Problems)
	}
}

// The repository's manifest keeps the rate window for every shard count lab/lab suite can take
// before a shard runs empty.
func TestRepoManifestRateWindow(t *testing.T) {
	jobs, err := loadManifest(filepath.Join("..", "..", "lab", "suite.txt"))
	if err != nil {
		t.Fatal(err)
	}
	meta := map[string]job{}
	var plan []jobResult
	measure := 0
	for _, j := range jobs {
		if strings.HasPrefix(j.Scenario, "rates.sh ") && j.Rate != rateMeasure {
			t.Errorf("%q measures rates but is not rate=measure", j.Scenario)
		}
		if !j.Default {
			continue
		}
		if j.Rate == rateMeasure {
			measure++
		}
		meta[j.Scenario] = j
		plan = append(plan, jobResult{Index: len(plan), Class: j.Class, Scenario: j.Scenario})
	}
	if measure == 0 {
		t.Fatal("no rate=measure job in the default suite")
	}
	for n := 1; n <= 6; n++ {
		in := shardInput{Plan: plan, N: n, Pool: 8, Margin: 30,
			Weight: func(j jobResult) float64 {
				if w := meta[j.Scenario].Weight; w > 0 {
					return w
				}
				return defaultWeightSec
			},
			Rate: func(j jobResult) string { return meta[j.Scenario].Rate }}
		l := assignShards(in)
		if len(l.Problems) != 0 {
			t.Errorf("%d shards: %v", n, l.Problems)
		}
		checkWindow(t, in, l)
	}
}

func mkPart(shard string, idx ...int) *summary {
	s := &summary{Shard: shard, PlanJobs: 3, PlanDigest: "d1", PlanScenarios: []string{"x0", "x1", "x2"}, Netstack: "default", WallSec: float64(idx[0] + 1)}
	for _, i := range idx {
		s.Results = append(s.Results, jobResult{Index: i, Scenario: s.PlanScenarios[i], PassLines: 2})
	}
	return s
}

func TestMergeSummaries(t *testing.T) {
	m := mergeSummaries([]*summary{mkPart("1/2", 0, 2), mkPart("2/2", 1)})
	if len(m.MergeProblems) != 0 || m.Jobs != 3 || m.Pass != 3 || m.TotalPassLines != 6 || m.WallSec != 2 || m.Netstack != "default" || m.PlanDigest != "d1" {
		t.Errorf("good merge: %+v", m)
	}
	f := mkPart("2/2", 1, 2)
	f.Results[0].Exit = 1
	m = mergeSummaries([]*summary{mkPart("1/2", 0), f})
	if m.Fail != 1 {
		t.Errorf("a failing job must stay failing: %+v", m)
	}
	if len(m.LeftoverFailures) != 0 {
		t.Errorf("a merge problem is not a leftover: %v", m.LeftoverFailures)
	}
}

// Each check of the merge, on its own: the problem names what went wrong, and a merge
// problem never shows up as a cleanup leftover.
func TestMergeProblems(t *testing.T) {
	for _, tc := range []struct {
		name  string
		parts func() []*summary
		want  string
	}{
		{"missing shard", func() []*summary { return []*summary{mkPart("1/2", 0, 2)} }, "job 1, x1, ran in no shard"},
		{"duplicated job", func() []*summary { return []*summary{mkPart("1/2", 0, 1), mkPart("2/2", 1, 2)} }, "job 1, x1, ran in shards 1/2 and 2/2"},
		{"uncovered job", func() []*summary { return []*summary{mkPart("1/2", 0), mkPart("2/2", 1)} }, "job 2, x2, ran in no shard"},
		{"shard given twice", func() []*summary { return []*summary{mkPart("1/2", 0, 2), mkPart("1/2", 1)} }, "shard 1/2 given twice"},
		{"another plan", func() []*summary {
			p := mkPart("2/2", 1)
			p.PlanDigest = "d2"
			return []*summary{mkPart("1/2", 0, 2), p}
		}, "shard 2/2 was cut from another plan: digest d2, not d1"},
		{"mixed netstacks", func() []*summary {
			p := mkPart("2/2", 1)
			p.Netstack = "wgstack"
			return []*summary{mkPart("1/2", 0, 2), p}
		}, "shard 2/2 ran with netstack wgstack, not default"},
		{"not a shard", func() []*summary {
			p := mkPart("2/2", 1)
			p.PlanDigest = ""
			return []*summary{mkPart("1/2", 0, 2), p}
		}, "part 2 has no shard, plan size or plan digest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := mergeSummaries(tc.parts())
			found := false
			for _, p := range m.MergeProblems {
				found = found || strings.Contains(p, tc.want)
			}
			if !found {
				t.Errorf("want a problem with %q, got %v", tc.want, m.MergeProblems)
			}
			if len(m.LeftoverFailures) != 0 {
				t.Errorf("merge problems reported as leftovers: %v", m.LeftoverFailures)
			}
		})
	}
	m := mergeSummaries([]*summary{mkPart("1/2", 0)})
	if m.MissingJobs != 2 {
		t.Errorf("missing jobs = %d, want 2", m.MissingJobs)
	}
}

func TestManifestKeys(t *testing.T) {
	p := filepath.Join(t.TempDir(), "s.txt")
	write := func(s string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("parallel yes weight=12.5 a.sh kernel 1\nparallel yes rate=flood b.sh\nexclusive-heavy yes rate=measure weight=3 c.sh\n")
	jobs, err := loadManifest(p)
	if err != nil || jobs[0].Weight != 12.5 || jobs[0].Scenario != "a.sh kernel 1" || jobs[1].Weight != 0 || jobs[1].Rate != rateFlood ||
		jobs[2].Rate != rateMeasure || jobs[2].Weight != 3 || jobs[2].Scenario != "c.sh" {
		t.Fatalf("%+v %v", jobs, err)
	}
	for _, bad := range []string{
		"parallel yes weight=x a.sh\n",
		"parallel yes weight=-1 a.sh\n",
		"parallel yes weight=5\n",
		"parallel yes rate=measure a.sh\n",
		"exclusive-heavy yes rate=fast a.sh\n",
		"exclusive-heavy yes speed=1 a.sh\n",
		"exclusive-heavy yes rate=flood a.sh\n",
		"parallel yes rate=overlap a.sh\n",
	} {
		write(bad)
		if _, err := loadManifest(p); err == nil {
			t.Errorf("%q must be an error", bad)
		}
	}
}

// labhost merge reads the real start times: a guarded job of another shard that ran during a
// rate=measure job is a warning, an allowed or same-shard one is not, and a clean run names the
// nearest guarded job.
func TestRateWindowCheck(t *testing.T) {
	t0 := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC)
	at := func(i int, sc string, cls class, rate string, start, dur float64) jobResult {
		return jobResult{Index: i, Scenario: sc, Class: cls, Rate: rate, StartedAt: t0.Add(time.Duration(start * float64(time.Second))), DurationSec: dur}
	}
	shardOf := map[int]string{0: "1/2", 1: "1/2", 2: "2/2", 3: "2/2", 4: "2/2", 5: "1/2"}
	res := []jobResult{
		at(0, "rates.sh kernel", classHeavy, rateMeasure, 100, 50),
		at(1, "lifecycle.sh kernel 5", classHeavy, rateGroup, 150, 10),
		at(2, "exhaustion.sh userspace postclose", classHeavy, rateOverlap, 0, 200),
		at(3, "exhaustion.sh kernel acceptq", classHeavy, "", 170, 20),
		at(4, "connlimit.sh", classParallel, rateFlood, 0, 30),
		// in the window's own shard the jobs run one at a time; a start rounded into the
		// window's last moment is not an overlap
		at(5, "exhaustion.sh userspace wgstall", classHeavy, "", 149.9, 30),
	}
	line, warns := rateWindowCheck(res, shardOf, 30)
	if len(warns) != 0 || !strings.Contains(line, `"exhaustion.sh kernel acceptq" in shard 2/2, was 20.0 s away, inside the 30 s margin`) {
		t.Errorf("clean run: %q %v", line, warns)
	}
	res[4] = at(4, "connlimit.sh", classParallel, rateFlood, 90, 30)
	line, warns = rateWindowCheck(res, shardOf, 30)
	if len(warns) != 1 || !strings.Contains(warns[0], `"connlimit.sh" in shard 2/2 ran for 20.0 s during "rates.sh kernel"`) {
		t.Errorf("overlap: %q %v", line, warns)
	}
	if line, _ := rateWindowCheck(res[2:], shardOf, 30); line != "" {
		t.Errorf("no rate=measure job, no line: %q", line)
	}
}

// A guarded job that breaks the window moves to the shard where the slowest shard ends earliest,
// not always into the window's shard: here f fits after shard 3's long pool.
func TestRateWindowGuardPicksTheShortestLayout(t *testing.T) {
	in := testInput(3,
		testJob{"m", classHeavy, 50, rateMeasure}, testJob{"g", classHeavy, 300, rateGroup},
		testJob{"f", classHeavy, 40, ""},
		testJob{"p1", classParallel, 300, ""}, testJob{"p2", classParallel, 20, ""})
	l := assignShards(in)
	if l.RateVM != 0 || l.Assign[2] != 2 || len(l.Problems) != 0 {
		t.Errorf("f should run after shard 3's pool: %+v", l)
	}
	checkWindow(t, in, l)
}
