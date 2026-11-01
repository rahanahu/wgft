// shard.go は run all の仕事を N 台の VM に分ける決定的な割り当てと、各 VM の summary.json の
// 統合。単独で流す仕事は割り当て先の VM の中で 1 つずつ流れるので、どの分け方でも
// 「VM の中で単独」の約束は変わらない。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

// defaultWeightSec は、記録にも manifest にも秒数が無い仕事の見積もり。
const defaultWeightSec = 10

// parseShard は "K/N" (1 <= K <= N) を読む。
func parseShard(s string) (k, n int, err error) {
	a, b, ok := strings.Cut(s, "/")
	if ok {
		k, err = strconv.Atoi(a)
		if err == nil {
			n, err = strconv.Atoi(b)
		}
	}
	if !ok || err != nil || n < 1 || k < 1 || k > n {
		return 0, 0, fmt.Errorf("-shard wants K/N with 1 <= K <= N, got %q", s)
	}
	return k, n, nil
}

// loadDurations は以前の run の summary.json からシナリオごとの秒数を読む。
// 同じシナリオが複数回あれば平均、shard の統合結果なら統合された Results をそのまま使う。
func loadDurations(path string) (map[string]float64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s summary
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	sum, cnt := map[string]float64{}, map[string]int{}
	for _, r := range s.Results {
		if r.SetupErr != "" || r.TimedOut || r.DurationSec <= 0 {
			continue
		}
		sum[r.Scenario] += r.DurationSec
		cnt[r.Scenario]++
	}
	if len(sum) == 0 {
		return nil, fmt.Errorf("%s: no usable job duration", path)
	}
	for k := range sum {
		sum[k] /= float64(cnt[k])
	}
	return sum, nil
}

// shardEstimate は 1 台の見積もりの秒数。プールは最も長い仕事より速くならず、
// 全体は pool 個ずつ流れるので合計の 1/pool より速くならない。単独の仕事はそのあとに 1 つずつ続く。
func shardEstimate(poolMax, poolSum, excl float64, pool int) float64 {
	return poolEstimate(poolMax, poolSum, pool) + excl
}

func poolEstimate(poolMax, poolSum float64, pool int) float64 {
	p := poolSum / float64(pool)
	if poolMax > p {
		p = poolMax
	}
	return p
}

// shardInput は割り当ての入力。Weight は仕事の見積もりの秒数、Rate は manifest の rate= の値。
type shardInput struct {
	Plan   []jobResult
	Weight func(jobResult) float64
	Rate   func(jobResult) string
	N      int     // 台の数
	Pool   int     // 1 台のプールの大きさ (-parallel)
	Margin float64 // 時間窓の終わりから、別の VM の単独の仕事が始まってよいまでの秒数
}

// shardLayout は割り当ての結果。
type shardLayout struct {
	Assign   map[int]int // 仕事の Index から台の番号 (0 始まり)
	Est      []float64   // 台ごとの見積もりの秒数
	Window   [2]float64  // rate=measure の仕事が走る時間窓の見積もり。台がそろって始まった時刻から数える
	RateVM   int         // 時間窓の台。rate=measure の仕事が無ければ -1
	Problems []string    // 守れなかった時間窓。割り当ては返すが、呼び出し側が警告する
}

// assignShards は plan の各仕事を n 台のどれかに割り当てる。
//
// 1. rate=measure と rate=group の単独の仕事は 1 つの塊にして、同じ台に置く。その台の単独の
// 仕事は rate=measure を先に流す (shardOrder)。
// 2. 塊と残りの仕事を重い順に、置いたあとの見積もりが最も小さい台へ置く (同点は台の番号の小さい方)。
// 3. 時間窓の守り: 別の台の守る仕事は、見積もりの時間が時間窓の前後 Margin を含む区間と重なっては
// ならない。守る仕事は rate=overlap を除く単独の仕事と、rate=flood の parallel の仕事。単独の仕事の
// 時間はその台の単独の段の中の自分の枠、rate=flood の仕事の時間はプールのどこで走るか決まらないので
// その台のプール全体 (0 からプールの見積もりの終わりまで)。破る仕事は、始まりの早いものから、
// その仕事が守りを破らない台のうち、見積もりの最も長い台が最も短くなる台へ移す。時間窓の台は
// いつも候補になる。その台ではプールが時間窓の前に終わり、単独の仕事は 1 つずつ流れるためである。
// 移すと元の台の後の仕事が早まり、時間窓の台のプールが延びれば時間窓が後ろへずれるので、破るものが
// 無くなるまで繰り返す。
//
// 入力が同じなら結果は同じで、台の数 n が同じなら K ごとに独立に計算できる。
func assignShards(in shardInput) shardLayout {
	type unit struct {
		jobs  []jobResult
		excl  bool
		w     float64
		first int
	}
	var units []unit
	grp := unit{excl: true, first: -1}
	for _, j := range in.Plan {
		if r := in.Rate(j); j.Class.exclusive() && (r == rateMeasure || r == rateGroup) {
			grp.jobs = append(grp.jobs, j)
			grp.w += in.Weight(j)
			if grp.first < 0 {
				grp.first = j.Index
			}
			continue
		}
		units = append(units, unit{jobs: []jobResult{j}, excl: j.Class.exclusive(), w: in.Weight(j), first: j.Index})
	}
	if len(grp.jobs) > 0 {
		units = append(units, grp)
	}
	cost := func(u unit) float64 {
		if u.excl {
			return u.w
		}
		return u.w / float64(in.Pool)
	}
	sort.SliceStable(units, func(a, b int) bool {
		ca, cb := cost(units[a]), cost(units[b])
		if ca != cb {
			return ca > cb
		}
		return units[a].first < units[b].first
	})
	n := in.N
	poolMax, poolSum, excl := make([]float64, n), make([]float64, n), make([]float64, n)
	assign := map[int]int{}
	for _, u := range units {
		best, bestEst := 0, 0.0
		for s := 0; s < n; s++ {
			pm, ps, ex := poolMax[s], poolSum[s], excl[s]
			if u.excl {
				ex += u.w
			} else {
				ps += u.w
				if u.w > pm {
					pm = u.w
				}
			}
			if est := shardEstimate(pm, ps, ex, in.Pool); s == 0 || est < bestEst {
				best, bestEst = s, est
			}
		}
		for _, j := range u.jobs {
			assign[j.Index] = best
		}
		if u.excl {
			excl[best] += u.w
		} else {
			poolSum[best] += u.w
			if u.w > poolMax[best] {
				poolMax[best] = u.w
			}
		}
	}
	l := shardLayout{Assign: assign, RateVM: -1}
	maxEst := func(l shardLayout) float64 {
		m := 0.0
		for _, e := range l.Est {
			m = max(m, e)
		}
		return m
	}
	breaks := func(bad []windowSlot, idx int) bool {
		for _, b := range bad {
			if b.Job.Index == idx {
				return true
			}
		}
		return false
	}
	// 破る仕事のうち始まりの最も早いものを、自分が守りを破らない台のうち見積もりの最も短くなる台へ
	// 移す。時間窓の台はいつも候補になる。移した先で後から破ることもあるので回数に上限を置き、
	// 上限に達したら、破る仕事を時間窓の台へ移すだけにする。こちらは必ず終わる
	for i := 0; i < 4*len(in.Plan); i++ {
		bad := evalLayout(in, &l)
		if len(bad) == 0 {
			return l
		}
		idx, from := bad[0].Job.Index, assign[bad[0].Job.Index]
		best, bestEst := -1, 0.0
		for s := 0; s < n; s++ {
			if s == from {
				continue
			}
			assign[idx] = s
			t := shardLayout{Assign: assign}
			if tb := evalLayout(in, &t); s != l.RateVM && breaks(tb, idx) {
				continue
			}
			if e := maxEst(t); best < 0 || e < bestEst {
				best, bestEst = s, e
			}
		}
		assign[idx] = best
	}
	for range in.Plan {
		bad := evalLayout(in, &l)
		if len(bad) == 0 {
			return l
		}
		assign[bad[0].Job.Index] = l.RateVM
	}
	evalLayout(in, &l)
	return l
}

// windowSlot は単独の仕事の 1 つの見積もりの時間。
type windowSlot struct {
	Job        jobResult
	VM         int
	Start, End float64
}

// evalLayout は l.Assign から見積もり、時間窓、守れない仕事を計算し直し、守れない仕事を
// 始まりの早い順に返す。
func evalLayout(in shardInput, l *shardLayout) []windowSlot {
	n := in.N
	poolMax, poolSum, excl := make([]float64, n), make([]float64, n), make([]float64, n)
	perVM := make([][]jobResult, n)
	for _, j := range in.Plan {
		s := l.Assign[j.Index]
		w := in.Weight(j)
		if j.Class.exclusive() {
			excl[s] += w
			perVM[s] = append(perVM[s], j)
		} else {
			poolSum[s] += w
			if w > poolMax[s] {
				poolMax[s] = w
			}
		}
	}
	l.Est = make([]float64, n)
	var slots []windowSlot
	l.RateVM, l.Window = -1, [2]float64{}
	for _, j := range in.Plan {
		if !j.Class.exclusive() && in.Rate(j) == rateFlood {
			s := l.Assign[j.Index]
			slots = append(slots, windowSlot{Job: j, VM: s, Start: 0, End: poolEstimate(poolMax[s], poolSum[s], in.Pool)})
		}
	}
	for s := 0; s < n; s++ {
		l.Est[s] = shardEstimate(poolMax[s], poolSum[s], excl[s], in.Pool)
		t := poolEstimate(poolMax[s], poolSum[s], in.Pool)
		for _, j := range shardOrder(perVM[s], in.Rate) {
			w := in.Weight(j)
			slots = append(slots, windowSlot{Job: j, VM: s, Start: t, End: t + w})
			if in.Rate(j) == rateMeasure {
				if l.RateVM < 0 {
					l.RateVM, l.Window[0] = s, t
				}
				l.Window[1] = t + w
			}
			t += w
		}
	}
	l.Problems = nil
	if l.RateVM < 0 {
		return nil
	}
	var bad []windowSlot
	for _, sl := range slots {
		if sl.VM == l.RateVM {
			continue
		}
		if in.Rate(sl.Job) == rateOverlap {
			continue
		}
		if sl.Start < l.Window[1]+in.Margin && sl.End > l.Window[0]-in.Margin {
			bad = append(bad, sl)
			l.Problems = append(l.Problems, fmt.Sprintf("%q in shard %d/%d is estimated to run from %.0f s to %.0f s, within %.0f s of the rate window of shard %d/%d, %.0f s to %.0f s",
				sl.Job.Scenario, sl.VM+1, n, sl.Start, sl.End, in.Margin, l.RateVM+1, n, l.Window[0], l.Window[1]))
		}
	}
	sort.SliceStable(bad, func(a, b int) bool {
		if bad[a].Start != bad[b].Start {
			return bad[a].Start < bad[b].Start
		}
		return bad[a].Job.Index < bad[b].Job.Index
	})
	return bad
}

// shardOrder は 1 台の仕事を流す順に並べる。rate=measure の単独の仕事を、単独の仕事の先頭に
// 置く。それ以外は plan の順。labhost run はプールを先に、単独の仕事をそのあとに plan の順で流すので、
// これで時間窓がその台の単独の段の始めに来る。
func shardOrder(jobs []jobResult, rate func(jobResult) string) []jobResult {
	out := make([]jobResult, len(jobs))
	copy(out, jobs)
	first := func(j jobResult) bool { return j.Class.exclusive() && rate(j) == rateMeasure }
	sort.SliceStable(out, func(a, b int) bool { return first(out[a]) && !first(out[b]) })
	return out
}

// planDigest は割り当ての入力と結果の要約。各台は自分で計画を作り直すので、統合のときに
// すべての台が同じ計画を切ったことをこれで確かめる。
func planDigest(in shardInput, l shardLayout) string {
	h := sha256.New()
	fmt.Fprintf(h, "n=%d pool=%d margin=%g\n", in.N, in.Pool, in.Margin)
	for _, j := range in.Plan {
		fmt.Fprintf(h, "%d\t%s\t%s\t%s\t%g\t%d\n", j.Index, j.Class, j.Scenario, in.Rate(j), in.Weight(j), l.Assign[j.Index])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// mergeSummaries は shard ごとの summary を 1 つにまとめる。取りこぼしや重複を verdict に
// 混ぜないため、台の揃い方、同じ計画と同じ netstack と同じ agent の実装であること、仕事の Index が計画の全体を
// 過不足なく覆うことを確かめ、問題は MergeProblems に入れる。wall は台の中で最も長いもの
// (台は並行に流れる)。
func mergeSummaries(parts []*summary) *summary {
	var problems []string
	m := &summary{}
	seenShard := map[string]bool{}
	seenIdx := map[int]string{}
	want, digest, netstack, impl, first := 0, "", "", "", true
	var plan []string
	name := func(i int) string {
		if i >= 0 && i < len(plan) {
			return fmt.Sprintf("job %d, %s,", i, plan[i])
		}
		return fmt.Sprintf("job %d", i)
	}
	for i, p := range parts {
		if p.Shard == "" || p.PlanJobs == 0 || p.PlanDigest == "" {
			problems = append(problems, fmt.Sprintf("part %d has no shard, plan size or plan digest: it was not made by run -shard", i+1))
			continue
		}
		if first {
			want, digest, netstack, impl, plan, first = p.PlanJobs, p.PlanDigest, p.Netstack, implOrGo(p.AgentImpl), p.PlanScenarios, false
			m.FromGo = p.FromGo
		}
		if seenShard[p.Shard] {
			problems = append(problems, "shard "+p.Shard+" given twice")
		}
		seenShard[p.Shard] = true
		if want != p.PlanJobs {
			problems = append(problems, fmt.Sprintf("shard %s was cut from a plan of %d jobs, not %d", p.Shard, p.PlanJobs, want))
		}
		if digest != p.PlanDigest {
			problems = append(problems, fmt.Sprintf("shard %s was cut from another plan: digest %s, not %s", p.Shard, p.PlanDigest, digest))
		}
		if netstack != p.Netstack {
			problems = append(problems, fmt.Sprintf("shard %s ran with netstack %s, not %s", p.Shard, p.Netstack, netstack))
		}
		if impl != implOrGo(p.AgentImpl) {
			problems = append(problems, fmt.Sprintf("shard %s ran with agent %s, not %s", p.Shard, implOrGo(p.AgentImpl), impl))
		}
		if n := shardCount(p.Shard); n != len(parts) {
			problems = append(problems, fmt.Sprintf("shard %s, but %d parts given", p.Shard, len(parts)))
		}
		for _, r := range p.Results {
			if prev, dup := seenIdx[r.Index]; dup {
				problems = append(problems, fmt.Sprintf("job %d, %s, ran in shards %s and %s", r.Index, r.Scenario, prev, p.Shard))
			}
			seenIdx[r.Index] = p.Shard
		}
		m.Warnings = append(m.Warnings, prefixAll("shard "+p.Shard+": ", p.Warnings)...)
		m.Results = append(m.Results, p.Results...)
		m.LeftoverNS = append(m.LeftoverNS, p.LeftoverNS...)
		m.LeftoverWorkdirs = append(m.LeftoverWorkdirs, p.LeftoverWorkdirs...)
		m.LeftoverProcs = append(m.LeftoverProcs, p.LeftoverProcs...)
		m.LeftoverLinks = append(m.LeftoverLinks, p.LeftoverLinks...)
		m.LeftoverFailures = append(m.LeftoverFailures, prefixAll("shard "+p.Shard+": ", p.LeftoverFailures)...)
		m.Interrupted = m.Interrupted || p.Interrupted
		m.VMCPUSeconds += p.VMCPUSeconds
		m.VCPUs += p.VCPUs
		m.MemTotalKB += p.MemTotalKB
		if p.WallSec > m.WallSec {
			m.WallSec = p.WallSec
		}
		if p.PeakMemUsedKB > m.PeakMemUsedKB {
			m.PeakMemUsedKB = p.PeakMemUsedKB
		}
		if p.PeakLoad1 > m.PeakLoad1 {
			m.PeakLoad1 = p.PeakLoad1
		}
		if m.StartedAt.IsZero() || p.StartedAt.Before(m.StartedAt) {
			m.StartedAt = p.StartedAt
		}
		m.Scenarios, m.Manifest, m.Parallel, m.Repeat = p.Scenarios, p.Manifest, p.Parallel, p.Repeat
	}
	if len(plan) != want {
		problems = append(problems, fmt.Sprintf("the plan lists %d scenarios for %d jobs", len(plan), want))
	}
	for i := 0; i < want; i++ {
		if _, ok := seenIdx[i]; !ok {
			problems = append(problems, name(i)+" ran in no shard; the suite is incomplete")
			m.MissingJobs++
		}
	}
	var outside []int
	for i := range seenIdx {
		if i < 0 || i >= want {
			outside = append(outside, i)
		}
	}
	sort.Ints(outside)
	for _, i := range outside {
		problems = append(problems, fmt.Sprintf("job %d is outside the plan of %d jobs", i, want))
	}
	sort.Slice(m.Results, func(i, j int) bool { return m.Results[i].Index < m.Results[j].Index })
	m.PlanJobs, m.PlanDigest, m.PlanScenarios, m.Netstack, m.AgentImpl = want, digest, plan, netstack, impl
	m.Shard = fmt.Sprintf("merged/%d", len(parts))
	finishSummary(m)
	m.MergeProblems = problems
	for _, p := range parts {
		if p.RateMarginSec > m.RateMarginSec {
			m.RateMarginSec = p.RateMarginSec
		}
	}
	var overlaps []string
	m.RateWindow, overlaps = rateWindowCheck(m.Results, seenIdx, m.RateMarginSec)
	m.Warnings = append(m.Warnings, overlaps...)
	return m
}

// guarded は、別の台で時間窓に重なってはならない仕事か。
func guarded(r jobResult) bool {
	if r.Class.exclusive() {
		return r.Rate != rateMeasure && r.Rate != rateGroup && r.Rate != rateOverlap
	}
	return r.Rate == rateFlood
}

// rateWindowCheck は実際の開始の時刻と所要時間で、rate=measure の仕事が走った間に別の台の守る仕事が
// 重なったかを確かめる。計画は見積もりで作るので、実際の時刻で確かめるのはここだけである。
// 1 行の要約と、重なった組ごとの警告を返す。rate=measure の仕事が無ければ空。
func rateWindowCheck(results []jobResult, shardOf map[int]string, margin float64) (string, []string) {
	var measure []jobResult
	for _, r := range results {
		if r.Rate == rateMeasure && r.DurationSec > 0 {
			measure = append(measure, r)
		}
	}
	if len(measure) == 0 {
		return "", nil
	}
	span := func(r jobResult) (float64, float64) {
		a := float64(r.StartedAt.UnixNano()) / 1e9
		return a, a + r.DurationSec
	}
	var warns []string
	nearest, nearName := -1.0, ""
	for _, r := range results {
		if !guarded(r) || r.DurationSec <= 0 {
			continue
		}
		rs, re := span(r)
		for _, w := range measure {
			if shardOf[r.Index] == shardOf[w.Index] {
				continue
			}
			ws, we := span(w)
			if ov := min(re, we) - max(rs, ws); ov > 0 {
				warns = append(warns, fmt.Sprintf("rate window overlapped: %q in shard %s ran for %.1f s during %q in shard %s",
					r.Scenario, shardOf[r.Index], ov, w.Scenario, shardOf[w.Index]))
				continue
			}
			gap := max(rs-we, ws-re)
			if nearest < 0 || gap < nearest {
				nearest, nearName = gap, fmt.Sprintf("%q in shard %s", r.Scenario, shardOf[r.Index])
			}
		}
	}
	if len(warns) > 0 {
		return fmt.Sprintf("%d overlaps of a guarded job of another shard with a rate=measure job; see the warnings", len(warns)), warns
	}
	if nearest < 0 {
		return "no guarded job ran in another shard", nil
	}
	line := fmt.Sprintf("no guarded job of another shard overlapped it; the nearest, %s, was %.1f s away", nearName, nearest)
	if nearest < margin {
		line += fmt.Sprintf(", inside the %.0f s margin", margin)
	}
	return line, nil
}

func shardCount(s string) int {
	_, n, err := parseShard(s)
	if err != nil {
		return -1
	}
	return n
}

func prefixAll(p string, in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = p + s
	}
	return out
}
