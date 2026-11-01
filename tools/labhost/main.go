// labhost はラボの VM の中でシナリオを流す道具 (試作)。VM は OS とカーネルを与える Lab Host で、
// テストを隔てる単位は VM ではなく Sandbox である、という筋書きを確かめるために作った。
// 1 つの Sandbox は ID、5 つの network namespace、作業ディレクトリ、そして自分が起こした
// プロセスを持つ。シナリオ自身は lab/*.sh のまま動かし、Sandbox の値を環境変数で渡す。
//
//	labhost run -parallel 4 -repeat 8 "e2e.sh kernel"
//	labhost run -parallel 4 "e2e.sh kernel" "ipv6.sh kernel"
//	labhost gc
//	labhost list
//
// VM の中で root として実行する。ホストでのビルドと VM への導入は lab/lab build が行う。
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultPrefix = "wgft-"
	defaultRoot   = "/tmp/wgft-lab"
	defaultRepo   = "/wgft"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "labhost: runs only on Linux, inside a lab VM")
		os.Exit(2)
	}
	sub := os.Args[1]
	args := os.Args[2:]
	var err error
	switch sub {
	case "run":
		err = cmdRun(args)
	case "merge":
		err = cmdMerge(args)
	case "gc":
		err = cmdGC(args)
	case "list":
		err = cmdList(args)
	case "create":
		err = cmdCreate(args)
	case "destroy":
		err = cmdDestroy(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "labhost: "+err.Error())
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage: labhost <command> [flags]

  run [flags] "<script> <args...>"...  run scenarios in disposable sandboxes
  run [flags] all                      run every job of `+manifestPath+`: parallel pool, then the
                                       exclusive jobs one at a time
  run -shard K/N [-durations FILE] all  run only shard K of N of that plan; every exclusive job
                                       stays alone within its shard's VM; exclusive jobs of other
                                       shards are planned around the rate=measure jobs
  merge [-out DIR] [-go-summary FILE] SUMMARY...
                                       merge the summary.json of all N shards into one verdict;
                                       a rust run's agent=go jobs take their results from the go
                                       configuration's merged summary given by -go-summary
  gc [flags]                           remove leftovers of dead runs: namespaces, processes, workdirs
  list                                 list the sandboxes that exist now
  create [-id ID]                      create one sandbox and print its environment
  destroy <ID>                         destroy one sandbox

run flags: -parallel N -repeat R -timeout DUR -keep-failed -no-gc -out DIR -prefix P -root DIR
           -repo DIR -manifest FILE -with-optional -run-lock PATH -wait DUR -shard K/N -durations FILE
           -rate-margin DUR
gc flags:  -prefix P -root DIR -keep-workdirs -run-lock PATH -wait DUR

One run per Lab Host VM: run and gc take a lock, `+defaultRunLock+`.lock by default, and refuse at
once if another run holds it; -wait DUR queues instead. create and destroy act on the one sandbox
you name and do not take the lock, so do not point them at a sandbox a run owns.
A run exits non-zero if any job failed, if it was interrupted, or if anything, a namespace, process,
workdir or link, was left behind: cleaning up is the harness's own job.
WGFT_LAB_AGENT_IMPL, go by default or rust, names the userspace-mode agent the scenarios run;
with rust, run all leaves out the manifest's agent=go jobs, which run the Go agent in any case.
`)
}

// jobResult は 1 回のシナリオの結果。PASS、FAIL、SKIP の行数も数える。旧来の流し方と
// 同じ確認が流れたことを、行数の一致で確かめられるようにするため。
type jobResult struct {
	Index       int           `json:"index"`
	Class       class         `json:"class"`
	Rate        string        `json:"rate,omitempty"` // manifest の rate=。統合のときに時間窓の実際の重なりを見るため
	PassLines   int           `json:"pass_lines"`
	FailLines   int           `json:"fail_lines"`
	SkipLines   int           `json:"skip_lines"`
	Scenario    string        `json:"scenario"`
	SandboxID   string        `json:"sandbox_id"`
	StartedAt   time.Time     `json:"started_at"`
	DurationSec float64       `json:"duration_sec"`
	Exit        int           `json:"exit"`
	TimedOut    bool          `json:"timed_out"`
	Err         string        `json:"error,omitempty"`
	SetupErr    string        `json:"setup_error,omitempty"`
	Log         string        `json:"log"`
	Cleanup     DestroyReport `json:"cleanup"`
}

// scenarioVerdict は 1 つのシナリオが出した PASS、FAIL、SKIP の行数の合計。
type scenarioVerdict struct {
	Scenario  string `json:"scenario"`
	Runs      int    `json:"runs"`
	PassLines int    `json:"pass_lines"`
	FailLines int    `json:"fail_lines"`
	SkipLines int    `json:"skip_lines"`
}

// fromGoVerdict は rust の組が流さなかった agent=go の仕事について、go の組の結果をまとめたもの。
// Runs が 0 なら、渡された go の組の summary にその仕事が無かった。
type fromGoVerdict struct {
	Scenario  string `json:"scenario"`
	Runs      int    `json:"runs"`
	Failed    int    `json:"failed"`
	PassLines int    `json:"pass_lines"`
	FailLines int    `json:"fail_lines"`
	SkipLines int    `json:"skip_lines"`
}

// summary は 1 回の run 全体の記録。
type summary struct {
	Scenarios        []string          `json:"scenarios"`
	Shard            string            `json:"shard,omitempty"`            // "K/N" of run -shard, "merged/N" after merge
	PlanJobs         int               `json:"plan_jobs,omitempty"`        // jobs in the whole plan before -shard cut it
	PlanDigest       string            `json:"plan_digest,omitempty"`      // hash of the cut plan; every shard of one run has the same
	PlanScenarios    []string          `json:"plan_scenarios,omitempty"`   // the whole plan's scenarios by job index, to name a missing job
	Netstack         string            `json:"netstack"`                   // WGFT_AGENT_NETSTACK the scenarios ran with; "default" when unset
	AgentImpl        string            `json:"agent_impl"`                 // WGFT_LAB_AGENT_IMPL the scenarios ran with: go or rust
	FromGo           []string          `json:"from_go,omitempty"`          // agent=go jobs a rust run left out; their results come from the go configuration
	FromGoVerdicts   []fromGoVerdict   `json:"from_go_verdicts,omitempty"` // merge -go-summary: the go configuration's results for FromGo
	MissingJobs      int               `json:"missing_jobs,omitempty"`     // merge: jobs of the plan that ran in no shard
	MergeProblems    []string          `json:"merge_problems,omitempty"`   // merge: missing, duplicated or mismatched shards
	RateMarginSec    float64           `json:"rate_margin_sec,omitempty"`  // -rate-margin of the shards
	RateWindow       string            `json:"rate_window,omitempty"`      // merge: what the real start times say about the rate window
	Manifest         string            `json:"manifest,omitempty"`
	ParallelJobs     int               `json:"parallel_jobs"`
	ExclusiveJobs    int               `json:"exclusive_jobs"`
	Verdicts         []scenarioVerdict `json:"verdicts,omitempty"`
	TotalPassLines   int               `json:"total_pass_lines"`
	TotalFailLines   int               `json:"total_fail_lines"`
	TotalSkipLines   int               `json:"total_skip_lines"`
	SlowestJobSec    float64           `json:"slowest_job_sec"`
	Parallel         int               `json:"parallel"`
	Repeat           int               `json:"repeat"`
	Jobs             int               `json:"jobs"`
	Pass             int               `json:"pass"`
	Fail             int               `json:"fail"`
	StartedAt        time.Time         `json:"started_at"`
	WallSec          float64           `json:"wall_sec"`
	VCPUs            int               `json:"vcpus"`
	VMCPUSeconds     float64           `json:"vm_cpu_seconds"`
	MemTotalKB       int               `json:"mem_total_kb"`
	PeakMemUsedKB    int               `json:"peak_mem_used_kb"`
	PeakLoad1        float64           `json:"peak_load1"`
	Interrupted      bool              `json:"interrupted"`
	LeftoverNS       []string          `json:"leftover_namespaces,omitempty"`
	LeftoverWorkdirs []string          `json:"leftover_workdirs,omitempty"`
	LeftoverProcs    []string          `json:"leftover_processes,omitempty"`
	LeftoverLinks    []string          `json:"leftover_links,omitempty"`
	LeftoverFailures []string          `json:"leftover_failures,omitempty"`
	Warnings         []string          `json:"warnings,omitempty"`
	Results          []jobResult       `json:"results"`
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	parallel := fs.Int("parallel", 1, "how many sandboxes run at once")
	repeat := fs.Int("repeat", 1, "how many times to run the whole scenario list")
	timeout := fs.Duration("timeout", 10*time.Minute, "wall-clock limit for one scenario")
	keepFailed := fs.Bool("keep-failed", false, "keep the workdir of a failed run")
	noGC := fs.Bool("no-gc", false, "do not collect leftovers of dead runs before starting")
	out := fs.String("out", "", "directory for the summary and the logs; default <root>/run-<timestamp>")
	prefix := fs.String("prefix", defaultPrefix, "namespace name prefix")
	root := fs.String("root", defaultRoot, "directory holding the sandbox workdirs")
	repo := fs.String("repo", defaultRepo, "repository root inside the VM")
	manifest := fs.String("manifest", "", "manifest for `run all`; default <repo>/"+manifestPath)
	runLockPath := fs.String("run-lock", defaultRunLock, "base path of the Lab Host lock that keeps one run per VM")
	wait := fs.Duration("wait", 0, "wait this long for the Lab Host lock instead of refusing at once")
	withOptional := fs.Bool("with-optional", false, "also run the manifest's default=no jobs")
	shardSpec := fs.String("shard", "", "run only shard K of N, written K/N, of the plan of `all`, cut by -durations or the manifest's weights")
	rateMargin := fs.Duration("rate-margin", 30*time.Second, "with -shard, how long after the estimated end of the rate window an exclusive job of another shard may start")
	durations := fs.String("durations", "", "summary.json of an earlier run; its job durations balance -shard")
	if err := fs.Parse(args); err != nil {
		return err
	}
	scenarios := fs.Args()
	if len(scenarios) == 0 {
		return fmt.Errorf("no scenario given; e.g. \"e2e.sh kernel\", or \"all\" for the manifest")
	}
	if err := validateRunCounts(*parallel, *repeat); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	impl, err := agentImplName()
	if err != nil {
		return err
	}
	// rust の run は Rust の wgft が入っていなければ、どの確認も Rust の agent を起動できずに失敗するだけなので、流す前に止める
	if impl == agentImplRust {
		if fi, err := os.Stat(rustWgft); err != nil || fi.Mode()&0o111 == 0 {
			return fmt.Errorf("WGFT_LAB_AGENT_IMPL=rust, but %s is not an installed executable; build with WGFT_LAB_AGENT_IMPL=rust lab/lab build", rustWgft)
		}
	}
	// "all" は lab/suite.txt の全体。分類は manifest が持ち、それ以外の指定は parallel として扱う
	runAll := len(scenarios) == 1 && scenarios[0] == "all"
	manifestFile := *manifest
	if manifestFile == "" {
		manifestFile = filepath.Join(*repo, manifestPath)
	}
	var plan []jobResult // Index, Class, Scenario だけを先に決める
	var fromGo []string  // rust の run が計画から外した agent=go の仕事
	manifestJobs := map[string]job{}
	if runAll {
		jobs, err := loadManifest(manifestFile)
		if err != nil {
			return err
		}
		for _, j := range jobs {
			manifestJobs[j.Scenario] = j
		}
		n := 0
		for r := 0; r < *repeat; r++ {
			for _, j := range jobs {
				if !j.Default && !*withOptional {
					continue
				}
				// agent=go の仕事はどの組でも Go の agent を動かすので、rust の組では流さず go の組から取る
				if j.GoAgent && impl == agentImplRust {
					if r == 0 {
						fromGo = append(fromGo, j.Scenario)
					}
					continue
				}
				plan = append(plan, jobResult{Index: n, Class: j.Class, Scenario: j.Scenario, Rate: j.Rate})
				n++
			}
		}
	} else {
		n := 0
		for r := 0; r < *repeat; r++ {
			for _, sc := range scenarios {
				plan = append(plan, jobResult{Index: n, Class: classParallel, Scenario: sc})
				n++
			}
		}
	}
	// 流すジョブが 1 つも無い run を成功にしない。マージの前の関門に使う道具なので、
	// 「流したつもりで exit 0」を作らない
	if len(plan) == 0 {
		return fmt.Errorf("nothing to run: the plan is empty; check the manifest's default column, or pass -with-optional")
	}
	planJobs, shardName, digest := 0, "", ""
	var planScenarios, shardWarnings []string
	if *shardSpec != "" {
		if !runAll {
			return fmt.Errorf("-shard cuts the plan of `all`; it does not apply to named scenarios")
		}
		k, n, err := parseShard(*shardSpec)
		if err != nil {
			return err
		}
		weights := map[string]float64{}
		if *durations != "" {
			if weights, err = loadDurations(*durations); err != nil {
				return err
			}
		}
		in := shardInput{
			Plan: plan,
			Weight: func(j jobResult) float64 {
				if w := weights[j.Scenario]; w > 0 {
					return w
				}
				if w := manifestJobs[j.Scenario].Weight; w > 0 {
					return w
				}
				return defaultWeightSec
			},
			Rate:   func(j jobResult) string { return manifestJobs[j.Scenario].Rate },
			N:      n,
			Pool:   *parallel,
			Margin: rateMargin.Seconds(),
		}
		l := assignShards(in)
		planJobs, shardName, digest = len(plan), fmt.Sprintf("%d/%d", k, n), planDigest(in, l)
		for _, j := range plan {
			planScenarios = append(planScenarios, j.Scenario)
		}
		var mine []jobResult
		for _, j := range plan {
			if l.Assign[j.Index] == k-1 {
				mine = append(mine, j)
			}
		}
		fmt.Printf("shard %s: %d of %d jobs; estimated seconds per shard: %s; plan digest %s\n", shardName, len(mine), len(plan), fmtFloats(l.Est), digest)
		if l.RateVM >= 0 {
			fmt.Printf("shard %s: rate window in shard %d/%d, estimated from %.0f s to %.0f s; guarded jobs of other shards are planned at least %.0f s away from it\n",
				shardName, l.RateVM+1, n, l.Window[0], l.Window[1], in.Margin)
		}
		for _, p := range l.Problems {
			msg := "rate window not kept: " + p
			fmt.Fprintln(os.Stderr, "labhost: warning: "+msg)
			shardWarnings = append(shardWarnings, msg)
		}
		if len(mine) == 0 {
			return fmt.Errorf("shard %s has no job; use fewer shards", shardName)
		}
		plan = shardOrder(mine, in.Rate)
	} else if *durations != "" {
		return fmt.Errorf("-durations balances -shard; give -shard too")
	}
	outDir := *out
	if outDir == "" {
		outDir = filepath.Join(*root, "run-"+time.Now().Format("20060102-150405"))
	}
	if err := os.MkdirAll(filepath.Join(outDir, "logs"), 0o755); err != nil {
		return err
	}
	// 単独で流す分類が約束する「VM の中で単独」を守るため、run は Lab Host ごとのロックを
	// gc より先に取り、最後まで持つ。持ち主が SIGKILL で死んでもカーネルが解放する
	lock, err := acquireRunLock(*runLockPath, *wait)
	if err != nil {
		return err
	}
	defer lock.Release()

	if !*noGC {
		rep := GC(*prefix, *root, false)
		b, _ := json.Marshal(rep)
		fmt.Printf("gc: %s\n", b)
	}
	// userspace モードのシナリオは非 root の wgftlab で server を動かす。useradd は VM 全体の
	// 資源で、同時に呼ぶと /etc/passwd のロックで失敗しうるので、流す前にここで 1 回だけ作る
	if err := ensureLabUser(); err != nil {
		fmt.Fprintln(os.Stderr, "labhost: warning: "+err.Error())
	}

	margin := 0.0
	if shardName != "" {
		margin = rateMargin.Seconds()
	}
	sum := summary{Shard: shardName, PlanJobs: planJobs, RateMarginSec: margin, PlanDigest: digest, PlanScenarios: planScenarios, Netstack: netstackName(),
		AgentImpl: impl, FromGo: fromGo, Scenarios: scenarios, Parallel: *parallel, Repeat: *repeat, StartedAt: time.Now(), Warnings: shardWarnings}
	sum.VCPUs = numCPU()
	sum.MemTotalKB = meminfoKB("MemTotal")

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	// 2 度目の SIGINT は即座に降りる。1 度目は後片付けのために待つ
	go func() {
		<-ctx.Done()
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT)
		<-ch
		fmt.Fprintln(os.Stderr, "labhost: second interrupt: leaving leftovers for gc")
		os.Exit(130)
	}()

	// 資源の使われ方を測る。ピークのメモリと load average は Sandbox の同時実行数の限界を見るため
	mctx, mstop := context.WithCancel(context.Background())
	var mwg sync.WaitGroup
	mwg.Add(1)
	peakUsed, peakLoad := 0, 0.0
	var pmu sync.Mutex
	go func() {
		defer mwg.Done()
		f, err := os.Create(filepath.Join(outDir, "metrics.csv"))
		if err != nil {
			return
		}
		defer f.Close()
		fmt.Fprintln(f, "unix,mem_used_kb,mem_total_kb,load1,sandboxes")
		cpu0 := cpuSeconds()
		for {
			used := sum.MemTotalKB - meminfoKB("MemAvailable")
			load := load1()
			n := countSandboxNS(*prefix)
			pmu.Lock()
			if used > peakUsed {
				peakUsed = used
			}
			if load > peakLoad {
				peakLoad = load
			}
			pmu.Unlock()
			fmt.Fprintf(f, "%d,%d,%d,%.2f,%d\n", time.Now().Unix(), used, sum.MemTotalKB, load, n)
			select {
			case <-mctx.Done():
				sum.VMCPUSeconds = cpuSeconds() - cpu0
				return
			case <-time.After(time.Second):
			}
		}
	}()

	// 日程は 2 つの分類だけ。並列に流せる仕事をプール (大きさ parallel) で流し、
	// そのあと単独で流す仕事を 1 つずつ流す。単独の仕事は RSS や到達頻度を測るので、
	// 隣に何も居ない状態で流す
	var parallelPlan, exclusivePlan []jobResult
	for _, j := range plan {
		if j.Class.exclusive() {
			exclusivePlan = append(exclusivePlan, j)
		} else {
			parallelPlan = append(parallelPlan, j)
		}
	}
	sum.ParallelJobs, sum.ExclusiveJobs = len(parallelPlan), len(exclusivePlan)
	fmt.Printf("plan: %d parallel jobs, pool of %d; %d exclusive jobs, one at a time\n",
		len(parallelPlan), *parallel, len(exclusivePlan))
	// VM 全体の socket buffer の基準を、プールの前と単独の仕事の前に確かめる。単独の仕事の前にも
	// 見るのは、lifecycle.sh の check 12 が値を下げたまま止まると、後の単独の仕事に効くため
	sbw := newSockbufWatch()
	warn := func(before string) {
		if msg := sbw.check(before); msg != "" {
			fmt.Fprintln(os.Stderr, "labhost: warning: "+msg)
			sum.Warnings = append(sum.Warnings, msg)
		}
	}
	if len(parallelPlan) > 0 {
		warn("the pool")
	}

	results := make(chan jobResult, len(plan)+1)
	jobs := make(chan jobResult)
	var wg sync.WaitGroup
	for i := 0; i < *parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				results <- runOne(ctx, j, *prefix, *root, *repo, outDir, *timeout, *keepFailed)
			}
		}()
	}
	go func() {
		for _, j := range parallelPlan {
			select {
			case <-ctx.Done():
				close(jobs)
				return
			case jobs <- j:
			}
		}
		close(jobs)
	}()
	wg.Wait()
	for _, j := range exclusivePlan {
		if ctx.Err() != nil {
			break
		}
		warn(j.Scenario)
		results <- runOne(ctx, j, *prefix, *root, *repo, outDir, *timeout, *keepFailed)
	}
	close(results)
	mstop()
	mwg.Wait()

	for r := range results {
		sum.Results = append(sum.Results, r)
	}
	sort.Slice(sum.Results, func(i, j int) bool { return sum.Results[i].Index < sum.Results[j].Index })
	nPar, nExcl := sum.ParallelJobs, sum.ExclusiveJobs
	finishSummary(&sum)
	sum.ParallelJobs, sum.ExclusiveJobs = nPar, nExcl
	if runAll {
		sum.Manifest = manifestFile
	}
	sum.WallSec = time.Since(sum.StartedAt).Seconds()
	sum.PeakMemUsedKB, sum.PeakLoad1 = peakUsed, peakLoad
	sum.Interrupted = ctx.Err() != nil
	sum.LeftoverNS, sum.LeftoverWorkdirs, sum.LeftoverProcs, sum.LeftoverLinks = leakCheck(*prefix, *root)
	sum.LeftoverFailures = leftoverFailures(&sum)

	b, _ := json.MarshalIndent(sum, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "summary.json"), b, 0o644); err != nil {
		return err
	}
	printSummary(&sum, outDir)
	// 後片付けに漏れがあれば、確認がすべて PASS でも run は失敗である。片付けの正しさは
	// harness 自身の責任で、漏れは次の run を汚す。終了コードはシナリオの失敗と同じ 1 にする。
	// ラボの道具は非 0 を等しく失敗として扱い、別の番号は「失敗ではない」と読まれかねない
	if sum.Fail > 0 || sum.Interrupted || len(sum.LeftoverFailures) > 0 {
		os.Exit(1)
	}
	return nil
}

// finishSummary は Results から件数、シナリオごとの行数、最も遅い仕事を数え直す。
// shard の統合でも同じ数え方を使うので、1 台で流した run と同じ形の summary になる。
func finishSummary(sum *summary) {
	for _, r := range sum.Results {
		if r.Exit == 0 && r.SetupErr == "" {
			sum.Pass++
		} else {
			sum.Fail++
		}
	}
	// シナリオごとの PASS / FAIL / SKIP の行数。旧来の流し方との突き合わせに使う
	byScenario := map[string]*scenarioVerdict{}
	var order []string
	for _, r := range sum.Results {
		v, ok := byScenario[r.Scenario]
		if !ok {
			v = &scenarioVerdict{Scenario: r.Scenario}
			byScenario[r.Scenario] = v
			order = append(order, r.Scenario)
		}
		v.Runs++
		v.PassLines += r.PassLines
		v.FailLines += r.FailLines
		v.SkipLines += r.SkipLines
		sum.TotalPassLines += r.PassLines
		sum.TotalFailLines += r.FailLines
		sum.TotalSkipLines += r.SkipLines
		if r.DurationSec > sum.SlowestJobSec {
			sum.SlowestJobSec = r.DurationSec
		}
	}
	sort.Strings(order)
	for _, k := range order {
		sum.Verdicts = append(sum.Verdicts, *byScenario[k])
	}
	sum.Jobs = len(sum.Results)
	sum.ParallelJobs, sum.ExclusiveJobs = 0, 0
	for _, r := range sum.Results {
		if r.Class.exclusive() {
			sum.ExclusiveJobs++
		} else {
			sum.ParallelJobs++
		}
	}
}

// validateRunCounts は -parallel と -repeat の範囲を確かめる。-parallel 0 は worker を 1 つも
// 作らないので parallel のジョブが流れず、-repeat 0 は plan を空にするので、どちらも何も確かめずに
// exit 0 になる。入口で弾く。
func validateRunCounts(parallel, repeat int) error {
	if parallel < 1 {
		return fmt.Errorf("-parallel must be at least 1, got %d", parallel)
	}
	if repeat < 1 {
		return fmt.Errorf("-repeat must be at least 1, got %d", repeat)
	}
	return nil
}

// runOne は Sandbox を 1 つ作り、シナリオを流し、後片付けする。
func runOne(ctx context.Context, planned jobResult, prefix, root, repo, outDir string, timeout time.Duration, keepFailed bool) jobResult {
	res := planned
	res.StartedAt = time.Now()
	index, scenario := res.Index, res.Scenario
	fields := strings.Fields(scenario)
	if len(fields) == 0 {
		res.SetupErr = "empty scenario"
		return res
	}
	id, err := newID()
	if err != nil {
		res.SetupErr = err.Error()
		return res
	}
	res.SandboxID = id
	if ctx.Err() != nil {
		res.SetupErr = "interrupted before start"
		return res
	}
	s, err := CreateSandbox(prefix, root, repo, id)
	if err != nil {
		res.SetupErr = err.Error()
		res.DurationSec = time.Since(res.StartedAt).Seconds()
		return res
	}
	logName := fmt.Sprintf("%03d-%s-%s.log", index, strings.ReplaceAll(scenario, " ", "-"), id)
	res.Log = filepath.Join(outDir, "logs", logName)
	r := s.Run(ctx, fields[0], fields[1:], res.Log, timeout)
	res.Exit, res.TimedOut, res.Err = r.Exit, r.TimedOut, r.Err
	res.DurationSec = time.Since(res.StartedAt).Seconds()
	res.PassLines, res.FailLines, res.SkipLines = countVerdicts(res.Log)
	keep := keepFailed && res.Exit != 0
	res.Cleanup = s.Destroy(keep)
	verdict := "PASS"
	if res.Exit != 0 {
		verdict = "FAIL"
	}
	fmt.Printf("%s  %-28s id=%s %5.1fs exit=%d lines=%d/%d/%d\n",
		verdict, scenario, id, res.DurationSec, res.Exit, res.PassLines, res.FailLines, res.SkipLines)
	return res
}

func cmdGC(args []string) error {
	fs := flag.NewFlagSet("gc", flag.ExitOnError)
	prefix := fs.String("prefix", defaultPrefix, "namespace name prefix")
	root := fs.String("root", defaultRoot, "directory holding the sandbox workdirs")
	keep := fs.Bool("keep-workdirs", false, "keep the workdirs of the sandboxes it collects")
	runLockPath := fs.String("run-lock", defaultRunLock, "base path of the Lab Host lock that keeps one run per VM")
	wait := fs.Duration("wait", 0, "wait this long for the Lab Host lock instead of refusing at once")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	// gc の走査は prefix だけを頼りにするので、同じ prefix で別の -root を使う run が居ると、
	// 生きている Sandbox の作業ディレクトリのロックを見つけられない。run と同じロックを取ることで、
	// gc が生きている netns を消す道を塞ぐ
	lock, err := acquireRunLock(*runLockPath, *wait)
	if err != nil {
		return err
	}
	defer lock.Release()
	rep := GC(*prefix, *root, *keep)
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	if len(rep.Errs) > 0 {
		return fmt.Errorf("gc left problems behind")
	}
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	prefix := fs.String("prefix", defaultPrefix, "namespace name prefix")
	root := fs.String("root", defaultRoot, "directory holding the sandbox workdirs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	names, err := listNamespaces()
	if err != nil {
		return err
	}
	byID := map[string][]string{}
	for _, n := range names {
		if id, role, ok := parseNSName(*prefix, n); ok {
			byID[id] = append(byID[id], role)
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		var pids int
		for _, r := range allRoles() {
			p, _ := nsPids(nsName(*prefix, id, r))
			pids += len(p)
		}
		fmt.Printf("%s roles=%s pids=%d workdir=%s\n", id, strings.Join(byID[id], ","), pids, filepath.Join(*root, id))
	}
	if len(ids) == 0 {
		fmt.Println("no sandbox")
	}
	return nil
}

func cmdCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	id := fs.String("id", "", "sandbox id; default random")
	prefix := fs.String("prefix", defaultPrefix, "namespace name prefix")
	root := fs.String("root", defaultRoot, "directory holding the sandbox workdirs")
	repo := fs.String("repo", defaultRepo, "repository root inside the VM")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	sid := *id
	if sid == "" {
		var err error
		if sid, err = newID(); err != nil {
			return err
		}
	}
	s, err := CreateSandbox(*prefix, *root, *repo, sid)
	if err != nil {
		return err
	}
	// ロックは持ち主が終わると消える。create は対話用なので、ロックを放してから抜ける
	// (gc と destroy がこの Sandbox を片付けられるようにする)
	if s.lock != nil {
		s.lock.Release()
		s.lock = nil
	}
	for _, e := range s.Env() {
		fmt.Println("export " + e)
	}
	return nil
}

func cmdDestroy(args []string) error {
	fs := flag.NewFlagSet("destroy", flag.ExitOnError)
	prefix := fs.String("prefix", defaultPrefix, "namespace name prefix")
	root := fs.String("root", defaultRoot, "directory holding the sandbox workdirs")
	keep := fs.Bool("keep-workdir", false, "keep the workdir")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: labhost destroy <ID>")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	id := fs.Arg(0)
	s := &Sandbox{ID: id, Prefix: *prefix, Dir: filepath.Join(*root, id), NS: map[string]string{}}
	for _, r := range allRoles() {
		s.NS[r] = nsName(*prefix, id, r)
	}
	rep := s.Destroy(*keep)
	b, _ := json.MarshalIndent(rep, "", "  ")
	fmt.Println(string(b))
	return nil
}

// ensureLabUser は userspace モードのシナリオが使う wgftlab を、流す前に 1 回だけ作る。
func ensureLabUser() error {
	if err := exec.Command("id", "wgftlab").Run(); err == nil {
		return nil
	}
	out, err := exec.Command("useradd", "--system", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "wgftlab").CombinedOutput()
	if err != nil {
		return fmt.Errorf("useradd wgftlab: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// leakCheck は run のあとに残ったものを数え上げる。prefix の netns、作業ディレクトリ、
// wgft の関わるプロセス、root netns に残った veth。
func leakCheck(prefix, root string) (ns, workdirs, procs, links []string) {
	names, _ := listNamespaces()
	for _, n := range names {
		if _, _, ok := parseNSName(prefix, n); ok {
			ns = append(ns, n)
		}
	}
	// Sandbox の作業ディレクトリは sandbox.lock を持つ。この印で見分けるので、-out で指定した
	// 実行ごとの置き場や、人が置いた別のディレクトリを取り違えない
	if ents, err := os.ReadDir(root); err == nil {
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			if _, err := os.Stat(filepath.Join(root, e.Name(), "sandbox.lock")); err != nil {
				continue
			}
			workdirs = append(workdirs, e.Name())
		}
	}
	// VM 全体に wgft/echo/ppecho/socat が残っていないか。数えるだけで、止めはしない
	watch := map[string]bool{"wgft": true, "echo": true, "ppecho": true, "socat": true}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, e := range ents {
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			if name := procName(pid); watch[name] {
				procs = append(procs, fmt.Sprintf("%d(%s)", pid, name))
			}
		}
	}
	if out, err := exec.Command("ip", "-br", "link").Output(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			name := strings.SplitN(f[0], "@", 2)[0]
			switch name {
			case "pub0", "pub1", "wan0", "lan0", "lan1", "br0", "wgft0", "eth0":
				links = append(links, name)
			}
		}
	}
	return ns, workdirs, procs, links
}

// leftoverFailures は summary から後片付けの漏れを数え上げる。純粋な関数なので、判定だけを
// 単体テストで確かめられる。-keep-failed で意図して残した作業ディレクトリは漏れではないので、
// その Sandbox の ID を除く。
func leftoverFailures(s *summary) []string {
	kept := map[string]bool{}
	for _, r := range s.Results {
		if r.Cleanup.WorkdirKept && r.SandboxID != "" {
			kept[r.SandboxID] = true
		}
	}
	var out []string
	if len(s.LeftoverNS) > 0 {
		out = append(out, "namespaces left behind: "+strings.Join(s.LeftoverNS, " "))
	}
	var leakedDirs []string
	for _, d := range s.LeftoverWorkdirs {
		if !kept[d] {
			leakedDirs = append(leakedDirs, d)
		}
	}
	if len(leakedDirs) > 0 {
		out = append(out, "workdirs left behind: "+strings.Join(leakedDirs, " "))
	}
	if len(s.LeftoverProcs) > 0 {
		out = append(out, "processes left behind: "+strings.Join(s.LeftoverProcs, " "))
	}
	if len(s.LeftoverLinks) > 0 {
		out = append(out, "links left behind in the root namespace: "+strings.Join(s.LeftoverLinks, " "))
	}
	// 仕事ごとの後片付けが自分で漏れを報告した場合も漏れとして数える。あとの gc が消せるかどうかは
	// 関係がない。片付けきれなかったこと自体が harness の不具合である
	for _, r := range s.Results {
		if len(r.Cleanup.LeftoverNS) > 0 || len(r.Cleanup.LeftoverPid) > 0 || len(r.Cleanup.Errs) > 0 {
			out = append(out, fmt.Sprintf("job %d, %s, sandbox %s, could not finish its cleanup: namespaces=%v pids=%v errors=%v",
				r.Index, r.Scenario, r.SandboxID, r.Cleanup.LeftoverNS, r.Cleanup.LeftoverPid, r.Cleanup.Errs))
		}
	}
	return out
}

func printSummary(s *summary, outDir string) {
	missing := ""
	if s.MissingJobs > 0 {
		missing = fmt.Sprintf(" missing=%d", s.MissingJobs)
	}
	verb := "run"
	if strings.HasPrefix(s.Shard, "merged/") {
		verb = "merge"
	}
	fmt.Printf("\n== labhost %s: %d jobs, parallel=%d, pass=%d fail=%d%s, wall=%.1fs\n", verb, s.Jobs, s.Parallel, s.Pass, s.Fail, missing, s.WallSec)
	if s.Shard != "" {
		fmt.Printf("   shard: %s of a plan of %d jobs, digest %s, netstack %s, agent %s\n", s.Shard, s.PlanJobs, s.PlanDigest, s.Netstack, implOrGo(s.AgentImpl))
	} else {
		fmt.Printf("   agent %s, netstack %s\n", implOrGo(s.AgentImpl), s.Netstack)
	}
	fmt.Printf("   vm: vcpus=%d cpu_seconds=%.1f mem_total=%dMiB peak_mem_used=%dMiB peak_load1=%.2f\n",
		s.VCPUs, s.VMCPUSeconds, s.MemTotalKB/1024, s.PeakMemUsedKB/1024, s.PeakLoad1)
	var min, max, total float64
	for i, r := range s.Results {
		if i == 0 || r.DurationSec < min {
			min = r.DurationSec
		}
		if r.DurationSec > max {
			max = r.DurationSec
		}
		total += r.DurationSec
	}
	if len(s.Results) > 0 {
		fmt.Printf("   scenario time: min=%.1fs max=%.1fs mean=%.1fs\n", min, max, total/float64(len(s.Results)))
	}
	if s.Interrupted {
		fmt.Println("   interrupted")
	}
	fmt.Printf("   slowest job: %.1fs   verdict lines: PASS %d FAIL %d SKIP %d\n",
		s.SlowestJobSec, s.TotalPassLines, s.TotalFailLines, s.TotalSkipLines)
	for _, v := range s.Verdicts {
		fmt.Printf("   %-30s runs=%d PASS=%d FAIL=%d SKIP=%d\n", v.Scenario, v.Runs, v.PassLines, v.FailLines, v.SkipLines)
	}
	// shard 1 台の run は go の組の結果を受け取らないので、外した数だけを示し、行は統合と 1 台の run で出す
	if len(s.FromGo) > 0 && s.Shard != "" && !strings.HasPrefix(s.Shard, "merged/") {
		fmt.Printf("   %d agent=go jobs are left to the go configuration; the merge shows their results\n", len(s.FromGo))
	} else if len(s.FromGo) > 0 {
		fmt.Printf("   %d agent=go jobs are not run with the %s agent; their results come from the go configuration and do not count here:\n", len(s.FromGo), implOrGo(s.AgentImpl))
		got := map[string]fromGoVerdict{}
		for _, v := range s.FromGoVerdicts {
			got[v.Scenario] = v
		}
		for _, sc := range s.FromGo {
			v, ok := got[sc]
			switch {
			case !ok:
				fmt.Printf("   from go: %-30s not given; run the go configuration as well\n", sc)
			case v.Runs == 0:
				fmt.Printf("   from go: %-30s not in the go configuration's summary\n", sc)
			default:
				verdict := "PASS"
				if v.Failed > 0 {
					verdict = "FAIL"
				}
				fmt.Printf("   from go: %-30s %s runs=%d PASS=%d FAIL=%d SKIP=%d\n", sc, verdict, v.Runs, v.PassLines, v.FailLines, v.SkipLines)
			}
		}
	}
	fmt.Printf("   leftovers: namespaces=%v workdirs=%v processes=%v links=%v\n", s.LeftoverNS, s.LeftoverWorkdirs, s.LeftoverProcs, s.LeftoverLinks)
	for _, w := range s.Warnings {
		fmt.Printf("   WARNING: %s\n", w)
	}
	if s.RateWindow != "" {
		fmt.Printf("   rate window: %s\n", s.RateWindow)
	}
	for _, f := range s.MergeProblems {
		fmt.Printf("   MERGE FAILURE: %s\n", f)
	}
	for _, f := range s.LeftoverFailures {
		fmt.Printf("   LEFTOVER FAILURE: the harness did not clean up; not a scenario failure: %s\n", f)
	}
	for _, r := range s.Results {
		if r.Exit != 0 || r.SetupErr != "" || len(r.Cleanup.LeftoverNS) > 0 || len(r.Cleanup.LeftoverPid) > 0 {
			fmt.Printf("   FAIL %d %s id=%s exit=%d timeout=%v setup=%q log=%s cleanup=%+v\n",
				r.Index, r.Scenario, r.SandboxID, r.Exit, r.TimedOut, r.SetupErr, r.Log, r.Cleanup)
		}
	}
	if outDir != "" {
		fmt.Printf("   summary: %s\n", filepath.Join(outDir, "summary.json"))
	}
}

func numCPU() int {
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "processor\t:")
}

func meminfoKB(key string) int {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, key+":") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				n, _ := strconv.Atoi(f[1])
				return n
			}
		}
	}
	return 0
}

func load1() float64 {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

// cpuSeconds は VM 全体が使った CPU 秒 (idle と iowait を除く)。
func cpuSeconds() float64 {
	b, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		f := strings.Fields(line)[1:]
		var busy float64
		for i, v := range f {
			n, _ := strconv.ParseFloat(v, 64)
			if i == 3 || i == 4 { // idle, iowait
				continue
			}
			busy += n
		}
		return busy / 100 // USER_HZ
	}
	return 0
}

func countSandboxNS(prefix string) int {
	names, _ := listNamespaces()
	ids := map[string]bool{}
	for _, n := range names {
		if id, _, ok := parseNSName(prefix, n); ok {
			ids[id] = true
		}
	}
	return len(ids)
}

const (
	agentImplGo   = "go"
	agentImplRust = "rust"
	// rustWgft は lab/lab build が Rust の wgft を入れる場所。lab/sandbox.sh の RUST_WGFT と同じ
	rustWgft = "/usr/local/lib/wgft-rust/wgft"
)

// agentImplName は確認が動かすユーザー空間モードの agent の実装。lab/lab は WGFT_LAB_AGENT_IMPL を
// そのまま渡し、lab/sandbox.sh が同じ値で AGENT_WGFT を決める。未設定は go。
func agentImplName() (string, error) {
	switch v := os.Getenv("WGFT_LAB_AGENT_IMPL"); v {
	case "", agentImplGo:
		return agentImplGo, nil
	case agentImplRust:
		return agentImplRust, nil
	default:
		return "", fmt.Errorf("WGFT_LAB_AGENT_IMPL=%s: want go or rust", v)
	}
}

// netstackName は確認が動かすエージェントの netstack。lab/lab は WGFT_LAB_AGENT_NETSTACK を
// WGFT_AGENT_NETSTACK として渡し、未設定ならエージェントの既定で動く。
func netstackName() string {
	if v := os.Getenv("WGFT_AGENT_NETSTACK"); v != "" {
		return v
	}
	return "default"
}

func fmtFloats(v []float64) string {
	p := make([]string, len(v))
	for i, f := range v {
		p[i] = fmt.Sprintf("%.0f", f)
	}
	return strings.Join(p, " / ")
}

// cmdMerge は run -shard K/N の summary.json を N 個受け取り、1 つの判定にまとめる。
// 台が足りない、重なる、計画を覆わない場合と、どれかが失敗か後片付けの漏れを出した場合は非 0。
func cmdMerge(args []string) error {
	fs := flag.NewFlagSet("merge", flag.ExitOnError)
	out := fs.String("out", "", "directory for the merged summary.json; default: only print")
	goSummary := fs.String("go-summary", "", "the go configuration's merged summary.json; a rust merge takes the agent=go jobs' results from it")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return fmt.Errorf("usage: labhost merge [-out DIR] [-go-summary FILE] SUMMARY_JSON [SUMMARY_JSON ...]")
	}
	var parts []*summary
	for _, p := range fs.Args() {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		var s summary
		if err := json.Unmarshal(b, &s); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		parts = append(parts, &s)
	}
	m := mergeSummaries(parts)
	if *goSummary != "" && len(m.FromGo) > 0 {
		// 取れない go の組の結果は警告にとどめ、rust の組の統合は書いて示す。取った結果は件数に入らないので、
		// 欠けても判定は変わらない
		g, err := loadGoSummary(*goSummary)
		if err != nil {
			m.Warnings = append(m.Warnings, "the go configuration's results are not shown: "+err.Error())
		} else {
			m.FromGoVerdicts = fromGoVerdicts(m.FromGo, g)
		}
	}
	dir := *out
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		b, _ := json.MarshalIndent(m, "", "  ")
		if err := os.WriteFile(filepath.Join(dir, "summary.json"), b, 0o644); err != nil {
			return err
		}
	}
	printSummary(m, dir)
	if m.Fail > 0 || m.Interrupted || len(m.LeftoverFailures) > 0 || len(m.MergeProblems) > 0 {
		os.Exit(1)
	}
	return nil
}

// loadGoSummary は merge -go-summary のファイルを読み、Go の agent で流れた summary であることを確かめる。
func loadGoSummary(path string) (*summary, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var g summary
	if err := json.Unmarshal(b, &g); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if implOrGo(g.AgentImpl) != agentImplGo {
		return nil, fmt.Errorf("%s ran with agent %s, not go", path, g.AgentImpl)
	}
	return &g, nil
}

// implOrGo は summary の agent_impl。この項目より前の summary は空で、Go の agent で流れた。
func implOrGo(v string) string {
	if v == "" {
		return agentImplGo
	}
	return v
}

// fromGoVerdicts は go の組の summary から、scenarios の仕事ごとの結果をまとめる。
func fromGoVerdicts(scenarios []string, g *summary) []fromGoVerdict {
	out := make([]fromGoVerdict, 0, len(scenarios))
	for _, sc := range scenarios {
		v := fromGoVerdict{Scenario: sc}
		for _, r := range g.Results {
			if r.Scenario != sc {
				continue
			}
			v.Runs++
			if r.Exit != 0 || r.SetupErr != "" {
				v.Failed++
			}
			v.PassLines += r.PassLines
			v.FailLines += r.FailLines
			v.SkipLines += r.SkipLines
		}
		out = append(out, v)
	}
	return out
}
