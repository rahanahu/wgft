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
  run [flags] all                      run every job of `+manifestPath+` (parallel pool, then the
                                       exclusive jobs one at a time)
  gc [flags]                           remove leftovers of dead runs (namespaces, processes, workdirs)
  list                                 list the sandboxes that exist now
  create [-id ID]                      create one sandbox and print its environment
  destroy <ID>                         destroy one sandbox

run flags: -parallel N -repeat R -timeout DUR -keep-failed -no-gc -out DIR -prefix P -root DIR
           -repo DIR -manifest FILE -with-optional
`)
}

// jobResult は 1 回のシナリオの結果。PASS、FAIL、SKIP の行数も数える。旧来の流し方と
// 同じ確認が流れたことを、行数の一致で確かめられるようにするため。
type jobResult struct {
	Index       int           `json:"index"`
	Class       class         `json:"class"`
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

// summary は 1 回の run 全体の記録。
type summary struct {
	Scenarios        []string          `json:"scenarios"`
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
	Results          []jobResult       `json:"results"`
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	parallel := fs.Int("parallel", 1, "how many sandboxes run at once")
	repeat := fs.Int("repeat", 1, "how many times to run the whole scenario list")
	timeout := fs.Duration("timeout", 10*time.Minute, "wall-clock limit for one scenario")
	keepFailed := fs.Bool("keep-failed", false, "keep the workdir of a failed run")
	noGC := fs.Bool("no-gc", false, "do not collect leftovers of dead runs before starting")
	out := fs.String("out", "", "directory for the summary and the logs (default <root>/run-<timestamp>)")
	prefix := fs.String("prefix", defaultPrefix, "namespace name prefix")
	root := fs.String("root", defaultRoot, "directory holding the sandbox workdirs")
	repo := fs.String("repo", defaultRepo, "repository root inside the VM")
	manifest := fs.String("manifest", "", "manifest for `run all` (default <repo>/"+manifestPath+")")
	withOptional := fs.Bool("with-optional", false, "also run the manifest's default=no jobs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	scenarios := fs.Args()
	if len(scenarios) == 0 {
		return fmt.Errorf("no scenario given (e.g. \"e2e.sh kernel\", or \"all\" for the manifest)")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
	// "all" は lab/suite.txt の全体。分類は manifest が持ち、それ以外の指定は parallel として扱う
	runAll := len(scenarios) == 1 && scenarios[0] == "all"
	manifestFile := *manifest
	if manifestFile == "" {
		manifestFile = filepath.Join(*repo, manifestPath)
	}
	var plan []jobResult // Index, Class, Scenario だけを先に決める
	if runAll {
		jobs, err := loadManifest(manifestFile)
		if err != nil {
			return err
		}
		n := 0
		for r := 0; r < *repeat; r++ {
			for _, j := range jobs {
				if !j.Default && !*withOptional {
					continue
				}
				plan = append(plan, jobResult{Index: n, Class: j.Class, Scenario: j.Scenario})
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
	outDir := *out
	if outDir == "" {
		outDir = filepath.Join(*root, "run-"+time.Now().Format("20060102-150405"))
	}
	if err := os.MkdirAll(filepath.Join(outDir, "logs"), 0o755); err != nil {
		return err
	}
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

	sum := summary{Scenarios: scenarios, Parallel: *parallel, Repeat: *repeat, StartedAt: time.Now()}
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
	fmt.Printf("plan: %d parallel jobs (pool of %d), %d exclusive jobs (one at a time)\n",
		len(parallelPlan), *parallel, len(exclusivePlan))

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
		results <- runOne(ctx, j, *prefix, *root, *repo, outDir, *timeout, *keepFailed)
	}
	close(results)
	mstop()
	mwg.Wait()

	for r := range results {
		sum.Results = append(sum.Results, r)
	}
	sort.Slice(sum.Results, func(i, j int) bool { return sum.Results[i].Index < sum.Results[j].Index })
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
	if runAll {
		sum.Manifest = manifestFile
	}
	sum.Jobs = len(sum.Results)
	sum.WallSec = time.Since(sum.StartedAt).Seconds()
	sum.PeakMemUsedKB, sum.PeakLoad1 = peakUsed, peakLoad
	sum.Interrupted = ctx.Err() != nil
	sum.LeftoverNS, sum.LeftoverWorkdirs, sum.LeftoverProcs, sum.LeftoverLinks = leakCheck(*prefix, *root)

	b, _ := json.MarshalIndent(sum, "", "  ")
	if err := os.WriteFile(filepath.Join(outDir, "summary.json"), b, 0o644); err != nil {
		return err
	}
	printSummary(&sum, outDir)
	if sum.Fail > 0 || sum.Interrupted {
		os.Exit(1)
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("must run as root")
	}
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
		fmt.Println("(no sandbox)")
	}
	return nil
}

func cmdCreate(args []string) error {
	fs := flag.NewFlagSet("create", flag.ExitOnError)
	id := fs.String("id", "", "sandbox id (default: random)")
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
	if ents, err := os.ReadDir(root); err == nil {
		for _, e := range ents {
			if e.IsDir() && !strings.HasPrefix(e.Name(), "run-") {
				workdirs = append(workdirs, e.Name())
			}
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

func printSummary(s *summary, outDir string) {
	fmt.Printf("\n== labhost run: %d jobs, parallel=%d, pass=%d fail=%d, wall=%.1fs\n", s.Jobs, s.Parallel, s.Pass, s.Fail, s.WallSec)
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
	fmt.Printf("   leftovers: namespaces=%v workdirs=%v processes=%v links=%v\n", s.LeftoverNS, s.LeftoverWorkdirs, s.LeftoverProcs, s.LeftoverLinks)
	for _, r := range s.Results {
		if r.Exit != 0 || r.SetupErr != "" || len(r.Cleanup.LeftoverNS) > 0 || len(r.Cleanup.LeftoverPid) > 0 {
			fmt.Printf("   FAIL %d %s id=%s exit=%d timeout=%v setup=%q log=%s cleanup=%+v\n",
				r.Index, r.Scenario, r.SandboxID, r.Exit, r.TimedOut, r.SetupErr, r.Log, r.Cleanup)
		}
	}
	fmt.Printf("   summary: %s\n", filepath.Join(outDir, "summary.json"))
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
