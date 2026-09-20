// sandbox.go は Sandbox の一生を扱う。Sandbox は 5 つの network namespace、作業ディレクトリ、
// そして自分が起こしたプロセスだけを持ち、他の Sandbox と VM 全体には触らない。
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/flock"
)

// role は Sandbox の中の netns の役目。名前は <prefix><id>-<role> になる。
// netns の中では同じインタフェース名、同じアドレス、同じポートを Sandbox ごとに使い回せるので、
// 分けるのは netns の名前と、netns が隔てないもの (作業ディレクトリ、ログ、プロセスの所有) だけ。
var roles = []string{"client", "vps", "router", "home", "lan"}

// runnerRole は、シナリオの shell 自身を走らせるための空の netns。トポロジには加わらない。
// shell を VM の root netns で動かすと、harness が SIGKILL で死んだときに shell が孤児として
// 残り、netns から数え上げられないので gc が見つけられない。空の netns に入れておけば、
// shell とその子も `ip netns pids` で見つかる。シナリオ側の kill 対象 (5 つの netns) には
// 入らないので、シナリオが自分の shell を止めてしまうことはない。
const runnerRole = "runner"

// allRoles は netns の名前として使う役目の全体。
func allRoles() []string { return append(append([]string{}, roles...), runnerRole) }

// roleEnvVar は shell のシナリオに netns の名前を渡す環境変数。
var roleEnvVar = map[string]string{
	"client": "WGFT_LAB_CLIENT_NS",
	"vps":    "WGFT_LAB_VPS_NS",
	"router": "WGFT_LAB_ROUTER_NS",
	"home":   "WGFT_LAB_HOME_NS",
	"lan":    "WGFT_LAB_LAN_NS",
}

// Sandbox は 1 回のシナリオを他から隔てて流すための単位。
type Sandbox struct {
	ID     string
	Prefix string
	Dir    string            // 作業ディレクトリ (データディレクトリとログの置き場)
	NS     map[string]string // role -> netns の名前
	Repo   string            // リポジトリの場所 (VM では /wgft)

	lock *flock.Lock // 生きている間だけ持つ。gc はこれが取れた Sandbox を死んだものと見なす
}

// newID は Sandbox の ID を作る。netns の名前に使うので英小文字と数字だけにし、
// 名前が長くなりすぎないよう 6 文字にする。
func newID() (string, error) {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b), nil
}

// nsName は role に対応する netns の名前。
func nsName(prefix, id, role string) string { return prefix + id + "-" + role }

// parseNSName は netns の名前から Sandbox の ID と role を取り出す。prefix で始まり、
// 末尾が既知の role である名前だけを受け付ける。gc が自分の作った netns だけに触るための関門。
func parseNSName(prefix, name string) (id, role string, ok bool) {
	if !strings.HasPrefix(name, prefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(name, prefix)
	i := strings.LastIndex(rest, "-")
	if i <= 0 {
		return "", "", false
	}
	id, role = rest[:i], rest[i+1:]
	for _, r := range allRoles() {
		if r == role && id != "" {
			return id, role, true
		}
	}
	return "", "", false
}

// Env は shell のシナリオと netns.sh に渡す環境変数。未設定なら今までの共有の netns と /tmp を
// 使うのがシナリオ側の既定なので、この環境変数の有無が Sandbox モードの切り替えになる。
func (s *Sandbox) Env() []string {
	env := []string{"WGFT_LAB_SANDBOX=" + s.ID, "WGFT_LAB_WORKDIR=" + s.Dir}
	for _, r := range roles {
		env = append(env, roleEnvVar[r]+"="+s.NS[r])
	}
	return env
}

// nsList は Sandbox が持つ netns の名前。シナリオの shell が入る runner も含む。
func (s *Sandbox) nsList() []string {
	out := make([]string, 0, len(s.NS))
	for _, r := range allRoles() {
		if n, ok := s.NS[r]; ok {
			out = append(out, n)
		}
	}
	return out
}

// CreateSandbox は作業ディレクトリと netns のトポロジを作る。トポロジは lab/netns.sh に任せるので、
// 共有の netns で使うものと同じ 1 つの定義から組み立てられる。
func CreateSandbox(prefix, rootDir, repo, id string) (*Sandbox, error) {
	s := &Sandbox{ID: id, Prefix: prefix, Dir: filepath.Join(rootDir, id), NS: map[string]string{}, Repo: repo}
	for _, r := range allRoles() {
		s.NS[r] = nsName(prefix, id, r)
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return nil, err
	}
	lock, err := flock.Acquire(filepath.Join(s.Dir, "sandbox"))
	if err != nil {
		return nil, fmt.Errorf("sandbox %s: %w", id, err)
	}
	s.lock = lock
	cmd := exec.Command("bash", filepath.Join(repo, "lab", "netns.sh"), "up")
	cmd.Env = append(os.Environ(), s.Env()...)
	out, err := cmd.CombinedOutput()
	_ = os.WriteFile(filepath.Join(s.Dir, "netns-up.log"), out, 0o644)
	if err != nil {
		s.Destroy(false)
		return nil, fmt.Errorf("netns.sh up: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("ip", "netns", "add", s.NS[runnerRole]).CombinedOutput(); err != nil {
		s.Destroy(false)
		return nil, fmt.Errorf("ip netns add %s: %v: %s", s.NS[runnerRole], err, strings.TrimSpace(string(out)))
	}
	// runner には経路も宛先も無いが、loopback だけは上げておく (shell から localhost を引く道具のため)
	_ = exec.Command("ip", "-n", s.NS[runnerRole], "link", "set", "lo", "up").Run()
	return s, nil
}

// RunResult は 1 回のシナリオの結果。
type RunResult struct {
	Exit     int
	TimedOut bool
	Err      string
}

// Run はシナリオを Sandbox の中で流す。シナリオ自身は runner の netns で動く bash で、
// 中の `ip netns exec` が Sandbox の netns に入る (今の shell の書き方のまま)。
// 直接の子プロセスは別のプロセスグループに入れて、シナリオが止まったときにまとめて止められるようにする。
// setsid nohup で切り離される孫は、後片付けで netns から数え上げて止める。
func (s *Sandbox) Run(ctx context.Context, script string, args []string, logPath string, timeout time.Duration) RunResult {
	lf, err := os.Create(logPath)
	if err != nil {
		return RunResult{Exit: -1, Err: err.Error()}
	}
	defer lf.Close()

	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	argv := append([]string{"netns", "exec", s.NS[runnerRole], "bash", filepath.Join(s.Repo, "lab", script)}, args...)
	cmd := exec.CommandContext(rctx, "ip", argv...)
	cmd.Dir = s.Repo
	cmd.Env = append(os.Environ(), s.Env()...)
	cmd.Stdout, cmd.Stderr = lf, lf
	setProcessGroup(cmd)
	// 打ち切りのときはプロセスグループ全体に送る。シナリオは sleep や socat を子に持つので、
	// bash 1 つに送っても待ち続けることがある
	cmd.Cancel = func() error { return terminateGroup(cmd.Process.Pid) }
	cmd.WaitDelay = 10 * time.Second

	err = cmd.Run()
	res := RunResult{}
	switch {
	case err == nil:
		res.Exit = 0
	default:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.Exit = ee.ExitCode()
		} else {
			res.Exit = -1
		}
		res.Err = err.Error()
	}
	if errors.Is(rctx.Err(), context.DeadlineExceeded) {
		res.TimedOut = true
	}
	return res
}

// nsPids は netns の中のプロセスの PID。`ip netns pids` は /proc を走査して netns を比べるので、
// setsid nohup で切り離された孫も、PID の記録も cgroup も無しに数え上げられる。
func nsPids(ns string) ([]int, error) {
	out, err := exec.Command("ip", "netns", "pids", ns).Output()
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, line := range strings.Fields(string(out)) {
		if p, err := strconv.Atoi(line); err == nil {
			pids = append(pids, p)
		}
	}
	return pids, nil
}

// procName は PID の comm。後片付けの記録に使う。
func procName(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return "?"
	}
	return strings.TrimSpace(string(b))
}

// killNamespaces は 5 つの netns の中のプロセスを、SIGTERM のあと残りを SIGKILL で止める。
// 名前で VM 全体を薙ぐ (pkill -x wgft) ことはしない。止めた顔ぶれを記録として返す。
func killNamespaces(nsNames []string, grace time.Duration) (killed []string) {
	seen := map[int]string{}
	collect := func() []int {
		var all []int
		for _, ns := range nsNames {
			pids, err := nsPids(ns)
			if err != nil {
				continue
			}
			for _, p := range pids {
				if p == os.Getpid() {
					continue
				}
				if _, ok := seen[p]; !ok {
					seen[p] = procName(p)
				}
				all = append(all, p)
			}
		}
		return all
	}
	for _, p := range collect() {
		signalPid(p, true)
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if len(collect()) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for _, p := range collect() {
		signalPid(p, false)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(collect()) == 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	for p, name := range seen {
		killed = append(killed, fmt.Sprintf("%d(%s)", p, name))
	}
	sort.Strings(killed)
	return killed
}

// DestroyReport は後片付けの結果。leftover が空でなければ漏れがある。
type DestroyReport struct {
	Killed      []string `json:"killed,omitempty"`
	LeftoverNS  []string `json:"leftover_namespaces,omitempty"`
	LeftoverPid []string `json:"leftover_pids,omitempty"`
	WorkdirKept bool     `json:"workdir_kept"`
	Errs        []string `json:"errors,omitempty"`
}

// Destroy は自分のプロセス、netns、作業ディレクトリを片付ける。netns を先に消すとプロセスは
// 名前の無い netns に残って動き続けるので、止める順は プロセス -> netns -> ディレクトリ。
func (s *Sandbox) Destroy(keepWorkdir bool) DestroyReport {
	var rep DestroyReport
	rep.Killed = killNamespaces(s.nsList(), 5*time.Second)
	for _, ns := range s.nsList() {
		if pids, err := nsPids(ns); err == nil && len(pids) > 0 {
			for _, p := range pids {
				rep.LeftoverPid = append(rep.LeftoverPid, fmt.Sprintf("%s:%d(%s)", ns, p, procName(p)))
			}
		}
		if out, err := exec.Command("ip", "netns", "delete", ns).CombinedOutput(); err != nil {
			if _, statErr := os.Stat(filepath.Join("/var/run/netns", ns)); statErr == nil {
				rep.Errs = append(rep.Errs, fmt.Sprintf("ip netns delete %s: %v: %s", ns, err, strings.TrimSpace(string(out))))
			}
		}
		if _, err := os.Stat(filepath.Join("/var/run/netns", ns)); err == nil {
			rep.LeftoverNS = append(rep.LeftoverNS, ns)
		}
	}
	if s.lock != nil {
		s.lock.Release()
		s.lock = nil
	}
	rep.WorkdirKept = keepWorkdir
	if !keepWorkdir {
		if err := os.RemoveAll(s.Dir); err != nil {
			rep.Errs = append(rep.Errs, err.Error())
			rep.WorkdirKept = true
		}
	}
	return rep
}

// listNamespaces は /var/run/netns にある名前。`ip netns list` を通さないので、
// 名前の一覧だけが要る場面ではこちらを使う。
func listNamespaces() ([]string, error) {
	ents, err := os.ReadDir("/var/run/netns")
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}

// GCReport は gc が何を片付けたか。
type GCReport struct {
	Removed  []string `json:"removed,omitempty"`  // 片付けた Sandbox の ID
	Skipped  []string `json:"skipped,omitempty"`  // 生きている (ロックを持っている) ので触らなかった ID
	Details  []string `json:"details,omitempty"`  // 止めたプロセスなどの記録
	Errs     []string `json:"errors,omitempty"`   //
	Scanned  int      `json:"scanned"`            // 見つけた Sandbox の数
	Orphaned []string `json:"orphaned,omitempty"` // netns が無く作業ディレクトリだけ残っていた ID
}

// GC は死んだ harness の残骸を片付ける。prefix で始まる netns と、作業ディレクトリの置き場を
// 見て、ロックが取れる (= 持ち主がいない) Sandbox のプロセス、netns、ディレクトリを消す。
// SIGINT なら harness 自身が片付けるが、SIGKILL では片付けられないので、流し始めに呼ぶ。
func GC(prefix, rootDir string, keepWorkdirs bool) GCReport {
	var rep GCReport
	ids := map[string]bool{}
	names, err := listNamespaces()
	if err != nil {
		rep.Errs = append(rep.Errs, err.Error())
	}
	for _, n := range names {
		if id, _, ok := parseNSName(prefix, n); ok {
			ids[id] = true
		}
	}
	if ents, err := os.ReadDir(rootDir); err == nil {
		for _, e := range ents {
			if !e.IsDir() || strings.HasPrefix(e.Name(), "run-") {
				continue
			}
			if _, err := os.Stat(filepath.Join(rootDir, e.Name(), "sandbox.lock")); err == nil {
				if !ids[e.Name()] {
					rep.Orphaned = append(rep.Orphaned, e.Name())
				}
				ids[e.Name()] = true
			}
		}
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	rep.Scanned = len(sorted)
	for _, id := range sorted {
		dir := filepath.Join(rootDir, id)
		// 作業ディレクトリごと消えた残骸 (netns だけが残っている場合) でもロックを試せるように、
		// 置き場を作ってから取る。ここで作ったディレクトリは、この後の Destroy が消す
		if err := os.MkdirAll(dir, 0o755); err != nil {
			rep.Errs = append(rep.Errs, err.Error())
			continue
		}
		// ロックが取れなければ持ち主が生きている。触らない
		lock, err := flock.Acquire(filepath.Join(dir, "sandbox"))
		if err != nil {
			if !errors.Is(err, flock.ErrLocked) {
				rep.Errs = append(rep.Errs, fmt.Sprintf("%s: %v", id, err))
			}
			rep.Skipped = append(rep.Skipped, id)
			continue
		}
		s := &Sandbox{ID: id, Prefix: prefix, Dir: dir, NS: map[string]string{}, lock: lock}
		for _, r := range allRoles() {
			s.NS[r] = nsName(prefix, id, r)
		}
		d := s.Destroy(keepWorkdirs)
		rep.Removed = append(rep.Removed, id)
		if len(d.Killed) > 0 {
			rep.Details = append(rep.Details, id+": killed "+strings.Join(d.Killed, " "))
		}
		if len(d.LeftoverNS) > 0 || len(d.LeftoverPid) > 0 {
			rep.Errs = append(rep.Errs, fmt.Sprintf("%s: leftover ns=%v pids=%v", id, d.LeftoverNS, d.LeftoverPid))
		}
		rep.Errs = append(rep.Errs, d.Errs...)
	}
	return rep
}
