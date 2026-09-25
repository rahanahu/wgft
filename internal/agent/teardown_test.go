package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/proto"
)

// tdKernel は撤去が触れるカーネルの模型である。links はインタフェースの名前から持つ鍵への対応で、
// 鍵がゼロなら鍵の無い WireGuard、notWG に名前があれば WireGuard 以外のリンクである。
type tdKernel struct {
	links    map[string]wgtypes.Key
	addrs    map[string]string // インタフェースのアドレス。無ければ空
	notWG    map[string]string
	table    bool
	calls    []string
	lock     credentials.State
	lockErr  error
	acquired bool

	holdersErr error
	deleteErr  error
	flowsErr   error
	flowsPubs  []json.RawMessage
	flowsAddr  string
}

func (k *tdKernel) ops() teardownOps {
	return teardownOps{
		inspectLock: func(string) (credentials.State, error) { return k.lock, k.lockErr },
		acquire: func(path string) (*credentials.Lock, error) {
			k.acquired = true
			return credentials.Acquire(path)
		},
		keyHolders: func(cur, prev wgtypes.Key) ([]string, error) {
			k.calls = append(k.calls, "holders")
			if k.holdersErr != nil {
				return nil, k.holdersErr
			}
			var zero wgtypes.Key
			var out []string
			for n, key := range k.links {
				if key != zero && (key == cur || key == prev) {
					out = append(out, n)
				}
			}
			return tdSorted(out), nil
		},
		link: func(name string, cur, prev wgtypes.Key) (linkState, error) {
			if kind, ok := k.notWG[name]; ok {
				return linkState{owner: linkNotWireGuard, kind: kind}, nil
			}
			key, ok := k.links[name]
			var zero wgtypes.Key
			switch {
			case !ok:
				return linkState{owner: linkAbsent}, nil
			case key == zero:
				return linkState{owner: linkKeyless}, nil
			case key == cur:
				return linkState{owner: linkCurrentKey, address: k.addrs[name]}, nil
			case key == prev:
				return linkState{owner: linkPreviousKey, address: k.addrs[name]}, nil
			}
			return linkState{owner: linkForeignKey}, nil
		},
		stagingName: func(iface string) string { return "wgftnew-" + iface },
		wireGuardLinks: func() ([]string, error) {
			var out []string
			for n := range k.links {
				out = append(out, n)
			}
			return tdSorted(out), nil
		},
		deleteLink: func(name string, cur, prev wgtypes.Key) (bool, error) {
			k.calls = append(k.calls, "delete "+name)
			if k.deleteErr != nil {
				return false, k.deleteErr
			}
			key, ok := k.links[name]
			if !ok {
				return false, nil
			}
			if key != cur && key != prev {
				return false, errors.New("not ours")
			}
			delete(k.links, name)
			return true, nil
		},
		tablePresent: func() (bool, error) { return k.table, nil },
		deleteTable: func() (bool, error) {
			k.calls = append(k.calls, "delete table")
			was := k.table
			k.table = false
			return was, nil
		},
		closeFlows: func(pubs []json.RawMessage, address string) (string, error) {
			k.calls = append(k.calls, "flows")
			k.flowsPubs, k.flowsAddr = pubs, address
			if k.flowsErr != nil {
				return "", k.flowsErr
			}
			return "closed 2 flows", nil
		},
	}
}

func tdSorted(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}

func tdKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// kernelCreds は、カーネルモードで動いていたエージェントの agent.json を書き、そのパスを返す。
func kernelCreds(t *testing.T, cur, prev wgtypes.Key) (string, *credentials.Credentials) {
	t.Helper()
	at := time.Date(2026, 9, 24, 1, 2, 3, 0, time.UTC)
	f := &credentials.Credentials{
		Name: "home", Endpoint: "vps:8443", CertSHA256: strings.Repeat("ab", 32), PermanentToken: "tok",
		WGPrivateKey:         cur.String(),
		LastState:            &proto.State{Generation: 9, WG: proto.WGConfig{Address: "10.200.0.2/24", ServerPubkey: "x"}},
		Mode:                 credentials.ModeKernel,
		PreviousWGPrivateKey: prev.String(),
		IPForwardEnabledAt:   &at,
		KernelPublication:    json.RawMessage(`{"generation":9,"rules":[]}`),
		KernelUnconverged:    json.RawMessage(`[{"generation":7,"rules":[]},{"generation":8,"rules":[]}]`),
		TunnelAddress:        "10.200.0.2/24",
	}
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	return path, f
}

func runTeardown(t *testing.T, k *tdKernel, opts TeardownOptions) (string, error) {
	t.Helper()
	if opts.Interface == "" {
		opts.Interface = "wgft0"
	}
	var out bytes.Buffer
	err := teardownWith(k.ops(), opts, &out)
	return out.String(), err
}

func tdRead(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// 今の鍵と 1 つ前の鍵を持つインタフェースを名前によらず消し、conntrack、テーブル、記録の順に消す。
// 登録の情報、今の鍵、last_state は残す(設計文書 10.3 節)。
func TestTeardownRemovesWhatTheKeysOwn(t *testing.T) {
	cur, prev, other := tdKey(t), tdKey(t), tdKey(t)
	path, _ := kernelCreds(t, cur, prev)
	k := &tdKernel{
		links: map[string]wgtypes.Key{"wgft0": cur, "wgftnew-wgft0": prev, "wgold": cur, "wg-other": other},
		table: true,
	}
	out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
	if err != nil {
		t.Fatalf("teardown: %v\n%s", err, out)
	}
	want := []string{"holders", "delete wgft0", "delete wgftnew-wgft0", "delete wgold", "flows", "delete table"}
	if !reflect.DeepEqual(k.calls, want) {
		t.Errorf("calls = %v, want %v", k.calls, want)
	}
	if _, ok := k.links["wg-other"]; !ok {
		t.Error("the interface with another key was deleted")
	}
	// 収束が済んでいない前の公開の列を古い順に、その後に直近の公開を渡す
	var gens []string
	for _, p := range k.flowsPubs {
		var g struct{ Generation int }
		_ = json.Unmarshal(p, &g)
		gens = append(gens, fmt.Sprint(g.Generation))
	}
	if strings.Join(gens, ",") != "7,8,9" || k.flowsAddr != "10.200.0.2/24" {
		t.Errorf("conntrack got pubs=%s address=%q", k.flowsPubs, k.flowsAddr)
	}
	after, err := credentials.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode != "" || after.PreviousWGPrivateKey != "" || after.IPForwardEnabledAt != nil || len(after.KernelPublication) != 0 || len(after.KernelUnconverged) != 0 {
		t.Errorf("kernel-mode records remain: %+v", after)
	}
	if after.Name != "home" || after.PermanentToken != "tok" || after.WGPrivateKey != cur.String() || after.LastState == nil || after.LastState.Generation != 9 {
		t.Errorf("the registration, key or last_state changed: %+v", after)
	}
	// 登録時のトンネルのアドレスの記録は登録の一部であり、撤去は消さない(設計文書 7b.1・9 節)
	if after.TunnelAddress != "10.200.0.2/24" {
		t.Errorf("teardown changed the tunnel address record to %q", after.TunnelAddress)
	}
	for _, s := range []string{
		"remove: the WireGuard interface wgft0, which holds this agent's key",
		"remove: the WireGuard interface wgftnew-wgft0, which holds this agent's previous key",
		"remove: the WireGuard interface wgold",
		"remove: table inet wgft_agent",
		"remove: the kernel-mode records in agent.json: mode kernel, previous key, ip_forward record, publication record, publications not yet converged",
		"deleted table inet wgft_agent",
		"the agent set it from 0 to 1 at 2026-09-24T01:02:03Z",
		"sysctl -w net.ipv4.ip_forward=0",
		"WGFT_MODE=kernel",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
	if strings.Contains(out, "wg-other") {
		t.Errorf("output names an interface that is not the agent's and not under its names:\n%s", out)
	}
	// ユーザー空間モードで起動し直せる。関門は記録だけを見る
	if _, err := enterMode(after, "", path); err != nil {
		t.Errorf("the mode gate still refuses after teardown: %v", err)
	}
}

// 稼働中のエージェントには何もせずに拒否する。ロックの状態を読めない場合も同じ(設計文書 10.3 節)。
func TestTeardownRefusesWhileRunning(t *testing.T) {
	cur, prev := tdKey(t), tdKey(t)
	for _, tc := range []struct {
		name string
		lock credentials.State
		err  error
		held bool
	}{
		{name: "locked", lock: credentials.Locked},
		{name: "unreadable", lock: credentials.Unknown, err: errors.New("boom")},
		{name: "locked after the check", lock: credentials.Unlocked, held: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := kernelCreds(t, cur, prev)
			if tc.held {
				l, err := credentials.Acquire(path)
				if err != nil {
					t.Fatal(err)
				}
				defer l.Release()
			}
			before := tdRead(t, path)
			k := &tdKernel{links: map[string]wgtypes.Key{"wgft0": cur}, table: true, lock: tc.lock, lockErr: tc.err}
			out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
			if err == nil {
				t.Fatalf("teardown succeeded:\n%s", out)
			}
			if tc.err == nil && !errors.Is(err, errAgentRunning) {
				t.Errorf("err = %v, want the running refusal", err)
			}
			if startup.IsRefusal(err) {
				t.Errorf("err = %v is a refusal; a running agent is a plain error", err)
			}
			if len(k.calls) != 0 || tdRead(t, path) != before {
				t.Errorf("changed something: calls=%v", k.calls)
			}
		})
	}
}

// ロックファイルがあって誰も持っていなければ、ロックを取って進める。
func TestTeardownTakesAnUnheldLock(t *testing.T) {
	cur, prev := tdKey(t), tdKey(t)
	path, _ := kernelCreds(t, cur, prev)
	k := &tdKernel{links: map[string]wgtypes.Key{}, lock: credentials.Unlocked}
	if _, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path}); err != nil {
		t.Fatal(err)
	}
	if !k.acquired {
		t.Error("the lock was not taken")
	}
	// 撤去の後はロックを放している
	l, err := credentials.Acquire(path)
	if err != nil {
		t.Fatalf("the lock is still held after teardown: %v", err)
	}
	l.Release()
}

// ホストを再起動した後のように、記録だけが残っていれば記録を消して成功する。モードの記録だけの場合も
// 同じである。カーネルに何かを書く前に落ちたエージェントが、この形を残す。
func TestTeardownClearsRecordsOnly(t *testing.T) {
	cur, prev := tdKey(t), tdKey(t)
	for _, modeOnly := range []bool{false, true} {
		path, f := kernelCreds(t, cur, prev)
		if modeOnly {
			f.PreviousWGPrivateKey, f.IPForwardEnabledAt, f.KernelPublication, f.KernelUnconverged = "", nil, nil, nil
			if err := f.Save(path); err != nil {
				t.Fatal(err)
			}
		}
		k := &tdKernel{links: map[string]wgtypes.Key{}}
		out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.Join(k.calls, " "), "delete") {
			t.Errorf("mode only %v: deleted something on a host with no interface and no table: %v", modeOnly, k.calls)
		}
		after, _ := credentials.Load(path)
		if after.Mode != "" || len(after.KernelPublication) != 0 || len(after.KernelUnconverged) != 0 {
			t.Errorf("mode only %v: records remain: %+v", modeOnly, after)
		}
		if !strings.Contains(out, "cleared the kernel-mode records") {
			t.Errorf("mode only %v: output:\n%s", modeOnly, out)
		}
	}
}

// 何も残っていないホストでは何も変えずに成功する。
func TestTeardownNothingLeft(t *testing.T) {
	cur := tdKey(t)
	f := &credentials.Credentials{Name: "home", WGPrivateKey: cur.String()}
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	before := tdRead(t, path)
	k := &tdKernel{links: map[string]wgtypes.Key{}}
	out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "nothing to remove") {
		t.Errorf("output:\n%s", out)
	}
	if strings.Contains(strings.Join(k.calls, " "), "delete") || strings.Contains(strings.Join(k.calls, " "), "flows") {
		t.Errorf("calls = %v", k.calls)
	}
	if tdRead(t, path) != before {
		t.Error("agent.json was rewritten")
	}
}

// 知らないモードの記録では、何も読まず何も消さずに種別 conflict で止まる(設計文書 10.3・11a 節)。
func TestTeardownRefusesAnUnknownMode(t *testing.T) {
	cur, prev := tdKey(t), tdKey(t)
	path, f := kernelCreds(t, cur, prev)
	f.Mode = "ebpf"
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	before := tdRead(t, path)
	k := &tdKernel{links: map[string]wgtypes.Key{"wgft0": cur}, table: true}
	out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
	r := startup.Of(err)
	if r == nil || r.Category != startup.CategoryConflict {
		t.Fatalf("err = %v, want a conflict refusal\n%s", err, out)
	}
	if !strings.Contains(err.Error(), `"ebpf"`) {
		t.Errorf("the refusal does not name the mode: %v", err)
	}
	if len(k.calls) != 0 || tdRead(t, path) != before || !k.table {
		t.Errorf("changed something: calls=%v", k.calls)
	}
}

// 設定の名前と作業用の名前にある鍵の一致しないリンクには触れずに示し、撤去は成功する。
func TestTeardownLeavesLinksItDoesNotOwn(t *testing.T) {
	cur, prev, other := tdKey(t), tdKey(t), tdKey(t)
	for _, tc := range []struct {
		name  string
		links map[string]wgtypes.Key
		notWG map[string]string
		want  string
	}{
		{name: "another key", links: map[string]wgtypes.Key{"wgft0": other}, want: "wgft0 is a WireGuard interface that holds neither this agent's key nor its previous one"},
		{name: "no key", links: map[string]wgtypes.Key{"wgftnew-wgft0": {}}, want: "wgftnew-wgft0 is a WireGuard interface with no key"},
		{name: "not WireGuard", links: map[string]wgtypes.Key{}, notWG: map[string]string{"wgft0": "veth"}, want: "wgft0 is a veth link, not WireGuard"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, _ := kernelCreds(t, cur, prev)
			k := &tdKernel{links: tc.links, notWG: tc.notWG, table: true}
			out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
			if err != nil {
				t.Fatalf("teardown: %v\n%s", err, out)
			}
			if !strings.Contains(out, "leave: "+tc.want) {
				t.Errorf("output lacks the untouched link:\n%s", out)
			}
			for _, c := range k.calls {
				if strings.HasPrefix(c, "delete wg") {
					t.Errorf("deleted a link it does not own: %v", k.calls)
				}
			}
			if k.table {
				t.Error("the table was not deleted")
			}
		})
	}
}

// agent.json が無ければ何も消さずに誤りを返し、見つけたテーブルとインタフェースを示す(設計文書 10.3 節)。
// 稼働の判定は指したデータディレクトリのロックファイルしか見ないので、--data-dir が実際のデータ
// ディレクトリを指していないと、稼働中のエージェントの資源を消しかねないためである。
func TestTeardownWithoutCredentialsRemovesNothing(t *testing.T) {
	other := tdKey(t)
	path := filepath.Join(t.TempDir(), "agent.json")
	k := &tdKernel{links: map[string]wgtypes.Key{"wgft0": other, "wgftnew-wgft0": {}, "wg-home": other}, table: true}
	out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
	if err == nil {
		t.Fatalf("teardown succeeded without agent.json:\n%s", out)
	}
	if startup.IsRefusal(err) {
		t.Errorf("err = %v is a refusal; it is a plain error, exit 1", err)
	}
	if len(k.calls) != 0 || !k.table {
		t.Errorf("changed something: calls=%v", k.calls)
	}
	for _, s := range []string{
		"found: table inet wgft_agent",
		"found: the WireGuard interface wgft0, wgft's configured name: WGFT_WG_INTERFACE of this run\n",
		"found: the WireGuard interface wgftnew-wgft0, wgft's configured name: the one the agent uses while creating wgft0\n",
		"found: the WireGuard interface wg-home, not a name wgft uses with this configuration\n",
	} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
	for _, s := range []string{"does not exist, so nothing was removed", "--data-dir"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error lacks %q: %v", s, err)
		}
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("teardown created agent.json: %v", err)
	}
}

// --dry-run は何も変えない。
func TestTeardownDryRun(t *testing.T) {
	cur, prev := tdKey(t), tdKey(t)
	path, _ := kernelCreds(t, cur, prev)
	before := tdRead(t, path)
	k := &tdKernel{links: map[string]wgtypes.Key{"wgft0": cur}, table: true}
	out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(k.calls, []string{"holders"}) || !k.table || tdRead(t, path) != before {
		t.Errorf("changed something: calls=%v", k.calls)
	}
	for _, s := range []string{"remove: the WireGuard interface wgft0", "dry run: nothing was changed", "restore by hand"} {
		if !strings.Contains(out, s) {
			t.Errorf("output lacks %q:\n%s", s, out)
		}
	}
}

// インタフェースを消せなければ、テーブルも記録も残して誤りを返す。関門が残骸を見落とさないためである。
func TestTeardownKeepsRecordsWhenALinkStays(t *testing.T) {
	cur, prev := tdKey(t), tdKey(t)
	path, _ := kernelCreds(t, cur, prev)
	before := tdRead(t, path)
	k := &tdKernel{links: map[string]wgtypes.Key{"wgft0": cur}, table: true, deleteErr: errors.New("busy")}
	if _, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path}); err == nil {
		t.Fatal("teardown succeeded")
	}
	if !k.table || tdRead(t, path) != before {
		t.Errorf("went on after the failure: calls=%v", k.calls)
	}
}

// 権限が足りなければ、種別 prerequisite の拒否になる。
func TestTeardownWithoutPrivilegeIsAPrerequisiteRefusal(t *testing.T) {
	cur, prev := tdKey(t), tdKey(t)
	path, _ := kernelCreds(t, cur, prev)
	k := &tdKernel{links: map[string]wgtypes.Key{}, holdersErr: syscall.EPERM}
	_, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
	if r := startup.Of(err); r == nil || r.Category != startup.CategoryPrerequisite || r.Subject != "CAP_NET_ADMIN" {
		t.Errorf("err = %v, want a prerequisite refusal about CAP_NET_ADMIN", err)
	}
}

// conntrack の失敗は警告にして続ける。last_state が無ければ conntrack を飛ばし、理由を示す。
func TestTeardownConntrack(t *testing.T) {
	cur, prev := tdKey(t), tdKey(t)
	t.Run("failure is a warning", func(t *testing.T) {
		path, _ := kernelCreds(t, cur, prev)
		k := &tdKernel{links: map[string]wgtypes.Key{"wgft0": cur}, table: true, flowsErr: errors.New("dump failed")}
		out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "warning: closing the agent's conntrack entries failed: dump failed") || k.table {
			t.Errorf("calls=%v output:\n%s", k.calls, out)
		}
	})
	t.Run("no last_state", func(t *testing.T) {
		path, f := kernelCreds(t, cur, prev)
		f.LastState = nil
		if err := f.Save(path); err != nil {
			t.Fatal(err)
		}
		k := &tdKernel{links: map[string]wgtypes.Key{"wgft0": cur}, table: true}
		out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
		if err != nil {
			t.Fatal(err)
		}
		for _, c := range k.calls {
			if c == "flows" {
				t.Errorf("conntrack ran without the tunnel address: %v", k.calls)
			}
		}
		if !strings.Contains(out, "skip: conntrack entries: agent.json has no last_state") {
			t.Errorf("output:\n%s", out)
		}
	})
}

// 停止中の rotate-key の後は今の鍵が空で、1 つ前の鍵だけが wgft0 を自分のものにする。
func TestTeardownAfterAStoppedRotateKey(t *testing.T) {
	cur, prev := tdKey(t), tdKey(t)
	path, f := kernelCreds(t, cur, prev)
	f.KeepPreviousKey()
	f.WGPrivateKey, f.LastState = "", nil
	if err := f.Save(path); err != nil {
		t.Fatal(err)
	}
	k := &tdKernel{links: map[string]wgtypes.Key{"wgft0": cur}, addrs: map[string]string{"wgft0": "10.200.0.5/24"}, table: true}
	out, err := runTeardown(t, k, TeardownOptions{CredentialsPath: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := k.links["wgft0"]; ok {
		t.Errorf("wgft0 with the previous key was not deleted:\n%s", out)
	}
	// last_state が無いので、conntrack は消す前の wgft0 のアドレスで見分ける
	if k.flowsAddr != "10.200.0.5/24" {
		t.Errorf("conntrack got the address %q, want wgft0's 10.200.0.5/24; calls=%v\n%s", k.flowsAddr, k.calls, out)
	}
}
