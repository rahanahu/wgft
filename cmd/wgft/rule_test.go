package main

import (
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、TCP のルールに packet_rate があるときの CLI の旨(design.md 7a.9 節。
// 書き出しと読み込みの互換のため値そのものは受け付けて保存するが、TCP には効かない)を
// 確かめる。fakeRuleBackend は internal/vpsd/admin の fakeBackend(その package の内部専用)
// を cmd/wgft から使えないので同じ形で持つ最小限の Backend 実装である。

type fakeRuleBackend struct{ st *store.Store }

func (b *fakeRuleBackend) Rules() ([]proto.Rule, error) { return b.st.Rules() }
func (b *fakeRuleBackend) Generation() (uint64, error)  { return b.st.Generation() }
func (b *fakeRuleBackend) Batch(req admin.BatchRequest) (*store.BatchResult, error) {
	return b.st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return admin.ApplyBatchToRules(rules, req)
	})
}
func (b *fakeRuleBackend) AgentState(string) (*proto.State, error) { return &proto.State{}, nil }
func (b *fakeRuleBackend) Agents() ([]admin.AgentInfo, error)      { return nil, nil }
func (b *fakeRuleBackend) RuleDrops() (map[string]uint64, error)   { return nil, nil }
func (b *fakeRuleBackend) JoinString(string) (admin.JoinStringResponse, error) {
	return admin.JoinStringResponse{}, nil
}
func (b *fakeRuleBackend) Revoke(string) error { return nil }
func (b *fakeRuleBackend) Warnings() ([]admin.Warning, error) {
	return nil, nil
}
func (b *fakeRuleBackend) DismissWarning(string, string, string) error { return nil }
func (b *fakeRuleBackend) CheckConnectivity(string) (admin.ConnCheck, error) {
	return admin.ConnCheck{}, nil
}
func (b *fakeRuleBackend) ServerInfo() (admin.ServerInfo, error) { return admin.ServerInfo{}, nil }

// newRuleCLITestServer は空のルール集合を持つ管理 API サーバーを立て、CLI が --admin に
// 渡す URL(http://127.0.0.1:port)を返す。
func newRuleCLITestServer(t *testing.T) (adminURL string, st *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(admin.New(st, &fakeRuleBackend{st: st}))
	t.Cleanup(srv.Close)
	return srv.URL, st
}

// runRuleCmd は `wgft rule ...` を実行し、標準出力・標準エラーを文字列として返す。
// rule.go のコマンドは cmd.OutOrStdout ではなく os.Stdout/os.Stderr に直接書くので、
// プロセスの標準出力・標準エラーそのものを一時的にパイプへ差し替えて捕まえる。
func runRuleCmd(t *testing.T, adminURL string, args ...string) (stdout, stderr string, err error) {
	t.Helper()

	captureFD := func(target **os.File) (restore func() string) {
		r, w, perr := os.Pipe()
		if perr != nil {
			t.Fatal(perr)
		}
		orig := *target
		*target = w
		var buf strings.Builder
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			io.Copy(&buf, r)
		}()
		return func() string {
			*target = orig
			w.Close()
			wg.Wait()
			r.Close()
			return buf.String()
		}
	}

	restoreOut := captureFD(&os.Stdout)
	restoreErr := captureFD(&os.Stderr)

	root := newRootCmd()
	fullArgs := append([]string{"rule"}, args...)
	fullArgs = append(fullArgs, "--admin", adminURL)
	root.SetArgs(fullArgs)
	root.SetOut(io.Discard)
	err = root.Execute()

	stdout = restoreOut()
	stderr = restoreErr()
	return stdout, stderr, err
}

// TestRuleAddTCPPacketRateNotice は、TCP のルールを packet_rate 付きで追加すると、
// packet_rate が TCP に効かない旨を 1 回示すことを確かめる(design.md 7a.9 節)。
// この経路では rule add は packet_rate を直接受け取れないので、rule rate packet で付ける。
func TestRuleAddTCPPacketRateNotice(t *testing.T) {
	adminURL, _ := newRuleCLITestServer(t)

	_, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--tcp", "25565", "--to", "192.168.1.20:25565")
	if err != nil {
		t.Fatalf("rule add: %v", err)
	}

	// packet_rate が無い TCP のルールでは旨を出さない
	res, _, err := runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	if strings.Contains(res, "no effect on TCP") {
		t.Errorf("a TCP rule without packet_rate must not trigger the notice: %s", res)
	}

	// rule rate packet で TCP のルールに packet_rate を付けると、その場で旨が出る
	id := firstRuleID(t, adminURL)
	_, stderr, err := runRuleCmd(t, adminURL, "rate", "packet", id, "500/second")
	if err != nil {
		t.Fatalf("rule rate packet: %v", err)
	}
	if !strings.Contains(stderr, "packet_rate is stored but has no effect on TCP rules") {
		t.Errorf("rule rate packet on a TCP rule must print the notice: stderr=%q", stderr)
	}

	// rule ls now shows the notice once, and UDP rules never trigger it
	stdout, stderr, err := runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	if !strings.Contains(stderr, "packet_rate is stored but has no effect on TCP rules") {
		t.Errorf("rule ls must print the notice once a TCP rule has packet_rate set: stderr=%q stdout=%q", stderr, stdout)
	}
	if strings.Count(stderr, "packet_rate is stored but has no effect on TCP rules") != 1 {
		t.Errorf("the notice must be printed exactly once, got: %q", stderr)
	}
}

// TestRuleAddUDPPacketRateNoNotice は、UDP のルールに packet_rate を設定しても
// 旨を出さないことを確かめる(packet_rate は UDP に効く。design.md 5.3, 7a.9 節)。
func TestRuleAddUDPPacketRateNoNotice(t *testing.T) {
	adminURL, _ := newRuleCLITestServer(t)

	if _, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--udp", "2456", "--to", "192.168.1.20:2456"); err != nil {
		t.Fatalf("rule add: %v", err)
	}
	id := firstRuleID(t, adminURL)

	_, stderr, err := runRuleCmd(t, adminURL, "rate", "packet", id, "500/second")
	if err != nil {
		t.Fatalf("rule rate packet: %v", err)
	}
	if strings.Contains(stderr, "no effect on TCP") {
		t.Errorf("a UDP rule must not trigger the TCP packet_rate notice: stderr=%q", stderr)
	}

	_, stderr, err = runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	if strings.Contains(stderr, "no effect on TCP") {
		t.Errorf("rule ls must not print the TCP notice for a UDP-only rule set: stderr=%q", stderr)
	}
}

// firstRuleID は管理 API から直接、最初のルールの ID を取り出す。
func firstRuleID(t *testing.T, adminURL string) string {
	t.Helper()
	c := &admin.Client{Base: adminURL}
	res, err := c.Rules()
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rules) == 0 {
		t.Fatal("no rules")
	}
	return res.Rules[0].ID
}
