package main

import (
	"io"
	"net/http/httptest"
	"net/netip"
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

type fakeRuleBackend struct {
	st *store.Store
	// agentNames は Agents() が返す登録済みエージェントの名前(design.md 11a 節の
	// `rule add`/`rule set --dry-run` のテスト用)。未設定(nil)なら旧来どおり Agents() は
	// 空を返す。batchCalls は Batch が実際に呼ばれた回数で、--dry-run がそれを 1 度も
	// 呼ばないことをテストで確かめるために数える。rulesCalls・agentsCalls・serverInfoCalls は
	// 同じ理由で GET /api/v1/rules・/api/v1/agents・/api/v1/server それぞれの呼び出し回数を
	// 数える(行の形の誤りが admin API に一度も触れずに失敗することを確かめる
	// TestRuleAddDryRunShapeErrorNeverReachesAdminAPI 用)。
	agentNames                                           []string
	batchCalls, rulesCalls, agentsCalls, serverInfoCalls int
	// serverInfo is what ServerInfo() returns to a `--dry-run` building its reserved-port set
	// (design.md 11a 節, reservedFromServerInfo). Batch derives its own proto.Reserved from this
	// same value, via reservedPortsLikeVPSD below rather than reservedFromServerInfo, so a test
	// that sets serverInfo and then runs both a --dry-run and a real add against the same
	// fixture actually cross-checks two independent implementations instead of one comparing
	// itself to itself (see reservedPortsLikeVPSD's own comment). Zero value reserves nothing
	// (WGPort 0, empty AdminAddr/AgentAPIPort), matching prior behavior for tests that do not
	// care about reserved ports.
	serverInfo admin.ServerInfo
}

func (b *fakeRuleBackend) Rules() ([]proto.Rule, error) {
	b.rulesCalls++
	return b.st.Rules()
}
func (b *fakeRuleBackend) Generation() (uint64, error) { return b.st.Generation() }
func (b *fakeRuleBackend) Batch(req admin.BatchRequest) (*store.BatchResult, error) {
	b.batchCalls++
	reserved := reservedPortsLikeVPSD(b.serverInfo)
	return b.st.ApplyBatch(reserved, func(rules []proto.Rule) ([]proto.Rule, error) {
		return admin.ApplyBatchToRules(rules, req)
	})
}

// reservedPortsLikeVPSD builds the proto.Reserved set a real Batch would refuse a listen_port
// for, the same way fakeRuleBackend.Batch needs it for a test. It is written independently of
// cmd/wgft/rule.go's reservedFromServerInfo, as a separate copy of internal/vpsd/vpsd.go's
// construction of Daemon.reserved (around opts.WGPort/AdminAddr/AgentAPIAddr) instead of a call
// to that function: a test that runs both a --dry-run (which calls reservedFromServerInfo) and a
// real add (which, through this function, calls neither reservedFromServerInfo nor vpsd.go) and
// then compares the two outcomes only actually cross-checks reservedFromServerInfo against
// vpsd.go's rule when the two are implemented separately. Calling reservedFromServerInfo here, as
// this test double once did, would make such a test pass even if reservedFromServerInfo's rule
// silently drifted from vpsd.go's, since both sides would apply the same (wrong) rule.
func reservedPortsLikeVPSD(info admin.ServerInfo) proto.Reserved {
	reserved := proto.Reserved{uint16(info.WGPort): "WireGuard"}
	if ap, err := netip.ParseAddrPort(info.AdminAddr); err == nil {
		reserved[ap.Port()] = "admin API"
	}
	if ap, err := netip.ParseAddrPort("0.0.0.0:" + info.AgentAPIPort); err == nil {
		reserved[ap.Port()] = "agent API"
	}
	return reserved
}
func (b *fakeRuleBackend) AgentState(string) (*proto.State, error) { return &proto.State{}, nil }
func (b *fakeRuleBackend) Agents() ([]admin.AgentInfo, error) {
	b.agentsCalls++
	if b.agentNames == nil {
		return nil, nil
	}
	out := make([]admin.AgentInfo, len(b.agentNames))
	for i, n := range b.agentNames {
		out[i] = admin.AgentInfo{Name: n}
	}
	return out, nil
}
func (b *fakeRuleBackend) RuleDrops() (map[string]uint64, error) { return nil, nil }
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
func (b *fakeRuleBackend) ServerInfo() (admin.ServerInfo, error) {
	b.serverInfoCalls++
	return b.serverInfo, nil
}

// newRuleCLITestServer は空のルール集合を持つ管理 API サーバーを立て、CLI が --admin に
// 渡す URL(http://127.0.0.1:port)を返す。
func newRuleCLITestServer(t *testing.T) (adminURL string, st *store.Store) {
	t.Helper()
	url, st, _ := newRuleCLITestServerWithAgents(t)
	return url, st
}

// newRuleCLITestServerWithAgents is newRuleCLITestServer plus the backend itself, so a test
// can register agents (design.md 11a 節: rule add/set --dry-run checks GET /api/v1/agents) and
// later read batchCalls to confirm --dry-run never calls Batch.
func newRuleCLITestServerWithAgents(t *testing.T, agents ...string) (adminURL string, st *store.Store, backend *fakeRuleBackend) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	backend = &fakeRuleBackend{st: st, agentNames: agents}
	srv := httptest.NewServer(admin.New(backend))
	t.Cleanup(srv.Close)
	return srv.URL, st, backend
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

// TestRuleRatePacketAndLsTCPNotice は、TCP のルールに packet_rate を付けると
// `rule rate packet` と `rule ls` の両方が、packet_rate が TCP に効かない旨を stderr に
// 示すことを確かめる(design.md 7a.9 節)。rule add は packet_rate を直接受け取れないので
// (旨を出す経路ではない)、rule rate packet で付ける。
func TestRuleRatePacketAndLsTCPNotice(t *testing.T) {
	adminURL, _ := newRuleCLITestServer(t)

	_, _, err := runRuleCmd(t, adminURL, "add", "--agent", "home", "--tcp", "25565", "--to", "192.168.1.20:25565")
	if err != nil {
		t.Fatalf("rule add: %v", err)
	}

	// packet_rate が無い TCP のルールでは、rule ls は旨を stderr にも出さない
	_, stderr, err := runRuleCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("rule ls: %v", err)
	}
	if strings.Contains(stderr, "no effect on TCP") {
		t.Errorf("a TCP rule without packet_rate must not trigger the notice: stderr=%q", stderr)
	}

	// rule rate packet で TCP のルールに packet_rate を付けると、その場で旨が出る
	id := firstRuleID(t, adminURL)
	_, stderr, err = runRuleCmd(t, adminURL, "rate", "packet", id, "500/second")
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
