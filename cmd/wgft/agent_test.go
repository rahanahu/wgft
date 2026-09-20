package main

import (
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// fakeAgentBackend is a minimal admin.Backend that serves a fixed Agents() list, for testing
// `wgft agent ls`'s handling of a disconnected agent's stale last report. The other methods
// are not exercised by `agent ls` and are stubbed out.
type fakeAgentBackend struct{ agents []admin.AgentInfo }

func (b *fakeAgentBackend) Rules() ([]proto.Rule, error) { return nil, nil }
func (b *fakeAgentBackend) Generation() (uint64, error)  { return 0, nil }
func (b *fakeAgentBackend) Batch(admin.BatchRequest) (*store.BatchResult, error) {
	return nil, errors.New("not implemented")
}
func (b *fakeAgentBackend) AgentState(string) (*proto.State, error) { return &proto.State{}, nil }
func (b *fakeAgentBackend) Agents() ([]admin.AgentInfo, error)      { return b.agents, nil }
func (b *fakeAgentBackend) RuleDrops() (map[string]uint64, error)   { return nil, nil }
func (b *fakeAgentBackend) JoinString(string) (admin.JoinStringResponse, error) {
	return admin.JoinStringResponse{}, nil
}
func (b *fakeAgentBackend) Revoke(string) error                         { return nil }
func (b *fakeAgentBackend) Warnings() ([]admin.Warning, error)          { return nil, nil }
func (b *fakeAgentBackend) DismissWarning(string, string, string) error { return nil }
func (b *fakeAgentBackend) CheckConnectivity(string) (admin.ConnCheck, error) {
	return admin.ConnCheck{}, nil
}
func (b *fakeAgentBackend) ServerInfo() (admin.ServerInfo, error) { return admin.ServerInfo{}, nil }

// newAgentCLITestServer starts a management API server backed by a fixed agent list and
// returns the URL to pass as --admin.
func newAgentCLITestServer(t *testing.T, agents []admin.AgentInfo) (adminURL string) {
	t.Helper()
	srv := httptest.NewServer(admin.New(&fakeAgentBackend{agents: agents}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// runAgentCmd runs `wgft agent ...` and returns stdout/stderr. Mirrors runRuleCmd
// (rule_test.go): agent.go's commands write to os.Stdout/os.Stderr directly, not
// cmd.OutOrStdout, so the process's real file descriptors are captured.
func runAgentCmd(t *testing.T, adminURL string, args ...string) (stdout, stderr string, err error) {
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
	fullArgs := append([]string{"agent"}, args...)
	fullArgs = append(fullArgs, "--admin", adminURL)
	root.SetArgs(fullArgs)
	root.SetOut(io.Discard)
	err = root.Execute()

	stdout = restoreOut()
	stderr = restoreErr()
	return stdout, stderr, err
}

// agentLsRow holds the parsed TUNNEL and RULES columns for one row of `agent ls` output.
type agentLsRow struct{ tunnel, rules string }

// agentLsFields finds the row for the given agent name in tabwriter output and splits it on
// runs of 2+ spaces (the column separator tabwriter pads with), returning the TUNNEL and
// RULES columns. Columns are located by the header row so this does not depend on which
// other columns are empty in a given test's fixture.
func agentLsFields(t *testing.T, stdout, agentName string) agentLsRow {
	t.Helper()
	lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
	if len(lines) < 1 {
		t.Fatalf("agent ls: no output")
	}
	header := lines[0]
	// tabwriter left-aligns and pads every column to a fixed width, so a column's header and
	// its value on every data row start at the same character offset; splitting on runs of
	// spaces instead would silently swallow an empty cell (e.g. WG_ENDPOINT with no value)
	// and misalign every column after it.
	col := func(name, nextName string) (start, end int) {
		start = strings.Index(header, name)
		if start < 0 {
			t.Fatalf("agent ls: header missing %q: %q", name, header)
		}
		end = len(header)
		if nextName != "" {
			if e := strings.Index(header, nextName); e >= 0 {
				end = e
			}
		}
		return start, end
	}
	tStart, tEnd := col("TUNNEL", "WG_ENDPOINT")
	rStart, rEnd := col("RULES", "WARN")
	slice := func(line string, start, end int) string {
		if start >= len(line) {
			return ""
		}
		if end > len(line) {
			end = len(line)
		}
		return strings.TrimRight(line[start:end], " ")
	}
	for _, line := range lines[1:] {
		if strings.HasPrefix(line, agentName+" ") {
			return agentLsRow{tunnel: slice(line, tStart, tEnd), rules: slice(line, rStart, rEnd)}
		}
	}
	t.Fatalf("agent ls: no row for agent %q in:\n%s", agentName, stdout)
	return agentLsRow{}
}

// TestAgentLsDisconnectedShowsLastReport confirms that `agent ls` marks a disconnected
// agent's TUNNEL and RULES as a last report ("last:" prefix) rather than printing its stale
// heartbeat content (tunnel ok, "N ok" rules) as if it were current. Before the fix, a
// disconnected agent with a healthy last heartbeat printed exactly like a connected, healthy
// one except for STREAM and HEARTBEAT.
func TestAgentLsDisconnectedShowsLastReport(t *testing.T) {
	old := time.Now().Add(-3 * time.Hour).Format(time.RFC3339)
	agents := []admin.AgentInfo{
		{
			Name: "office", Address: "10.200.0.3", Connected: false, LastHeartbeat: old,
			Tunnel: admin.TunnelStatus{State: proto.StatusOK},
			Rules:  []proto.RuleStatus{{ID: "r_a", State: proto.StatusOK}},
		},
	}
	adminURL := newAgentCLITestServer(t, agents)

	stdout, _, err := runAgentCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("agent ls: %v", err)
	}
	fields := agentLsFields(t, stdout, "office")
	if fields.tunnel != "last:ok" {
		t.Errorf("disconnected agent's TUNNEL = %q, want the last: prefix (a stale report, not the current state)", fields.tunnel)
	}
	if fields.rules != "last:1 ok" {
		t.Errorf("disconnected agent's RULES = %q, want the last: prefix (a stale report, not the current state)", fields.rules)
	}
}

// TestAgentLsConnectedStillShowsLiveState is the control: a connected agent's TUNNEL and
// RULES print without the "last:" prefix.
func TestAgentLsConnectedStillShowsLiveState(t *testing.T) {
	agents := []admin.AgentInfo{
		{
			Name: "home", Address: "10.200.0.2", Connected: true, StreamFrom: "203.0.113.10:51820",
			LastHeartbeat: time.Now().Format(time.RFC3339),
			Tunnel:        admin.TunnelStatus{State: proto.StatusOK},
			Rules:         []proto.RuleStatus{{ID: "r_a", State: proto.StatusOK}},
		},
	}
	adminURL := newAgentCLITestServer(t, agents)

	stdout, _, err := runAgentCmd(t, adminURL, "ls")
	if err != nil {
		t.Fatalf("agent ls: %v", err)
	}
	if strings.Contains(stdout, "last:") {
		t.Errorf("connected agent must not be marked as a stale last report, got:\n%s", stdout)
	}
	fields := agentLsFields(t, stdout, "home")
	if fields.tunnel != "ok" {
		t.Errorf("connected agent's TUNNEL = %q, want the live state \"ok\" unprefixed", fields.tunnel)
	}
	if fields.rules != "1 ok" {
		t.Errorf("connected agent's RULES = %q, want \"1 ok\" unprefixed", fields.rules)
	}
}

// WGFT_JOIN 自体が原因の起動中止(初回登録前の欠落、構文の誤り)は、ネットワークに触る前に
// 終了コード 3 で止まる(設計文書 11b 節)。以前は internal/agent.ensureRegistered がプレーンな error を
// 返すだけで、cmd/wgft のどこもそれを拒否に写していなかったため、終了コード 1 になり、同梱の
// agent.service(Restart=on-failure、RestartSec=2、RestartPreventExitStatus=3。この値を含まない)が
// 2 秒おきに再起動を繰り返していた。agent run を cobra 経由で実行し、実際の CLI の経路で確かめる。
func TestAgentJoinErrorsExitCode(t *testing.T) {
	none := filepath.Join(t.TempDir(), "none.env")
	cases := []struct {
		name string
		join string
	}{
		{"no join, not registered", ""},
		{"malformed join", "not-a-join-string"},
		{"join with no port", "wgft://example.com/tok#sha256:00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("WGFT_JOIN", tc.join)
			root := newRootCmd()
			root.SetArgs([]string{"agent", "run", "--config", none, "--data-dir", t.TempDir()})
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			err := root.Execute()
			if got := exitCode(err); err == nil || got != exitRefusal {
				t.Errorf("err=%v exitCode=%d, want %d", err, got, exitRefusal)
			}
			r := startup.Of(err)
			if r == nil || r.Subject != "WGFT_JOIN" {
				t.Errorf("refusal = %v, want one about WGFT_JOIN", r)
			}
		})
	}
}

// TestEveryAgentSettingIsCheckedAtTheDoor is the agent's counterpart of server_test.go's
// TestEveryServerSettingIsCheckedAtTheDoor: it walks every WGFT_* setting agent run reads
// (agentSpecs, so a new setting shows up here on its own) and requires a malformed value for each
// one to exit 3 at the door. The two settings that cannot be judged from the value alone are listed
// with the reason, so adding a setting without deciding this fails the test (docs/design.md 11b 節).
func TestEveryAgentSettingIsCheckedAtTheDoor(t *testing.T) {
	bad := map[string]string{
		"WGFT_DATA_DIR":      "  ",
		"WGFT_JOIN":          "",
		"WGFT_NAME":          "",
		allowtargets.Env:     "192.168.1.0/33",
		"WGFT_MAX_UDP_FLOWS": "0",
		"WGFT_MAX_TCP_FLOWS": "one",
	}
	noBadValue := map[string]string{
		"WGFT_JOIN": "malformed is judged at registration, not at the door: a registered agent never reads a stale value (11a 節), so refusing here would stop an agent that works",
		"WGFT_NAME": "the naming rule lives in the server (internal/vpsd/store); the registration API's HTTP 400 becomes the config refusal",
	}
	for _, sp := range agentSpecs() {
		if _, ok := bad[sp.Env]; !ok {
			t.Errorf("%s is read by agentSpecs but has no malformed value in this table; add one, or add a reason to noBadValue", sp.Env)
		}
	}
	for _, sp := range agentSpecs() {
		value := bad[sp.Env]
		if value == "" {
			if _, ok := noBadValue[sp.Env]; !ok {
				t.Errorf("%s has an empty malformed value and no reason in noBadValue", sp.Env)
			}
			continue
		}
		t.Run(sp.Env, func(t *testing.T) {
			t.Setenv(sp.Env, value)
			root := newRootCmd()
			root.SetArgs([]string{"agent", "run", "--config", filepath.Join(t.TempDir(), "none.env"), "--data-dir", t.TempDir()})
			root.SetOut(io.Discard)
			root.SetErr(io.Discard)
			done := make(chan error, 1)
			go func() { done <- root.Execute() }()
			var err error
			select {
			case err = <-done:
			case <-time.After(30 * time.Second):
				t.Fatalf("%s=%q: agent run did not return; the door does not check this setting", sp.Env, value)
			}
			if got := exitCode(err); err == nil || got != exitRefusal {
				t.Fatalf("%s=%q: err=%v exitCode=%d, want %d", sp.Env, value, err, got, exitRefusal)
			}
			if r := startup.Of(err); r == nil || r.Category != startup.CategoryConfig {
				t.Errorf("%s=%q: refusal = %v, want category %q", sp.Env, value, r, startup.CategoryConfig)
			}
		})
	}
}

// 登録済みの agent は、compose に残った壊れた WGFT_JOIN では止まらない(設計文書 11a・11b 節)。
// 値だけから構文の誤りは分かるが、その値を使うかどうかは認証情報ファイルで決まるので、入口では
// 警告だけを出す。ここでは、登録済みの認証情報を置いたうえで、拒否にならないことを確かめる。
// agent.Run はこの後で stream に接続しようとして失敗するが、その失敗は拒否ではない。
func TestRegisteredAgentIsNotRefusedForMalformedJoin(t *testing.T) {
	dir := t.TempDir()
	// 到達できないエンドポイントを持つ登録済みの認証情報。stream の接続は失敗するが、それは
	// 再試行で直りうる失敗なので終了コード 1 である。
	body := `{"name":"home","endpoint":"127.0.0.1:1","cert_sha256":"` + strings.Repeat("ab", 32) + `","permanent_token":"tok"}`
	if err := os.WriteFile(filepath.Join(dir, "agent.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WGFT_JOIN", "not-a-join-string")
	cmd := &cobra.Command{Use: "run", RunE: func(*cobra.Command, []string) error { return nil }}
	cmd.Flags().String("data-dir", dir, "")
	cmd.Flags().String("join", "", "")
	cmd.Flags().String("name", "", "")
	cmd.Flags().String("agent-allow-targets", "", "")
	cmd.Flags().String("config", filepath.Join(dir, "none.env"), "")
	registerLimitFlags(cmd.Flags())
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	opts, _, err := buildAgentOptions(cmd)
	if err != nil {
		t.Fatalf("buildAgentOptions = %v, want no refusal for a stale malformed join on a registered agent", err)
	}
	if opts.Join != "not-a-join-string" {
		t.Errorf("opts.Join = %q, want the value passed through unchanged", opts.Join)
	}
}

// TestAgentRefusalExitsWithRefusalCode is the unit-level counterpart: a refusal from any layer maps
// to exit code 3, and an ordinary error to 1, through the single check in exitCode.
func TestAgentRefusalExitsWithRefusalCode(t *testing.T) {
	err := startup.Config("WGFT_JOIN", "not registered and no join string; provide via WGFT_JOIN or --join")
	if got := exitCode(err); got != exitRefusal {
		t.Errorf("exitCode(%v) = %d, want %d", err, got, exitRefusal)
	}
	// wrapping must not hide it: the agent wraps a re-registration refusal with context.
	if got := exitCode(fmt.Errorf("re-register failed: %w", err)); got != exitRefusal {
		t.Errorf("exitCode(wrapped) = %d, want %d", got, exitRefusal)
	}
	if got := exitCode(errors.New("network unreachable")); got != 1 {
		t.Errorf("exitCode(plain error) = %d, want 1", got)
	}
}
