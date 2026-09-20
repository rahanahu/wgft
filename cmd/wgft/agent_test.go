package main

import (
	"errors"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/agent"
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
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	srv := httptest.NewServer(admin.New(st, &fakeAgentBackend{agents: agents}))
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
			Tunnel: proto.TunnelStatus{State: proto.StatusOK},
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
			Tunnel:        proto.TunnelStatus{State: proto.StatusOK},
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
// 終了コード 3 で止まる(仕様 11a 節)。以前は internal/agent.ensureRegistered がプレーンな error を
// 返すだけで、cmd/wgft のどこもそれを *configError や *wg.StartupRefusal に写していなかったため、
// 終了コード 1 になり、同梱の agent.service(Restart=on-failure、RestartSec=2、
// RestartPreventExitStatus=3。この値を含まない)が 2 秒おきに再起動を繰り返していた。
// agent run を cobra 経由で実行し、実際の CLI の経路で確かめる。
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
			if got := exitCode(err); err == nil || got != exitConfigRefusal {
				t.Errorf("err=%v exitCode=%d, want %d", err, got, exitConfigRefusal)
			}
			if !isAgentConfigRefusal(err) {
				t.Errorf("isAgentConfigRefusal(%v) = false, want true", err)
			}
		})
	}
}

// TestAgentConfigRefusalExitsWithConfigRefusal is the unit-level counterpart of
// server_test.go's TestConntrackReadFailureExitsWithConfigRefusal, checking isAgentConfigRefusal
// and exitCode directly against internal/agent.ConfigRefusal.
func TestAgentConfigRefusalExitsWithConfigRefusal(t *testing.T) {
	err := &agent.ConfigRefusal{Reason: "not registered and no join string; provide via WGFT_JOIN or --join"}
	if !isAgentConfigRefusal(err) {
		t.Errorf("isAgentConfigRefusal(%v) = false, want true", err)
	}
	if got := exitCode(err); got != exitConfigRefusal {
		t.Errorf("exitCode(%v) = %d, want %d", err, got, exitConfigRefusal)
	}
	// sanity: confirm the type really is what isAgentConfigRefusal looks for.
	var refusal *agent.ConfigRefusal
	if !errors.As(error(err), &refusal) {
		t.Fatal("sanity: err is not a *agent.ConfigRefusal")
	}
	// a plain error, and nil, must not be misclassified.
	if isAgentConfigRefusal(errors.New("network unreachable")) {
		t.Error("isAgentConfigRefusal(plain error) = true, want false")
	}
	if isAgentConfigRefusal(nil) {
		t.Error("isAgentConfigRefusal(nil) = true, want false")
	}
}
