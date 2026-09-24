package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// A version 8 database, with an agent, rules and a generation already in it, moves to version 9 on
// Open. The existing agent stays enabled, and the rules, the generation and the agent's other
// columns are kept (design.md 5.1 節: 既存の行は有効のまま).
func TestMigrationFromV8KeepsAgentsEnabled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	dsn, err := sqliteDSN(path)
	if err != nil {
		t.Fatal(err)
	}
	// The version 8 data is written with SQL of its own: this binary's store methods already
	// read disabled_at, which a version 8 database does not have.
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		if _, err := db.Exec(migrations[i]); err != nil {
			t.Fatalf("v%d: %v", i+1, err)
		}
	}
	for _, q := range []string{
		"PRAGMA user_version = 8",
		`INSERT INTO agents (name, address, public_key, token_hash, created_at, registered_from) VALUES ('home', '10.200.0.2', 'pk', x'01', 500, '203.0.113.2')`,
		`INSERT INTO rules (id, position, json) VALUES ('r_a', 0, '{"id":"r_a","agent":"home","proto":"udp","listen_port":"2456","target":"192.168.1.20:2456","vps_mode":"kernel","enabled":true}')`,
		`INSERT INTO meta (key, value) VALUES ('generation', '7')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	db.Close()

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 9 {
		t.Fatalf("user_version = %d, %v; want 9", version, err)
	}
	a, err := s.AgentByName("home")
	if err != nil {
		t.Fatal(err)
	}
	if a.Disabled() || a.Address.String() != "10.200.0.2" || a.PublicKey != "pk" || a.RegisteredFrom != "203.0.113.2" || a.CreatedAt.Unix() != 500 {
		t.Errorf("agent after migration = %+v, want the version 8 row, enabled", a)
	}
	if gen, _ := s.Generation(); gen != 7 {
		t.Errorf("generation after migration = %d, want 7", gen)
	}
	if rules, err := s.Rules(); err != nil || len(rules) != 1 || rules[0].ID != "r_a" || !rules[0].Enabled {
		t.Errorf("rules after migration = %+v, %v", rules, err)
	}
	res, err := s.SetAgentDisabled("home", true, time.Unix(1000, 0), nil)
	if err != nil || !res.Changed || res.Generation != 8 {
		t.Fatalf("SetAgentDisabled after migration = %+v, %v", res, err)
	}
}

// A version 9 database is newer than a binary that only knows version 8 (v1.1.1), so that binary
// refuses to start instead of reading past the disabled mark and forwarding for a disabled agent
// again (design.md 5.1 節: fail-closed).
func TestV9DatabaseIsNewerForV8Binary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	saved := migrations
	migrations = saved[:8]
	defer func() { migrations = saved }()
	_, err = Open(path)
	if !errors.Is(err, ErrSchemaNewer) || err.Error() != fmt.Sprintf("%v: version 9, while this binary supports up to 8", ErrSchemaNewer) {
		t.Fatalf("Open with 8 migrations = %v, want ErrSchemaNewer for version 9", err)
	}
	if _, err := OpenReadOnly(path); !errors.Is(err, ErrSchemaNewer) {
		t.Fatalf("OpenReadOnly with 8 migrations = %v, want ErrSchemaNewer", err)
	}
}

func enabledRule(id, agent string, port uint16) proto.Rule {
	return proto.Rule{ID: id, Agent: agent, Proto: proto.UDP, ListenPort: proto.PortRange{Lo: port, Hi: port},
		Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true}
}

// Disable and enable advance the generation by one each time the state changes, and not at all when
// it does not. A repeated disable keeps the time of the first one. An unknown name is
// ErrAgentNotFound, and nothing about the rules' stored values changes.
func TestSetAgentDisabledIdempotentAndGeneration(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	if _, err := s.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, enabledRule("r_a", "home", 2456)), nil
	}); err != nil {
		t.Fatal(err)
	}

	first := time.Unix(1000, 0)
	res, err := s.SetAgentDisabled("home", true, first, nil)
	if err != nil || !res.Changed || res.Generation != 2 || !res.DisabledAt.Equal(first) {
		t.Fatalf("disable = %+v, %v; want changed at generation 2", res, err)
	}
	res, err = s.SetAgentDisabled("home", true, time.Unix(2000, 0), nil)
	if err != nil || res.Changed || res.Generation != 2 || !res.DisabledAt.Equal(first) {
		t.Fatalf("second disable = %+v, %v; want unchanged, generation 2, the first time kept", res, err)
	}
	a, err := s.AgentByName("home")
	if err != nil || !a.Disabled() || !a.DisabledAt.Equal(first) {
		t.Fatalf("agent = %+v, %v", a, err)
	}
	if list, _ := s.Agents(); len(list) != 1 || !list[0].DisabledAt.Equal(first) {
		t.Errorf("Agents() = %+v, want the disabled time", list)
	}
	if rules, _ := s.Rules(); !rules[0].Enabled {
		t.Error("disable must not rewrite the rule's stored enabled")
	}

	res, err = s.SetAgentDisabled("home", false, time.Unix(3000, 0), nil)
	if err != nil || !res.Changed || res.Generation != 3 || !res.DisabledAt.IsZero() {
		t.Fatalf("enable = %+v, %v; want changed at generation 3", res, err)
	}
	res, err = s.SetAgentDisabled("home", false, time.Unix(4000, 0), nil)
	if err != nil || res.Changed || res.Generation != 3 {
		t.Fatalf("second enable = %+v, %v; want unchanged at generation 3", res, err)
	}
	if a, _ := s.AgentByName("home"); a.Disabled() {
		t.Error("agent still disabled after enable")
	}

	_, err = s.SetAgentDisabled("ghost", true, first, nil)
	if !errors.Is(err, ErrAgentNotFound) || err.Error() != `agent "ghost" is not registered` {
		t.Errorf("unknown agent = %v, want ErrAgentNotFound", err)
	}
	if gen, _ := s.Generation(); gen != 3 {
		t.Errorf("generation after the unknown name = %d, want 3", gen)
	}
}

// The check runs only when the state changes, inside the transaction, and a refusal saves nothing:
// the agent stays disabled and the generation does not move.
func TestSetAgentDisabledCheckRefusalSavesNothing(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	if _, err := s.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, enabledRule("r_a", "home", 2456)), nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetAgentDisabled("home", true, time.Unix(1000, 0), nil); err != nil {
		t.Fatal(err)
	}
	refusal := errors.New("port is bound")
	var seen []proto.Rule
	_, err := s.SetAgentDisabled("home", false, time.Unix(2000, 0), func(rules []proto.Rule) error {
		seen = rules
		return refusal
	})
	if !errors.Is(err, refusal) {
		t.Fatalf("enable with a refusing check = %v", err)
	}
	if len(seen) != 1 || seen[0].ID != "r_a" {
		t.Errorf("check saw %+v, want the stored rules", seen)
	}
	if a, _ := s.AgentByName("home"); !a.Disabled() {
		t.Error("a refused enable must leave the agent disabled")
	}
	if gen, _ := s.Generation(); gen != 2 {
		t.Errorf("generation after a refused enable = %d, want 2", gen)
	}
	called := false
	if _, err := s.SetAgentDisabled("home", true, time.Unix(3000, 0), func([]proto.Rule) error { called = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("the check must not run when the state does not change")
	}
}

// The generation compares what is delivered (design.md 5.1 節). While the agent is disabled, turning
// one of its rules off or on changes nothing that is delivered, since the copy is enabled:false
// either way, so the generation stays. Adding a rule to it or changing a target does change the
// copy, and so does the same toggle once the agent is enabled.
func TestApplyBatchComparesTheDeliveredCopy(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	batch := func(mutate func([]proto.Rule) []proto.Rule) *BatchResult {
		t.Helper()
		res, err := s.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) { return mutate(rules), nil })
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	batch(func(r []proto.Rule) []proto.Rule { return append(r, enabledRule("r_a", "home", 2456)) })
	if _, err := s.SetAgentDisabled("home", true, time.Unix(1000, 0), nil); err != nil {
		t.Fatal(err)
	}
	gen, _ := s.Generation()

	res := batch(func(r []proto.Rule) []proto.Rule { r[0].Enabled = false; return r })
	if res.Changed || res.Generation != gen {
		t.Errorf("toggling a disabled agent's rule off = %+v, want no new generation", res)
	}
	res = batch(func(r []proto.Rule) []proto.Rule { r[0].Enabled = true; return r })
	if res.Changed || res.Generation != gen {
		t.Errorf("toggling a disabled agent's rule on = %+v, want no new generation", res)
	}
	res = batch(func(r []proto.Rule) []proto.Rule { return append(r, enabledRule("r_b", "home", 2460)) })
	if !res.Changed || res.Generation != gen+1 {
		t.Errorf("adding a rule to a disabled agent = %+v, want generation %d", res, gen+1)
	}
	res = batch(func(r []proto.Rule) []proto.Rule { r[0].Target = "192.168.1.21:2456"; return r })
	if !res.Changed || res.Generation != gen+2 {
		t.Errorf("changing a disabled agent's target = %+v, want generation %d", res, gen+2)
	}

	if _, err := s.SetAgentDisabled("home", false, time.Unix(2000, 0), nil); err != nil {
		t.Fatal(err)
	}
	gen, _ = s.Generation()
	res = batch(func(r []proto.Rule) []proto.Rule { r[0].Enabled = false; return r })
	if !res.Changed || res.Generation != gen+1 {
		t.Errorf("toggling an enabled agent's rule = %+v, want generation %d", res, gen+1)
	}
}

// Revoke deletes the row, and the disabled mark with it: an agent registered again under the same
// name starts enabled (design.md 5.1 節).
func TestRevokeClearsDisabledAndReregisterStartsEnabled(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	if _, err := s.SetAgentDisabled("home", true, time.Unix(1000, 0), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAgent("home"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AgentByName("home"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("AgentByName after revoke = %v", err)
	}
	registerAgent(t, s, "home")
	a, err := s.AgentByName("home")
	if err != nil || a.Disabled() {
		t.Fatalf("re-registered agent = %+v, %v; want enabled", a, err)
	}
}

// DeliveredRule masks enabled only for a disabled agent and keeps the rest of the copy.
func TestDeliveredRule(t *testing.T) {
	r := enabledRule("r_a", "home", 2456)
	if got := DeliveredRule(&r, false); got != r.ForAgent() {
		t.Errorf("enabled agent: %+v, want %+v", got, r.ForAgent())
	}
	want := r.ForAgent()
	want.Enabled = false
	if got := DeliveredRule(&r, true); got != want {
		t.Errorf("disabled agent: %+v, want %+v", got, want)
	}
	if !r.Enabled {
		t.Error("DeliveredRule modified the stored rule")
	}
}

// AgentSnapshot reads the agent's row, the rules and the generation in one transaction. An enable
// that commits while the snapshot is being read must not mix into it: the snapshot shows either the
// disabled agent at the old generation or the enabled agent at the new one, never the disabled flag
// with the new generation.
func TestAgentSnapshotIsOneRead(t *testing.T) {
	s := openTemp(t)
	registerAgent(t, s, "home")
	if _, err := s.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules, rule("r_a", proto.UDP, 2456, 2456, "192.168.1.20:2456")), nil
	}); err != nil {
		t.Fatal(err)
	}
	res, err := s.SetAgentDisabled("home", true, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	gen := res.Generation

	enabled := make(chan error, 1)
	testHookAgentSnapshot = func() {
		testHookAgentSnapshot = nil
		go func() {
			_, err := s.SetAgentDisabled("home", false, time.Now(), nil)
			enabled <- err
		}()
		// A snapshot that is one read holds the database, so the enable waits for it. Separate
		// reads let the enable commit here.
		select {
		case err := <-enabled:
			enabled <- err
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Cleanup(func() { testHookAgentSnapshot = nil })

	snap, err := s.AgentSnapshot("home")
	if err != nil {
		t.Fatal(err)
	}
	if !snap.Agent.Disabled() || snap.Generation != gen || len(snap.Rules) != 1 {
		t.Errorf("snapshot during the enable = disabled %v, generation %d, %d rules; want disabled, generation %d, 1 rule",
			snap.Agent.Disabled(), snap.Generation, len(snap.Rules), gen)
	}
	if err := <-enabled; err != nil {
		t.Fatal(err)
	}
	snap, err = s.AgentSnapshot("home")
	if err != nil {
		t.Fatal(err)
	}
	if snap.Agent.Disabled() || snap.Generation != gen+1 {
		t.Errorf("snapshot after the enable = disabled %v, generation %d; want enabled, generation %d", snap.Agent.Disabled(), snap.Generation, gen+1)
	}

	if _, err := s.AgentSnapshot("gone"); !errors.Is(err, sql.ErrNoRows) {
		t.Errorf("snapshot of an unregistered agent = %v, want sql.ErrNoRows", err)
	}
}
