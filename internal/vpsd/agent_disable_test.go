//go:build linux

package vpsd

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// eventLog records, in order, the deliveries (onPushAll) and the publications (the participant's
// Prepare) a disable or an enable makes, so the tests can check the order design.md 5.1 節 fixes.
type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) take() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := l.events
	l.events = nil
	return out
}

// recordingParticipant publishes whatever it is given, or fails the whole transaction while err is
// set, and records each attempt with the rule IDs of the Plan it was asked to publish.
type recordingParticipant struct {
	log *eventLog
	mu  sync.Mutex
	err error
	// drift is what Observe reports as drifted (converge_gate_test.go).
	drift []string
}

func (p *recordingParticipant) setErr(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.err = err
}

func (p *recordingParticipant) Observe() (dataplane.Observed, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return dataplane.Observed{Drift: p.drift}, nil
}
func (p *recordingParticipant) Repair() dataplane.Committed { return dataplane.Committed{} }

func (p *recordingParticipant) Prepare(d dataplane.Desired) (dataplane.Prepared, error) {
	p.mu.Lock()
	err := p.err
	p.mu.Unlock()
	if err != nil {
		p.log.add("publish failed")
		return nil, err
	}
	ids := []string{}
	for _, pp := range d.Plan.Ports {
		ids = append(ids, pp.RuleID)
	}
	sort.Strings(ids)
	p.log.add("publish " + strings.Join(ids, ","))
	return holdPrepared{}, nil
}

// disableDataplane is holdDataplane with a configurable result for the two reads the enable's
// write-time checks make.
type disableDataplane struct {
	holdDataplane
	bound      linux.Bound
	boundErr   error
	inspectErr error
}

func (d *disableDataplane) BoundPorts() (linux.Bound, error) { return d.bound, d.boundErr }
func (d *disableDataplane) Inspect() (*linux.Report, error) {
	if d.inspectErr != nil {
		return nil, d.inspectErr
	}
	return &linux.Report{}, nil
}

type disableFixture struct {
	d   *Daemon
	st  *store.Store
	dp  *disableDataplane
	p   *recordingParticipant
	log *eventLog
}

// newDisableFixture builds a Daemon with two registered agents, home and other. home has rules A
// (TCP, enabled), B (UDP, disabled) and C (UDP, enabled), the example of design.md 5.1 節, and other
// has one enabled rule. The first apply has already published A, C and O.
func newDisableFixture(t *testing.T) *disableFixture {
	t.Helper()
	st := openTestStore(t)
	for _, name := range []string{"home", "other"} {
		tok, err := st.IssueJoinToken(name, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := st.Register(tok, name, "203.0.113.2", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
			t.Fatal(err)
		}
	}
	port := func(p uint16) proto.PortRange { return proto.PortRange{Lo: p, Hi: p} }
	if _, err := st.ApplyBatch(nil, func(rules []proto.Rule) ([]proto.Rule, error) {
		return append(rules,
			proto.Rule{ID: "r_a", Agent: "home", Proto: proto.TCP, ListenPort: port(25565), Target: "192.168.1.30:25565", VPSMode: proto.ModeKernel, Enabled: true},
			proto.Rule{ID: "r_b", Agent: "home", Proto: proto.UDP, ListenPort: port(2456), Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel},
			proto.Rule{ID: "r_c", Agent: "home", Proto: proto.UDP, ListenPort: port(2458), Target: "192.168.1.21:2456", VPSMode: proto.ModeKernel, Enabled: true},
			proto.Rule{ID: "r_o", Agent: "other", Proto: proto.UDP, ListenPort: port(3000), Target: "192.168.2.20:3000", VPSMode: proto.ModeKernel, Enabled: true},
		), nil
	}); err != nil {
		t.Fatal(err)
	}
	log := &eventLog{}
	p := &recordingParticipant{log: log}
	dp := &disableDataplane{holdDataplane: holdDataplane{p: p}, bound: linux.Bound{}}
	d := &Daemon{st: st, dp: dp, serverKey: testKey(t), network: netip.MustParsePrefix("10.200.0.0/24"),
		opts: Options{Mode: modeKernel, WGInterface: "wgft0", MTU: 1420}}
	d.onPushAll = func() { log.add("deliver") }
	d.hub = d.newHub(d)
	captureLog(t)
	d.mu.Lock()
	err := d.applyNFT(rulesOf(t, st))
	d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := log.take(); !sameEvents(got, "publish r_a,r_c,r_o", "deliver") {
		t.Fatalf("first apply = %v", got)
	}
	return &disableFixture{d: d, st: st, dp: dp, p: p, log: log}
}

func sameEvents(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// Disable delivers before it publishes, and the publication leaves every rule of the agent out while
// the other agent's rule stays. Enable publishes first and delivers only after, and brings A and C
// back while B stays out by its own setting. The stored rules are never rewritten.
func TestDisableAndEnableOrderAndEffect(t *testing.T) {
	f := newDisableFixture(t)

	res, err := f.d.DisableAgent("home")
	if err != nil {
		t.Fatal(err)
	}
	if res != (admin.AgentDisabledResponse{Name: "home", Disabled: true, Changed: true, Generation: 2}) {
		t.Errorf("disable = %+v", res)
	}
	if got := f.log.take(); !sameEvents(got, "deliver", "publish r_o") {
		t.Errorf("disable events = %v, want the delivery before the publication of only r_o", got)
	}
	rules := rulesOf(t, f.st)
	if !rules[0].Enabled || rules[1].Enabled || !rules[2].Enabled {
		t.Errorf("stored rules changed by disable: %+v", rules)
	}
	for _, id := range []string{"r_a", "r_c"} {
		if rs := applyStatusOf(t, f.d).Rules[id]; rs.ApplyState != admin.ApplyNotActive || rs.Reason != `agent "home" is disabled` {
			t.Errorf("%s apply state = %+v", id, rs)
		}
	}
	if rs := applyStatusOf(t, f.d).Rules["r_b"]; rs.Reason != "disabled" {
		t.Errorf("r_b reason = %q, want its own disabled", rs.Reason)
	}

	// A second disable changes nothing, delivers nothing and keeps the generation.
	res, err = f.d.DisableAgent("home")
	if err != nil || res.Changed || res.Generation != 2 || !res.Disabled {
		t.Errorf("second disable = %+v, %v", res, err)
	}
	if got := f.log.take(); len(got) != 0 {
		t.Errorf("second disable events = %v, want none", got)
	}

	res, err = f.d.EnableAgent("home")
	if err != nil {
		t.Fatal(err)
	}
	if res != (admin.AgentDisabledResponse{Name: "home", Changed: true, Generation: 3}) {
		t.Errorf("enable = %+v", res)
	}
	if got := f.log.take(); !sameEvents(got, "publish r_a,r_c,r_o", "deliver") {
		t.Errorf("enable events = %v, want the publication of A, C and O before the delivery", got)
	}

	res, err = f.d.EnableAgent("home")
	if err != nil || res.Changed || res.Generation != 3 {
		t.Errorf("second enable = %+v, %v", res, err)
	}
	if got := f.log.take(); len(got) != 0 {
		t.Errorf("second enable events = %v, want none", got)
	}
}

// An operation that changes nothing answers success with changed false and does nothing else, even
// while the data plane cannot publish: no save, no delivery and no publication (design.md 7a.11
// 節). Publishing what an earlier operation left unpublished is the 30s retry's job.
func TestUnchangedDisableAndEnableDoNothing(t *testing.T) {
	f := newDisableFixture(t)
	f.p.setErr(errors.New("netlink: no buffer space available"))
	res, err := f.d.EnableAgent("home")
	if err != nil || res != (admin.AgentDisabledResponse{Name: "home", Generation: 1}) {
		t.Errorf("enable of an enabled agent = %+v, %v; want success, unchanged", res, err)
	}
	if got := f.log.take(); len(got) != 0 {
		t.Errorf("enable of an enabled agent: events %v, want none", got)
	}

	if _, err := f.d.DisableAgent("home"); err == nil {
		t.Fatal("the disable must report the failed publication")
	}
	f.log.take()
	res, err = f.d.DisableAgent("home")
	if err != nil || res != (admin.AgentDisabledResponse{Name: "home", Disabled: true, Generation: 2}) {
		t.Errorf("disable of a disabled agent, publication still failing = %+v, %v; want success, unchanged", res, err)
	}
	if got := f.log.take(); len(got) != 0 {
		t.Errorf("disable of a disabled agent: events %v, want none", got)
	}
}

// A generation an earlier failed enable left unpublished is delivered by whichever apply publishes
// it, not only by the retry: here a batch that changes nothing. Before the delivery was made in one
// place, that batch published the enable, cleared the need to retry, and home never received it.
func TestLaterPublicationDeliversAFailedEnable(t *testing.T) {
	f := newDisableFixture(t)
	if _, err := f.d.DisableAgent("home"); err != nil {
		t.Fatal(err)
	}
	f.log.take()
	f.p.setErr(errors.New("netlink: no buffer space available"))
	_, err := f.d.EnableAgent("home")
	var ce *admin.AgentChangeError
	if !errors.As(err, &ce) || !ce.Saved {
		t.Fatalf("enable = %v, want saved-not-published", err)
	}
	f.log.take()

	f.p.setErr(nil)
	res, err := f.d.Batch(admin.BatchRequest{})
	if err != nil || res.Changed {
		t.Fatalf("empty batch = %+v, %v", res, err)
	}
	if got := f.log.take(); !sameEvents(got, "publish r_a,r_c,r_o", "deliver") {
		t.Errorf("empty batch events = %v, want the enable published and delivered", got)
	}
	if st, _ := f.d.ApplyStatus(); st.ActiveGeneration != 3 {
		t.Errorf("active generation = %d, want 3", st.ActiveGeneration)
	}
	// Nothing is left to deliver: another empty batch publishes the same generation and stays quiet.
	if _, err := f.d.Batch(admin.BatchRequest{}); err != nil {
		t.Fatal(err)
	}
	if got := f.log.take(); !sameEvents(got, "publish r_a,r_c,r_o") {
		t.Errorf("second empty batch events = %v, want no delivery", got)
	}
}

func applyStatusOf(t *testing.T, d *Daemon) admin.ApplyStatus {
	t.Helper()
	st, ok := d.ApplyStatus()
	if !ok {
		t.Fatal("no apply status")
	}
	return st
}

// A failed publication after the disable is saved still delivers the stop to the agents (it went
// out first) and reports saved-not-published. A failed publication after the enable is saved
// delivers nothing: the agents stay stopped until a retry publishes, and the retry delivers then.
func TestDisableAndEnablePublishFailure(t *testing.T) {
	f := newDisableFixture(t)
	f.p.setErr(errors.New("netlink: no buffer space available"))

	_, err := f.d.DisableAgent("home")
	var ce *admin.AgentChangeError
	if !errors.As(err, &ce) || !ce.Saved {
		t.Fatalf("disable with a failing publication = %v, want saved-not-published", err)
	}
	if !strings.HasPrefix(err.Error(), "saved: agent home is disabled in the server database, but the change is not published yet: ") {
		t.Errorf("message = %q", err.Error())
	}
	if got := f.log.take(); !sameEvents(got, "deliver", "publish failed") {
		t.Errorf("events = %v, want the delivery even though the publication failed", got)
	}
	if a, _ := f.st.AgentByName("home"); !a.Disabled() {
		t.Error("the disable must stay saved")
	}
	// The retry publishes it, and does not deliver it a second time.
	f.p.setErr(nil)
	f.d.retryOnce()
	if got := f.log.take(); !sameEvents(got, "publish r_o") {
		t.Errorf("retry events = %v, want the disabled agent's rules left out and no second delivery", got)
	}

	f.p.setErr(errors.New("netlink: no buffer space available"))
	_, err = f.d.EnableAgent("home")
	if !errors.As(err, &ce) || !ce.Saved {
		t.Fatalf("enable with a failing publication = %v, want saved-not-published", err)
	}
	if got := f.log.take(); !sameEvents(got, "publish failed") {
		t.Errorf("events = %v, want no delivery after a failed publication", got)
	}
	// The retry publishes it and delivers it then.
	f.p.setErr(nil)
	f.d.retryOnce()
	if got := f.log.take(); !sameEvents(got, "publish r_a,r_c,r_o", "deliver") {
		t.Errorf("retry events = %v, want the delivery once published", got)
	}
}

// Enable runs the batch's write-time checks on the agent's enabled rules, with no force override. A
// port bound on the VPS refuses it and saves nothing. A disabled rule of the agent is not checked,
// the same as in a batch. A failure to read what the checks need is not a refusal.
func TestEnableRunsTheWriteTimeChecks(t *testing.T) {
	f := newDisableFixture(t)
	if _, err := f.d.DisableAgent("home"); err != nil {
		t.Fatal(err)
	}
	f.log.take()

	// Another agent's port is bound: only the enabled agent's own rules are checked.
	f.dp.bound = linux.Bound{proto.UDP: {3000: {netip.MustParseAddr("0.0.0.0")}}}
	if _, err := f.d.EnableAgent("home"); err != nil {
		t.Fatalf("enable with only another agent's port bound = %v", err)
	}
	if _, err := f.d.DisableAgent("home"); err != nil {
		t.Fatal(err)
	}
	f.log.take()

	// r_b's port is bound: r_b is disabled by its own setting, so it is not checked.
	f.dp.bound = linux.Bound{proto.UDP: {2456: {netip.MustParseAddr("0.0.0.0")}}}
	if _, err := f.d.EnableAgent("home"); err != nil {
		t.Fatalf("enable with only a disabled rule's port bound = %v", err)
	}
	if _, err := f.d.DisableAgent("home"); err != nil {
		t.Fatal(err)
	}
	f.log.take()
	genBefore, _ := f.st.Generation()

	f.dp.bound = linux.Bound{proto.TCP: {25565: {netip.MustParseAddr("0.0.0.0")}}}
	_, err := f.d.EnableAgent("home")
	var ce *admin.AgentChangeError
	if !errors.As(err, &ce) || ce.Saved {
		t.Fatalf("enable with r_a's port bound = %v, want refused with nothing saved", err)
	}
	if !strings.HasPrefix(err.Error(), "refused to enable agent home; nothing changed: rule r_a: tcp/25565 is bound") ||
		!strings.HasSuffix(err.Error(), "; risk of locking out SSH etc.; free the port and enable the agent again") ||
		strings.Contains(err.Error(), "--force") {
		t.Errorf("message = %q", err.Error())
	}
	if a, _ := f.st.AgentByName("home"); !a.Disabled() {
		t.Error("a refused enable must leave the agent disabled")
	}
	if gen, _ := f.st.Generation(); gen != genBefore {
		t.Errorf("generation moved from %d to %d on a refusal", genBefore, gen)
	}
	if got := f.log.take(); len(got) != 0 {
		t.Errorf("events = %v, want nothing published or delivered on a refusal", got)
	}

	f.dp.bound = linux.Bound{}
	f.dp.boundErr = errors.New("/proc/net/tcp: permission denied")
	_, err = f.d.EnableAgent("home")
	if err == nil || errors.As(err, &ce) {
		t.Fatalf("enable with an unreadable bound-port list = %v, want a plain error", err)
	}
	f.dp.boundErr = nil
	f.dp.inspectErr = errors.New("nft: not found")
	if _, err = f.d.EnableAgent("home"); err == nil || errors.As(err, &ce) {
		t.Fatalf("enable with a failed inspection = %v, want a plain error", err)
	}
	f.dp.inspectErr = nil
	if _, err := f.d.EnableAgent("home"); err != nil {
		t.Fatalf("enable once the port is free = %v", err)
	}
}

// An unknown name is store.ErrAgentNotFound for both, and a failed save is a plain error.
func TestDisableAndEnableUnknownAndSaveFailure(t *testing.T) {
	f := newDisableFixture(t)
	for _, op := range []func(string) (admin.AgentDisabledResponse, error){f.d.DisableAgent, f.d.EnableAgent} {
		if _, err := op("ghost"); !errors.Is(err, store.ErrAgentNotFound) {
			t.Errorf("unknown name = %v", err)
		}
	}
	f.st.Close()
	var ce *admin.AgentChangeError
	for _, op := range []func(string) (admin.AgentDisabledResponse, error){f.d.DisableAgent, f.d.EnableAgent} {
		if _, err := op("home"); err == nil || errors.As(err, &ce) || errors.Is(err, store.ErrAgentNotFound) {
			t.Errorf("closed store = %v, want a plain error", err)
		}
	}
}

// The state delivered to a disabled agent carries every rule as enabled:false and agent_disabled,
// and another agent's state is untouched. After enable, each rule is back to its own setting.
func TestAgentStateMasksADisabledAgent(t *testing.T) {
	f := newDisableFixture(t)
	if _, err := f.d.DisableAgent("home"); err != nil {
		t.Fatal(err)
	}
	st, err := f.d.AgentState("home")
	if err != nil {
		t.Fatal(err)
	}
	if !st.AgentDisabled || len(st.Rules) != 3 {
		t.Fatalf("state = %+v", st)
	}
	for _, r := range st.Rules {
		if r.Enabled {
			t.Errorf("rule %s delivered enabled to a disabled agent", r.ID)
		}
	}
	b, _ := json.Marshal(st)
	if !strings.Contains(string(b), `"agent_disabled":true`) {
		t.Errorf("wire form = %s", b)
	}
	other, err := f.d.AgentState("other")
	if err != nil || other.AgentDisabled || len(other.Rules) != 1 || !other.Rules[0].Enabled {
		t.Errorf("other agent's state = %+v, %v", other, err)
	}
	if b, _ := json.Marshal(other); strings.Contains(string(b), "agent_disabled") {
		t.Errorf("an enabled agent's state must omit agent_disabled: %s", b)
	}

	if _, err := f.d.EnableAgent("home"); err != nil {
		t.Fatal(err)
	}
	st, _ = f.d.AgentState("home")
	want := map[string]bool{"r_a": true, "r_b": false, "r_c": true}
	for _, r := range st.Rules {
		if r.Enabled != want[r.ID] {
			t.Errorf("after enable, rule %s enabled = %v", r.ID, r.Enabled)
		}
	}
	if st.AgentDisabled {
		t.Error("agent_disabled after enable")
	}
}

// The connectivity check refuses a disabled agent's rule, as it refuses a disabled rule.
func TestCheckConnectivityRefusesADisabledAgentsRule(t *testing.T) {
	f := newDisableFixture(t)
	if _, err := f.d.DisableAgent("home"); err != nil {
		t.Fatal(err)
	}
	_, err := f.d.CheckConnectivity("r_a")
	if err == nil || err.Error() != "cannot check a rule of a disabled agent: agent home is disabled" {
		t.Errorf("check = %v", err)
	}
}

// The agent list carries disabled always and disabled_at only for a disabled agent.
func TestAgentsListDisabled(t *testing.T) {
	// A zone other than UTC, so that a timestamp written in UTC stands out against created_at.
	savedLocal := time.Local
	time.Local = time.FixedZone("JST", 9*60*60)
	t.Cleanup(func() { time.Local = savedLocal })
	f := newDisableFixture(t)
	if _, err := f.d.DisableAgent("home"); err != nil {
		t.Fatal(err)
	}
	list, err := f.d.Agents()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(list)
	var raw []map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	for _, a := range raw {
		switch a["name"] {
		case "home":
			if a["disabled"] != true {
				t.Errorf("home disabled = %v", a["disabled"])
			}
			at, _ := a["disabled_at"].(string)
			if _, err := time.Parse(time.RFC3339, at); err != nil || strings.Contains(at, ".") {
				t.Errorf("home disabled_at = %q, want seconds RFC3339", at)
			}
			// the same offset convention as created_at in the same object: both are written in the
			// server's local zone, so under a zone other than UTC neither ends in Z
			created, _ := a["created_at"].(string)
			if strings.HasSuffix(at, "Z") != strings.HasSuffix(created, "Z") || at[len(at)-6:] != created[len(created)-6:] {
				t.Errorf("disabled_at %q and created_at %q use different offsets", at, created)
			}
		case "other":
			if v, ok := a["disabled"]; !ok || v != false {
				t.Errorf("other disabled = %v, %v; want false, present", v, ok)
			}
			if _, ok := a["disabled_at"]; ok {
				t.Error("an enabled agent must omit disabled_at")
			}
		}
	}
}

// Through the admin API with the real Daemon behind it: the two 422s are told apart by saved alone,
// and the client turns them back into *admin.AgentChangeError.
func TestAgentChangeOverTheAdminAPI(t *testing.T) {
	f := newDisableFixture(t)
	srv := httptest.NewServer(admin.New(f.d))
	defer srv.Close()
	c := &admin.Client{Base: srv.URL}

	post := func(path string) (int, map[string]any) {
		t.Helper()
		resp, err := http.Post(srv.URL+path, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var body map[string]any
		json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}
	if code, body := post("/api/v1/agents/home/disable"); code != http.StatusOK || body["disabled"] != true || body["changed"] != true || body["name"] != "home" {
		t.Fatalf("disable = %d %v", code, body)
	}
	if code, body := post("/api/v1/agents/ghost/enable"); code != http.StatusNotFound || body["saved"] != false {
		t.Errorf("unknown = %d %v", code, body)
	}

	f.dp.bound = linux.Bound{proto.TCP: {25565: {netip.MustParseAddr("0.0.0.0")}}}
	if code, body := post("/api/v1/agents/home/enable"); code != http.StatusUnprocessableEntity || body["saved"] != false {
		t.Errorf("refused enable = %d %v, want 422 saved:false", code, body)
	}
	_, err := c.EnableAgent("home")
	var ce *admin.AgentChangeError
	if !errors.As(err, &ce) || ce.Saved {
		t.Errorf("client refused enable = %v", err)
	}

	f.dp.bound = linux.Bound{}
	f.p.setErr(errors.New("netlink: no buffer space available"))
	if code, body := post("/api/v1/agents/home/enable"); code != http.StatusUnprocessableEntity || body["saved"] != true {
		t.Errorf("unpublished enable = %d %v, want 422 saved:true", code, body)
	}
	_, err = c.DisableAgent("home")
	if !errors.As(err, &ce) || !ce.Saved {
		t.Errorf("client unpublished disable = %v", err)
	}
	f.p.setErr(nil)
	res, err := c.EnableAgent("home")
	if err != nil || res.Disabled || res.Name != "home" {
		t.Errorf("client enable = %+v, %v", res, err)
	}
}
