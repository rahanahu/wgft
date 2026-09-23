package doctor

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、判定が証拠をどこから読むかの契約(evidence.go)を確かめる。判定そのものは
// cmd/wgft/doctor_test.go が、切り出しの前と同じ試験でそのまま確かめている。

// fakeEvidence は 3 つの読み取りを数える証拠である。CLI の *admin.Client と Web UI の
// doctorEvidence の両方が満たす interface を、ここでは試験が満たす。
type fakeEvidence struct {
	rules      *adminapi.BatchResponse
	agents     []adminapi.AgentInfo
	check      *adminapi.ConnCheck
	checkErr   error
	rulesErr   error
	agentsErr  error
	rulesCalls int
	agentCalls int
	dialCalls  int
}

func (f *fakeEvidence) Rules() (*adminapi.BatchResponse, error) {
	f.rulesCalls++
	return f.rules, f.rulesErr
}

func (f *fakeEvidence) Agents() ([]adminapi.AgentInfo, error) {
	f.agentCalls++
	return f.agents, f.agentsErr
}

func (f *fakeEvidence) CheckConnectivity(ruleID string) (*adminapi.ConnCheck, error) {
	f.dialCalls++
	return f.check, f.checkErr
}

func newFakeEvidence() *fakeEvidence {
	r := proto.Rule{ID: "r_1", Agent: "home", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 443, Hi: 443},
		Target: "192.168.1.30:443", Enabled: true}
	return &fakeEvidence{
		rules:  &adminapi.BatchResponse{Generation: 3, Rules: []proto.Rule{r}},
		agents: []adminapi.AgentInfo{{Name: "home", Connected: true}},
		check:  &adminapi.ConnCheck{OK: true, Reach: "target", Detail: "connected"},
	}
}

// TestReadCostsTwoReadsAndDialsNothing は、引数を付けない診断の費用を固定する(設計文書 10.2a
// 節)。ルールの本数によらず読み取りは 2 回で、疎通の確認はここでは呼ばない。画面を開いたときに
// 疎通を試さない(10.2d 節)のは、この性質にそのまま乗っている。
func TestReadCostsTwoReadsAndDialsNothing(t *testing.T) {
	ev := newFakeEvidence()
	in, err := Read(ev, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	rep := BuildReport(in.Rules.Rules, in)
	if ev.rulesCalls != 1 || ev.agentCalls != 1 {
		t.Errorf("reads = %d rules, %d agents; want 1 and 1", ev.rulesCalls, ev.agentCalls)
	}
	if ev.dialCalls != 0 {
		t.Errorf("Read dialled %d time(s); nothing may be dialled without an explicit AddProbe", ev.dialCalls)
	}
	if rep.Probed {
		t.Error("a report built without AddProbe must not claim it probed")
	}
	probe := checkByID(t, rep, CheckProbe)
	if probe.Status != StatusNotTested || probe.Reason != ReasonNoProbe {
		t.Errorf("rule.probe = %q/%q, want %q/%q", probe.Status, probe.Reason, StatusNotTested, ReasonNoProbe)
	}
}

// TestAddProbeDialsOnceAndIsReported は、明示の操作が 1 回だけ dial し、その結果が報告に入る
// ことを確かめる。
func TestAddProbeDialsOnceAndIsReported(t *testing.T) {
	ev := newFakeEvidence()
	in, err := Read(ev, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	in.AddProbe(ev, "r_1")
	rep := BuildReport(in.Rules.Rules, in)
	if ev.dialCalls != 1 {
		t.Errorf("dials = %d, want 1", ev.dialCalls)
	}
	if !rep.Probed {
		t.Error("a report built after AddProbe must say it probed")
	}
	if probe := checkByID(t, rep, CheckProbe); probe.Status != StatusOK {
		t.Errorf("rule.probe = %q, want %q", probe.Status, StatusOK)
	}
}

// TestAddProbeKeepsTheReportWhenTheServerRefusesToDial は、疎通の確認が拒まれても報告そのものは
// 出すことを確かめる(設計文書 10.2a 節。誤りは probeResult へ畳み込み、報告は出す)。
func TestAddProbeKeepsTheReportWhenTheServerRefusesToDial(t *testing.T) {
	ev := newFakeEvidence()
	ev.check, ev.checkErr = nil, errors.New("only TCP rules can be checked")
	in, err := Read(ev, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	in.AddProbe(ev, "r_1")
	rep := BuildReport(in.Rules.Rules, in)
	probe := checkByID(t, rep, CheckProbe)
	if probe.Status != StatusUnknown {
		t.Errorf("rule.probe = %q, want %q when the server declined to dial", probe.Status, StatusUnknown)
	}
	if want := "only TCP rules can be checked"; !strings.Contains(probe.Detail, want) {
		t.Errorf("rule.probe detail = %q, want it to carry %q", probe.Detail, want)
	}
}

// TestReadReturnsTheFailureOfEitherRead は、証拠に届かなかったことを呼び出し側に返すことを
// 確かめる。CLI はこれを終了コード 2 に、Web UI は誤りの応答に写す(10.2a、10.5 節)。
func TestReadReturnsTheFailureOfEitherRead(t *testing.T) {
	ev := newFakeEvidence()
	ev.rulesErr = errors.New("admin api did not answer")
	if _, err := Read(ev, time.Now()); err == nil {
		t.Error("Read must return the rules read's failure")
	}
	if ev.agentCalls != 0 {
		t.Error("Read must stop at the first failure instead of reading on")
	}

	ev = newFakeEvidence()
	ev.agentsErr = errors.New("admin api did not answer")
	if _, err := Read(ev, time.Now()); err == nil {
		t.Error("Read must return the agents read's failure")
	}
}

func checkByID(t *testing.T, rep Report, id string) Check {
	t.Helper()
	for _, c := range rep.Checks {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("no check %q in the report", id)
	return Check{}
}
