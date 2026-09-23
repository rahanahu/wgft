package doctor

import (
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
)

// このファイルは、判定が証拠をどこから読むかを 1 つの interface にまとめる(design.md 10.2d 節
// 「診断のロジックの置き場所」)。証拠の読み方は呼び出し側で分かれる。CLI は admin.Client 越しに
// 管理用 API を呼び、Web UI は同じプロセスの中で Backend を呼ぶ。判定はその違いを見ない。

// Evidence is where a diagnosis reads the evidence it judges: the three admin API reads of design.md
// 10.2a 節's table of checks. The signatures are *admin.Client's, so the CLI passes its client as it
// is; the Web UI passes an adapter that answers the same three questions from the Backend in the
// same process (internal/vpsd/admin's doctorEvidence).
//
// Rules and Agents are what an argument-less run costs: two reads, whatever the number of rules.
// CheckConnectivity dials, so nothing calls it unless the operator asks for it (AddProbe).
type Evidence interface {
	// Rules is GET /api/v1/rules: the rules themselves, the generation, the server's own apply
	// state, Resource Guard's counters and what each agent last reported about each rule.
	Rules() (*adminapi.BatchResponse, error)
	// Agents is GET /api/v1/agents:each agent's stream, generation, tunnel and warnings.
	Agents() ([]adminapi.AgentInfo, error)
	// CheckConnectivity is POST /api/v1/rules/{id}/check: one real TCP connection from the server,
	// through the tunnel and the agent, to the target (design.md 10.1 節).
	CheckConnectivity(ruleID string) (*adminapi.ConnCheck, error)
}

// Read collects the evidence every diagnosis starts from: one rules read and one agents read, in
// that order, and nothing else. A failure of either is returned as it is; the caller decides what
// to do with it, since "the admin API did not answer" means a different exit code to the CLI
// (design.md 10.2a 節, exit code 2) than an error page does to the Web UI.
//
// now is passed in rather than read here, so a diagnosis is reproducible from fixed evidence.
func Read(ev Evidence, now time.Time) (Input, error) {
	in := Input{Now: now, Probes: map[string]ProbeResult{}}
	rules, err := ev.Rules()
	if err != nil {
		return Input{}, err
	}
	in.Rules = rules
	agents, err := ev.Agents()
	if err != nil {
		return Input{}, err
	}
	in.Agents = agents
	return in, nil
}

// AddProbe runs the one active check of this diagnosis against ruleID and records its result,
// error included: the admin API refuses to dial a UDP rule, a disabled rule or a rule of an
// unregistered agent, and that refusal is itself a finding (probeCheck), not a reason to give up
// the report.
//
// Only an explicit operator action calls this: `--probe` on the CLI, the probe button on the Web
// UI. Neither the CLI's argument-less run nor opening the Web UI's page dials anything, because
// the server's dial deadline would otherwise pile up once per rule (design.md 10.2a、10.2d 節).
func (in *Input) AddProbe(ev Evidence, ruleID string) {
	res, err := ev.CheckConnectivity(ruleID)
	if in.Probes == nil {
		in.Probes = map[string]ProbeResult{}
	}
	in.Probed = true
	in.Probes[ruleID] = ProbeResult{Check: res, Err: err}
}
