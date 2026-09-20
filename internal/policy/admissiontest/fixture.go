// Package admissiontest は、Admission Policy の共有 fixture(internal/policy/testdata/admission)を
// 読み、評価器に流して照らすテスト用の部品である(設計文書 7a.9 節「fixture の形式と等価性の検査」)。
//
// 評価器は Engine の実装として差し込む。nftables の行の列を解釈器で実行する実装
// (internal/policy/nftables/interp)と、Go の評価器(internal/policy/goengine)の 2 つが、同じ
// fixture を同じ手順で流す。本番のコードはこのパッケージを import しない。
package admissiontest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// Fixture は 1 つの場面。
type Fixture struct {
	// Name はファイル名から .json を除いたもの。
	Name string `json:"-"`
	// Comment は場面の説明。
	Comment    string                       `json:"comment"`
	Policy     Policy                       `json:"policy"`
	Events     []Event                      `json:"events"`
	WantDrops  map[string]map[string]uint64 `json:"want_drops"`
	Tolerances []string                     `json:"tolerances"`
}

// Policy は fixture のルールの一覧と、送信元ごとの同時フロー数の上限。
type Policy struct {
	Rules             []Rule   `json:"rules"`
	PerSourceFlowCaps FlowCaps `json:"per_source_flow_caps"`
}

// FlowCaps は送信元ごとの同時フロー数の上限。省略すると既定値(UDP 256、TCP 128)、0 は上限なし
// (WGFT_MAX_*_FLOWS_PER_SOURCE と同じ)。
type FlowCaps struct {
	UDP *int `json:"udp"`
	TCP *int `json:"tcp"`
}

// Rule は fixture のルール 1 本。値の書き方は 5.3 節と同じで、forwarding は transparent か relay。
type Rule struct {
	ID            string         `json:"id"`
	Proto         proto.Proto    `json:"proto"`
	Forwarding    string         `json:"forwarding"`
	SourceAllow   []netip.Prefix `json:"source_allow"`
	SourceDeny    []netip.Prefix `json:"source_deny"`
	PerSourceRate *proto.Rate    `json:"per_source_rate"`
	NewFlowRate   *proto.Rate    `json:"new_flow_rate"`
	PacketRate    *proto.Rate    `json:"packet_rate"`
}

// Op は出来事の種類。
type Op string

const (
	OpFlow   Op = "flow"   // 新しいフローの最初のパケット
	OpPacket Op = "packet" // 成立済みのフローのパケット
	OpEnd    Op = "end"    // フローの終わり
)

// Event は出来事 1 つ。
type Event struct {
	AtMS int64  `json:"at_ms"`
	Op   Op     `json:"op"`
	Rule string `json:"rule"`
	Src  string `json:"src"`
	Flow string `json:"flow"`
	// Want は admit、drop:<種類>、または drop(drop カウンタに数えない拒否。IR に無いルール ID)。
	// end では空にする。
	Want string `json:"want"`
}

// 評価器の名前。TestAdmissionFixtures が結果を報告するときの見出しに使う。
const (
	EngineNFTables = "nftables" // internal/policy/nftables の行の列を解釈器で実行する
	EngineGo       = "goengine" // internal/policy/goengine
)

// Admit と Drop は Want と Engine の結果の値。
const (
	Admit = "admit"
	Drop  = "drop"
)

// DropOf は drop:<種類> を返す。
func DropOf(kind string) string { return Drop + ":" + kind }

// Tolerances は fixture が名前で挙げられる許容差(設計文書 7a.4 節と 7a.9 節「許容差の扱い」)。
var Tolerances = []string{
	"udp_flow_counting",        // UDP の 1 フローの数え方
	"timeout_asymmetry",        // タイムアウトの非対称
	"token_bucket_granularity", // トークンバケットの粒度
	"table_replacement_reset",  // テーブル差し替えによる ct count/meter のリセット
	"rejection_visibility",     // 拒否の見え方
	"new_flow_counting",        // 新しいフローの数え方
	"drop_counter_units",       // drop カウンタの単位
	"per_source_table_expiry",  // 送信元ごとの表の期限と溢れ
	"refill_boundary",          // 補充の境界
}

// dropKinds は drop の種類の一覧(policy.Order の各段の DropKind)。
var dropKinds = func() []string {
	var out []string
	for _, s := range policy.Order {
		out = append(out, s.DropKind())
	}
	return out
}()

// Load は dir の *.json をすべて読み、名前の順に返す。
func Load(dir string) ([]*Fixture, error) {
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, err
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no fixtures in %s", dir)
	}
	sort.Strings(paths)
	var out []*Fixture
	for _, p := range paths {
		fx, err := LoadFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, fx)
	}
	return out, nil
}

// LoadFile は fixture を 1 つ読み、形を検査する。知らないフィールドは誤りにする。
func LoadFile(path string) (*Fixture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	fx := &Fixture{}
	if err := dec.Decode(fx); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	fx.Name = strings.TrimSuffix(filepath.Base(path), ".json")
	if err := fx.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return fx, nil
}

func (fx *Fixture) validate() error {
	ids := map[string]bool{}
	for _, r := range fx.Policy.Rules {
		if r.ID == "" || ids[r.ID] {
			return fmt.Errorf("rule id %q is empty or repeated", r.ID)
		}
		ids[r.ID] = true
		if r.Proto != proto.UDP && r.Proto != proto.TCP {
			return fmt.Errorf("rule %s: proto %q is neither udp nor tcp", r.ID, r.Proto)
		}
		if _, err := forwarding(r.Forwarding); err != nil {
			return fmt.Errorf("rule %s: %w", r.ID, err)
		}
	}
	for _, c := range []*int{fx.Policy.PerSourceFlowCaps.UDP, fx.Policy.PerSourceFlowCaps.TCP} {
		if c != nil && *c < 0 {
			return fmt.Errorf("per_source_flow_caps must not be negative")
		}
	}
	var last int64
	for i, ev := range fx.Events {
		if ev.AtMS < last {
			return fmt.Errorf("event %d: at_ms %d goes back in time", i, ev.AtMS)
		}
		last = ev.AtMS
		if ev.Flow == "" || ev.Rule == "" {
			return fmt.Errorf("event %d: rule and flow are required", i)
		}
		if _, err := netip.ParseAddr(ev.Src); err != nil {
			return fmt.Errorf("event %d: src: %w", i, err)
		}
		switch ev.Op {
		case OpFlow, OpPacket:
			if !validWant(ev.Want) {
				return fmt.Errorf("event %d: want %q is none of admit, drop, drop:<kind>", i, ev.Want)
			}
		case OpEnd:
			if ev.Want != "" {
				return fmt.Errorf("event %d: end takes no want", i)
			}
		default:
			return fmt.Errorf("event %d: op %q is none of flow, packet, end", i, ev.Op)
		}
	}
	for rule, kinds := range fx.WantDrops {
		for kind := range kinds {
			if !slices.Contains(dropKinds, kind) {
				return fmt.Errorf("want_drops[%s]: unknown kind %q", rule, kind)
			}
		}
	}
	for _, tol := range fx.Tolerances {
		if !slices.Contains(Tolerances, tol) {
			return fmt.Errorf("unknown tolerance %q", tol)
		}
	}
	return nil
}

func validWant(w string) bool {
	if w == Admit || w == Drop {
		return true
	}
	kind, ok := strings.CutPrefix(w, Drop+":")
	return ok && slices.Contains(dropKinds, kind)
}

func forwarding(s string) (model.Forwarding, error) {
	switch s {
	case "transparent", "":
		return model.Transparent, nil
	case "relay":
		return model.Relay, nil
	default:
		return 0, fmt.Errorf("forwarding %q is neither transparent nor relay", s)
	}
}

// FirstPort は、fixture のルールに振る待ち受けポートの最初の値。ルールは fixture の順に
// FirstPort、FirstPort+1、... の 1 ポートずつを持つ。fixture はポートを書かない(ポートと宛先は
// IR の外の Plan が持つため)。
const FirstPort = 20000

// Plan は fixture のルールから Plan を組み立てる(internal/planner.Build。本番と同じ経路で、
// Plan.Admission が IR になる)。どのルールも登録済みのエージェントに属し、有効である。
func (fx *Fixture) Plan() (planner.Plan, error) {
	limits := flowcap.Limits{}
	if c := fx.Policy.PerSourceFlowCaps.UDP; c != nil {
		limits.UDPPerSource = capSetting(*c)
	}
	if c := fx.Policy.PerSourceFlowCaps.TCP; c != nil {
		limits.TCPPerSource = capSetting(*c)
	}
	var rules []model.Rule
	for i, r := range fx.Policy.Rules {
		fwd, err := forwarding(r.Forwarding)
		if err != nil {
			return planner.Plan{}, err
		}
		port := uint16(FirstPort + i)
		rules = append(rules, model.Rule{
			ID: r.ID, Agent: "agent", Proto: r.Proto, ListenPort: proto.PortRange{Lo: port, Hi: port},
			Target: fmt.Sprintf("192.168.1.10:%d", port), Forwarding: fwd,
			SourceAllow: r.SourceAllow, SourceDeny: r.SourceDeny,
			PerSourceRate: r.PerSourceRate, NewFlowRate: r.NewFlowRate, PacketRate: r.PacketRate,
			Enabled: true,
		})
	}
	return planner.Build(planner.Input{Rules: rules, Limits: limits,
		Agents: []planner.Agent{{Name: "agent", Addr: netip.MustParseAddr("10.200.0.2")}}}), nil
}

// capSetting は fixture の上限を flowcap.Limits の値へ写す(0 は上限なし)。
func capSetting(c int) int {
	if c == 0 {
		return flowcap.PerSourceOff
	}
	return c
}
