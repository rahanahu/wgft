package vpsd

import (
	"errors"
	"fmt"
	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/reconcile"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
	"log"
	"net/netip"
	"sort"
)

// bringUpWG は起動時に wg インタフェースを立ち上げ、ピア以外(鍵、ポート、アドレス、MTU)を宣言に
// 収束させる(仕様 9 節)。ピアは最初のトランザクション(applyNFT)が、公開の前に足し、公開の後に
// 消す順序で収束させる(設計文書 7a.3 節)。宣言のピアは、所有判定で中止するときのドライランの
// 表示にだけ使う。
func (d *Daemon) bringUpWG() error {
	cfg, _, err := d.wgConfig()
	if err != nil {
		return err
	}
	changes, err := d.dp.EnsureDevice(*cfg)
	if err != nil {
		// 所有判定・衝突による中止は、専用の終了コードに写せるようそのまま返す(wg0: で包まない)。
		var refusal *wg.StartupRefusal
		if errors.As(err, &refusal) {
			return err
		}
		return fmt.Errorf("%s: %w", d.opts.WGInterface, err)
	}
	for _, c := range changes {
		log.Printf("%s: %s", d.opts.WGInterface, c)
	}
	return nil
}

// wgConfig は SQLite の宣言から WireGuard の宣言(ピア集合を含む)と、エージェント名からアドレスへの表を作る。
func (d *Daemon) wgConfig() (*dataplane.WGConfig, map[string]netip.Addr, error) {
	peers, agentAddr, err := d.agents()
	if err != nil {
		return nil, nil, err
	}
	return &dataplane.WGConfig{
		PrivateKey: d.serverKey, ListenPort: int(d.opts.WGPort), Address: d.network, MTU: d.opts.MTU, Peers: peers,
	}, agentAddr, nil
}

// reconciler は Runtime を駆動する Reconciler を返す(設計文書 7a.2、7a.3 節)。frontend はプロキシモードの
// 中継(proxyrelay)、dataplane はモードの Backend である。
func (d *Daemon) reconciler() *reconcile.Reconciler {
	if d.rec == nil {
		rt := reconcile.Runtime{Dataplane: d.dp.participant()}
		if d.proxy != nil {
			rt.Frontend = relayFrontend{d.proxy}
		}
		d.rec = reconcile.New(rt)
	}
	return d.rec
}

// applyNFT は SQLite の宣言(ルール、エージェント、ピア)を 1 つのトランザクションで適用する(設計文書
// 7a.2、7a.3 節)。Reconciler が固定の順序で進める。プロキシモードの新しい待ち受けを先に開き(frontend の
// Prepare)、開けたポートだけに nftables の接続元 IP ごとの上限の行を付ける(dataplane の Prepare への入力)。
// dataplane の Prepare は新しいピアを足し、テーブルの差し替えを組み立てる。差し替え(dataplane の Commit)が
// 失敗したら新しい待ち受けを閉じ、足したピアを戻し、旧い待ち受けと旧いテーブルを揃えたまま残す。成功したら、
// 差し替えの直前に読んだ drop カウンタを累積し、消えたピアを外し、conntrack を収束させ、中継を始めて不要な
// 待ち受けを閉じる(仕様 6.1 節)。
//
// ルール単位の失敗(待ち受けの bind)はエラーにしない。そのルールだけを理由付きの not_active にし、
// 新規のフローを拒み(fail-closed)、安全な成立済みのフローを Retiring として残す(設計文書 7a.3 節)。
func (d *Daemon) applyNFT(rules []proto.Rule) error {
	wgCfg, agentAddr, err := d.wgConfig()
	if err != nil {
		return err
	}
	gen, err := d.st.Generation()
	if err != nil {
		return err
	}
	plan, excluded := d.buildPlan(rules, agentAddr)
	plan.Generation = gen
	out, err := d.reconciler().Reconcile(reconcile.Input{Plan: plan, WG: wgCfg, Excluded: excluded})
	if err != nil {
		return fmt.Errorf("failed to apply nftables: %w", err)
	}
	// 差し替えの直前に読んだ drop カウンタ(前回の差し替え以降の増分)を SQLite に累積する(仕様 6.1 節)。
	// 差し替えが成功したときだけ返るので、失敗した差し替えのカウンタを二重に数えない
	if len(out.Committed.Drops) > 0 {
		if err := d.accumulateDrops(out.Committed.Drops); err != nil {
			log.Printf("accumulating drop counters: %v", err)
		}
	}
	for _, c := range out.Committed.WGChanges {
		log.Printf("%s: %s", d.opts.WGInterface, c)
	}
	for _, e := range out.Committed.Errors {
		log.Printf("%v", e)
	}
	ids := make([]string, 0, len(out.Failed))
	for id := range out.Failed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		log.Printf("rule %s: not active: %v", id, out.Failed[id])
	}
	active := 0
	for _, r := range rules {
		if r.Enabled && r.VPSMode == proto.ModeKernel {
			active++
		}
	}
	if d.opts.Mode == modeUserspace {
		log.Printf("applied %d rules in userspace mode (%d agents, %d peers)", len(rules), len(agentAddr), len(wgCfg.Peers))
	} else {
		log.Printf("applied table inet %s (%d rules, %d enabled in kernel mode, %d agents, %d peers)",
			nft.TableName, len(rules), active, len(agentAddr), len(wgCfg.Peers))
	}
	if out.Committed.Closed > 0 {
		log.Printf("conntrack: removed %d unneeded flows", out.Committed.Closed)
	}
	if d.proxy != nil {
		d.proxyInputHints(rules)
	}
	return nil
}

// relayFrontend はプロキシモードの中継(proxyrelay)を Runtime の frontend の participant にする
// (設計文書 7a.2 節)。proxyrelay の Prepare は bind に失敗したポートをログに出し、そのルールを
// Failed として報告するだけで、全体としては失敗しない(ルール単位の失敗。7a.3 節)。
// *proxyrelay.Prepared の Commit は失敗せず、2 回目以降は何もしないので、
// 戻れない地点の後に呼ぶ frontend の Commit の契約を満たす。
type relayFrontend struct{ m *proxyrelay.Manager }

func (f relayFrontend) Prepare(plan planner.Plan) (reconcile.FrontendPrepared, error) {
	return relayPrepared{f.m.Prepare(relayRules(plan.Relay()))}, nil
}

// relayPrepared は *proxyrelay.Prepared を frontend の Prepared にする。Retiring のルールは、
// 成立済みの接続を残してよいかの判定(新しい宣言と直前の Active の値の両方が接続元を許すか)に写す。
type relayPrepared struct{ *proxyrelay.Prepared }

func (p relayPrepared) Commit(retiring []dataplane.Retiring) {
	keep := make(map[string]func(netip.Addr) bool, len(retiring))
	for _, r := range retiring {
		keep[r.Previous.RuleID] = r.SourceAllowed
	}
	p.Prepared.Commit(keep)
}

// relayRules は、Plan の Relay のポートのうち TCP のものから中継の宣言を作る。Plan は無効なルールと、
// アドレスの分からないエージェントのルールを既に含まないので、ここで検査し直さない
// (relayfrontend_test.go の TestRelayRulesFromPlan)。
func relayRules(ports []planner.PortPlan) []proxyrelay.Rule {
	var out []proxyrelay.Rule
	for _, pp := range ports {
		if pp.Forwarding != model.Relay || pp.Proto != proto.TCP {
			continue
		}
		// proxy は単一ポート運用。範囲のルールは先頭ポートだけを使う(仕様 5.4、6.2 節)
		out = append(out, proxyrelay.Rule{
			ID: pp.RuleID, ListenPort: pp.ListenPort.Lo, AgentAddr: pp.AgentAddr, AgentPort: pp.ListenPort.Lo,
			ProxyProtocol: pp.SourceMetadata == model.ProxyV2,
			SourceDeny:    pp.Policy.SourceDeny, SourceAllow: pp.Policy.SourceAllow, Agent: pp.Agent,
		})
	}
	return out
}

// proxyInputHints は、プロキシモードの公開ポートが既定 drop の input で塞がれていれば提示する。
func (d *Daemon) proxyInputHints(rules []proto.Rule) {
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || r.VPSMode != proto.ModeProxy {
			continue
		}
		if lines, err := d.dp.InputPortSuggestions(r.ListenPort.Lo); err == nil && len(lines) > 0 {
			log.Printf("warning: proxy rule %s public port %d is blocked at input; add the following:", r.ID, r.ListenPort.Lo)
			for _, l := range lines {
				log.Printf("    %s", l)
			}
		}
	}
}

// buildPlan は、保存済みのルール集合とエージェントのアドレスから Plan を組み立てる(設計文書 7a.2 節)。
// ルールは書き込みのときに検査済みなので、ここでは検査し直さずに内部モデルへ写すだけにする。
// 検査し直すと、検査の規則が厳しくなる前に保存された行(proto.ValidateUpsert が検査し直さない行。
// 仕様 5.4 節)で適用そのものが止まるためである。写せない行(vps_mode と proxy_protocol の組み合わせが
// 無効な行)は書き込みの検査を通らないので現れないはずだが、現れたらログに出して Plan から外す。
// 世代(Plan.Generation)は呼び出し側が入れる。
//
// excluded は、Plan が転送しないルール(無効、エージェントが未登録、写せない行)と、その理由である。
// 管理用 API はこれらを理由付きの not_active として示す(設計文書 7a.3 節)。
func (d *Daemon) buildPlan(rules []proto.Rule, agentAddr map[string]netip.Addr) (planner.Plan, map[string]string) {
	normalized := make([]model.Rule, 0, len(rules))
	excluded := map[string]string{}
	for _, r := range rules {
		m, err := model.FromProto(r)
		if err != nil {
			log.Printf("leaving a rule out of the data plane: %v", err)
			excluded[r.ID] = "invalid: " + err.Error()
			continue
		}
		// Planner (Build) は無効なルールと、宛先の分からないエージェントのルールを黙って Plan.Ports
		// から外す。以前は kernel backend の nft.emit だけがこの後者を記録していたが(Relay のルールは
		// 記録していなかった)、Plan がその区別を吸収した今は、組み立ての入り口であるここで
		// Forwarding を問わず一様に記録する(設計文書 7a.8 節 Phase 3)。
		if !m.Enabled {
			excluded[m.ID] = "disabled"
		} else if _, ok := agentAddr[m.Agent]; !ok {
			log.Printf("rule %s: agent %q is not registered, skipping", m.ID, m.Agent)
			excluded[m.ID] = fmt.Sprintf("agent %q is not registered", m.Agent)
		}
		normalized = append(normalized, m)
	}
	agents := make([]planner.Agent, 0, len(agentAddr))
	for name, addr := range agentAddr {
		agents = append(agents, planner.Agent{Name: name, Addr: addr})
	}
	return planner.Build(planner.Input{Rules: normalized, Limits: d.opts.Limits, Agents: agents}), excluded
}

// accumulateDrops は今回読んだカウンタ(前回の適用以降の増分そのもの)を累積する。
func (d *Daemon) accumulateDrops(drops []dataplane.Drop) error {
	deltas := make([]store.DropDelta, 0, len(drops))
	for _, dr := range drops {
		if dr.Packets == 0 {
			continue
		}
		deltas = append(deltas, store.DropDelta{RuleID: dr.RuleID, Kind: dr.Kind, Packets: dr.Packets, Bytes: dr.Bytes})
	}
	if len(deltas) == 0 {
		return nil
	}
	return d.st.AddDrops(deltas)
}

// checkRule は、他テーブルの同じポートの DNAT(常に拒否)と、VPS 上で bind 中のポート
// (--force で上書き可)との衝突を見る(仕様 5.3, 6.1 節)。
func (d *Daemon) checkRule(r *proto.Rule, rep *linux.Report, force bool) error {
	if !r.Enabled || r.VPSMode != proto.ModeKernel {
		return nil
	}
	if c := rep.DNATConflicts(r.Proto, r.ListenPort); len(c) > 0 {
		return fmt.Errorf("rule %s: %s/%s overlaps the DNAT in %s (%s)", r.ID, r.Proto, r.ListenPort, c[0].Where, c[0].Ports)
	}
	bound, err := d.dp.BoundPorts()
	if err != nil {
		return fmt.Errorf("checking bound ports: %w", err)
	}
	if c := bound.Conflicts(r.Proto, r.ListenPort); len(c) > 0 && !force {
		for port, addrs := range c {
			return fmt.Errorf("rule %s: %s/%d is bound by a process on the VPS at %v; risk of locking out SSH etc., override with --force", r.ID, r.Proto, port, addrs)
		}
	}
	return nil
}
