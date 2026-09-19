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
)

// reconcileWG は wg0 を SQLite の宣言に収束させる。
func (d *Daemon) reconcileWG() error {
	peers, _, err := d.agents()
	if err != nil {
		return err
	}
	changes, err := d.dp.EnsureWG(dataplane.WGConfig{
		PrivateKey: d.serverKey, ListenPort: int(d.opts.WGPort), Address: d.network, MTU: d.opts.MTU, Peers: peers,
	})
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

func (d *Daemon) applyNFT(rules []proto.Rule) error {
	peers, agentAddr, err := d.agents()
	if err != nil {
		return err
	}
	// 差し替えの直前に drop カウンタを読み、増分を SQLite に累積する(仕様 6.1 節)。
	// テーブルはこの後まるごと差し替わり、カウンタは 0 に戻る
	if drops, err := d.dp.ReadDrops(); err != nil {
		log.Printf("reading drop counters: %v", err)
	} else if len(drops) > 0 {
		if err := d.accumulateDrops(drops); err != nil {
			log.Printf("accumulating drop counters: %v", err)
		}
	}
	// Runtime が固定の順序で適用する(設計文書 7a.2 節)。プロキシモードの新しい待ち受けを先に開き
	// (frontend の Prepare)、開けたポートだけに nftables の接続元 IP ごとの上限の行を付ける
	// (dataplane の Prepare への入力)。nftables の差し替え(dataplane の Commit)が失敗したら新しい
	// 待ち受けを閉じて旧い待ち受けと旧いテーブルを揃えたまま残し、成功したら中継を始めて不要な待ち受けを
	// 閉じる(frontend の Commit。仕様 6.1 節)
	plan := d.buildPlan(rules, agentAddr)
	rt := reconcile.Runtime{Dataplane: d.dp.participant()}
	if d.proxy != nil {
		rt.Frontend = relayFrontend{d.proxy}
	}
	if err := rt.Apply(plan); err != nil {
		return fmt.Errorf("failed to apply nftables: %w", err)
	}
	active := 0
	for _, r := range rules {
		if r.Enabled && r.VPSMode == proto.ModeKernel {
			active++
		}
	}
	if d.opts.Mode == modeUserspace {
		log.Printf("applied %d rules in userspace mode (%d agents, %d peers)", len(rules), len(agentAddr), len(peers))
	} else {
		log.Printf("applied table inet %s (%d rules, %d enabled in kernel mode, %d agents, %d peers)",
			nft.TableName, len(rules), active, len(agentAddr), len(peers))
	}
	// conntrack の収束は必ず nftables の差し替えの後に走らせる(仕様 6.1 節)。
	// 先に走らせると、旧テーブルで許可されたフローが差し替えまでの間に入る
	d.converge(plan)
	if d.proxy != nil {
		d.proxyInputHints(rules)
	}
	return nil
}

// relayFrontend はプロキシモードの中継(proxyrelay)を Runtime の frontend の participant にする
// (設計文書 7a.2 節)。proxyrelay の Prepare は bind に失敗したポートをログに出して飛ばすだけで、
// 全体としては失敗しない。*proxyrelay.Prepared の Commit は失敗せず、2 回目以降は何もしないので、
// 戻れない地点の後に呼ぶ frontend の Commit の契約を満たす。
type relayFrontend struct{ m *proxyrelay.Manager }

func (f relayFrontend) Prepare(plan planner.Plan) (reconcile.FrontendPrepared, error) {
	return relayPrepared{f.m.Prepare(relayRules(plan.Relay()))}, nil
}

// relayPrepared は *proxyrelay.Prepared を frontend の Prepared にする。Retiring にするルール
// (StopAccepting と Retire。設計文書 7a.3 節)はまだ渡さないので、宣言から消えた待ち受けは
// 今までどおり成立済みの接続とともに閉じる。
type relayPrepared struct{ *proxyrelay.Prepared }

func (p relayPrepared) Commit() { p.Prepared.Commit(nil) }

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
// 世代(Plan.Generation)は Phase 4 の Reconciler が使うまで入れない。
func (d *Daemon) buildPlan(rules []proto.Rule, agentAddr map[string]netip.Addr) planner.Plan {
	normalized := make([]model.Rule, 0, len(rules))
	for _, r := range rules {
		m, err := model.FromProto(r)
		if err != nil {
			log.Printf("leaving a rule out of the data plane: %v", err)
			continue
		}
		// Planner (Build) は無効なルールと、宛先の分からないエージェントのルールを黙って Plan.Ports
		// から外す。以前は kernel backend の nft.emit だけがこの後者を記録していたが(Relay のルールは
		// 記録していなかった)、Plan がその区別を吸収した今は、組み立ての入り口であるここで
		// Forwarding を問わず一様に記録する(設計文書 7a.8 節 Phase 3)。
		if m.Enabled {
			if _, ok := agentAddr[m.Agent]; !ok {
				log.Printf("rule %s: agent %q is not registered, skipping", m.ID, m.Agent)
			}
		}
		normalized = append(normalized, m)
	}
	agents := make([]planner.Agent, 0, len(agentAddr))
	for name, addr := range agentAddr {
		agents = append(agents, planner.Agent{Name: name, Addr: addr})
	}
	return planner.Build(planner.Input{Rules: normalized, Limits: d.opts.Limits, Agents: agents})
}

// converge は外から入って DNAT されたフローを Plan の Transparent なルールに収束させる(仕様 6.1 節)。
// ユーザー空間モードでは、接続元制限を満たさなくなったセッションを閉じる(仕様 6.3 節)。
// フィルタ(無効なルール、未登録のエージェント)は Plan.Transparent() が既に済ませている
// (design.md 7a.8 節 Phase 3: internal/dataplane/linuxkernel/conntrack.RulesFromPlan)。
func (d *Daemon) converge(plan planner.Plan) {
	if n, err := d.dp.Converge(plan); err != nil {
		log.Printf("conntrack converge: %v", err)
	} else if n > 0 {
		log.Printf("conntrack: removed %d unneeded flows", n)
	}
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
