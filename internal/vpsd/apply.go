package vpsd

import (
	"context"
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
	"strings"
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
	_, err := d.apply(rules, false)
	return err
}

// applyThenReadConntrack applies the rules and, only once they are applied, reads the conntrack
// UDP timeouts and the conntrack-table-size warning. apply, readTimeouts and warn are passed in
// (rather than reached through *Daemon) so the ordering and error handling here can be unit
// tested with fakes, without a real store, kernel or nftables (apply_test.go).
//
// Order matters: kernel mode's table inet wgft contains ct expressions, and applying it over
// netlink is what makes the kernel auto-load nf_conntrack (and nft_ct, nf_nat) on a host where
// nothing else has loaded it yet, the same as `nft` would. Reading the sysctls first fails there
// (a fresh install, or every boot on a host where nothing else loads the module first); moving the
// read after apply fixed it in the lab with no modprobe. Nothing before this point in Run consumes
// the timeouts or the warning: their only other use, in admin_backend.go, serves the admin and
// agent APIs, which start listening later in Run, so this reordering does not affect Phase 4's
// convergence order or its point-of-no-return guarantees.
//
// A read failure once the table is applied is not a missing module load (the write already
// happened): it is a permanent environment problem (this sysctl path does not exist on this
// kernel, or is not readable), so it is wrapped as a *wg.StartupRefusal, matching the exit-code
// classification design.md 11a 節 already gives the analogous "no WireGuard support" failure in
// wg.Ensure. That keeps systemd's RestartPreventExitStatus=3 from looping forever on a failure
// that retrying cannot fix, instead of the generic error (exit code 1) ReadUDPTimeouts previously
// became.
func applyThenReadConntrack(apply func() error, readTimeouts func() (linux.UDPTimeouts, error), warn func() string) (linux.UDPTimeouts, error) {
	if err := apply(); err != nil {
		return linux.UDPTimeouts{}, err
	}
	t, err := readTimeouts()
	if err != nil {
		return linux.UDPTimeouts{}, &wg.StartupRefusal{
			Reason: fmt.Sprintf("reading the conntrack UDP timeouts after applying table inet %s: %v", nft.TableName, err),
		}
	}
	if w := warn(); w != "" {
		log.Printf("warning: %s", w)
	}
	return t, nil
}

// convergeLoop は、管理者の操作を待たずに宣言へ収束させる(設計文書 7a.3 節:実際の状態への収束、
// 再試行)。kernel backend は dataplane.Sensor として nftables とリンクとアドレスの変更の通知を
// 受け取り、通知があれば(まとめて 1 回)observeOnce が実際の状態を読み、直前の Commit と食い違えば
// 公開し直す。通知の取りこぼしと WireGuard のピアの変更(通知が無い)には 5 分ごとの observeOnce が
// 備える。ルールの Prepare の失敗(bind)と backend 全体の失敗は、解消しても通知が来ない(ポートが
// 空く、table inet wgft を保持していたプロセスが終わる)ので、30 秒ごとの retryOnce が試し直す。
// userspace backend は Sensor を持たないので、通知を購読しない。
func (d *Daemon) convergeLoop(ctx context.Context) {
	wake := make(chan struct{}, 1)
	poke := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	if s, ok := d.dp.participant().(dataplane.Sensor); ok {
		go reconcile.Watch(ctx, s, poke, reconcile.DefaultBackoff, log.Printf)
	}
	reconcile.DefaultTriggers.Run(ctx, wake, d.observeOnce, d.retryOnce)
}

// observeOnce は、Reconciler の Observe で実際の状態を直前の Commit と比べ、食い違い(またはまだ
// 公開できていない backend 全体の失敗)があれば SQLite の宣言を適用し直す。食い違いの無い
// observeOnce は何も commit しないので、nftables のテーブルを差し替えず、meter と ct count の状態を
// 保つ。同じ失敗は続くあいだ 1 行だけログに出す。
func (d *Daemon) observeOnce() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.rec == nil {
		return
	}
	drift, due, err := d.rec.Observe()
	if err != nil {
		d.logConverge(fmt.Sprintf("checking the data plane: %v", err))
		return
	}
	if len(drift) > 0 {
		log.Printf("data plane changed outside wgft (%s); applying the rules again", strings.Join(drift, "; "))
	}
	if !due {
		d.logConverge("")
		return
	}
	d.reapply()
}

// logConverge は、observeOnce の失敗の行を、前回と違うときだけ出す。空の msg は失敗が終わったことを
// 記録する。通知は他のテーブルの変更でも来るので、失敗が続くあいだ通知のたびに出すとログが溢れる。
func (d *Daemon) logConverge(msg string) {
	if msg != "" && msg != d.lastConvergeErr {
		log.Print(msg)
	}
	d.lastConvergeErr = msg
}

// retryOnce は、宣言がすべて Active になっていないあいだ(ルールの Prepare の失敗か、backend 全体の
// 失敗)、30 秒ごと(reconcile.DefaultTriggers.Retry。エージェントの待ち受けの再試行、仕様 5.2 節と
// 同じ間隔)に SQLite の宣言を適用し直す。前回と同じものを公開するだけの再試行は何も commit しない
// ので、nftables のテーブルを差し替えず、meter と ct count の状態を保つ。
func (d *Daemon) retryOnce() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.rec == nil || !d.rec.Status().NeedsRetry {
		return
	}
	d.reapply()
}

// reapply は SQLite の宣言を再試行として適用する(前回と同じものを公開するだけなら commit しない)。
// 管理者の変更が backend 全体の失敗で公開できなかった場合、その変更はエージェントにも配られていない
// (admin_backend.go の Batch は適用の失敗で配信を省く)。再試行がその世代を公開したら、ここで配る。
func (d *Daemon) reapply() {
	rules, err := d.st.Rules()
	if err != nil {
		d.logConverge(fmt.Sprintf("applying the rules again: %v", err))
		return
	}
	before := d.rec.Status().ActiveGeneration
	if _, err := d.apply(rules, true); err != nil {
		d.logConverge(fmt.Sprintf("applying the rules again: %v", err))
		return
	}
	d.logConverge("")
	if d.rec.Status().ActiveGeneration != before && d.hub != nil {
		go d.hub.PushAll()
	}
}

// apply は applyNFT の本体。retry が真なら、前回と同じものを公開するだけのときに何も commit せず、
// ログも出さない。
func (d *Daemon) apply(rules []proto.Rule, retry bool) (reconcile.Outcome, error) {
	wgCfg, agentAddr, err := d.wgConfig()
	if err != nil {
		return reconcile.Outcome{}, err
	}
	gen, err := d.st.Generation()
	if err != nil {
		return reconcile.Outcome{}, err
	}
	plan, excluded := d.buildPlan(rules, agentAddr)
	plan.Generation = gen
	out, err := d.reconciler().Reconcile(reconcile.Input{Plan: plan, WG: wgCfg, Excluded: excluded, Retry: retry})
	if err != nil {
		// This is the one failure path for both modes (design.md 7a.2 節の Runtime), but only the
		// kernel backend's Commit is an nftables transaction; userspace has no nftables to blame.
		if d.opts.Mode == modeUserspace {
			return out, fmt.Errorf("failed to apply the userspace dataplane: %w", err)
		}
		return out, fmt.Errorf("failed to apply nftables: %w", err)
	}
	if len(out.Drift) > 0 {
		log.Printf("data plane changed outside wgft (%s); applying the rules again", strings.Join(out.Drift, "; "))
	}
	// ルール単位の失敗の行は、何も commit しない再試行でも決める。理由が変わったときの 1 行を落とさない
	var lines []string
	d.notActive, lines = ruleFailureLog(d.notActive, out.Failed)
	for _, l := range lines {
		log.Print(l)
	}
	if out.NoOp {
		if out.Repaired {
			d.logRepair(out.Committed, true)
		}
		return out, nil
	}
	// 差し替えの直前に読んだ drop カウンタ(前回の差し替え以降の増分)を SQLite に累積する(仕様 6.1 節)。
	// 差し替えが成功したときだけ返るので、失敗した差し替えのカウンタを二重に数えない
	if len(out.Committed.Drops) > 0 {
		if err := d.accumulateDrops(out.Committed.Drops); err != nil {
			log.Printf("accumulating drop counters: %v", err)
		}
	}
	d.logRepair(out.Committed, retry)
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
	if d.proxy != nil {
		d.proxyInputHints(rules)
	}
	return out, nil
}

// logRepair は、Commit か修復の再試行(dataplane の Repair)が戻れない地点の後に行ったことをログに
// 出す(設計文書 7a.3 節:戻れない地点の後の修復)。再試行(retry)では、前回と同じ失敗を再試行の
// たびには出さない。修復が済んだときに 1 行出す。
func (d *Daemon) logRepair(c dataplane.Committed, retry bool) {
	for _, ch := range c.WGChanges {
		log.Printf("%s: %s", d.opts.WGInterface, ch)
	}
	msgs := make([]string, 0, len(c.Errors))
	for _, e := range c.Errors {
		msgs = append(msgs, e.Error())
	}
	msg := strings.Join(msgs, "; ")
	if msg != "" && (!retry || msg != d.lastRepairErr) {
		for _, m := range msgs {
			log.Print(m)
		}
	}
	if c.Closed > 0 {
		log.Printf("conntrack: removed %d unneeded flows", c.Closed)
	}
	switch {
	case c.RepairPending:
		d.lastRepairErr = msg
	case d.lastRepairErr != "":
		log.Printf("repaired what failed after the last publication")
		d.lastRepairErr = ""
	}
}

// ruleFailureLog は、ルール単位の失敗のうちログに出す行を決める。prev は前回までに記録した失敗
// (ルール ID → 理由)。失敗が始まったとき、理由が変わったときに 1 行、失敗していたルールが失敗しなく
// なったときに 1 行だけ出す。適用は 30 秒ごとに再試行されるので、同じ失敗を毎回出すとログが溢れる。
// 今の理由は管理用 API と Web UI の状態で見える(設計文書 7a.3 節)。
func ruleFailureLog(prev map[string]string, failed map[string]error) (map[string]string, []string) {
	next := make(map[string]string, len(failed))
	var lines []string
	ids := make([]string, 0, len(failed))
	for id := range failed {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		reason := failed[id].Error()
		next[id] = reason
		if prev[id] != reason {
			lines = append(lines, fmt.Sprintf("rule %s: not active: %s", id, reason))
		}
	}
	var recovered []string
	for id := range prev {
		if _, still := next[id]; !still {
			recovered = append(recovered, id)
		}
	}
	sort.Strings(recovered)
	for _, id := range recovered {
		lines = append(lines, fmt.Sprintf("rule %s: no longer failing", id))
	}
	return next, lines
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
			Policy:        pp.Policy, Agent: pp.Agent,
		})
	}
	return out
}

// proxyInputHints は、vpsd 自身が host のソケットで受けるルールの公開ポートが既定 drop の input で
// 塞がれていれば提示する。カーネルモードでは、host のソケットで受けるのはプロキシモード(Relay。
// TCP のみ)のルールだけで、Transparent なルールは他テーブルの DNAT + forward を経由し input を
// 通らない(仕様 6.1・6.2 節)。ユーザー空間モードでは vps_mode の区別に意味が無く、全ルールが
// host のソケットで受ける中継になるため、有効なルールすべてを対象にする(仕様 6.3 節)。
func (d *Daemon) proxyInputHints(rules []proto.Rule) {
	for i := range rules {
		r := &rules[i]
		if !r.Enabled {
			continue
		}
		if d.opts.Mode != modeUserspace && r.VPSMode != proto.ModeProxy {
			continue
		}
		if lines, err := d.dp.InputPortSuggestions(r.ListenPort, r.Proto); err == nil && len(lines) > 0 {
			log.Printf("warning: rule %s public port %s/%s is blocked at input; add the following:", r.ID, r.ListenPort, r.Proto)
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
	return planner.Build(planner.Input{Rules: normalized, Limits: d.opts.AdmissionLimits, Agents: agents}), excluded
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
