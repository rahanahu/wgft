package vpsd

import (
	"errors"
	"fmt"
	"github.com/rahanahu/wgft/internal/vpsd/check"
	ctconv "github.com/rahanahu/wgft/internal/vpsd/conntrack"
	"github.com/rahanahu/wgft/internal/vpsd/nft"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/wg"
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
	changes, err := d.dp.EnsureWG(wg.Config{
		Interface: d.opts.WGInterface, PrivateKey: d.serverKey, ListenPort: int(d.opts.WGPort),
		Address: d.network, MTU: d.opts.MTU, Peers: peers, AdoptExisting: d.opts.AdoptExisting,
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
	// プロキシモードの新しい待ち受けを先に開き(Prepare)、開けたポートだけに nftables の
	// 接続元 IP ごとの上限の行を付ける。nftables の差し替えが失敗したら新しい待ち受けを閉じて
	// 旧い待ち受けと旧いテーブルを揃えたまま残し、成功したら中継を始めて不要な待ち受けを閉じる(仕様 6.1 節)
	var prepared *proxyrelay.Prepared
	var proxyListening map[uint16]bool
	if d.proxy != nil {
		prepared = d.proxy.Prepare(proxyrelay.FromRules(rules, agentAddr))
		proxyListening = prepared.Listening()
	}
	if err := d.dp.ApplyNFT(rules, agentAddr, proxyListening); err != nil {
		if prepared != nil {
			prepared.Rollback()
		}
		return fmt.Errorf("failed to apply nftables: %w", err)
	}
	if prepared != nil {
		prepared.Commit()
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
	d.converge(rules, agentAddr)
	if d.proxy != nil {
		d.proxyInputHints(rules)
	}
	return nil
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

// converge は外から入って DNAT されたフローを、現在のカーネルモードの有効なルールに収束させる(仕様 6.1 節)。
func (d *Daemon) converge(rules []proto.Rule, agentAddr map[string]netip.Addr) {
	var crules []ctconv.Rule
	for i := range rules {
		r := &rules[i]
		if !r.Enabled || r.VPSMode != proto.ModeKernel {
			continue
		}
		addr, ok := agentAddr[r.Agent]
		if !ok {
			continue
		}
		crules = append(crules, ctconv.Rule{Proto: r.Proto, ListenPort: r.ListenPort, AgentAddr: addr,
			SourceDeny: r.SourceDeny, SourceAllow: r.SourceAllow})
	}
	if n, err := d.dp.Converge(crules, d.network); err != nil {
		log.Printf("conntrack converge: %v", err)
	} else if n > 0 {
		log.Printf("conntrack: removed %d unneeded flows", n)
	}
}

// accumulateDrops は今回読んだカウンタ(前回の適用以降の増分そのもの)を累積する。
func (d *Daemon) accumulateDrops(drops []nft.Drop) error {
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
func (d *Daemon) checkRule(r *proto.Rule, rep *check.Report, force bool) error {
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
