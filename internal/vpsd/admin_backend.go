package vpsd

import (
	"errors"
	"fmt"
	"github.com/rahanahu/wgft/internal/buildinfo"
	"github.com/rahanahu/wgft/internal/reconcile"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
	"log"
	"net"
	"net/netip"
	"strconv"
	"time"
)

// Rules / Generation / Agents / JoinString / Revoke は admin.Backend の実装。
// 操作名を付けて包むのは、admin.go の 500 応答が err.Error() をそのまま本文にするため。
// 包まないと運用者は "database is locked" のような文言だけを見て、どの読み取りが失敗したか分からない。
func (d *Daemon) Rules() ([]proto.Rule, error) {
	rules, err := d.st.Rules()
	if err != nil {
		return nil, fmt.Errorf("reading rules: %w", err)
	}
	return rules, nil
}

func (d *Daemon) Generation() (uint64, error) {
	gen, err := d.st.Generation()
	if err != nil {
		return 0, fmt.Errorf("reading generation: %w", err)
	}
	return gen, nil
}

func (d *Daemon) RuleDrops() (map[string]uint64, error) {
	drops, err := d.st.RuleDrops()
	if err != nil {
		return nil, fmt.Errorf("reading rule drops: %w", err)
	}
	return drops, nil
}

func (d *Daemon) Agents() ([]admin.AgentInfo, error) {
	list, err := d.st.Agents()
	if err != nil {
		return nil, err
	}
	dev, _ := d.dp.WGStatus()
	out := make([]admin.AgentInfo, 0, len(list))
	for _, a := range list {
		info := admin.AgentInfo{Name: a.Name, Address: a.Address.String(), PublicKey: a.PublicKey,
			RegisteredFrom: a.RegisteredFrom, CreatedAt: a.CreatedAt.Format(time.RFC3339)}
		st := d.hub.Status(a.Name)
		info.Connected, info.StreamFrom = st.Connected, st.StreamFrom
		if !st.LastHeartbeat.IsZero() {
			info.LastHeartbeat = st.LastHeartbeat.Format(time.RFC3339)
		}
		if st.Heartbeat != nil {
			info.Generation = st.Heartbeat.Generation
			info.Tunnel = st.Heartbeat.Tunnel
			info.Rules = st.Heartbeat.Rules
		}
		if st.Connected {
			// 版の交渉(仕様 7a.6 節)。観測用の加算フィールドで、管理用 API の契約は変えない
			info.ProtocolVersion = st.Protocol.Version
			info.AgentProtocolLegacy = st.Protocol.Legacy
			info.AgentProtocolMin = st.Protocol.AgentMin
			info.AgentProtocolMax = st.Protocol.AgentMax
		}
		if dev != nil && a.PublicKey != "" {
			for _, p := range dev.Peers {
				if p.PublicKey.String() == a.PublicKey {
					if p.Endpoint != nil {
						info.WGEndpoint = p.Endpoint.String()
					}
					if !p.LastHandshakeTime.IsZero() {
						info.LastHandshake = p.LastHandshakeTime.Format(time.RFC3339)
					}
				}
			}
		}
		if ws, err := d.st.AgentWarnings(a.Name); err != nil {
			// fail open: 1 エージェントの警告が読めなくても agent 一覧そのものは返す(仕様どおり)。
			// ただし黙って空にはせず、原因をログに残す。運用者は WARN 列と dashboard の警告数が
			// 実際より少ないことに気づけない代わりに、ログでその欠落に気づける
			log.Printf("agent %s: reading warnings: %v", a.Name, err)
		} else {
			for _, w := range ws {
				info.Warnings = append(info.Warnings, admin.Warning{Agent: w.Agent, Kind: w.Kind, Detail: w.Detail, At: w.CreatedAt.Format(time.RFC3339)})
			}
		}
		out = append(out, info)
	}
	return out, nil
}

const joinTokenTTL = time.Hour

// JoinString は接続文字列 wgft://host:port/token#sha256:<証明書のハッシュ> を発行する(仕様 5.1 節)。
func (d *Daemon) JoinString(name string) (admin.JoinStringResponse, error) {
	host := d.opts.AgentAPIHost
	if host == "" {
		h, _, _ := net.SplitHostPort(d.opts.WGEndpoint)
		_, port, _ := net.SplitHostPort(d.opts.AgentAPIAddr)
		if h == "" || port == "" {
			return admin.JoinStringResponse{}, errors.New("cannot determine the host for the join string; set --agent-api-host or --wg-endpoint")
		}
		host = net.JoinHostPort(h, port)
	}
	tok, err := d.st.IssueJoinToken(name, joinTokenTTL)
	if err != nil {
		return admin.JoinStringResponse{}, err
	}
	fp := d.agentAPI.Fingerprint()
	log.Printf("issued a join string for agent %s", name)
	return admin.JoinStringResponse{
		JoinString: fmt.Sprintf("wgft://%s/%s#sha256:%x", host, tok, fp[:]),
		ExpiresAt:  time.Now().Add(joinTokenTTL).Format(time.RFC3339),
	}, nil
}

// Revoke は恒久トークンを無効化し、ピアを消し、アドレスを回収する(仕様 11 節)。
// そのエージェントのルールは残るが、行を持たなくなる。中継は CloseAgent で閉じ、ピアと nftables は
// 1 つのトランザクション(applyNFT)で消す。ピアはテーブルの差し替えの後に外れる(設計文書 7a.3 節)。
func (d *Daemon) Revoke(name string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.st.RevokeAgent(name); err != nil {
		return err
	}
	_ = d.st.ClearWarning(name, store.WarnIPMismatch, "")
	_ = d.st.ClearWarning(name, store.WarnIPFlapping, "")
	log.Printf("revoked agent %s", name)
	d.hub.Disconnect(name, proto.CloseRevoked, "revoked")
	if d.proxy != nil {
		d.proxy.CloseAgent(name)
	}
	rules, err := d.st.Rules()
	if err != nil {
		return err
	}
	return d.applyNFT(rules)
}

// Batch はルールの変更を 1 トランザクションで保存し、成功したら nftables を差し替える。
func (d *Daemon) Batch(req admin.BatchRequest) (*store.BatchResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	rep, err := d.dp.Inspect()
	if err != nil {
		return nil, err
	}
	_, agentAddr, err := d.agents()
	if err != nil {
		return nil, err
	}
	// added/updated/deleted は成功ログ用(batchSummary)。mutate は ApplyBatch から 1 回だけ
	// 呼ばれる(store.ApplyBatch にリトライは無い)ので、ここで直接埋めてよい。
	var added, updated, deleted []string
	res, err := d.st.ApplyBatch(d.reserved, func(rules []proto.Rule) ([]proto.Rule, error) {
		// ExpectedDigest の照合は、rules(このトランザクションが読んだ「今の」集合)に対して
		// 行う。読み取りと変更の間に他経路が割り込む余地が無いので、Web UI の読み込み確認・
		// 適用のように、確認を描いた時点から適用までに間がある操作で、その間の別経路の変更を
		// 見逃さず塞げる(仕様 5.4、10.1 節)。
		if req.ExpectedDigest != "" && proto.RulesDigest(rules) != req.ExpectedDigest {
			return nil, admin.ErrBatchConflict
		}
		added, updated, deleted = nil, nil, nil
		byID := map[string]int{}
		for i, r := range rules {
			byID[r.ID] = i
		}
		// 無い ID の削除は成功扱いにしない(`rule ls` の短縮表示をそのまま渡した場合など)
		del := map[string]bool{}
		for _, id := range req.Delete {
			if _, ok := byID[id]; !ok {
				return nil, fmt.Errorf("rule %q not found", id)
			}
			del[id] = true
			deleted = append(deleted, id)
		}
		for _, u := range req.Upsert {
			if _, ok := agentAddr[u.Agent]; !ok {
				return nil, fmt.Errorf("rule %s: agent %q is not registered", u.ID, u.Agent)
			}
			if i, ok := byID[u.ID]; ok {
				// 読み込みは変わっていない行も upsert に含むので、中身が変わった行だけを記録する
				if proto.RulesDigest([]proto.Rule{rules[i]}) != proto.RulesDigest([]proto.Rule{u}) {
					updated = append(updated, u.ID)
				}
				rules[i] = u
			} else {
				byID[u.ID] = len(rules)
				rules = append(rules, u)
				added = append(added, u.ID)
			}
		}
		out := rules[:0]
		for _, r := range rules {
			if !del[r.ID] {
				out = append(out, r)
			}
		}
		// 追加・変更されたルールだけ、他テーブルの DNAT と bind 中のポートを検査する
		for _, u := range req.Upsert {
			if err := d.checkRule(&u, rep, req.Force); err != nil {
				return nil, err
			}
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	// 変更は SQLite に確定済みなので、データプレーンへの適用に失敗しても記録を残す
	log.Print(batchSummary(req.Op, added, updated, deleted, res.Generation, res.Changed))
	if err := d.applyNFT(res.Rules); err != nil {
		log.Printf("rules: %s: applying the data plane failed: %v", opOrAPI(req.Op), err)
		return nil, err
	}
	if res.Changed {
		go d.hub.PushAll()
	}
	return res, nil
}

// AgentState はそのエージェントに配る全体状態(仕様 5.2 節)。
func (d *Daemon) AgentState(agent string) (*proto.State, error) {
	_, agentAddr, err := d.agents()
	if err != nil {
		return nil, err
	}
	addr, ok := agentAddr[agent]
	if !ok {
		return nil, fmt.Errorf("agent %q is not registered", agent)
	}
	rules, err := d.st.Rules()
	if err != nil {
		return nil, err
	}
	gen, err := d.st.Generation()
	if err != nil {
		return nil, err
	}
	wgAddr := d.network
	st := &proto.State{
		Generation: gen,
		WG: proto.WGConfig{
			ServerPubkey: d.serverKey.PublicKey().String(), Endpoint: d.opts.WGEndpoint,
			Address: netip.PrefixFrom(addr, wgAddr.Bits()).String(), MTU: d.opts.MTU, Keepalive: 25,
			UDPTimeout: d.timeouts.Timeout, UDPTimeoutStream: d.timeouts.TimeoutStream,
		},
		Rules: []proto.AgentRule{},
	}
	for i := range rules {
		if rules[i].Agent == agent {
			st.Rules = append(st.Rules, rules[i].ForAgent())
		}
	}
	return st, nil
}

// DismissWarning は警告を消す(管理者が正当と確認したとき。仕様 5.2 節)。
func (d *Daemon) DismissWarning(agent, kind, detail string) error {
	if err := d.st.ClearWarning(agent, kind, detail); err != nil {
		return err
	}
	log.Printf("dismissed warning %s for agent %s", kind, agent)
	return nil
}

// CheckConnectivity は TCP ルールの疎通確認(仕様 10.1 節)。vpsd から wg0 経由でエージェントの
// リスナーに接続し、中継を通して target に届くかを見る。確かめられるのは内側の経路まで。
func (d *Daemon) CheckConnectivity(ruleID string) (admin.ConnCheck, error) {
	rules, err := d.st.Rules()
	if err != nil {
		return admin.ConnCheck{}, err
	}
	var r *proto.Rule
	for i := range rules {
		if rules[i].ID == ruleID {
			r = &rules[i]
			break
		}
	}
	if r == nil {
		return admin.ConnCheck{}, fmt.Errorf("rule %q not found", ruleID)
	}
	if r.Proto != proto.TCP {
		return admin.ConnCheck{}, fmt.Errorf("connectivity check is for TCP rules only; a UDP send cannot tell success")
	}
	if !r.Enabled {
		return admin.ConnCheck{}, fmt.Errorf("cannot check a disabled rule")
	}
	_, agentAddr, err := d.agents()
	if err != nil {
		return admin.ConnCheck{}, err
	}
	addr, ok := agentAddr[r.Agent]
	if !ok {
		return admin.ConnCheck{}, fmt.Errorf("agent %q is not registered", r.Agent)
	}
	res := d.dp.CheckConnectivity(net.JoinHostPort(addr.String(), strconv.Itoa(int(r.ListenPort.Lo))))
	return admin.ConnCheck{OK: res.OK, Reach: res.Reach, Detail: res.Detail}, nil
}

// Warnings は全警告(UI / CLI 用)。
func (d *Daemon) Warnings() ([]admin.Warning, error) {
	ws, err := d.st.Warnings()
	if err != nil {
		return nil, err
	}
	out := make([]admin.Warning, 0, len(ws))
	for _, w := range ws {
		out = append(out, admin.Warning{Agent: w.Agent, Kind: w.Kind, Detail: w.Detail, At: w.CreatedAt.Format(time.RFC3339)})
	}
	return out, nil
}

// ServerInfo は vpsd/VPS の構成と環境を返す(ダッシュボード上部、仕様 10.1)。
func (d *Daemon) ServerInfo() (admin.ServerInfo, error) {
	apiPort := ""
	if _, p, err := net.SplitHostPort(d.opts.AgentAPIAddr); err == nil {
		apiPort = p
	}
	ipf := ""
	if b, err := d.st.GetMeta(metaIPForwardSetAt); err == nil {
		ipf = string(b)
	}
	return admin.ServerInfo{
		Version:          buildinfo.Version,
		Mode:             d.opts.Mode,
		StartedAt:        d.startedAt.UTC().Format(time.RFC3339),
		WGInterface:      d.opts.WGInterface,
		WGAddress:        d.opts.WGAddress,
		WGPort:           int(d.opts.WGPort),
		WGEndpoint:       d.opts.WGEndpoint,
		AgentAPIPort:     apiPort,
		AdminAddr:        d.opts.AdminAddr,
		MTU:              d.opts.MTU,
		ServerPubKey:     d.serverKey.PublicKey().String(),
		Kernel:           d.kernel,
		NFT:              d.nftVer,
		IPForwardSetAt:   ipf,
		UDPTimeout:       d.timeouts.Timeout,
		UDPTimeoutStream: d.timeouts.TimeoutStream,
	}, nil
}

// ApplyStatus は admin.ApplyStatusBackend の実装。Reconciler が持つ Desired と Active の対応
// (設計文書 7a.3 節)を管理用 API の形に写す。最初の適用を試みるまでは false を返す。
func (d *Daemon) ApplyStatus() (admin.ApplyStatus, bool) {
	d.mu.Lock()
	rec := d.rec
	d.mu.Unlock()
	if rec == nil {
		return admin.ApplyStatus{}, false
	}
	st := rec.Status()
	if !st.Reconciled {
		return admin.ApplyStatus{}, false
	}
	return applyStatusToAdmin(st), true
}

// udpPooler is implemented by a serverDataplane that tracks UDP flows in a resource.Pool. Only
// userspace mode does (userspaceDataplane, dataplane_userspace.go): kernel mode counts UDP through
// nftables/conntrack, not through resource.Pool (design.md 7a.10 節「kernel 側の保護」). Kept
// separate from serverDataplane so kernelDataplane needs no meaningless implementation.
type udpPooler interface {
	UDPPool() *resource.Pool
}

// ResourceStatus is admin.ResourceStatusBackend's implementation (design.md 7a.10 節「拒否の報告」).
// TCP always has a pool: d.proxy judges every Relay connection (kernel mode: its own pool; userspace
// mode: the same pool the relay uses, design.md 7a.10 節「共有プールと隔離予約」). UDP has one only
// in userspace mode, so kernel mode's FlowBudget has no "udp" entry and no UDP rule ever appears in
// Refusals.
func (d *Daemon) ResourceStatus() admin.ResourceStatus {
	budget := map[proto.Proto]admin.FlowBudget{}
	refusals := map[string]map[string]uint64{}
	addPool := func(p proto.Proto, pool *resource.Pool) {
		if pool == nil {
			return
		}
		budget[p] = admin.FlowBudget{InUse: pool.InUse(), Limit: pool.Total()}
		for rule, byReason := range pool.Refusals() {
			m := make(map[string]uint64, len(byReason))
			for reason, n := range byReason {
				m[string(reason)] = n
			}
			refusals[rule] = m
		}
	}
	addPool(proto.TCP, d.proxy.Pool())
	if up, ok := d.dp.(udpPooler); ok {
		addPool(proto.UDP, up.UDPPool())
	}
	return admin.ResourceStatus{FlowBudget: budget, Refusals: refusals}
}

func applyStatusToAdmin(st reconcile.Status) admin.ApplyStatus {
	out := admin.ApplyStatus{DesiredGeneration: st.DesiredGeneration, ActiveGeneration: st.ActiveGeneration,
		Rules: make(map[string]admin.RuleApply, len(st.Rules)), LastError: st.LastError}
	for id, rs := range st.Rules {
		out.Rules[id] = admin.RuleApply{ApplyState: string(rs.State), Reason: rs.Reason, ActiveGeneration: rs.ActiveGeneration}
	}
	conv := func(rs []reconcile.Resource) []admin.DriftResource {
		res := make([]admin.DriftResource, 0, len(rs))
		for _, r := range rs {
			res = append(res, admin.DriftResource{RuleID: r.RuleID, Proto: r.Proto, ListenPort: r.ListenPort, Forwarding: r.Forwarding})
		}
		return res
	}
	out.Drift = admin.Drift{ActiveOnly: conv(st.ActiveOnly), Retiring: conv(st.Retiring)}
	return out
}
