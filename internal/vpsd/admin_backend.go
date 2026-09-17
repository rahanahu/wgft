package vpsd

import (
	"errors"
	"fmt"
	"github.com/rahanahu/wgft/internal/buildinfo"
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
func (d *Daemon) Rules() ([]proto.Rule, error) { return d.st.Rules() }

func (d *Daemon) Generation() (uint64, error) { return d.st.Generation() }

func (d *Daemon) RuleDrops() (map[string]uint64, error) { return d.st.RuleDrops() }

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
		if ws, err := d.st.AgentWarnings(a.Name); err == nil {
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
	return admin.JoinStringResponse{
		JoinString: fmt.Sprintf("wgft://%s/%s#sha256:%x", host, tok, fp[:]),
		ExpiresAt:  time.Now().Add(joinTokenTTL).Format(time.RFC3339),
	}, nil
}

// Revoke は恒久トークンを無効化し、ピアを消し、アドレスを回収する(仕様 11 節)。
// そのエージェントのルールは残るが、行を持たなくなる。中継は CloseAgent で閉じ、ピアと nftables は再収束で消す。
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
	if err := d.reconcileWG(); err != nil {
		return err
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
	res, err := d.st.ApplyBatch(d.reserved, func(rules []proto.Rule) ([]proto.Rule, error) {
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
		}
		for _, u := range req.Upsert {
			if _, ok := agentAddr[u.Agent]; !ok {
				return nil, fmt.Errorf("rule %s: agent %q is not registered", u.ID, u.Agent)
			}
			if i, ok := byID[u.ID]; ok {
				rules[i] = u
			} else {
				byID[u.ID] = len(rules)
				rules = append(rules, u)
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
	if err := d.applyNFT(res.Rules); err != nil {
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
	return d.st.ClearWarning(agent, kind, detail)
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
