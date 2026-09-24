//go:build linux

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/proto"
)

// kernelModeBuilt は、このビルドがカーネルモードの dataplane を持つかどうかである(mode.go)。
const kernelModeBuilt = true

// kernelOps はカーネルと外の世界に触れる操作である。単体テストだけが差し替える。
type kernelOps struct {
	ensureLink     func(wg.AgentConfig) ([]string, error)
	inspectLink    func(iface string, current, previous wgtypes.Key) (wg.AgentState, error)
	keyHolders     func(iface string, current, previous wgtypes.Key) ([]string, error)
	publish        func(nft.AgentPublication, nft.AgentConfig) error
	lookup         nft.LookupFunc
	probe          func(ctx context.Context, dest netip.AddrPort) error
	readIPForward  func() (bool, error)
	writeIPForward func() error
	localAddrs     func() (map[netip.Addr]bool, error)
	now            func() time.Time
}

func defaultKernelOps() kernelOps {
	return kernelOps{
		ensureLink:  wg.EnsureAgent,
		inspectLink: wg.InspectAgent,
		keyHolders:  wg.AgentKeyHolders,
		publish:     nft.ApplyAgent,
		lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		probe: func(ctx context.Context, dest netip.AddrPort) error {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", dest.String())
			if err != nil {
				return err
			}
			return c.Close()
		},
		readIPForward:  linux.ReadIPForward,
		writeIPForward: linux.WriteIPForward,
		localAddrs:     hostAddrs,
		now:            time.Now,
	}
}

// 名前の解決と宛先の試し接続の期限(仕様 5.2・7b.2・7b.3 節)。試し接続の 2 秒と同時に試す数の 32 は
// ユーザー空間モードの中継と同じ値である(internal/dataplane/userspace/relay)。
const (
	kernelResolveTimeout  = 10 * time.Second
	kernelProbeTimeout    = 2 * time.Second
	kernelProbeConcurrent = 32
)

// kernelDataplane はカーネルモードの dataplane である(仕様 7b 節)。カーネルの WireGuard インタフェースと
// table inet wgft_agent を宣言へ収束させる。エージェントのプロセスはパケットを中継しない。close はカーネルの
// 資源を消さないので、停止の間も転送は続く(7b.4 節)。
//
// どのメソッドも、runtime が rt.mu を持った状態で呼ぶ(dataplane.go)。f は runtime と共有する認証情報
// ファイルで、applyRules が公開の記録を書き込み、runtime が last_state と同じ 1 回の保存で書き出す。
type kernelDataplane struct {
	ops   kernelOps
	iface string
	allow *allowtargets.List
	f     *credentials.Credentials
	// ctx は停止で取り消される。名前の解決に使い、取り消された解決の結果では公開しない
	ctx context.Context

	have bool
	priv wgtypes.Key
	wg   proto.WGConfig
	// server は vpsd のトンネルアドレスである。全体状態に無いので、自分のアドレスの帯の先頭とする(4 節)
	server netip.Addr
	// endpoint は直前に解決したエンドポイントであり、endpointOf はその元にした名前である(7b.1 節)。
	// 解決できていない間はゼロで、インタフェースの収束はカーネルが持つエンドポイントを残す
	//
	// この 3 つは epMu が守る。名前を引く準備(prepareApply)が rt.mu の外で読むためである
	epMu       sync.Mutex
	endpoint   netip.AddrPort
	endpointOf string
	endpointEr error

	// converged は、このプロセスが wgft0 を一度でも収束させたかどうかである。偽の間の所有の衝突、
	// アドレス帯の重なり、前提の欠如は起動の失敗として扱う(11b 節、fatalError)
	converged bool

	// pub は直近に公開に成功したテーブルの記録である。起動時は認証情報ファイルの記録から読む
	pub *nft.AgentPublication
	// lkg はルールごとの、直前に解決できた宛先のアドレスである(7b.2 節)。宣言の宛先の文字列が
	// 同じ間だけ使う
	lkg map[string]lkgEntry
	// probeErr は TCP のルールの宛先の試し接続の誤りである(7b.3 節の 2 つ目の種類)。ルール ID ごと
	probeErr map[string]string
	// forwardErr は net.ipv4.ip_forward が 1 でないことの理由である(7b.1 節)。nil なら 1
	forwardErr error
	// local はホスト自身のアドレスである。forwardErr があるときだけ読む
	local map[netip.Addr]bool
}

// lkgEntry は、ルールの宛先の名前を最後に解決できたときの結果である。
type lkgEntry struct {
	target string
	addrs  []netip.Addr
}

// startupFatal は、最初の収束で起きたときにプロセスを終える誤りかどうかである。
func startupFatal(err error) bool {
	var notOurs *wg.NotOursError
	var overlap *wg.OverlapError
	return errors.As(err, &notOurs) || errors.As(err, &overlap) || startup.Of(err) != nil
}

// newKernelDataplane はカーネルモードの dataplane を作る。カーネルには何も書かない。
func newKernelDataplane(ctx context.Context, iface string, allow *allowtargets.List, f *credentials.Credentials) (agentDataplane, error) {
	d := &kernelDataplane{ops: defaultKernelOps(), iface: iface, allow: allow, f: f, ctx: ctx,
		lkg: map[string]lkgEntry{}, probeErr: map[string]string{}}
	d.loadRecord()
	return d, nil
}

// loadRecord は認証情報ファイルの公開の記録を読み、直前に公開したテーブルと、ルールごとの直前に
// 解決できたアドレスの元にする。読めない記録は無いものとして扱う。記録は診断と比較のためのもので、
// 起動を止める理由にはしない。
func (d *kernelDataplane) loadRecord() {
	if len(d.f.KernelPublication) == 0 {
		return
	}
	var pub nft.AgentPublication
	if err := json.Unmarshal(d.f.KernelPublication, &pub); err != nil {
		log.Printf("kernel mode: ignoring the unreadable publication record in the credentials file: %v", err)
		return
	}
	d.pub = &pub
	for _, r := range pub.Rules {
		host, _, err := net.SplitHostPort(r.Target)
		if err != nil || len(r.Ranges) == 0 {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		var addrs []netip.Addr
		for _, rg := range r.Ranges {
			addrs = append(addrs, rg.Dest.Addr())
		}
		d.lkg[r.RuleID] = lkgEntry{target: r.Target, addrs: sortedAddrs(addrs)}
	}
}

// startup は起動時に、何かを書く前に行う検査と準備である(7b.1・7b.4 節)。wgft0 の所有を判定し、
// 他の所有者のものなら終了コード 1 の誤りを返す。権限が足りなければ種別 prerequisite の拒否を返す。
// 続けて、別の名前で自分の鍵を持つインタフェースを警告し、ip_forward を 1 にし、ホストの設定の
// 手掛かりを 1 行ずつ出す。save は認証情報ファイルを保存する。ip_forward を変える記録に使う。
func (d *kernelDataplane) startup(priv wgtypes.Key, save func() error) error {
	prev, err := d.f.PreviousKey()
	if err != nil {
		return err
	}
	st, err := d.ops.inspectLink(d.iface, priv, prev)
	if err != nil {
		return wg.AgentPrivilegeRefusal(fmt.Errorf("read %s: %w", d.iface, err))
	}
	if st.Exists && !st.Ownership.Ours() {
		return &wg.NotOursError{Interface: d.iface, Ownership: st.Ownership, Kind: st.Kind,
			Keyless: st.Kind == "wireguard" && st.PublicKey == wgtypes.Key{}}
	}
	if st.Ownership == wg.OwnedByPreviousKey {
		log.Printf("kernel mode: %s holds the previous key; the first convergence moves it to the current key", d.iface)
	}
	if names, err := d.ops.keyHolders(d.iface, priv, prev); err != nil {
		log.Printf("kernel mode: cannot list WireGuard interfaces to look for this agent's key under another name: %v", err)
	} else {
		for _, n := range names {
			log.Printf("warning: the WireGuard interface %s holds this agent's key but is not %s, which this agent uses; "+
				"it is left over from an earlier WGFT_WG_INTERFACE and is not deleted automatically; delete it with `ip link del %s` once it is not needed", n, d.iface, n)
		}
	}
	if err := d.enableForwarding(save); err != nil {
		return err
	}
	logHostFindings(d.iface)
	return nil
}

// enableForwarding は net.ipv4.ip_forward を 1 にし、0 から変えたときはその日時を記録する(7b.1 節)。
// 記録は値を書く前に保存する。書いた後に保存すると、その間に落ちたとき、wgft が変えた値の記録が
// 残らないためである。記録を保存できなければ値を書かずに誤りを返し、起動は終了コード 1 で終わる。
// 値を書けなければ記録を元に戻し、警告して続け、宛先がホスト自身でないルールを error として報告する。
// 今の値を読めなかった場合は、0 だったとは言えないので、1 を書いても記録しない。
func (d *kernelDataplane) enableForwarding(save func() error) error {
	on, rerr := d.ops.readIPForward()
	if rerr == nil && on {
		d.forwardErr = nil
		return nil
	}
	prev := d.f.IPForwardEnabledAt
	recorded := false
	if rerr == nil && prev == nil {
		now := d.ops.now().UTC()
		d.f.IPForwardEnabledAt = &now
		if err := save(); err != nil {
			d.f.IPForwardEnabledAt = prev
			return fmt.Errorf("record that the agent sets net.ipv4.ip_forward before setting it: %w", err)
		}
		recorded = true
	}
	if err := d.ops.writeIPForward(); err != nil {
		if recorded {
			d.f.IPForwardEnabledAt = prev
			if serr := save(); serr != nil {
				log.Printf("warning: cannot remove the ip_forward record after the write failed: %v", serr)
			}
		}
		d.forwardErr = fmt.Errorf("net.ipv4.ip_forward is not 1 and cannot be set: %w", err)
		log.Printf("warning: %v; rules whose target is not this host are reported as errors until it is 1", d.forwardErr)
		if l, err := d.ops.localAddrs(); err == nil {
			d.local = l
		}
		return nil
	}
	d.forwardErr = nil
	switch {
	case rerr != nil:
		log.Printf("net.ipv4.ip_forward could not be read: %v; wrote 1 without recording a change, since it may already have been 1", rerr)
	default:
		log.Printf("set net.ipv4.ip_forward to 1; it is left at 1 when the agent stops, and wgft agent teardown shows it as a value to restore")
	}
	return nil
}

// logHostFindings は、エージェントの転送を妨げうるホストの設定を 1 行ずつ出す(7b.1 節)。どれも
// 書き換えない。明示の accept や経路の組み方によっては転送が通るので、止めもしない。
func logHostFindings(iface string) {
	if rep, err := linux.Inspect(iface, nft.AgentTableName); err != nil {
		log.Printf("kernel mode: cannot read the other nftables tables to check their forward policy: %v", err)
	} else {
		for _, f := range rep.Findings {
			if f.Hook != linux.HookForward {
				continue
			}
			log.Printf("warning: %s drops forwarded packets by default; forwarding from %s to the LAN stops there unless that table accepts it, "+
				"for example with an accept for packets in from %s and for established packets out to %s", f.Where, iface, iface, iface)
		}
	}
	for _, name := range []string{"all", "default"} {
		if v, err := os.ReadFile("/proc/sys/net/ipv4/conf/" + name + "/rp_filter"); err == nil && strings.TrimSpace(string(v)) == "1" {
			log.Printf("warning: net.ipv4.conf.%s.rp_filter is 1, strict; on a home with more than one LAN segment it can drop forwarded replies; wgft does not change it", name)
			break
		}
	}
	if u, err := linux.ReadConntrackUsage(); err == nil {
		if w := u.StartupWarning(); w != "" {
			log.Printf("%s", w)
		}
	}
}

func (d *kernelDataplane) build(priv wgtypes.Key, w proto.WGConfig) (bool, error) {
	if _, err := wgtypes.ParseKey(w.ServerPubkey); err != nil {
		return false, fmt.Errorf("server_pubkey: %w", err)
	}
	addr, err := netip.ParsePrefix(w.Address)
	if err != nil || !addr.Addr().Is4() {
		return false, fmt.Errorf("address %q is not an IPv4 CIDR", w.Address)
	}
	if w.MTU <= 0 {
		return false, fmt.Errorf("mtu %d is not positive", w.MTU)
	}
	if w.Keepalive < 0 || w.Keepalive > 65535 {
		return false, fmt.Errorf("keepalive %d is not between 0 and 65535", w.Keepalive)
	}
	d.priv, d.wg, d.have = priv, w, true
	d.server = addr.Masked().Addr().Next()
	return true, nil
}

func (d *kernelDataplane) built() bool { return d.have }

// cachedEndpoint は直前に解決できたエンドポイントである。まだ無ければゼロで、インタフェースの収束は
// カーネルが持つエンドポイントを残す(7b.1 節)。
func (d *kernelDataplane) cachedEndpoint() netip.AddrPort {
	d.epMu.Lock()
	defer d.epMu.Unlock()
	return d.endpoint
}

// linkConfig は wgft0 の宣言である。
func (d *kernelDataplane) linkConfig() (wg.AgentConfig, error) {
	prev, err := d.f.PreviousKey()
	if err != nil {
		return wg.AgentConfig{}, err
	}
	serverPub, _ := wgtypes.ParseKey(d.wg.ServerPubkey)
	addr, _ := netip.ParsePrefix(d.wg.Address)
	return wg.AgentConfig{
		Interface: d.iface, PrivateKey: d.priv, PreviousKey: prev, Address: addr, MTU: d.wg.MTU,
		Server: wg.ServerPeer{PublicKey: serverPub, Address: d.server, Endpoint: d.cachedEndpoint(),
			Keepalive: time.Duration(d.wg.Keepalive) * time.Second},
	}, nil
}

// kernelPrepared は、rt.mu の外で行った名前の解決の結果である(prepareApply)。
type kernelPrepared struct {
	// endpoint は、エンドポイントを引いたときの結果である。引かなかったら tried が偽である
	tried      bool
	endpointOf string
	endpoint   netip.AddrPort
	endpointEr error
	// resolved はルールの宛先の名前の解決の結果である
	resolved map[string]nft.Resolution
	// err は、停止で解決が打ち切られたことを表す。このとき公開しない
	err error
}

// prepareApply は全体状態 st の適用に要る名前を rt.mu の外で引く。runtime は結果を applyRules に
// 渡す。DNS を待つ間、ハートビートと doctor が排他を待たないためである。読むのは変わらない値
// (ops と ctx)と、epMu が守るエンドポイントの控えだけである。
//
// エンドポイントを引くのは、宣言のエンドポイントが変わったときと、まだ一度も解決できていないとき
// だけである(7b.1 節)。解決できていた名前を引けなくなっても、控えたアドレスを使い続ける。
// 宛先の名前は同時に引き、1 つの遅い名前が他の名前の期限を使い切らないようにする。
func (d *kernelDataplane) prepareApply(st *proto.State) any {
	p := &kernelPrepared{endpointOf: st.WG.Endpoint}
	d.epMu.Lock()
	need := !d.endpoint.IsValid() || d.endpointOf != st.WG.Endpoint
	d.epMu.Unlock()
	ctx, cancel := context.WithTimeout(d.ctx, kernelResolveTimeout)
	defer cancel()
	if need {
		p.tried = true
		p.endpoint, p.endpointEr = resolveEndpointAddr(ctx, st.WG.Endpoint, d.ops.lookup)
	}
	p.resolved = resolveTargets(ctx, st.Rules, d.ops.lookup)
	if d.ctx.Err() != nil {
		p.err = errors.New("not publishing: the agent is stopping")
	}
	return p
}

// resolveTargets は、ルールの宛先の名前を同時に引いてから、nft.ResolveAgentTargets に結果を渡す。
// IPv4 の選び方と誤りの扱いは nft.ResolveAgentTargets のままである。
func resolveTargets(ctx context.Context, rules []proto.AgentRule, lookup nft.LookupFunc) map[string]nft.Resolution {
	type answer struct {
		addrs []netip.Addr
		err   error
	}
	hosts := map[string]bool{}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		host, _, err := net.SplitHostPort(r.Target)
		if err != nil || host == "" {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		hosts[host] = true
	}
	answers := make(map[string]answer, len(hosts))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := lookup(ctx, h)
			mu.Lock()
			answers[h] = answer{a, err}
			mu.Unlock()
		}()
	}
	wg.Wait()
	return nft.ResolveAgentTargets(ctx, rules, func(_ context.Context, host string) ([]netip.Addr, error) {
		a := answers[host]
		return a.addrs, a.err
	})
}

// useEndpoint は、prepareApply で引いたエンドポイントを控えに入れる。引けなかったら、控えたアドレスを
// 使い続け、理由が変わったときだけ 1 行出す。
func (d *kernelDataplane) useEndpoint(p *kernelPrepared) {
	if !p.tried {
		return
	}
	d.epMu.Lock()
	defer d.epMu.Unlock()
	if p.endpointEr != nil {
		if d.endpointEr == nil || d.endpointEr.Error() != p.endpointEr.Error() {
			log.Printf("kernel mode: cannot resolve the server endpoint %s: %v; keeping the endpoint %s has now", p.endpointOf, p.endpointEr, d.iface)
		}
		d.endpointEr = p.endpointEr
		return
	}
	d.endpoint, d.endpointOf, d.endpointEr = p.endpoint, p.endpointOf, nil
}

// resolveEndpointAddr は host:port のエンドポイントを IPv4 のアドレスに解決する。複数あれば最も小さいもの
// を使う。カーネルの WireGuard のピアは 1 つのエンドポイントしか持たないためである。
func resolveEndpointAddr(ctx context.Context, endpoint string, lookup nft.LookupFunc) (netip.AddrPort, error) {
	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	p, err := net.LookupPort("udp", port)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if !a.Unmap().Is4() {
			return netip.AddrPort{}, fmt.Errorf("%s is not an IPv4 address", a)
		}
		return netip.AddrPortFrom(a.Unmap(), uint16(p)), nil
	}
	addrs, err := lookup(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	var v4 []netip.Addr
	for _, a := range addrs {
		if a = a.Unmap(); a.Is4() {
			v4 = append(v4, a)
		}
	}
	if len(v4) == 0 {
		return netip.AddrPort{}, fmt.Errorf("%s has no IPv4 address", host)
	}
	return netip.AddrPortFrom(sortedAddrs(v4)[0], uint16(p)), nil
}

func (d *kernelDataplane) nftConfig() nft.AgentConfig {
	c := nft.AgentConfig{WGInterface: d.iface}
	if d.allow != nil {
		c.AllowTarget, c.AllowTargetSource = d.allow.Allows, allowtargets.Env
	}
	return c
}

// applyRules は wgft0 を収束させ、宛先を解決してテーブルを組み、1 つのバッチで公開する(7b.1 節から 7b.3 節)。
// wgft0 を先に収束させるのは、ピアを公開の前に置くためである(7a.3 節)。
//
// 誤りを返すのはテーブル全体の失敗(7b.3 節の 3 つ目の種類)だけで、このとき旧いテーブルと記録を残す。
// ルール単位の失敗は公開の記録の理由に載り、read が報告する。
//
// prepared は prepareApply の結果で、名前の解決を rt.mu の外で済ませてある。nil なら、ここで引く。
func (d *kernelDataplane) applyRules(gen uint64, rules []proto.AgentRule, prepared any) (string, error) {
	p, ok := prepared.(*kernelPrepared)
	if !ok || p == nil {
		p = d.prepareApply(&proto.State{WG: d.wg, Rules: rules}).(*kernelPrepared)
	}
	if p.err != nil || d.ctx.Err() != nil {
		return "", errors.New("not publishing: the agent is stopping")
	}
	d.useEndpoint(p)
	cfg, err := d.linkConfig()
	if err != nil {
		return "", err
	}
	changes, err := d.ops.ensureLink(cfg)
	if err != nil {
		if !d.converged && startupFatal(err) {
			return "", &fatalError{err: err}
		}
		return "", fmt.Errorf("converge %s: %w", d.iface, err)
	}
	if !d.converged {
		d.converged = true
	}
	if len(changes) > 0 {
		log.Printf("kernel mode: %s: %s", d.iface, strings.Join(changes, "; "))
	}

	pub := d.planWith(gen, rules, p.resolved)
	if err := d.ops.publish(pub, d.nftConfig()); err != nil {
		return "", fmt.Errorf("publish table inet %s: %w", nft.AgentTableName, err)
	}
	prev := d.pub
	d.pub = &pub
	if b, err := json.Marshal(pub); err == nil {
		d.f.KernelPublication = b
	}
	convergeAgentFlows(prev, pub)
	d.probeAll()
	return d.summary(), nil
}

// planWith は解決の結果からポートごとの DNAT を決める(7b.2 節)。解決に失敗した名前は、宣言の宛先の
// 文字列が同じ間だけ、直前に解決できたアドレスを使い続ける(2026-09-24 の所有者の決定)。使い続けるときも
// 今の許可一覧、IPv4 だけの規則、ループバックと未指定のアドレスの拒否を当てはめ直し、そのことを理由に
// 示す。一度も解決できていないルールは公開しない。
func (d *kernelDataplane) planWith(gen uint64, rules []proto.AgentRule, resolved map[string]nft.Resolution) nft.AgentPublication {
	cfg := d.nftConfig()
	pub := nft.PlanAgent(nft.AgentInput{Generation: gen, Rules: rules, Resolved: resolved}, cfg)
	byID := make(map[string]proto.AgentRule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}
	lkg := map[string]lkgEntry{}
	for i, res := range pub.Rules {
		r := byID[res.RuleID]
		host, _, err := net.SplitHostPort(r.Target)
		if err != nil {
			continue
		}
		if _, err := netip.ParseAddr(host); err == nil {
			continue
		}
		rs := resolved[host]
		if !rs.Failed() {
			if rs.Err == nil && len(rs.Addrs) > 0 {
				lkg[r.ID] = lkgEntry{target: r.Target, addrs: rs.Addrs}
			}
			continue
		}
		old, ok := d.lkg[r.ID]
		if !ok || old.target != r.Target {
			continue // 一度も解決できていない宛先は公開しない
		}
		lkg[r.ID] = old
		again := nft.PlanAgent(nft.AgentInput{Generation: gen, Rules: []proto.AgentRule{r},
			Resolved: map[string]nft.Resolution{host: {Addrs: old.addrs}}}, cfg).Rules[0]
		again.Reason = staleReason(host, rs.Err, again)
		pub.Rules[i] = again
	}
	d.lkg = lkg
	return pub
}

// staleReason は、名前の解決に失敗して直前の解決の結果を使ったルールの理由である。文言に
// "name resolution" を含め、server doctor が target_resolve_failed に分類できるようにする。
func staleReason(host string, err error, res nft.AgentRuleResult) string {
	head := fmt.Sprintf("name resolution of target host %q failed: %v", host, err)
	if len(res.Ranges) == 0 {
		return head + "; the address from the last successful resolution is not usable either: " + res.Reason
	}
	s := fmt.Sprintf("%s; still forwarding to %s from the last successful resolution", head, res.Ranges[0].Dest.Addr())
	if res.Reason != "" {
		s += "; " + res.Reason
	}
	return s
}

// probeAll は、公開した TCP のルールの宛先へ試し接続する(7b.3 節の 2 つ目の種類)。試すのは、連続する
// ポートと宛先の範囲(公開の記録の AgentRange)ごとに、その先頭のポートの 1 つだけである(2026-09-24 の
// 所有者の決定)。ユーザー空間モードはポートごとに試す。失敗は報告にだけ使い、DNAT は残す。
func (d *kernelDataplane) probeAll() {
	d.probeErr = map[string]string{}
	if d.pub == nil {
		return
	}
	type job struct {
		rule string
		dest netip.AddrPort
	}
	var jobs []job
	for _, r := range d.pub.Rules {
		if r.Proto != proto.TCP {
			continue
		}
		for _, rg := range r.Ranges {
			jobs = append(jobs, job{r.RuleID, rg.Dest})
		}
	}
	errs := make([]error, len(jobs))
	sem := make(chan struct{}, kernelProbeConcurrent)
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ctx, cancel := context.WithTimeout(d.ctx, kernelProbeTimeout)
			defer cancel()
			errs[i] = d.ops.probe(ctx, j.dest)
		}()
	}
	wg.Wait()
	for i, j := range jobs {
		if errs[i] != nil {
			if _, done := d.probeErr[j.rule]; !done {
				d.probeErr[j.rule] = fmt.Sprintf("target %s: %v", j.dest, errs[i])
			}
		}
	}
}

// summary は適用のログの 1 行に載せる要約である。
func (d *kernelDataplane) summary() string {
	published, refused := 0, 0
	for _, r := range d.pub.Rules {
		if len(r.Ranges) > 0 {
			published++
		}
		if r.Reason != "" {
			refused++
		}
	}
	return fmt.Sprintf("published table inet %s: %d rules with DNAT, %d rules with a reason", nft.AgentTableName, published, refused)
}

// refresh は 30 秒ごとの見直しである。TCP の宛先へ試し接続し直し、ip_forward を読み直す(7b.1・7b.3 節)。
func (d *kernelDataplane) refresh() {
	if !d.have {
		return
	}
	on, err := d.ops.readIPForward()
	switch {
	case err == nil && on && d.forwardErr != nil:
		log.Printf("net.ipv4.ip_forward is 1 now; rules whose target is not this host are no longer reported as errors")
		d.forwardErr = nil
	case err == nil && !on && d.forwardErr == nil:
		d.forwardErr = errors.New("net.ipv4.ip_forward is 0")
		log.Printf("warning: net.ipv4.ip_forward is 0; rules whose target is not this host are reported as errors until it is 1")
	}
	if d.forwardErr != nil {
		if l, err := d.ops.localAddrs(); err == nil {
			d.local = l
		}
	}
	d.probeAll()
}

// close はカーネルに何もしない。wgft0 とテーブルは停止の間も残し、転送を続ける(7b.4 節)。撤去は
// wgft agent teardown が行う。受け取った wg 設定と鍵だけを忘れるので、runtime は次に build を呼ぶ。
// rotate-key はこの経路で新しい鍵を渡す。直前の公開の記録と、直前に解決できたアドレスは残す。
func (d *kernelDataplane) close() {
	d.have = false
}

func (d *kernelDataplane) lastHandshake() time.Time {
	prev, _ := d.f.PreviousKey()
	st, err := d.ops.inspectLink(d.iface, d.priv, prev)
	if err != nil || !st.Ownership.Ours() {
		return time.Time{}
	}
	for _, p := range st.Peers {
		return p.LastHandshake
	}
	return time.Time{}
}

// read はインタフェースとルールの状態を 1 回ずつ読む(10.2c 節)。
func (d *kernelDataplane) read() dataplaneReading {
	var r dataplaneReading
	if !d.have {
		return r
	}
	prev, _ := d.f.PreviousKey()
	st, err := d.ops.inspectLink(d.iface, d.priv, prev)
	switch {
	case err != nil:
		r.tunnel = tunnelReading{present: d.converged, err: fmt.Errorf("read %s: %w", d.iface, err)}
	case st.Exists && st.Ownership.Ours():
		r.tunnel.present = true
		for _, p := range st.Peers {
			r.tunnel.endpoint = p.Endpoint
			r.tunnel.lastHandshake = p.LastHandshake
			r.tunnel.rxBytes, r.tunnel.txBytes = p.ReceiveBytes, p.TransmitBytes
		}
		d.epMu.Lock()
		epErr := d.endpointEr
		d.epMu.Unlock()
		if !r.tunnel.endpoint.IsValid() && epErr != nil {
			r.tunnel.err = fmt.Errorf("endpoint %s: %w", d.wg.Endpoint, epErr)
		}
	}
	if d.pub != nil {
		r.rules = d.ruleStatuses()
	}
	return r
}

// ruleStatuses は公開の記録からルールごとの状態を作る(5.2・7b.3 節)。公開できなかった理由、試し接続の
// 誤り、ip_forward の順に見る。
func (d *kernelDataplane) ruleStatuses() []proto.RuleStatus {
	out := make([]proto.RuleStatus, 0, len(d.pub.Rules))
	for _, r := range d.pub.Rules {
		s := proto.RuleStatus{ID: r.RuleID, State: proto.StatusOK}
		switch {
		case r.Reason != "":
			s.State, s.Reason = proto.StatusError, r.Reason
		case d.probeErr[r.RuleID] != "":
			s.State, s.Reason = proto.StatusError, d.probeErr[r.RuleID]
		case d.forwardErr != nil && !d.allLocal(r):
			s.State, s.Reason = proto.StatusError, d.forwardErr.Error()+"; the kernel does not forward to a target that is not this host"
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (d *kernelDataplane) allLocal(r nft.AgentRuleResult) bool {
	for _, rg := range r.Ranges {
		if !d.local[rg.Dest.Addr()] {
			return false
		}
	}
	return len(r.Ranges) > 0
}

// convergeAgentFlows は、公開の後に成立済みのフローを宣言へ収束させる(7b.4 節)。wgft0 から入って DNAT
// されたフローのうち、宣言から消えたポートと実効宛先が変わったポートのフローを消す。
//
// TODO: conntrack の収束の部品が入ったら、ここから呼ぶ。失敗は修復として残し、30 秒ごとに試し直す。
// それまでは何もしない。prev は直前に公開したテーブルの記録で、起動後の最初の公開では認証情報ファイルの
// 記録である。
var convergeAgentFlows = func(prev *nft.AgentPublication, cur nft.AgentPublication) {}

// hostAddrs はホストのすべてのインタフェースの IPv4 のアドレスである。
func hostAddrs() (map[netip.Addr]bool, error) {
	addrs, err := netlink.AddrList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}
	out := map[netip.Addr]bool{}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IPNet.IP); ok {
			out[ip.Unmap()] = true
		}
	}
	return out, nil
}

func sortedAddrs(a []netip.Addr) []netip.Addr {
	out := append([]netip.Addr(nil), a...)
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	var uniq []netip.Addr
	for i, x := range out {
		if i == 0 || x != out[i-1] {
			uniq = append(uniq, x)
		}
	}
	return uniq
}
