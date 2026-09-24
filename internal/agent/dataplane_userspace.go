package agent

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// userspaceDataplane はユーザー空間モードの dataplane である(仕様 7 節)。wireguard-go と netstack の
// トンネル(internal/dataplane/userspace/tunnel)と、その上の中継(internal/dataplane/userspace/relay)
// を包む。中継はトンネルの netstack で待ち受けるので、2 つは一緒に立ち、一緒に閉じる。
type userspaceDataplane struct {
	// allow は宛先の許可一覧(仕様 7 節、WGFT_AGENT_ALLOW_TARGETS)。nil なら制限しない
	allow *allowtargets.List
	// limits は同時フロー数のプロセス全体の予算(仕様 7 節)。ゼロ値は既定値
	limits resource.Limits

	tun       *tunnel.Tunnel
	tunCancel context.CancelFunc
	rl        *relay.Manager
}

// newUserspaceDataplane は何も立てていないユーザー空間モードの dataplane を作る。
func newUserspaceDataplane(allow *allowtargets.List, limits resource.Limits) *userspaceDataplane {
	return &userspaceDataplane{allow: allow, limits: limits}
}

// newTunnel はトンネルを作る。値は tunnel.New で、テストだけが作成の失敗を模すために差し替える。
var newTunnel = tunnel.New

// readTunnelStatus はトンネルの状態を 1 回読む。値は tunnel.Tunnel.Status で、テストだけが
// 読みの回数と、1 つの応答に混ざる時点を確かめるために差し替える。
var readTunnelStatus = (*tunnel.Tunnel).Status

// build はトンネルを立て、その netstack の上に中継を作る(仕様 7 節)。リスナーは開かないので、
// 呼び出し側が続けて applyRules を呼ぶ。
func (d *userspaceDataplane) build(priv wgtypes.Key, wg proto.WGConfig) (retryable bool, err error) {
	cfg, err := tunnelConfig(priv, wg)
	if err != nil {
		return false, err
	}
	tun, err := newTunnel(cfg)
	if err != nil {
		return true, err // 資源の不足など、環境による失敗
	}
	ctx, cancel := context.WithCancel(context.Background())
	go tun.Run(ctx)
	d.tun, d.tunCancel = tun, cancel
	d.rl = relay.New(tun, d.relayOptions(wg))
	return true, nil
}

func (d *userspaceDataplane) built() bool { return d.tun != nil }

// applyRules はリスナーを宣言に合わせる。変わったものだけを開閉する(仕様 5.2, 7 節)。
// 開けなかったリスナーはルールの error として read に現れ、refresh が開き直す。
func (d *userspaceDataplane) applyRules(rules []proto.AgentRule) (string, error) {
	acts := d.rl.Apply(relay.DesiredFromRules(rules))
	return fmt.Sprintf("%d actions, %d listeners", len(acts), len(d.rl.Status())), nil
}

func (d *userspaceDataplane) refresh() {
	if d.rl != nil {
		d.rl.Retry()
	}
}

// close は中継を閉じてからトンネルを閉じる。閉じるのが先なので、古い device と netstack、
// その goroutine は、次の build が新しいものを作る前に必ず片付く。
func (d *userspaceDataplane) close() {
	if d.rl != nil {
		d.rl.Close()
		d.rl = nil
	}
	if d.tunCancel != nil {
		d.tunCancel()
		d.tunCancel = nil
	}
	if d.tun != nil {
		d.tun.Close()
		d.tun = nil
	}
}

// lastHandshake が読むのは今の device なので、ゼロでない値は必ず今のトンネルのものである。
func (d *userspaceDataplane) lastHandshake() time.Time {
	return d.tun.Status().LastHandshake
}

// read はトンネルの状態と中継の状態を 1 回ずつ読む。ルールごとの状態と doctor のリスナーの集計は、
// 同じ Manager.Status の読みから作る(設計文書 10.2c 節)。
func (d *userspaceDataplane) read() dataplaneReading {
	var r dataplaneReading
	if d.tun != nil {
		ts := readTunnelStatus(d.tun)
		r.tunnel = tunnelReading{
			present:       true,
			endpoint:      ts.Endpoint,
			lastHandshake: ts.LastHandshake,
			rxBytes:       ts.RxBytes,
			txBytes:       ts.TxBytes,
			err:           ts.Err,
		}
	}
	if d.rl != nil {
		sts := d.rl.Status()
		r.rules = ruleStatuses(sts)
		r.relay = &relayReading{listeners: sts, tcp: d.rl.TCPPool(), udp: d.rl.UDPPool()}
	}
	return r
}

// relayOptions は中継の調整値を作る。宛先の許可一覧があれば、中継が宛先へ接続するときに
// 使う判定として渡す(仕様 7 節)。一覧が無ければ渡さないので、中継の挙動は一覧の導入前と同じになる。
func (d *userspaceDataplane) relayOptions(wg proto.WGConfig) relay.Options {
	o := relay.Options{
		UDPIdleTimeout: time.Duration(wg.UDPTimeoutStream) * time.Second,
		Limits:         d.limits,
	}
	if d.allow != nil {
		o.AllowTarget = d.allow.Allows
		o.AllowTargetSource = allowtargets.Env
	}
	return o
}

// ruleStatuses はリスナーの状態からルールごとの状態を合成する(仕様 5.2 節)。1 つでも error なら
// そのルールは error である。ハートビートと doctor が同じ判定を使うので、この 1 か所に置く
// (設計文書 10.2c 節)。呼び出し側は Manager.Status の結果を 1 回だけ読んで渡す。
func ruleStatuses(sts []relay.Status) []proto.RuleStatus {
	byRule := map[string]*proto.RuleStatus{}
	for _, s := range sts {
		r := byRule[s.RuleID]
		if r == nil {
			r = &proto.RuleStatus{ID: s.RuleID, State: proto.StatusOK}
			byRule[s.RuleID] = r
		}
		if s.Err != nil && r.State == proto.StatusOK {
			r.State, r.Reason = proto.StatusError, fmt.Sprintf("%s: %v", s.Key, s.Err)
		}
	}
	out := make([]proto.RuleStatus, 0, len(byRule))
	for _, r := range byRule {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// tunnelConfig は全体状態の wg 節からトンネルの宣言を作る。
// vpsd のアドレスは全体状態にないので、自分のアドレスの帯の先頭(10.200.0.1)とする(仕様 4 節)。
func tunnelConfig(priv wgtypes.Key, w proto.WGConfig) (tunnel.Config, error) {
	serverPub, err := wgtypes.ParseKey(w.ServerPubkey)
	if err != nil {
		return tunnel.Config{}, fmt.Errorf("server_pubkey: %w", err)
	}
	addr, err := netip.ParsePrefix(w.Address)
	if err != nil || !addr.Addr().Is4() {
		return tunnel.Config{}, fmt.Errorf("address %q is not an IPv4 CIDR", w.Address)
	}
	server := addr.Masked().Addr().Next()
	return tunnel.Config{
		PrivateKey: priv, ServerPublicKey: serverPub, Endpoint: w.Endpoint,
		Address: addr.Addr(), ServerAddress: server, MTU: w.MTU,
		Keepalive: time.Duration(w.Keepalive) * time.Second,
	}, nil
}
