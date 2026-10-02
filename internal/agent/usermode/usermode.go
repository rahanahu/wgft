// Package usermode はエージェントのユーザー空間モードの dataplane を持つ(設計文書 7a.7 節)。
// wireguard-go と netstack のトンネルと、その上の中継を包み、internal/agent/agentdp の Dataplane を
// 満たす。internal/agent の下では agentdp と allowtargets だけを import する。
//
// 本番のコードが package の外から使ってよい名前は New だけである。実行時の状態は New の結果を
// agentdp.Dataplane として持ち、型 Dataplane を名指さず、そのメソッドも直接は呼ばない。ほかの公開した
// 名前は internal/agent のテストのための口であり、フィールド Allow、Limits、Tun、Relay、変数
// NewTunnel、ReadTunnelStatus、関数 RuleStatuses、メソッド RelayOptions が当たる。
// internal/dataplane/deps_test.go の TestAgentModeTestSeamsStayInTests がこれを検査する。
package usermode

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/netip"
	"sort"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// udpTimeoutStreamMaxSeconds は wg.udp_timeout_stream として受け入れる上限。VPS は
// nf_conntrack_udp_timeout_stream を 32 bit の int として持つ(internal/platform/linux の
// ReadUDPTimeouts)ので、正規の VPS が読んで送る値はこれを超えない。math.MaxInt64/int64(time.Second)
// (秒を time.Duration の int64 ナノ秒に変えたときに桁あふれする境目、約 292 年)より十分小さい
const udpTimeoutStreamMaxSeconds = math.MaxInt32

// secondsToDuration は、VPS から届く全体状態の秒の値(wg.udp_timeout_stream、wg.keepalive)を
// time.Duration に変える。0 以下、max を超える値、あるいは max 以下でも変換の結果が 1 秒に届かない
// 値(max の選び方が正しければ起こらないはずだが、2 段目の守りとして確かめる)は、奪われた VPS が
// 送りうる桁あふれする値(例:20211507185753197 は `* time.Second` で 512ns に巻き戻る)への備えとして
// def に落とす。桁あふれが作る極めて短い間隔は、無通信の掃除の goroutine や keepalive の ticker を
// 回し続けて家のホストの CPU を使い切る。0 は値を送らない旧い server の正当な値なので、黙って def に
// 落とす。0 以外で拒んだときは、Build のときにしか呼ばれないこの経路から英語で 1 行を記録する
func secondsToDuration(name string, seconds, max int, def time.Duration) time.Duration {
	if seconds == 0 {
		return def
	}
	if seconds > 0 && seconds <= max {
		if d := time.Duration(seconds) * time.Second; d >= time.Second {
			return d
		}
	}
	log.Printf("wg.%s %d is out of the accepted range 1-%d seconds; using the default %v instead", name, seconds, max, def)
	return def
}

// Dataplane はユーザー空間モードの dataplane である(仕様 7 節)。wireguard-go と netstack の
// トンネル(internal/dataplane/userspace/tunnel)と、その上の中継(internal/dataplane/userspace/relay)
// を包む。中継はトンネルの netstack で待ち受けるので、2 つは一緒に立ち、一緒に閉じる。
type Dataplane struct {
	// Allow は宛先の許可一覧(仕様 7 節、WGFT_AGENT_ALLOW_TARGETS)。nil なら制限しない。
	// newRuntime が opts.AllowTargets から渡すので、doctor が示す一覧と同じ値である
	Allow *allowtargets.List
	// Limits は同時フロー数のプロセス全体の予算(仕様 7 節)。ゼロ値は既定値
	Limits resource.Limits
	// unicast はブロードキャストとマルチキャストの宛先の判定である(仕様 7 節)。New がこのホストの
	// インタフェースの一覧を読む判定を置く。nil なら一覧に依らない判定だけを行う
	unicast *allowtargets.Unicast

	// Tun と Relay は今のトンネルと中継である。どちらも Build が作り、Close が閉じて nil に戻す
	Tun       *tunnel.Tunnel
	tunCancel context.CancelFunc
	Relay     *relay.Manager
}

// New は何も立てていないユーザー空間モードの dataplane を作る。
func New(allow *allowtargets.List, limits resource.Limits) *Dataplane {
	return &Dataplane{Allow: allow, Limits: limits, unicast: allowtargets.NewUnicast(nil, nil)}
}

// NewTunnel はトンネルを作る。値は tunnel.New で、テストだけが作成の失敗を模すために差し替える。
var NewTunnel = tunnel.New

// ReadTunnelStatus はトンネルの状態を 1 回読む。値は tunnel.Tunnel.Status で、テストだけが
// 読みの回数と、1 つの応答に混ざる時点を確かめるために差し替える。
var ReadTunnelStatus = (*tunnel.Tunnel).Status

// Build はトンネルを立て、その netstack の上に中継を作る(仕様 7 節)。リスナーは開かないので、
// 呼び出し側が続けて ApplyRules を呼ぶ。
func (d *Dataplane) Build(priv wgtypes.Key, wg proto.WGConfig) (retryable bool, err error) {
	cfg, err := tunnelConfig(priv, wg)
	if err != nil {
		return false, err
	}
	tun, err := NewTunnel(cfg)
	if err != nil {
		return true, err // 資源の不足など、環境による失敗
	}
	ctx, cancel := context.WithCancel(context.Background())
	go tun.Run(ctx)
	d.Tun, d.tunCancel = tun, cancel
	d.Relay = relay.New(tun, d.RelayOptions(wg))
	return true, nil
}

func (d *Dataplane) Built() bool { return d.Tun != nil }

// ApplyRules はリスナーを宣言に合わせる。変わったものだけを開閉する(仕様 5.2, 7 節)。
// 開けなかったリスナーはルールの error として Read に現れ、Refresh が開き直す。
func (d *Dataplane) ApplyRules(_ uint64, rules []proto.AgentRule, _ any) (string, error) {
	acts := d.Relay.Apply(relay.DesiredFromRules(rules))
	return fmt.Sprintf("%d actions, %d listeners", len(acts), len(d.Relay.Status())), nil
}

func (d *Dataplane) Refresh() {
	if d.Relay != nil {
		d.Relay.Retry()
	}
}

// Close は中継を閉じてからトンネルを閉じる。閉じるのが先なので、古い device と netstack、
// その goroutine は、次の Build が新しいものを作る前に必ず片付く。
func (d *Dataplane) Close() {
	if d.Relay != nil {
		d.Relay.Close()
		d.Relay = nil
	}
	if d.tunCancel != nil {
		d.tunCancel()
		d.tunCancel = nil
	}
	if d.Tun != nil {
		d.Tun.Close()
		d.Tun = nil
	}
}

// LastHandshake が読むのは今の device なので、ゼロでない値は必ず今のトンネルのものである。
func (d *Dataplane) LastHandshake() time.Time {
	return d.Tun.Status().LastHandshake
}

// Read はトンネルの状態と中継の状態を 1 回ずつ読む。ルールごとの状態と doctor のリスナーの集計は、
// 同じ Manager.Status の読みから作る(設計文書 10.2c 節)。
func (d *Dataplane) Read() agentdp.Reading {
	var r agentdp.Reading
	if d.Tun != nil {
		ts := ReadTunnelStatus(d.Tun)
		r.Tunnel = agentdp.TunnelReading{
			Present:       true,
			Endpoint:      ts.Endpoint,
			LastHandshake: ts.LastHandshake,
			RxBytes:       ts.RxBytes,
			TxBytes:       ts.TxBytes,
			Err:           ts.Err,
		}
		bufs := d.Tun.SocketBuffers()
		r.Tunnel.SocketBuffers = &bufs
		r.Tunnel.UDPAccounting = &agentdp.UDPAccountingReading{Fault: d.Tun.UDPReceiveFault()}
	}
	if d.Relay != nil {
		sts := d.Relay.Status()
		r.Rules = RuleStatuses(sts)
		r.Relay = &agentdp.RelayReading{Listeners: sts, TCP: d.Relay.TCPPool(), UDP: d.Relay.UDPPool()}
	}
	return r
}

// RelayOptions は中継の調整値を作る。ブロードキャストとマルチキャストの宛先の拒否は常に渡し、
// 宛先の許可一覧はあれば渡す。どちらも中継が宛先へ接続するときに使う判定である(仕様 7 節)。
// 一覧が無ければ、中継はホスト名の宛先を一覧の導入前と同じく名前のまま接続し、拒否は接続の Control が
// 解決した各アドレスに当てる。
func (d *Dataplane) RelayOptions(wg proto.WGConfig) relay.Options {
	o := relay.Options{
		UDPIdleTimeout: secondsToDuration("udp_timeout_stream", wg.UDPTimeoutStream, udpTimeoutStreamMaxSeconds, 120*time.Second),
		Limits:         d.Limits,
		RefuseTarget:   d.unicast.Refuse,
	}
	if d.Allow != nil {
		o.AllowTarget = d.Allow.Allows
		o.AllowTargetSource = allowtargets.Env
	}
	return o
}

// RuleStatuses はリスナーの状態からルールごとの状態を合成する(仕様 5.2 節)。1 つでも error なら
// そのルールは error である。ハートビートと doctor が同じ判定を使うので、この 1 か所に置く
// (設計文書 10.2c 節)。呼び出し側は Manager.Status の結果を 1 回だけ読んで渡す。
func RuleStatuses(sts []relay.Status) []proto.RuleStatus {
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
		Keepalive: secondsToDuration("keepalive", w.Keepalive, agentdp.KeepaliveMaxSeconds, 25*time.Second),
	}, nil
}
