//go:build linux

package kernelmode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/reconcile"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/proto"
)

// Built は、このビルドがカーネルモードの dataplane を持つかどうかである(internal/agent の mode.go)。
const Built = true

// Prerequisites はカーネルモードのホストの前提を、カーネルに何も書かずに確かめる(設計文書 7b.5 節)。
// internal/agent の enterMode がモードを記録するより前、つまり登録より前に呼ぶ。テストだけが差し替える。
var Prerequisites = func() error {
	return checkKernelPrerequisites(nft.AgentTablePresent, wg.AgentWireGuardSupport)
}

// Ops はカーネルと外の世界に触れる操作である。単体テストだけが差し替える。
type Ops struct {
	EnsureLink     func(wg.AgentConfig) ([]string, error)
	InspectLink    func(iface string, current, previous wgtypes.Key) (wg.AgentState, error)
	KeyHolders     func(iface string, current, previous wgtypes.Key) ([]string, error)
	Publish        func(nft.AgentPublication, nft.AgentConfig) error
	Fingerprint    func(table string) (fp string, present bool, err error)
	Lookup         nft.LookupFunc
	Probe          func(ctx context.Context, dest netip.AddrPort) error
	ReadIPForward  func() (bool, error)
	WriteIPForward func() error
	LocalAddrs     func() (map[netip.Addr]bool, error)
	Now            func() time.Time
	SendDatagram   func(dst netip.AddrPort) error
	RouteIface     func(dst netip.Addr) (string, error)
	ConvergeFlows  func(prev []nft.AgentPublication, cur nft.AgentPublication, scope conntrack.AgentScope) (conntrack.AgentResult, error)
	// notify はカーネルの変更の通知の購読である(7b.4 節の変更の通知)。vpsd の kernel backend と同じ購読を使う
	Notify dataplane.Sensor
}

func defaultKernelOps() Ops {
	return Ops{
		EnsureLink:  wg.EnsureAgent,
		InspectLink: wg.InspectAgent,
		KeyHolders:  wg.AgentKeyHolders,
		Publish:     nft.ApplyAgent,
		Fingerprint: nft.Fingerprint,
		Lookup: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		Probe: func(ctx context.Context, dest netip.AddrPort) error {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", dest.String())
			if err != nil {
				return err
			}
			return c.Close()
		},
		ReadIPForward:  linux.ReadIPForward,
		WriteIPForward: linux.WriteIPForward,
		LocalAddrs:     hostAddrs,
		Now:            time.Now,
		SendDatagram: func(dst netip.AddrPort) error {
			c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(dst))
			if err != nil {
				return err
			}
			defer c.Close()
			_, err = c.Write([]byte{0})
			return err
		},
		RouteIface:    wg.AgentRouteInterface,
		ConvergeFlows: conntrack.ConvergeAgent,
		Notify:        linuxkernel.Notifications{},
	}
}

// kernelSessionPort は、keepalive ごとのデータグラムを送る vpsd のトンネルアドレスのポートである
// (7b.1 節のセッションの回復)。discard のポートで、応答を求めない。カーネルモードの vpsd は wg0 から入る
// 新しい接続を input で落とし、数えない。ユーザー空間モードの vpsd の netstack はこのポートで待ち受けない。
const kernelSessionPort = 9

// 名前の解決と宛先の試し接続の期限(仕様 5.2・7b.2・7b.3 節)。試し接続の 2 秒と同時に試す数の 32 は
// ユーザー空間モードの中継と同じ値である(internal/dataplane/userspace/relay)。
const (
	kernelResolveTimeout  = 10 * time.Second
	kernelProbeTimeout    = 2 * time.Second
	kernelProbeConcurrent = 32
)

// Dataplane はカーネルモードの dataplane である(仕様 7b 節)。カーネルの WireGuard インタフェースと
// table inet wgft_agent を宣言へ収束させる。エージェントのプロセスはパケットを中継しない。Close はカーネルの
// 資源を消さないので、停止の間も転送は続く(7b.4 節)。
//
// どのメソッドも、runtime が rt.mu を持った状態で呼ぶ(agentdp.Dataplane)。f は runtime と共有する認証情報
// ファイルで、ApplyRules が公開の記録を書き込み、runtime が last_state と同じ 1 回の保存で書き出す。
type Dataplane struct {
	Ops   Ops
	iface string
	allow *allowtargets.List
	f     *credentials.Credentials
	// ctx は停止で取り消される。名前の解決に使い、取り消された解決の結果では公開しない
	ctx context.Context

	have bool
	Priv wgtypes.Key
	WG   proto.WGConfig
	// server は vpsd のトンネルアドレスである。全体状態に無いので、自分のアドレスの帯の先頭とする(4 節)
	server netip.Addr
	// endpoint は直前に解決したエンドポイントであり、endpointOf はその元にした名前である(7b.1 節)。
	// 解決できていない間はゼロで、インタフェースの収束はカーネルが持つエンドポイントを残す
	//
	// この 3 つは epMu が守る。名前を引く準備(PrepareApply)が rt.mu の外で読むためである。epMu は
	// rt.mu の中からも外からも取るので、順は rt.mu -> epMu である。epMu の中では値の読み書きとログの
	// 出力だけを行う
	epMu       sync.Mutex
	endpoint   netip.AddrPort
	endpointOf string
	endpointEr error
	// declared は宣言のエンドポイントの名前である。30 秒ごとの見直しが引き直すのはこの名前で、epMu が守る
	declared string

	// converged は、このプロセスが wgft0 を一度でも収束させたかどうかである。偽の間の所有の衝突、
	// アドレス帯の重なり、前提の欠如は起動の失敗として扱う(11b 節、agentdp.FatalError)
	converged bool

	// pub は直近に公開に成功したテーブルの記録である。起動時は認証情報ファイルの記録から読む
	Pub *nft.AgentPublication
	// fp は、このプロセスが直前に公開したテーブルの指紋である(7a.3 節)。fpKnown が偽なら、まだ公開して
	// いないか読み直せなかったので、比べる基準が無い
	fp      string
	fpKnown bool
	// driftSeen は直前の見直しで見つけた食い違いの説明である。同じ食い違いが直らない間は 1 行だけ出す
	driftSeen string
	// observeErr は直前の見直しの誤りである。同じ誤りが続く間は 1 行だけ出す。repairErr と
	// resolveErr と endpointErr をつないだもので、agent doctor の check_error になる
	ObserveErr string
	// repairErr はテーブルと wgft0 の比べと修復の誤りで、30 秒ごとの見直しと通知の後の見直しの両方が
	// 書く。resolveErr は名前の解決し直しで変わった DNAT の公開の誤り、endpointErr はエンドポイントの
	// 引き直しの後の wgft0 の収束の誤りで、どちらも 30 秒ごとの見直しだけが書く。通知の後の見直しは
	// 名前もエンドポイントも扱わないので、その誤りを消さない
	repairErr, resolveErr, endpointErr string
	// gate は、公開し直しが失敗した後に、変更の通知による公開し直しの間隔を空ける(7b.4 節の変更の
	// 通知、7a.3 節の再試行)。失敗した公開もテーブルを差し替えることがあり、その差し替えの通知で
	// 公開し直すと、失敗が 1 秒に数回の間隔で繰り返されるためである。30 秒ごとの見直しは間隔を待たない
	gate reconcile.RetryGate

	// kaStop は keepalive ごとのデータグラムを送る goroutine を止める(7b.1 節)。動いていなければ nil。
	// kaUnit は keepalive の値の単位で、テストだけが短くする
	kaStop func()
	kaUnit time.Duration
	// hsValue は直前に見た最終ハンドシェイクで、hsSince はその値を見始めた時刻か、エンドポイントを
	// 最後に引いた時刻の遅い方である。ハンドシェイクが keepalive の 5 倍の間新しくならなければ、
	// 次の見直しがエンドポイントを引き直す(7b.1 節)
	hsValue time.Time
	hsSince time.Time
	// endpointStale は、次の見直しでエンドポイントを引き直すことを表す。epMu が守る
	endpointStale bool
	// routeFinding は、vpsd のトンネルアドレスへの経路が wgft0 を通らないことの直前の説明である。
	// 変わったときだけ 1 行出す
	routeFinding string

	// unconverged は、conntrack の収束が済んでいない前の公開の列である(7b.4 節)。古い順に並び、最後の
	// 要素が pub の直前の公開である。空なら、pub への収束は済んでいる。認証情報ファイルに写して
	// 再起動をまたいで残す。convergeErr は直前の収束の誤りで、変わったときだけ 1 行出す
	unconverged []nft.AgentPublication
	convergeErr string
	// save は認証情報ファイルを保存する。30 秒ごとの見直しで収束が済んだときに、列を消した記録を書く
	save func() error
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

// runtime はこれらの任意の interface を型アサーションだけで探し、満たさなければ黙ってその処理を
// 飛ばす(internal/agent/agentdp)。メソッドの形がずれたらコンパイルで気付けるよう、ここで固定する。
var (
	_ agentdp.Preparer       = (*Dataplane)(nil)
	_ agentdp.WGChecker      = (*Dataplane)(nil)
	_ agentdp.Observer       = (*Dataplane)(nil)
	_ agentdp.Sensed         = (*Dataplane)(nil)
	_ agentdp.StartupChecker = (*Dataplane)(nil)
	_ agentdp.KernelDoctor   = (*Dataplane)(nil)
)

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

// New はカーネルモードの dataplane を作る。カーネルには何も書かない。
func New(ctx context.Context, iface string, allow *allowtargets.List, f *credentials.Credentials, save func() error) (agentdp.Dataplane, error) {
	return NewWithOps(ctx, iface, allow, f, save, defaultKernelOps()), nil
}

// NewWithOps は、カーネルと名前解決への操作 ops を受け取って New と同じ dataplane を組む。本番の経路は
// New が defaultKernelOps で呼ぶ。試験は偽物の ops を渡す。
func NewWithOps(ctx context.Context, iface string, allow *allowtargets.List, f *credentials.Credentials, save func() error, ops Ops) *Dataplane {
	d := &Dataplane{Ops: ops, iface: iface, allow: allow, f: f, ctx: ctx, save: save,
		lkg: map[string]lkgEntry{}, probeErr: map[string]string{}}
	d.loadRecord()
	return d
}

// loadRecord は認証情報ファイルの公開の記録を読み、直前に公開したテーブルと、ルールごとの直前に
// 解決できたアドレスの元にする。読めない記録は無いものとして扱う。記録は診断と比較のためのもので、
// 起動を止める理由にはしない。
func (d *Dataplane) loadRecord() {
	if len(d.f.KernelUnconverged) > 0 {
		if err := json.Unmarshal(d.f.KernelUnconverged, &d.unconverged); err != nil {
			log.Printf("kernel mode: ignoring the unreadable list of unconverged publications in the credentials file: %v", err)
			d.unconverged = nil
		}
	}
	if len(d.f.KernelPublication) == 0 {
		return
	}
	var pub nft.AgentPublication
	if err := json.Unmarshal(d.f.KernelPublication, &pub); err != nil {
		log.Printf("kernel mode: ignoring the unreadable publication record in the credentials file: %v", err)
		return
	}
	d.Pub = &pub
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

// Build は wg 設定 w を受け取る。検証は CheckWG に任せ、カーネルには何も書かない。wgft0 を収束させるのは
// ApplyRules である。
func (d *Dataplane) Build(priv wgtypes.Key, w proto.WGConfig) (bool, error) {
	addr, err := d.CheckWG(w)
	if err != nil {
		return false, err
	}
	d.Priv, d.WG, d.have = priv, w, true
	d.server = agentServerAddress(addr)
	d.epMu.Lock()
	d.declared = w.Endpoint
	d.epMu.Unlock()
	d.startKeepalive()
	return true, nil
}

// CheckWG は、server から届いた wg 設定 w を、カーネルに書く前に検証する(設計文書 7b.1・11 節)。
// server が配る wg 設定のうち、エージェントがホストに書く前に確かめる値の検証はここに集める。runtime は
// 今のトンネルを閉じる前にこれを呼び(agentdp.WGChecker)、Build も同じ検証を通す。返すのは wgft0 のアドレスで
// ある。
//
// トンネルのアドレスは、認証情報ファイルに記録した登録時のアドレスと照合する。VPS を奪った攻撃者が
// LAN の帯より細かい帯を配ると、wgft0 の接続経路が LAN の経路に勝ち、ホストから LAN へ向かう通信の
// 一部がトンネルへ入るためである。正規の運用では、登録の後にエージェントのアドレスは変わらない。
// 記録は書き換えない。記録するのは適用が済んだ後の runtime である(internal/agent の finishApplyLocked)。
func (d *Dataplane) CheckWG(w proto.WGConfig) (netip.Prefix, error) {
	if _, err := wgtypes.ParseKey(w.ServerPubkey); err != nil {
		return netip.Prefix{}, fmt.Errorf("server_pubkey: %w", err)
	}
	addr, err := netip.ParsePrefix(w.Address)
	if err != nil || !addr.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("address %q is not an IPv4 CIDR", w.Address)
	}
	if err := d.f.CheckTunnelAddress(addr); err != nil {
		return netip.Prefix{}, fmt.Errorf("%w; kernel mode refuses it and leaves %s, its address and its routes as they are, "+
			"since an address the agent was not registered with could route part of this host's LAN into the tunnel; "+
			"the server moves an agent to a new address only when the agent registers again, after `wgft server teardown --purge` on the VPS, "+
			"so register this agent again with a new join string to take a new address, and otherwise find out who changed the server", err, d.iface)
	}
	if w.MTU <= 0 {
		return netip.Prefix{}, fmt.Errorf("mtu %d is not positive", w.MTU)
	}
	if w.Keepalive < 0 || w.Keepalive > 65535 {
		return netip.Prefix{}, fmt.Errorf("keepalive %d is not between 0 and 65535", w.Keepalive)
	}
	return addr, nil
}

func (d *Dataplane) Built() bool { return d.have }

// LinkConfig は wgft0 の宣言である。
func (d *Dataplane) LinkConfig() (wg.AgentConfig, error) {
	prev, err := d.f.PreviousKey()
	if err != nil {
		return wg.AgentConfig{}, err
	}
	serverPub, _ := wgtypes.ParseKey(d.WG.ServerPubkey)
	addr, _ := netip.ParsePrefix(d.WG.Address)
	return wg.AgentConfig{
		Interface: d.iface, PrivateKey: d.Priv, PreviousKey: prev, Address: addr, MTU: d.WG.MTU,
		Server: wg.ServerPeer{PublicKey: serverPub, Address: d.server, Endpoint: d.cachedEndpoint(),
			Keepalive: time.Duration(d.WG.Keepalive) * time.Second},
	}, nil
}

func (d *Dataplane) nftConfig() nft.AgentConfig {
	c := nft.AgentConfig{WGInterface: d.iface}
	if d.allow != nil {
		c.AllowTarget, c.AllowTargetSource = d.allow.Allows, allowtargets.Env
	}
	return c
}

// Close はカーネルに何もしない。wgft0 とテーブルは停止の間も残し、転送を続ける(7b.4 節)。撤去は
// wgft agent teardown が行う。受け取った wg 設定と鍵だけを忘れるので、runtime は次に Build を呼ぶ。
// rotate-key はこの経路で新しい鍵を渡す。直前の公開の記録と、直前に解決できたアドレスは残す。
func (d *Dataplane) Close() {
	d.have = false
	d.stopKeepalive()
}

func (d *Dataplane) LastHandshake() time.Time {
	prev, _ := d.f.PreviousKey()
	st, err := d.Ops.InspectLink(d.iface, d.Priv, prev)
	if err != nil || !st.Ownership.Ours() {
		return time.Time{}
	}
	for _, p := range st.Peers {
		return p.LastHandshake
	}
	return time.Time{}
}
