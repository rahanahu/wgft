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
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/lograte"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/reconcile"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/proto"
)

// kernelModeBuilt は、このビルドがカーネルモードの dataplane を持つかどうかである(mode.go)。
const kernelModeBuilt = true

// kernelPrerequisites はカーネルモードのホストの前提を、カーネルに何も書かずに確かめる(設計文書 7b.5 節)。
// enterMode がモードを記録するより前、つまり登録より前に呼ぶ。テストだけが差し替える。
var kernelPrerequisites = func() error {
	return checkKernelPrerequisites(nft.AgentTablePresent, wg.AgentWireGuardSupport)
}

// checkKernelPrerequisites は、CAP_NET_ADMIN と WireGuard のモジュールの 2 つの前提を順に確かめる。
// CAP_NET_ADMIN は、実際にそれを要する読み出し(nftables のテーブルの一覧)で確かめる。CapEff の
// ビットではなく読み出しを使うのは、ネットワーク名前空間を持つ利用者名前空間での権限を、後の
// 書き込みと同じ判定でカーネルに問うためである。
//
// 前提の欠如と言い切れる誤りだけを拒否にする。権限の誤り(EPERM)は種別 prerequisite の CAP_NET_ADMIN、
// WireGuard の汎用 netlink のファミリが無いことは種別 prerequisite の wireguard module である。
// それ以外の誤りでは起動を止めない。この検査が無かったときと同じく、後の最初の収束が分類する。
func checkKernelPrerequisites(readTables func() (bool, error), wireGuard func() error) error {
	if _, err := readTables(); errors.Is(err, os.ErrPermission) {
		return wg.AgentPrivilegeRefusal(err)
	}
	if err := wireGuard(); startup.Of(err) != nil {
		return err
	}
	return nil
}

// kernelOps はカーネルと外の世界に触れる操作である。単体テストだけが差し替える。
type kernelOps struct {
	ensureLink     func(wg.AgentConfig) ([]string, error)
	inspectLink    func(iface string, current, previous wgtypes.Key) (wg.AgentState, error)
	keyHolders     func(iface string, current, previous wgtypes.Key) ([]string, error)
	publish        func(nft.AgentPublication, nft.AgentConfig) error
	fingerprint    func(table string) (fp string, present bool, err error)
	lookup         nft.LookupFunc
	probe          func(ctx context.Context, dest netip.AddrPort) error
	readIPForward  func() (bool, error)
	writeIPForward func() error
	localAddrs     func() (map[netip.Addr]bool, error)
	now            func() time.Time
	sendDatagram   func(dst netip.AddrPort) error
	routeIface     func(dst netip.Addr) (string, error)
	convergeFlows  func(prev []nft.AgentPublication, cur nft.AgentPublication, scope conntrack.AgentScope) (conntrack.AgentResult, error)
	// notify はカーネルの変更の通知の購読である(7b.4 節の変更の通知)。vpsd の kernel backend と同じ購読を使う
	notify dataplane.Sensor
}

func defaultKernelOps() kernelOps {
	return kernelOps{
		ensureLink:  wg.EnsureAgent,
		inspectLink: wg.InspectAgent,
		keyHolders:  wg.AgentKeyHolders,
		publish:     nft.ApplyAgent,
		fingerprint: nft.Fingerprint,
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
		sendDatagram: func(dst netip.AddrPort) error {
			c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(dst))
			if err != nil {
				return err
			}
			defer c.Close()
			_, err = c.Write([]byte{0})
			return err
		},
		routeIface:    wg.AgentRouteInterface,
		convergeFlows: conntrack.ConvergeAgent,
		notify:        linuxkernel.Notifications{},
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
	// declared は宣言のエンドポイントの名前である。30 秒ごとの見直しが引き直すのはこの名前で、epMu が守る
	declared string

	// converged は、このプロセスが wgft0 を一度でも収束させたかどうかである。偽の間の所有の衝突、
	// アドレス帯の重なり、前提の欠如は起動の失敗として扱う(11b 節、fatalError)
	converged bool

	// pub は直近に公開に成功したテーブルの記録である。起動時は認証情報ファイルの記録から読む
	pub *nft.AgentPublication
	// fp は、このプロセスが直前に公開したテーブルの指紋である(7a.3 節)。fpKnown が偽なら、まだ公開して
	// いないか読み直せなかったので、比べる基準が無い
	fp      string
	fpKnown bool
	// driftSeen は直前の見直しで見つけた食い違いの説明である。同じ食い違いが直らない間は 1 行だけ出す
	driftSeen string
	// observeErr は直前の見直しの誤りである。同じ誤りが続く間は 1 行だけ出す。repairErr と endpointErr を
	// つないだもので、agent doctor の check_error になる
	observeErr string
	// repairErr はテーブルと wgft0 の比べと修復の誤りで、30 秒ごとの見直しと通知の後の見直しの両方が
	// 書く。endpointErr はエンドポイントの引き直しの後の wgft0 の収束の誤りで、30 秒ごとの見直しだけが
	// 書く。通知の後の見直しはエンドポイントを扱わないので、その誤りを消さない
	repairErr, endpointErr string
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
func newKernelDataplane(ctx context.Context, iface string, allow *allowtargets.List, f *credentials.Credentials, save func() error) (agentDataplane, error) {
	d := &kernelDataplane{ops: defaultKernelOps(), iface: iface, allow: allow, f: f, ctx: ctx, save: save,
		lkg: map[string]lkgEntry{}, probeErr: map[string]string{}}
	d.loadRecord()
	return d, nil
}

// loadRecord は認証情報ファイルの公開の記録を読み、直前に公開したテーブルと、ルールごとの直前に
// 解決できたアドレスの元にする。読めない記録は無いものとして扱う。記録は診断と比較のためのもので、
// 起動を止める理由にはしない。
func (d *kernelDataplane) loadRecord() {
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

// build は wg 設定 w を受け取る。検証は checkWG に任せ、カーネルには何も書かない。wgft0 を収束させるのは
// applyRules である。
func (d *kernelDataplane) build(priv wgtypes.Key, w proto.WGConfig) (bool, error) {
	addr, err := d.checkWG(w)
	if err != nil {
		return false, err
	}
	d.priv, d.wg, d.have = priv, w, true
	d.server = agentServerAddress(addr)
	d.epMu.Lock()
	d.declared = w.Endpoint
	d.epMu.Unlock()
	d.startKeepalive()
	return true, nil
}

// checkWG は、server から届いた wg 設定 w を、カーネルに書く前に検証する(設計文書 7b.1・11 節)。
// server が配る wg 設定のうち、エージェントがホストに書く前に確かめる値の検証はここに集める。runtime は
// 今のトンネルを閉じる前にこれを呼び(wgChecker)、build も同じ検証を通す。返すのは wgft0 のアドレスで
// ある。
//
// トンネルのアドレスは、認証情報ファイルに記録した登録時のアドレスと照合する。VPS を奪った攻撃者が
// LAN の帯より細かい帯を配ると、wgft0 の接続経路が LAN の経路に勝ち、ホストから LAN へ向かう通信の
// 一部がトンネルへ入るためである。正規の運用では、登録の後にエージェントのアドレスは変わらない。
// 記録は書き換えない。記録するのは適用が済んだ後の runtime である(finishApplyLocked)。
func (d *kernelDataplane) checkWG(w proto.WGConfig) (netip.Prefix, error) {
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

// startKeepalive は、keepalive ごとに wgft0 を通して vpsd のトンネルアドレスへ小さな UDP のデータ
// グラムを 1 つ送る goroutine を立て直す(7b.1 節のセッションの回復)。keepalive のパケットだけでは、
// vpsd の側がセッションを失ったときに新しいハンドシェイクが鍵の寿命まで始まらない。データを送れば、
// 応答が無いまま 15 秒たったところで WireGuard がハンドシェイクをやり直す。応答は要らない。
// keepalive が 0 なら送らない。goroutine は ops と、立てたときの宛先と間隔だけを使い、排他を取らない。
// 送れない間は、理由が変わったときだけ 1 行出す。ピアにエンドポイントが無い間(名前がまだ解決できて
// いないとき)は、そのことを出す。
func (d *kernelDataplane) startKeepalive() {
	d.stopKeepalive()
	if d.wg.Keepalive <= 0 {
		return
	}
	unit := d.kaUnit
	if unit <= 0 {
		unit = time.Second
	}
	every := time.Duration(d.wg.Keepalive) * unit
	dst := netip.AddrPortFrom(d.server, kernelSessionPort)
	send, iface := d.ops.sendDatagram, d.iface
	ctx, cancel := context.WithCancel(d.ctx)
	d.kaStop = cancel
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		last := ""
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			err := send(dst)
			reason := sendFailure(err)
			if reason == last {
				continue
			}
			switch {
			case err == nil:
				log.Printf("kernel mode: the keepalive datagram to %s is sent again", dst)
			case errors.Is(err, syscall.EDESTADDRREQ):
				log.Printf("kernel mode: cannot send the keepalive datagram to %s yet: the server peer on %s has no endpoint, as when the endpoint name has not resolved; it is sent once the peer has one", dst, iface)
			default:
				log.Printf("kernel mode: cannot send the keepalive datagram to %s: %s; until this works, a session the server lost may recover only when its keys expire", dst, reason)
			}
			last = reason
		}
	}()
}

// sendFailure は、データグラムを送れなかった理由を、ログを出し直すかの比べに使う形にする。送れたら空で
// ある。net の書き込みの誤りは送信元のポートを含み、送るたびに違うので、下層の errno があればそれで
// 比べる。
func sendFailure(err error) string {
	if err == nil {
		return ""
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

func (d *kernelDataplane) stopKeepalive() {
	if d.kaStop != nil {
		d.kaStop()
		d.kaStop = nil
	}
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
			// 誤りの文面はルールの理由になり、見直しは理由の変化で記録を書き換える(7b.2 節)。問い合わせ
			// ごとに変わる送信元のポートを除き、同じ誤りを 30 秒ごとの変化にしない
			answers[h] = answer{a, lograte.StableError(err)}
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
	d.checkRoute()

	pub := d.planWith(gen, rules, p.resolved)
	if err := d.publish(pub); err != nil {
		return "", err
	}
	d.probeAll()
	return d.summary(), nil
}

// publish はテーブルを 1 つのバッチで差し替え、成功したら記録を認証情報ファイルへ写し、差し替えた
// テーブルの指紋を読み直し、成立済みのフローを収束させる(7b.4 節、7a.3 節の実際の状態への収束)。
// 失敗したら旧いテーブルと記録を残す。認証情報ファイルの保存は呼び出し側が行う。成否は gate に記録し、
// 通知による公開し直しの間隔を決める。見直し(compare)の wgft0 の収束の失敗も gate に記録する。
// 全体状態の適用の失敗は、試し直しを待つ間の通知の後の見直しを runtime が止めるので、間隔に関わらない。
// エンドポイントの引き直しの後の収束の失敗は記録しない。通知の後の見直しはエンドポイントを比べないので、
// 記録するとテーブルの修復だけを遅らせる。
func (d *kernelDataplane) publish(pub nft.AgentPublication) error {
	if err := d.ops.publish(pub, d.nftConfig()); err != nil {
		d.gate.Failed()
		return fmt.Errorf("publish table inet %s: %w", nft.AgentTableName, err)
	}
	d.gate.Succeeded()
	prev := d.pub
	d.pub = &pub
	if b, err := json.Marshal(pub); err == nil {
		d.f.KernelPublication = b
	}
	// 指紋を読めなければ、比べる基準が分からない。次の見直しは食い違いとして公開し直し、読み直す
	// (7a.3 節の指紋の読み直しの失敗と同じ扱い)
	fp, present, err := d.ops.fingerprint(nft.AgentTableName)
	d.fp, d.fpKnown = fp, err == nil && present
	if prev != nil {
		d.unconverged = appendUnconverged(d.unconverged, *prev)
	}
	d.convergeFlows()
	return nil
}

// maxUnconverged は、収束が済んでいない前の公開を残す数の上限である。収束が失敗し続ける間に公開が
// 続いても、認証情報ファイルが大きくならないようにする。上限を超えた古い公開のフローは見分けられなく
// なり、残る。
const maxUnconverged = 32

// appendUnconverged は、収束が済んでいない前の公開の列に p を加える。直前の要素と DNAT も宣言も同じなら、
// 収束の判定に使う中身が変わらないので、置き換えて並びを伸ばさない。DNAT が同じでも宣言の宛先の文字列が
// 違う公開は畳まない。収束は宣言の宛先の変化で宛先の変更を見分けるので、IP リテラルへ変えてから同じ
// ホスト名へ戻した中間の公開を落とすと、宛先の変更を見落とす(7b.4 節)。
func appendUnconverged(list []nft.AgentPublication, p nft.AgentPublication) []nft.AgentPublication {
	if n := len(list); n > 0 && sameDNATs(list[n-1], p) && sameDeclarations(list[n-1], p) {
		list[n-1] = p
		return list
	}
	list = append(list, p)
	if len(list) > maxUnconverged {
		list = list[len(list)-maxUnconverged:]
	}
	return list
}

// sameDeclarations は、2 つの公開のルールの宣言、つまりルールごとのプロトコル、待ち受けのポートの範囲、
// 宣言の宛先の文字列が同じかどうかである。世代と理由は比べない。
func sameDeclarations(a, b nft.AgentPublication) bool {
	type decl struct {
		proto  proto.Proto
		listen proto.PortRange
		target string
	}
	byID := func(p nft.AgentPublication) map[string]decl {
		m := make(map[string]decl, len(p.Rules))
		for _, r := range p.Rules {
			m[r.RuleID] = decl{r.Proto, r.ListenPort, r.Target}
		}
		return m
	}
	return reflect.DeepEqual(byID(a), byID(b))
}

// convergeFlows は、conntrack を今の公開に収束させる(7b.4 節)。wgft0 から入って DNAT されたフローの
// うち、宣言から消えたポートのフロー、実効宛先の宣言が変わったポートのフロー、今の許可一覧の外に
// DNAT したフローを消す。成功したら収束が済んでいない前の公開の列を消し、失敗したら列を残して、
// 30 秒ごとの見直しでテーブルを差し替えずに試し直す(7a.3 節の修復)。列は認証情報ファイルに写す。
// 前の公開が 1 つも無ければ、どのフローも wgft のものと見分けられないので、何もしない。
func (d *kernelDataplane) convergeFlows() {
	if d.pub == nil || len(d.unconverged) == 0 {
		d.recordUnconverged()
		return
	}
	addr, err := netip.ParsePrefix(d.wg.Address)
	if err != nil {
		return
	}
	scope := conntrack.AgentScope{Local: addr.Addr(), Peer: d.server}
	if d.allow != nil {
		scope.AllowTarget = d.allow.Allows
	}
	res, err := d.ops.convergeFlows(d.unconverged, *d.pub, scope)
	// 閉じたフローがあれば出す。閉じられなかったフローは誤りに数が入るので、誤りと同じく変わったときだけ
	// 出す。同じ削除の失敗が 30 秒ごとに繰り返す間、同じ行を出し続けないためである
	if res.Deleted() > 0 {
		log.Printf("kernel mode: conntrack: %s", res)
	}
	switch {
	case err == nil:
		if d.convergeErr != "" {
			log.Printf("kernel mode: conntrack converges again")
		}
		d.convergeErr = ""
		d.unconverged = nil
	case err.Error() != d.convergeErr:
		log.Printf("kernel mode: conntrack: %v; established flows the new table does not allow may still pass until this succeeds, and the 30-second check tries again", err)
		d.convergeErr = err.Error()
	}
	d.recordUnconverged()
}

// recordUnconverged は、収束が済んでいない前の公開の列を認証情報ファイルの項目に写す。
func (d *kernelDataplane) recordUnconverged() {
	if len(d.unconverged) == 0 {
		d.f.KernelUnconverged = nil
		return
	}
	if b, err := json.Marshal(d.unconverged); err == nil {
		d.f.KernelUnconverged = b
	}
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
	// 収束が済んでいなければ、テーブルを差し替えずに収束だけを試し直す(7a.3 節の修復)
	if len(d.unconverged) > 0 && d.converged {
		d.convergeFlows()
		if len(d.unconverged) == 0 && d.save != nil {
			if err := d.save(); err != nil {
				log.Printf("save credentials file after conntrack converged: %v", err)
			}
		}
	}
	d.probeAll()
}

// close はカーネルに何もしない。wgft0 とテーブルは停止の間も残し、転送を続ける(7b.4 節)。撤去は
// wgft agent teardown が行う。受け取った wg 設定と鍵だけを忘れるので、runtime は次に build を呼ぶ。
// rotate-key はこの経路で新しい鍵を渡す。直前の公開の記録と、直前に解決できたアドレスは残す。
func (d *kernelDataplane) close() {
	d.have = false
	d.stopKeepalive()
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

// ruleStatuses は公開の記録からルールごとの状態を作る(5.2・7b.3 節)。公開の記録の理由、試し接続の
// 誤り、ip_forward の順に見る。理由を持っていても DNAT を公開したルール(直前の解決の結果で転送を
// 続けているルールと、範囲の一部のポートだけを公開したルール)は、後ろの 2 つの誤りも理由に続ける
// (7b.2 節)。直前のアドレスの宛先が応えないことを、理由の先頭の文言が隠さないようにするためである。
// server doctor は、直前の解決の結果で転送を続けている文言の後ろの残りでこのルールの宛先を判定する
// (10.2a 節、internal/vpsd/doctor の StaleResolution)。
func (d *kernelDataplane) ruleStatuses() []proto.RuleStatus {
	out := make([]proto.RuleStatus, 0, len(d.pub.Rules))
	for _, r := range d.pub.Rules {
		s := proto.RuleStatus{ID: r.RuleID, State: proto.StatusOK}
		var parts []string
		if r.Reason != "" {
			parts = append(parts, r.Reason)
		}
		if len(r.Ranges) > 0 {
			if e := d.probeErr[r.RuleID]; e != "" {
				parts = append(parts, e)
			}
			if d.forwardErr != nil && !d.allLocal(r) {
				parts = append(parts, d.forwardErr.Error()+"; the kernel does not forward to a target that is not this host")
			}
		}
		if len(parts) > 0 {
			s.State, s.Reason = proto.StatusError, strings.Join(parts, "; ")
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

// doctorKernel は agent doctor のためにカーネルを読む(設計文書 10.2c 節)。停止中の agent doctor と同じ
// readKernel を、メモリの上の認証情報ファイルと公開の記録で呼ぶ。記録は公開に成功するたびに d.f に
// 写すので、d.pub と同じ中身である。
func (d *kernelDataplane) doctorKernel() *DoctorKernel {
	return readKernel(kernelReadInput{iface: d.iface, creds: d.f, pub: d.f.KernelPublication})
}

func (d *kernelDataplane) checkError() string { return d.observeErr }

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

// observePrepare は 30 秒ごとの見直しのうち、名前の解決だけを行う(7b.2 節)。rt.mu の外で呼ぶ。
// 停止で打ち切られたら nil を返し、見直しは何もしない。
func (d *kernelDataplane) observePrepare(rules []proto.AgentRule) any {
	ctx, cancel := context.WithTimeout(d.ctx, kernelResolveTimeout)
	defer cancel()
	p := &observePrepared{}
	d.epMu.Lock()
	stale, name := d.endpointStale, d.declared
	d.epMu.Unlock()
	if stale && name != "" {
		p.endpoint = &kernelPrepared{tried: true, endpointOf: name}
		p.endpoint.endpoint, p.endpoint.endpointEr = resolveEndpointAddr(ctx, name, d.ops.lookup)
	}
	p.resolved = resolveTargets(ctx, rules, d.ops.lookup)
	if d.ctx.Err() != nil {
		return nil
	}
	return p
}

// observePrepared は observePrepare の結果である。endpoint は、エンドポイントを引き直したときだけある。
type observePrepared struct {
	resolved map[string]nft.Resolution
	endpoint *kernelPrepared
}

// observeCommit は 30 秒ごとの見直しの残りである(7b.2・7b.4 節)。rt.mu を持って呼ぶ。
//
//   - 名前の解決し直し:PlanAgent の結果の DNAT が直前の公開と違うときだけテーブルを公開し直す。解決の
//     結果が変わっても、選ぶアドレスが同じなら公開し直さない。理由の文言だけが変わったときは、記録を
//     書き換えるが、テーブルは差し替えない
//   - 外からの変更:実際のテーブルの指紋と wgft0 の状態を、直前の公開と宣言に比べる。食い違えば、wgft0 を
//     収束させてからテーブルを公開し直す。エンドポイントだけの違いは食い違いとして扱わない(7b.1 節)
//
// saved は記録が変わったかどうかで、真なら呼び出し側が認証情報ファイルを保存する。見直しの失敗は
// 旧いテーブルを残し、次の見直しで試し直す。
func (d *kernelDataplane) observeCommit(gen uint64, rules []proto.AgentRule, prepared any) (saved bool, err error) {
	op, ok := prepared.(*observePrepared)
	if !ok || !d.have || !d.converged || d.pub == nil {
		return false, nil
	}
	return d.compare(gen, rules, op)
}

// sensor はカーネルの変更の通知の購読である(7b.4 節の変更の通知)。
func (d *kernelDataplane) sensor() dataplane.Sensor { return d.ops.notify }

// observeNotified は、変更の通知をまとめた後の見直しである(7b.4 節の変更の通知)。rt.mu を持って呼ぶ。
// 30 秒ごとの見直しのうち外からの変更だけを扱い、名前を引かず、試し接続もしない。比べるのは直前の
// 公開そのものである。自分の公開と wgft0 の収束も通知を生むが、公開の直後に指紋を読み直してあるので、
// その通知の後の見直しは一致を確かめて終わる。
func (d *kernelDataplane) observeNotified(gen uint64, rules []proto.AgentRule) (saved bool, err error) {
	if !d.have || !d.converged || d.pub == nil {
		return false, nil
	}
	return d.compare(gen, rules, nil)
}

// compare は、実際のテーブルと wgft0 を直前の公開と宣言に比べ、食い違えば直す。op は 30 秒ごとの
// 見直しの名前の解決の結果で、nil なら変更の通知の後の見直しである。
//
// 通知の後の見直しは、公開し直しが失敗した後、gate が開くまで公開し直さない。ただし新しく見つかった
// 食い違い、つまり新たにログに出す食い違いは待たずに直す。30 秒ごとの見直しは gate を見ない。
//
// 同じ食い違いのログは、30 秒ごとの見直しが食い違いを見つけない回を挟むまで 1 行だけにする。通知の
// 後の見直しが食い違いを見つけない回は区切りに数えない。自分の公開の直後の通知は必ず一致を見つけるので、
// 数えると、他のプロセスが同じ変更を繰り返すたびに 1 行出すことになるためである。
func (d *kernelDataplane) compare(gen uint64, rules []proto.AgentRule, op *observePrepared) (saved bool, err error) {
	// 引き直したエンドポイントの収束に失敗しても、表の修復と経路の確認へ進み、誤りは最後に返す。
	// 印は残るので、次の見直しが試し直す。ここで返すと、収束の失敗が続く間(稼働中に現れた重なりなど)、
	// 30 秒ごとの見直しが表の修復に届かない
	var reErr error
	if op != nil && op.endpoint != nil {
		reErr = d.reResolved(op.endpoint)
	}
	saved, held, err := d.repair(gen, rules, op)
	// 門が閉じて何も試さなかった見直しは、前の誤りを残す。試していないので、直ったとは言えない
	if !held {
		d.repairErr = errText(err)
	}
	// エンドポイントの誤りは 30 秒ごとの見直しだけが書き換える
	if op != nil {
		d.endpointErr = errText(reErr)
	}
	d.noteObserveErr()
	if err == nil {
		err = reErr
	}
	return saved, err
}

// repair は compare の本体で、テーブルと wgft0 を比べて直す。held は、通知の後の見直しが門のために
// 何も試さずに終わったことを表す。
func (d *kernelDataplane) repair(gen uint64, rules []proto.AgentRule, op *observePrepared) (saved, held bool, err error) {
	next, changedDNAT := *d.pub, false
	if op != nil {
		next = d.planWith(gen, rules, op.resolved)
		changedDNAT = !sameDNATs(*d.pub, next)
	}
	tableDrift, linkDrift, link, err := d.drift()
	if err != nil {
		return false, false, err
	}
	d.watchHandshake(link)
	drift := strings.Join(nonEmpty(tableDrift, linkDrift), "; ")
	fresh := drift != "" && drift != d.driftSeen
	if fresh {
		log.Printf("kernel mode: %s; publishing the table again", drift)
	}
	if drift != "" || op != nil {
		d.driftSeen = drift
	}
	if op == nil && drift != "" && !d.gate.Allow(fresh) {
		return false, true, nil
	}
	if linkDrift != "" {
		cfg, err := d.linkConfig()
		if err != nil {
			return false, false, err
		}
		changes, err := d.ops.ensureLink(cfg)
		if err != nil {
			d.gate.Failed()
			return false, false, fmt.Errorf("converge %s: %w", d.iface, err)
		}
		if len(changes) > 0 {
			log.Printf("kernel mode: %s: %s", d.iface, strings.Join(changes, "; "))
		}
	}
	// 経路は wgft0 が宣言どおりになってから確かめる。wgft0 が消えたり down だったりする間は、経路が
	// 既定経路へ出るのは当然で、確かめる意味が無い(7b.1 節)
	d.checkRoute()
	switch {
	case changedDNAT:
		log.Printf("kernel mode: target resolution changed the DNAT of %s; publishing the table again", strings.Join(changedRules(*d.pub, next), ", "))
	case drift != "":
	default:
		if reflect.DeepEqual(d.pub.Rules, next.Rules) {
			return false, false, nil
		}
		// 理由の文言だけが変わった。テーブルは同じなので差し替えない
		d.pub = &next
		if b, err := json.Marshal(next); err == nil {
			d.f.KernelPublication = b
		}
		return true, false, nil
	}
	if err := d.publish(next); err != nil {
		return false, false, err
	}
	// driftSeen は公開し直しても残す。他のプロセスが同じ変更を繰り返す間、見直しは直し続けるが、
	// ログは 30 秒ごとの見直しが食い違いを見つけない回を挟むまで 1 行だけにする
	if changedDNAT {
		d.probeAll()
	}
	return true, false, nil
}

// noteObserveErr は、repairErr と endpointErr をつないだ見直しの誤りを、変わったときだけ 1 行出す。
// 30 秒ごとの見直しと通知の後の見直しで同じ控えを使う。どちらも同じテーブルと wgft0 を読み、同じ誤りに
// 当たるためである。
func (d *kernelDataplane) noteObserveErr() {
	msg := strings.Join(nonEmpty(d.repairErr, d.endpointErr), "; ")
	switch {
	case msg == d.observeErr:
	case msg == "":
		log.Printf("kernel mode: checking table inet %s and %s works again", nft.AgentTableName, d.iface)
	default:
		log.Printf("kernel mode: checking table inet %s and %s failed: %s; the previous publication stays in place and the next check tries again", nft.AgentTableName, d.iface, msg)
	}
	d.observeErr = msg
}

// errText は誤りの文面である。nil なら空である。
func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// drift は、実際のテーブルと wgft0 が直前の公開と宣言に一致しなければ、それぞれ何が違うかを返す。
// 一致すれば空である。テーブルは指紋で、wgft0 は種別、鍵、up、MTU、アドレス、ピアの集合と
// AllowedIPs と keepalive で比べる。エンドポイントは比べない(7b.1 節)。
func (d *kernelDataplane) drift() (table, link string, st wg.AgentState, err error) {
	fp, present, err := d.ops.fingerprint(nft.AgentTableName)
	switch {
	case err != nil:
		return "", "", st, fmt.Errorf("read table inet %s: %w", nft.AgentTableName, err)
	case !present:
		table = "table inet " + nft.AgentTableName + " is gone"
	case !d.fpKnown:
		table = "the fingerprint of table inet " + nft.AgentTableName + " was not read after the last publication"
	case fp != d.fp:
		table = "table inet " + nft.AgentTableName + " was changed outside wgft"
	}
	prev, _ := d.f.PreviousKey()
	st, err = d.ops.inspectLink(d.iface, d.priv, prev)
	if err != nil {
		return "", "", st, fmt.Errorf("read %s: %w", d.iface, err)
	}
	return table, d.linkDrift(st), st, nil
}

// watchHandshake は、wgft0 の最終ハンドシェイクが keepalive の 5 倍の間新しくならなければ、次の見直しで
// エンドポイントの名前を引き直すよう印を付ける(7b.1 節、4 節と同じ契機)。カーネルの WireGuard は
// 名前を自分では引き直さない。IP リテラルのエンドポイントと keepalive が 0 の設定では引き直さない。
func (d *kernelDataplane) watchHandshake(st wg.AgentState) {
	var hs time.Time
	for _, p := range st.Peers {
		hs = p.LastHandshake
	}
	now := d.ops.now()
	if !hs.Equal(d.hsValue) || d.hsSince.IsZero() {
		d.hsValue, d.hsSince = hs, now
	}
	if d.wg.Keepalive <= 0 {
		return
	}
	host, _, err := net.SplitHostPort(d.wg.Endpoint)
	if err != nil {
		return
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	if now.Sub(d.hsSince) >= 5*time.Duration(d.wg.Keepalive)*time.Second {
		d.epMu.Lock()
		d.endpointStale = true
		d.epMu.Unlock()
	}
}

// reResolved は、見直しが引き直したエンドポイントを控えに入れ、wgft0 のピアへ設定する。引けなかった
// 場合は控えを使い続ける。どちらの場合も、次に引き直すのはさらに keepalive の 5 倍の後である。ただし
// wgft0 の収束に失敗したら、次の見直しで試し直す。
func (d *kernelDataplane) reResolved(p *kernelPrepared) error {
	d.epMu.Lock()
	before := d.endpoint
	d.epMu.Unlock()
	d.useEndpoint(p)
	if p.endpointEr != nil {
		d.resolvedAgain()
		return nil
	}
	if p.endpoint != before {
		log.Printf("kernel mode: no new handshake for 5 times the keepalive; resolved the server endpoint %s again to %s", p.endpointOf, p.endpoint)
	}
	// アドレスが変わらなくても wgft0 を収束させる。カーネルのピアのエンドポイントが外から書き換えられて
	// いれば、ここで戻る。収束に失敗したら印を残し、次の見直しで引き直しと収束を試し直す
	cfg, err := d.linkConfig()
	if err != nil {
		return err
	}
	changes, err := d.ops.ensureLink(cfg)
	if err != nil {
		return fmt.Errorf("converge %s: %w", d.iface, err)
	}
	if len(changes) > 0 {
		log.Printf("kernel mode: %s: %s", d.iface, strings.Join(changes, "; "))
	}
	d.resolvedAgain()
	return nil
}

// resolvedAgain は引き直しの印を消し、次に引き直すまでの keepalive の 5 倍を数え直す。
func (d *kernelDataplane) resolvedAgain() {
	d.epMu.Lock()
	d.endpointStale = false
	d.epMu.Unlock()
	d.hsSince = d.ops.now()
}

// checkRoute は、vpsd のトンネルアドレスへの経路が wgft0 を通るかを、ポリシールーティングの規則を
// 含めて確かめる(7b.1 節)。アドレス帯の重なりの検査は main の経路表だけを読むので、先に引かれる
// 規則の表(Tailscale の表 52 など)が奪う経路はここでだけ見える。稼働中に main の表に現れた重なりも
// ここで見える。警告はカーネルの引き当てが示す事実だけを述べ、原因は決めつけない。警告だけを出し、
// 起動は止めない(2026-09-24、所有者の決定)。ポリシールーティングは稼働中にも変わるためである。
// 変わったときだけ 1 行出す。wgft0 が宣言どおりになった後に呼ぶ。
func (d *kernelDataplane) checkRoute() {
	iface, err := d.ops.routeIface(d.server)
	finding := ""
	switch {
	case err != nil:
		finding = fmt.Sprintf("cannot look up the route to the server's tunnel address %s: %v", d.server, err)
	case iface != d.iface:
		finding = fmt.Sprintf("policy rules included, the route to the server's tunnel address %s leaves through %s, not %s; replies to the server may not go through the tunnel; look for a policy routing rule that sends %s to another table, such as the one Tailscale adds for accepted subnet routes, or for an address or route on another interface that covers it", d.server, iface, d.iface, d.server)
	}
	if finding == d.routeFinding {
		return
	}
	switch {
	case finding != "":
		log.Printf("warning: %s", finding)
	default:
		log.Printf("kernel mode: the route to the server's tunnel address %s leaves through %s again", d.server, d.iface)
	}
	d.routeFinding = finding
}

func nonEmpty(s ...string) []string {
	var out []string
	for _, x := range s {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// linkDrift は wgft0 の状態 st が宣言と違えば、その説明を返す。
func (d *kernelDataplane) linkDrift(st wg.AgentState) string {
	cfg, err := d.linkConfig()
	if err != nil {
		return ""
	}
	if !st.Exists {
		return d.iface + " is gone"
	}
	diff := linkDiffs(st, cfg)
	if len(diff) == 0 {
		return ""
	}
	return fmt.Sprintf("%s differs from the declaration in %s", d.iface, strings.Join(diff, ", "))
}

// linkDiffs は、ある wgft0 の状態 st が宣言 cfg と違う点を並べる。30 秒ごとの見直しと agent doctor の
// dataplane.interface が同じ関数を使う(設計文書 10.2c 節)。エンドポイントは比べない(7b.1 節)。
func linkDiffs(st wg.AgentState, cfg wg.AgentConfig) []string {
	var diff []string
	if st.Ownership != wg.OwnedByCurrentKey {
		diff = append(diff, "the key")
	}
	if !st.Up {
		diff = append(diff, "the up flag")
	}
	if st.MTU != cfg.MTU {
		diff = append(diff, "the MTU")
	}
	if len(st.Addresses) != 1 || st.Addresses[0] != cfg.Address {
		diff = append(diff, "the address")
	}
	want := netip.PrefixFrom(cfg.Server.Address, 32)
	if len(st.Peers) != 1 || st.Peers[0].PublicKey != cfg.Server.PublicKey ||
		len(st.Peers[0].AllowedIPs) != 1 || st.Peers[0].AllowedIPs[0] != want ||
		st.Peers[0].Keepalive != cfg.Server.Keepalive {
		diff = append(diff, "the peer")
	}
	return diff
}

// sameDNATs は、2 つの公開が同じ DNAT を持つかどうかである。世代と理由の文言は比べない。
func sameDNATs(a, b nft.AgentPublication) bool {
	return reflect.DeepEqual(a.DNATs(), b.DNATs())
}

// changedRules は、DNAT が変わったルールの ID を並べる。
func changedRules(a, b nft.AgentPublication) []string {
	byID := func(p nft.AgentPublication) map[string][]nft.AgentRange {
		m := map[string][]nft.AgentRange{}
		for _, r := range p.Rules {
			m[r.RuleID] = r.Ranges
		}
		return m
	}
	am, bm := byID(a), byID(b)
	var out []string
	for id, rb := range bm {
		if !reflect.DeepEqual(am[id], rb) {
			out = append(out, id)
		}
	}
	for id := range am {
		if _, ok := bm[id]; !ok {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}
