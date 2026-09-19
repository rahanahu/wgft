// Package vpsd は VPS 側のデーモン。
// wg0 を宣言に収束させ、SQLite のルールを nftables に適用し、エージェント用 API と管理用 API を待ち受ける。
//
// ファイルの分け方:
//   - vpsd.go: Options、Daemon、Run(起動の配線)
//   - dataplane.go: 転送面(カーネルの wg・nftables・conntrack)へのインタフェースとカーネル実装
//   - dataplane_userspace.go: ユーザー空間モードの転送面(internal/dataplane/userspace の Backend)を包む層
//   - apply.go: wg の立ち上げとルールの適用(bringUpWG、applyNFT。Reconciler が駆動する)
//   - admin_backend.go: 管理用 API(admin.Backend)の実装
//   - agent_backend.go: 登録(agentapi.Backend)と stream(stream.Backend)の実装
//   - watch.go: 窃取検知(IP の食い違いと往復。仕様 5.2 節)
//   - startup.go: サーバ鍵、環境の読み取り、ip_forward
package vpsd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel"
	"github.com/rahanahu/wgft/internal/dataplane/userspace"
	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/internal/flowcap"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/reconcile"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/agentapi"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/stream"
	"github.com/rahanahu/wgft/proto"
	"log"
	"net"
	"net/netip"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const serverKeyMeta = "wg_server_private_key"

// adminTailscalePort は --admin-tailscale での待ち受けポート(TCP)。
const adminTailscalePort = "8686"

// ifaceAddrs はネットワークインタフェース 1 つぶんの名前とアドレス一覧。
// pickTailscaleAddr を実際のインタフェースなしに単体テストするための型。
type ifaceAddrs struct {
	name  string
	addrs []net.Addr
}

// pickTailscaleAddr は、名前が "tailscale" で始まるインタフェースにある
// 100.64.0.0/10 の最初の IPv4 アドレスを選ぶ(iface, ip)。
// CGNAT 帯は Tailscale 専用ではなく VPS 事業者の内部網にも使われ得るため、
// インタフェース名で絞る(仕様 11 節)。該当がないとき、CGNAT アドレスを
// 持つ他のインタフェースがあれば、その名前を other に入れる(なければ空)。
func pickTailscaleAddr(ifaces []ifaceAddrs) (iface, ip string, other string) {
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	firstCGNAT := func(f ifaceAddrs) (string, bool) {
		for _, a := range f.addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			addr, ok := netip.AddrFromSlice(ipn.IP)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.Is4() && cgnat.Contains(addr) {
				return addr.String(), true
			}
		}
		return "", false
	}
	for _, f := range ifaces {
		if !strings.HasPrefix(f.name, "tailscale") {
			continue
		}
		if a, ok := firstCGNAT(f); ok {
			return f.name, a, ""
		}
	}
	for _, f := range ifaces {
		if strings.HasPrefix(f.name, "tailscale") {
			continue
		}
		if _, ok := firstCGNAT(f); ok {
			return "", "", f.name
		}
	}
	return "", "", ""
}

// tailscaleIP は稼働中のインタフェースから pickTailscaleAddr で選んだ結果を返す。
func tailscaleIP() (iface, ip, other string) {
	ifs, err := net.Interfaces()
	if err != nil {
		return "", "", ""
	}
	list := make([]ifaceAddrs, 0, len(ifs))
	for _, i := range ifs {
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		list = append(list, ifaceAddrs{name: i.Name, addrs: addrs})
	}
	return pickTailscaleAddr(list)
}

// tailscaleStatusSelf は `tailscale status --json` の出力のうち使う部分だけ。
type tailscaleStatusSelf struct {
	Self struct {
		TailscaleIPs []string `json:"TailscaleIPs"`
		DNSName      string   `json:"DNSName"`
	} `json:"Self"`
}

// parseTailscaleStatus は `tailscale status --json` の出力から、Self.TailscaleIPs の
// 最初の IPv4 アドレスと Self.DNSName(MagicDNS 名。末尾のドットを外す)を取り出す。
// IPv4 のアドレスが 1 つもなければ ok は偽。
func parseTailscaleStatus(data []byte) (ip, dnsName string, ok bool) {
	var st tailscaleStatusSelf
	if err := json.Unmarshal(data, &st); err != nil {
		return "", "", false
	}
	for _, s := range st.Self.TailscaleIPs {
		addr, err := netip.ParseAddr(s)
		if err != nil || !addr.Is4() {
			continue
		}
		return addr.String(), strings.TrimSuffix(st.Self.DNSName, "."), true
	}
	return "", "", false
}

// runTailscaleStatus は `tailscale status --json` を実行し、その標準出力を返す。
// tailscale コマンドが PATH になければ、それも失敗として err に返る。
func runTailscaleStatus(ctx context.Context) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, "tailscale", "status", "--json").Output()
}

// detectAdminTailscale は --admin-tailscale の待ち受け先を選ぶ。
// まず `tailscale status --json` の Self から選び、コマンドがない・失敗する・
// 使えるアドレスがないときは、tailscale で始まる名前のインタフェースから選ぶ
// (tailscaleIP、仕様 11 節)。detail はログに添える出どころの説明。
// どちらからも選べず、CGNAT アドレスを持つ他のインタフェースがあれば other に入れる。
func detectAdminTailscale(ctx context.Context) (ip, dnsName, detail, other string) {
	if out, err := runTailscaleStatus(ctx); err == nil {
		if sip, sdns, ok := parseTailscaleStatus(out); ok {
			d := "from tailscale status"
			if sdns != "" {
				d = sdns + ", from tailscale status"
			}
			return sip, sdns, d, ""
		}
	}
	iface, iip, iother := tailscaleIP()
	if iip != "" {
		return iip, "", "from interface " + iface, ""
	}
	return "", "", "", iother
}

// Options は vpsd の起動オプション。
type Options struct {
	DBPath       string
	WGInterface  string
	WGPort       uint16
	WGAddress    string // 10.200.0.1/24
	WGEndpoint   string // エージェントに配る host:port(空なら未設定のまま配る)
	MTU          int
	AgentAPIAddr string // 0.0.0.0:8443(公開)
	AgentAPIHost string // 接続文字列に入れる host:port。空なら WGEndpoint のホスト + AgentAPIAddr のポート
	AdminAddr    string // unix:///run/wgft/admin.sock(既定)か host:port
	// AdminTailscale が真なら、加えて tailnet のアドレス(100.64.0.0/10)でも待ち受ける(仕様 11 節)。
	AdminTailscale bool
	// AdminHost は Host 検査で追加で許可する名前(tailnet の MagicDNS 名など)。
	AdminHost []string
	// AdoptExisting が真のとき、鍵の一致しない既存 wg インタフェースを引き継ぐ(9 節)。
	AdoptExisting bool
	// Mode は転送方式 "kernel" / "userspace"(仕様 9・11a 節)。初回に記録し以後は照合する。
	Mode string
	// Limits は同時フロー数のプロセス全体の上限と、vpsd だけの接続元 IP ごとの上限(仕様 7 節)。
	// ゼロ値の項目は既定値。接続元ごとの上限を外すのは flowcap.PerSourceOff
	Limits flowcap.Limits
	// Version は起動ログに出す wgft のバージョン(cmd/wgft の effectiveVersion)。空なら省く。
	Version string
}

// Daemon は動いている vpsd。管理用 API の Backend を実装する。
type Daemon struct {
	opts      Options
	st        *store.Store
	reserved  proto.Reserved
	timeouts  linux.UDPTimeouts
	serverKey wgtypes.Key

	network   netip.Prefix // 10.200.0.0/24
	startedAt time.Time
	kernel    string
	nftVer    string
	agentAPI  *agentapi.Server
	hub       *stream.Hub
	proxy     *proxyrelay.Manager
	flaps     *flapState

	mu sync.Mutex // ルール・エージェントの変更と、wg0・nftables の適用を直列化する

	// dp は転送面。カーネル(nftables + カーネル WireGuard、仕様 6.1 節)とユーザー空間(仕様 6.3 節)の 2 つの実装がある
	dp serverDataplane
	// rec は dp とプロキシモードの中継を 1 つのトランザクションで駆動し、Desired と Active を持つ
	// (設計文書 7a.3 節)。最初の applyNFT で作る
	rec *reconcile.Reconciler
}

// Run は起動して、シグナルまで動く。
func Run(opts Options) error {
	st, err := store.Open(opts.DBPath)
	if err != nil {
		return fmt.Errorf("server database %s: %w", opts.DBPath, err)
	}
	defer st.Close()

	// 既存の名前の検証。消さずに警告だけする
	if bad, err := st.InvalidAgentNames(); err != nil {
		log.Printf("warning: checking agent names: %v", err)
	} else {
		for _, n := range bad {
			log.Printf("warning: agent %q has a name that does not match the current validation rule (spec 5.1); keeping it as is", n)
		}
	}

	// 起動ロック。二重起動を防ぎ、teardown が「vpsd 稼働中」を検出できるようにする(仕様 9 節)。
	// flock は状態ファイルの呼び名を知らない汎用パッケージなので、ここで利用者向けの
	// 呼び名(サーバのデータベース)に言い換える。
	lock, err := flock.Acquire(opts.DBPath)
	if errors.Is(err, flock.ErrLocked) {
		return errors.New("server database is in use by another process")
	}
	if err != nil {
		return fmt.Errorf("startup lock: %w", err)
	}
	defer lock.Release()

	d := &Daemon{opts: opts, st: st, dp: &kernelDataplane{
		iface: opts.WGInterface,
		b:     linuxkernel.New(linuxkernel.Options{Interface: opts.WGInterface, AdoptExisting: opts.AdoptExisting}),
	}}
	d.reserved = proto.Reserved{opts.WGPort: "WireGuard"}
	if ap, err := netip.ParseAddrPort(opts.AdminAddr); err == nil {
		d.reserved[ap.Port()] = "admin API"
	}
	if _, port, err := net.SplitHostPort(opts.AgentAPIAddr); err == nil {
		if p, err := netip.ParseAddrPort("0.0.0.0:" + port); err == nil {
			d.reserved[p.Port()] = "agent API"
		}
	}
	// モードとアドレス帯の初回記録・照合は、鍵やインタフェースを作る前に済ませる(仕様 9・11a 節)。
	_, keyErr := st.GetMeta(serverKeyMeta)
	hadServerKey := keyErr == nil
	if err := reconcileModeAndAddress(st, opts, hadServerKey); err != nil {
		return err
	}
	// ログに出すモードは、この起動で実際に使う値(WGFT_MODE 未指定なら記録済みの値)を
	// SQLite から読み直して使う。opts.Mode は未指定なら空のままなので、それを出すと
	// 空欄のログになる(reconcileModeAndAddress の「WGFT_MODE unset」の分岐参照)。
	recordedMode, err := st.GetMeta(modeMeta)
	if err != nil {
		return fmt.Errorf("reading recorded mode: %w", err)
	}
	mode := string(recordedMode)
	// データプレーンは、この起動で実際に使うモード(記録済みの値)で選ぶ。WGFT_MODE を指定しない
	// 再起動では opts.Mode が空なので、それで選ぶと記録が userspace でも kernel のデータプレーンになる。
	// ログ(apply.go)と管理用 API(admin_backend.go)が見る d.opts.Mode も同じ値にそろえる
	d.opts.Mode = mode
	var uspace *userspace.Backend
	if mode == modeUserspace {
		uspace = userspace.New(userspace.Options{Limits: opts.Limits})
		d.dp = &userspaceDataplane{b: uspace}
	}
	if d.serverKey, err = serverKey(st); err != nil {
		return err
	}
	if other, ok := d.dp.OtherDeviceWithKey(d.serverKey); ok {
		log.Printf("warning: another WireGuard device %q with the same server key exists; suspect leftovers from changing WGFT_WG_INTERFACE, remove it with server teardown", other)
	}
	if d.network, err = netip.ParsePrefix(opts.WGAddress); err != nil {
		return fmt.Errorf("--wg-address %q: %w", opts.WGAddress, err)
	}
	if err := d.bringUpWG(); err != nil {
		return err
	}
	// teardown が --state だけで正しいインタフェース名とポートを知れるよう meta に残す。
	recordTeardownHints(st, opts)
	d.startedAt = time.Now()
	d.kernel = readKernel()
	d.nftVer = readNFTVersion()
	if d.timeouts, err = d.dp.ReadUDPTimeouts(); err != nil {
		return err
	}

	// 他テーブルの検査(仕様 6.1 節)。起動時は警告と提示だけで、自動では書き換えない
	rep, err := d.dp.Inspect()
	if err != nil {
		return fmt.Errorf("nftables check: %w", err)
	}
	for _, f := range rep.Findings {
		log.Printf("warning: %s", f)
	}
	if f := d.dp.EnableIPForward(st); f != nil {
		log.Printf("warning: %s", f)
	}
	// カーネルモードのプロキシ中継も同じ上限で数える(仕様 6.2 節)。接続元 IP ごとの数は、
	// nftables の flows_tcp がカーネルモードのルールと合わせて数える(6.1、7 節)ので、ここでは数えない。
	// 起動時の applyNFT が待ち受けを開き、開けたポートだけに上限の行を付けるよう、先に作る
	proxyOpts := proxyrelay.Options{Cap: &flowcap.Counter{Total: opts.Limits.WithDefaults().TCPTotal}}
	if uspace != nil {
		// ユーザー空間モードでは netstack 越しにエージェントへ
		proxyOpts.Dial = func(addr string) (net.Conn, error) { return uspace.Dial("tcp", addr) }
		proxyOpts.Cap = uspace.TCPCounter() // 同時接続数は relay と合計で数える(仕様 7 節)
	}
	d.proxy = proxyrelay.New(proxyOpts)
	// 起動時に SQLite のルールを適用する(手作業で変えられたテーブルは宣言に戻る)
	rules, err := st.Rules()
	if err != nil {
		return err
	}
	if err := d.applyNFT(rules); err != nil {
		return err
	}
	if d.agentAPI, err = agentapi.New(st, d); err != nil {
		return fmt.Errorf("agent API: %w", err)
	}
	d.hub = stream.New(d)
	d.hub.RateLimit = d.agentAPI.Allow
	d.flaps = &flapState{hist: map[string]map[string][]ipObs{}}
	// stream の接続元 IP を接続の事象で記録し、往復を検知する(仕様 5.2 節)
	d.hub.OnStreamConnect = func(agent, from string) { d.observeFlap(agent, "stream", "stream source", from) }
	d.agentAPI.Handle("GET /api/v1/agents/stream", d.hub.ServeHTTP)
	_ = st.PurgeExpiredJoinTokens()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 3)
	srv := admin.New(st, d)
	srv.AllowedHosts = append(srv.AllowedHosts, opts.AdminHost...)
	if opts.AdminTailscale {
		if ip, dnsName, detail, other := detectAdminTailscale(ctx); ip != "" {
			srv.AllowedHosts = append(srv.AllowedHosts, ip)
			if dnsName != "" {
				srv.AllowedHosts = append(srv.AllowedHosts, dnsName)
			}
			tsAddr := net.JoinHostPort(ip, adminTailscalePort)
			tsLn, err := admin.Listen(tsAddr, false)
			if err != nil {
				return fmt.Errorf("admin API tailscale: %w", err)
			}
			log.Printf("also listening for the admin API on Tailscale %s (%s)", tsAddr, detail)
			go func() { errc <- fmt.Errorf("admin API tailscale: %w", admin.ServeListener(tsLn, srv)) }()
		} else if other != "" {
			log.Printf("warning: --admin-tailscale set but %s has a 100.64.0.0/10 address and is not a Tailscale interface; the admin API is NOT listening there", other)
		} else {
			log.Printf("warning: --admin-tailscale set but no tailnet address (100.64.0.0/10) found")
		}
	}
	adminLn, err := admin.Listen(opts.AdminAddr, true)
	if err != nil {
		return fmt.Errorf("admin API: %w", err)
	}
	agentLn, err := d.agentAPI.Listen(opts.AgentAPIAddr)
	if err != nil {
		return fmt.Errorf("agent API: %w", err)
	}
	// 起動完了の行は、データプレーンの適用と全部の待ち受けが済んでから出す(仕様 10.4 節)。
	// これより前に失敗すれば、この行は出ずにプロセスが終わる
	gen, err := st.Generation()
	if err != nil {
		return err
	}
	_, agentAddr, err := d.agents()
	if err != nil {
		return err
	}
	log.Printf("wgft %s server started: mode %s, interface %s, generation %d, %d rules, %d agents",
		opts.Version, mode, opts.WGInterface, gen, len(rules), len(agentAddr))
	go func() { errc <- fmt.Errorf("admin API: %w", admin.ServeListener(adminLn, srv)) }()
	go func() { errc <- fmt.Errorf("agent API: %w", d.agentAPI.ServeListener(agentLn)) }()
	go d.watchIPMismatch(ctx)
	select {
	case <-ctx.Done():
		log.Printf("shutting down; keeping wg0 and the table")
		return nil
	case err := <-errc:
		return err
	}
}

// agents は SQLite のエージェントから、wg のピア集合と名前 → アドレスの表を作る。
// 公開鍵が未宣言(stream に一度も来ていない)のエージェントはアドレスだけ持ち、ピアにはならない。
// dataplane.Peer を直接返すので、両方の Backend の dataplane.WGConfig にそのまま渡せる
// (design.md 7a.8 節 Phase 3: カーネル固有の wg.Peer への変換は kernelDataplane の役目ではなくなった)。
func (d *Daemon) agents() ([]dataplane.Peer, map[string]netip.Addr, error) {
	list, err := d.st.Agents()
	if err != nil {
		return nil, nil, err
	}
	var peers []dataplane.Peer
	addr := make(map[string]netip.Addr, len(list))
	for _, a := range list {
		addr[a.Name] = a.Address
		if a.PublicKey == "" {
			continue
		}
		key, err := wgtypes.ParseKey(a.PublicKey)
		if err != nil {
			log.Printf("agent %s has an invalid public key: %v", a.Name, err)
			continue
		}
		peers = append(peers, dataplane.Peer{PublicKey: key, Address: a.Address})
	}
	return peers, addr, nil
}
