// Package vpsd は VPS 側のデーモン。
// wg0 を宣言に収束させ、SQLite のルールを nftables に適用し、エージェント用 API と管理用 API を待ち受ける。
//
// ファイルの分け方:
//   - vpsd.go: Options、Daemon、Run(起動の配線)
//   - dataplane.go: 転送面(カーネルの wg・nftables・conntrack)へのインタフェースとカーネル実装
//   - apply.go: wg とルールの収束(reconcileWG、applyNFT、converge)
//   - admin_backend.go: 管理用 API(admin.Backend)の実装
//   - agent_backend.go: 登録(agentapi.Backend)と stream(stream.Backend)の実装
//   - watch.go: 窃取検知(IP の食い違いと往復。仕様 5.2 節)
//   - startup.go: サーバ鍵、環境の読み取り、ip_forward
package vpsd

import (
	"context"
	"fmt"
	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/agentapi"
	"github.com/rahanahu/wgft/internal/vpsd/proxyrelay"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/stream"
	"github.com/rahanahu/wgft/internal/vpsd/wg"
	"github.com/rahanahu/wgft/proto"
	"log"
	"net"
	"net/netip"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const serverKeyMeta = "wg_server_private_key"

// adminTailscalePort は --admin-tailscale での待ち受けポート(TCP)。
const adminTailscalePort = "8686"

// tailscaleIP は自分の tailnet アドレス(100.64.0.0/10)を返す。無ければ空。
func tailscaleIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	cgnat := netip.MustParsePrefix("100.64.0.0/10")
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok {
			if ip, ok := netip.AddrFromSlice(ipn.IP); ok && cgnat.Contains(ip.Unmap()) {
				return ip.Unmap().String()
			}
		}
	}
	return ""
}

// Version はビルド時に -X で埋める(scripts/build-release.sh)。
var Version = "dev"

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
}

// Daemon は動いている vpsd。管理用 API の Backend を実装する。
type Daemon struct {
	opts      Options
	st        *store.Store
	reserved  proto.Reserved
	timeouts  wg.UDPTimeouts
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

	// dp は転送面。カーネル(nftables + カーネル WireGuard)が唯一の実装で、v0.2.0 でユーザー空間実装を並べる(仕様 13 節)
	dp dataplane
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
	lock, err := flock.Acquire(opts.DBPath)
	if err != nil {
		return fmt.Errorf("startup lock: %w", err)
	}
	defer lock.Release()

	d := &Daemon{opts: opts, st: st, dp: &kernelDataplane{iface: opts.WGInterface}}
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
	if d.serverKey, err = serverKey(st); err != nil {
		return err
	}
	if other, ok := d.dp.OtherDeviceWithKey(d.serverKey); ok {
		log.Printf("warning: another WireGuard device %q with the same server key exists; suspect leftovers from changing WGFT_WG_INTERFACE, remove it with server teardown", other)
	}
	if d.network, err = netip.ParsePrefix(opts.WGAddress); err != nil {
		return fmt.Errorf("--wg-address %q: %w", opts.WGAddress, err)
	}
	if err := d.reconcileWG(); err != nil {
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
	d.dp.EnableIPForward(st)
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
	d.proxy = proxyrelay.New(proxyrelay.Options{})
	// 起動時のプロキシ中継の初期化(applyNFT は proxy 作成より前に走るため、ここで一度収束させる)
	if startupRules, e := st.Rules(); e == nil {
		_, aa, _ := d.agents()
		d.proxy.Apply(proxyrelay.FromRules(startupRules, aa))
		d.proxyInputHints(startupRules)
	}
	d.agentAPI.Handle("GET /api/v1/agents/stream", d.hub.ServeHTTP)
	_ = st.PurgeExpiredJoinTokens()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 3)
	srv := admin.New(st, d)
	srv.AllowedHosts = append(srv.AllowedHosts, opts.AdminHost...)
	if opts.AdminTailscale {
		if ts := tailscaleIP(); ts != "" {
			srv.AllowedHosts = append(srv.AllowedHosts, ts)
			tsAddr := net.JoinHostPort(ts, adminTailscalePort)
			log.Printf("also listening for the admin API on Tailscale %s", tsAddr)
			go func() { errc <- fmt.Errorf("admin API tailscale: %w", admin.Serve(tsAddr, srv, false)) }()
		} else {
			log.Printf("warning: --admin-tailscale set but no tailnet address (100.64.0.0/10) found")
		}
	}
	go func() { errc <- fmt.Errorf("admin API: %w", admin.Serve(opts.AdminAddr, srv, true)) }()
	go func() { errc <- fmt.Errorf("agent API: %w", d.agentAPI.Serve(opts.AgentAPIAddr)) }()
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
func (d *Daemon) agents() ([]wg.Peer, map[string]netip.Addr, error) {
	list, err := d.st.Agents()
	if err != nil {
		return nil, nil, err
	}
	var peers []wg.Peer
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
		peers = append(peers, wg.Peer{PublicKey: key, Address: a.Address})
	}
	return peers, addr, nil
}
