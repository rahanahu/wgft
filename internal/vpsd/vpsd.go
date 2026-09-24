//go:build linux

// Package vpsd は VPS 側のデーモン。
// wg0 を宣言に収束させ、SQLite のルールを nftables に適用し、エージェント用 API と管理用 API を待ち受ける。
//
// ファイルの分け方:
//   - vpsd.go: Options、Daemon、Run(起動の配線)
//   - dataplane.go: 転送面(カーネルの wg・nftables・conntrack)へのインタフェースとカーネル実装
//   - dataplane_userspace.go: ユーザー空間モードの転送面(internal/dataplane/userspace の Backend)を包む層
//   - apply.go: wg の立ち上げとルールの適用(bringUpWG、applyNFT。Reconciler が動かす)
//   - hold.go: 起動の保留(最初の適用が失敗したときの待ち方。設計文書 11b 節)
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
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/internal/reconcile"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/internal/startup"
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
	"sync/atomic"
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
	// Limits は同時フロー数のプロセス全体の予算(仕様 7 節、Resource Guard)。ゼロ値の項目は既定値
	Limits resource.Limits
	// AdmissionLimits は vpsd だけが持つ接続元 IP ごとの上限(仕様 7 節、Admission Policy)。
	// ゼロ値の項目は既定値。上限を外すのは policy.PerSourceOff
	AdmissionLimits policy.AdmissionLimits
	// Version は起動ログに出す wgft のバージョン(cmd/wgft の effectiveVersion)。空なら省く。
	Version string
}

// Daemon は動いている vpsd。管理用 API の Backend を実装する。
type Daemon struct {
	opts      Options
	st        *store.Store
	reserved  proto.Reserved
	serverKey wgtypes.Key
	// timeouts は、エージェントに配る conntrack の UDP タイムアウト 2 値である(仕様 4 節)。
	// 起動の保留(設計文書 11b 節)の間は管理用 API が先に応答を始めていて、保留が解けた時点で
	// この値が入るので、待ち受けと同時に書き換わりうる。読み書きは udpTimeouts を通す。
	timeouts atomic.Pointer[linux.UDPTimeouts]

	network   netip.Prefix // 10.200.0.0/24
	startedAt time.Time
	kernel    string
	nftVer    string
	agentAPI  *agentapi.Server
	hub       *stream.Hub
	proxy     *proxyrelay.Manager
	flaps     *flapState
	// lag はエージェントごとのルール集合の世代の遅れの始まり(genlag.go、設計文書 10.2a 節)
	lag genLag

	mu sync.Mutex // ルール・エージェントの変更と、wg0・nftables の適用を直列化する

	// dp は転送面。カーネル(nftables + カーネル WireGuard、仕様 6.1 節)とユーザー空間(仕様 6.3 節)の 2 つの実装がある
	dp serverDataplane
	// rec は dp とプロキシモードの中継を 1 つのトランザクションで動かし、Desired と Active を持つ
	// (設計文書 7a.3 節)。最初の applyNFT で作る
	rec *reconcile.Reconciler
	// notActive はログに記録済みのルール単位の失敗(ルール ID → 理由)。同じ失敗を再試行のたびに
	// ログへ出さないために持つ(apply.go の ruleFailureLog)
	notActive map[string]string
	// lastConvergeErr は observeOnce と retryOnce が直前に出した失敗の行。同じ失敗を通知や再試行の
	// たびに出さないために持つ(apply.go の logConverge)。
	lastConvergeErr string
	// lastRepairErr は、戻れない地点の後の修復が残っているあいだの失敗の行。同じ失敗を再試行の
	// たびに出さないために持つ(apply.go の logRepair)。
	lastRepairErr string
	// applied は、起動の保留(設計文書 11b 節)の間だけ持つ channel である。どの経路の適用でも、
	// 成功した時点で apply が閉じ、保留のループがそれを見て起動の残りに進む(hold.go)。
	// 保留に入っていない間は nil である。
	applied chan struct{}
	// holdReason は、起動の保留の間に最後に出した適用の失敗の理由である。同じ理由の試し直しを
	// ログに出さず、理由が変わったときだけ 1 行出すために持つ(hold.go の retryHold)。
	holdReason string
	// afterMismatchAcksRead は単体テスト用の差し込み口。judgeIPMismatch が確認済みの組を読んだ
	// 直後に呼ぶ。本番では nil。
	afterMismatchAcksRead func()
}

// reservedPorts は Daemon.reserved を組む。vpsd 自身が既に使っているポートへの listen_port を
// store.ApplyBatch(proto.ValidateUpsert 経由)が拒むための、予約ポートの正本である。
// internal/vpsd/admin の ReservedFromServerInfo(CLI の `rule add`/`rule set --dry-run` と
// Web UI の読み込みの確認が使う)は、この規則を admin.ServerInfo から組み立て直した写しであり、
// 入力が Options ではなく admin.ServerInfo(管理用 API の GET /api/v1/server か、同一プロセス内の
// ServerInfo() が返す値)である点が違う。WireGuard のポートは常に予約する。管理用 API のポートは
// AdminAddr が host:port として構文解析できたときだけ予約する(既定の Unix ソケット
// "unix:///run/wgft/admin.sock" は予約しない。host:port 以外の理由で構文解析に失敗した値も
// 同様に予約しない。固定のポートを代わりに予約したりはしない)。エージェント用 API のポートは
// AgentAPIAddr を net.SplitHostPort で分けて取る(admin.ServerInfo.AgentAPIPort は既にこの分割を
// 済ませた文字列を持つ点が異なる)。この関数を切り出す前は、この組み立てを検査するテストが
// リポジトリのどこにも無く、例えば管理用 API のポートの予約を落とす変異を入れても
// `go test ./...` はどこも落ちなかった。
func reservedPorts(opts Options) proto.Reserved {
	reserved := proto.Reserved{opts.WGPort: "WireGuard"}
	if ap, err := netip.ParseAddrPort(opts.AdminAddr); err == nil {
		reserved[ap.Port()] = "admin API"
	}
	if _, port, err := net.SplitHostPort(opts.AgentAPIAddr); err == nil {
		if p, err := netip.ParseAddrPort("0.0.0.0:" + port); err == nil {
			reserved[p.Port()] = "agent API"
		}
	}
	return reserved
}

// Run は起動して、シグナルまで動く。
func Run(opts Options) error {
	st, err := store.Open(opts.DBPath)
	if errors.Is(err, store.ErrSchemaNewer) {
		// 新しい版が書いたデータベースは、この版では読めない。運用者がその版を入れ直すか
		// 控えを戻すまで同じ結果になるので、prerequisite の拒否にする(設計文書 11b 節)。
		return startup.Prerequisite("server database", "%s: %v. Install the newer wgft again, or restore a copy of the database taken with this version", opts.DBPath, err)
	}
	if err != nil {
		return fmt.Errorf("server database %s: %w", opts.DBPath, err)
	}
	defer st.Close()

	// 既存の名前の検証。消さずに警告だけする
	if bad, err := st.InvalidAgentNames(); err != nil {
		log.Printf("warning: checking agent names: %v", err)
	} else {
		for _, n := range bad {
			log.Printf("warning: agent %q has a name that does not match the current validation rule from spec 5.1; keeping it as is", n)
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
	d.reserved = reservedPorts(opts)
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
	// 構文は入口(cmd/wgft の buildServerOptions)で弾いてあるので、ここへ届くのは入口を通らない
	// 呼び出しだけである。二重の守りとして、届いた場合も設定の値の誤りとして拒否する
	// (設計文書 11b 節。かつてはここがただのエラーで、終了コード 1 の再起動の繰り返しになっていた)。
	if d.network, err = netip.ParsePrefix(opts.WGAddress); err != nil {
		return startup.Config("WGFT_WG_ADDRESS", "%q is not a valid address/prefix such as 10.200.0.1/24: %v", opts.WGAddress, err)
	}
	if err := d.bringUpWG(); err != nil {
		return err
	}
	// teardown が --state だけで正しいインタフェース名とポートを知れるよう meta に残す。
	recordTeardownHints(st, opts)
	d.startedAt = time.Now()
	d.kernel = readKernel()
	d.nftVer = readNFTVersion()

	// 他テーブルの検査(仕様 6.1 節)。起動時は警告と提示だけで、自動では書き換えない
	rep, err := d.dp.Inspect()
	if err != nil {
		return fmt.Errorf("nftables check: %w", err)
	}
	for _, f := range rep.Findings {
		log.Printf("warning: %s", f)
	}
	// 自分の待ち受けポート(WireGuard の UDP と agent API の TCP)も、同じ input firewall の検査に
	// 含める(仕様 4・6.1 節。実機の Debian 13 で見つかった。改訂の記録参照)。proxyInputHints と
	// 同じく、読めなければ黙って省く(非 root や、userspace モードで nftables が無い場合)
	for _, t := range ownPortTargets(opts) {
		if lines, err := d.dp.InputPortSuggestions(proto.PortRange{Lo: t.port, Hi: t.port}, t.proto); err == nil && len(lines) > 0 {
			log.Printf("warning: input firewall blocks the %s port %d/%s; add the following:", t.purpose, t.port, t.proto)
			for _, l := range lines {
				log.Printf("    %s", l)
			}
		}
	}
	if f := d.dp.EnableIPForward(st); f != nil {
		log.Printf("warning: %s", f)
	}
	// カーネルモードのプロキシ中継も同じ上限で数える(仕様 6.2 節)。Admission Policy は、待ち受けを
	// 開けたポートに付ける nftables の行が判定する(6.1、7 節)ので、中継では判定しない。起動時の
	// applyNFT が待ち受けを開き、開けたポートだけに行を付けるよう、先に作る
	lim := opts.Limits.WithDefaults()
	proxyOpts := proxyrelay.Options{Pool: resource.NewPool(lim.TCPTotal)}
	if uspace != nil {
		// ユーザー空間モードでは netstack 越しにエージェントへ
		proxyOpts.Dial = func(addr string) (net.Conn, error) { return uspace.Dial("tcp", addr) }
		proxyOpts.Pool = uspace.TCPPool() // 同時接続数は relay と合計で数える(仕様 7 節)
		// Admission Policy のすべての段を Go の評価器が判定する。接続元 IP ごとの同時接続数は、
		// Transparent の TCP のルールと合わせて数える(6.2、6.3 節)
		proxyOpts.Admit = uspace.AdmitRelayFlow
	}
	d.proxy = proxyrelay.New(proxyOpts)
	// 起動時に SQLite のルールを適用する(手作業で変えられたテーブルは宣言に戻る)
	rules, err := st.Rules()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return d.serve(ctx, rules)
}

// serve は、サーバのデータベースと転送面が立ち上がった後の起動の残りである。最初のルールの適用、
// 失敗したときの起動の保留(設計文書 11b 節)、conntrack の UDP タイムアウトの読み取り、待ち受け、
// 起動完了の行、収束のループの順に進み、ctx が切れるか待ち受けが終わるまで戻らない。
// Run から分けてあるのは、転送面を差し替えた単体テストがこの順序を確かめられるようにするためである
// (hold_test.go)。
func (d *Daemon) serve(ctx context.Context, rules []proto.Rule) error {
	var err error
	// エージェント用 API の証明書と stream の hub は、どの待ち受けを開くより先に作る。起動の保留の
	// 間も管理用 API がこの 2 つを読む(admin_backend.go の Agents と JoinString)ためである。
	if d.agentAPI, err = agentapi.New(d.st, d); err != nil {
		return fmt.Errorf("agent API: %w", err)
	}
	d.hub = d.newHub(d)
	d.hub.RateLimit = d.agentAPI.Allow
	d.agentAPI.Handle("GET /api/v1/agents/stream", d.hub.ServeHTTP)
	_ = d.st.PurgeExpiredJoinTokens()

	errc := make(chan error, 3)
	// openAdmin は管理用 API の待ち受けを開く。起動の保留に入るときと、保留を経ない起動の最後の
	// 両方から呼ぶので、2 度開かないようにする。
	adminUp := false
	openAdmin := func() error {
		if adminUp {
			return nil
		}
		if err := d.listenAdmin(ctx, errc); err != nil {
			return err
		}
		adminUp = true
		return nil
	}

	// テーブルの適用、続いて conntrack の UDP タイムアウトと表の大きさの警告を読む。この順序と、
	// 適用後もなお読めない場合の扱いは apply.go の applyThenReadConntrack を見よ(設計文書 11b 節)。
	// 最初の適用が失敗したときは終了せず、管理用 API だけを開いて試し直す(起動の保留。11b 節)。
	held := false
	timeouts, err := applyThenReadConntrack(
		func() error {
			err := d.applyFirst(rules)
			if err == nil {
				return nil
			}
			// 起動の拒否は保留の対象にしない。運用者が手を入れるまで消えない失敗なので、管理用 API を
			// 開いて待つ意味が無く、従来どおり終了コード 3 で止める(設計文書 11b 節の入る条件)
			if startup.IsRefusal(err) {
				return err
			}
			held = true
			return d.hold(ctx, err, openAdmin, errc)
		},
		d.dp.ReadUDPTimeouts,
		d.dp.ConntrackWarning,
	)
	if err != nil {
		if errors.Is(err, errHoldStopped) {
			// 保留の間に ctx が切れた。このプロセスは何も公開していないので、そのまま終える。
			// カーネルに前のプロセスの公開が残っていることはあるので、主語をこのプロセスに限る
			log.Printf("shutting down during the startup hold; this process never applied the rules")
			return nil
		}
		return err
	}
	d.timeouts.Store(&timeouts)
	if held {
		// 保留の間に運用者が宣言を直しているので、起動完了の行に出す数を読み直す
		if rules, err = d.st.Rules(); err != nil {
			return err
		}
	}
	if err := openAdmin(); err != nil {
		return err
	}
	agentLn, err := d.agentAPI.Listen(d.opts.AgentAPIAddr)
	if err != nil {
		return fmt.Errorf("agent API: %w", err)
	}
	// 起動完了の行は、データプレーンの適用と全部の待ち受けが済んでから出す(仕様 10.4 節)。
	// これより前に失敗すれば、この行は出ずにプロセスが終わる。起動の保留の間も出さない(11b 節)
	gen, err := d.st.Generation()
	if err != nil {
		return err
	}
	_, agentAddr, err := d.agents()
	if err != nil {
		return err
	}
	log.Printf("wgft %s server started: mode %s, interface %s, generation %d, %d rules, %d agents",
		d.opts.Version, d.opts.Mode, d.opts.WGInterface, gen, len(rules), len(agentAddr))
	go func() { errc <- fmt.Errorf("agent API: %w", d.agentAPI.ServeListener(agentLn)) }()
	go d.watchIPMismatch(ctx)
	go d.convergeLoop(ctx)
	go d.pollUDPReplies(ctx)
	select {
	case <-ctx.Done():
		if d.opts.Mode == modeUserspace {
			log.Printf("shutting down")
		} else {
			log.Printf("shutting down; keeping interface %s and the table", d.opts.WGInterface)
		}
		return nil
	case err := <-errc:
		return err
	}
}

// listenAdmin は管理用 API の待ち受けを開いて応答を始める。--admin-tailscale の追加の待ち受けも
// 同じ管理用 API なので、ここで一緒に開く。起動の保留の間に開くのはこの待ち受けだけであり、
// 待ち受けそのものの失敗は従来どおりの誤りで、cmd/wgft が終了コード 1 にする(設計文書 11b 節)。
func (d *Daemon) listenAdmin(ctx context.Context, errc chan<- error) error {
	srv := admin.New(d)
	srv.AllowedHosts = append(srv.AllowedHosts, d.opts.AdminHost...)
	if d.opts.AdminTailscale {
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
			log.Printf("also listening for the admin API on Tailscale %s, %s", tsAddr, detail)
			go func() { errc <- fmt.Errorf("admin API tailscale: %w", admin.ServeListener(tsLn, srv)) }()
		} else if other != "" {
			log.Printf("warning: --admin-tailscale set but %s has a 100.64.0.0/10 address and is not a Tailscale interface; the admin API is NOT listening there", other)
		} else {
			log.Printf("warning: --admin-tailscale set but no tailnet address within 100.64.0.0/10 found")
		}
	}
	adminLn, err := admin.Listen(d.opts.AdminAddr, true)
	if err != nil {
		return fmt.Errorf("admin API: %w", err)
	}
	go func() { errc <- fmt.Errorf("admin API: %w", admin.ServeListener(adminLn, srv)) }()
	return nil
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

// newHub は stream の hub を作り、Daemon が受け取る接続とハートビートの事象をつなぐ。backend は
// serve では Daemon 自身で、テストは偽物を渡してつなぎ方だけを確かめる。
func (d *Daemon) newHub(backend stream.Backend) *stream.Hub {
	h := stream.New(backend)
	d.flaps = &flapState{hist: map[string]map[string][]ipObs{}}
	// stream の接続元 IP を接続の事象で記録し、往復を検知する(仕様 5.2 節)
	h.OnStreamConnect = func(agent, from string) { d.observeFlap(agent, "stream", "stream source", from) }
	// ハートビートが報告した世代を、server の今の世代と突き合わせて遅れの始まりを記録する。
	// server の世代もここで読むので、再起動の後の最初のハートビートから数え始める
	h.OnHeartbeat = d.observeAgentGeneration
	return h
}
