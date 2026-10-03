//go:build linux

// Package teardown は `wgft server teardown` を持つ。撤去(アンインストール、仕様 10.3 節)。vpsd が
// 自分で作ったものだけを消し、手で足したもの(ファイアウォールのポート、他テーブルの wg 参照行、
// ip_forward)は一覧を出して手で戻してもらう。停止した vpsd の後片付けとして行い、稼働中なら拒否する。
// 稼働中の server(internal/vpsd の Daemon)には依存せず、internal/vpsd の下位の package のうち
// store だけを使う。撤去の手掛かりを起動時に記録する RecordHints も、読む側と同じこの package に置く。
package teardown

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	ctconv "github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// Hints は撤去の手掛かりとして起動時に記録する、server の設定の値である。各項目の意味は
// internal/vpsd.Options の同じ名前の項目と同じである。
type Hints struct {
	WGInterface  string
	WGPort       uint16
	AgentAPIAddr string
}

// RecordHints records the values `wgft server teardown` needs (10.3 節) to find what to
// remove without a --wg-interface flag of its own. A write failure here is not fatal to startup
// (this hint is only ever read by a later, separate teardown run), but it must not be silent: an
// operator who never sees it in the log has no way to know teardown may later have to guess
// (design.md 10.5・10.3 節).
func RecordHints(st *store.Store, h Hints) {
	if err := st.SetMeta(store.MetaTeardownWGInterface, []byte(h.WGInterface)); err != nil {
		log.Printf("warning: recording the wg interface name for teardown failed: %v; a later `wgft server teardown` may not find %s and will say so", err, h.WGInterface)
	}
	if err := st.SetMeta(store.MetaTeardownWGPort, []byte(strconv.Itoa(int(h.WGPort)))); err != nil {
		log.Printf("warning: recording the wg port for teardown's manual-restore list failed: %v", err)
	}
	if _, port, err := net.SplitHostPort(h.AgentAPIAddr); err == nil {
		if err := st.SetMeta(store.MetaTeardownAgentAPIPort, []byte(port)); err != nil {
			log.Printf("warning: recording the agent API port for teardown's manual-restore list failed: %v", err)
		}
	}
}

// Options は撤去の指定。
type Options struct {
	DBPath string
	Purge  bool // 状態ファイル(鍵・証明書含む SQLite 3 ファイル)も消す
	DryRun bool // 消すものと一覧を出すだけ
	Yes    bool // --purge の確認を省く
	Adopt  bool // 鍵が一致しない/状態ファイルが無いときでも wg を消す
}

// ops は撤去がロック、サーバのデータベース、カーネル、ファイルに触れる操作である。単体テストだけが
// 差し替える。
type ops struct {
	// inspectLock はロックファイルを作らずにロックの状態を読む。何も変えない撤去だけが使う。
	inspectLock func(dbPath string) (flock.State, error)
	// acquireLock はロックを取り、ロックファイルが無ければ作る。作ったかどうかも返す。
	acquireLock func(dbPath string) (*flock.Lock, bool, error)
	// adoptOwner は、撤去が作ったロックファイルの持ち主を dir の持ち主に合わせる。
	adoptOwner func(l *flock.Lock, dir string) error
	// mkdirAll は、何かを変える撤去が、無い置き場のディレクトリを作る。
	mkdirAll    func(dir string) error
	openStore   func(path string) (*store.Store, error)
	wgOwned     func(iface string, key wgtypes.Key) (owned, exists bool, err error)
	deleteTable func() error
	converge    func(wgNet netip.Prefix) (int, error)
	deleteLink  func(iface string) (bool, error)
	remove      func(path string) error
	// readIPForward は net.ipv4.ip_forward の今の値を読む。書き込みも probe もしない。
	readIPForward func() (string, error)
}

func defaultOps() ops {
	return ops{
		inspectLock: flock.Inspect,
		acquireLock: flock.AcquireCreating,
		adoptOwner:  adoptDirOwner,
		mkdirAll:    func(dir string) error { return os.MkdirAll(dir, 0o700) },
		// 撤去はデータベースを読むだけなので、スキーマの移行も権限の締め直しもしない読み取り専用で開く
		// (設計文書 10.3 節)。
		openStore:     store.OpenReadOnly,
		wgOwned:       wg.Owned,
		deleteTable:   nft.DeleteTable,
		converge:      func(wgNet netip.Prefix) (int, error) { return ctconv.Converge(nil, wgNet) },
		deleteLink:    wg.DeleteLink,
		remove:        os.Remove,
		readIPForward: linux.ReadIPForwardValue,
	}
}

// errServerRunning は、稼働中の server に対する撤去の拒否である。普通の誤りであり、終了コードは 1 である
// (設計文書 11b 節)。
var errServerRunning = errors.New("server is running; stop it first with systemctl disable --now wgft")

// Run は撤去を実行する。out に進捗と「手で戻す一覧」を書く。
func Run(opts Options, out io.Writer) error {
	return run(defaultOps(), opts, out)
}

func run(o ops, opts Options, out io.Writer) error {
	// 停止した vpsd の後片付けとして行う。稼働中なら何もしないで拒否する(設計文書 10.3 節)。
	// 何かを変える撤去は、ロックファイルが無ければ作ってロックを取り、データベースを開く前から
	// 終わるまで持つ。判定の後に起動した server が、撤去の途中で資源やデータベースを作り直さないため
	// である。server もデータベースを開く前にこのロックを取るので、撤去の間に起動した server は何にも
	// 触れずに終わる。ロックの状態を読めなければ、何も変えずに止まる。
	// --dry-run と、--yes の無い --purge は何も変えないので、ロックファイルを作らない Inspect で同じ
	// 判定だけをする。
	mutating := !opts.DryRun && (!opts.Purge || opts.Yes)
	if mutating {
		lock, err := lockForTeardown(o, opts.DBPath, out)
		if err != nil {
			return err
		}
		// --purge のロックファイルの削除(purgeState の最後)の後で放す
		defer lock.Release()
	} else {
		switch state, err := o.inspectLock(opts.DBPath); {
		case err != nil:
			return fmt.Errorf("cannot tell whether the server is running, so nothing was removed: reading the lock of %s failed: %w", opts.DBPath, err)
		case state == flock.Locked:
			return errServerRunning
		}
	}

	p, err := readPlan(o, opts, out)
	if err != nil {
		return err
	}

	// 事前判定:wg インタフェースが自分のものでなければ、何も消さずに中止する。
	if !opts.Adopt && !p.userspace {
		owned, exists, err := o.wgOwned(p.iface, p.serverKey)
		if err != nil {
			return fmt.Errorf("check ownership of wg %s: %w", p.iface, err)
		}
		if exists && !owned {
			return fmt.Errorf("wg %s was not created by wgft, key does not match%s; refusing to avoid deleting someone else's wg; pass --adopt-existing to adopt and delete it", p.iface, map[bool]string{true: "; no server database", false: ""}[!p.haveState])
		}
	}

	if p.userspace {
		fmt.Fprint(out, "userspace mode: nothing to remove in the kernel; no nftables table, no wg interface")
	} else {
		fmt.Fprintf(out, "removing: table inet wgft / wg %s / conntrack entries created by wgft", p.iface)
	}
	if opts.Purge {
		fmt.Fprintf(out, " / server database %s incl. -wal and -shm", opts.DBPath)
	}
	fmt.Fprintln(out)

	if opts.DryRun {
		printManual(out, p.manual)
		return nil
	}
	if opts.Purge && !opts.Yes {
		return fmt.Errorf("--purge deletes keys and certificates and requires agents to re-register; pass --yes to continue")
	}

	if p.userspace {
		purgeState(o, opts, out)
		printManual(out, p.manual)
		return nil
	}

	// 1. table inet wgft(自分のテーブルだけ。既に無ければ何もしない)
	if err := o.deleteTable(); err != nil {
		return fmt.Errorf("delete nft table: %w", err)
	}
	fmt.Fprintln(out, "deleted table inet wgft")

	// 2. conntrack 収束(ルール 0 件で、wgft 由来の DNAT 済みエントリを消す。帯は記録した wg_address)
	if n, err := o.converge(p.wgNet); err != nil {
		fmt.Fprintf(out, "warning: conntrack converge failed: %v\n", err)
	} else {
		fmt.Fprintf(out, "deleted %d conntrack entries created by wgft\n", n)
	}

	// 3. wg インタフェース(所有判定は上で済み。--adopt-existing なら判定を飛ばして消す)
	if deleted, err := o.deleteLink(p.iface); err != nil {
		return fmt.Errorf("delete wg: %w", err)
	} else if deleted {
		fmt.Fprintf(out, "deleted wg %s\n", p.iface)
	} else {
		fmt.Fprintf(out, "wg %s did not exist\n", p.iface)
	}

	// 4. --purge:状態ファイル(WAL の -wal, -shm と、最後に隣の .lock)
	purgeState(o, opts, out)

	printManual(out, p.manual)
	return nil
}

// lockForTeardown は、何かを変える撤去のためにサーバのデータベースのロックを取る(設計文書 10.3 節)。
// ロックファイルが無ければ作り、持ち主をデータベースの置き場の持ち主に合わせる。同梱の unit は server を
// DynamicUser で動かすので、root の撤去が作った 0600 のロックファイルが root の持ち物のまま残ると、
// server は次の起動でそれを開けずに終了コード 1 を繰り返す。systemd は持ち主の正しい置き場の中の
// ファイルの持ち主を直さない。
// 置き場のディレクトリが無ければ、server と同じく 0700 で作ってからロックを取る。取らずに進むと、
// 撤去の途中に起動した server が、systemd の作った置き場でロックを取って資源を作り、撤去がそれを消す。
// 撤去が作ったディレクトリは root の持ち物のまま残す。合わせる先の持ち主が無いためである。同梱の unit
// では、systemd が次の起動でその置き場を移して持ち主を付け替える。
func lockForTeardown(o ops, dbPath string, out io.Writer) (*flock.Lock, error) {
	dir := filepath.Dir(dbPath)
	if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
		if err := o.mkdirAll(dir); err != nil {
			return nil, fmt.Errorf("cannot lock the server database, so nothing was removed: creating its directory %s failed: %w", dir, err)
		}
		fmt.Fprintf(out, "created the directory %s of the server database to hold the server's lock during teardown\n", dir)
	}
	lock, created, err := o.acquireLock(dbPath)
	if errors.Is(err, flock.ErrLocked) {
		return nil, errServerRunning
	}
	if err != nil {
		return nil, fmt.Errorf("cannot tell whether the server is running, so nothing was removed: locking %s failed: %w", dbPath, err)
	}
	if created {
		if err := o.adoptOwner(lock, dir); err != nil {
			fmt.Fprintf(out, "warning: giving the lock file %s the owner of %s failed: %v; if the server runs as another user and then cannot open it, delete the file\n", flock.LockPath(dbPath), dir, err)
		}
	}
	return lock, nil
}

// adoptDirOwner は、ロックファイルの持ち主とグループを dir の持ち主とグループに合わせる。既に同じなら
// 何もしない。dir は symlink を辿って読む。同梱の unit の置き場 /var/lib/wgft は /var/lib/private/wgft
// への symlink であり、server の利用者が持つのはその先である。
func adoptDirOwner(l *flock.Lock, dir string) error {
	di, err := os.Stat(dir)
	if err != nil {
		return err
	}
	fi, err := l.Stat()
	if err != nil {
		return err
	}
	ds, ok1 := di.Sys().(*syscall.Stat_t)
	ls, ok2 := fi.Sys().(*syscall.Stat_t)
	if !ok1 || !ok2 {
		return errors.New("file owner is not available")
	}
	if ds.Uid == ls.Uid && ds.Gid == ls.Gid {
		return nil
	}
	return l.Chown(int(ds.Uid), int(ds.Gid))
}

// plan は、何かを消す前にサーバのデータベースから読み取った撤去の対象である。
type plan struct {
	iface     string
	wgNet     netip.Prefix // conntrack の収束に使うアドレス帯
	serverKey wgtypes.Key
	manual    []string
	haveState bool
	userspace bool // 記録されたモードが userspace なら、カーネルには消すものが無い(仕様 6.3 節)
}

// readPlan はサーバのデータベースを読み取り専用で開き、撤去の対象を読んで閉じる。--purge がファイルを
// 消す前に閉じるためである。
func readPlan(o ops, opts Options, out io.Writer) (plan, error) {
	p := plan{
		iface: "wgft0",
		// SQLite に記録した wg_address(仕様 11a 節)を優先し、無ければ既定
		wgNet: netip.MustParsePrefix("10.200.0.0/24"),
	}
	if _, err := os.Stat(opts.DBPath); err != nil {
		fmt.Fprintf(out, "server database %s is missing, so assuming the default interface name %s; ownership cannot be confirmed by key, so --adopt-existing is required to delete it\n", opts.DBPath, p.iface)
		return p, nil
	}
	p.haveState = true
	st, err := o.openStore(opts.DBPath)
	if err != nil {
		return p, fmt.Errorf("server database: %w", err)
	}
	defer st.Close()
	if b, e := st.GetMeta(store.MetaTeardownWGInterface); e == nil && len(b) > 0 {
		p.iface = string(b)
	} else {
		// 記録が無い(RecordHints が一度も成功していない)か読めない場合、既定名を
		// 仮定していることを出力に出す。黙って仮定すると、--adopt-existing(鍵の一致を
		// 見ずに削除する)と組み合わさったとき、実際とは無関係な同名のインタフェースを
		// 消しかねない(design.md 10.3・10.5 節)。
		fmt.Fprintf(out, "warning: no recorded wg interface name in the server database: %v; assuming the default %s; if the server used a different --wg-interface, this teardown will not find it, and --adopt-existing could delete an unrelated interface named %s\n", e, p.iface, p.iface)
	}
	if b, e := st.GetMeta(store.MetaServerKey); e == nil && len(b) == wgtypes.KeyLen {
		p.serverKey, _ = wgtypes.NewKey(b)
	}
	if b, e := st.GetMeta(store.MetaWGAddress); e == nil && len(b) > 0 {
		if pr, perr := netip.ParsePrefix(string(b)); perr == nil {
			p.wgNet = pr.Masked()
		} else {
			fmt.Fprintf(out, "warning: recorded wg address %q is invalid; using %s for the conntrack cleanup\n", b, p.wgNet)
		}
	}
	if b, e := st.GetMeta(store.MetaMode); e == nil && string(b) == store.ModeUserspace {
		p.userspace = true
	}
	p.manual = manualRestoreList(st, p.userspace, p.iface, o.readIPForward)
	return p, nil
}

// purgeState は --purge のときだけ、サーバのデータベースとその付随ファイルを消す。ロックファイルは
// 最後に消す。呼び出し側はその後でロックを放す(設計文書 10.3 節)。
func purgeState(o ops, opts Options, out io.Writer) {
	if !opts.Purge {
		return
	}
	targets := []string{opts.DBPath, opts.DBPath + "-wal", opts.DBPath + "-shm", flock.LockPath(opts.DBPath)}
	for _, p := range targets {
		if err := o.remove(p); err == nil {
			fmt.Fprintf(out, "deleted %s\n", p)
		} else if !os.IsNotExist(err) {
			fmt.Fprintf(out, "warning: cannot delete %s: %v\n", p, err)
		}
	}
}

// manualRestoreList は「手で戻す一覧」を SQLite と meta から具体値で作る。
func manualRestoreList(st *store.Store, userspace bool, iface string, readIPForward func() (string, error)) []string {
	var list []string

	// ファイアウォールで開けたポート
	if b, err := st.GetMeta(store.MetaTeardownWGPort); err == nil && len(b) > 0 {
		list = append(list, "close UDP "+string(b)+" opened in the firewall for WireGuard")
	}
	if b, err := st.GetMeta(store.MetaTeardownAgentAPIPort); err == nil && len(b) > 0 {
		list = append(list, "close TCP "+string(b)+" opened in the firewall for the agent API")
	}
	if rules, err := st.Rules(); err == nil {
		var ports []string
		for i := range rules {
			ports = append(ports, portRangeString(rules[i].Proto, rules[i].ListenPort))
		}
		if len(ports) > 0 {
			list = append(list, "close the published ports opened in the firewall, per rule: "+strings.Join(ports, ", "))
		}
	}

	if userspace {
		list = append(list, "delete the unit or container that ran the server, its env, the binary, and the data directory; the data directory remains unless --purge")
		return list
	}

	list = append(list, ipForwardLine(st, readIPForward))

	// 他テーブルの wg 参照行(自動では戻さない。所在を案内)
	list = append(list, "if you added lines to other tables as server check suggested, e.g. `oifname \""+iface+"\" ...` for DOCKER-USER or FORWARD, restore them by hand; check their location with `nft list ruleset | grep "+iface+"`")

	// wgft が置いたものではないファイル
	list = append(list,
		"delete the systemd unit and env: /etc/systemd/system/wgft.service, /etc/wgft/",
		"delete the binary: /usr/local/bin/wgft",
		"delete the state directory: /var/lib/wgft, which remains unless --purge",
	)

	return list
}

// ipForwardLine は「手で戻す一覧」の ip_forward の行を、6.1 節の 2 段の記録と今の値から作る
// (設計文書 10.3 節)。確定の記録があれば、wgft が 0 から 1 にしたと示す。予定の記録だけがあれば、
// 書いた後に記録できなかったか書けなかったかを区別できないので、変えたかもしれないとだけ示し、今の値を
// 添えて運用者に判断を任せる。どちらも無ければ、wgft は変えていないと示す。記録を読めなければ、
// どれとも言わない。
func ipForwardLine(st *store.Store, readIPForward func() (string, error)) string {
	const head = "net.ipv4.ip_forward: "
	confirmed, cerr := st.GetMeta(store.MetaIPForwardSetAt)
	planned, perr := st.GetMeta(store.MetaIPForwardWriteStartedAt)
	var recErrs []string
	for _, e := range []error{cerr, perr} {
		if e != nil && !errors.Is(e, store.ErrNotFound) {
			recErrs = append(recErrs, e.Error())
		}
	}
	cur, rerr := readIPForward()
	now := "it is now " + cur
	if rerr != nil {
		now = fmt.Sprintf("reading its current value failed: %v", rerr)
	}
	switch {
	case cerr == nil && len(confirmed) > 0:
		return head + "wgft set it 0->1 at " + string(confirmed) + "; if nothing else uses forwarding, restore with `sysctl -w net.ipv4.ip_forward=0`, and delete the file in /etc/sysctl.d if it was made persistent"
	case len(recErrs) > 0:
		return head + "reading wgft's record of changing it failed: " + strings.Join(recErrs, "; ") + "; " + now + "; check the current value and decide whether to restore it with `sysctl -w net.ipv4.ip_forward=0`"
	case perr == nil && len(planned) > 0:
		return head + "wgft read 0 and started to set it to 1 at " + string(planned) + ", but the result was not recorded, so wgft may have changed it; " + now + "; check the current value and decide; if wgft set it and nothing else uses forwarding, restore with `sysctl -w net.ipv4.ip_forward=0`"
	case rerr != nil:
		return head + "wgft did not change it; no action needed; " + now
	case cur == "1":
		return head + "wgft did not change it, already 1; no action needed"
	default:
		return head + "wgft did not change it, now " + cur + "; no action needed"
	}
}

func printManual(out io.Writer, manual []string) {
	if len(manual) == 0 {
		return
	}
	fmt.Fprintln(out, "\nrestore by hand, wgft does not revert these:")
	for _, m := range manual {
		fmt.Fprintln(out, "  - "+m)
	}
}

func portRangeString(p proto.Proto, r proto.PortRange) string {
	if r.Lo == r.Hi {
		return fmt.Sprintf("%s/%d", p, r.Lo)
	}
	return fmt.Sprintf("%s/%d-%d", p, r.Lo, r.Hi)
}
