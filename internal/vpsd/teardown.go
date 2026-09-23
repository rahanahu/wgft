//go:build linux

package vpsd

// 撤去(アンインストール、仕様 10.3 節)。vpsd が自分で作ったものだけを消し、
// 手で足したもの(ファイアウォールのポート、他テーブルの wg 参照行、ip_forward)は
// 一覧を出して手で戻してもらう。停止した vpsd の後片付けとして行い、稼働中なら拒否する。

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	ctconv "github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// 撤去のために vpsd が起動時に残す meta。teardown が --state だけで手掛かりを得られる。
const (
	metaWGInterface    = "teardown_wg_interface"
	metaWGPort         = "teardown_wg_port"
	metaAgentAPIPort   = "teardown_agent_api_port"
	metaIPForwardSetAt = "ip_forward_set_by_wgft_at"
)

// recordTeardownHints records the values `wgft server teardown` needs (10.3 節) to find what to
// remove without a --wg-interface flag of its own. A write failure here is not fatal to startup
// (this hint is only ever read by a later, separate teardown run), but it must not be silent: an
// operator who never sees it in the log has no way to know teardown may later have to guess
// (design.md 10.5・10.3 節).
func recordTeardownHints(st *store.Store, opts Options) {
	if err := st.SetMeta(metaWGInterface, []byte(opts.WGInterface)); err != nil {
		log.Printf("warning: recording the wg interface name for teardown failed: %v; a later `wgft server teardown` may not find %s and will say so", err, opts.WGInterface)
	}
	if err := st.SetMeta(metaWGPort, []byte(strconv.Itoa(int(opts.WGPort)))); err != nil {
		log.Printf("warning: recording the wg port for teardown's manual-restore list failed: %v", err)
	}
	if _, port, err := net.SplitHostPort(opts.AgentAPIAddr); err == nil {
		if err := st.SetMeta(metaAgentAPIPort, []byte(port)); err != nil {
			log.Printf("warning: recording the agent API port for teardown's manual-restore list failed: %v", err)
		}
	}
}

// TeardownOptions は撤去の指定。
type TeardownOptions struct {
	DBPath string
	Purge  bool // 状態ファイル(鍵・証明書含む SQLite 3 ファイル)も消す
	DryRun bool // 消すものと一覧を出すだけ
	Yes    bool // --purge の確認を省く
	Adopt  bool // 鍵が一致しない/状態ファイルが無いときでも wg を消す
}

// Teardown は撤去を実行する。out に進捗と「手で戻す一覧」を書く。
func Teardown(opts TeardownOptions, out io.Writer) error {
	// 停止した vpsd の後片付けとして行う。稼働中なら何もしないで拒否する。
	if locked, err := flock.IsLocked(opts.DBPath); err == nil && locked {
		return fmt.Errorf("server is running; stop it first with systemctl disable --now wgft")
	}

	iface := "wgft0"
	// conntrack の収束に使うアドレス帯。SQLite に記録した wg_address(仕様 11a 節)を優先し、無ければ既定
	wgNet := netip.MustParsePrefix("10.200.0.0/24")
	var serverKey wgtypes.Key
	var manual []string
	haveState := false
	userspace := false // 記録されたモードが userspace なら、カーネルには消すものが無い(仕様 6.3 節)
	if _, err := os.Stat(opts.DBPath); err == nil {
		haveState = true
		st, err := store.Open(opts.DBPath)
		if err != nil {
			return fmt.Errorf("server database: %w", err)
		}
		defer st.Close()
		if b, e := st.GetMeta(metaWGInterface); e == nil && len(b) > 0 {
			iface = string(b)
		} else {
			// 記録が無い(recordTeardownHints が一度も成功していない)か読めない場合、既定名を
			// 仮定していることを出力に出す。黙って仮定すると、--adopt-existing(鍵の一致を
			// 見ずに削除する)と組み合わさったとき、実際とは無関係な同名のインタフェースを
			// 消しかねない(design.md 10.3・10.5 節)。
			fmt.Fprintf(out, "warning: no recorded wg interface name in the server database: %v; assuming the default %s; if the server used a different --wg-interface, this teardown will not find it, and --adopt-existing could delete an unrelated interface named %s\n", e, iface, iface)
		}
		if b, e := st.GetMeta(serverKeyMeta); e == nil && len(b) == wgtypes.KeyLen {
			serverKey, _ = wgtypes.NewKey(b)
		}
		if b, e := st.GetMeta(wgAddressMeta); e == nil && len(b) > 0 {
			if p, perr := netip.ParsePrefix(string(b)); perr == nil {
				wgNet = p.Masked()
			} else {
				fmt.Fprintf(out, "warning: recorded wg address %q is invalid; using %s for the conntrack cleanup\n", b, wgNet)
			}
		}
		if b, e := st.GetMeta(modeMeta); e == nil && string(b) == modeUserspace {
			userspace = true
		}
		manual = manualRestoreList(st, userspace, iface)
	} else {
		fmt.Fprintf(out, "server database %s is missing, so assuming the default interface name %s; ownership cannot be confirmed by key, so --adopt-existing is required to delete it\n", opts.DBPath, iface)
	}

	// 事前判定:wg インタフェースが自分のものでなければ、何も消さずに中止する。
	if !opts.Adopt && !userspace {
		owned, exists, err := wg.Owned(iface, serverKey)
		if err != nil {
			return fmt.Errorf("check ownership of wg %s: %w", iface, err)
		}
		if exists && !owned {
			return fmt.Errorf("wg %s was not created by wgft, key does not match%s; refusing to avoid deleting someone else's wg; pass --adopt-existing to adopt and delete it", iface, map[bool]string{true: "; no server database", false: ""}[!haveState])
		}
	}

	if userspace {
		fmt.Fprint(out, "userspace mode: nothing to remove in the kernel; no nftables table, no wg interface")
	} else {
		fmt.Fprintf(out, "removing: table inet wgft / wg %s / conntrack entries created by wgft", iface)
	}
	if opts.Purge {
		fmt.Fprintf(out, " / server database %s incl. -wal and -shm", opts.DBPath)
	}
	fmt.Fprintln(out)

	if opts.DryRun {
		printManual(out, manual)
		return nil
	}
	if opts.Purge && !opts.Yes {
		return fmt.Errorf("--purge deletes keys and certificates and requires agents to re-register; pass --yes to continue")
	}

	if userspace {
		purgeState(opts, out)
		printManual(out, manual)
		return nil
	}

	// 1. table inet wgft(自分のテーブルだけ。既に無ければ何もしない)
	if err := nft.DeleteTable(); err != nil {
		return fmt.Errorf("delete nft table: %w", err)
	}
	fmt.Fprintln(out, "deleted table inet wgft")

	// 2. conntrack 収束(ルール 0 件で、wgft 由来の DNAT 済みエントリを消す。帯は記録した wg_address)
	if n, err := ctconv.Converge(nil, wgNet); err != nil {
		fmt.Fprintf(out, "warning: conntrack converge failed: %v\n", err)
	} else {
		fmt.Fprintf(out, "deleted %d conntrack entries created by wgft\n", n)
	}

	// 3. wg インタフェース(所有判定は上で済み。--adopt-existing なら判定を飛ばして消す)
	if deleted, err := wg.DeleteLink(iface); err != nil {
		return fmt.Errorf("delete wg: %w", err)
	} else if deleted {
		fmt.Fprintf(out, "deleted wg %s\n", iface)
	} else {
		fmt.Fprintf(out, "wg %s did not exist\n", iface)
	}

	// 4. --purge:状態ファイル(WAL の -wal, -shm と、隣の .lock も)
	purgeState(opts, out)

	printManual(out, manual)
	return nil
}

// purgeState は --purge のときだけ、サーバのデータベースとその付随ファイルを消す。
func purgeState(opts TeardownOptions, out io.Writer) {
	if !opts.Purge {
		return
	}
	targets := []string{opts.DBPath, opts.DBPath + "-wal", opts.DBPath + "-shm", flock.LockPath(opts.DBPath)}
	for _, p := range targets {
		if err := os.Remove(p); err == nil {
			fmt.Fprintf(out, "deleted %s\n", p)
		} else if !os.IsNotExist(err) {
			fmt.Fprintf(out, "warning: cannot delete %s: %v\n", p, err)
		}
	}
}

// manualRestoreList は「手で戻す一覧」を SQLite と meta から具体値で作る。
func manualRestoreList(st *store.Store, userspace bool, iface string) []string {
	var list []string

	// ファイアウォールで開けたポート
	if b, err := st.GetMeta(metaWGPort); err == nil && len(b) > 0 {
		list = append(list, "close UDP "+string(b)+" opened in the firewall for WireGuard")
	}
	if b, err := st.GetMeta(metaAgentAPIPort); err == nil && len(b) > 0 {
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
		list = append(list, "delete by hand the unit or container that ran the server, its env, the binary, and the data directory; it remains unless --purge")
		return list
	}

	// ip_forward
	if b, err := st.GetMeta(metaIPForwardSetAt); err == nil && len(b) > 0 {
		list = append(list, "net.ipv4.ip_forward: wgft set it 0->1 at "+string(b)+"; if nothing else uses forwarding, restore with `sysctl -w net.ipv4.ip_forward=0`, and delete the file in /etc/sysctl.d if it was made persistent")
	} else {
		list = append(list, "net.ipv4.ip_forward: wgft did not change it, already 1; no action needed")
	}

	// 他テーブルの wg 参照行(自動では戻さない。所在を案内)
	list = append(list, "if you added lines to other tables as server check suggested, e.g. `oifname \""+iface+"\" ...` for DOCKER-USER or FORWARD, restore them by hand; check their location with `nft list ruleset | grep "+iface+"`")

	// wgft が置いたものではないファイル
	list = append(list, "delete by hand the systemd unit and env: /etc/systemd/system/wgft.service, /etc/wgft/; the binary: /usr/local/bin/wgft; and the state directory: /var/lib/wgft, which remains unless --purge")

	return list
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
