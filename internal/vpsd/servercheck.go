//go:build linux

package vpsd

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// Check は起動せずに、そのモードで必要な検査を走らせて結果を書く読み取り専用コマンド
// (仕様 6.1・10.3・11a 節)。
// SQLite が無い初回でも、WGFT_MODE 未指定でも止まらない。非 root では nft の検査を省く。
func Check(opts Options, out io.Writer) error {
	mode := opts.Mode
	if mode == "" {
		mode = "unset"
	}
	fmt.Fprintf(out, "mode: %s\n", mode)
	fmt.Fprintf(out, "interface: %s / wg port: %d / address range: %s\n", opts.WGInterface, opts.WGPort, opts.WGAddress)

	// nft の検査(他テーブルの policy drop・DOCKER-USER・DNAT 衝突。仕様 6.1 節)。root が要る。
	// ユーザー空間モードは nftables も ip_forward も使わない(仕様 6.3 節)。
	root := os.Geteuid() == 0
	if mode == modeUserspace {
		fmt.Fprintln(out, "nft check: not used in userspace mode; rules are relayed by the wgft process")
	} else if !root {
		fmt.Fprintln(out, "nft check: skipped because not root; run sudo wgft server check")
	} else if rep, err := linux.Inspect(opts.WGInterface, nft.TableName); err != nil {
		fmt.Fprintf(out, "nft check: cannot run: %v\n", err)
	} else if len(rep.Findings) == 0 {
		fmt.Fprintln(out, "nft check: no problems")
	} else {
		fmt.Fprintln(out, "nft check: the following needs attention:")
		for _, f := range rep.Findings {
			fmt.Fprintf(out, "  - %s\n", f)
		}
	}
	if mode != modeUserspace {
		checkIPForward(out)
		checkConntrack(out)
	}
	// own ports の検査:host の input firewall が vpsd 自身の待ち受けポート(WireGuard の UDP と
	// agent API の TCP)を塞いでいないか。host の input firewall はモードに関係しない層なので、
	// userspace モードでも実行する(実機の Debian 13 で見つかった。改訂の記録参照)。
	if !root {
		fmt.Fprintln(out, "own ports check: skipped because not root; run sudo wgft server check")
	} else {
		checkOwnPorts(out, opts)
	}

	// SQLite があれば、記録済みのモード・アドレス帯との照合と、改名の検出を出す。
	if _, err := os.Stat(opts.DBPath); err != nil {
		fmt.Fprintln(out, "server database: not present yet, first run; skipping check against records")
		return nil
	}
	printDBModes(out, opts.DBPath)
	// 読み取り専用で開く。store.Open は権限を狭め、スキーマを移行するので、check では使わない(仕様 9 節)
	st, err := store.OpenReadOnly(opts.DBPath)
	if err != nil {
		printDBOpenFailure(out, err)
		return nil
	}
	defer st.Close()
	checkRecordedMode(out, st, opts.Mode)
	checkMeta(out, st, wgAddressMeta, "recorded address range", opts.WGAddress)
	// rule ports の検査:個々のルールの listen port が host の input firewall で塞がれていないか。
	// own ports check と同じく root が要り、rules は SQLite からしか読めないのでここで行う
	// (実機の Debian 13、ユーザー空間モードで見つかった。改訂の記録参照)。
	if !root {
		fmt.Fprintln(out, "rule ports check: skipped because not root; run sudo wgft server check")
	} else if rules, err := st.Rules(); err != nil {
		fmt.Fprintf(out, "rule ports check: cannot read rules: %v\n", err)
	} else {
		checkRulePorts(out, rules, mode)
	}
	if b, err := st.GetMeta(serverKeyMeta); err == nil && mode != modeUserspace {
		if k, err := wgtypes.NewKey(b); err == nil {
			if other, ok := wg.OtherDeviceWithKey(opts.WGInterface, k); ok {
				fmt.Fprintf(out, "warning: another interface %q with the same server key exists; suspect leftovers from changing WGFT_WG_INTERFACE\n", other)
			}
		}
	}
	return nil
}

// ownPortTarget は、input firewall との突き合わせ対象にする vpsd 自身の待ち受けポート 1 つ。
type ownPortTarget struct {
	purpose string // ログとエラーメッセージに出す呼び名("WireGuard"、"agent API")
	proto   proto.Proto
	port    uint16
}

// ownPortTargets は、host の input firewall と突き合わせる vpsd 自身の待ち受けポートを列挙する
// (仕様 4 節「VPS で外に開けるポートは次の 3 種類だけ」のうち、転送対象のポートを除く 2 つ)。
// 管理用 API(WGFT_ADMIN)は含めない。既定は Unix ソケットで、host:port にした場合も
// localhost や Tailscale のアドレスで使う想定であり(11 節)、インターネットから直接受ける
// ポートではないため、input firewall を開ける提示の対象にする理由が無い。
func ownPortTargets(opts Options) []ownPortTarget {
	targets := []ownPortTarget{{purpose: "WireGuard", proto: proto.UDP, port: opts.WGPort}}
	if _, portStr, err := net.SplitHostPort(opts.AgentAPIAddr); err == nil {
		if v, err := strconv.ParseUint(portStr, 10, 16); err == nil {
			targets = append(targets, ownPortTarget{purpose: "agent API", proto: proto.TCP, port: uint16(v)})
		}
	}
	return targets
}

// checkOwnPorts は、ownPortTargets の各ポートが host の input firewall で塞がれていないかを
// linux.InputPortSuggestions で確かめ、他の nft check と同じ Finding の形で表示する。呼び出し元は
// 事前に root を確かめておく(nftables の読み取りに要るため)。
func checkOwnPorts(out io.Writer, opts Options) {
	var findings []linux.Finding
	for _, t := range ownPortTargets(opts) {
		lines, err := linux.InputPortSuggestions(proto.PortRange{Lo: t.port, Hi: t.port}, t.proto, nft.TableName)
		if err != nil {
			fmt.Fprintf(out, "own ports check %s %d/%s: cannot run: %v\n", t.purpose, t.port, t.proto, err)
			continue
		}
		if len(lines) == 0 {
			continue
		}
		findings = append(findings, linux.Finding{
			Where:   "input firewall",
			Problem: fmt.Sprintf("blocks the %s port %d/%s; no agent could ever reach it from outside", t.purpose, t.port, t.proto),
			Suggest: lines,
		})
	}
	if len(findings) == 0 {
		fmt.Fprintln(out, "own ports check: no problems")
		return
	}
	fmt.Fprintln(out, "own ports check: the following needs attention:")
	for _, f := range findings {
		fmt.Fprintf(out, "  - %s\n", f)
	}
}

// checkRulePorts は、host の input firewall が個々のルールの listen port を塞いでいないかを確かめる。
// カーネルモードでは、host のソケットで受けるのはプロキシモード(Relay。TCP のみ)のルールだけで、
// Transparent なルールは他テーブルの DNAT と forward を経由し input を通らない(仕様 6.1・6.2 節)。
// ユーザー空間モードは vps_mode の区別に意味を持たず、有効なルールすべてが host のソケットで受ける
// 中継になるため、全ルールを対象にする(仕様 6.3 節)。判定は apply.go の proxyInputHints と同じ。
func checkRulePorts(out io.Writer, rules []proto.Rule, mode string) {
	var findings []linux.Finding
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		if mode != modeUserspace && r.VPSMode != proto.ModeProxy {
			continue
		}
		lines, err := linux.InputPortSuggestions(r.ListenPort, r.Proto, nft.TableName)
		if err != nil {
			fmt.Fprintf(out, "rule ports check %s %s/%s: cannot run: %v\n", r.ID, r.ListenPort, r.Proto, err)
			continue
		}
		if len(lines) == 0 {
			continue
		}
		findings = append(findings, linux.Finding{
			Where:   "input firewall",
			Problem: fmt.Sprintf("blocks rule %s's port %s/%s; the server binds it on the host, so a client would get no answer", r.ID, r.ListenPort, r.Proto),
			Suggest: lines,
		})
	}
	if len(findings) == 0 {
		fmt.Fprintln(out, "rule ports check: no problems")
		return
	}
	fmt.Fprintln(out, "rule ports check: the following needs attention:")
	for _, f := range findings {
		fmt.Fprintf(out, "  - %s\n", f)
	}
}

// printDBOpenFailure は、サーバのデータベースを開けなかった理由を出す。server check の終了コードは
// この場合も 0 のままなので(7a.11 節)、運用者は終了コードでなく出力でこの失敗に気付く必要がある。
// 新しい版が書いたスキーマ(store.SchemaNewerError)は、そのうちで運用者が最も見落としてはいけない
// 場合である。この版はそのデータベースをまったく読めず、ちょうど入れ替えの巻き戻しの最中、
// 新しい版が書いたデータベースに対して旧い版の server check を実行する場面で起きる。専用の、
// 他の行に紛れない文言にし、出力の先頭からでも末尾からでも読み落とさないよう 2 回出す
// (改訂の記録参照)。それ以外の理由(権限、他プロセスの保持、壊れたファイルなど)は、
// 従来どおり 1 行だけ出す。
func printDBOpenFailure(out io.Writer, err error) {
	var sne *store.SchemaNewerError
	if errors.As(err, &sne) {
		headline := fmt.Sprintf("server database: schema version %d is newer than this binary; this binary supports up to %d and cannot run with this database at all", sne.Version, sne.MaxSupported)
		fmt.Fprintln(out, headline)
		fmt.Fprintln(out, "server database: install the newer wgft again, or restore a copy of the database taken with this version")
		fmt.Fprintf(out, "server database: cannot open: %v\n", err)
		fmt.Fprintln(out, headline)
		return
	}
	fmt.Fprintf(out, "server database: cannot open: %v\n", err)
}

// printDBModes は、SQLite の本体と WAL の補助ファイルの権限を 1 行ずつ出す。0600 より広ければ、
// 次の起動で server が狭めることを添える(check 自身は変えない)。
func printDBModes(out io.Writer, path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		fi, err := os.Stat(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			fmt.Fprintf(out, "server database file mode: cannot read %s: %v\n", p, err)
			continue
		}
		perm := fi.Mode().Perm()
		if store.ExtraPerm(perm) != 0 {
			fmt.Fprintf(out, "server database file mode: %s is %04o; the server narrows it to %04o on its next start\n", p, perm, perm&^store.ExtraPerm(perm))
			continue
		}
		fmt.Fprintf(out, "server database file mode: %s is %04o\n", p, perm)
	}
}

// checkRecordedMode は、記録済みのモードと今回の設定を照合して 1 行出す。食い違いがあっても
// ここでは拒否しない。実際にモードを切り替えられるかどうかは、次の `server run` で
// reconcileModeAndAddress の関門(mode.go の modeGate)が決める。
func checkRecordedMode(out io.Writer, st *store.Store, want string) {
	have, err := st.GetMeta(modeMeta)
	if errors.Is(err, store.ErrNotFound) {
		fmt.Fprintln(out, "recorded mode: not recorded")
		return
	}
	if err != nil {
		fmt.Fprintf(out, "recorded mode: cannot read: %v\n", err)
		return
	}
	if want == "" || string(have) == want {
		fmt.Fprintf(out, "recorded mode: %s\n", have)
		return
	}
	// 種別を添えて、起動が止まる場合にどの拒否になるかを運用者に見せる(設計文書 11b 節)。
	fmt.Fprintf(out, "warning: the recorded mode is %s but the setting is %s; the mode change gate runs at start and refuses with [%s] if leftovers of the old mode remain\n",
		have, want, startup.CategoryModeGate)
}

// checkMeta は meta の記録と現在値を照合して 1 行出す。
func checkMeta(out io.Writer, st *store.Store, key, label, want string) {
	have, err := st.GetMeta(key)
	if errors.Is(err, store.ErrNotFound) {
		fmt.Fprintf(out, "%s: not recorded\n", label)
		return
	}
	if err != nil {
		fmt.Fprintf(out, "%s: cannot read: %v\n", label, err)
		return
	}
	if want == "" || string(have) == want {
		fmt.Fprintf(out, "%s: %s\n", label, have)
		return
	}
	// 記録との食い違いは、起動のたびに conflict の拒否になる。teardown --purge と再登録が要ることは
	// 起動時のエラーが示すので、ここでは種別だけを添える(設計文書 11b 節)。
	fmt.Fprintf(out, "warning: %s differs from the record %s; setting is %s; the server refuses to start with [%s]\n",
		label, have, want, startup.CategoryConflict)
}

// checkIPForward reports net.ipv4.ip_forward's current value (spec section 6.1). It never writes
// 1 itself: internal/platform/linux.IPForwardStatus stays read-only, only probing writability the
// same way EnableIPForward's real write would face at startup.
func checkIPForward(out io.Writer) {
	val, openErr, err := linux.IPForwardStatus()
	if err != nil {
		fmt.Fprintf(out, "ip_forward: cannot read %s: %v\n", linux.IPForwardPath, err)
		return
	}
	fmt.Fprintf(out, "ip_forward: %s\n", val)
	if val == "1" {
		return
	}
	if openErr != nil {
		finding := linux.Finding{
			Where:   "net.ipv4.ip_forward",
			Problem: fmt.Sprintf("is %s and not writable: %v; kernel-mode forwarding needs it at 1", val, openErr),
			Suggest: []string{"sysctl -w net.ipv4.ip_forward=1"},
		}
		fmt.Fprintf(out, "  - %s\n", finding)
	}
}

// checkConntrack は conntrack の表の使用状況を 1 行出し、上限が小さければ警告する。値は変えない。
// 実際の読み取りと閾値の判定は internal/platform/linux が持つ(agent の kernel backend でも使う
// ため。設計文書 7a.7 節)。
//
// nf_conntrack が一度もロードされていないホスト(新規インストール、他にロードする常駐が無い
// ホストは再起動のたびに)では、`server check` はテーブルを何も適用しないので読めない。これは
// カーネルモードの起動を止める条件ではない。`wgft server run` は自分の table inet wgft を適用した
// 後にこの値を読み、その適用の netlink 書き込みが nf_conntrack を自動ロードするため
// (internal/vpsd/vpsd.go の Run)、読めない状態はそれだけでは起動を妨げない。適用の後もなお
// 読めない場合は、再試行で直りうる失敗として終了コード 1 で終わり、unit が起動し直す
// (設計文書 11b 節)。
func checkConntrack(out io.Writer) {
	usage, err := linux.ReadConntrackUsage()
	if err != nil {
		finding := linux.Finding{
			Where:   "nf_conntrack_max",
			Problem: fmt.Sprintf("cannot read %s: %v", linux.ConntrackMaxPath, err),
			Suggest: []string{
				"expected when nf_conntrack has never loaded on this host; a fresh install, or every boot if nothing else loads it first",
				"harmless for kernel mode: `server run` loads nf_conntrack itself when it applies table inet wgft, before it reads this value",
				"the actual limit and usage cannot be shown before that first start; run server check again afterwards to see them",
			},
		}
		fmt.Fprintln(out, "conntrack: cannot read yet")
		fmt.Fprintf(out, "  - %s\n", finding)
		return
	}
	if usage.HaveCount {
		fmt.Fprintf(out, "conntrack: %d of %d entries in use\n", usage.Count, usage.Max)
	} else {
		fmt.Fprintf(out, "conntrack: max %d entries\n", usage.Max)
	}
	if f := usage.Finding(); f != nil {
		fmt.Fprintf(out, "  - %s\n", f)
	}
}
