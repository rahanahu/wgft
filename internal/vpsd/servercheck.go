package vpsd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/vpsd/check"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/wg"
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
	if mode == modeUserspace {
		fmt.Fprintln(out, "nft check: not used in userspace mode (rules are relayed by the wgft process)")
	} else if os.Geteuid() != 0 {
		fmt.Fprintln(out, "nft check: skipped because not root; run sudo wgft server check")
	} else if rep, err := check.Inspect(opts.WGInterface); err != nil {
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

	// SQLite があれば、記録済みのモード・アドレス帯との照合と、改名の検出を出す。
	if _, err := os.Stat(opts.DBPath); err != nil {
		fmt.Fprintln(out, "server database: not present yet, first run; skipping check against records")
		return nil
	}
	printDBModes(out, opts.DBPath)
	// 読み取り専用で開く。store.Open は権限を狭め、スキーマを移行するので、check では使わない(仕様 9 節)
	st, err := store.OpenReadOnly(opts.DBPath)
	if err != nil {
		fmt.Fprintf(out, "server database: cannot open: %v\n", err)
		return nil
	}
	defer st.Close()
	checkMeta(out, st, modeMeta, "recorded mode", opts.Mode)
	checkMeta(out, st, wgAddressMeta, "recorded address range", opts.WGAddress)
	if b, err := st.GetMeta(serverKeyMeta); err == nil && mode != modeUserspace {
		if k, err := wgtypes.NewKey(b); err == nil {
			if other, ok := wg.OtherDeviceWithKey(opts.WGInterface, k); ok {
				fmt.Fprintf(out, "warning: another interface %q with the same server key exists; suspect leftovers from changing WGFT_WG_INTERFACE\n", other)
			}
		}
	}
	return nil
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
	fmt.Fprintf(out, "warning: %s differs from the record %s; setting is %s\n", label, have, want)
}

// checkIPForward reports net.ipv4.ip_forward's current value (spec section 6.1).
// It never writes 1: to stay a read-only check it only probes writability by
// opening the file O_WRONLY and closing it again without writing, the same test
// EnableIPForward's real write would face at startup.
func checkIPForward(out io.Writer) {
	cur, err := os.ReadFile(ipForwardPath)
	if err != nil {
		fmt.Fprintf(out, "ip_forward: cannot read %s: %v\n", ipForwardPath, err)
		return
	}
	val := strings.TrimSpace(string(cur))
	fmt.Fprintf(out, "ip_forward: %s\n", val)
	if val == "1" {
		return
	}
	if f, err := os.OpenFile(ipForwardPath, os.O_WRONLY, 0); err != nil {
		finding := check.Finding{
			Where:   "net.ipv4.ip_forward",
			Problem: fmt.Sprintf("is %s and not writable (%v); kernel-mode forwarding needs it at 1", val, err),
			Suggest: []string{"sysctl -w net.ipv4.ip_forward=1"},
		}
		fmt.Fprintf(out, "  - %s\n", finding)
	} else {
		f.Close()
	}
}

// conntrack の表の上限と現在の件数(仕様 6.1 節)。nf_conntrack が未ロードなら読めない。
var (
	conntrackMaxPath   = "/proc/sys/net/netfilter/nf_conntrack_max"
	conntrackCountPath = "/proc/sys/net/netfilter/nf_conntrack_count"
)

// conntrackMinMax は、これを下回ると警告する nf_conntrack_max。接続元ごとの meter の上限(65535 件)と同じ桁で、
// メモリの小さい VPS の既定値(16384 など)を拾う。
const conntrackMinMax = 65536

// checkConntrack は conntrack の表の使用状況を 1 行出し、上限が小さければ警告する。値は変えない。
func checkConntrack(out io.Writer) {
	max, err := readProcInt(conntrackMaxPath)
	if err != nil {
		fmt.Fprintf(out, "conntrack: cannot read %s: %v; is the nf_conntrack module loaded\n", conntrackMaxPath, err)
		return
	}
	if count, err := readProcInt(conntrackCountPath); err == nil {
		fmt.Fprintf(out, "conntrack: %d of %d entries in use\n", count, max)
	} else {
		fmt.Fprintf(out, "conntrack: max %d entries\n", max)
	}
	if f := conntrackFinding(max); f != nil {
		fmt.Fprintf(out, "  - %s\n", f)
	}
}

// conntrackFinding は上限が小さいときの警告を作る。足りていれば nil。
func conntrackFinding(max int) *check.Finding {
	if max >= conntrackMinMax {
		return nil
	}
	return &check.Finding{
		Where:   "net.netfilter.nf_conntrack_max",
		Problem: fmt.Sprintf("is %d; every forwarded flow takes one entry, so a flood of new flows can fill the table and the kernel then drops new connections for the whole host", max),
		Suggest: []string{
			fmt.Sprintf("sysctl -w net.netfilter.nf_conntrack_max=%d", conntrackMinMax*4),
			"set new_flow_rate on public rules; flows dropped by it are never added to the table",
		},
	}
}

func readProcInt(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}
