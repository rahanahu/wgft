package agent

// 撤去(wgft agent teardown、設計文書 10.3 節)。停止したカーネルモードのエージェントが残した資源を消す。
// 消すのは、今の鍵か 1 つ前の鍵を持つ WireGuard インタフェース、wgft が DNAT した conntrack のエントリ、
// table inet wgft_agent、agent.json のカーネルモードの記録である。登録の情報、今の鍵、last_state は残し、
// 撤去の後にユーザー空間モードで起動し直せるようにする。
//
// 判定と順序はこのファイルが持ち、カーネルに触れる操作は teardownOps に分けてある。Linux の操作は
// teardown_linux.go にある。Linux 以外では入口(cmd/wgft)が先に拒むので、ここには届かない。

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/startup"
)

// TeardownOptions は撤去の指定である。
type TeardownOptions struct {
	// CredentialsPath は agent.json のパスである。
	CredentialsPath string
	// Interface は WGFT_WG_INTERFACE の値である。鍵の一致しないリンクをこの名前と作業用の名前で
	// 探して示すために使う。鍵の一致するインタフェースは名前によらず消す。
	Interface string
	// DryRun なら、消すものと手で戻す一覧を示すだけで何も変えない。
	DryRun bool
}

// linkOwner は、名前で見たリンクの持ち主の判定である。
type linkOwner int

const (
	linkAbsent linkOwner = iota
	linkCurrentKey
	linkPreviousKey
	linkForeignKey
	linkKeyless
	linkNotWireGuard
)

func (o linkOwner) ours() bool { return o == linkCurrentKey || o == linkPreviousKey }

// linkState は名前で見たリンクである。kind はリンクの種別で、WireGuard 以外のときだけ文面に使う。
type linkState struct {
	owner linkOwner
	kind  string
}

// teardownOps は撤去がカーネルとロックに触れる操作である。単体テストだけが差し替える。
type teardownOps struct {
	inspectLock func(path string) (credentials.State, error)
	acquire     func(path string) (*credentials.Lock, error)
	// keyHolders は、current か previous の鍵を持つ WireGuard インタフェースの名前を返す。ゼロの鍵は
	// どれにも一致しない。
	keyHolders  func(current, previous wgtypes.Key) ([]string, error)
	link        func(name string, current, previous wgtypes.Key) (linkState, error)
	stagingName func(iface string) string
	// deleteLink は、name が今か前の鍵を持つときだけ消す。消したかどうかを返す。
	deleteLink   func(name string, current, previous wgtypes.Key) (bool, error)
	tablePresent func() (bool, error)
	deleteTable  func() (bool, error)
	// closeFlows は、公開の記録 pubs(古い順)から wgft が DNAT したフローを見分けて消し、結果の
	// 1 行を返す。address はエージェントのトンネルアドレスと帯である。
	closeFlows func(pubs []json.RawMessage, address string) (string, error)
}

// errAgentRunning は、稼働中のエージェントに対する撤去の拒否である。普通の誤りであり、終了コードは 1 である
// (設計文書 11b 節)。
var errAgentRunning = errors.New("the agent is running, so nothing was removed: stop it first, for example with systemctl stop wgft-agent, then run wgft agent teardown again")

// Teardown は撤去を実行し、out に消すもの、触らないもの、結果、手で戻す一覧を書く(設計文書 10.3 節)。
func Teardown(opts TeardownOptions, out io.Writer) error {
	return teardownWith(defaultTeardownOps(), opts, out)
}

// teardownPlan は、何も変える前に読み取った撤去の対象である。
type teardownPlan struct {
	f         *credentials.Credentials // nil なら agent.json が無い
	cur, prev wgtypes.Key

	links  []string // 消すインタフェース。今か前の鍵を持つもの
	owners map[string]linkOwner
	leave  []string // 触らないリンクの説明
	table  bool

	// pubs は conntrack の収束に渡す公開の記録である。address はエージェントのトンネルアドレスである。
	// flowsSkip が空でなければ、conntrack は飛ばし、その理由を示す
	pubs      []json.RawMessage
	address   string
	flowsSkip string

	records []string // 消す記録の名前
	// forwardAt は ip_forward を 0 から 1 に変えた記録である。記録を消した後の手で戻す一覧に使う
	forwardAt *time.Time
}

func (p *teardownPlan) empty() bool {
	return len(p.links) == 0 && !p.table && len(p.records) == 0
}

func teardownWith(ops teardownOps, opts TeardownOptions, out io.Writer) error {
	path := opts.CredentialsPath
	// 稼働の判定は rotate-key と同じく、ロックファイルを作らない Inspect で行う(設計文書 9・10.3 節)。
	// ロックファイルがあって誰も持っていなければ、ロックを取って終わるまで持つ。判定の後に起動した
	// エージェントが、撤去の途中で資源を作り直さないためである。ロックファイルが無ければ取らない。
	// 取ろうとすると、呼び出し元の権限でロックファイルを作り、非特権で動くエージェントの起動を塞ぐ
	state, err := ops.inspectLock(path)
	if err != nil {
		return fmt.Errorf("cannot tell whether the agent is running, so nothing was removed: reading the lock of %s failed: %w", path, err)
	}
	switch state {
	case credentials.Locked:
		return errAgentRunning
	case credentials.Unlocked:
		lock, err := ops.acquire(path)
		if errors.Is(err, credentials.ErrLocked) {
			return errAgentRunning
		}
		if err != nil {
			return fmt.Errorf("lock %s, so that the agent cannot start meanwhile: %w; nothing was removed", path, err)
		}
		defer lock.Release()
	}

	plan, err := planTeardown(ops, opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "agent teardown: credentials file %s\n", path)
	if plan.f == nil {
		fmt.Fprintf(out, "note: %s does not exist, so no WireGuard interface can be judged the agent's by its key; only table inet wgft_agent, which wgft owns by its name, is removed\n", path)
	}
	if plan.empty() {
		for _, l := range plan.leave {
			fmt.Fprintln(out, "leave: "+l)
		}
		fmt.Fprintln(out, "nothing to remove: no WireGuard interface holds this agent's key, there is no table inet wgft_agent, and agent.json has no kernel-mode record")
		return nil
	}
	for _, n := range plan.links {
		fmt.Fprintln(out, "remove: "+describeLink(n, plan.owners[n], opts.Interface))
	}
	if plan.flowsSkip == "" {
		fmt.Fprintln(out, "remove: conntrack entries of the flows the agent forwarded")
	} else {
		fmt.Fprintln(out, "skip: conntrack entries: "+plan.flowsSkip)
	}
	if plan.table {
		fmt.Fprintln(out, "remove: table inet wgft_agent")
	}
	if len(plan.records) > 0 {
		fmt.Fprintln(out, "remove: the kernel-mode records in agent.json: "+strings.Join(plan.records, ", "))
	}
	for _, l := range plan.leave {
		fmt.Fprintln(out, "leave: "+l)
	}
	if opts.DryRun {
		fmt.Fprintln(out, "dry run: nothing was changed")
		printTeardownManual(out, plan.forwardAt)
		return nil
	}

	// インタフェースを最初に消す。テーブルを先に消すと、wgft0 が残っている間に filter_pre と input の
	// 守りが無くなる(設計文書 10.3 節)
	for _, n := range plan.links {
		deleted, err := ops.deleteLink(n, plan.cur, plan.prev)
		if err != nil {
			return kernelErr(fmt.Errorf("delete the WireGuard interface %s: %w; the records in agent.json are kept, so run wgft agent teardown again once it is fixed", n, err))
		}
		if deleted {
			fmt.Fprintf(out, "deleted the WireGuard interface %s\n", n)
		} else {
			fmt.Fprintf(out, "the WireGuard interface %s was already gone\n", n)
		}
	}
	if plan.flowsSkip == "" {
		// 失敗は警告にして続ける。残ったエントリは conntrack の期限で消える
		if res, err := ops.closeFlows(plan.pubs, plan.address); err != nil {
			fmt.Fprintf(out, "warning: closing the agent's conntrack entries failed: %v; the entries left expire with the host's conntrack timeouts\n", err)
		} else {
			fmt.Fprintln(out, "conntrack: "+res)
		}
	}
	if plan.table {
		deleted, err := ops.deleteTable()
		if err != nil {
			return kernelErr(fmt.Errorf("delete table inet wgft_agent: %w; the records in agent.json are kept, so run wgft agent teardown again once it is fixed", err))
		}
		if deleted {
			fmt.Fprintln(out, "deleted table inet wgft_agent")
		} else {
			fmt.Fprintln(out, "table inet wgft_agent was already gone")
		}
	}
	if len(plan.records) > 0 {
		clearKernelRecords(plan.f)
		if err := plan.f.Save(path); err != nil {
			return fmt.Errorf("clear the kernel-mode records in %s: %w; the kernel resources are gone, so run wgft agent teardown again to clear the records", path, err)
		}
		fmt.Fprintln(out, "cleared the kernel-mode records in agent.json; the registration, the key and last_state are kept")
	}
	printTeardownManual(out, plan.forwardAt)
	return nil
}

// planTeardown は何も変えずに撤去の対象を読む。
func planTeardown(ops teardownOps, opts TeardownOptions) (*teardownPlan, error) {
	p := &teardownPlan{owners: map[string]linkOwner{}}
	f, err := credentials.Load(opts.CredentialsPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, fmt.Errorf("read the credentials file: %w; nothing was removed", err)
	default:
		p.f = f
	}
	if p.f != nil {
		switch p.f.Mode {
		case "", credentials.ModeKernel, credentials.ModeUserspace:
		default:
			// 新しい版が書いた記録かもしれない。この版はその版が残した資源を判定できず、記録を消すと
			// その版の撤去が手掛かりを失うので、何も変えずに止まる(設計文書 10.3・11a 節)
			return nil, startup.Conflict("WGFT_MODE",
				"the credentials file agent.json records the mode %q, which this version of wgft does not know, so nothing was removed; "+
					"it may have been written by a newer version, whose kernel state this version cannot judge; "+
					"run wgft agent teardown of the version that wrote it, or restore agent.json from a backup", p.f.Mode)
		}
		if p.f.WGPrivateKey != "" {
			if p.cur, err = p.f.PrivateKey(); err != nil {
				return nil, fmt.Errorf("the credentials file: %w; nothing was removed", err)
			}
		}
		if p.prev, err = p.f.PreviousKey(); err != nil {
			return nil, fmt.Errorf("the credentials file: %w; nothing was removed", err)
		}
	}

	var zero wgtypes.Key
	if p.cur != zero || p.prev != zero {
		names, err := ops.keyHolders(p.cur, p.prev)
		if err != nil {
			return nil, kernelErr(fmt.Errorf("list the WireGuard interfaces: %w; nothing was removed", err))
		}
		for _, n := range names {
			st, err := ops.link(n, p.cur, p.prev)
			if err != nil {
				return nil, kernelErr(fmt.Errorf("read the WireGuard interface %s: %w; nothing was removed", n, err))
			}
			if st.owner.ours() {
				p.links = append(p.links, n)
				p.owners[n] = st.owner
			}
		}
	}
	// 設定の名前と作業用の名前にある、鍵の一致しないリンクは消さずに示す(設計文書 10.3 節)
	for _, n := range []string{opts.Interface, ops.stagingName(opts.Interface)} {
		if _, ok := p.owners[n]; ok {
			continue
		}
		st, err := ops.link(n, p.cur, p.prev)
		if err != nil {
			return nil, kernelErr(fmt.Errorf("read %s: %w; nothing was removed", n, err))
		}
		if s := describeLeftLink(n, st, p.f == nil); s != "" {
			p.leave = append(p.leave, s)
		}
	}
	if p.table, err = ops.tablePresent(); err != nil {
		return nil, kernelErr(fmt.Errorf("list the nftables tables: %w; nothing was removed", err))
	}
	if p.f != nil {
		p.records = kernelRecords(p.f)
		p.forwardAt = p.f.IPForwardEnabledAt
		p.pubs, p.address, p.flowsSkip = flowInputs(p.f)
	} else {
		p.flowsSkip = "agent.json does not exist, so no flow can be told apart as the agent's"
	}
	return p, nil
}

// flowInputs は conntrack の収束の入力を agent.json から取る。前の公開は、収束が済んでいない前の公開の
// 列(古い順)と、直近の公開の記録をこの順に並べたものである。エージェントの収束と同じ並びであり、
// 列の公開は直近の公開より前に公開された。公開の記録が無いか、エージェントのトンネルアドレスが
// 分からなければ、wgft のフローを見分けられないので、その理由を返す。
func flowInputs(f *credentials.Credentials) (pubs []json.RawMessage, address, skip string) {
	if len(f.KernelUnconverged) > 0 {
		var list []json.RawMessage
		if err := json.Unmarshal(f.KernelUnconverged, &list); err != nil {
			return nil, "", fmt.Sprintf("the list of publications not yet converged in agent.json cannot be read: %v", err)
		}
		pubs = append(pubs, list...)
	}
	if len(f.KernelPublication) > 0 {
		pubs = append(pubs, f.KernelPublication)
	}
	if len(pubs) == 0 {
		return nil, "", "agent.json has no publication record, so no flow can be told apart as the agent's"
	}
	if f.LastState == nil || f.LastState.WG.Address == "" {
		return nil, "", "agent.json has no last_state, so the agent's tunnel address is unknown and no flow can be told apart as the agent's"
	}
	return pubs, f.LastState.WG.Address, ""
}

// kernelRecords は、agent.json にあるカーネルモードの記録の名前を返す。
func kernelRecords(f *credentials.Credentials) []string {
	var r []string
	if f.Mode != "" {
		r = append(r, "mode "+f.Mode)
	}
	if f.PreviousWGPrivateKey != "" {
		r = append(r, "previous key")
	}
	if f.IPForwardEnabledAt != nil {
		r = append(r, "ip_forward record")
	}
	if len(f.KernelPublication) > 0 {
		r = append(r, "publication record")
	}
	if len(f.KernelUnconverged) > 0 {
		r = append(r, "publications not yet converged")
	}
	return r
}

// clearKernelRecords はカーネルモードの記録を消す。ユーザー空間モードのエージェントはモードの記録を
// 書かないので、モードも空にして、旧い版と同じ形に戻す(設計文書 11a 節)。
func clearKernelRecords(f *credentials.Credentials) {
	f.Mode = ""
	f.PreviousWGPrivateKey = ""
	f.IPForwardEnabledAt = nil
	f.KernelPublication = nil
	f.KernelUnconverged = nil
}

func describeLink(name string, o linkOwner, iface string) string {
	which := "this agent's key"
	if o == linkPreviousKey {
		which = "this agent's previous key"
	}
	s := fmt.Sprintf("the WireGuard interface %s, which holds %s", name, which)
	if name != iface {
		s += fmt.Sprintf("; its name is not %s, the WGFT_WG_INTERFACE of this run, so it is left from creating the interface or from an earlier WGFT_WG_INTERFACE", iface)
	}
	return s
}

// describeLeftLink は、設定の名前か作業用の名前にあって撤去が触らないリンクの説明である。無ければ空。
func describeLeftLink(name string, st linkState, noCredentials bool) string {
	switch st.owner {
	case linkNotWireGuard:
		return fmt.Sprintf("%s is a %s link, not WireGuard; wgft leaves it untouched", name, st.kind)
	case linkKeyless:
		return fmt.Sprintf("%s is a WireGuard interface with no key, so it cannot be judged the agent's and wgft leaves it untouched; if nothing uses it, delete it with `ip link del %s`", name, name)
	case linkForeignKey:
		if noCredentials {
			return fmt.Sprintf("%s is a WireGuard interface, and without agent.json its key cannot be compared, so wgft leaves it untouched; if it was this agent's, confirm that and delete it with `ip link del %s`", name, name)
		}
		return fmt.Sprintf("%s is a WireGuard interface that holds neither this agent's key nor its previous one, so wgft leaves it untouched; "+
			"if it was left by an earlier registration of this agent, for example after agent.json was lost, confirm that and delete it with `ip link del %s`", name, name)
	}
	return ""
}

// printTeardownManual は、wgft が自動では戻さないものの一覧を、agent.json の記録から具体値で示す
// (設計文書 10.3 節)。forwardAt は ip_forward を 0 から 1 に変えた記録で、nil なら記録は無い。
func printTeardownManual(out io.Writer, forwardAt *time.Time) {
	fmt.Fprintln(out, "\nrestore by hand, wgft does not revert these:")
	if forwardAt != nil {
		fmt.Fprintf(out, "  - net.ipv4.ip_forward: the agent set it from 0 to 1 at %s; wgft leaves it at 1, since something else on this host may forward packets; "+
			"if nothing does, restore it with `sysctl -w net.ipv4.ip_forward=0`, and remove any file in /etc/sysctl.d that sets it to 1\n", forwardAt.UTC().Format(time.RFC3339))
	} else {
		fmt.Fprintln(out, "  - net.ipv4.ip_forward: agent.json has no record that the agent changed it from 0; nothing to restore")
	}
	fmt.Fprintln(out, "  - WGFT_MODE: remove WGFT_MODE=kernel from agent.env, or set it to userspace, before the agent starts again; with kernel it builds the interface and the table again")
	fmt.Fprintln(out, "  - CAP_NET_ADMIN: userspace mode does not need it; if it was added to the agent's unit for kernel mode, remove it")
}

// kernelErr は、カーネルの読み書きの権限の不足を、種別 prerequisite の拒否にする(設計文書 10.3・11b 節)。
// 他の誤りはそのまま返す。
func kernelErr(err error) error {
	if err == nil || !errors.Is(err, os.ErrPermission) {
		return err
	}
	return startup.Prerequisite("CAP_NET_ADMIN",
		"agent teardown reads and deletes kernel WireGuard interfaces and nftables tables, which needs CAP_NET_ADMIN: %v; run it as root, for example with sudo", err)
}
