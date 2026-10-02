//go:build linux

package kernelmode

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/textsafe"
	"github.com/rahanahu/wgft/proto"
)

// kernelReadInput は readKernel の材料である。稼働中のエージェントはメモリの上の値を、停止中の
// agent doctor は認証情報ファイルの値を渡す。どちらも同じ形なので、読み方は 1 つで済む。
type kernelReadInput struct {
	iface string
	creds *credentials.Credentials
	// pub は直近の公開の記録(nft.AgentPublication の JSON)である。無ければ全体状態の宣言から導ける
	// 範囲だけを比べる
	pub json.RawMessage
}

// DoctorOps はカーネルを読む操作である。単体テストだけが差し替える。どれもカーネルに書かない。
type DoctorOps struct {
	// Link はリンクの属性を読む。CAP_NET_ADMIN は要らない
	Link func(iface string) (exists bool, kind string, up bool, err error)
	// InspectLink は WireGuard の鍵とピアを読む。CAP_NET_ADMIN が要る
	InspectLink func(iface string, current, previous wgtypes.Key) (wg.AgentState, error)
	// InspectTable はテーブルを読み戻して記録と比べる。CAP_NET_ADMIN が要る
	InspectTable func(want nft.AgentPublication, iface string) (nft.AgentInspection, bool, error)
	// ReadSysctl は /proc/sys/net/ipv4 の下の値を読む。CAP_NET_ADMIN は要らない
	ReadSysctl func(name string) (string, error)
	// ForwardDrops は、既定で落とす他のテーブルの forward のチェーンの場所を返す。CAP_NET_ADMIN が要る
	ForwardDrops func(iface string) ([]string, error)
	// Route は、宛先への経路が向かうインタフェースの名前を返す。CAP_NET_ADMIN は要らない
	Route func(dst netip.Addr) (string, error)
	// LocalAddrs はホスト自身の IPv4 のアドレスである。CAP_NET_ADMIN は要らない
	LocalAddrs func() (map[netip.Addr]bool, error)
}

func defaultKernelDoctorOps() DoctorOps {
	return DoctorOps{
		Link: func(iface string) (bool, string, bool, error) {
			l, err := netlink.LinkByName(iface)
			if _, nf := err.(netlink.LinkNotFoundError); nf {
				return false, "", false, nil
			}
			if err != nil {
				return false, "", false, err
			}
			return true, l.Type(), l.Attrs().Flags&net.FlagUp != 0, nil
		},
		InspectLink:  wg.InspectAgent,
		InspectTable: nft.InspectAgent,
		ReadSysctl: func(name string) (string, error) {
			b, err := os.ReadFile("/proc/sys/net/ipv4/" + name)
			return strings.TrimSpace(string(b)), err
		},
		ForwardDrops: func(iface string) ([]string, error) {
			rep, err := linux.Inspect(iface, nft.AgentTableName)
			if err != nil {
				return nil, err
			}
			var out []string
			for _, f := range rep.Findings {
				if f.Hook == linux.HookForward {
					out = append(out, f.Where)
				}
			}
			return out, nil
		},
		// 30 秒ごとの見直しの経路の判定(checkRoute)と同じ関数である
		Route:      wg.AgentRouteInterface,
		LocalAddrs: hostAddrs,
	}
}

// DoctorKernelOps はテストだけが差し替える。
var DoctorKernelOps = defaultKernelDoctorOps()

// readKernel はカーネルモードの dataplane を読む(設計文書 10.2c 節)。判定はしない。
func readKernel(in kernelReadInput) *controlapi.DoctorKernel {
	ops := DoctorKernelOps
	var cur wgtypes.Key
	if in.creds.WGPrivateKey != "" {
		cur, _ = wgtypes.ParseKey(in.creds.WGPrivateKey)
	}
	prev, _ := in.creds.PreviousKey()
	st := in.creds.LastState
	return &controlapi.DoctorKernel{
		Interface:  readKernelInterface(ops, in.iface, cur, prev, st),
		Table:      readKernelTable(ops, in.iface, in.pub, st),
		Forwarding: readKernelForwarding(ops, in.iface),
	}
}

// agentServerAddress は vpsd のトンネルアドレスである。全体状態に無いので、エージェントのアドレスの
// 帯の先頭とする(4 節)。
func agentServerAddress(p netip.Prefix) netip.Addr { return p.Masked().Addr().Next() }

// declaredAgentLink は全体状態の wg 設定からインタフェースの宣言を組む。エンドポイントは入れない。
// エンドポイントは食い違いとして比べないためである(7b.1 節)。
func declaredAgentLink(iface string, cur, prev wgtypes.Key, w proto.WGConfig) (wg.AgentConfig, bool) {
	serverPub, err := wgtypes.ParseKey(w.ServerPubkey)
	if err != nil {
		return wg.AgentConfig{}, false
	}
	addr, err := netip.ParsePrefix(w.Address)
	if err != nil || !addr.Addr().Is4() {
		return wg.AgentConfig{}, false
	}
	// CheckWG (dataplane_kernel.go) rejects w.Keepalive outside 0-65535 before it ever
	// reaches a running dataplane, so st.WG here should already be in range; this repeats
	// the same bound defensively so a tampered or corrupted agent.json cannot make this
	// read-only diagnostic multiply an out-of-range value into a nonsense Keepalive display.
	if w.Keepalive < 0 || w.Keepalive > agentdp.KeepaliveMaxSeconds {
		return wg.AgentConfig{}, false
	}
	return wg.AgentConfig{
		Interface: iface, PrivateKey: cur, PreviousKey: prev, Address: addr, MTU: w.MTU,
		Server: wg.ServerPeer{PublicKey: serverPub, Address: agentServerAddress(addr),
			Keepalive: time.Duration(w.Keepalive) * time.Second},
	}, true
}

func readKernelInterface(ops DoctorOps, iface string, cur, prev wgtypes.Key, st *proto.State) controlapi.DoctorKernelInterface {
	ki := controlapi.DoctorKernelInterface{Name: iface}
	var cfg wg.AgentConfig
	if st != nil {
		cfg, ki.Declared = declaredAgentLink(iface, cur, prev, st.WG)
	}
	if ki.Declared {
		// 経路は権限なしで読めるので、鍵を読めない実行でも示す
		ki.ServerAddress = cfg.Server.Address.String()
		if name, err := ops.Route(cfg.Server.Address); err != nil {
			ki.RouteError = err.Error()
		} else {
			ki.RouteInterface = name
		}
	}
	exists, kind, up, err := ops.Link(iface)
	if err != nil {
		ki.ReadError = err.Error()
		return ki
	}
	ki.Exists, ki.Kind, ki.Up = exists, kind, up
	switch {
	case !exists:
		ki.Ownership = controlapi.KernelOwnershipAbsent
		return ki
	case kind != "wireguard":
		ki.Ownership = controlapi.KernelOwnershipNotWireGuard
		return ki
	}
	s, err := ops.InspectLink(iface, cur, prev)
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			ki.NeedsNetAdmin = true
		} else {
			ki.DeviceError = err.Error()
		}
		return ki
	}
	ki.Ownership = ownershipWord(s)
	ki.Up, ki.MTU = s.Up, s.MTU
	for _, a := range s.Addresses {
		ki.Addresses = append(ki.Addresses, a.String())
	}
	for _, p := range s.Peers {
		dp := controlapi.DoctorKernelPeer{PublicKey: p.PublicKey.String(), Keepalive: p.Keepalive,
			LastHandshake: p.LastHandshake, RxBytes: p.ReceiveBytes, TxBytes: p.TransmitBytes}
		if p.Endpoint.IsValid() {
			dp.Endpoint = p.Endpoint.String()
		}
		for _, a := range p.AllowedIPs {
			dp.AllowedIPs = append(dp.AllowedIPs, a.String())
		}
		ki.Peers = append(ki.Peers, dp)
	}
	if ki.Declared && s.Ownership.Ours() {
		ki.PeerOK = serverPeerPresent(s, cfg)
		ki.Differs = linkDiffs(s, cfg)
	}
	return ki
}

func ownershipWord(s wg.AgentState) string {
	switch {
	case !s.Exists:
		return controlapi.KernelOwnershipAbsent
	case s.Ownership == wg.NotWireGuard:
		return controlapi.KernelOwnershipNotWireGuard
	case s.Ownership == wg.OwnedByCurrentKey:
		return controlapi.KernelOwnershipCurrent
	case s.Ownership == wg.OwnedByPreviousKey:
		return controlapi.KernelOwnershipPrevious
	case s.PublicKey == (wgtypes.Key{}):
		return controlapi.KernelOwnershipKeyless
	}
	return controlapi.KernelOwnershipForeign
}

// serverPeerPresent は、server の公開鍵を持ち、server のトンネルアドレスを AllowedIPs に含むピアが
// あるかどうかである。無ければ、vpsd から届くパケットを WireGuard が受け取らない。
func serverPeerPresent(s wg.AgentState, cfg wg.AgentConfig) bool {
	for _, p := range s.Peers {
		if p.PublicKey != cfg.Server.PublicKey {
			continue
		}
		for _, a := range p.AllowedIPs {
			if a.Contains(cfg.Server.Address) {
				return true
			}
		}
	}
	return false
}

func readKernelTable(ops DoctorOps, iface string, raw json.RawMessage, st *proto.State) controlapi.DoctorKernelTable {
	var t controlapi.DoctorKernelTable
	var want nft.AgentPublication
	switch {
	case len(raw) > 0 && json.Unmarshal(raw, &want) == nil:
		t.Source, t.Generation = controlapi.KernelTableFromRecord, want.Generation
	case st != nil:
		// 記録が無い。宣言から、名前の解決と許可一覧を当てはめずに組む(10.2c 節の「記録が無い場合」)
		want = nft.PlanAgent(nft.AgentInput{Generation: st.Generation, Rules: st.Rules}, nft.AgentConfig{WGInterface: iface})
		t.Source, t.Generation = controlapi.KernelTableFromDeclaration, st.Generation
	}
	ins, present, err := ops.InspectTable(want, iface)
	if err != nil {
		t.ReadError = err.Error()
		t.NeedsNetAdmin = errors.Is(err, os.ErrPermission)
		t.Present = present
		return t
	}
	t.Present = present
	if !present || t.Source == "" {
		return t
	}
	var missing, unexpected []string
	if t.Source == controlapi.KernelTableFromRecord {
		var guard []string
		var names []string
		missing, guard, names = splitMissing(ins.MissingItems, want, ops.LocalAddrs)
		t.GuardEffects, t.GuardClosed = guardEffects(names)
		t.GuardMissingCount, t.GuardMissing = len(guard), capItems(guard)
		t.MovedCount, t.Moved = len(ins.Moved), capItems(ins.Moved)
		unexpected = unexpectedItems(ins)
		t.Rules = recordRules(want, nil)
	} else {
		missing, t.Rules = declarationDiff(want, st, ins.DNATs)
	}
	t.MissingCount, t.Missing = len(missing), capItems(missing)
	t.UnexpectedCount, t.Unexpected = len(unexpected), capItems(unexpected)
	return t
}

// splitMissing は欠けた行を、転送を止めるものと止めないもの(守りの行)に分ける(設計文書 10.2c 節の
// 「dataplane.table の判定」)。宛先がホスト自身でないルールだけが通る行と、ホスト自身のルールだけが通る
// 行は、記録にその宛先のルールがあるときだけ転送を止める側に数える。ホスト自身のアドレスを読めなければ、
// どちらの宛先もありうるので、止める側に数える。
//
// names は、守りの側に数えた行のうち名前の付いたもの(nft.Guard*)である。
func splitMissing(items []nft.MissingItem, pub nft.AgentPublication, localAddrs func() (map[netip.Addr]bool, error)) (carry, guard, names []string) {
	self, lan := true, true
	if local, err := localAddrs(); err == nil {
		self, lan = false, false
		for _, d := range pub.DNATs() {
			if local[d.Dest.Addr()] {
				self = true
			} else {
				lan = true
			}
		}
	}
	for _, m := range items {
		switch {
		case m.Role == nft.RoleCarry,
			m.Role == nft.RoleCarryLAN && lan,
			m.Role == nft.RoleCarrySelf && self:
			carry = append(carry, m.Desc)
		default:
			guard = append(guard, m.Desc)
			if m.Guard != "" && !slices.Contains(names, m.Guard) {
				names = append(names, m.Guard)
			}
		}
	}
	return carry, guard, names
}

// guardEffects は、欠けた守りの行の組み合わせから、開きうる面と、残っている行がまだ閉じている面を決める
// (設計文書 10.2c 節の「dataplane.table の判定」)。drop の行は層になっている。ホストのポートは filter_pre
// と input の drop の行が両方欠けたとき、他のテーブルの DNAT は filter_pre の drop の行が欠けたとき、
// LAN への面は filter_pre と forward の wgft0 から入るものの drop の行が両方欠けたときに開く。ラボで
// 確かめた組み合わせである。
func guardEffects(names []string) (effects, closed []string) {
	gone := func(n string) bool { return slices.Contains(names, n) }
	pre, in, from := gone(nft.GuardPreDrop), gone(nft.GuardInputDrop), gone(nft.GuardForwardFromDrop)
	switch {
	case pre && in:
		effects = append(effects, controlapi.KernelEffectHost)
	case pre:
		closed = append(closed, controlapi.KernelClosedHostByInput)
	case in:
		closed = append(closed, controlapi.KernelClosedHostByFilterPre)
	}
	if pre {
		effects = append(effects, controlapi.KernelEffectOtherDNAT)
	}
	switch {
	case pre && from:
		effects = append(effects, controlapi.KernelEffectLAN)
	case pre:
		closed = append(closed, controlapi.KernelClosedLANByForward)
	case from:
		closed = append(closed, controlapi.KernelClosedLANByFilterPre)
	}
	if gone(nft.GuardHairpinDrop) {
		effects = append(effects, controlapi.KernelEffectHairpin)
	}
	if gone(nft.GuardForwardToDrop) {
		effects = append(effects, controlapi.KernelEffectToTunnel)
	}
	if gone(nft.GuardMSS) {
		effects = append(effects, controlapi.KernelEffectMSS)
	}
	return effects, closed
}

// unexpectedItems は、記録に無いのに実際の表にあるものを、1 つの行を 1 件として並べる。
//
// InspectAgent は同じ行を 2 か所から数えうる。nat_pre に加わった行は、行の形の比較で Unexpected に
// 入り、DNAT として読めなければ Unrecognized にも、読めれば ExtraDNATs にも入る。Unrecognized と、
// 加わった行から読んだ DNAT は数えない。wgft が書いた形の行の map に加わった要素は、行の比較には
// 表れないので、DNAT として数える(ExtraDNATsInPlace)。加わった行と加わった要素が同時にあっても、
// どちらも数える。
func unexpectedItems(ins nft.AgentInspection) []string {
	out := append([]string(nil), ins.Unexpected...)
	for _, d := range ins.ExtraDNATsInPlace {
		out = append(out, "DNAT "+dnatText(d))
	}
	return out
}

// recordRules は記録をルールごとの状態にする。covered は、宣言から導いた場合に、実際の表で DNAT を
// 置いていたポートの数である。
func recordRules(pub nft.AgentPublication, covered map[string]int) []controlapi.DoctorRule {
	out := make([]controlapi.DoctorRule, 0, len(pub.Rules))
	for _, r := range pub.Rules {
		dr := controlapi.DoctorRule{ID: r.RuleID, State: proto.StatusOK, Proto: r.Proto, Ports: r.ListenPort.Len()}
		if r.Reason != "" {
			dr.State, dr.Reason = proto.StatusError, clipKernelText(r.Reason)
		}
		for _, rg := range r.Ranges {
			dr.DNATPorts += rg.Ports.Len()
		}
		if n, ok := covered[r.RuleID]; ok {
			dr.DNATPorts = n
		}
		out = append(out, dr)
	}
	return out
}

// declarationDiff は、記録の無い実行で、宣言から導ける範囲だけを比べる(10.2c 節)。IP リテラルの宛先の
// ルールは、そのポートの DNAT がその宛先を指すことを、ホスト名の宛先のルールは、そのポートに DNAT が
// あることだけを確かめる。ループバックの宛先のように宣言から公開できないと分かるルールは、理由を持つ。
// 許可一覧は当てはめない。
func declarationDiff(want nft.AgentPublication, st *proto.State, got []nft.AgentDNAT) (missing []string, rules []controlapi.DoctorRule) {
	type key struct {
		rule  string
		proto proto.Proto
		port  uint16
	}
	actual := map[key]netip.AddrPort{}
	for _, d := range got {
		for p := int(d.Ports.Lo); p <= int(d.Ports.Hi); p++ {
			actual[key{d.RuleID, d.Proto, uint16(p)}] = netip.AddrPortFrom(d.Dest.Addr(), uint16(int(d.Dest.Port())+p-int(d.Ports.Lo)))
		}
	}
	byID := map[string]proto.AgentRule{}
	for _, r := range st.Rules {
		byID[r.ID] = r
	}
	covered := map[string]int{}
	named := map[string]bool{}
	for _, r := range want.Rules {
		decl := byID[r.RuleID]
		host, _, _ := net.SplitHostPort(decl.Target)
		if _, err := netip.ParseAddr(host); err != nil && host != "" {
			// ホスト名の宛先。解決の結果は分からないので、ポートに DNAT があることだけを見る
			named[r.RuleID] = true
			n, first := 0, -1
			for p := int(r.ListenPort.Lo); p <= int(r.ListenPort.Hi); p++ {
				if _, ok := actual[key{r.RuleID, r.Proto, uint16(p)}]; ok {
					n++
				} else if first < 0 {
					first = p
				}
			}
			covered[r.RuleID] = n
			if first >= 0 {
				missing = append(missing, fmt.Sprintf("DNAT %s %d of rule %s, a host-name target, and %d port%s in all",
					r.Proto, first, r.RuleID, r.ListenPort.Len()-n, plural(r.ListenPort.Len()-n)))
			}
			continue
		}
		n := 0
		for _, rg := range r.Ranges {
			for p := int(rg.Ports.Lo); p <= int(rg.Ports.Hi); p++ {
				dest := netip.AddrPortFrom(rg.Dest.Addr(), uint16(int(rg.Dest.Port())+p-int(rg.Ports.Lo)))
				if actual[key{r.RuleID, r.Proto, uint16(p)}] == dest {
					n++
				}
			}
		}
		covered[r.RuleID] = n
		published := 0
		for _, rg := range r.Ranges {
			published += rg.Ports.Len()
		}
		if n < published {
			missing = append(missing, fmt.Sprintf("DNAT of rule %s to %s: %d of %d port%s in place", r.RuleID, decl.Target, n, published, plural(published)))
		}
	}
	rules = recordRules(want, covered)
	for i := range rules {
		if named[rules[i].ID] {
			// 宣言から組んだ記録は名前を解決していないので、その理由は事実ではない
			rules[i].State, rules[i].Reason = proto.StatusOK, ""
		}
	}
	return missing, rules
}

func dnatText(d nft.AgentDNAT) string { return d.String() }

func capItems(s []string) []string {
	if len(s) > maxKernelItems {
		s = s[:maxKernelItems]
	}
	out := make([]string, len(s))
	for i, x := range s {
		out[i] = clipKernelText(x)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// clipKernelText は上限(controlapi.DoctorTextMaxBytes)を超える文字列を切り、切ったことを添える。
// 実行時の状態の側(internal/agent)の clipText と同じ値で同じように切る。カーネルモードの実装は実行時の状態の側の
// 関数を呼ばないので、カーネルの読み取りの側にも同じ 1 行を置く。切る位置は rune の境目に合わせるので、
// 結果は正しい UTF-8 のままである。
func clipKernelText(s string) string {
	return textsafe.ClipText(s, controlapi.DoctorTextMaxBytes)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func readKernelForwarding(ops DoctorOps, iface string) controlapi.DoctorKernelForwarding {
	var f controlapi.DoctorKernelForwarding
	if v, err := ops.ReadSysctl("ip_forward"); err != nil {
		f.IPForwardError = err.Error()
	} else {
		f.IPForward = v
	}
	for _, name := range []string{"all", "default"} {
		if v, err := ops.ReadSysctl("conf/" + name + "/rp_filter"); err == nil && v == "1" {
			f.RPFilterStrict = append(f.RPFilterStrict, name)
		}
	}
	drops, err := ops.ForwardDrops(iface)
	switch {
	case err != nil:
		f.PolicyError = err.Error()
		f.PolicyNeedsNetAdmin = errors.Is(err, os.ErrPermission)
	default:
		f.PolicyDrops = drops
	}
	return f
}

// ProcessNetAdmin は、このプロセスが実効として CAP_NET_ADMIN を持つかどうかを /proc/self/status の
// CapEff から読む。読めなければ nil を返す。
func ProcessNetAdmin() *bool {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}
	return capEffHasNetAdmin(string(b))
}

// capNetAdmin は CAP_NET_ADMIN の番号である(linux/capability.h)。
const capNetAdmin = 12

func capEffHasNetAdmin(status string) *bool {
	for _, line := range strings.Split(status, "\n") {
		v, ok := strings.CutPrefix(line, "CapEff:")
		if !ok {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
		if err != nil {
			return nil
		}
		has := n&(1<<capNetAdmin) != 0
		return &has
	}
	return nil
}
