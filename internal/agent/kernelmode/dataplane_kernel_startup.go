//go:build linux

package kernelmode

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/reasontext"
	"github.com/rahanahu/wgft/internal/startup"
)

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

// Startup は起動時に、何かを書く前に行う検査と準備である(7b.1・7b.4 節)。wgft0 の所有を判定し、
// 他の所有者のものなら終了コード 1 の誤りを返す。権限が足りなければ種別 prerequisite の拒否を返す。
// 続けて、別の名前で自分の鍵を持つインタフェースを警告し、ip_forward を 1 にし、ホストの設定の
// 手掛かりを 1 行ずつ出す。save は認証情報ファイルを保存する。ip_forward を変える記録に使う。
func (d *Dataplane) Startup(priv wgtypes.Key, save func() error) error {
	prev, err := d.f.PreviousKey()
	if err != nil {
		return err
	}
	st, err := d.Ops.InspectLink(d.iface, priv, prev)
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
	if names, err := d.Ops.KeyHolders(d.iface, priv, prev); err != nil {
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
func (d *Dataplane) enableForwarding(save func() error) error {
	on, rerr := d.Ops.ReadIPForward()
	if rerr == nil && on {
		d.forwardErr, d.forwardUnknown, d.forwardWriteErr = nil, false, nil
		return nil
	}
	prev := d.f.IPForwardEnabledAt
	recorded := false
	if rerr == nil && prev == nil {
		now := d.Ops.Now().UTC()
		d.f.IPForwardEnabledAt = &now
		if err := save(); err != nil {
			d.f.IPForwardEnabledAt = prev
			return fmt.Errorf("record that the agent sets net.ipv4.ip_forward before setting it: %w", err)
		}
		recorded = true
	}
	if err := d.Ops.WriteIPForward(); err != nil {
		if recorded {
			d.f.IPForwardEnabledAt = prev
			if serr := save(); serr != nil {
				log.Printf("warning: cannot remove the ip_forward record after the write failed: %v", serr)
			}
		}
		d.forwardWriteErr = err
		if rerr != nil {
			// 値を読めていないので、1 でないとは言えない。読みと書きの両方の誤りを示す(7b.1 節)
			d.forwardErr = fmt.Errorf(reasontext.IPForward+" could not be read: %v; setting it to 1 failed too: %w; "+reasontext.IPForwardUnknown, rerr, err)
			d.forwardUnknown = true
		} else {
			d.forwardErr = fmt.Errorf(reasontext.IPForward+" is not 1 and cannot be set: %w", err)
			d.forwardUnknown = false
		}
		log.Printf("warning: %v; rules whose target is not this host are reported as errors until it is 1", d.forwardErr)
		if l, err := d.Ops.LocalAddrs(); err == nil {
			d.local = l
		}
		return nil
	}
	d.forwardErr, d.forwardUnknown, d.forwardWriteErr = nil, false, nil
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
