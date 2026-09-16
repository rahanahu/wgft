// Package conntrack は、外から入って DNAT されたフローを宣言状態に収束させる(仕様 6.1 節)。
// 「宣言状態に収束させる」1 手順だけを持つ:Dump → 判定 → 削除。nftables テーブルの差し替えの後に走らせる。
package conntrack

import (
	"fmt"
	"net/netip"

	"github.com/ti-mo/conntrack"

	"github.com/rahanahu/wgft/proto"
)

// Rule は収束の判定に使う、ルールの部分集合。カーネルモードで有効なものだけを渡す。
type Rule struct {
	Proto       proto.Proto
	ListenPort  proto.PortRange
	AgentAddr   netip.Addr // DNAT 先(エージェントのアドレス)
	SourceDeny  []netip.Prefix
	SourceAllow []netip.Prefix
}

// dumper と deleter は ti-mo/conntrack.Conn の使う部分。テストで差し替える。
type conn interface {
	Dump(opts *conntrack.DumpOptions) ([]conntrack.Flow, error)
	Delete(f conntrack.Flow) error
}

// Converge は対象のフローを Dump し、現在のルールで許されないものを削除する。削除数を返す。
func Converge(rules []Rule, wgNet netip.Prefix) (int, error) {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return 0, fmt.Errorf("conntrack: %w", err)
	}
	defer c.Close()
	return converge(c, rules, wgNet)
}

func converge(c conn, rules []Rule, wgNet netip.Prefix) (int, error) {
	flows, err := c.Dump(nil)
	if err != nil {
		return 0, fmt.Errorf("conntrack dump: %w", err)
	}
	deleted := 0
	for _, f := range flows {
		if !isForwardedDNAT(f, wgNet) {
			continue
		}
		if allowed(f, rules) {
			continue
		}
		if err := c.Delete(f); err != nil {
			// 競合で既に消えている等は致命的でない。続ける
			continue
		}
		deleted++
	}
	return deleted, nil
}

// isForwardedDNAT は「外から入って DNAT されたフロー」か(収束の対象)。
// vpsd 自身が wg0 へ張ったフローは orig 宛先が wg 帯の中なので外れる。
func isForwardedDNAT(f conntrack.Flow, wgNet netip.Prefix) bool {
	if !f.Status.DstNAT() {
		return false
	}
	origDst := f.TupleOrig.IP.DestinationAddress
	replySrc := f.TupleReply.IP.SourceAddress
	return origDst.Is4() && !wgNet.Contains(origDst) && replySrc.Is4() && wgNet.Contains(replySrc)
}

// allowed は、現在有効なカーネルモードのルールのいずれかがこのフローを許すか。
func allowed(f conntrack.Flow, rules []Rule) bool {
	origProto := protoOf(f.TupleOrig.Proto.Protocol)
	origDport := f.TupleOrig.Proto.DestinationPort
	origSrc := f.TupleOrig.IP.SourceAddress
	replySrc := f.TupleReply.IP.SourceAddress // DNAT 先のアドレス
	for _, r := range rules {
		if r.Proto != origProto || !r.ListenPort.Contains(origDport) {
			continue
		}
		// reply 側の送信元が、このルールの DNAT 先(エージェントのアドレス)と一致するか。
		// ルールの agent を変えたとき、旧エージェント宛の既存フローを消すための判定。
		if replySrc != r.AgentAddr {
			continue
		}
		if sourceAllowed(origSrc, r) {
			return true
		}
	}
	return false
}

// sourceAllowed は deny / allow の判定(deny が先)。
func sourceAllowed(src netip.Addr, r Rule) bool {
	for _, p := range r.SourceDeny {
		if p.Contains(src) {
			return false
		}
	}
	if len(r.SourceAllow) == 0 {
		return true
	}
	for _, p := range r.SourceAllow {
		if p.Contains(src) {
			return true
		}
	}
	return false
}

func protoOf(n uint8) proto.Proto {
	switch n {
	case 6:
		return proto.TCP
	case 17:
		return proto.UDP
	}
	return ""
}
