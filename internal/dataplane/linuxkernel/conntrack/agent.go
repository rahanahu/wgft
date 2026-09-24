//go:build linux

package conntrack

// エージェントのカーネルモードの conntrack の収束(設計文書 7b.4 節)。
//
// テーブル inet wgft_agent を差し替えても conntrack のエントリは残るので、公開の後に、wgft0 から入って
// wgft が DNAT したフローのうち、今の公開に合わないものを消す。ユーザー空間モードの中継がリスナーを
// 閉じ直して得ていた意味(7 節の収束の表)を、カーネルモードではこの収束が担う。
//
// 判定は公開の記録(nft.AgentPublication)だけを使い、エージェントの実行時の状態を持たない。
// 呼び出し側は、最後に収束を済ませた公開と、その後に公開したが収束が済んでいない公開の列を、
// 今の公開とともに渡す。

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/ti-mo/conntrack"
	"github.com/ti-mo/netfilter"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/proto"
)

// AgentScope は、エージェントのホストの conntrack のうち wgft0 から入ったフローを見分ける値と、
// 残すフローの宛先を判定する許可一覧である。
type AgentScope struct {
	// Local は wgft0 のアドレス(エージェントのトンネルアドレス)である。
	Local netip.Addr
	// Peer は vpsd のトンネルアドレスである。wgft0 のピアの AllowedIPs はこのアドレスの /32 だけなので、
	// wgft0 から入るパケットの送信元は必ずこのアドレスになる。
	Peer netip.Addr
	// AllowTarget は宛先の許可一覧の判定である(nft.AgentConfig.AllowTarget と同じもの)。nil なら制限しない。
	AllowTarget func(netip.AddrPort) bool
}

// AgentResult は 1 回の収束の結果である。数は、wgft のフローと見分けたものだけを数える。
type AgentResult struct {
	// Kept は、今の公開に合うので残したフローの数である。
	Kept int
	// Removed は、ポートが宣言から消えたので消したフローの数である。ルールの削除と無効化、
	// エージェントの無効化がこれに当たる。
	Removed int
	// Retargeted は、ポートの実効宛先の宣言が変わったので消したフローの数である。
	Retargeted int
	// NotAllowed は、宣言は変わらないが DNAT の宛先が今の許可一覧の外にあるので消したフローの数である。
	NotAllowed int
	// Failed は、消すべきだったが削除に失敗したフローの数である。
	Failed int
}

// Deleted は消したフローの数である。
func (r AgentResult) Deleted() int { return r.Removed + r.Retargeted + r.NotAllowed }

// String はログの 1 行に載せる要約である。
func (r AgentResult) String() string {
	s := fmt.Sprintf("closed %d flows: %d removed, %d retargeted, %d not allowed; kept %d",
		r.Deleted(), r.Removed, r.Retargeted, r.NotAllowed, r.Kept)
	if r.Failed > 0 {
		s += fmt.Sprintf("; failed to close %d", r.Failed)
	}
	return s
}

// ConvergeAgent は、エージェントのホストの conntrack を公開 cur に収束させる(設計文書 7b.4 節)。
//
// prev は、cur より前の公開を古い順に並べた列である。最後に収束を済ませた公開と、その後に公開したが
// 収束が済んでいない公開を入れる。wgft のフローかどうかは、DNAT の宛先がこの列か cur の宛先に合うかで
// 見分けるので、列が空なら何も消さない。呼び出し側は、収束が済むまで列を状態ファイルに残す。
// 残さないと、収束が済まないまま再起動したときに、記録より前の公開のフローを見分けられない。
//
// conntrack を読めなかった場合と、エントリの削除に失敗した場合は誤りを返す。削除の失敗では、
// 他のフローの削除は続け、結果の数も返す。呼び出し側は同じ prev と cur で試し直す。
func ConvergeAgent(prev []nft.AgentPublication, cur nft.AgentPublication, scope AgentScope) (AgentResult, error) {
	c, err := conntrack.Dial(nil)
	if err != nil {
		return AgentResult{}, fmt.Errorf("conntrack: %w", err)
	}
	defer c.Close()
	return convergeAgent(c, prev, cur, scope)
}

func (s AgentScope) validate() error {
	if !s.Local.Is4() {
		return fmt.Errorf("conntrack: the agent's tunnel address %v is not IPv4", s.Local)
	}
	if !s.Peer.Is4() {
		return fmt.Errorf("conntrack: the server's tunnel address %v is not IPv4", s.Peer)
	}
	return nil
}

// agentConn は ti-mo/conntrack.Conn のうち、エージェントの収束が使う部分である。テストで差し替える。
type agentConn interface {
	DumpFilter(f conntrack.Filter, opts *conntrack.DumpOptions) ([]conntrack.Flow, error)
	Delete(f conntrack.Flow) error
}

// ipv4Only は IPv4 のエントリだけを読む。wgft0 から入るフローは IPv4 だけである。ライブラリの説明では
// 種別で絞る読み出しは Linux 4.20 以降でだけ効くので、判定の側でも IPv4 だけを見る。
var ipv4Only = conntrack.NewFilter().Family(netfilter.ProtoIPv4)

func convergeAgent(c agentConn, prev []nft.AgentPublication, cur nft.AgentPublication, scope AgentScope) (AgentResult, error) {
	if err := scope.validate(); err != nil {
		return AgentResult{}, err
	}
	flows, err := c.DumpFilter(ipv4Only, nil)
	if err != nil {
		return AgentResult{}, fmt.Errorf("conntrack dump: %w", err)
	}
	prevIdx := make([]agentIndex, len(prev))
	for i, p := range prev {
		prevIdx[i] = indexAgent(p)
	}
	curIdx := indexAgent(cur)
	var res AgentResult
	var firstErr error
	for _, f := range flows {
		v := classifyAgentFlow(f, prevIdx, curIdx, scope)
		switch v {
		case agentForeign:
			continue
		case agentKeep:
			res.Kept++
			continue
		}
		// 既に消えていたエントリは、消したのと同じに扱う(タイムアウトや競合で先に消える)
		if err := c.Delete(f); err != nil && !errors.Is(err, unix.ENOENT) {
			res.Failed++
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		switch v {
		case agentRemoved:
			res.Removed++
		case agentRetargeted:
			res.Retargeted++
		case agentNotAllowed:
			res.NotAllowed++
		}
	}
	if firstErr != nil {
		return res, fmt.Errorf("conntrack delete: closing %d of the agent's flows failed, the first with: %w", res.Failed, firstErr)
	}
	return res, nil
}

// agentVerdict は 1 つのフローの判定である。
type agentVerdict int

const (
	// agentForeign は、wgft のフローと見分けられないフローである。触らない。
	agentForeign agentVerdict = iota
	agentKeep
	agentRemoved
	agentRetargeted
	agentNotAllowed
)

// classifyAgentFlow は 1 つのフローを判定する。prev は古い順である。
func classifyAgentFlow(f conntrack.Flow, prev []agentIndex, cur agentIndex, scope AgentScope) agentVerdict {
	// wgft0 から入って DNAT されたフローだけを見る。conntrack は入口のインタフェースを記録しないが、
	// wgft0 のピアの AllowedIPs は vpsd のトンネルアドレスの /32 だけなので、元の向きの送信元と宛先の
	// 組が wgft0 から入ったことを表す
	if !f.Status.DstNAT() {
		return agentForeign
	}
	orig, reply := f.TupleOrig, f.TupleReply
	if orig.IP.SourceAddress.Unmap() != scope.Peer || orig.IP.DestinationAddress.Unmap() != scope.Local {
		return agentForeign
	}
	p := protoOf(orig.Proto.Protocol)
	if p == "" {
		return agentForeign
	}
	port := orig.Proto.DestinationPort
	// 応答の向きの送信元が、DNAT の宛先である
	to := netip.AddrPortFrom(reply.IP.SourceAddress.Unmap(), reply.Proto.SourcePort)

	now := cur.lookup(p, port)
	if now.dest.IsValid() && to == now.dest {
		return agentKeep
	}
	// このフローを作った公開を起点にする。まず、DNAT の宛先を実際に公開した最も新しい公開を探す。
	// 無ければ、宣言からフローを作りえた最も新しい公開を使う。ホスト名の宣言はポートだけで照合するので、
	// 先に宣言で探すと、そのフローを作っていない後の公開を起点に選びうる。どの公開も作りえないフローは、
	// 他のテーブルが DNAT したものとみなして触らない
	i, match := len(prev)-1, matchNone
	for ; i >= 0; i-- {
		if d := prev[i].lookup(p, port); d.dest.IsValid() && d.dest == to {
			match = matchAddr
			break
		}
	}
	if i < 0 {
		for i = len(prev) - 1; i >= 0; i-- {
			if match = prev[i].lookup(p, port).produced(to); match != matchNone {
				break
			}
		}
	}
	if i < 0 {
		return agentForeign
	}
	origin := prev[i].lookup(p, port)
	// 起点から今までの公開が、そのポートを同じ実効宛先の文字列で宣言し続けていれば残す(7 節の収束の表)。
	// 公開できなかったポートも宣言には含まれるので、宣言の変わらない解決の失敗ではフローが残る
	for _, later := range prev[i+1:] {
		if v := origin.follow(later.lookup(p, port)); v != agentKeep {
			return v
		}
	}
	if v := origin.follow(now); v != agentKeep {
		return v
	}
	// 許可一覧が守る範囲はモードで変わらない(7b 節)。一覧の外になった宛先へのフローを残さない。
	// ただし、ポートだけで照合したフローは消さない。他のテーブルが同じポートへ DNAT したフローと
	// 区別できず、wgft が作っていないフローに触れうるためである
	if match == matchAddr && scope.AllowTarget != nil && !scope.AllowTarget(to) {
		return agentNotAllowed
	}
	return agentKeep
}

// agentDecl は、1 つの公開のうち 1 つの (プロトコル, ポート) の宣言である。
type agentDecl struct {
	// found は、そのポートを宣言するルールがあることを表す。公開できなかったポートも含む。
	found bool
	// ok は、宣言の宛先を host:port として読めたことを表す。読めなければ host は空である。
	ok bool
	// host は宣言の宛先のホストである。IP リテラルかホスト名である。
	host string
	// port はそのポートの実効宛先のポートである。宛先のポートに範囲の中の位置を足したものである。
	port int
	// dest は公開した実効宛先である。公開しなかったポートでは無効である。
	dest netip.AddrPort
}

// agentMatch は、フローの DNAT の宛先と宣言の照合の強さである。
type agentMatch int

const (
	matchNone agentMatch = iota
	// matchPort は、ホスト名の宣言とポートだけが合ったことを表す。
	matchPort
	// matchAddr は、アドレスとポートの両方が合ったことを表す。
	matchAddr
)

// produced は、DNAT の宛先が to のフローを、この宣言が作りえたかどうかである。ホスト名の宛先は、
// 公開の記録が解決の結果の履歴を持たないので、ポートだけを比べる。
func (d agentDecl) produced(to netip.AddrPort) agentMatch {
	if !d.ok || int(to.Port()) != d.port {
		return matchNone
	}
	if a, err := netip.ParseAddr(d.host); err == nil {
		if a.Unmap() == to.Addr() {
			return matchAddr
		}
		return matchNone
	}
	return matchPort
}

// follow は、d の宣言で作ったフローを、後の宣言 later の下で残すかどうかである。宛先を読めない宣言の
// host は空なので、d とは一致しない。
func (d agentDecl) follow(later agentDecl) agentVerdict {
	switch {
	case !later.found:
		return agentRemoved
	case later.host != d.host || later.port != d.port:
		return agentRetargeted
	}
	return agentKeep
}

// agentIndex は 1 つの公開を、ポートの宣言を引ける形にしたものである。
type agentIndex []agentRuleDecl

type agentRuleDecl struct {
	proto  proto.Proto
	listen proto.PortRange
	ok     bool
	host   string
	port   int // listen.Lo の実効宛先のポート
	ranges []nft.AgentRange
}

func indexAgent(pub nft.AgentPublication) agentIndex {
	idx := make(agentIndex, 0, len(pub.Rules))
	for _, r := range pub.Rules {
		d := agentRuleDecl{proto: r.Proto, listen: r.ListenPort, ranges: r.Ranges}
		if host, ps, err := net.SplitHostPort(r.Target); err == nil && host != "" {
			if n, err := strconv.ParseUint(ps, 10, 16); err == nil && n != 0 {
				d.ok, d.host, d.port = true, host, int(n)
			}
		}
		idx = append(idx, d)
	}
	return idx
}

// lookup は (p, port) の宣言を引く。ルールの範囲は重ならない(server が検査する)ので、最初に合う
// ルールを使う。
func (idx agentIndex) lookup(p proto.Proto, port uint16) agentDecl {
	for _, r := range idx {
		if r.proto != p || !r.listen.Contains(port) {
			continue
		}
		d := agentDecl{found: true, ok: r.ok, host: r.host}
		if r.ok {
			d.port = r.port + int(port-r.listen.Lo)
		}
		for _, rg := range r.ranges {
			if rg.Ports.Contains(port) {
				d.dest = netip.AddrPortFrom(rg.Dest.Addr().Unmap(), rg.Dest.Port()+(port-rg.Ports.Lo))
				break
			}
		}
		return d
	}
	return agentDecl{}
}
