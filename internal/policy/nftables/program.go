// Package nftables は、AdmissionPolicy の IR(internal/policy)を nftables の行の列へコンパイルする
// (設計文書 7a.9 節「nftables へのコンパイルの約束」)。
//
// 出力の Program は、google/nftables を import しない素の Go のデータである。
// internal/dataplane/linuxkernel/nft が行の列を nftables の式へ写し、DNAT、input、forward、
// postrouting の行を加える。テスト専用の解釈器(internal/policy/nftables/interp)は、IR を読まずに
// この行の列だけを入力にして、共有 fixture(internal/policy/testdata/admission)の出来事を流す。
//
// このパッケージは internal/policy、internal/model、proto だけを import し、dataplane、frontend、
// platform を import しない(設計文書 7a.7 節)。
package nftables

import (
	"net/netip"
	"time"

	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// Port は判定の行を付けるポート 1 つ(Plan の Transparent のポートと、frontend が待ち受けを
// 開けている Relay のポート)。並びは Plan の順で、この順が行の順になる。
type Port struct {
	RuleID     string
	Proto      proto.Proto
	Ports      proto.PortRange
	Forwarding model.Forwarding
}

// SetKind は set の種類。
type SetKind int

const (
	// SetInterval は `flags interval` の set(deny_N、allow_N)。要素は Elements で固定する。
	SetInterval SetKind = iota
	// SetMeter は送信元ごとの limit を持つ動的 set(meter_N)。`flags dynamic`、Timeout、Size を持つ。
	SetMeter
	// SetFlowCount は送信元ごとの同時フロー数を数える動的 set(flows_udp、flows_tcp)。
	// ct count と組み合わせるので timeout を持たない(設計文書 6.1 節)。
	SetFlowCount
)

// Set は 1 つの名前付き set の宣言。キーはどれも IPv4 の送信元アドレスである。
type Set struct {
	Name     string
	Kind     SetKind
	Elements []netip.Prefix // SetInterval だけ。policy.Build が正規化した CIDR の列
	Timeout  time.Duration  // SetMeter だけ
	Size     int            // SetMeter と SetFlowCount
}

// Match は行の一致条件のうち、送信元の set を除いたもの。どの行も `iifname != "<wg>"` を
// 先頭に持つが、インタフェース名は写す側(nft)の設定なので、ここには持たない。
type Match struct {
	Proto      proto.Proto
	Ports      proto.PortRange
	CtStateNew bool // `ct state new`。成立済みのフローのパケットには一致しない
	// IPv4 は `meta nfproto ipv4`。IPv4 のパケットにだけ一致する。v1 の Admission Policy の行は、
	// 送信元を読まない集約のレートの行を含めて、すべて持つ(設計文書 7a.9 節「IPv4 だけを扱う v1 の
	// 守り」)。inet のテーブルでは、これが無いと IPv6 のパケットが集約のトークンを使い、IPv4 の
	// 通信の new_flow_rate と packet_rate を締め出せる
	IPv4 bool
}

// StmtKind は行の文の種類。
type StmtKind int

const (
	// StmtSourceInSet は `ip saddr @Set`(deny)。
	StmtSourceInSet StmtKind = iota
	// StmtSourceNotInSet は `ip saddr != @Set`(allow)。
	StmtSourceNotInSet
	// StmtPerSourceLimit は `add @Set { ip saddr limit rate over Rate burst Burst packets }`。
	// 要素(送信元)ごとにトークンバケットを持つ。
	StmtPerSourceLimit
	// StmtPerSourceCtCount は `add @Set { ip saddr ct count over Count }`。
	StmtPerSourceCtCount
	// StmtLimit は `limit rate over Rate burst Burst packets`(集約のトークンバケット。行ごとに 1 つ)。
	StmtLimit
)

// Stmt は行の文。Kind によって使うフィールドが決まる。
type Stmt struct {
	Kind  StmtKind
	Set   string     // StmtSourceInSet、StmtSourceNotInSet、StmtPerSourceLimit、StmtPerSourceCtCount
	Rate  proto.Rate // StmtPerSourceLimit、StmtLimit
	Burst uint32     // StmtPerSourceLimit、StmtLimit
	Count uint32     // StmtPerSourceCtCount
}

// UsesSource は文が `ip saddr`(IPv4 の送信元)を読むかを返す。読む行は Match.IPv4 に関わらず、
// IPv4 のパケットにだけ一致する(nft が `ip saddr` の前に `meta nfproto ipv4` を置く)。
func (s Stmt) UsesSource() bool { return s.Kind != StmtLimit }

// Row は filter_pre の行 1 つ。文が一致すれば `counter drop` する。判定は常に drop なので、
// フィールドには持たない。
type Row struct {
	RuleID  string
	Step    policy.Step
	Kind    string // drop の種類(Step.DropKind())
	Comment string // `wgft:<ルール ID>:<種類>`。drop カウンタの持ち主をこれで特定する
	Match   Match
	Stmt    Stmt
}

// Program は IR をコンパイルした結果。
//
// Sets は、行が初めて参照する順に並ぶ。写す側は、行が初めて参照した時点で set を宣言すれば、
// set と行を今と同じ順に送れる。Rows はポートの順、1 つのポートの中では policy.Order の順に並ぶ。
type Program struct {
	Sets []Set
	Rows []Row
}

// Set は名前で set を探す。
func (p Program) Set(name string) (Set, bool) {
	for _, s := range p.Sets {
		if s.Name == name {
			return s, true
		}
	}
	return Set{}, false
}

// Comment は行に付けるカウンタのコメント(`wgft:<ルール ID>:<種類>`)。
// internal/dataplane/linuxkernel/nft の DNAT の行も同じ形を使う。
func Comment(ruleID, kind string) string { return "wgft:" + ruleID + ":" + kind }
