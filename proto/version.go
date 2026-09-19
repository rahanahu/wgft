package proto

// wire protocol の版と機能の交渉(仕様 7a.6 節)。番号の付いた版は 1 から始まる。agent の
// pubkey メッセージに protocol_min/protocol_max が無い、または vpsd の state メッセージに
// server_protocol_version が無い場合は legacy v0 として別に扱う(このファイルの型は関与しない。
// 版のフィールドの有無で判定する。proto/stream.go、proto/state.go を参照)。

// ProtocolRange は話せる版の範囲(両端を含む)。
type ProtocolRange struct {
	Min int
	Max int
}

// SupportedProtocol は、この build の server と agent が共通に話せる、番号の付いた版の範囲。
// 現在の版と直前の版を必ず支えるという約束により、v2 を追加する変更は Max を 2 に広げるだけで、
// v1 を落とすときに初めて Min を 2 に上げる。SelectProtocolVersion 自体は変えなくてよい。
var SupportedProtocol = ProtocolRange{Min: 1, Max: 1}

// SupportedCapabilities は、この build が持つ capability の語彙。今のところ語彙が無いため空。
var SupportedCapabilities = []string{}

// SelectProtocolVersion は、local と remote の範囲の共通部分のうち最大の版を選ぶ(仕様 7a.6 節)。
// 共通部分が無ければ ok は false。
func SelectProtocolVersion(local, remote ProtocolRange) (version int, ok bool) {
	lo := local.Min
	if remote.Min > lo {
		lo = remote.Min
	}
	hi := local.Max
	if remote.Max < hi {
		hi = remote.Max
	}
	if lo > hi {
		return 0, false
	}
	return hi, true
}

// Negotiated は、1 本の stream 接続について選んだ版と、agent が宣言した機能(仕様 7a.6 節)。
// Legacy が true なら agent は版のフィールドを持たない legacy v0 で、Version 以下のフィールドは
// 意味を持たない(全体状態には版のフィールドを載せない)。
type Negotiated struct {
	Legacy       bool
	Version      int      // 選んだ版(Legacy なら 0)
	AgentMin     int      // agent が宣言した protocol_min(Legacy なら 0)
	AgentMax     int      // agent が宣言した protocol_max(Legacy なら 0)
	Capabilities []string // agent が宣言した capabilities(Legacy か、宣言が無ければ nil)
}
