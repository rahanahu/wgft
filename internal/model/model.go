// Package model は、維持する外部仕様(proto.Rule)から正規化した内部のドメインモデルを持つ(設計文書 7a.2 節)。
//
// このパッケージは OS、nftables、gVisor を知らない純粋な Go の型と関数だけを持つ。
// dataplane、frontend、platform、vpsd、agent のどの package も import しない(設計文書 7a.7 節)。
// proto パッケージは維持する外部仕様であり、import してよい対象に含まれる。
package model

import "fmt"

// Forwarding はルール 1 本の転送の意味を選ぶ(設計文書 7a.2 節)。
// server・agent 全体の転送方式(今の WGFT_MODE。internal/vpsd が持つ文字列の語彙で、この
// パッケージの型ではない)と紛れる「kernel」という語を、ルール単位の選択には使わない。
type Forwarding int

const (
	// Transparent は素通しの転送(今の proto.ModeKernel)。nftables の DNAT で完結する。
	Transparent Forwarding = iota
	// Relay は vpsd 自身が TCP を終端して中継する転送(今の proto.ModeProxy)。
	Relay
)

func (f Forwarding) String() string {
	switch f {
	case Transparent:
		return "transparent"
	case Relay:
		return "relay"
	default:
		return fmt.Sprintf("Forwarding(%d)", int(f))
	}
}

// SourceMetadata は、中継が接続先へ送信元の情報を付けるかどうかを選ぶ(設計文書 7a.2 節)。
// Transparent と組み合わせられるのは NoSourceMetadata だけである。
type SourceMetadata int

const (
	// NoSourceMetadata は送信元の情報を付けない(今の proxy_protocol=false)。
	NoSourceMetadata SourceMetadata = iota
	// ProxyV2 は PROXY protocol v2 ヘッダを先頭に付ける(今の proxy_protocol=true)。Relay でしか選べない。
	ProxyV2
)

func (m SourceMetadata) String() string {
	switch m {
	case NoSourceMetadata:
		return "none"
	case ProxyV2:
		return "proxy-v2"
	default:
		return fmt.Sprintf("SourceMetadata(%d)", int(m))
	}
}
