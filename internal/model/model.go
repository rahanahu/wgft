// Package model は、外部契約(proto.Rule)から正規化した内部のドメインモデルを持つ(設計文書 7a.2 節)。
//
// このパッケージは OS、nftables、gVisor を知らない純粋な Go の型と関数だけを持つ。
// dataplane、frontend、platform、vpsd、agent のどの package も import しない(設計文書 7a.7 節)。
// proto パッケージは外部契約であり、import してよい対象に含まれる。
package model

import "fmt"

// Forwarding はルール 1 本の転送の意味を選ぶ(設計文書 7a.2 節)。
// DataplaneMode(server・agent 全体の転送方式)と紛れる「kernel」という語を、
// ルール単位の選択には使わない。
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

// DataplaneMode は server 全体、あるいは agent 全体の転送方式を選ぶ(設計文書 7a.2 節)。
// 今の WGFT_MODE に当たる、ルールではなくプロセス単位の値である。
type DataplaneMode int

const (
	// Kernel はカーネルの nftables と WireGuard を使う(今の WGFT_MODE=kernel)。
	Kernel DataplaneMode = iota
	// Userspace は wireguard-go と gVisor の netstack だけを使う(今の WGFT_MODE=userspace)。
	Userspace
)

func (m DataplaneMode) String() string {
	switch m {
	case Kernel:
		return "kernel"
	case Userspace:
		return "userspace"
	default:
		return fmt.Sprintf("DataplaneMode(%d)", int(m))
	}
}

// ParseDataplaneMode は WGFT_MODE の値("kernel"/"userspace")を解釈する。
// この 2 語は外部契約(設計文書 7a.6 節)なので、DataplaneMode.String() と対にして変えない。
func ParseDataplaneMode(s string) (DataplaneMode, error) {
	switch s {
	case "kernel":
		return Kernel, nil
	case "userspace":
		return Userspace, nil
	default:
		return 0, fmt.Errorf("mode %q is neither kernel nor userspace", s)
	}
}
