package nettun

// IPv4 の断片の再組み立ての表は、wgstack と共有するために葉の package internal/ipv4frag に置く(設計文書
// wgstack.md の「package の配置」)。ここでは、この package の中の名前を表の型と値に結び付け、Device が
// 表を作る上限と、表を呼ぶ前の口を持つ。

import (
	"sync/atomic"

	"github.com/rahanahu/wgft/internal/ipv4frag"
)

type (
	ipv4ReassemblyLimits = ipv4frag.Limits
	ipv4FragmentNotice   = ipv4frag.Notice
	ipv4Reassembly       = ipv4frag.Table
)

const (
	ipv4FragmentHeld      = ipv4frag.Held
	ipv4FragmentComplete  = ipv4frag.Complete
	ipv4FragmentDuplicate = ipv4frag.Duplicate
	ipv4FragmentRejected  = ipv4frag.Rejected
	ipv4FragmentCapacity  = ipv4frag.Capacity
	ipv4FragmentClosed    = ipv4frag.Closed

	ipv4ReasonNone      = ipv4frag.ReasonNone
	ipv4ReasonMalformed = ipv4frag.ReasonMalformed
	ipv4ReasonOptions   = ipv4frag.ReasonOptions
	ipv4ReasonOverlap   = ipv4frag.ReasonOverlap
	ipv4ReasonConflict  = ipv4frag.ReasonConflict
	ipv4ReasonExpired   = ipv4frag.ReasonExpired
	ipv4ReasonCapacity  = ipv4frag.ReasonCapacity
)

var newIPv4Reassembly = ipv4frag.New

func ipv4SetChecksum(h []byte) { ipv4frag.SetChecksum(h) }

// reassemblyLimits は Device が作る再組み立ての表の上限。値は設計文書の値で、試験だけが Device を作る前に
// 置き換える。
var reassemblyLimits = ipv4ReassemblyLimits{
	Entries: reassemblyEntries, Fragments: reassemblyFragments, Bytes: reassemblyBytes, Lifetime: reassemblyLifetime,
}

// reassemblyHook は、Device が表の Process と Sweep を呼ぶ前に呼ぶ口。nil なら何もしない。試験が、表の処理が
// 長くかかる場合を模すために置く。
var reassemblyHook atomic.Pointer[func()]

func callReassemblyHook() {
	if h := reassemblyHook.Load(); h != nil {
		(*h)()
	}
}
