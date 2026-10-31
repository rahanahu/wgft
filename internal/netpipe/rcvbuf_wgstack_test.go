package netpipe

import "github.com/rahanahu/wgft/internal/wgstack"

// wgstack の接続も、中継が型アサーションで探す面を満たすことを、コンパイルの時点で固定する(設計文書
// wgstack.md の「今の境目」)。
var (
	_ boostReporter  = (*wgstack.Conn)(nil)
	_ deliverer      = (*wgstack.Conn)(nil)
	_ deliveryCloser = (*wgstack.Conn)(nil)
	_ closeWriter    = (*wgstack.Conn)(nil)
)
