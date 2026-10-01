package netpipe

import "github.com/rahanahu/wgft/internal/nettun"

// 本番の netstack の接続が boostReporter を満たすことを、コンパイルの時点で固定する。FollowBoost は
// 実行時の型の判定で組を見分けるので、OnBoost の形が変わると、誤りを出さずにカーネルの側の固定を
// やめる(設計文書 7 節)。
var _ boostReporter = (*nettun.TCPConn)(nil)
