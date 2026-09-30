//go:build !linux

package netpipe

import "syscall"

// Linux 以外では受信と送信のバッファを固定しない。OS の既定の自動調整に任せる。Windows と macOS で
// 固定したときの速さと、ホスト全体の TCP のメモリの上限の働き方を確かめていないためである
// (設計文書 7 節)。枠の知らせも登録しないので、netstack の接続が floor に戻るのを止めることもない。
func followBoost(syscall.RawConn, boostReporter) {}
