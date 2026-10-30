package wgstack

import "errors"

// 会計の不整合の検出(wgstack.md の「未確認の点と未決の点」の会計の不整合)。送る segment の範囲が送信の輪と
// 番号の会計に合わなければ、壊れた状態で送り続けず、RST を送って接続を閉じる。

// errAccounting は会計の不整合で閉じた接続の誤り。
var errAccounting = errors.New("wgstack: closed the connection after an internal accounting error")

// sendRangeOK は、再送する [seq, seq+n) が SND.UNA から SND.MAX の内側にあり、送信の輪の生きている範囲に
// 収まるかを返す。
func (c *tcb) sendRangeOK(seq, n uint32) bool {
	if !seqGE(seq, c.sndUna) || seqGT(seq+n, c.sndMax) {
		return false
	}
	off := c.unaOff + uint64(seq-c.sndUna)
	return off+uint64(n) <= c.tailOff
}

// accountingFault は会計の不整合を数えて記録し、RST を送って接続を閉じる。mu を持って呼ぶ。
func (c *tcb) accountingFault(now int64) {
	c.s.refused(&c.s.accountingFaults, &c.s.faultGate, now, "closed a connection after an internal accounting error")
	c.sendRST()
	c.abortWith(errAccounting)
}
