package wgstack

// 送り出しを遅らせることの補正(wgstack-performance.md の「ACK のまとまりと遅れた送り出し」)。wgstack は
// Device の Read の時に segment を作るので、まとめて届いた ACK を処理する間は SND.NXT が進まず、送り残しが
// 空になることがある。ACK のたびに送る送り手を前提にした規則には、その送り手が今までに送っていたはずの
// 状態を渡す。

// sendableEnd は、ACK のたびに送る送り手なら今の SND.NXT になっている番号を返す。HyStart++ は ACK を処理する
// 前にこの値を取り、往復を始めた時の SND.NXT にする。今の SND.NXT に、輻輳の窓と
// 相手の窓が許し、書き込まれていて未送信の新しいデータを足す。
func (c *tcb) sendableEnd() uint32 {
	end := c.sndNxt
	if seqGT(c.sndMax, end) {
		end = c.sndMax
	}
	pipe := c.pipe()
	if c.cwnd <= pipe {
		return end
	}
	lim := seqMin(c.dataEndSeq(), c.sndUna+c.sndWnd)
	if seqGT(lim, end) {
		end += min(c.cwnd-pipe, lim-end)
	}
	return end
}

// noteDrainedWithData は、ACK が送り残しを空にした時に送れる新しいデータがあれば、その時刻を最後に送った時刻
// とする。ACK のたびに送る送り手はこの時に送っているので、次の Read までの間を黙っていた時間に数えない
// (黙った後の輻輳の窓と CUBIC の epoch のずらし)。
func (c *tcb) noteDrainedWithData(now int64) {
	if c.sndUna == c.sndMax && c.hasNewData() {
		c.lastSendAt = now
	}
}
