package wgstack

// 受け手の ACK の送り方のうち、遅延 ACK の外で ACK を早める規則。

// minRcvMSSEst は相手の segment の大きさの推定の初期値の上限(Linux の TCP_MSS_DEFAULT)。
const minRcvMSSEst = 536

// notePushed は順序どおりに受けた n byte の segment で相手の segment の大きさの推定を更新し、推定より小さな
// segment なら印を付ける(Linux の tcp_measure_rcv_mss と ICSK_ACK_PUSHED)。mu を持って呼ぶ。
func (c *tcb) notePushed(n int) {
	if c.rcvMSSEst == 0 {
		c.rcvMSSEst = uint32(min(minRcvMSSEst, c.rcvMSS()))
	}
	if uint32(n) >= c.rcvMSSEst {
		c.rcvMSSEst = uint32(min(n, c.rcvMSS()))
		return
	}
	c.ackPushed = true
}

// quickackMax は遅らせずに返す ACK の数の上限(Linux の TCP_MAX_QUICKACKS)。
const quickackMax = 16

// noteQuickack は、接続の始めの最初のデータと、RTO より長く黙った後のデータで、遅らせずに返す ACK の数を
// 補う(Linux の tcp_event_data_recv と tcp_incr_quickack)。数は広告した窓の 2 MSS ごとに 1 つで、2 以上
// quickackMax 以下にする。mu を持って呼ぶ。
func (c *tcb) noteQuickack(now int64) {
	if c.rcvdData && now-c.lastDataRcvd <= c.curRTO() {
		return
	}
	q := uint64(c.rcvWindow()) / (2 * uint64(max(c.rcvMSSEst, 1)))
	c.quickAcks = uint8(min(max(q, 2), quickackMax))
}

// noteDuplicate は、すべて届いていた segment を受けたとき、その範囲を D-SACK の block として次の ACK の
// 先頭に載せ(RFC 2883)、ACK を遅らせない(Linux の tcp_enter_quickack_mode)。mu を持って呼ぶ。
func (c *tcb) noteDuplicate(seq, n uint32, now int64) {
	if n == 0 {
		return
	}
	if c.sackOK {
		c.dsack, c.dsackPending = sackBlock{seq, seq + n}, true
	}
	c.quickAcks = max(c.quickAcks, 2)
}

// ackOnDrain は、アプリケーションの読み取りが受信のバッファを空にし、遅延 ACK を待つ小さな segment がある
// とき、対話の流れでなければ ACK をすぐ送る(Linux の tcp_cleanup_rbuf)。通信量の少ない stream の受け手は
// segment ごとに ACK を返すので、送り手は ACK を待って新しいデータを止めない。mu を持って呼ぶ。
func (c *tcb) ackOnDrain() {
	if c.ackPushed && !c.pingpong && c.rcv.unread() == 0 && c.tdl[tmrDelack] != 0 {
		c.ackNow = true
	}
}
