package wgstack

// 受け手の ACK の送り方のうち、遅延 ACK の外で ACK を早める規則。

// minRcvMSSEst は相手の segment の大きさの推定の初期値の上限(Linux の TCP_MSS_DEFAULT)。
const minRcvMSSEst = 536

// measureRcvMSS は順序どおりに受けた n byte の segment で相手の segment の大きさの推定を更新する(Linux の
// tcp_measure_rcv_mss)。mu を持って呼ぶ。
func (c *tcb) measureRcvMSS(n int) {
	if c.rcvMSSEst == 0 {
		c.rcvMSSEst = uint32(min(minRcvMSSEst, c.rcvMSS()))
	}
	if uint32(n) >= c.rcvMSSEst {
		c.rcvMSSEst = uint32(min(n, c.rcvMSS()))
	}
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
	c.raiseQuickack()
}

// raiseQuickack は遅らせずに返す ACK の数を、広告した窓の 2 MSS ごとに 1 つ、2 から quickackMax の間の数まで
// 上げる。進んでいる数は下げない(Linux の tcp_incr_quickack)。
func (c *tcb) raiseQuickack() {
	q := uint64(c.rcvWindow()) / (2 * uint64(max(c.rcvMSSEst, 1)))
	c.quickAcks = max(c.quickAcks, uint8(min(max(q, 2), quickackMax)))
}

// noteDuplicate は、既に届いていた [seq, seq+n) を受けたとき、その範囲を D-SACK の block として次の ACK の
// 先頭に載せ(RFC 2883)、quickack に入って対話の印を外す(Linux の tcp_dsack_set、tcp_dsack_extend、
// tcp_enter_quickack_mode)。ACK を送る前に次の重複が届けば、接するか重なるときだけ block を広げる。mu を
// 持って呼ぶ。
func (c *tcb) noteDuplicate(seq, n uint32, now int64) {
	if n == 0 {
		return
	}
	if c.sackOK {
		b := sackBlock{seq, seq + n}
		switch {
		case !c.dsackPending:
			c.dsack, c.dsackPending = b, true
		case seqLE(b.left, c.dsack.right) && seqLE(c.dsack.left, b.right):
			c.dsack = sackBlock{seqMin(b.left, c.dsack.left), seqMax(b.right, c.dsack.right)}
		}
	}
	c.raiseQuickack()
	c.pingpong = false
}

// ackOnDrain は、アプリケーションの読み取りが受信のバッファを空にし、遅延 ACK を待つ segment があるとき、
// 対話の流れでなければ ACK をすぐ送る。遅延 ACK はアプリケーションに窓を更新させ、応答を同じ segment に
// 載せる機会を与えるために待つ(RFC 1122 4.2.3.2)。読み取りで窓は更新済みで、対話の流れでなければ応答も
// 来ないので、待つ理由が残らない。segment の大きさによらない。読み手が追いつく間は segment ごとに ACK を
// 返し(RFC 5681 4.2 の「少なくとも 2 つ目ごと」の内側)、読み手が遅れる間は 2 segment ごとの規則に戻る。
// mu を持って呼ぶ。
func (c *tcb) ackOnDrain() {
	if !c.pingpong && c.rcv.unread() == 0 && c.tdl[tmrDelack] != 0 {
		c.ackNow = true
	}
}
