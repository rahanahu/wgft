package wgstack

// 輻輳の窓の検証(RFC 7661、wgstack-performance.md の段の順序)。送り残しが輻輳の窓に届かない、アプリケーションに
// 制限された間は窓を増やさない。窓の使い方は 1 往復(cwndUsageSeq まで)ごとに数える(Linux の tcp_cwnd_validate)。

// noteCwndUse は新しいデータを送った後と、輻輳の窓が新しいデータを止めた時に呼ぶ。limited は輻輳の窓が止めたか、
// 送った後の輻輳の窓に 1 segment の余地が無いか。
// この窓の間に止められたことと、送り残しの最大を覚える。mu を持って呼ぶ。
func (c *tcb) noteCwndUse(limited bool) {
	flight := c.sndMax - c.sndUna
	if !seqLT(c.sndUna, c.cwndUsageSeq) || limited || (!c.cwndLimited && flight > c.maxFlight) {
		c.cwndLimited = limited
		c.maxFlight = flight
		c.cwndUsageSeq = c.sndMax
	}
}

// isCwndLimited は窓を増やしてよいかを返す(Linux の tcp_is_cwnd_limited)。この窓の間に輻輳の窓が送るのを
// 止めたか、slow start の間なら窓が送り残しの最大の 2 倍に届いていないときに真である。
func (c *tcb) isCwndLimited() bool {
	if c.cwndLimited {
		return true
	}
	if c.cwnd < c.ssthresh {
		return c.cwnd < 2*c.maxFlight
	}
	return false
}
