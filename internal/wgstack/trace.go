package wgstack

import (
	"net/netip"
	"time"
)

// 試験と性能の測定だけが使う観測(wgstack-performance.md の「安く確かめる手順」)。本番の Device は
// Config.Trace を nil、Config.TestBoost を既定の値のまま使う。

// TraceKind は TraceEvent の種類。
type TraceKind uint8

const (
	TraceAck TraceKind = iota // ACK を 1 つ処理した後
	TraceRTO                  // 再送のタイマーの期限で送り直しを決めた後
)

// TraceEvent は Config.Trace に渡す接続の送り手の状態。
type TraceEvent struct {
	Kind          TraceKind
	At            time.Duration // 核の時刻
	Local, Remote netip.AddrPort
	Cwnd          uint32
	Ssthresh      uint32
	Flight        uint32 // SND.MAX - SND.UNA
	Pipe          uint32 // RFC 6675 の pipe
	Sacked        uint32 // SACK 済みの byte
	SndUna        uint32
	SndNxt        uint32
	SndMax        uint32
	InRecovery    bool
	DupAcks       int
	PeerWnd       uint32 // 相手が広告した窓(scale を掛けた byte)
	AdvWnd        uint32 // 自分が広告した窓の右端から RCV.NXT までの byte
	SRTT          time.Duration
	RTO           time.Duration // 後退を含む今の RTO
}

// 再送の原因。Stats の Retrans の欄の添字である。
const (
	rtxFast    uint8 = iota // 3 つの重複した ACK による高速の再送
	rtxPartial              // 回復の中の部分の確認による再送
	rtxRTO                  // RTO の後に SND.UNA から送り直した segment
	rtxPMTU                 // PMTU の引き下げの後に SND.UNA から送り直した segment
	numRtxCauses
)

// BoostPolicy は試験だけが使う boost の与え方(Config.TestBoost)。
type BoostPolicy uint8

const (
	BoostOnDemand BoostPolicy = iota // 既定。需要の区間が demandBytes に届いたときに求める
	BoostAtAccept                    // Accept が接続を返すときに両方の向きの boost を求める
	BoostNever                       // boost を求めない
)

// traceEvent は Config.Trace に今の状態を渡す。接続の錠を持って呼ぶ。
func (c *tcb) traceEvent(kind TraceKind, now int64) {
	var adv uint32
	if c.advRight > c.rcv.nxtOff {
		adv = uint32(min(c.advRight-c.rcv.nxtOff, 1<<32-1))
	}
	c.s.trace(TraceEvent{
		Kind:       kind,
		At:         time.Duration(now),
		Local:      netip.AddrPortFrom(addrFrom(c.tup.laddr), c.tup.lport),
		Remote:     netip.AddrPortFrom(addrFrom(c.tup.raddr), c.tup.rport),
		Cwnd:       c.cwnd,
		Ssthresh:   c.ssthresh,
		Flight:     c.sndMax - c.sndUna,
		Pipe:       c.pipe(),
		Sacked:     c.sacked,
		SndUna:     c.sndUna,
		SndNxt:     c.sndNxt,
		SndMax:     c.sndMax,
		InRecovery: c.inRecovery,
		DupAcks:    c.dupAcks,
		PeerWnd:    c.sndWnd,
		AdvWnd:     adv,
		SRTT:       time.Duration(c.srtt),
		RTO:        time.Duration(c.curRTO()),
	})
}
