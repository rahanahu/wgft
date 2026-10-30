package wgstack

import (
	"time"

	"github.com/rahanahu/wgft/internal/ipv4frag"
)

// IPv4 の断片の入口。断片はすべて internal/nettun と共有する再組み立ての表(internal/ipv4frag)に渡し、完成した
// datagram だけを核の入口に戻す(設計文書の「UDP、ICMP、再組み立て」と packet-validation.md の再組み立ての表)。
// Time Exceeded と Parameter Problem は wgstack が自分で作り、送る条件は表の package が決める。

// 再組み立ての表の上限。値は internal/nettun と同じで、設定項目にしない。
var fragLimits = ipv4frag.Limits{Entries: 128, Fragments: 512, Bytes: 4 << 20, Lifetime: 30 * time.Second}

const fragSweep = int64(time.Second)

func coreTime(now int64) time.Time { return time.Unix(0, now) }

// inputFragment は 1 つの断片を表に渡す。
func (s *stack) inputFragment(ip *ipv4, now int64) {
	pkt := ip.header[:ip.hlen+len(ip.payload)]
	res := s.frag.Process(pkt, coreTime(now))
	if res.Status == ipv4frag.Rejected && res.Notice.Reason == ipv4frag.ReasonExpired {
		// 前の項目の期限を知らせた後、この断片を空いた項目で処理し直す
		s.fragNotice(res.Notice, nil, now)
		res = s.frag.Process(pkt, coreTime(now))
	}
	switch res.Status {
	case ipv4frag.Held:
		s.fragments.Add(1)
		s.noteFragSweep(now)
	case ipv4frag.Duplicate, ipv4frag.Closed:
		s.fragments.Add(1)
	case ipv4frag.Complete:
		s.input(res.Packet, now)
	case ipv4frag.Capacity:
		s.fragments.Add(1) // 1 つの datagram だけで表が満ちる。ICMP を返さずに捨てる
	default:
		s.fragments.Add(1)
		s.fragNotice(res.Notice, pkt, now)
	}
}

// fragNotice は表の知らせに ICMP の誤りを返す。期限には Time Exceeded、option の誤りには Parameter Problem を
// 返す。送る条件は internal/nettun と同じである(packet-validation.md の断片に対する ICMP)。
func (s *stack) fragNotice(n ipv4frag.Notice, offending []byte, now int64) {
	if (n.Reason != ipv4frag.ReasonExpired && n.Reason != ipv4frag.ReasonOptions) ||
		(!n.HasFirst && n.Reason != ipv4frag.ReasonOptions) {
		return
	}
	// 保存した最初の引用は、後から届いた不正な断片を対象にしない
	if n.Reason == ipv4frag.ReasonOptions && n.HasFirst && len(offending) >= 8 &&
		(int(offending[6])<<8|int(offending[7]))&0x1fff != 0 {
		return
	}
	local := addrFrom(s.addr).As4()
	if n.Reason == ipv4frag.ReasonExpired {
		quote, ok := n.TimeoutQuote(local)
		if !ok {
			return
		}
		s.sendICMPErrorRaw(quote, icmpTimeExceeded, 1, 0, now, false)
		return
	}
	if _, ok := n.ParamProblemOK(offending, local); !ok {
		return
	}
	s.sendICMPErrorRaw(offending, icmpParamProblem, 0, uint32(n.Pointer)<<24, now, true)
}

// noteFragSweep は、断片を保持した後に次の掃除の期限をタイマーの goroutine に知らせる。goroutine は眠る前に
// 表が空なら掃除の期限を数えないので、知らせないと何も起きない Device では最長 1 時間眠り、寿命の 30 秒を過ぎても
// 項目を外さない。期限が過ぎていれば今から 1 秒後にする。
func (s *stack) noteFragSweep(now int64) {
	d := s.fragNextSweep.Load()
	if d <= now {
		d = now + fragSweep
		s.fragNextSweep.Store(d)
	}
	s.noteDeadline(d)
}

// sweepFrag は 1 秒ごとに期限を過ぎた項目を外し、Time Exceeded を返す。advance から呼ぶ。
func (s *stack) sweepFrag(now int64) {
	if now < s.fragNextSweep.Load() {
		return
	}
	s.fragNextSweep.Store(now + fragSweep)
	for _, n := range s.frag.Sweep(coreTime(now)) {
		s.fragNotice(n, nil, now)
	}
}
