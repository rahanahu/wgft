package nettun

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"

	"github.com/rahanahu/wgft/internal/lograte"
)

// DefaultTCPClosingCap は、SetTCPClosingCap を呼ばない Device が使う閉じかけの TCP の endpoint の
// 天井 K。値は WGFT_MAX_TCP_FLOWS の既定(resource.TCPTotal)と同じにする。tunnel と utun は
// 必ず resource.Limits の値で SetTCPClosingCap を呼ぶので、この既定を使うのは試験の Device だけ
// である。0 を「上限なし」にしないのは、設定層を通らずに作った Device で守りが黙って外れないため
// (設計文書 7a.10 節の WithDefaults と同じ理由)。
const DefaultTCPClosingCap = 2048

// tcpClosing は、中継が閉じた後も gVisor に残る TCP の endpoint(FIN_WAIT_1、FIN_WAIT_2、CLOSING、
// CLOSE_WAIT、LAST_ACK、TIME_WAIT)の数の 2 段の天井(設計文書 7 節「閉じた後の TCP の endpoint の
// 上限」)。数は gVisor の統計 CurrentConnected と CurrentEstablished の差で、TCPConn.Close のたびに
// 読む。差が K 以上なら TIME_WAIT の endpoint だけを、2K 以上なら状態を問わず、graceful close の
// 代わりに Abort(RST)で直ちに解放する。K の段はデータを失わない。2K の段は未配送の応答を捨てる。
// Linux の tcp_max_tw_buckets と tcp_max_orphans に当たる過負荷の分岐で、天井の下では TCP の
// 意味を変えない。reaper も timer も goroutine も持たず、統計の読み取りと比較だけである。
type tcpClosing struct {
	cap              atomic.Int64 // K
	releasedTimeWait atomic.Uint64
	releasedOther    atomic.Uint64
	releaseLog       lograte.Gate
}

// SetTCPClosingCap は天井 K を設定する。0 以下なら DefaultTCPClosingCap になる。
func (t *Device) SetTCPClosingCap(k int) {
	if k <= 0 {
		k = DefaultTCPClosingCap
	}
	t.tcpClosing.cap.Store(int64(k))
}

// TCPClosingCap は天井 K。
func (t *Device) TCPClosingCap() int { return int(t.tcpClosing.cap.Load()) }

// TCPClosing は今の閉じかけの TCP の endpoint の数。2 つの統計は別々の atomic なので、読み取りの
// 間に遷移が入れば 1 つずれることがある。天井の判定はこの値で行い、上界の式はそのずれを含む
// (設計文書 7 節)。
func (t *Device) TCPClosing() int {
	tcpStats := t.stack.Stats().TCP
	d := int64(tcpStats.CurrentConnected.Value()) - int64(tcpStats.CurrentEstablished.Value())
	if d < 0 {
		return 0
	}
	return int(d)
}

// TCPClosingReleased は天井で解放した endpoint の累計を、K の段(TIME_WAIT)と 2K の段(その他)に
// 分けて返す。
func (t *Device) TCPClosingReleased() (timeWait, other uint64) {
	return t.tcpClosing.releasedTimeWait.Load(), t.tcpClosing.releasedOther.Load()
}

// connectedState は、固定版の gVisor が connected と扱う状態の集合(ESTABLISHED と 6 つの閉じかけの
// 状態)。Abort が RST を送って解放するのはこの状態だけで、相手の RST で既に閉じた endpoint などの
// Close は解放にならないので、2K の段では数えず通常の Close に落とす。
func connectedState(s tcp.EndpointState) bool {
	switch s {
	case tcp.StateEstablished, tcp.StateFinWait1, tcp.StateFinWait2, tcp.StateTimeWait, tcp.StateCloseWait, tcp.StateLastAck, tcp.StateClosing:
		return true
	}
	return false
}

// closeTCP は、中継が閉じる endpoint を天井に照らし、解放したなら真を返す。偽なら呼び出し側が
// 通常の Close を行う。Abort は connected な状態(TIME_WAIT を含む)なら RST を送って直ちに解放し、
// TIME_WAIT と FIN_WAIT_2 の timer を止める。State の読み取りと Abort の間に TIME_WAIT の期限が
// 来て endpoint が閉じていれば、Abort は閉じた endpoint の閉鎖を繰り返すだけで害は無い。
func (t *Device) closeTCP(ep tcpip.Endpoint) bool {
	k := t.tcpClosing.cap.Load()
	d := int64(t.TCPClosing())
	state := tcp.EndpointState(ep.State())
	switch {
	case d >= 2*k && connectedState(state):
		ep.Abort()
		t.tcpClosing.releasedOther.Add(1)
	case d >= k && state == tcp.StateTimeWait:
		ep.Abort()
		t.tcpClosing.releasedTimeWait.Add(1)
	default:
		return false
	}
	if t.tcpClosing.releaseLog.Allow() {
		tw, other := t.TCPClosingReleased()
		logf("userspace tunnel: closing TCP endpoints reached the cap of %d because connections close faster than the netstack retires them; "+
			"released %d endpoints in TIME_WAIT at the cap and %d in other closing states at twice the cap with RST since the tunnel was built",
			k, tw, other)
	}
	return true
}
