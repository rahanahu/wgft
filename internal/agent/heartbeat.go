package agent

import (
	"fmt"
	"log"
	"reflect"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/textsafe"
	"github.com/rahanahu/wgft/proto"
)

// heartbeat は処理済み世代、トンネルの状態、ルールごとの状態をまとめる(仕様 5.2 節)。
func (rt *runtime) heartbeat() proto.Heartbeat {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	hb := proto.Heartbeat{Generation: rt.gen, Rules: []proto.RuleStatus{}}
	r := rt.dp.Read()
	tun := rt.tunnelSnapshotLocked(r.Tunnel)
	hb.Tunnel = tun.hb
	if !tun.present {
		return hb
	}
	if r.Rules != nil {
		hb.Rules = r.Rules
	}
	return hb
}

// wireHeartbeat は、ハートビートを stream に載せる形にした写しを返す(仕様 5.2 節)。トンネルとルールの
// 理由を、vpsd の受け口と同じ変換(表示できない文字の置き換えと proto.ReasonMaxBytes での切り詰め)に
// かける。理由はエージェントが作る文言で、宛先のホスト名や OS の誤りの文面を含むので、長さが決まら
// ない。上限が無いと、ルールの数に比例してハートビートの 1 通が vpsd の読みの上限(1 MiB)を超え、
// stream が切れる。受け口の変換は自分の結果を変えないので、vpsd が保存する理由は、この切り詰めの前と
// 同じ文言を残す。ログ(logStatus)には切り詰める前の理由を書くので、元の hb は書き換えない。
func wireHeartbeat(hb proto.Heartbeat) proto.Heartbeat {
	out := hb
	out.Tunnel.Reason = wireReason(hb.Tunnel.Reason)
	if hb.Rules != nil {
		out.Rules = make([]proto.RuleStatus, len(hb.Rules))
		for i, r := range hb.Rules {
			r.Reason = wireReason(r.Reason)
			out.Rules[i] = r
		}
	}
	return out
}

// wireReason は、1 つの理由を stream に載せる形にする。
func wireReason(s string) string {
	return textsafe.SanitizeAndClip(s, proto.ReasonMaxBytes)
}

// tunnelSnapshot はトンネルの状態の写しである。present はトンネルがあるかどうか、hb はハートビートに
// 載せる形、raw は読んだままの値である。送受信バイト数は proto.TunnelStatus に載らないので raw
// にしかなく、present が偽のときの raw に意味は無い。
type tunnelSnapshot struct {
	present bool
	hb      proto.TunnelStatus
	raw     agentdp.TunnelReading
}

// tunnelSnapshotLocked は、dataplane を 1 回だけ読んだ値 r から、ハートビートと doctor が共有する
// 写しを作る(設計文書 10.2c 節)。呼び出し側は rt.mu を持つ。doctor が別に読み直す形にすると、
// 送受信バイト数と最終ハンドシェイクが 1 つの応答の中で異なる時点の値になる。
func (rt *runtime) tunnelSnapshotLocked(r agentdp.TunnelReading) tunnelSnapshot {
	if !r.Present {
		// トンネルが無い理由は 4 通りある。作成に失敗して試し直しを待っている場合(仕様 7 節)、
		// 作成が wg 設定の誤りで終わって次の全体状態を待っている場合、全体状態をまだ受け取っていない
		// 場合、rotate-key や停止で閉じた直後の場合である
		reason := controlapi.ReasonNoTunnel
		switch {
		case !rt.rebuild.retryAt.IsZero():
			reason = controlapi.ReasonNoTunnelBuildRetrying
		case rt.retrySt != nil:
			reason = controlapi.ReasonNoTunnelBuildFailed
		case rt.f == nil || rt.f.LastState == nil:
			reason = controlapi.ReasonNoTunnelFullStatePending
		}
		return tunnelSnapshot{hb: proto.TunnelStatus{State: proto.StatusError, Reason: reason}}
	}
	// dataplane が読むのは今の device で、鍵を変えた後に前の鍵のハンドシェイクは残らないので
	// (agentdp.Dataplane の LastHandshake)、最終ハンドシェイクは必ず今のトンネルのものである。
	// watchdog が rebuildState に持つ値は closeLocked が消さず、立て直した直後は前のトンネルの
	// 値が残るので、2 つを混ぜない(設計文書 10.2c 節)
	snap := tunnelSnapshot{present: true, raw: r, hb: proto.TunnelStatus{State: proto.StatusOK, LastHandshake: r.LastHandshake}}
	if r.Endpoint.IsValid() {
		snap.hb.Endpoint = r.Endpoint.String()
	}
	// 拒んだ全体状態は、トンネルの読みの誤りより先に示す。server が送った設定をエージェントが使って
	// いないことは、運用者が最初に知るべきことである(設計文書 7b.1・11 節)
	if rt.refused != nil {
		snap.hb.State = proto.StatusError
		snap.hb.Reason = fmt.Sprintf("%s of generation %d; the tunnel and rules stay as generation %d left them: %v", controlapi.ReasonWGRefused, rt.refused.gen, rt.gen, rt.refused.err)
		return snap
	}
	if r.Err != nil {
		snap.hb.State, snap.hb.Reason = proto.StatusError, r.Err.Error()
	} else if r.LastHandshake.IsZero() {
		snap.hb.State, snap.hb.Reason = proto.StatusError, controlapi.ReasonHandshakePending
	}
	return snap
}

// logStatus は 30 秒ごとに呼ばれる(Run のティッカー)。毎回は出さず、前回のログと同じ内容なら黙る
// (トンネルとルールの状態が変わらない定常運転でジャーナルを埋めないため)。
func (rt *runtime) logStatus() {
	hb := rt.heartbeat()
	lines := make([]string, 0, 1+len(hb.Rules))
	lines = append(lines, fmt.Sprintf("generation %d tunnel=%s %s endpoint=%s", hb.Generation, hb.Tunnel.State, hb.Tunnel.Reason, hb.Tunnel.Endpoint))
	for _, r := range hb.Rules {
		lines = append(lines, fmt.Sprintf("rule %s %s %s", r.ID, r.State, r.Reason))
	}
	if reflect.DeepEqual(lines, rt.lastStatusLines) {
		return
	}
	rt.lastStatusLines = lines
	for _, l := range lines {
		log.Printf("%s", l)
	}
}
