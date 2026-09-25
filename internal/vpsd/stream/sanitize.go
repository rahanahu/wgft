package stream

import (
	"github.com/rahanahu/wgft/internal/textsafe"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、ハートビートに乗る文字列を受け口で締める(design.md 11 節、5.2 節)。agent は
// 信頼の境界の外にあり、乗っ取られた agent は Tunnel.State・Tunnel.Reason・Tunnel.Endpoint・
// Rules[].ID・Rules[].State・Rules[].Reason に何でも書ける。ここで切り詰めて、表示できない文字
// (unicode.IsPrint が偽の文字。internal/textsafe の SanitizeForTerminal を見よ)を読める形に
// 置き換えた値だけを h.status[agent].Heartbeat に保存するので、admin API・agent ls・rule ls・
// status・server doctor のどの読み手も同じ、すでに安全な値を読む。CLI 側の表示時のもう 1 段
// (textsafe.SanitizeForTerminal を個別に呼ぶ箇所)は、この受け口を経ない値(agent doctor・
// rotate-key が制御ソケットから直接読む応答)のための、独立したもう 1 つの守りである。

// maxHeartbeatStateLen は Tunnel.State と Rules[].State に許す長さの上限である。実際の値は
// proto.StatusOK("ok")・proto.StatusError("error")の 2 語だけで、どちらも 5 バイトに満たない。
const maxHeartbeatStateLen = 64

// maxHeartbeatReasonLen は Tunnel.Reason と Rules[].Reason に許す長さの上限である。internal/agent の
// 同種の上限(agent 自身の doctor 応答が使う maxDoctorText)と同じ 512 バイトにそろえる。この経路が
// 積む理由の文字列(bind の失敗、target への接続確認の失敗、宛先の許可一覧による拒否)は実測で
// 100 バイトに満たないので、5 倍の余裕がある。
const maxHeartbeatReasonLen = 512

// maxHeartbeatIDLen は Rules[].ID に許す長さの上限である。実際のルール ID は "r_" と ULID(26 文字)の
// 28 バイトなので、4 倍を超える余裕がある。乗っ取られた agent は、この ID をそのルールの持ち主のもので
// あるかのように偽って任意の文字列を送れるので、値の形を検証せず長さと文字種だけを締める。
const maxHeartbeatIDLen = 128

// maxHeartbeatEndpointLen は Tunnel.Endpoint(agent が解決した "host:port")に許す長さの上限である。
// IPv6 の最長表記(45 バイト)にポートを添えても 128 バイトには収まらないので、ここも同じ値を使う。
const maxHeartbeatEndpointLen = 128

// sanitizeHeartbeat は、受け取ったハートビートの文字列だけを切り詰めて安全な文字に置き換えた
// 写しを返す。Generation は素通しする。元の hb は書き換えない。
func sanitizeHeartbeat(hb *proto.Heartbeat) *proto.Heartbeat {
	out := &proto.Heartbeat{
		Generation: hb.Generation,
		Tunnel: proto.TunnelStatus{
			State:         clipAndSanitize(hb.Tunnel.State, maxHeartbeatStateLen),
			Reason:        clipAndSanitize(hb.Tunnel.Reason, maxHeartbeatReasonLen),
			Endpoint:      clipAndSanitize(hb.Tunnel.Endpoint, maxHeartbeatEndpointLen),
			LastHandshake: hb.Tunnel.LastHandshake,
		},
	}
	if len(hb.Rules) > 0 {
		out.Rules = make([]proto.RuleStatus, len(hb.Rules))
		for i, r := range hb.Rules {
			out.Rules[i] = proto.RuleStatus{
				ID:     clipAndSanitize(r.ID, maxHeartbeatIDLen),
				State:  clipAndSanitize(r.State, maxHeartbeatStateLen),
				Reason: clipAndSanitize(r.Reason, maxHeartbeatReasonLen),
			}
		}
	}
	return out
}

// clipAndSanitize replaces every unsafe rune and invalid UTF-8 byte in s with a visible, inert
// escape, then caps the escaped result at max bytes on a rune boundary (design.md 11 節).
//
// Escaping runs first, and clipping second, so that the byte count actually stored never exceeds
// max (plus ClipText's short truncation marker). Escaping a byte can grow it up to about 6x (one
// unsafe byte becomes an escape like `\x1b` or `\u009b`), so clipping an already-escaped string
// bounds what is kept by what will actually be stored; clipping first and escaping second, as an
// earlier version of this function did, could grow the stored value up to that same factor past
// max, since every one of the max raw bytes kept could itself be unsafe and expand on escaping
// (レビューの指摘, 2026-09-26). The one cost is that escaping runs over the full, unclipped input
// first; that input is already bounded by the hub's own WebSocket read limit (1 MiB), so this is a
// bounded, one-time allocation per field per heartbeat, not an unbounded one.
func clipAndSanitize(s string, max int) string {
	return textsafe.ClipText(textsafe.SanitizeForTerminal(s), max)
}
