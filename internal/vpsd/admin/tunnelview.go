package admin

import (
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/adminapi"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは、`agent ls`(GET /api/v1/agents)が返すトンネルの状態を、wire の
// proto.TunnelStatus とは別の、管理用 API 専用の形に写す(design.md 7a.11 節)。
//
// proto.TunnelStatus.LastHandshake は agent -> server のハートビート(仕様 5.2 節)にも乗る wire の
// 型で、time.Time を素の json:"...,omitempty" で持つ。encoding/json の omitempty は struct を
// 「空」と見なさないので、一度もハンドシェイクしていないトンネルでも
// "last_handshake":"0001-01-01T00:00:00Z" が常に出力され、しかも time.Time の既定の書式
// (RFC3339Nano)は、同じ応答の他のタイムスタンプ(created_at、last_heartbeat など、すべて
// !IsZero() で守った RFC3339 の文字列)と揃っていない。
//
// wire の型はそのまま変えない。TunnelStatus はここでは変えず、proto.TunnelStatus を
// agent -> server の唯一の表現として保つことで、新旧どちらの方向の decode 互換も
// 一切変えない(proto/stream_test.go の互換テストが確かめる)。管理用 API だけがこの型
// (TunnelStatus。同名だが admin パッケージのもの)を経由して見せ方を変える。
//
// LastHandshake が無い(観測していない)ときは、他のタイムスタンプと同じ規則で省く
// (design.md 7a.11 節)。

// TunnelStatus is the tunnel status as `agent ls`/the admin API show it (design.md 5.2、7a.11 節).
// 宣言は internal/vpsd/adminapi にあり、ここは別名である(design.md 10.2d 節。admin.go の別名と
// 同じ理由である)。
type TunnelStatus = adminapi.TunnelStatus

// TunnelStatusView converts the wire type to the admin API's view (design.md 7a.11 節). The wire
// type itself is left untouched; only this rendering changes. Exported for internal/vpsd, which
// builds AgentInfo from the heartbeat's proto.TunnelStatus.
func TunnelStatusView(t proto.TunnelStatus) TunnelStatus {
	v := TunnelStatus{State: t.State, Reason: t.Reason, Endpoint: t.Endpoint}
	if !t.LastHandshake.IsZero() {
		v.LastHandshake = t.LastHandshake.Format(time.RFC3339)
	}
	return v
}
