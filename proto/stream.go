package proto

import "time"

// stream(仕様 5.2 節)で流れるメッセージ。双方向で、エージェントは公開鍵とハートビートを、
// vpsd は全体状態を送る。1 つの型で表し、Type で中身を選ぶ。
const (
	MsgPublicKey = "pubkey"    // エージェント → vpsd。接続直後の最初のメッセージ
	MsgState     = "state"     // vpsd → エージェント。差分ではなく全体
	MsgHeartbeat = "heartbeat" // エージェント → vpsd。30 秒ごとと、全体状態の適用直後
)

// Message は stream の 1 メッセージ。
type Message struct {
	Type      string     `json:"type"`
	PublicKey string     `json:"public_key,omitempty"` // MsgPublicKey:wg 公開鍵(base64)
	State     *State     `json:"state,omitempty"`      // MsgState
	Heartbeat *Heartbeat `json:"heartbeat,omitempty"`  // MsgHeartbeat

	// ProtocolMin/ProtocolMax/Capabilities は MsgPublicKey に載る版と機能の交渉(仕様 7a.6 節)。
	// ポインタと *[]string にしてあるのは、フィールドが無いこと(legacy v0 の agent)と、
	// 空配列(版はあるが追加の機能は無い)を JSON の上で区別するため。encoding/json の
	// omitempty は空スライスも「空」として省いてしまうので、[]string のままでは区別できない
	ProtocolMin  *int      `json:"protocol_min,omitempty"`
	ProtocolMax  *int      `json:"protocol_max,omitempty"`
	Capabilities *[]string `json:"capabilities,omitempty"`
}

// ReconnectBackoffMax は、エージェントが stream を繋ぎ直す待ちの上限である(仕様 5.2 節)。エージェントの
// 既定の上限はこの値で、server doctor は、鍵の変更を断った記録が今も試みを続けるエージェントのものか
// どうかを、この値と KeyChangeEvery から判断する(仕様 10.2a 節)。
const ReconnectBackoffMax = 5 * time.Minute

// KeyChangeEvery は、vpsd の鍵の変更の頻度の上限で 1 回分が戻る間隔である(仕様 5.2 節)。wire には
// 載らない。vpsd の上限と server doctor が同じ値を使うためにここに置く。
const KeyChangeEvery = 10 * time.Minute

// Heartbeat はエージェントの状態(仕様 5.2 節)。
type Heartbeat struct {
	Generation uint64       `json:"generation"` // 最後に受け取って処理した世代(部分失敗でも進める)
	Tunnel     TunnelStatus `json:"tunnel"`
	Rules      []RuleStatus `json:"rules"`
}

// 状態の値。
const (
	StatusOK    = "ok"
	StatusError = "error"
)

// TunnelStatus はトンネルの状態。
type TunnelStatus struct {
	State         string    `json:"state"` // ok | error
	Reason        string    `json:"reason,omitempty"`
	Endpoint      string    `json:"endpoint,omitempty"` // 解決したエンドポイント(ip:port)
	LastHandshake time.Time `json:"last_handshake,omitempty"`
}

// ReasonMaxBytes は、ハートビートの TunnelStatus.Reason と RuleStatus.Reason の長さの上限である。
// 単位はバイト(仕様 5.2 節)。エージェントは送る前に、vpsd は受け取った後に、どちらも表示できない文字を
// 置き換えてからこの長さで切り詰める(internal/textsafe の SanitizeAndClip)。切り詰めたときは、
// 後ろに切ったことを示す印を添える。印はこの長さの外に付く。
const ReasonMaxBytes = 512

// RuleStatus はルールごとの状態。error はリスナーの開放失敗か、TCP の target への接続確認の失敗。
type RuleStatus struct {
	ID     string `json:"id"`
	State  string `json:"state"` // ok | error
	Reason string `json:"reason,omitempty"`
}

// WebSocket の切断理由コード(4000 番台はアプリケーション用)。
const (
	CloseSuperseded       = 4000 // 同じエージェントの新しい接続に置き換わった
	CloseRevoked          = 4001 // 恒久トークンが無効化された
	CloseHeartbeatTimeout = 4002 // ハートビート(30 秒間隔)が 90 秒間届かなかった
	CloseProtocolMismatch = 4003 // 版の範囲(protocol_min/protocol_max)の共通部分が無い(仕様 7a.6 節)
	// CloseProtocolMalformed は、版の advertisement 自体が壊れている場合(protocol_min/
	// protocol_max の片方だけがある、または Min < 1 か Min > Max の無効な範囲)。
	// CloseProtocolMismatch(双方とも正当な範囲を宣言したが共通部分が無い)とは原因が異なる。
	// 前者は相手の実装の不具合、後者は版を上げれば直る正常な状態なので、コードでも区別できる
	// ようにした(仕様 7a.6 節)。
	CloseProtocolMalformed = 4004
)
