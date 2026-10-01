package controlapi

// ReasonHandshakePending は、トンネルはあるが WireGuard のハンドシェイクがまだ済んでいないときの理由。
// 適用直後の追送り(internal/agent の needsHandshakeFollowUp)がこの値で判定するので、文言を変える
// ときは両方に効く。
//
// 公開しているのは、制御ソケットの doctor の応答から同じ場合を見分ける読み手がいるためである
// (設計文書 10.2c 節)。応答が載せるのは理由の文字列だけで、ハンドシェイク待ちを tunnel.Status の
// Err による誤りと分ける材料は他に無い。写しを持たせると、この文言を変えたときに読み手だけが
// 取り残される。
const ReasonHandshakePending = "handshake not established"

// ReasonWGRefused は、トンネルが立っている間に届いた wg 設定をカーネルモードのエージェントが拒んだときの、
// ハートビートのトンネルの理由の書き出しである(設計文書 7b.1 節)。agent doctor の tunnel.local が同じ
// 場合を見分けて所見の文面を変えるので、ReasonHandshakePending と同じく公開する。
const ReasonWGRefused = "refused the wg configuration"

// トンネルが無いときのハートビートと doctor の応答のトンネルの理由である(設計文書 7 節、10.2c 節)。
// agent doctor の tunnel.local は、作成に失敗した場合(FAILED)と全体状態をまだ受け取っていない場合
// (UNKNOWN)をこの文言で見分けるので、ReasonHandshakePending と同じく公開する。
//
//   - ReasonNoTunnel は、rotate-key や停止で閉じた直後のような、ほかに当たらない場合である
//   - ReasonNoTunnelBuildRetrying は、作成に失敗して試し直しを待っている場合である
//   - ReasonNoTunnelBuildFailed は、作成が試し直さない失敗で終わった場合であり、
//     ReasonNoTunnelBuildRetrying の書き出しでもある
//   - ReasonNoTunnelFullStatePending は、全体状態をまだ受け取っていない場合であり、
//     ReasonFullStateNotReceived を含む
const (
	ReasonNoTunnel                 = "no tunnel"
	ReasonNoTunnelBuildFailed      = ReasonNoTunnel + "; building it failed"
	ReasonNoTunnelBuildRetrying    = ReasonNoTunnelBuildFailed + " and will be retried"
	ReasonFullStateNotReceived     = "full state not received"
	ReasonNoTunnelFullStatePending = ReasonNoTunnel + "; " + ReasonFullStateNotReceived
)
