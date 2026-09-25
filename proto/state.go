package proto

import (
	"net"
	"strconv"
)

// WGConfig は全体状態でエージェントに渡す wg の設定(仕様 5.2 節)。
type WGConfig struct {
	ServerPubkey     string `json:"server_pubkey"`
	Endpoint         string `json:"endpoint"` // host:port
	Address          string `json:"address"`  // 10.200.0.2/24 の形
	MTU              int    `json:"mtu"`
	Keepalive        int    `json:"keepalive"`          // 秒
	UDPTimeout       int    `json:"udp_timeout"`        // VPS の nf_conntrack_udp_timeout(秒)
	UDPTimeoutStream int    `json:"udp_timeout_stream"` // VPS の nf_conntrack_udp_timeout_stream(秒)
}

// AgentRule はエージェントに配るルールの部分集合。vps_mode と接続元制限は配らない(仕様 5.3 節)。
type AgentRule struct {
	ID         string    `json:"id"`
	Proto      Proto     `json:"proto"`
	ListenPort PortRange `json:"listen_port"`
	Target     string    `json:"target"`
	Enabled    bool      `json:"enabled"`
}

// State は vpsd がエージェントに配る全体状態(仕様 5.2 節)。差分ではなく常に全体を送る。
type State struct {
	Generation uint64      `json:"generation"`
	WG         WGConfig    `json:"wg"`
	Rules      []AgentRule `json:"rules"`

	// ServerProtocolVersion/ServerCapabilities は、その stream 接続で選んだ版と server の機能
	// (仕様 7a.6 節)。agent が legacy v0 なら vpsd はこのフィールドを載せない(nil のまま)。
	// *[]string にしてあるのは Message.Capabilities と同じ理由(空配列と不在の区別)
	ServerProtocolVersion *int      `json:"server_protocol_version,omitempty"`
	ServerCapabilities    *[]string `json:"server_capabilities,omitempty"`

	// AgentDisabled は、server がこのエージェントを無効にしていることを示す(仕様 5.1 節)。無効の間、
	// Rules はすべて enabled:false の写しで届く。エージェントが止まるのはその enabled:false による
	// ものであり、このフィールドはエージェント自身の診断のためだけにある。守りには使わない。
	// 加算のフィールドで、有効なら省く。旧い版のエージェントは読み飛ばす(Go の encoding/json は
	// 構造体に無いフィールドを無視する。仕様 7a.6 節)ので、版と機能の交渉は要らない
	AgentDisabled bool `json:"agent_disabled,omitempty"`
}

// ForAgent はエージェントに配る部分だけを取り出す。
func (r *Rule) ForAgent() AgentRule {
	return AgentRule{ID: r.ID, Proto: r.Proto, ListenPort: r.ListenPort, Target: r.Target, Enabled: r.Enabled}
}

// EffectiveTarget は listen_port 内のポート p に対応する実効宛先(仕様 7 節)。
// target のポートに、範囲内での位置を足したもの。p が範囲外なら ok は false。
// Rule.Validate は「target のポートに範囲の幅を足した実効宛先が 65535 を超える場合」を拒否する
// (仕様 5.3 節)が、AgentRule は Validate を経ずに vpsd から届いた State 経由でも組み立てられる
// (internal/dataplane/linuxkernel/nft.planAgentRule も同じ算出を自前で検査しているのはこのため)。
// ここでも同じ上限を検査し、越える p には ok=false を返す。
func (r AgentRule) EffectiveTarget(p uint16) (target string, ok bool) {
	if !r.ListenPort.Contains(p) {
		return "", false
	}
	host, port, err := splitTarget(r.Target)
	if err != nil {
		return "", false
	}
	eff := int(port) + int(p-r.ListenPort.Lo)
	if eff > 65535 {
		return "", false
	}
	return net.JoinHostPort(host, strconv.Itoa(eff)), true
}
