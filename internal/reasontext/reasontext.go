// Package reasontext は、ルールの理由の文言のうち、理由を書く側と、それを部分一致で読む server
// doctor(internal/vpsd/doctor)の両方が使う断片を持つ(設計文書 7a.7、10.2a 節)。
//
// 書く側は、エージェント(internal/agent、internal/dataplane/linuxkernel/nft、
// internal/dataplane/userspace/relay)と、ルールを公開しなかった server(internal/vpsd、
// internal/vpsd/proxyrelay、中継の Prepare)である。エージェントの理由はハートビートで、server の
// 理由は管理用 API で doctor に届く。稼働中の別の版のエージェントも同じ文言を送り続けるので、
// 断片の値は変えない。値を変えると、古いエージェントの理由を doctor が分類できなくなる。
//
// ルールの理由のほかに、vpsd が stream を閉じるときの理由の文言のうち、エージェントの側が読んで
// 見分けるもの(KeyChangeLimited)もここに置く。値を変えてはならない理由は同じである。
//
// この package はモジュールの中の何も import しない葉である。dataplane の実装と 2 つの制御プレーンの
// どこからも import できる。
package reasontext

import (
	"fmt"
	"strings"
)

// AllowTargetsEnv は、エージェントの宛先の許可一覧の設定の名前である(設計文書 7 節、11a 節)。
// 許可一覧が拒んだ宛先の理由は、拒んだ設定としてこの名前を含む。internal/agent/allowtargets の
// Env はこの値である。
const AllowTargetsEnv = "WGFT_AGENT_ALLOW_TARGETS"

// NotAllowed は、設定の名前を添えずに宛先を拒んだ理由が含む語である。
const NotAllowed = "is not allowed"

// BindFailed は、server の中継が公開側の待ち受けを開けなかったルールの理由の頭である。
const BindFailed = "bind failed"

// NameResolution は、宛先のホスト名を解決できなかった理由が含む語である。
const NameResolution = "name resolution"

// NameResolutionFailed は、宛先のホスト名 host の解決が err で失敗した理由である。
func NameResolutionFailed(host string, err error) string {
	return fmt.Sprintf(NameResolution+" of target host %q failed: %v", host, err)
}

// StillForwardingTo と FromLastResolution は、宛先のホスト名の解決に失敗したが、直前の解決の結果で
// 転送を続けているルールの理由の目印である(設計文書 7b.2 節)。2 つの間に、転送を続けている宛先の
// アドレスを置く。理由は NameResolutionFailed の文言で始まる。
const (
	StillForwardingTo  = "; still forwarding to "
	FromLastResolution = " from the last successful resolution"
)

// LoopbackUnsupported は、カーネルモードがループバックの宛先を転送しないことを述べる理由が含む句で
// ある(設計文書 7b.2 節)。
const LoopbackUnsupported = "does not forward to loopback targets"

// UnicastOnly は、エージェントがブロードキャストかマルチキャストの宛先を拒んだ理由が含む句である
// (設計文書 7 節)。2 つのモードが同じ文言を書く。
const UnicastOnly = "the agent forwards only to unicast targets"

// IPForward は、エージェントのホストの ip_forward が 1 でないために転送できないことを述べる理由が
// 含む sysctl の名前である(設計文書 7b.1 節)。
const IPForward = "net.ipv4.ip_forward"

// DidNotAnswer は、宛先への試し接続が期限までに応えなかった理由が含む句である(設計文書 5.2 節)。
const DidNotAnswer = "did not answer"

// RuleDisabled は、server がルール自身の無効のために公開しなかった理由である。
const RuleDisabled = "disabled"

// NotRegistered は、server がルールのエージェントが登録されていないために公開しなかった理由が含む語
// である。
const NotRegistered = "not registered"

// AgentNotRegistered は、エージェント agent が登録されていないために server がルールを公開しなかった
// 理由である。
func AgentNotRegistered(agent string) string {
	return fmt.Sprintf("agent %q is "+NotRegistered, agent)
}

// agentPrefix と agentDisabledSuffix は、AgentDisabled の文言の頭と末尾である。
const (
	agentPrefix         = "agent "
	agentDisabledSuffix = " is disabled"
)

// AgentDisabled は、エージェント agent が無効なために server がルールを公開しなかった理由である
// (設計文書 5.1 節)。
func AgentDisabled(agent string) string {
	return fmt.Sprintf(agentPrefix+"%q"+agentDisabledSuffix, agent)
}

// IsAgentDisabled は、reason が AgentDisabled の文言かどうかを見る。ルール自身の無効の理由
// RuleDisabled も語 "disabled" を含むので、呼び手はこちらを先に見る。
func IsAgentDisabled(reason string) bool {
	return strings.HasPrefix(reason, agentPrefix) && strings.HasSuffix(reason, agentDisabledSuffix)
}

// KeyChangeLimited は、vpsd が鍵の変更の頻度の上限(設計文書 5.2 節)で公開鍵の宣言を断るときの
// stream の close の理由である。符号は公開鍵の拒否と同じ 1008 なので、エージェントはこの文言で上限に
// よる拒否を見分け、agent doctor が示す(設計文書 10.2c 節)。
const KeyChangeLimited = "public key changes are limited; retry later"
