//go:build linux

package agent

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/proto"
)

// TestCredentialsFileSizeLimitCoversTheLargestFile は、エージェントが書きうる最大の認証情報ファイルが
// credentials.MaxFileSize に収まることを確かめる(仕様 9 節)。上限を超えるファイルは Load が拒み、Save も
// 書かないので、収まらなければ大きな配置のエージェントが状態を保存できなくなる。
//
// 最大の大きさは次の 3 つで決まる。last_state は制御ストリームの 1 通(streamReadLimit)に収まる。
// カーネルモードの公開の記録は、直近の 1 つと、収束が済んでいない前の公開の列の maxUnconverged 個が並ぶ。
// 1 つの公開はルールごとに 1 項目を持つ。見積もりは、1 通に最も多くのルールが入るよう各項目を最短にし、
// 公開の項目の宛先を最長の IPv4 の値にする。範囲のルールを許可一覧が複数の範囲に分ける場合と、
// 公開しなかった理由の文言の長さは含めない。この 2 つは見積もりの外として 9 節に明記してある。
// ファイルの大きさはルールの数について一次式なので、少ない数で 2 点を測り、1 通に入る最大の数へ伸ばす。
func TestCredentialsFileSizeLimitCoversTheLargestFile(t *testing.T) {
	rule := proto.AgentRule{ID: "a", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 1, Hi: 1}, Target: "a:1", Enabled: true}
	state := func(n int) *proto.State {
		s := &proto.State{
			Generation: ^uint64(0),
			WG: proto.WGConfig{ServerPubkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Endpoint: "vps.example.net:51820",
				Address: "10.200.0.254/24", MTU: 1420, Keepalive: 25, UDPTimeout: 30, UDPTimeoutStream: 120},
		}
		for range n {
			s.Rules = append(s.Rules, rule)
		}
		return s
	}
	message := func(n int) int {
		b, err := json.Marshal(proto.Message{Type: proto.MsgState, State: state(n)})
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	file := func(n int) int {
		st := state(n)
		pub := nft.AgentPublication{Generation: ^uint64(0)}
		for _, r := range st.Rules {
			pub.Rules = append(pub.Rules, nft.AgentRuleResult{RuleID: r.ID, Proto: r.Proto, ListenPort: r.ListenPort, Target: r.Target,
				Ranges: []nft.AgentRange{{Ports: r.ListenPort, Dest: netip.MustParseAddrPort("255.255.255.255:65535")}}})
		}
		list := make([]nft.AgentPublication, maxUnconverged)
		for i := range list {
			list[i] = pub
		}
		pb, err := json.Marshal(pub)
		if err != nil {
			t.Fatal(err)
		}
		lb, err := json.Marshal(list)
		if err != nil {
			t.Fatal(err)
		}
		f := &credentials.Credentials{Name: "home", Endpoint: "vps.example.net:8443", Mode: credentials.ModeKernel,
			LastState: st, KernelPublication: pb, KernelUnconverged: lb}
		// Save と同じ形で書き出す
		b, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	const n1, n2 = 200, 400
	perRuleMessage := float64(message(n2)-message(n1)) / (n2 - n1)
	maxRules := int(float64(streamReadLimit-message(0))/perRuleMessage) + 1
	if message(maxRules) <= streamReadLimit {
		t.Fatalf("the estimate of the rules that fit in one stream message is too small: %d rules make %d bytes", maxRules, message(maxRules))
	}
	f1, f2 := file(n1), file(n2)
	largest := float64(f1) + float64(maxRules-n1)*float64(f2-f1)/(n2-n1)
	t.Logf("rules in one stream message: fewer than %d; the largest credentials file: %.0f bytes; the limit: %d bytes", maxRules, largest, credentials.MaxFileSize)
	if largest > credentials.MaxFileSize {
		t.Errorf("the largest credentials file the agent can write is about %.0f bytes, over credentials.MaxFileSize of %d bytes", largest, credentials.MaxFileSize)
	}
}
