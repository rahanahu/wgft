package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/vpsd/stream"
	"github.com/rahanahu/wgft/proto"
)

// 仕様 5.3 節のエージェントあたりのルールの数の上限の根拠の試験。上限の数のルールを、ルールの ID
// (proto.MaxRuleIDLen)、target(proto.MaxTargetLen)、ハートビートの理由(proto.ReasonMaxBytes)の上限の
// 範囲で、符号化の後が最も長くなる値で組んでも、全体状態はエージェントが読む 1 通(streamReadLimit)に、
// ハートビートは vpsd が読む 1 通(hubStreamReadLimit)に収まることを確かめる。

// distinctID は、alphabet の文字だけからなる n バイトの ID のうち、i 番目のものを返す。alphabet の文字は
// どれも 1 バイトで、符号化で同じ長さに膨らむものを選ぶので、ID ごとの大きさは i によらない。
func distinctID(alphabet string, n, i int) string {
	b := []byte(strings.Repeat(alphabet[:1], n))
	for k := n - 1; i > 0; k-- {
		b[k] = alphabet[i%len(alphabet)]
		i /= len(alphabet)
	}
	return string(b)
}

// worstTarget は vpsd の符号化(json.Marshal、HTML 向けの書き換えあり)で最も長くなる、検査を通る
// target である。253 バイトの `&` は 1 文字が 6 バイトになる。ポートは幅 2 の範囲の末尾が 65535 に
// 収まる 5 桁の値である。
var worstTarget = strings.Repeat("&", 253) + ":65534"

// worstState は、vpsd の符号化で最も長くなる、上限の数のルールの全体状態である。ID は `<`・`>`・`&` の
// 組み合わせで 128 バイト(どれも 1 文字が 6 バイト)、listen_port は 5 桁の範囲、ルールは無効である。
func worstState() *proto.State {
	version := 1 << 30
	caps := []string{}
	st := &proto.State{
		Generation: 1<<64 - 1,
		WG: proto.WGConfig{ServerPubkey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Endpoint: strings.Repeat("&", 253) + ":65535",
			Address: "255.255.255.255/32", MTU: 65535, Keepalive: 65535, UDPTimeout: 1 << 30, UDPTimeoutStream: 1 << 30},
		ServerProtocolVersion: &version, ServerCapabilities: &caps, AgentDisabled: true,
	}
	for i := 0; i < proto.MaxRulesPerAgent; i++ {
		lo := uint16(10000 + 2*i)
		st.Rules = append(st.Rules, proto.AgentRule{ID: distinctID("<>&", proto.MaxRuleIDLen, i), Proto: proto.TCP,
			ListenPort: proto.PortRange{Lo: lo, Hi: lo + 1}, Target: worstTarget, Enabled: false})
	}
	return st
}

// TestWorstRuleValuesPassValidation は、試験に使う最悪の値が server の検査を通る値であることを確かめる。
// 通らない値で測ると、上限の根拠を示さない。
func TestWorstRuleValuesPassValidation(t *testing.T) {
	r := proto.Rule{ID: distinctID("<>&", proto.MaxRuleIDLen, 511), Agent: "home", Proto: proto.TCP,
		ListenPort: proto.PortRange{Lo: 11022, Hi: 11023}, Target: worstTarget, VPSMode: proto.ModeKernel}
	if err := r.Validate(); err != nil {
		t.Errorf("the worst rule for the full state is refused: %v", err)
	}
	r.ID = distinctID(`"\`, proto.MaxRuleIDLen, 511)
	if err := r.Validate(); err != nil {
		t.Errorf("the worst rule ID for the heartbeat is refused: %v", err)
	}
	if len(worstTarget) != proto.MaxTargetLen {
		t.Errorf("worstTarget is %d bytes, want %d", len(worstTarget), proto.MaxTargetLen)
	}
}

// TestFullStateOfMaxRulesFitsTheAgentReadLimit は、上限の数のルールの全体状態を vpsd と同じ符号化
// (hub の sendState の json.Marshal)にした大きさが、エージェントの streamReadLimit より小さいことを
// 確かめる。1 本多い全体状態の大きさとの差から 1 本あたりの大きさも示す。
// 変異の確認:proto.MaxRulesPerAgent を 2048 にすると落ちる。
func TestFullStateOfMaxRulesFitsTheAgentReadLimit(t *testing.T) {
	st := worstState()
	b, err := json.Marshal(proto.Message{Type: proto.MsgState, State: st})
	if err != nil {
		t.Fatal(err)
	}
	if len(b) >= streamReadLimit {
		t.Errorf("the full state of %d rules is %d bytes, not under the agent's %d", len(st.Rules), len(b), streamReadLimit)
	}
	one, _ := json.Marshal(st.Rules[0])
	t.Logf("full state of %d rules: %d bytes (%.2f MiB); one rule: %d bytes; limit %d bytes", len(st.Rules), len(b), float64(len(b))/(1<<20), len(one), streamReadLimit)
}

// TestHeartbeatOfMaxRulesFitsTheHubReadLimit は、上限の数のルールがすべて最悪の理由で error のハートビートを、
// エージェントの符号化(wireHeartbeat と encodeMessage)にした大きさが、hub の 1 通の上限より小さいことを
// 確かめる。ID は、HTML 向けの書き換えをしない符号化で最も膨らむ `"` と `\` の組み合わせで 128 バイトである。
// 変異の確認:proto.MaxRulesPerAgent を 1024 にすると落ちる。
func TestHeartbeatOfMaxRulesFitsTheHubReadLimit(t *testing.T) {
	largest, largestName := 0, ""
	for name, reason := range worstReasons() {
		hb := proto.Heartbeat{Generation: 1<<64 - 1, Tunnel: proto.TunnelStatus{State: proto.StatusError, Reason: reason,
			Endpoint: "[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535", LastHandshake: time.Now()}}
		for i := 0; i < proto.MaxRulesPerAgent; i++ {
			hb.Rules = append(hb.Rules, proto.RuleStatus{ID: distinctID(`"\`, proto.MaxRuleIDLen, i), State: proto.StatusError, Reason: reason})
		}
		wire := wireHeartbeat(hb)
		b, err := encodeMessage(proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &wire})
		if err != nil {
			t.Fatal(err)
		}
		if len(b) >= hubStreamReadLimit {
			t.Errorf("%s: a heartbeat of %d rules is %d bytes, not under the hub's %d", name, proto.MaxRulesPerAgent, len(b), hubStreamReadLimit)
		}
		if len(b) > largest {
			largest, largestName = len(b), name
		}
	}
	t.Logf("largest heartbeat of %d rules: %d bytes (%.2f MiB), reason %s; limit %d bytes", proto.MaxRulesPerAgent, largest, float64(largest)/(1<<20), largestName, hubStreamReadLimit)
}

// sizeBackend は、worstState を配る stream.Backend である。
type sizeBackend struct{ server wgtypes.Key }

func (b *sizeBackend) Authenticate(tok string) (string, string, error) {
	if tok != "tok" {
		return "", "", stream.ErrUnauthorized
	}
	return "home", "id", nil
}
func (b *sizeBackend) ServerPublicKey() wgtypes.Key                       { return b.server.PublicKey() }
func (b *sizeBackend) OtherAgentHasKey(string, wgtypes.Key) (bool, error) { return false, nil }
func (b *sizeBackend) SetPublicKey(string, string, wgtypes.Key) error     { return nil }
func (b *sizeBackend) StateFor(_, _ string, _ wgtypes.Key, sel proto.Negotiated) (*proto.State, error) {
	st := worstState()
	version, caps := sel.Version, proto.SupportedCapabilities
	st.ServerProtocolVersion, st.ServerCapabilities = &version, &caps
	return st, nil
}

// lockedDataplane は fakeDataplane の適用の記録を、試験の goroutine から読めるように守る。
type lockedDataplane struct {
	mu sync.Mutex
	*fakeDataplane
}

func (d *lockedDataplane) ApplyRules(gen uint64, rules []proto.AgentRule, prep any) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.fakeDataplane.ApplyRules(gen, rules, prep)
}

func (d *lockedDataplane) appliedRules() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.applied) == 0 {
		return -1
	}
	return len(d.applied[len(d.applied)-1])
}

// TestMaxRulesOverTheRealStream は、本物の hub(internal/vpsd/stream)と本物のエージェントの stream の
// 経路で、上限の数のルールの最悪の全体状態をエージェントが読んで適用し、すべてのルールが最悪の理由で
// error のハートビートを hub が読んで保存することを確かめる。どちらの側も、実際の読み取りの上限を使う。
func TestMaxRulesOverTheRealStream(t *testing.T) {
	server, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	hub := stream.New(&sizeBackend{server: server})
	mux := http.NewServeMux()
	mux.Handle("/api/v1/agents/stream", hub)
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	pin := sha256.Sum256(srv.Certificate().Raw)

	reason := strings.Repeat(`"`, 4096) // worstReasons のうち、送る大きさが最も大きい理由
	dp := &lockedDataplane{fakeDataplane: &fakeDataplane{up: true, reading: agentdp.Reading{
		Tunnel: agentdp.TunnelReading{Present: true, Err: errors.New(reason)},
	}}}
	for i := 0; i < proto.MaxRulesPerAgent; i++ {
		dp.reading.Rules = append(dp.reading.Rules, proto.RuleStatus{ID: distinctID(`"\`, proto.MaxRuleIDLen, i), State: proto.StatusError, Reason: reason})
	}
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rt := &runtime{
		dp: dp,
		f: &credentials.Credentials{
			Endpoint:       strings.TrimPrefix(srv.URL, "https://"),
			CertSHA256:     hex.EncodeToString(pin[:]),
			PermanentToken: "tok",
		},
		heartbeatInterval: 50 * time.Millisecond,
	}
	rt.setPrivKey(priv)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.streamOnce(ctx) }()
	ended := false
	t.Cleanup(func() {
		cancel()
		if !ended {
			<-done
		}
	})

	deadline := time.Now().Add(10 * time.Second)
	for {
		hb := hub.Status("home").Heartbeat
		if dp.appliedRules() == proto.MaxRulesPerAgent && hb != nil && len(hb.Rules) == proto.MaxRulesPerAgent {
			break
		}
		select {
		case err := <-done:
			ended = true
			t.Fatalf("the agent's stream ended: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("within 10 s: the agent applied %d rules, the hub stored a heartbeat %v; want %d each",
				dp.appliedRules(), hb != nil, proto.MaxRulesPerAgent)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !hub.Status("home").Connected {
		t.Error("the agent is not connected after the exchange")
	}
}
