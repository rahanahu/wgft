package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/reasontext"
	"github.com/rahanahu/wgft/internal/vpsd/doctor"
	"github.com/rahanahu/wgft/internal/vpsd/stream"
	"github.com/rahanahu/wgft/proto"
)

// 仕様 5.2 節のハートビートの理由の上限の試験。エージェントは理由を vpsd の受け口と同じ変換に
// かけてから送り、メッセージを HTML 向けの書き換え無しに JSON にする。

// clipMark は textsafe.ClipText が切り詰めたときに後ろへ付ける印である。
const clipMark = "... truncated"

// hubStreamReadLimit は、vpsd の hub が確立した stream の 1 通に許す大きさ(internal/vpsd/stream の
// streamReadLimit、仕様 5.2 節)の写しである。
const hubStreamReadLimit = 1 << 20

// 理由は 512 バイトちょうどまでそのまま送り、超えたら rune の境目で切って印を添える。境目にかかった
// 多バイト文字は丸ごと落とし、結果は正しい UTF-8 のままである。
func TestWireReasonCapsAt512Bytes(t *testing.T) {
	a := func(n int) string { return strings.Repeat("a", n) }
	cases := []struct {
		name, in, want string
	}{
		{"512 bytes stay", a(512), a(512)},
		{"513 bytes are cut at 512", a(513), a(512) + clipMark},
		{"a 3-byte rune that ends at 512 stays", a(509) + "あ", a(509) + "あ"},
		{"a 3-byte rune across 512 is dropped whole", a(510) + "あ", a(510) + clipMark},
		{"a 3-byte rune starting at 511 is dropped whole", a(511) + "あ", a(511) + clipMark},
		{"a 4-byte rune across 512 is dropped whole", a(509) + "😀", a(509) + clipMark},
		{"an ESC is escaped before the cut", a(510) + "\x1b", a(510) + `\x` + clipMark},
		{"an invalid byte is escaped before the cut", a(508) + "\xff", a(508) + `\xff`},
		{"a short reason stays", "bind failed", "bind failed"},
		{"an empty reason stays empty", "", ""},
	}
	for _, c := range cases {
		got := wireReason(c.in)
		if got != c.want {
			t.Errorf("%s: wireReason = %q (%d bytes), want %q (%d bytes)", c.name, got, len(got), c.want, len(c.want))
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: wireReason returned invalid UTF-8 %q", c.name, got)
		}
		if len(got) > proto.ReasonMaxBytes+len(clipMark) {
			t.Errorf("%s: wireReason returned %d bytes, over %d plus the mark", c.name, len(got), proto.ReasonMaxBytes)
		}
	}
	// 多バイト文字を避けて 512 バイトより手前で切った理由は、hub がもう一度 512 バイトで切るので、印の前に
	// エージェントの印の頭の `.` が 1 から 3 個残る(設計文書 5.2 節)。印より前の文言は変わらない
	for n := 509; n <= 511; n++ {
		got := stream.HeartbeatReason(wireReason(a(n) + "\u3042\u3042"))
		want := a(n) + strings.Repeat(".", 512-n) + clipMark
		if n == 509 {
			want = a(509) + "\u3042" + clipMark
		}
		if got != want {
			t.Errorf("%d bytes and a 3-byte rune: the hub stores %q, want %q", n, got, want)
		}
	}
	if proto.ReasonMaxBytes != 512 {
		t.Errorf("proto.ReasonMaxBytes = %d, want 512", proto.ReasonMaxBytes)
	}
}

// エージェントが送る理由を hub が保存した値は、切り詰めの印より前の文言が、エージェントが切り詰めずに
// 送った場合に hub が保存する値と同じである。server doctor が分類に使う語は、その文言の中で探すので、
// 語が理由の中のどこにあっても、分類はエージェントの切り詰めの前後で変わらない。語の終わりを hub の
// 上限の前後に 1 バイトずつずらし、膨らむ文字(`&`、制御文字、不正なバイト)と多バイト文字で埋めた
// 前置きでも確かめる。
func TestWireReasonKeepsWhatTheHubKeeps(t *testing.T) {
	rule := reasonTCPRule("r1", "game.lan:25565", 25565)
	markers := []string{
		"connection refused",
		"no route to host",
		"i/o timeout",
		reasontext.DidNotAnswer,
		reasontext.IPForward,
		reasontext.AllowTargetsEnv,
		reasontext.LoopbackUnsupported,
		reasontext.BindFailed,
		"lookup game.lan: no such host",
	}
	fillers := map[string]string{
		"ascii":     "x",
		"ampersand": "&",
		"quote":     `"`,
		"control":   "\x01",
		"invalid":   "\xfe",
		"japanese":  "あ",
		"emoji":     "😀",
	}
	checked := 0
	for fname, unit := range fillers {
		for _, m := range markers {
			for pad := 400; pad <= 560; pad++ {
				// 前置きは pad バイトに収まる分だけ unit を繰り返し、残りを "y" で埋める
				prefix := strings.Repeat(unit, pad/len(unit)) + strings.Repeat("y", pad%len(unit))
				raw := prefix + "; " + m + "; trailing words"
				old := stream.HeartbeatReason(raw)
				got := stream.HeartbeatReason(wireReason(raw))
				kept := strings.TrimSuffix(old, clipMark)
				if !strings.HasPrefix(got, kept) {
					t.Fatalf("%s/%q/%d: the hub keeps %q without the agent's cap but %q with it", fname, m, pad, old, got)
				}
				if !strings.HasSuffix(old, clipMark) && got != old {
					t.Fatalf("%s/%q/%d: a reason the hub keeps whole changed: %q -> %q", fname, m, pad, old, got)
				}
				before := serverDoctorReadsStored(t, rule, proto.StatusError, old)
				after := serverDoctorReadsStored(t, rule, proto.StatusError, got)
				for id, c := range before {
					if a := after[id]; a.Status != c.Status || a.Reason != c.Reason {
						t.Fatalf("%s/%q/%d: %s is %s %s without the agent's cap, %s %s with it (reason %q)",
							fname, m, pad, id, c.Status, c.Reason, a.Status, a.Reason, raw)
					}
				}
				checked++
			}
		}
	}
	if checked == 0 {
		t.Fatal("no case ran")
	}
}

// 語が hub の上限の内側にあれば、エージェントの切り詰めの後も server doctor はその語で分類する。上の
// 試験は前後で同じことだけを見るので、ここで語が実際に残ることを確かめる。
func TestWireReasonKeepsAMarkerInsideTheCap(t *testing.T) {
	rule := reasonTCPRule("r1", "game.lan:25565", 25565)
	tail := "; " + reasontext.IPForward + " is 0"
	raw := strings.Repeat("&", proto.ReasonMaxBytes-len(tail)) + tail + strings.Repeat("&", 4096)
	stored := stream.HeartbeatReason(wireReason(raw))
	if !strings.Contains(stored, reasontext.IPForward) {
		t.Fatalf("the marker ending at byte %d was cut: %q", proto.ReasonMaxBytes, stored)
	}
	reads := serverDoctorReadsStored(t, rule, proto.StatusError, stored)
	var found bool
	for _, c := range reads {
		if c.Reason == doctor.ReasonAgentIPForwardOff {
			found = true
		}
	}
	if !found {
		t.Errorf("server doctor did not classify the capped reason as agent_ip_forward_off: %+v", reads)
	}
}

// worstReasons は、エージェントの変換の後に JSON で最も膨らむ理由の候補である。
func worstReasons() map[string]string {
	return map[string]string{
		"ampersand":      strings.Repeat("&", 4096),
		"angle brackets": strings.Repeat("<>", 2048),
		"quote":          strings.Repeat(`"`, 4096),
		"backslash":      strings.Repeat(`\`, 4096),
		"NUL":            strings.Repeat("\x00", 4096),
		"invalid byte":   strings.Repeat("\xff", 4096),
		"line separator": strings.Repeat("\u2028", 2048),
		"C1 control":     strings.Repeat("\u009b", 2048),
	}
}

// 512 本のルールがすべて最悪の理由で error のハートビートも、hub の 1 通の上限(1 MiB)に収まる。ルール ID
// は server が配った値で、この変更の範囲外なので、hub が保存する上限の 128 バイトとし、JSON で最も
// 膨らむ表示できる文字 `"` で埋める。HTML 向けの書き換えを残すと `&` の理由で上限を超えることも
// 確かめ、入力が意味のある最悪の値であることを示す。
func TestHeartbeatOf512RulesFitsTheHubReadLimit(t *testing.T) {
	const rules = 512
	id := strings.Repeat(`"`, 128)
	for name, reason := range worstReasons() {
		hb := proto.Heartbeat{Generation: 1<<64 - 1, Tunnel: proto.TunnelStatus{State: proto.StatusError, Reason: reason,
			Endpoint: "[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535", LastHandshake: time.Now()}}
		for i := 0; i < rules; i++ {
			hb.Rules = append(hb.Rules, proto.RuleStatus{ID: id, State: proto.StatusError, Reason: reason})
		}
		wire := wireHeartbeat(hb)
		b, err := encodeMessage(proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &wire})
		if err != nil {
			t.Fatal(err)
		}
		if len(b) >= hubStreamReadLimit {
			t.Errorf("%s: a heartbeat of %d rules is %d bytes, not under the hub's %d", name, rules, len(b), hubStreamReadLimit)
		}
		// 1 つの理由は、変換の後に 512 バイトと印までである。JSON では本文の 1 バイトが高々 2 バイトになり、
		// 印は JSON で膨らまない ASCII なので、引用符を含めて 2*512+13+2 = 1039 バイトまでである
		if enc := encodedLen(t, wire.Rules[0].Reason); enc > 2*proto.ReasonMaxBytes+len(clipMark)+2 {
			t.Errorf("%s: one reason encodes to %d bytes", name, enc)
		}
		t.Logf("%s: %d bytes", name, len(b))
	}
	hb := proto.Heartbeat{Tunnel: proto.TunnelStatus{State: proto.StatusError}}
	for i := 0; i < rules; i++ {
		hb.Rules = append(hb.Rules, proto.RuleStatus{ID: id, State: proto.StatusError, Reason: strings.Repeat("&", 4096)})
	}
	wire := wireHeartbeat(hb)
	escaped, err := json.Marshal(proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &wire})
	if err != nil {
		t.Fatal(err)
	}
	if len(escaped) <= hubStreamReadLimit {
		t.Errorf("with HTML escaping the heartbeat is %d bytes; the input no longer shows why the escaping must be off", len(escaped))
	}
}

// encodedLen は、文字列 s を stream のメッセージと同じ符号化で JSON にした長さである。
func encodedLen(t *testing.T, s string) int {
	t.Helper()
	b, err := encodeMessage(proto.Message{Type: s})
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := encodeMessage(proto.Message{})
	return len(b) - len(empty) + len(`""`)
}

// encodeMessage は `<`・`>`・`&` を書き換えず、それ以外は json.Marshal と同じバイト列を作る。vpsd の
// json.Unmarshal は、どちらの形からも同じメッセージを読む。
func TestEncodeMessageDoesNotEscapeHTML(t *testing.T) {
	min, max := 1, 1
	caps := []string{}
	plain := proto.Message{Type: proto.MsgPublicKey, PublicKey: "k", ProtocolMin: &min, ProtocolMax: &max, Capabilities: &caps}
	got, err := encodeMessage(plain)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(plain)
	if string(got) != string(want) {
		t.Errorf("encodeMessage = %s, want json.Marshal's %s", got, want)
	}

	m := proto.Message{Type: proto.MsgHeartbeat, Heartbeat: &proto.Heartbeat{Generation: 3,
		Tunnel: proto.TunnelStatus{State: proto.StatusError, Reason: "a <b> & \"c\" \\ \x01 \u2028"},
		Rules:  []proto.RuleStatus{{ID: "r_<&>", State: proto.StatusError, Reason: "target a&b.lan:80: dial tcp: lookup a&b.lan: no such host"}}}}
	b, err := encodeMessage(m)
	if err != nil {
		t.Fatal(err)
	}
	for _, esc := range []string{`\u003c`, `\u003e`, `\u0026`} {
		if strings.Contains(string(b), esc) {
			t.Errorf("encodeMessage wrote %s: %s", esc, b)
		}
	}
	if strings.HasSuffix(string(b), "\n") {
		t.Errorf("encodeMessage left the encoder's newline: %q", b)
	}
	var back, viaMarshal proto.Message
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	escaped, _ := json.Marshal(m)
	if err := json.Unmarshal(escaped, &viaMarshal); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, viaMarshal) || !reflect.DeepEqual(back, m) {
		t.Errorf("decoded %+v, from json.Marshal %+v, sent %+v", back.Heartbeat, viaMarshal.Heartbeat, m.Heartbeat)
	}
}

// streamOnce が実際に送るハートビートは、理由を切り詰め、HTML 向けの書き換えをしない。ログに使う
// rt.heartbeat() の理由は切り詰めない。
func TestStreamOnceSendsCappedReasons(t *testing.T) {
	raws := make(chan []byte, 4)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/stream", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		ws.SetReadLimit(hubStreamReadLimit)
		ctx := r.Context()
		if _, _, err := ws.Read(ctx); err != nil { // pubkey
			return
		}
		for {
			_, b, err := ws.Read(ctx)
			if err != nil {
				return
			}
			select {
			case raws <- b:
			default:
			}
		}
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	pin := sha256.Sum256(srv.Certificate().Raw)

	long := strings.Repeat("&", 2000)
	dp := &fakeDataplane{up: true, reading: agentdp.Reading{
		Tunnel: agentdp.TunnelReading{Present: true, Err: errors.New("endpoint " + long),
			Endpoint:      netip.MustParseAddrPort("203.0.113.1:51820"),
			LastHandshake: time.Date(2026, 10, 3, 1, 2, 3, 0, time.UTC)},
	}}
	for i := 0; i < 3; i++ {
		dp.reading.Rules = append(dp.reading.Rules, proto.RuleStatus{ID: fmt.Sprintf("r%d", i), State: proto.StatusError, Reason: "target " + long + ": connection refused"})
	}
	// 理由の無い ok のルールも混ぜ、状態と ID がそのまま届くことを見る
	dp.reading.Rules = append(dp.reading.Rules, proto.RuleStatus{ID: "r_ok", State: proto.StatusOK})
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
		heartbeatInterval: 20 * time.Millisecond,
		gen:               7,
	}
	rt.setPrivKey(priv)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.streamOnce(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	var b []byte
	select {
	case b = <-raws:
	case <-time.After(5 * time.Second):
		t.Fatal("no heartbeat within 5 s")
	}
	if strings.Contains(string(b), `\u0026`) {
		t.Errorf("the heartbeat escapes & for HTML: %.80s...", b)
	}
	var m proto.Message
	if err := json.Unmarshal(b, &m); err != nil || m.Heartbeat == nil {
		t.Fatalf("the hub cannot read the heartbeat: %v", err)
	}
	if got, want := m.Heartbeat.Tunnel.Reason, wireReason("endpoint "+long); got != want {
		t.Errorf("tunnel reason = %d bytes %.40q..., want the capped %d bytes", len(got), got, len(want))
	}
	if len(m.Heartbeat.Rules) != 4 {
		t.Fatalf("rules = %+v", m.Heartbeat.Rules)
	}
	for _, r := range m.Heartbeat.Rules[:3] {
		if want := wireReason("target " + long + ": connection refused"); r.Reason != want || len(r.Reason) != proto.ReasonMaxBytes+len(clipMark) {
			t.Errorf("rule %s reason = %d bytes, want the capped %d bytes", r.ID, len(r.Reason), len(want))
		}
	}
	// 届いたハートビートは、元のハートビートの理由だけを切り詰めた形と全項目で同じである。世代、
	// ルールの ID と状態、トンネルの状態、エンドポイント、最終ハンドシェイクを落とさない
	want := rt.heartbeat()
	want.Tunnel.Reason = wireReason(want.Tunnel.Reason)
	want.Rules = append([]proto.RuleStatus(nil), want.Rules...)
	for i := range want.Rules {
		want.Rules[i].Reason = wireReason(want.Rules[i].Reason)
	}
	if want.Generation != 7 || want.Tunnel.Endpoint == "" || want.Tunnel.LastHandshake.IsZero() || want.Tunnel.State != proto.StatusError {
		t.Fatalf("the test's own heartbeat lacks a field to compare: %+v", want.Tunnel)
	}
	gotJSON, _ := json.Marshal(m.Heartbeat)
	wantJSON, _ := json.Marshal(want)
	if string(gotJSON) != string(wantJSON) {
		t.Errorf("the sent heartbeat differs from the original with only the reasons capped:\n got %.400s\nwant %.400s", gotJSON, wantJSON)
	}
	// 送る写しを作っても、ログに使う値は切り詰めない
	rt.mu.Lock()
	reading := rt.dp.Read()
	rt.mu.Unlock()
	if reading.Rules[0].Reason != "target "+long+": connection refused" {
		t.Error("sending the heartbeat changed the dataplane's reading")
	}
	if hb := rt.heartbeat(); hb.Rules[0].Reason != "target "+long+": connection refused" {
		t.Errorf("rt.heartbeat() returned a capped reason of %d bytes; the log keeps the full text", len(hb.Rules[0].Reason))
	}
}

// wireHeartbeat は理由だけを変え、他の項目(世代、ルールの ID と状態、トンネルの状態、エンドポイント、
// 最終ハンドシェイク)をそのまま写す。元の hb は書き換えない。
func TestWireHeartbeatKeepsEveryOtherField(t *testing.T) {
	long := strings.Repeat("&", 1000)
	hb := proto.Heartbeat{Generation: 42,
		Tunnel: proto.TunnelStatus{State: proto.StatusError, Reason: long, Endpoint: "203.0.113.1:51820",
			LastHandshake: time.Date(2026, 10, 3, 1, 2, 3, 0, time.UTC)},
		Rules: []proto.RuleStatus{
			{ID: "r_1", State: proto.StatusError, Reason: long},
			{ID: "r_2", State: proto.StatusOK},
		}}
	orig := hb
	orig.Rules = append([]proto.RuleStatus(nil), hb.Rules...)
	got := wireHeartbeat(hb)
	want := orig
	want.Tunnel.Reason = wireReason(long)
	want.Rules = []proto.RuleStatus{
		{ID: "r_1", State: proto.StatusError, Reason: wireReason(long)},
		{ID: "r_2", State: proto.StatusOK},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wireHeartbeat = %+v, want %+v", got, want)
	}
	if !reflect.DeepEqual(hb, orig) {
		t.Errorf("wireHeartbeat changed its argument: %+v", hb)
	}
	if empty := wireHeartbeat(proto.Heartbeat{Rules: []proto.RuleStatus{}}); empty.Rules == nil {
		t.Error("an empty rule list became null; the server reads [] and null alike, but the wire form should not change")
	}
}
