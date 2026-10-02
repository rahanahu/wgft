package stream

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

// sanitizeHeartbeat は、トンネルとルールの理由を HeartbeatReason と同じ形にして保存する。エージェントの
// 理由と server doctor の分類を結ぶ試験(internal/agent の reason_roundtrip_test.go)は
// HeartbeatReason を通すので、hub の実際の切り詰めと同じであることをここで固定する。
func TestSanitizeHeartbeatClipsReasonsLikeHeartbeatReason(t *testing.T) {
	long := strings.Repeat("name resolution of target host \"a.lan\" failed\x1b[2J; ", 40)
	if len(long) <= maxHeartbeatReasonLen {
		t.Fatalf("the reason is %d bytes; it must pass the %d-byte cap", len(long), maxHeartbeatReasonLen)
	}
	want := HeartbeatReason(long)
	if len(want) >= len(long) || strings.Contains(want, "\x1b") {
		t.Fatalf("HeartbeatReason did not clip and escape the reason: %d bytes", len(want))
	}
	got := sanitizeHeartbeat(&proto.Heartbeat{
		Tunnel: proto.TunnelStatus{State: proto.StatusError, Reason: long},
		Rules:  []proto.RuleStatus{{ID: "r1", State: proto.StatusError, Reason: long}},
	})
	if got.Tunnel.Reason != want {
		t.Errorf("Tunnel.Reason = %q, want HeartbeatReason's %q", got.Tunnel.Reason, want)
	}
	if got.Rules[0].Reason != want {
		t.Errorf("Rules[0].Reason = %q, want HeartbeatReason's %q", got.Rules[0].Reason, want)
	}
}

// エージェントは、ハートビートを HTML 向けの書き換え(`<` を `\u003c` にするなど)無しに JSON にして送る
// (設計文書 5.2 節)。hub はその形を、書き換えた形と同じ値に読んで保存する。書き換えた形を送る前の版の
// エージェントと、書き換えない形を送る今の版のエージェントが、同じ保存の値になる。
func TestHubStoresAHeartbeatWithoutHTMLEscapingLikeTheEscapedOne(t *testing.T) {
	reason := "target a&b<c>.lan:80: dial tcp: lookup a&b<c>.lan: no such host"
	for _, tc := range []struct {
		name string
		msg  string
	}{
		{"not escaped", `{"type":"heartbeat","heartbeat":{"generation":4,"tunnel":{"state":"error","reason":"` + reason + `"},"rules":[{"id":"r&1","state":"error","reason":"` + reason + `"}]}}`},
		{"escaped", `{"type":"heartbeat","heartbeat":{"generation":4,"tunnel":{"state":"error","reason":"` + htmlEscaped(reason) + `"},"rules":[{"id":"r\u00261","state":"error","reason":"` + htmlEscaped(reason) + `"}]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, _ := wgtypes.GeneratePrivateKey()
			b := &fakeBackend{server: server, keys: map[string]wgtypes.Key{}, gen: 4}
			h := New(b)
			srv := httptest.NewServer(h)
			defer srv.Close()
			url := "ws" + strings.TrimPrefix(srv.URL, "http")
			key, _ := wgtypes.GeneratePrivateKey()
			c, _, err := dial(t, url, "tok-home")
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()
			sendJSON(t, c, proto.Message{Type: proto.MsgPublicKey, PublicKey: key.PublicKey().String()})
			if _, err := readMsg(t, c); err != nil {
				t.Fatalf("first state: %v", err)
			}
			if err := c.Write(context.Background(), websocket.MessageText, []byte(tc.msg)); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(2 * time.Second)
			for h.Status("home").Heartbeat == nil && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
			hb := h.Status("home").Heartbeat
			if hb == nil {
				t.Fatal("the heartbeat was not stored")
			}
			if hb.Generation != 4 || hb.Tunnel.Reason != reason || len(hb.Rules) != 1 || hb.Rules[0].ID != "r&1" || hb.Rules[0].Reason != reason {
				t.Errorf("stored %+v", hb)
			}
		})
	}
}

// htmlEscaped は、json.Marshal が HTML 向けに書き換える 3 文字を書き換えた s である。
func htmlEscaped(s string) string {
	return strings.NewReplacer("&", `\u0026`, "<", `\u003c`, ">", `\u003e`).Replace(s)
}
