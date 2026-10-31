package vpsd

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

// TestSpecStateForVersionFields は、言語に依らない仕様(docs/design/spec の messages.md と stream.md)の
// 全体状態の版のフィールドと rules の書き方を、実際の Daemon.StateFor で確かめる。
// internal/vpsd/stream の spec_test.go は Hub の符号化を fixture と照らすが、版のフィールドを足す
// Backend はそこでは写しなので、この試験が実物を受け持つ。
func TestSpecStateForVersionFields(t *testing.T) {
	f := newDisableFixture(t)
	tok, err := f.st.IssueJoinToken("empty", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := f.st.Register(tok, "empty", "203.0.113.3", netip.MustParsePrefix("10.200.0.0/24")); err != nil {
		t.Fatal(err)
	}
	f.d.mu.Lock()
	err = f.d.applyNFT(rulesOf(t, f.st))
	f.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"empty", "home"} {
		a, err := f.st.AgentByName(name)
		if err != nil {
			t.Fatal(err)
		}
		priv, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		key := priv.PublicKey()
		if err := f.d.SetPublicKey(name, a.Identity, key); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for _, tc := range []struct {
			sel  proto.Negotiated
			want bool
		}{{proto.Negotiated{Version: 1, AgentMin: 1, AgentMax: 1, Capabilities: []string{}}, true}, {proto.Negotiated{Legacy: true}, false}} {
			st, err := f.d.StateFor(name, a.Identity, key, tc.sel)
			if err != nil {
				t.Fatalf("%s %+v: %v", name, tc.sel, err)
			}
			b, err := json.Marshal(proto.Message{Type: proto.MsgState, State: st})
			if err != nil {
				t.Fatal(err)
			}
			s := string(b)
			hasV1 := strings.Contains(s, `,"server_protocol_version":1,"server_capabilities":[]`)
			hasAny := strings.Contains(s, "server_protocol_version") || strings.Contains(s, "server_capabilities")
			if tc.want && !hasV1 || !tc.want && hasAny {
				t.Errorf("%s legacy=%v: %s", name, tc.sel.Legacy, s)
			}
			if name == "empty" && !strings.Contains(s, `"rules":[]`) {
				t.Errorf("an agent without rules must get \"rules\":[]: %s", s)
			}
			if name == "home" && strings.Contains(s, `"rules":[]`) {
				t.Errorf("home has rules: %s", s)
			}
		}
	}
}
