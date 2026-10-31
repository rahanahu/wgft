package stream

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

// このファイルは、言語に依らない仕様(docs/design/spec の stream.md と messages.md)の fixture と、
// server の stream の受け口(Hub)を照らす。fixture はリポジトリの直下の testdata/spec にあり、Rust の
// 実装も読む。全体状態の中身は vpsd の Daemon.StateFor が作るので、ここでは fixture の全体状態を返す
// Backend を使い、Hub の符号化、版の交渉、close の符号と理由を確かめる。

var specDir = filepath.Join("..", "..", "..", "testdata", "spec")

// specServerKey は fixture の server の秘密鍵である。本物の鍵ではない。
const specServerKey = "wGtcpoTz2kJWMNETk6NBa9HGlmqjj4cQaayXJBKgpHE="

func specFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(specDir, rel))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(b, []byte("\n"))
}

// specBackend は fixture の全体状態を返す Backend である。版のフィールドの扱いは vpsd の
// Daemon.StateFor と同じにする。
type specBackend struct {
	*fakeBackend
	state proto.State
}

func (b *specBackend) StateFor(agent, identity string, key wgtypes.Key, sel proto.Negotiated) (*proto.State, error) {
	if _, err := b.fakeBackend.StateFor(agent, identity, key, sel); err != nil {
		return nil, err
	}
	st := b.state
	st.ServerProtocolVersion, st.ServerCapabilities = nil, nil
	if !sel.Legacy {
		version := sel.Version
		caps := append([]string{}, proto.SupportedCapabilities...)
		st.ServerProtocolVersion = &version
		st.ServerCapabilities = &caps
	}
	return &st, nil
}

func newSpecHub(t *testing.T) (*Hub, *specBackend, string) {
	t.Helper()
	server, err := wgtypes.ParseKey(specServerKey)
	if err != nil {
		t.Fatal(err)
	}
	var m proto.Message
	if err := json.Unmarshal(specFixture(t, "wire/state.json"), &m); err != nil {
		t.Fatal(err)
	}
	b := &specBackend{fakeBackend: &fakeBackend{server: server, keys: map[string]wgtypes.Key{}}, state: *m.State}
	h := New(b)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return h, b, "ws" + strings.TrimPrefix(srv.URL, "http")
}

func specWrite(t *testing.T, c *websocket.Conn, raw []byte) {
	t.Helper()
	if err := c.Write(context.Background(), websocket.MessageText, raw); err != nil {
		t.Fatal(err)
	}
}

func specRead(c *websocket.Conn) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := c.Read(ctx)
	return b, err
}

// TestSpecWireServerState は、fixture の pubkey を受けた Hub が、fixture と同じ byte 列の全体状態を
// 送ることを確かめる。版の宣言の無い pubkey には、版のフィールドの無い全体状態を送る。
func TestSpecWireServerState(t *testing.T) {
	for _, tc := range []struct{ pubkey, state string }{
		{"wire/pubkey.json", "wire/state.json"},
		{"wire/pubkey-legacy.json", "wire/state-legacy.json"},
	} {
		_, _, url := newSpecHub(t)
		c, _, err := dial(t, url, "tok-home")
		if err != nil {
			t.Fatal(err)
		}
		specWrite(t, c, specFixture(t, tc.pubkey))
		got, err := specRead(c)
		if err != nil {
			t.Fatalf("%s: %v", tc.pubkey, err)
		}
		if want := specFixture(t, tc.state); !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %s\nwant %s", tc.pubkey, got, want)
		}
		c.CloseNow()
	}
}

// TestSpecWireCloseReasons は、close の符号と理由の fixture を Hub と照らす。
func TestSpecWireCloseReasons(t *testing.T) {
	var cases []struct {
		Case   string `json:"case"`
		Name   string `json:"name"`
		First  string `json:"first"`
		Code   int    `json:"code"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(specFixture(t, "wire/close.json"), &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no cases")
	}
	agentKey, err := wgtypes.ParseKey("BdPeyy13167Sr+s5NgOv2j6ddcWP0k2sbBmn7cU1M3w=")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.Case, func(t *testing.T) {
			h, b, url := newSpecHub(t)
			token := "tok-home"
			switch tc.Case {
			case "other-agent-key":
				b.keys["office"] = agentKey
			case "key-change-limited":
				b.setKeyErr = fmt.Errorf("agent %q: %w", "home", ErrKeyChangeLimited)
			case "peer-setup-failed":
				b.setKeyErr = errors.New("saving failed")
			case "heartbeat-timeout":
				h.HeartbeatTimeout = 200 * time.Millisecond
			case "first-timeout":
				h.firstMessageTimeout = 200 * time.Millisecond
			}
			c, _, err := dial(t, url, token)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()
			if tc.First != "" {
				specWrite(t, c, []byte(tc.First))
			}
			switch tc.Case {
			case "superseded", "revoked", "heartbeat-timeout":
				if _, err := specRead(c); err != nil {
					t.Fatalf("first state: %v", err)
				}
			}
			switch tc.Case {
			case "superseded":
				c2, _, err := dial(t, url, token)
				if err != nil {
					t.Fatal(err)
				}
				defer c2.CloseNow()
				specWrite(t, c2, []byte(tc.First))
			case "revoked":
				h.Disconnect("home", proto.CloseRevoked, "revoked")
			}
			var ce websocket.CloseError
			for {
				_, err = specRead(c)
				if err != nil {
					break
				}
			}
			if tc.Code == -1 {
				// 符号 -1 は close のフレームが届かずに接続が終わることを表す
				if errors.As(err, &ce) {
					t.Errorf("want no close frame, got %d %q", ce.Code, ce.Reason)
				}
				return
			}
			if !errors.As(err, &ce) {
				t.Fatalf("want a close frame, got %v", err)
			}
			if int(ce.Code) != tc.Code || ce.Reason != tc.Reason {
				t.Errorf("close = %d %q, want %d %q", ce.Code, ce.Reason, tc.Code, tc.Reason)
			}
		})
	}
}

// TestSpecWireServerLimits は、stream.md の server の側の時間と上限を固定する。
func TestSpecWireServerLimits(t *testing.T) {
	if firstMessageReadLimit != 4096 || streamReadLimit != 1<<20 || maxPendingPerAgent != 2 {
		t.Errorf("first %d, stream %d, pending %d", firstMessageReadLimit, streamReadLimit, maxPendingPerAgent)
	}
	if defaultFirstMessageTimeout != 10*time.Second || defaultHeartbeatTimeout != 90*time.Second || writeTimeout != 10*time.Second {
		t.Errorf("first message %v, heartbeat %v, write %v", defaultFirstMessageTimeout, defaultHeartbeatTimeout, writeTimeout)
	}
	if maxHeartbeatStateLen != 64 || maxHeartbeatReasonLen != 512 || maxHeartbeatIDLen != 128 || maxHeartbeatEndpointLen != 128 {
		t.Errorf("heartbeat caps %d %d %d %d", maxHeartbeatStateLen, maxHeartbeatReasonLen, maxHeartbeatIDLen, maxHeartbeatEndpointLen)
	}
}
