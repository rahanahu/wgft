//go:build linux

package vpsd

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// overLimitRules は agent の n 本の UDP のルールを、ポート base から作る。
func overLimitRules(agent, prefix string, base, n int) []proto.Rule {
	out := make([]proto.Rule, n)
	for i := range out {
		p := uint16(base + i)
		out[i] = proto.Rule{ID: fmt.Sprintf("%s%04d", prefix, i), Agent: agent, Proto: proto.UDP, ListenPort: proto.PortRange{Lo: p, Hi: p},
			Target: fmt.Sprintf("192.168.1.20:%d", p), VPSMode: proto.ModeKernel, Enabled: true}
	}
	return out
}

// TestRuleCountWarnings は、起動のときの警告が、ルールの数がエージェントあたりの上限を超えるエージェント
// ごとに 1 行、名前の順に出ることを確かめる(仕様 5.4 節)。上限ちょうどのエージェントには出ない。
func TestRuleCountWarnings(t *testing.T) {
	var rules []proto.Rule
	rules = append(rules, overLimitRules("zeta", "z", 1000, 513)...)
	rules = append(rules, overLimitRules("home", "h", 2000, 512)...)
	rules = append(rules, overLimitRules("alpha", "a", 3000, 700)...)
	got := ruleCountWarnings(rules)
	want := []string{
		`warning: agent "alpha" has 700 rules, over the limit of 512 rules per agent; saving a change that adds rules to it is refused until rules are deleted or moved to another agent. With this many rules, a heartbeat can exceed the 1 MiB the server reads when many rules report errors, which closes the agent's stream, and the full state can exceed the 4 MiB the agent reads`,
		`warning: agent "zeta" has 513 rules, over the limit of 512 rules per agent; saving a change that adds rules to it is refused until rules are deleted or moved to another agent. With this many rules, a heartbeat can exceed the 1 MiB the server reads when many rules report errors, which closes the agent's stream, and the full state can exceed the 4 MiB the agent reads`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("ruleCountWarnings =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := ruleCountWarnings(overLimitRules("home", "h", 2000, 512)); len(got) != 0 {
		t.Errorf("ruleCountWarnings at the limit = %v, want none", got)
	}
}

// TestOverLimitAgentKeepsItsStream は、上限の導入の前に 512 本を超えて保存されたエージェント(仕様
// 5.4 節)について、server が公開を続け、エージェントの stream の接続を受け付けて全部のルールの全体状態を
// 配ることを確かめる。保存は、本数を増やすバッチだけを拒み、削除は通す。
// 変異の確認:判定を「後の本数 > 上限」だけにすると、削除が拒まれて落ちる。
func TestOverLimitAgentKeepsItsStream(t *testing.T) {
	path := filepath.Join(t.TempDir(), "s.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	tokens := map[string]string{}
	for _, name := range []string{"home", "other"} {
		tok, err := st.IssueJoinToken(name, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		permanent, _, err := st.Register(tok, name, "203.0.113.2", netip.MustParsePrefix("10.200.0.0/24"))
		if err != nil {
			t.Fatal(err)
		}
		tokens[name] = permanent
	}
	// 上限の検査の前に保存されたデータを模して、SQL で直接書く
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := db.Begin()
	for i, r := range overLimitRules("home", "r_h", 10000, 600) {
		js, _ := json.Marshal(r)
		if _, err := tx.Exec("INSERT INTO rules (id, position, json) VALUES (?, ?, ?)", r.ID, i, string(js)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	db.Close()

	log := &eventLog{}
	p := &recordingParticipant{log: log}
	dp := &disableDataplane{holdDataplane: holdDataplane{p: p}, bound: linux.Bound{}}
	d := &Daemon{st: st, dp: dp, serverKey: testKey(t), network: netip.MustParsePrefix("10.200.0.0/24"),
		opts: Options{Mode: store.ModeKernel, WGInterface: "wgft0", MTU: 1420}}
	d.hub = d.newHub(d)
	captureLog(t)
	d.mu.Lock()
	err = d.applyNFT(rulesOf(t, st))
	d.mu.Unlock()
	if err != nil {
		t.Fatalf("publishing 600 rules of one agent: %v", err)
	}
	if _, err := d.bindDeliveryTimeouts(func() (linux.UDPTimeouts, error) { return linux.UDPTimeouts{}, nil }); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(d.hub)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": {"Bearer " + tokens["home"]}},
	})
	if err != nil {
		t.Fatalf("home's stream: %v", err)
	}
	defer ws.CloseNow()
	ws.SetReadLimit(4 << 20)
	msg, _ := json.Marshal(proto.Message{Type: proto.MsgPublicKey, PublicKey: newKey(t).String()})
	if err := ws.Write(ctx, websocket.MessageText, msg); err != nil {
		t.Fatal(err)
	}
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatalf("home's first State: %v", err)
	}
	var m proto.Message
	if err := json.Unmarshal(data, &m); err != nil || m.Type != proto.MsgState || len(m.State.Rules) != 600 {
		t.Fatalf("home's first State: type %q, %v; want a State with 600 rules", m.Type, err)
	}

	add := overLimitRules("home", "r_x", 3000, 1)
	if _, err := d.Batch(admin.BatchRequest{Upsert: add}); err == nil || !strings.Contains(err.Error(), `agent "home" would have 601 rules`) {
		t.Errorf("adding a rule over the limit = %v, want it refused", err)
	}
	if _, err := d.Batch(admin.BatchRequest{Delete: []string{"r_h0000", "r_h0001"}}); err != nil {
		t.Errorf("deleting rules over the limit = %v, want it to work", err)
	}
	st2, err := d.AgentState("home")
	if err != nil || len(st2.Rules) != 598 {
		t.Errorf("home's State after the delete = %v rules, %v; want 598", len(st2.Rules), err)
	}
}
