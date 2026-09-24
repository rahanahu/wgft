package admin

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// udpReplyBackend is a fakeBackend that also observes UDP replies.
type udpReplyBackend struct {
	*fakeBackend
	replies map[string]UDPReply
}

func (b *udpReplyBackend) UDPReplies([]proto.Rule) (map[string]UDPReply, bool) {
	return b.replies, true
}

// udp_replies is additive to API v1 (design.md 10.2a、7a.11 節): a Backend that does not observe
// replies serves the rules without the field, and one that does adds it with its entries as is.
func TestRulesResponseUDPReplies(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := &fakeBackend{st: st}
	if _, ok := getRulesJSON(t, base, st)["udp_replies"]; ok {
		t.Error("a Backend without UDPReplyBackend must not add udp_replies")
	}
	replies := map[string]UDPReply{
		"r_seen":   {Since: "2026-09-24T07:00:00Z", LastReplyAt: "2026-09-24T10:00:12Z"},
		"r_silent": {Since: "2026-09-24T07:00:00Z"},
		"r_blind":  {NotObserved: "reading the reply counters: permission denied"},
	}
	got := getRulesJSON(t, &udpReplyBackend{fakeBackend: base, replies: replies}, st)
	var back map[string]UDPReply
	if err := json.Unmarshal(got["udp_replies"], &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, replies) {
		t.Errorf("udp_replies = %+v, want %+v", back, replies)
	}
	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal(got["udp_replies"], &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["r_silent"]["last_reply_at"]; ok {
		t.Error("a rule with no reply seen must omit last_reply_at")
	}
	if _, ok := raw["r_blind"]["since"]; ok {
		t.Error("a rule that cannot be observed must omit since")
	}
}
