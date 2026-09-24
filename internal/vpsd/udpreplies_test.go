//go:build linux

package vpsd

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/proto"
)

// 管理用 API の udp_replies は、有効な UDP のルールのうち Backend が観測しているものだけを持つ
// (設計文書 10.2a、7a.11 節)。観測できないことは not_observed に写し、時刻を持たない。
func TestUDPRepliesView(t *testing.T) {
	since := time.Date(2026, 9, 24, 7, 0, 0, 0, time.UTC)
	last := since.Add(3 * time.Hour)
	rules := []proto.Rule{
		{ID: "r_seen", Proto: proto.UDP, Enabled: true},
		{ID: "r_silent", Proto: proto.UDP, Enabled: true},
		{ID: "r_blind", Proto: proto.UDP, Enabled: true},
		{ID: "r_failed", Proto: proto.UDP, Enabled: true}, // 公開していないので Backend の観測に無い
		{ID: "r_off", Proto: proto.UDP, Enabled: false},
		{ID: "r_tcp", Proto: proto.TCP, Enabled: true},
	}
	obs := map[string]dataplane.UDPReply{
		"r_seen":   {Since: since, Last: last},
		"r_silent": {Since: since},
		"r_blind":  {Err: errors.New("reading the reply counters: permission denied")},
		"r_off":    {Since: since, Last: last},
		"r_tcp":    {Since: since, Last: last},
		"r_gone":   {Since: since},
	}
	got := udpRepliesView(rules, obs)
	want := map[string]admin.UDPReply{
		"r_seen":   {Since: since.Format(time.RFC3339), LastReplyAt: last.Format(time.RFC3339)},
		"r_silent": {Since: since.Format(time.RFC3339)},
		"r_blind":  {NotObserved: "reading the reply counters: permission denied"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("udpRepliesView = %+v, want %+v", got, want)
	}
}
