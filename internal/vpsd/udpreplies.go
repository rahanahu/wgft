//go:build linux

package vpsd

import (
	"context"
	"log"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel"
	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/proto"
)

// このファイルは UDP の応答の観測(設計文書 10.2a 節「UDP の応答の観測」)を管理用 API へ渡す。
// 観測そのものは dataplane の Backend が持つ。ユーザー空間モードは中継が宛先からの応答を読むたびに
// 記し、カーネルモードは table inet wgft の応答のカウンタを vpsd が周期的に読む。wire もハート
// ビートも変えないので、エージェントの版とモードに依らない。

// udpReplyPoller is implemented by a Backend whose reply observation needs periodic reads: the
// kernel backend, which reads its reply counters.
type udpReplyPoller interface {
	PollUDPReplies() error
}

// pollUDPReplies reads the kernel backend's reply counters every linuxkernel.UDPReplyPollInterval
// until ctx is done. It does nothing for a Backend that observes replies as they come (userspace).
// A failure to read is logged when it starts and when it ends, not on every poll; the admin API
// shows it per rule meanwhile.
func (d *Daemon) pollUDPReplies(ctx context.Context) {
	p, ok := d.dp.participant().(udpReplyPoller)
	if !ok {
		return
	}
	t := time.NewTicker(linuxkernel.UDPReplyPollInterval)
	defer t.Stop()
	failing := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		err := p.PollUDPReplies()
		switch {
		case err != nil && err.Error() != failing:
			log.Printf("udp replies are not observed: %v", err)
			failing = err.Error()
		case err == nil && failing != "":
			log.Printf("udp replies are observed again")
			failing = ""
		}
	}
}

// UDPReplies is admin.UDPReplyBackend's implementation (design.md 10.2a、7a.11 節): the Backend's
// reply observation of each enabled UDP rule of rules that it publishes now. rules is the rule set
// already read for this response.
func (d *Daemon) UDPReplies(rules []proto.Rule) (map[string]admin.UDPReply, bool) {
	o, ok := d.dp.participant().(dataplane.UDPReplyObserver)
	if !ok {
		return nil, false
	}
	return udpRepliesView(rules, o.UDPReplies()), true
}

// udpRepliesView maps the Backend's observation to the admin API's shape, keeping only the
// enabled UDP rules of rules.
func udpRepliesView(rules []proto.Rule, obs map[string]dataplane.UDPReply) map[string]admin.UDPReply {
	out := map[string]admin.UDPReply{}
	for _, r := range rules {
		if r.Proto != proto.UDP || !r.Enabled {
			continue
		}
		w, ok := obs[r.ID]
		if !ok {
			continue
		}
		if w.Err != nil {
			out[r.ID] = admin.UDPReply{NotObserved: w.Err.Error()}
			continue
		}
		v := admin.UDPReply{Since: w.Since.Format(time.RFC3339)}
		if !w.Last.IsZero() {
			v.LastReplyAt = w.Last.Format(time.RFC3339)
		}
		out[r.ID] = v
	}
	return out
}
