package proto

import (
	"encoding/json"
	"testing"
)

func TestMessageRoundTrip(t *testing.T) {
	msgs := []Message{
		{Type: MsgPublicKey, PublicKey: "k"},
		{Type: MsgState, State: &State{Generation: 3, Rules: []AgentRule{{ID: "r", Proto: UDP, ListenPort: PortRange{1, 2}, Target: "h:1", Enabled: true}}}},
		{Type: MsgHeartbeat, Heartbeat: &Heartbeat{Generation: 3, Tunnel: TunnelStatus{State: StatusOK, Endpoint: "1.2.3.4:51820"},
			Rules: []RuleStatus{{ID: "r", State: StatusError, Reason: "bind: address in use"}}}},
	}
	for _, m := range msgs {
		b, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		var back Message
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if back.Type != m.Type || (m.State == nil) != (back.State == nil) || (m.Heartbeat == nil) != (back.Heartbeat == nil) {
			t.Errorf("round trip: %s -> %+v", b, back)
		}
	}
}
