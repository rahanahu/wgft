package main

import (
	"testing"

	"github.com/rahanahu/wgft/internal/agent/controlapi"
)

// agentNoTunnelCheck は、エージェントがトンネルの無いときに送る理由(controlapi の定数。
// internal/agent の tunnelSnapshotLocked が使う)のそれぞれを、作成の失敗(FAILED)、全体状態の
// 待ち(UNKNOWN)、それ以外(UNKNOWN)に分ける(設計文書 10.2c 節)。
func TestAgentNoTunnelCheckReadsEachReason(t *testing.T) {
	for _, tc := range []struct {
		reason, status, code string
	}{
		{controlapi.ReasonNoTunnelBuildRetrying, statusFailed, agentReasonTunnelBuildFailed},
		{controlapi.ReasonNoTunnelBuildFailed, statusFailed, agentReasonTunnelBuildFailed},
		{controlapi.ReasonNoTunnelFullStatePending, statusUnknown, agentReasonFullStatePending},
		{controlapi.ReasonNoTunnel, statusUnknown, agentReasonNoTunnel},
	} {
		var c agentDoctorCheck
		agentNoTunnelCheck(&c, tc.reason)
		if c.Status != tc.status || c.Reason != tc.code {
			t.Errorf("reason %q: %s %s, want %s %s", tc.reason, c.Status, c.Reason, tc.status, tc.code)
		}
	}
}
