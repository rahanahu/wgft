package main

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/sockbuf"
	"github.com/rahanahu/wgft/proto"
)

// tunnel.socket_buffers は、稼働中のエージェントがトンネルを立てた直後に測った WireGuard の UDP
// ソケットのバッファを、ユーザー空間モードの条件と比べる(設計文書 7 節、10.2c 節)。条件に届かなければ
// FAILED になるが、総合判定と終了コードは動かさない。値は稼働中のエージェントが測ったものであり、
// 予測を条件の判定に使わない。
func TestAgentDoctorSocketBuffers(t *testing.T) {
	short := &agent.DoctorSocketBuffers{Supported: true, Port: 35454, Sockets: 2, Recv: 425984, Send: 425984, Required: sockbuf.Required}
	cases := []struct {
		name       string
		resp       *agent.DoctorResponse
		stopped    bool
		kernel     bool
		wantStatus string
		wantReason string
		wantDetail []string
		wantNext   []string
		wantExit   int
	}{
		{name: "met", resp: healthyLiveResponse(), wantStatus: statusOK,
			wantDetail: []string{"port 35454", "receive buffer of 14680064 bytes", "send buffer of 14680064 bytes", "requires 14680064 bytes each"}},
		{name: "short on both", resp: runtimeResponse(func(st *agent.DoctorRuntimeState) { st.Tunnel.SocketBuffers = short }),
			wantStatus: statusFailed, wantReason: "socket_buffer_below_requirement",
			wantDetail: []string{"receive buffer of 425984 bytes", "at least 14680064 bytes each"},
			// sysctl に書く値と、Linux が報告する 2 倍の値を並べ、7 MiB を設定した運用者が 14 MiB を読み違えない
			wantNext: []string{"net.core.rmem_max and net.core.wmem_max to 7340032", "/etc/sysctl.d", "sysctl --system", "container host",
				"restart the agent", "7340032 in the sysctl reads here as 14680064"}},
		{name: "short on send only", resp: runtimeResponse(func(st *agent.DoctorRuntimeState) {
			b := *short
			b.Recv, b.Send = 14680064, 8388608
			st.Tunnel.SocketBuffers = &b
		}), wantStatus: statusFailed, wantReason: "socket_buffer_below_requirement", wantDetail: []string{"send buffer of 8388608 bytes"}},
		{name: "not measured on this os", resp: runtimeResponse(func(st *agent.DoctorRuntimeState) {
			st.Tunnel.SocketBuffers = &agent.DoctorSocketBuffers{}
		}), wantStatus: statusNotTested, wantReason: "not_measured_on_this_os", wantDetail: []string{"Linux only", "not been verified"}},
		{name: "measurement failed", resp: runtimeResponse(func(st *agent.DoctorRuntimeState) {
			st.Tunnel.SocketBuffers = &agent.DoctorSocketBuffers{Supported: true, Port: 35454, Required: sockbuf.Required, Error: "no UDP socket bound to port 35454 was found"}
		}), wantStatus: statusUnknown, wantReason: "socket_buffers_unreadable", wantDetail: []string{"no UDP socket bound to port 35454"}},
		{name: "an older agent does not report it", resp: runtimeResponse(func(st *agent.DoctorRuntimeState) { st.Tunnel.SocketBuffers = nil }),
			wantStatus: statusUnknown, wantReason: "socket_buffers_not_reported", wantNext: []string{"restart the agent"}},
		{name: "no tunnel", resp: runtimeResponse(func(st *agent.DoctorRuntimeState) {
			st.Tunnel = agent.DoctorTunnel{State: proto.StatusError, Reason: "no tunnel"}
			st.Rules, st.Budgets = nil, nil
		}), wantStatus: statusSkipped, wantReason: "no_tunnel"},
		{name: "stopped", stopped: true, wantStatus: statusSkipped, wantReason: "agent_not_running", wantExit: 1},
		{name: "kernel mode", kernel: true, resp: kernelRuntime(func(*agent.DoctorRuntimeState) {}), wantStatus: statusNotTested, wantReason: "kernel_mode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := testAgentDoctorInput(t, t.TempDir())
			if tc.kernel {
				writeTestCredentials(t, in.CredentialsPath, kernelCredentials())
			} else {
				writeTestCredentials(t, in.CredentialsPath, registeredCredentials())
			}
			if !tc.stopped {
				holdTheLock(t, in.CredentialsPath)
				in.Dial = fakeDoctorSocket(t, liveReply(tc.resp))
			}
			rep := agentDiagnose(in)
			c, ok := findAgentCheck(rep, agentCheckSocketBufs)
			if !ok {
				t.Fatal("no tunnel.socket_buffers in the report")
			}
			if c.Status != tc.wantStatus || c.Reason != tc.wantReason {
				t.Errorf("status %s reason %q, want %s %q; detail: %s", c.Status, c.Reason, tc.wantStatus, tc.wantReason, c.Detail)
			}
			if c.verdict {
				t.Error("tunnel.socket_buffers moves the verdict; it must not")
			}
			for _, w := range tc.wantDetail {
				if !strings.Contains(c.Detail, w) {
					t.Errorf("detail lacks %q: %s", w, c.Detail)
				}
			}
			for _, w := range tc.wantNext {
				if !strings.Contains(c.Next, w) {
					t.Errorf("next lacks %q: %s", w, c.Next)
				}
			}
			if c.Status == statusFailed && c.Next == "" {
				t.Error("a FAILED item needs a next step")
			}
			// 条件に届かないことは終了コードを動かさない。止まっているエージェントの 1 は agent.process による
			if got := agentDoctorExitCode(rep); got != tc.wantExit {
				t.Errorf("exit code %d, want %d", got, tc.wantExit)
			}
		})
	}
}
