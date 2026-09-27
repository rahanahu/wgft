package main

import (
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent"
	"github.com/rahanahu/wgft/proto"
)

// tunnel.udp_accounting は、netstack の UDP の受信の会計がトンネルの UDP を止めていないかを示す
// (設計文書 7 節、10.2c 節)。止めていれば FAILED になり、総合判定と終了コードを動かす。通常時は OK で
// 終了コード 0 である。ソケットのバッファだけが条件に届かない実行は、従来どおり終了コード 0 である。
func TestAgentDoctorUDPAccounting(t *testing.T) {
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
		// wantSocketBufs は、指定したときの tunnel.socket_buffers の状態である
		wantSocketBufs string
	}{
		{name: "consistent", resp: healthyLiveResponse(), wantStatus: statusOK, wantDetail: []string{"consistent"}},
		{name: "stopped by a fault", resp: runtimeResponse(func(st *agent.DoctorRuntimeState) {
			st.Tunnel.UDPAccounting = &agent.DoctorUDPAccounting{Stopped: true, Error: "unreserved UDP dequeue"}
		}), wantStatus: statusFailed, wantReason: "udp_accounting_stopped",
			wantDetail: []string{"stopped all UDP", "unreserved UDP dequeue", "TCP rules keep working"},
			wantNext:   []string{"restart the agent", "report this as a bug"}, wantExit: 1},
		{name: "an older agent does not report it", resp: runtimeResponse(func(st *agent.DoctorRuntimeState) { st.Tunnel.UDPAccounting = nil }),
			wantStatus: statusUnknown, wantReason: "udp_accounting_not_reported", wantNext: []string{"restart the agent"}},
		{name: "no tunnel", resp: runtimeResponse(func(st *agent.DoctorRuntimeState) {
			st.Tunnel = agent.DoctorTunnel{State: proto.StatusError, Reason: "no tunnel"}
			st.Rules, st.Budgets = nil, nil
		}), wantStatus: statusSkipped, wantReason: "no_tunnel"},
		// ソケットのバッファだけが条件に届かない実行は、従来どおり終了コード 0 のままである
		{name: "socket buffers alone short", resp: runtimeResponse(func(st *agent.DoctorRuntimeState) {
			st.Tunnel.SocketBuffers = &agent.DoctorSocketBuffers{Supported: true, Port: 35454, Sockets: 2, Recv: 425984, Send: 425984, Required: 14680064}
		}), wantStatus: statusOK, wantDetail: []string{"consistent"}, wantSocketBufs: statusFailed},
		{name: "stopped agent", stopped: true, wantStatus: statusSkipped, wantReason: "agent_not_running", wantExit: 1},
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
			c, ok := findAgentCheck(rep, agentCheckUDPAcct)
			if !ok {
				t.Fatal("no tunnel.udp_accounting in the report")
			}
			if c.Status != tc.wantStatus || c.Reason != tc.wantReason {
				t.Errorf("status %s reason %q, want %s %q; detail: %s", c.Status, c.Reason, tc.wantStatus, tc.wantReason, c.Detail)
			}
			if !c.verdict {
				t.Error("tunnel.udp_accounting does not move the verdict")
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
			if strings.ContainsAny(c.Detail+c.Next, "()") {
				t.Errorf("parentheses in %q / %q", c.Detail, c.Next)
			}
			if tc.wantSocketBufs != "" {
				if sb, _ := findAgentCheck(rep, agentCheckSocketBufs); sb.Status != tc.wantSocketBufs {
					t.Errorf("tunnel.socket_buffers = %s, want %s", sb.Status, tc.wantSocketBufs)
				}
			}
			if got := agentDoctorExitCode(rep); got != tc.wantExit {
				t.Errorf("exit code %d, want %d", got, tc.wantExit)
			}
		})
	}
}
