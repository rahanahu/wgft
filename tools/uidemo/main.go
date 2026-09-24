// Package main は README のスクリーンショット撮影用の使い捨てデモである。
// internal/vpsd/admin パッケージの公開 API (New, Serve) だけを使い、
// 固定のサンプルデータを返す Backend で Web UI を 127.0.0.1:8687 (TCP) に立てる。
// nftables や WireGuard には一切触れない。起動は scripts/screenshot-ui.sh から行う想定で、
// 単体でも `go run ./tools/uidemo` で動く (Ctrl-C で終了)。
//
// 「適用中のファイアウォール設定」欄は admin パッケージが実際の nft コマンドを
// exec.Command で呼ぶため、このデモでは一時ディレクトリに偽の nft 実行ファイルを置き、
// PATH の先頭に加えることでもっともらしい表示を出す (admin パッケージ自体は変更しない)。
package main

import (
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/admin"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// listenAddr は Web UI の待ち受け先。scripts/screenshot-ui.sh もこの値を使う。
const listenAddr = "127.0.0.1:8687"

func main() {
	mode := flag.String("mode", "kernel", "forwarding mode to show in the sample ServerInfo; kernel or userspace")
	flag.Parse()
	if *mode != "kernel" && *mode != "userspace" {
		log.Fatalf("uidemo: -mode must be kernel or userspace, got %q", *mode)
	}
	if err := run(*mode); err != nil {
		log.Fatal(err)
	}
}

func run(mode string) error {
	dir, err := os.MkdirTemp("", "wgft-uidemo-*")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := installFakeNFT(dir); err != nil {
		return fmt.Errorf("fake nft: %w", err)
	}

	srv := admin.New(newFakeBackend(mode))
	log.Printf("uidemo: http://%s, fixed sample data, mode=%s, for screenshots only", listenAddr, mode)
	return admin.Serve(listenAddr, srv, false)
}

// installFakeNFT は「nft list table inet wgft」に応じるだけの偽の nft 実行ファイルを
// dir に置き、PATH の先頭に加える。これは admin パッケージが呼ぶ本物の nft コマンドの
// 代わりで、root 権限や実際の nftables テーブルなしにダッシュボードの
// 「適用中のファイアウォール設定」欄を埋めるためのものである。
func installFakeNFT(dir string) error {
	path := filepath.Join(dir, "nft")
	if err := os.WriteFile(path, []byte(fakeNFTScript), 0o755); err != nil {
		return err
	}
	return os.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// fakeNFTScript is the fake `nft` binary's output: a plausible ruleset for the
// kernel-mode rules in the sample data below (the two proxy-mode rules are not DNAT'd).
const fakeNFTScript = `#!/bin/sh
cat <<'NFT'
table inet wgft {
	chain prerouting {
		type nat hook prerouting priority dstnat;
		iif != "wgft0" udp dport 2456-2457 dnat ip to 192.168.1.20:2456
		iif != "wgft0" udp dport 2458-2459 dnat ip to 192.168.1.20:2458
		iif != "wgft0" tcp dport 8080 dnat ip to 192.168.1.10:8080
		iif != "wgft0" tcp dport 8081 dnat ip to 192.168.1.30:8081
		iif != "wgft0" udp dport 19132 dnat ip to 192.168.1.30:19132
		iif != "wgft0" udp dport 30000-30001 dnat ip to 192.168.1.40:30000
		iif != "wgft0" udp dport 30002-30003 dnat ip to 192.168.1.40:30002
	}
	chain postrouting {
		type nat hook postrouting priority srcnat;
		oif "wgft0" masquerade
	}
}
NFT
`

// fakeBackend implements admin.Backend with fixed sample data: four agents (home,
// office, lab, and backup, which is disabled), twelve rules across three named groups
// plus one ungrouped, two of them left by an agent that was revoked (oldhome), one
// ip-mismatch warning, and a server info block. Among the rules, r_game_udp and
// r_game_udp2 are adjacent and mergeable; r_lab_udp30000 and
// r_lab_udp30002 are adjacent but not (their deny lists differ).
//
// Every timestamp (heartbeats, handshakes, the warning, the server's start) is computed
// relative to the time of each request, not to the time the demo started, so a screenshot
// looks the same however long the demo has been running: a healthy agent's heartbeat stays a
// few seconds old instead of going stale after the liveness window.
type fakeBackend struct {
	rules []proto.Rule
	drops map[string]uint64
	mode  string
}

// rfcAgo returns the RFC 3339 time d before now.
func rfcAgo(d time.Duration) string { return time.Now().Add(-d).Format(time.RFC3339) }

// sampleWarning is the office agent's ip-mismatch warning, raised three minutes ago.
func sampleWarning() admin.Warning {
	return admin.Warning{
		Agent:  "office",
		Kind:   "ip-mismatch",
		Detail: "stream 203.0.113.24 / wg 198.51.100.9",
		At:     rfcAgo(3 * time.Minute),
	}
}

// sampleAgents returns the three sample agents with their timestamps taken relative to now.
func sampleAgents() []admin.AgentInfo {
	mismatch := sampleWarning()

	return []admin.AgentInfo{
		{
			// generation 42 matches Generation() below, and it reports every rule it
			// owns, so r_pub_tcp25565, r_game_udp and r_game_udp2 show "applied"
			// while r_home_tcp8081 shows "error" with a realistic dial failure from
			// checkTarget (relay.Manager). A listen bind conflict can't happen
			// here: the agent's listener lives on its own netstack (design 7 section).
			Name: "home", Address: "10.200.0.2", CreatedAt: rfcAgo(72 * time.Hour),
			Connected: true, StreamFrom: "203.0.113.10:51820", WGEndpoint: "203.0.113.10:51820",
			LastHeartbeat: rfcAgo(5 * time.Second), Generation: 42,
			PublicKey: "HhYgfQgcVISS51VHjdkVxdPeCdaDL3P+vgm9soc8MLQ=", LastHandshake: rfcAgo(40 * time.Second),
			Tunnel: admin.TunnelStatus{State: proto.StatusOK, Endpoint: "203.0.113.10:51820"},
			Rules: []proto.RuleStatus{
				{ID: "r_pub_tcp25565", State: proto.StatusOK},
				{ID: "r_game_udp", State: proto.StatusOK},
				{ID: "r_game_udp2", State: proto.StatusOK},
				{ID: "r_home_tcp8081", State: proto.StatusError, Reason: "tcp/8081: dial tcp 192.168.1.30:8081: connect: connection refused"},
			},
		},
		{
			// disconnected, so r_pub_tcp8080 shows "agent offline" regardless of Rules. Tunnel
			// and StreamFrom/WGEndpoint are the last heartbeat before the stream dropped
			// (design 5.2 section); Connected: false must keep the dashboard from drawing
			// them as current (tunnel "OK", a live IP match/mismatch): the tunnel shows as a
			// stale last report, and the IP comparison (both values are history) is hidden.
			Name: "office", Address: "10.200.0.3", CreatedAt: rfcAgo(48 * time.Hour),
			Connected: false, StreamFrom: "203.0.113.24:41220", WGEndpoint: "198.51.100.9:51820",
			LastHeartbeat: rfcAgo(3 * time.Minute), Generation: 40,
			PublicKey: "Z50DXIe02Z4jmIIULTXv8vct6DA04NgcDKgxLdm6ytI=", LastHandshake: rfcAgo(6 * time.Minute),
			Tunnel:   admin.TunnelStatus{State: proto.StatusOK, Endpoint: "198.51.100.9:51820"},
			Warnings: []admin.Warning{mismatch},
		},
		{
			// generation 40 is behind Generation() (42), so both of its rules show
			// "pending" no matter what Rules below says. It fell behind 20 seconds ago, as a
			// current server reports in generation_behind_since, so the diagnosis reads it as
			// UNKNOWN generation_pending (still within the 60s limit) and the dashboard marks
			// its rules "? agent" rather than a red "✕ agent".
			Name: "lab", Address: "10.200.0.4", CreatedAt: rfcAgo(24 * time.Hour),
			Connected: true, StreamFrom: "192.0.2.55:51820", WGEndpoint: "192.0.2.55:51820",
			LastHeartbeat: rfcAgo(12 * time.Second), Generation: 40, GenerationBehindSince: rfcAgo(20 * time.Second),
			PublicKey: "qJzBQ+ilV8EQ9749TxyIY1sB1jRieCYDU33kUi6aAPg=", LastHandshake: rfcAgo(18 * time.Second),
			Tunnel: admin.TunnelStatus{State: proto.StatusOK, Endpoint: "192.0.2.55:51820"},
			Rules: []proto.RuleStatus{
				{ID: "r_lab_udp19132", State: proto.StatusOK},
				{ID: "r_lab_tcp22", State: proto.StatusOK},
			},
		},
		{
			// disabled (design 5.1 section): it stays connected and keeps its key, but the server
			// forwards none of its rules and it reports none of them. The dashboard shows a neutral
			// "Disabled" row with its tunnel and heartbeat as muted reference values, and its rule
			// as a grey "Agent disabled" with a dash.
			Name: "backup", Address: "10.200.0.5", CreatedAt: rfcAgo(96 * time.Hour),
			Disabled: true, DisabledAt: time.Now().Add(-26 * time.Hour).Format(time.RFC3339),
			Connected: true, StreamFrom: "198.51.100.40:51820", WGEndpoint: "198.51.100.40:51820",
			LastHeartbeat: rfcAgo(8 * time.Second), Generation: 42,
			PublicKey: "mVQ2xbJ6yJ0jdmvdXk1LcS1jHkq3rN7eTqS5pBnd0Fs=", LastHandshake: rfcAgo(70 * time.Second),
			Tunnel: admin.TunnelStatus{State: proto.StatusOK, Endpoint: "198.51.100.40:51820"},
		},
	}
}

// disabledAgents and revokedAgents name the sample agents whose rules the server does not
// publish: backup is disabled, and oldhome was revoked while its rules were kept (design 5.1
// section). ApplyStatus reports their rules not_active with the reasons a real server gives.
var (
	disabledAgents = map[string]bool{"backup": true}
	revokedAgents  = map[string]bool{"oldhome": true}
)

func newFakeBackend(mode string) *fakeBackend {
	rules := []proto.Rule{
		{
			ID: "r_pub_tcp25565", Agent: "home", Group: "public", Note: "public server",
			Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565},
			Target: "192.168.1.15:25565", VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: true,
			SourceAllow: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("198.51.100.0/24")},
		},
		{
			ID: "r_pub_tcp8080", Agent: "office", Group: "public", Note: "voice chat",
			Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 8080, Hi: 8080},
			Target: "192.168.1.10:8080", VPSMode: proto.ModeKernel, Enabled: true,
		},
		{
			ID: "r_game_udp", Agent: "home", Group: "game", Note: "weekend server for friends",
			Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2457},
			Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true,
		},
		{
			// Adjacent to r_game_udp above with everything else equal (agent, proto,
			// mode, proxy_protocol, lists, rates, enabled), so the rule detail page's
			// merge section offers each as the other's candidate.
			ID: "r_game_udp2", Agent: "home", Group: "game", Note: "extra port for the weekend server",
			Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2458, Hi: 2459},
			Target: "192.168.1.20:2458", VPSMode: proto.ModeKernel, Enabled: true,
		},
		{
			// A TCP rule with nothing listening on its target, for a realistic error
			// state (see the home agent's Rules above).
			ID: "r_home_tcp8081", Agent: "home", Note: "extra web port",
			Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 8081, Hi: 8081},
			Target: "192.168.1.30:8081", VPSMode: proto.ModeKernel, Enabled: true,
		},
		{
			// deny, allow, and a rate together, so the rule detail page has content
			// in every one of its sections when inspected manually.
			ID: "r_lab_udp19132", Agent: "lab",
			Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 19132, Hi: 19132},
			Target: "192.168.1.30:19132", VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny:    []netip.Prefix{netip.MustParsePrefix("203.0.113.50/32")},
			SourceAllow:   []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
			PerSourceRate: &proto.Rate{Count: 10, Unit: proto.PerSecond},
		},
		{
			ID: "r_lab_tcp22", Agent: "lab",
			Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 22, Hi: 22},
			Target: "192.168.1.2:22", VPSMode: proto.ModeProxy, Enabled: false,
		},
		{
			// Adjacent range rules that cannot merge (their deny lists differ), so the
			// rule detail page's merge section shows a reason instead of a
			// candidate for both r_lab_udp30000 and r_lab_udp30002.
			ID: "r_lab_udp30000", Agent: "lab", Note: "test range A",
			Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 30000, Hi: 30001},
			Target: "192.168.1.40:30000", VPSMode: proto.ModeKernel, Enabled: true,
		},
		{
			ID: "r_lab_udp30002", Agent: "lab", Note: "test range B",
			Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 30002, Hi: 30003},
			Target: "192.168.1.40:30002", VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny: []netip.Prefix{netip.MustParsePrefix("203.0.113.90/32")},
		},
		{
			// The disabled agent's rule keeps its own enabled flag; it does not forward while the
			// agent is disabled.
			ID: "r_backup_tcp8443", Agent: "backup", Group: "backup", Note: "offsite backup sync",
			Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 8443, Hi: 8443},
			Target: "192.168.2.10:8443", VPSMode: proto.ModeKernel, Enabled: true,
		},
		{
			// Two rules left by the revoked agent oldhome, waiting for an agent of that name to
			// register again (design 5.1 section). The dashboard shows them grey as
			// "Agent not registered" with a dash, without counting them as errors.
			ID: "r_old_tcp9000", Agent: "oldhome", Group: "backup", Note: "old file share",
			Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 9000, Hi: 9000},
			Target: "192.168.3.10:9000", VPSMode: proto.ModeKernel, Enabled: true,
		},
		{
			ID: "r_old_udp9001", Agent: "oldhome", Group: "backup",
			Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 9001, Hi: 9001},
			Target: "192.168.3.10:9001", VPSMode: proto.ModeKernel, Enabled: true,
		},
	}

	return &fakeBackend{
		rules: rules,
		drops: map[string]uint64{
			"r_pub_tcp25565": 8392,
			"r_pub_tcp8080":  523,
			"r_game_udp":     14,
		},
		mode: mode,
	}
}

func (b *fakeBackend) ServerInfo() (admin.ServerInfo, error) {
	return admin.ServerInfo{
		Version:          "v1.1.0",
		Mode:             b.mode,
		StartedAt:        rfcAgo(50*time.Hour + 5*time.Minute), // uptime: 2d 2h
		WGInterface:      "wgft0",
		WGAddress:        "10.200.0.1/24",
		WGPort:           51821,
		WGEndpoint:       "vps.example.com:51821",
		AgentAPIPort:     "8443",
		AdminAddr:        listenAddr,
		MTU:              1420,
		ServerPubKey:     "wJ6znEXOTPMBUXW+3z2vqjaMYikBWi2gYGA9EI0PZXk=",
		Kernel:           "6.1.0-53-amd64",
		NFT:              "v1.0.6",
		IPForwardSetAt:   "", // unchanged
		UDPTimeout:       30,
		UDPTimeoutStream: 120,
	}, nil
}

func (b *fakeBackend) Rules() ([]proto.Rule, error) { return b.rules, nil }
func (b *fakeBackend) Generation() (uint64, error)  { return 42, nil }

// Batch applies upsert/delete to the in-memory sample rules via admin.ApplyBatchToRules,
// the same helper internal/vpsd/admin_test.go's fakeBackend uses, so the "Import"
// confirmation page (tools/uidemo) can actually apply against the demo data. Generation
// stays fixed at 42 (ServerInfo/AgentState below match), since the demo has no real
// generation tracking.
func (b *fakeBackend) Batch(req admin.BatchRequest) (*store.BatchResult, error) {
	rules, err := admin.ApplyBatchToRules(b.rules, req)
	if err != nil {
		return nil, err
	}
	b.rules = rules
	return &store.BatchResult{Rules: b.rules, Generation: 42, Changed: len(req.Upsert) > 0 || len(req.Delete) > 0}, nil
}

func (b *fakeBackend) AgentState(agent string) (*proto.State, error) {
	return &proto.State{Generation: 42}, nil
}

func (b *fakeBackend) Agents() ([]admin.AgentInfo, error) { return sampleAgents(), nil }

func (b *fakeBackend) RuleDrops() (map[string]uint64, error) { return b.drops, nil }

func (b *fakeBackend) JoinString(name string) (admin.JoinStringResponse, error) {
	return admin.JoinStringResponse{
		JoinString: "wgft://vps.example.com:8443/" + name + "#sha256:demo0000000000000000000000000000000000000000000000000000000000",
		ExpiresAt:  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}, nil
}

func (b *fakeBackend) Revoke(name string) error { return nil }

func (b *fakeBackend) DisableAgent(name string) (admin.AgentDisabledResponse, error) {
	return admin.AgentDisabledResponse{Name: name, Disabled: true}, nil
}

func (b *fakeBackend) EnableAgent(name string) (admin.AgentDisabledResponse, error) {
	return admin.AgentDisabledResponse{Name: name}, nil
}

func (b *fakeBackend) Warnings() ([]admin.Warning, error) {
	return []admin.Warning{sampleWarning()}, nil
}

func (b *fakeBackend) DismissWarning(agent, kind, detail string) error { return nil }
func (b *fakeBackend) IPMismatchAcks() ([]store.Ack, error)            { return nil, nil }

func (b *fakeBackend) CheckConnectivity(ruleID string) (admin.ConnCheck, error) {
	return admin.ConnCheck{OK: true, Reach: "target", Detail: "demo: path OK"}, nil
}

// ApplyStatus reports every enabled rule's public port as active at generation 42, the way a
// real server reports it, except the rules of the disabled and the revoked agent, which a real
// server leaves out of the data plane as not_active with these reasons (internal/vpsd/apply.go).
// The dashboard reads only not_active and pending from it; the diagnosis page (/ui/doctor) reads
// it for the public port.
func (b *fakeBackend) ApplyStatus() (admin.ApplyStatus, bool) {
	gen := uint64(42)
	st := admin.ApplyStatus{DesiredGeneration: gen, ActiveGeneration: gen, Rules: map[string]admin.RuleApply{}}
	for _, r := range b.rules {
		switch {
		case !r.Enabled:
		case disabledAgents[r.Agent]:
			st.Rules[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: fmt.Sprintf("agent %q is disabled", r.Agent)}
		case revokedAgents[r.Agent]:
			st.Rules[r.ID] = admin.RuleApply{ApplyState: admin.ApplyNotActive, Reason: fmt.Sprintf("agent %q is not registered", r.Agent)}
		default:
			st.Rules[r.ID] = admin.RuleApply{ApplyState: admin.ApplyActive, ActiveGeneration: &gen}
		}
	}
	return st, true
}

// AgentRuleStatuses reports what each rule's agent last said about it, from the sample agents
// above, so the diagnosis page can show a rule stopping at its target (r_home_tcp8081) and a UDP
// rule whose listener is open (r_game_udp).
func (b *fakeBackend) AgentRuleStatuses(rules []proto.Rule) map[string]admin.AgentRuleStatus {
	out := make(map[string]admin.AgentRuleStatus, len(rules))
	agents := sampleAgents()
	for _, r := range rules {
		st := admin.AgentRuleStatus{Agent: r.Agent}
		for _, a := range agents {
			if a.Name != r.Agent {
				continue
			}
			st.Connected = a.Connected
			for _, rs := range a.Rules {
				if rs.ID == r.ID {
					st.State, st.Reason, st.At = rs.State, rs.Reason, a.LastHeartbeat
				}
			}
		}
		out[r.ID] = st
	}
	return out
}
