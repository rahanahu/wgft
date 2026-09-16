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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	dir, err := os.MkdirTemp("", "wgft-uidemo-*")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(dir)

	if err := installFakeNFT(dir); err != nil {
		return fmt.Errorf("fake nft: %w", err)
	}

	st, err := store.Open(filepath.Join(dir, "demo.sqlite"))
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()

	srv := admin.New(st, newFakeBackend())
	log.Printf("uidemo: http://%s (fixed sample data, for screenshots only)", listenAddr)
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

// fakeNFTScript is the fake `nft` binary's output: a plausible ruleset for the three
// kernel-mode rules in the sample data below (the two proxy-mode rules are not DNAT'd).
const fakeNFTScript = `#!/bin/sh
cat <<'NFT'
table inet wgft {
	chain prerouting {
		type nat hook prerouting priority dstnat;
		iif != "wgft0" udp dport 2456-2457 dnat ip to 192.168.1.20:2456
		iif != "wgft0" tcp dport 8080 dnat ip to 192.168.1.10:8080
		iif != "wgft0" udp dport 19132 dnat ip to 192.168.1.30:19132
	}
	chain postrouting {
		type nat hook postrouting priority srcnat;
		oif "wgft0" masquerade
	}
}
NFT
`

// fakeBackend implements admin.Backend with fixed sample data: three agents (home,
// office, lab), five rules across two named groups plus one ungrouped, one
// ip-mismatch warning, and a server info block.
type fakeBackend struct {
	agents   []admin.AgentInfo
	rules    []proto.Rule
	drops    map[string]uint64
	warnings []admin.Warning
	info     admin.ServerInfo
}

func newFakeBackend() *fakeBackend {
	base := time.Now()
	rfc := func(d time.Duration) string { return base.Add(d).Format(time.RFC3339) }

	mismatch := admin.Warning{
		Agent:  "office",
		Kind:   "ip-mismatch",
		Detail: "stream 203.0.113.24 / wg 198.51.100.9",
		At:     rfc(-3 * time.Minute),
	}

	agents := []admin.AgentInfo{
		{
			Name: "home", Address: "10.200.0.2", CreatedAt: rfc(-72 * time.Hour),
			Connected: true, StreamFrom: "203.0.113.10:51820", WGEndpoint: "203.0.113.10:51820",
			LastHeartbeat: rfc(-5 * time.Second), Generation: 42,
			Tunnel: proto.TunnelStatus{State: proto.StatusOK, Endpoint: "203.0.113.10:51820"},
		},
		{
			Name: "office", Address: "10.200.0.3", CreatedAt: rfc(-48 * time.Hour),
			Connected: false, StreamFrom: "203.0.113.24:41220", WGEndpoint: "198.51.100.9:51820",
			LastHeartbeat: rfc(-3 * time.Minute), Generation: 40,
			Warnings: []admin.Warning{mismatch},
		},
		{
			Name: "lab", Address: "10.200.0.4", CreatedAt: rfc(-24 * time.Hour),
			Connected: true, StreamFrom: "192.0.2.55:51820", WGEndpoint: "192.0.2.55:51820",
			LastHeartbeat: rfc(-12 * time.Second), Generation: 42,
			Tunnel: proto.TunnelStatus{State: proto.StatusOK, Endpoint: "192.0.2.55:51820"},
		},
	}

	rules := []proto.Rule{
		{
			ID: "r_mc_tcp25565", Agent: "home", Group: "minecraft", Note: "public server",
			Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565},
			Target: "192.168.1.15:25565", VPSMode: proto.ModeProxy, ProxyProtocol: true, Enabled: true,
			SourceAllow: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("198.51.100.0/24")},
		},
		{
			ID: "r_mc_tcp8080", Agent: "office", Group: "minecraft", Note: "Bedrock voice",
			Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 8080, Hi: 8080},
			Target: "192.168.1.10:8080", VPSMode: proto.ModeKernel, Enabled: true,
		},
		{
			ID: "r_valheim_udp", Agent: "home", Group: "valheim", Note: "weekend server for friends",
			Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2457},
			Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true,
		},
		{
			ID: "r_lab_udp19132", Agent: "lab",
			Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 19132, Hi: 19132},
			Target: "192.168.1.30:19132", VPSMode: proto.ModeKernel, Enabled: true,
			SourceDeny:    []netip.Prefix{netip.MustParsePrefix("203.0.113.50/32")},
			PerSourceRate: &proto.Rate{Count: 10, Unit: proto.PerSecond},
		},
		{
			ID: "r_lab_tcp22", Agent: "lab",
			Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 22, Hi: 22},
			Target: "192.168.1.2:22", VPSMode: proto.ModeProxy, Enabled: false,
		},
	}

	return &fakeBackend{
		agents: agents,
		rules:  rules,
		drops: map[string]uint64{
			"r_mc_tcp25565": 8392,
			"r_mc_tcp8080":  523,
			"r_valheim_udp": 14,
		},
		warnings: []admin.Warning{mismatch},
		info: admin.ServerInfo{
			Version:          "v0.1.0-abc1234",
			Mode:             "kernel",
			StartedAt:        rfc(-(50*time.Hour + 5*time.Minute)), // uptime: 2d 2h
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
		},
	}
}

func (b *fakeBackend) Rules() ([]proto.Rule, error) { return b.rules, nil }
func (b *fakeBackend) Generation() (uint64, error)  { return 42, nil }

func (b *fakeBackend) Batch(req admin.BatchRequest) (*store.BatchResult, error) {
	return &store.BatchResult{Rules: b.rules, Generation: 42, Changed: false}, nil
}

func (b *fakeBackend) AgentState(agent string) (*proto.State, error) {
	return &proto.State{Generation: 42}, nil
}

func (b *fakeBackend) Agents() ([]admin.AgentInfo, error) { return b.agents, nil }

func (b *fakeBackend) RuleDrops() (map[string]uint64, error) { return b.drops, nil }

func (b *fakeBackend) JoinString(name string) (admin.JoinStringResponse, error) {
	return admin.JoinStringResponse{
		JoinString: "wgft://vps.example.com:8443/" + name + "#sha256:demo0000000000000000000000000000000000000000000000000000000000",
		ExpiresAt:  time.Now().Add(24 * time.Hour).Format(time.RFC3339),
	}, nil
}

func (b *fakeBackend) Revoke(name string) error { return nil }

func (b *fakeBackend) Warnings() ([]admin.Warning, error) { return b.warnings, nil }

func (b *fakeBackend) DismissWarning(agent, kind, detail string) error { return nil }

func (b *fakeBackend) CheckConnectivity(ruleID string) (admin.ConnCheck, error) {
	return admin.ConnCheck{OK: true, Reach: "target", Detail: "demo: path OK"}, nil
}

func (b *fakeBackend) ServerInfo() (admin.ServerInfo, error) { return b.info, nil }
