//go:build linux

package kernelmode

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/proto"
)

// このファイルの偽物と補助は、internal/agent と internal/agent/kernelmode に同じ名前のファイルで
// 1 つずつある。internal/agent のテストは kernelmode のテストのファイルに届かず、kernelmode のテストは
// internal/agent を import できないためである。2 つは kernelmode の名前の修飾子と、package と import の
// 行だけが違う。片方を直したら、もう片方も同じに直す。

// fakeKernel は Ops の記録器である。カーネルにも DNS にも触れずに、カーネルモードの dataplane が
// 何をどの順で呼ぶかを確かめる。
type fakeKernel struct {
	ensured   []wg.AgentConfig
	ensureErr error
	link      wg.AgentState
	linkErr   error
	holders   []string

	published  []nft.AgentPublication
	publishErr error
	// table は実際のテーブルの指紋の元である。公開のたびに進み、外からの変更は tableEdit を進めて模す
	tableGen  int
	tableEdit int
	tableGone bool
	// fpErr は、次の指紋の読みを 1 回だけ失敗させる
	fpErr error

	dns    map[string][]netip.Addr // 無い名前は解決できない
	dnsErr error                   // 設定すれば、どの名前も解決できない
	// probed は試し接続の宛先である。probeAll は同時に試すので、mu が守る
	mu       sync.Mutex
	probed   []netip.AddrPort
	probeErr map[netip.AddrPort]error
	// forwardOn は ip_forward の今の値、forwardReadEr と forwardWriteEr は読み書きの誤りである
	forwardOn      bool
	forwardReadEr  error
	forwardWriteEr error
	forwardWrites  int
	local          map[netip.Addr]bool
	// datagrams は keepalive ごとのデータグラムの宛先である。別の goroutine が送るので、mu が守る
	datagrams []netip.AddrPort
	// sendErr は、設定すればデータグラムの n 回目(0 から)の送信の誤りを返す。mu が守る
	sendErr func(n int) error
	// route は vpsd のトンネルアドレスへの経路が出るインタフェースである。空なら wgft0
	route    string
	routeErr error
	// onEnsure は、設定すれば wgft0 の収束が成功したときに呼ばれる
	onEnsure func()
	// lookups は引いた名前の記録である
	lookups []string
	// converged は conntrack の収束の呼び出しの記録である。convergeErr を設定すれば失敗させる
	converged   []convergeCall
	convergeErr error
	convergeRes conntrack.AgentResult
}

type convergeCall struct {
	prev  []nft.AgentPublication
	cur   nft.AgentPublication
	scope conntrack.AgentScope
}

func (k *fakeKernel) ops() Ops {
	return Ops{
		EnsureLink: func(cfg wg.AgentConfig) ([]string, error) {
			k.ensured = append(k.ensured, cfg)
			if k.ensureErr == nil && k.onEnsure != nil {
				k.onEnsure()
			}
			return nil, k.ensureErr
		},
		InspectLink: func(string, wgtypes.Key, wgtypes.Key) (wg.AgentState, error) { return k.link, k.linkErr },
		KeyHolders:  func(string, wgtypes.Key, wgtypes.Key) ([]string, error) { return k.holders, nil },
		Publish: func(p nft.AgentPublication, _ nft.AgentConfig) error {
			if k.publishErr != nil {
				return k.publishErr
			}
			k.published = append(k.published, p)
			k.tableGen++
			k.tableGone = false
			return nil
		},
		Fingerprint: func(string) (string, bool, error) {
			if err := k.fpErr; err != nil {
				k.fpErr = nil
				return "", false, err
			}
			if k.tableGone {
				return "", false, nil
			}
			return fmt.Sprintf("fp-%d-%d", k.tableGen, k.tableEdit), true, nil
		},
		Lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			k.mu.Lock()
			k.lookups = append(k.lookups, host)
			k.mu.Unlock()
			if k.dnsErr != nil {
				return nil, k.dnsErr
			}
			a, ok := k.dns[host]
			if !ok {
				return nil, fmt.Errorf("no such host %s", host)
			}
			return a, nil
		},
		Probe: func(_ context.Context, d netip.AddrPort) error {
			k.mu.Lock()
			defer k.mu.Unlock()
			k.probed = append(k.probed, d)
			return k.probeErr[d]
		},
		ReadIPForward: func() (bool, error) { return k.forwardOn, k.forwardReadEr },
		WriteIPForward: func() error {
			k.forwardWrites++
			if k.forwardWriteEr != nil {
				return k.forwardWriteEr
			}
			k.forwardOn = true
			return nil
		},
		LocalAddrs: func() (map[netip.Addr]bool, error) { return k.local, nil },
		SendDatagram: func(dst netip.AddrPort) error {
			k.mu.Lock()
			defer k.mu.Unlock()
			k.datagrams = append(k.datagrams, dst)
			if k.sendErr != nil {
				return k.sendErr(len(k.datagrams) - 1)
			}
			return nil
		},
		ConvergeFlows: func(prev []nft.AgentPublication, cur nft.AgentPublication, scope conntrack.AgentScope) (conntrack.AgentResult, error) {
			k.converged = append(k.converged, convergeCall{append([]nft.AgentPublication(nil), prev...), cur, scope})
			return k.convergeRes, k.convergeErr
		},
		RouteIface: func(netip.Addr) (string, error) {
			if k.route == "" {
				return "wgft0", k.routeErr
			}
			return k.route, k.routeErr
		},
		Now: func() time.Time { return time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC) },
	}
}

// newTestKernel は fakeKernel を使うカーネルモードの dataplane を、wg 設定を受け取った状態で作る。
func newTestKernel(t *testing.T, k *fakeKernel, f *credentials.Credentials, allow *allowtargets.List) *Dataplane {
	t.Helper()
	if f == nil {
		f = &credentials.Credentials{}
	}
	d := NewWithOps(context.Background(), "wgft0", allow, f, nil, k.ops())
	if _, err := d.Build(testKey(t), testWG(t)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

func testKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testWG(t *testing.T) proto.WGConfig {
	return proto.WGConfig{ServerPubkey: testKey(t).PublicKey().String(), Endpoint: "203.0.113.1:51820",
		Address: "10.200.0.2/24", MTU: 1420, Keepalive: 25}
}

func tcpRule(id, target string, lo, hi uint16) proto.AgentRule {
	return proto.AgentRule{ID: id, Proto: proto.TCP, ListenPort: proto.PortRange{Lo: lo, Hi: hi}, Target: target, Enabled: true}
}

// ours は、宣言どおりの wgft0 の状態を返す。
func ours(t *testing.T, d *Dataplane) wg.AgentState {
	t.Helper()
	cfg, err := d.LinkConfig()
	if err != nil {
		t.Fatal(err)
	}
	return wg.AgentState{Exists: true, Kind: "wireguard", Ownership: wg.OwnedByCurrentKey, Up: true, MTU: cfg.MTU,
		Addresses: []netip.Prefix{cfg.Address},
		Peers: []wg.PeerState{{PublicKey: cfg.Server.PublicKey, AllowedIPs: []netip.Prefix{netip.PrefixFrom(cfg.Server.Address, 32)},
			Keepalive: cfg.Server.Keepalive, Endpoint: netip.MustParseAddrPort("198.51.100.200:51820")}}}
}

func gens(ps []nft.AgentPublication) []uint64 {
	var out []uint64
	for _, p := range ps {
		out = append(out, p.Generation)
	}
	return out
}

// fakeKernelDoctor は DoctorOps の代わりである。カーネルに触れずに、読み方の関数が何を返すかを
// 確かめる。eperm は CAP_NET_ADMIN の無い呼び出し元の読み出しを模す。
type fakeKernelDoctor struct {
	exists, up bool
	kind       string
	state      wg.AgentState
	eperm      bool
	route      string

	table   nft.AgentInspection
	present bool
	// wantSeen は InspectTable に渡された比べる相手である
	wantSeen nft.AgentPublication

	sysctl map[string]string
	drops  []string
	// local はホスト自身のアドレスである。localErr があれば読めない
	local    map[netip.Addr]bool
	localErr error
}

func (k *fakeKernelDoctor) ops() DoctorOps {
	perm := fmt.Errorf("netlink receive: %w", syscall.EPERM)
	return DoctorOps{
		Link: func(string) (bool, string, bool, error) { return k.exists, k.kind, k.up, nil },
		InspectLink: func(string, wgtypes.Key, wgtypes.Key) (wg.AgentState, error) {
			if k.eperm {
				return wg.AgentState{}, perm
			}
			return k.state, nil
		},
		InspectTable: func(want nft.AgentPublication, _ string) (nft.AgentInspection, bool, error) {
			k.wantSeen = want
			if k.eperm {
				return nft.AgentInspection{}, false, fmt.Errorf("listing tables: %w", perm)
			}
			return k.table, k.present, nil
		},
		ReadSysctl: func(name string) (string, error) {
			v, ok := k.sysctl[name]
			if !ok {
				return "", os.ErrNotExist
			}
			return v, nil
		},
		ForwardDrops: func(string) ([]string, error) {
			if k.eperm {
				return nil, fmt.Errorf("listing chains: %w", perm)
			}
			return k.drops, nil
		},
		Route:      func(netip.Addr) (string, error) { return k.route, nil },
		LocalAddrs: func() (map[netip.Addr]bool, error) { return k.local, k.localErr },
	}
}

// withKernelDoctor は読み方の操作をテストの間だけ差し替える。
func withKernelDoctor(t *testing.T, k *fakeKernelDoctor) {
	t.Helper()
	old := DoctorKernelOps
	DoctorKernelOps = k.ops()
	t.Cleanup(func() { DoctorKernelOps = old })
}

// healthyKernel は、宣言どおりの wgft0 を持つホストである。
func healthyKernel(t *testing.T, f *credentials.Credentials) *fakeKernelDoctor {
	t.Helper()
	key, _ := wgtypes.ParseKey(f.WGPrivateKey)
	server, _ := wgtypes.ParseKey(f.LastState.WG.ServerPubkey)
	return &fakeKernelDoctor{
		exists: true, up: true, kind: "wireguard", route: "wgft0", present: true,
		state: wg.AgentState{Exists: true, Kind: "wireguard", Ownership: wg.OwnedByCurrentKey, PublicKey: key.PublicKey(),
			Up: true, MTU: 1420, Addresses: []netip.Prefix{netip.MustParsePrefix("10.200.0.2/24")},
			Peers: []wg.PeerState{{PublicKey: server, AllowedIPs: []netip.Prefix{netip.MustParsePrefix("10.200.0.1/32")},
				Endpoint: netip.MustParseAddrPort("203.0.113.1:51820"), Keepalive: 25 * time.Second}}},
		sysctl: map[string]string{"ip_forward": "1", "conf/all/rp_filter": "0", "conf/default/rp_filter": "2"},
	}
}
