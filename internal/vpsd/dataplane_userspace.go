package vpsd

// ユーザー空間モードの転送面(仕様 6.3 節)を Daemon に見せる薄い層。転送そのもの(wireguard-go と
// netstack のトンネル、中継、接続元制限とレート制限の評価器)は internal/dataplane/userspace の
// Backend が持ち、ここは Daemon の serverDataplane の形に合わせることと、ユーザー空間モードでは
// 何もしないホスト側の検査(他テーブル、bind 中のポート、ip_forward)だけを受け持つ。

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/userspace"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/vpsd/check"
	"github.com/rahanahu/wgft/internal/vpsd/conncheck"
	ctconv "github.com/rahanahu/wgft/internal/vpsd/conntrack"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/wg"
	"github.com/rahanahu/wgft/proto"
)

// userspaceDataplane はユーザー空間モードの転送面。
type userspaceDataplane struct {
	b *userspace.Backend
}

// EnsureWG は wg.Config のうち Backend の宣言に当たる部分を渡す。インタフェース名と
// AdoptExisting はカーネルの wg インタフェースだけの性質なので使わない。
func (u *userspaceDataplane) EnsureWG(cfg wg.Config) ([]string, error) {
	peers := make([]dataplane.Peer, len(cfg.Peers))
	for i, p := range cfg.Peers {
		peers[i] = dataplane.Peer{PublicKey: p.PublicKey, Address: p.Address}
	}
	return u.b.EnsureWG(dataplane.WGConfig{PrivateKey: cfg.PrivateKey, ListenPort: cfg.ListenPort,
		Address: cfg.Address, MTU: cfg.MTU, Peers: peers})
}

func (u *userspaceDataplane) WGStatus() (*wgtypes.Device, error) { return u.b.WGStatus() }

func (u *userspaceDataplane) OtherDeviceWithKey(wgtypes.Key) (string, bool) { return "", false }

// ReadUDPTimeouts はカーネルの conntrack を使わないので、既定値をそのまま配る(エージェントの UDP セッションの期限)。
func (u *userspaceDataplane) ReadUDPTimeouts() (wg.UDPTimeouts, error) {
	return wg.UDPTimeouts{Timeout: 30, TimeoutStream: 120}, nil
}

// Inspect は他テーブルの検査を行わない(nftables を使わない。仕様 6.3 節)。
func (u *userspaceDataplane) Inspect() (*check.Report, error) { return &check.Report{}, nil }

// BoundPorts は空。bind の失敗がそのまま分かる(仕様 6.3 節)。
func (u *userspaceDataplane) BoundPorts() (check.Bound, error) {
	return check.Bound{proto.TCP: {}, proto.UDP: {}}, nil
}

// InputPortSuggestions は input が policy drop なら足す行を返す。nftables を読めない(非 root)ときは提示しない。
func (u *userspaceDataplane) InputPortSuggestions(port uint16) ([]string, error) {
	lines, err := check.InputPortSuggestions(port)
	if err != nil {
		return nil, nil
	}
	return lines, nil
}

func (u *userspaceDataplane) ReadDrops() ([]dataplane.Drop, error) { return u.b.ReadDrops() }

// participant は Backend そのもの。Backend は Plan だけから組み立てる。
// プロキシモード(Relay)のルールは Daemon の proxyrelay が受け持ち、Backend は Transparent のルールだけを開く。
func (u *userspaceDataplane) participant() dataplane.Participant {
	return u.b
}

// Converge は接続元制限を満たさなくなった進行中のセッションを閉じる(conntrack 収束の代わり。仕様 6.3 節)。
func (u *userspaceDataplane) Converge(_ []ctconv.Rule, _ netip.Prefix, plan planner.Plan) (int, error) {
	return u.b.Converge(plan)
}

func (u *userspaceDataplane) EnableIPForward(*store.Store) *check.Finding { return nil }

func (u *userspaceDataplane) CheckConnectivity(addr string) conncheck.Result {
	return conncheck.Check(addr, conncheck.Options{Dial: u.b.Dial})
}
