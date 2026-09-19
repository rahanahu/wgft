package vpsd

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/vpsd/check"
	"github.com/rahanahu/wgft/internal/vpsd/conncheck"
	ctconv "github.com/rahanahu/wgft/internal/vpsd/conntrack"
	"github.com/rahanahu/wgft/internal/vpsd/nft"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/wg"
)

// serverDataplane は VPS 側の転送面を Daemon から見た形。Daemon がカーネルや外部の状態を触るときは、
// 必ずここを通る。実装は 2 つある。kernelDataplane(nftables の DNAT とカーネル WireGuard、仕様 6.1 節)は
// まだこのパッケージの中にあり、Phase 3(設計文書 7a.8 節)で internal/dataplane/linuxkernel へ移す。
// userspaceDataplane(仕様 6.3 節)は internal/dataplane/userspace の Backend を包むだけの薄い層で、
// 他テーブルの検査や ip_forward のような、ユーザー空間モードでは何もしないホスト側の検査を受け持つ。
//
// メソッドの形はいまのカーネル実装の型(wg.Config、check.Report など)をそのまま出している。
// participant は、どちらの実装も Plan だけから table inet wgft(または userspace の宣言)を組み立てる
// (設計文書 7a.8 節 Phase 3)。rules と agentAddr の引数は、ログの件数表示のためだけに applyNFT が残す。
type serverDataplane interface {
	// EnsureWG は wg インタフェースを宣言(鍵、ポート、アドレス、MTU、ピア集合)に収束させ、行った変更を返す(仕様 9 節)。
	EnsureWG(cfg wg.Config) ([]string, error)
	// WGStatus は wg インタフェースの現在のピア(エンドポイント、最終ハンドシェイク)を返す。
	WGStatus() (*wgtypes.Device, error)
	// OtherDeviceWithKey は同じサーバ鍵を持つ別名の WireGuard デバイスがあればその名前を返す(インタフェース名の変更の検出)。
	OtherDeviceWithKey(key wgtypes.Key) (string, bool)
	// ReadUDPTimeouts は conntrack の UDP タイムアウト 2 値を読む(全体状態でエージェントに配る。仕様 4 節)。
	ReadUDPTimeouts() (wg.UDPTimeouts, error)
	// Inspect は他テーブルの forward / input / DNAT の検査(仕様 6.1 節)。起動時と rule add 時に使う。
	Inspect() (*check.Report, error)
	// BoundPorts は VPS 上で bind 中のポート(SSH の締め出しを防ぐ検査。仕様 5.3 節)。
	BoundPorts() (check.Bound, error)
	// InputPortSuggestions は、プロキシモードの公開ポートが input で塞がれていれば足す行を返す(仕様 6.2 節)。
	InputPortSuggestions(port uint16) ([]string, error)
	// ReadDrops は差し替え直前の drop カウンタを読む(仕様 6.1 節)。
	ReadDrops() ([]dataplane.Drop, error)
	// participant は、Runtime の dataplane の participant を返す(設計文書 7a.2 節)。その Commit が転送の
	// 宣言を 1 回で公開する(カーネルでは table inet wgft の 1 トランザクションの差し替え。仕様 6.1 節)。
	// 組み立ての元になる Plan は Runtime.Apply が dataplane.Desired 経由で渡す
	participant() dataplane.Participant
	// Converge は外から入った進行中のフローを宣言に収束させ、消した数を返す(仕様 6.1、6.3 節)。
	Converge(rules []ctconv.Rule, wgNet netip.Prefix, plan planner.Plan) (int, error)
	// EnableIPForward は net.ipv4.ip_forward を 1 にする(仕様 6.1 節)。
	// 書き込みに失敗すると、policy drop と同じ流儀の Finding を返す(成功時とすでに 1 のときは nil)。
	EnableIPForward(st *store.Store) *check.Finding
	// CheckConnectivity は wg 経由でエージェントのリスナーに TCP 接続する疎通確認(仕様 10.1 節)。
	CheckConnectivity(addr string) conncheck.Result
}

// kernelDataplane はカーネルの WireGuard と nftables と conntrack を使う転送面。
type kernelDataplane struct {
	iface string // wg インタフェース名(既定 wgft0)
}

func (k *kernelDataplane) EnsureWG(cfg wg.Config) ([]string, error) { return wg.Ensure(cfg) }
func (k *kernelDataplane) WGStatus() (*wgtypes.Device, error)       { return wg.Status(k.iface) }
func (k *kernelDataplane) OtherDeviceWithKey(key wgtypes.Key) (string, bool) {
	return wg.OtherDeviceWithKey(k.iface, key)
}
func (k *kernelDataplane) ReadUDPTimeouts() (wg.UDPTimeouts, error) { return wg.ReadUDPTimeouts() }
func (k *kernelDataplane) Inspect() (*check.Report, error)          { return check.Inspect(k.iface) }
func (k *kernelDataplane) BoundPorts() (check.Bound, error)         { return check.BoundPorts() }
func (k *kernelDataplane) InputPortSuggestions(port uint16) ([]string, error) {
	return check.InputPortSuggestions(port)
}
func (k *kernelDataplane) ReadDrops() ([]dataplane.Drop, error) {
	drops, err := nft.ReadDrops()
	if err != nil {
		return nil, err
	}
	out := make([]dataplane.Drop, len(drops))
	for i, d := range drops {
		out[i] = dataplane.Drop{RuleID: d.RuleID, Kind: d.Kind, Packets: d.Packets, Bytes: d.Bytes}
	}
	return out, nil
}

// participant は table inet wgft を Plan から組み立てる participant を返す(設計文書 7a.8 節 Phase 3)。
func (k *kernelDataplane) participant() dataplane.Participant {
	return kernelTable{k: k}
}

// kernelTable は、table inet wgft の 1 回の差し替えを Runtime の dataplane の participant にする。
type kernelTable struct{ k *kernelDataplane }

// Prepare は何も確保しない。nft.Apply が組み立てと差し替えを 1 回で行い、組み立ての失敗でも
// 差し替えの失敗でも何も公開しない(旧いテーブルのまま残る)ので、Commit だけで dataplane の
// Commit の契約を満たす(design.md 7a.2 節:kernel backend は一度の nftables トランザクションで
// 不可分に公開するので、これで Prepare/Commit の契約を満たす)。
func (t kernelTable) Prepare(d dataplane.Desired) (dataplane.Prepared, error) {
	return &kernelTablePrepared{t: t, desired: d}, nil
}

type kernelTablePrepared struct {
	t       kernelTable
	desired dataplane.Desired
}

func (p *kernelTablePrepared) Commit() error {
	return nft.Apply(p.desired.Plan, p.desired.RelayListening, nft.Config{WGInterface: p.t.k.iface})
}

// Rollback は何もしない。Prepare は何も確保せず、失敗した Commit は何も公開していない。
func (p *kernelTablePrepared) Rollback() {}
func (k *kernelDataplane) Converge(rules []ctconv.Rule, wgNet netip.Prefix, _ planner.Plan) (int, error) {
	return ctconv.Converge(rules, wgNet)
}
func (k *kernelDataplane) EnableIPForward(st *store.Store) *check.Finding { return EnableIPForward(st) }
func (k *kernelDataplane) CheckConnectivity(addr string) conncheck.Result {
	return conncheck.Check(addr, conncheck.Options{})
}
