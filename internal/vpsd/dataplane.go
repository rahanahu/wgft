package vpsd

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/vpsd/conncheck"
	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// serverDataplane は VPS 側の転送面を Daemon から見た形。Daemon がカーネルや外部の状態を触るときは、
// 必ずここを通る。実装は 2 つある。kernelDataplane は internal/dataplane/linuxkernel.Backend を
// 包むだけの薄い層で、他テーブルの検査や ip_forward のような、Backend の役目ではない host 側の
// 検査(internal/platform/linux)を受け持つ(design.md 7a.7、7a.8 節 Phase 3)。userspaceDataplane
// (仕様 6.3 節)は internal/dataplane/userspace の Backend を包む、同じ形の薄い層である。
//
// 両方の Backend が dataplane.Backend(EnsureWG、WGStatus、Converge、ReadDrops、Dial、Participant)
// を実装するので、このインタフェースのその部分はほぼ素通しになる。それ以外のメソッド
// (OtherDeviceWithKey、ReadUDPTimeouts、Inspect、BoundPorts、InputPortSuggestions、EnableIPForward、
// CheckConnectivity)は、Backend の外の host 側検査や vpsd の都合(store への記録)を持つので、
// dataplane.Backend には無い。
type serverDataplane interface {
	// EnsureWG は wg インタフェースを宣言(鍵、ポート、アドレス、MTU、ピア集合)に収束させ、行った変更を返す(仕様 9 節)。
	EnsureWG(cfg dataplane.WGConfig) ([]string, error)
	// WGStatus は wg インタフェースの現在のピア(エンドポイント、最終ハンドシェイク)を返す。
	WGStatus() (*wgtypes.Device, error)
	// OtherDeviceWithKey は同じサーバ鍵を持つ別名の WireGuard デバイスがあればその名前を返す(インタフェース名の変更の検出)。
	OtherDeviceWithKey(key wgtypes.Key) (string, bool)
	// ReadUDPTimeouts は conntrack の UDP タイムアウト 2 値を読む(全体状態でエージェントに配る。仕様 4 節)。
	ReadUDPTimeouts() (linux.UDPTimeouts, error)
	// Inspect は他テーブルの forward / input / DNAT の検査(仕様 6.1 節)。起動時と rule add 時に使う。
	Inspect() (*linux.Report, error)
	// BoundPorts は VPS 上で bind 中のポート(SSH の締め出しを防ぐ検査。仕様 5.3 節)。
	BoundPorts() (linux.Bound, error)
	// InputPortSuggestions は、プロキシモードの公開ポートが input で塞がれていれば足す行を返す(仕様 6.2 節)。
	InputPortSuggestions(port uint16) ([]string, error)
	// ReadDrops は差し替え直前の drop カウンタを読む(仕様 6.1 節)。
	ReadDrops() ([]dataplane.Drop, error)
	// participant は、Runtime の dataplane の participant を返す(設計文書 7a.2 節)。その Commit が転送の
	// 宣言を 1 回で公開する(カーネルでは table inet wgft の 1 トランザクションの差し替え。仕様 6.1 節)。
	// 組み立ての元になる Plan は Runtime.Apply が dataplane.Desired 経由で渡す
	participant() dataplane.Participant
	// Converge は外から入った進行中のフローを Plan に収束させ、消した数を返す(仕様 6.1、6.3 節)。
	Converge(plan planner.Plan) (int, error)
	// EnableIPForward は net.ipv4.ip_forward を 1 にする(仕様 6.1 節)。
	// 書き込みに失敗すると、policy drop と同じ流儀の Finding を返す(成功時とすでに 1 のときは nil)。
	EnableIPForward(st *store.Store) *linux.Finding
	// CheckConnectivity は wg 経由でエージェントのリスナーに TCP 接続する疎通確認(仕様 10.1 節)。
	CheckConnectivity(addr string) conncheck.Result
}

// kernelDataplane はカーネルの WireGuard と nftables と conntrack を使う転送面。実際の収束と適用は
// internal/dataplane/linuxkernel.Backend が持ち、ここは host 側の検査(internal/platform/linux)を
// 添えるだけの薄い層である(design.md 7a.8 節 Phase 3)。
type kernelDataplane struct {
	iface string // wg インタフェース名(既定 wgft0)。Inspect/BoundPorts/InputPortSuggestions が使う
	b     *linuxkernel.Backend
}

func (k *kernelDataplane) EnsureWG(cfg dataplane.WGConfig) ([]string, error) {
	return k.b.EnsureWG(cfg)
}
func (k *kernelDataplane) WGStatus() (*wgtypes.Device, error) { return k.b.WGStatus() }
func (k *kernelDataplane) OtherDeviceWithKey(key wgtypes.Key) (string, bool) {
	return k.b.OtherDeviceWithKey(key)
}
func (k *kernelDataplane) ReadUDPTimeouts() (linux.UDPTimeouts, error) {
	return linux.ReadUDPTimeouts()
}
func (k *kernelDataplane) Inspect() (*linux.Report, error) {
	return linux.Inspect(k.iface, nft.TableName)
}
func (k *kernelDataplane) BoundPorts() (linux.Bound, error) { return linux.BoundPorts() }
func (k *kernelDataplane) InputPortSuggestions(port uint16) ([]string, error) {
	return linux.InputPortSuggestions(port, nft.TableName)
}
func (k *kernelDataplane) ReadDrops() ([]dataplane.Drop, error)           { return k.b.ReadDrops() }
func (k *kernelDataplane) participant() dataplane.Participant             { return k.b }
func (k *kernelDataplane) Converge(plan planner.Plan) (int, error)        { return k.b.Converge(plan) }
func (k *kernelDataplane) EnableIPForward(st *store.Store) *linux.Finding { return EnableIPForward(st) }
func (k *kernelDataplane) CheckConnectivity(addr string) conncheck.Result {
	return conncheck.Check(addr, conncheck.Options{})
}
