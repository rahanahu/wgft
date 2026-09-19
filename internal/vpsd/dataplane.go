package vpsd

import (
	"log"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/vpsd/check"
	"github.com/rahanahu/wgft/internal/vpsd/conncheck"
	ctconv "github.com/rahanahu/wgft/internal/vpsd/conntrack"
	"github.com/rahanahu/wgft/internal/vpsd/nft"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/wg"
	"github.com/rahanahu/wgft/proto"
)

// dataplane は VPS 側の転送面。Daemon がカーネルや外部の状態を触るときは、必ずここを通る。
// 唯一の実装は kernelDataplane(nftables の DNAT とカーネル WireGuard、仕様 6.1 節)で、
// ユーザー空間モード(仕様 13 節)はこの後ろに wireguard-go と netstack の実装を並べる。
// メソッドの形はいまのカーネル実装の型(wg.Config、check.Report など)をそのまま出しており、
// ユーザー空間実装を足すときに、両方に共通する形へ整える。
type dataplane interface {
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
	ReadDrops() ([]nft.Drop, error)
	// ApplyNFT はルール集合から table inet wgft を組み立て、1 トランザクションで差し替える(仕様 6.1 節)。
	ApplyNFT(rules []proto.Rule, agentAddr map[string]netip.Addr) error
	// Converge は外から入って DNAT されたフローを宣言に収束させ、消した数を返す(仕様 6.1 節)。
	Converge(rules []ctconv.Rule, wgNet netip.Prefix) (int, error)
	// EnableIPForward は net.ipv4.ip_forward を 1 にする(仕様 6.1 節)。
	// 書き込みに失敗すると、policy drop と同じ流儀の Finding を返す(成功時とすでに 1 のときは nil)。
	EnableIPForward(st *store.Store) *check.Finding
	// CheckConnectivity は wg 経由でエージェントのリスナーに TCP 接続する疎通確認(仕様 10.1 節)。
	CheckConnectivity(addr string) conncheck.Result
}

// kernelDataplane はカーネルの WireGuard と nftables と conntrack を使う転送面。
type kernelDataplane struct {
	iface string // wg インタフェース名(既定 wgft0)
	// udpPerSourceCap と tcpPerSourceCap は接続元 IP ごとの同時フロー数の上限(仕様 7, 11a 節)。
	// 0 はそのプロトコルの上限を無効にする
	udpPerSourceCap int
	tcpPerSourceCap int
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
func (k *kernelDataplane) ReadDrops() ([]nft.Drop, error) { return nft.ReadDrops() }
func (k *kernelDataplane) ApplyNFT(rules []proto.Rule, agentAddr map[string]netip.Addr) error {
	return nft.Apply(rules, nft.Config{
		WGInterface: k.iface, AgentAddr: agentAddr, Logf: log.Printf,
		UDPPerSourceCap: k.udpPerSourceCap, TCPPerSourceCap: k.tcpPerSourceCap,
	})
}
func (k *kernelDataplane) Converge(rules []ctconv.Rule, wgNet netip.Prefix) (int, error) {
	return ctconv.Converge(rules, wgNet)
}
func (k *kernelDataplane) EnableIPForward(st *store.Store) *check.Finding { return EnableIPForward(st) }
func (k *kernelDataplane) CheckConnectivity(addr string) conncheck.Result {
	return conncheck.Check(addr, conncheck.Options{})
}
