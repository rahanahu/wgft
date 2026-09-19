package vpsd

// ユーザー空間モードの転送面(仕様 6.3 節)を Daemon に見せる薄い層。転送そのもの(wireguard-go と
// netstack のトンネル、中継、接続元制限とレート制限の評価器)は internal/dataplane/userspace の
// Backend が持ち、ここは Daemon の serverDataplane の形に合わせることと、ユーザー空間モードでは
// 何もしないホスト側の検査(他テーブル、bind 中のポート、ip_forward)だけを受け持つ。

import (
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/userspace"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/vpsd/conncheck"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// userspaceDataplane はユーザー空間モードの転送面。
type userspaceDataplane struct {
	b *userspace.Backend
}

// EnsureDevice は Backend にそのまま渡す。インタフェース名と AdoptExisting はカーネルの wg
// インタフェースだけの性質で、dataplane.WGConfig には無い(その doc コメントのとおり)。
func (u *userspaceDataplane) EnsureDevice(cfg dataplane.WGConfig) ([]string, error) {
	return u.b.EnsureDevice(cfg)
}

func (u *userspaceDataplane) WGStatus() (*wgtypes.Device, error) { return u.b.WGStatus() }

func (u *userspaceDataplane) OtherDeviceWithKey(wgtypes.Key) (string, bool) { return "", false }

// ReadUDPTimeouts はカーネルの conntrack を使わないので、既定値をそのまま配る(エージェントの UDP セッションの期限)。
func (u *userspaceDataplane) ReadUDPTimeouts() (linux.UDPTimeouts, error) {
	return linux.UDPTimeouts{Timeout: 30, TimeoutStream: 120}, nil
}

// Inspect は他テーブルの検査を行わない(nftables を使わない。仕様 6.3 節)。
func (u *userspaceDataplane) Inspect() (*linux.Report, error) { return &linux.Report{}, nil }

// BoundPorts は空。bind の失敗がそのまま分かる(仕様 6.3 節)。
func (u *userspaceDataplane) BoundPorts() (linux.Bound, error) {
	return linux.Bound{proto.TCP: {}, proto.UDP: {}}, nil
}

// InputPortSuggestions は input が policy drop なら足す行を返す。nftables を読めない(非 root)ときは提示しない。
// userspace モードは自分の nftables テーブルを作らないが、kernel モードから切り替えた後に残った
// table inet wgft を他人のファイアウォールと取り違えないよう、kernel モードと同じく検査から除く。
// host の input firewall はモードに関係しない層なので、userspace モードでも同じ検査を行う(仕様 6.3 節)
func (u *userspaceDataplane) InputPortSuggestions(pr proto.PortRange, p proto.Proto) ([]string, error) {
	lines, err := linux.InputPortSuggestions(pr, p, nft.TableName)
	if err != nil {
		return nil, nil
	}
	return lines, nil
}

// participant は Backend そのもの。Backend は Plan だけから組み立てる。
// プロキシモード(Relay)のルールは Daemon の proxyrelay が受け持ち、Backend は Transparent のルールだけを開く。
func (u *userspaceDataplane) participant() dataplane.Participant {
	return u.b
}

func (u *userspaceDataplane) EnableIPForward(*store.Store) *linux.Finding { return nil }

// ConntrackWarning は空文字を返す。ユーザー空間モードはカーネルの conntrack を使わないので、
// nf_conntrack_max の大小に意味が無い(仕様 6.3 節)。
func (u *userspaceDataplane) ConntrackWarning() string { return "" }

func (u *userspaceDataplane) CheckConnectivity(addr string) conncheck.Result {
	return conncheck.Check(addr, conncheck.Options{Dial: u.b.Dial})
}
