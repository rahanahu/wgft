//go:build linux

package vpsd

import (
	"fmt"
	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func serverKey(st *store.Store) (wgtypes.Key, error) {
	b, err := st.GetOrCreateMeta(store.MetaServerKey, func() ([]byte, error) {
		k, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		log.Printf("generated the WireGuard server key; public key %s", k.PublicKey())
		return k[:], nil
	})
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("server key: %w", err)
	}
	return wgtypes.NewKey(b)
}

// readKernel は稼働カーネルのバージョン(表示用)。
func readKernel() string {
	b, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// readNFTVersion は nft のバージョン(表示用)。取れなければ空。
func readNFTVersion() string {
	out, err := exec.Command("nft", "--version").Output()
	if err != nil {
		return ""
	}
	if f := strings.Fields(strings.TrimSpace(string(out))); len(f) >= 2 {
		return f[1] // "nftables v1.1.6 (...)" → v1.1.6
	}
	return strings.TrimSpace(string(out))
}

// EnableIPForward は net.ipv4.ip_forward を確認し、1 でなければ 1 にする(仕様 6.1 節)。実際の
// 読み書きは internal/platform/linux の ReadIPForward と WriteIPForward が持つ(agent の kernel backend
// も同じ部品を使う。設計文書 7a.7 節)。すでに 1 なら何も書かない。書けなくても落ちず、警告して続ける。
// 1 にした値は 0 に戻さない。0 を読んで 1 にするときは、撤去(teardown)が戻す候補として示せるよう、
// meta に 2 段の記録を残す(この記録は store を知らない platform/linux の役目ではなく、ここで行う)。
// 書き込みに失敗したときと、変えたことをどちらの段でも記録できなかったときは、他テーブルの policy drop
// と同じ流儀の Finding を返す。呼び出し側(Run)がそれをログに出す。それ以外は nil を返す。
func EnableIPForward(st *store.Store) *linux.Finding {
	return enableIPForward(defaultIPForwardOps(), st)
}

// ipForwardRecords は、ip_forward の 2 段の記録を保存するサーバのデータベースの操作である。
// *store.Store が満たす。単体テストだけが失敗を差し込む。
type ipForwardRecords interface {
	SetMeta(key string, value []byte) error
	DeleteMeta(key string) error
	SetMetaAndDelete(key string, value []byte, del string) error
}

// ipForwardOps は、enableIPForward が触れるカーネルの値と時計である。単体テストだけが差し替える。
type ipForwardOps struct {
	read  func() (on bool, err error)
	write func() error
	now   func() time.Time
}

func defaultIPForwardOps() ipForwardOps {
	return ipForwardOps{read: linux.ReadIPForward, write: linux.WriteIPForward, now: time.Now}
}

// enableIPForward は EnableIPForward の本体である。記録は 2 段にする(設計文書 6.1 節、
// 2026-10-03、所有者の決定)。
//
//  1. 値を読む。1 なら何もしない。前の起動の予定の記録が残っていても消さない
//  2. 読めなければ 1 を書き、どちらの記録も残さない。0 だったとは言えないためである。書けなければ、0 とは
//     言わない Finding を返す
//  3. 0 なら、書く前に予定の記録(MetaIPForwardWriteStartedAt)を保存する。保存できなくても警告して書く。
//     転送が落ちたままになるほうが悪いためである(11b 節)
//  4. 書けなければ予定の記録を消し、書けなかった Finding を返す
//  5. 書けたら、確定の記録(MetaIPForwardSetAt)の保存と予定の記録の削除を 1 つのトランザクションで行う
//
// 書いた直後に止まった場合と 5 の失敗では予定の記録だけが残り、撤去は「wgft が変えたかもしれない」と
// 示す。どちらの記録も残らないのは 3 と 5 の両方が失敗した場合だけで、そのときは Finding で知らせる。
func enableIPForward(o ipForwardOps, rec ipForwardRecords) *linux.Finding {
	on, rerr := o.read()
	if rerr == nil && on {
		return nil // すでに 1。触らない
	}
	if rerr != nil {
		if err := o.write(); err != nil {
			return ipForwardUnreadableAndUnwritable(rerr, err)
		}
		return nil
	}
	plannedErr := rec.SetMeta(store.MetaIPForwardWriteStartedAt, []byte(o.now().UTC().Format(time.RFC3339)))
	if plannedErr != nil {
		// 書いた直後に止まっても手掛かりが残るよう、書く前にログへ出す
		log.Printf("warning: recording that wgft read net.ipv4.ip_forward as 0 and is about to set it to 1 failed: %v; setting it anyway; unless the change is recorded after the write, a later `wgft server teardown` may not know that wgft changed it", plannedErr)
	}
	if err := o.write(); err != nil {
		// 0 のままなので、予定の記録は撤去に何も示さない。消せなくても、撤去は今の値の 0 を添えて示す
		if plannedErr == nil {
			if derr := rec.DeleteMeta(store.MetaIPForwardWriteStartedAt); derr != nil {
				log.Printf("warning: removing the record that wgft was about to set net.ipv4.ip_forward failed: %v; a later `wgft server teardown` will say wgft may have changed it", derr)
			}
		}
		return ipForwardWriteFailed(err)
	}
	log.Printf("set net.ipv4.ip_forward to 1")
	at := o.now().UTC().Format(time.RFC3339)
	if err := rec.SetMetaAndDelete(store.MetaIPForwardSetAt, []byte(at), store.MetaIPForwardWriteStartedAt); err != nil {
		if plannedErr != nil {
			return &linux.Finding{
				Where:   "net.ipv4.ip_forward",
				Problem: fmt.Sprintf("wgft set it from 0 to 1 at %s, but recording that failed both before the write: %v, and after it: %v; a later `wgft server teardown` may not know that wgft changed it, so restore it by hand when removing wgft if nothing else uses forwarding", at, plannedErr, err),
			}
		}
		log.Printf("warning: recording that wgft set net.ipv4.ip_forward to 1 failed: %v; a later `wgft server teardown` will say wgft may have changed it", err)
	}
	return nil
}

// ipForwardUnreadableAndUnwritable は、値を読めず、1 も書けなかったときの Finding である。値を読めて
// いないので、0 だったとは言わない。読みと書きの両方の誤りを示し、確かめ方と直し方を案内する。
func ipForwardUnreadableAndUnwritable(readErr, writeErr error) *linux.Finding {
	return &linux.Finding{
		Where: "net.ipv4.ip_forward",
		Problem: fmt.Sprintf("could not be read: %v; setting it to 1 failed too: %v; its value is unknown, so kernel-mode forwarding may not work. "+
			"Read the value with the first command below; if it reads 0, set it with the second", readErr, writeErr),
		Suggest: []string{"sysctl net.ipv4.ip_forward", "sysctl -w net.ipv4.ip_forward=1"},
	}
}

// ipForwardWriteFailed は、0 を読んだ後に 1 を書けなかったときの Finding である。読み取り専用の /proc や seccomp/LSM
// で塞がれている場合などに当たる。落とさず警告する。
func ipForwardWriteFailed(err error) *linux.Finding {
	return &linux.Finding{
		Where:   "net.ipv4.ip_forward",
		Problem: fmt.Sprintf("is 0 and could not be set to 1: %v; kernel-mode forwarding will not work until this is set", err),
		Suggest: []string{"sysctl -w net.ipv4.ip_forward=1"},
	}
}
