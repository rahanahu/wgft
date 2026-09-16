package vpsd

import (
	"fmt"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func serverKey(st *store.Store) (wgtypes.Key, error) {
	b, err := st.GetOrCreateMeta(serverKeyMeta, func() ([]byte, error) {
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

// EnableIPForward は net.ipv4.ip_forward を確認し、1 でなければ 1 にする(仕様 6.1 節)。
// すでに 1 なら何も書かない。書けなくても落ちず、警告して続ける。1 にした値は 0 に戻さない。
// 0→1 にしたときは meta に日時を残し、撤去(teardown)で戻す候補として示せるようにする。
func EnableIPForward(st *store.Store) {
	const path = "/proc/sys/net/ipv4/ip_forward"
	if cur, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(cur)) == "1" {
		return // すでに 1。触らない
	}
	if err := os.WriteFile(path, []byte("1\n"), 0); err != nil {
		// 読み取り専用の /proc や seccomp/LSM で塞がれている場合など。落とさず警告する。
		log.Printf("warning: cannot set net.ipv4.ip_forward to 1 (%v); for kernel-mode forwarding you must run `sysctl -w net.ipv4.ip_forward=1` by hand", err)
		return
	}
	log.Printf("set net.ipv4.ip_forward to 1")
	_ = st.SetMeta(metaIPForwardSetAt, []byte(time.Now().UTC().Format(time.RFC3339)))
}
