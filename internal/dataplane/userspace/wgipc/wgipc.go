// Package wgipc は、wireguard-go の device の IpcGet が返す設定の文字列(UAPI の get の応答)を
// 読む。エージェントのトンネル(internal/dataplane/userspace/tunnel)、`vpsd` のユーザー空間モードの
// トンネル(internal/dataplane/userspace/utun)、ソケットのバッファの測定
// (internal/dataplane/userspace/sockbuf)が、同じ鍵の名前と同じ読み方を共有する。
package wgipc

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Peer は IpcGet から読んだ 1 つのピアの状態。カーネルモードの wgtypes.Peer に相当する。
type Peer struct {
	PublicKey     wgtypes.Key
	Endpoint      netip.AddrPort // 未確立ならゼロ値
	LastHandshake time.Time      // ゼロなら未確立
	RxBytes       int64
	TxBytes       int64
}

// ListenPort は、IpcGet の出力から listen_port の値を取り出す。
func ListenPort(ipcGet string) (uint16, error) {
	for _, line := range strings.Split(ipcGet, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || k != "listen_port" {
			continue
		}
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("parse listen_port %q: %w", v, err)
		}
		return uint16(n), nil
	}
	return 0, fmt.Errorf("IpcGet output has no listen_port line")
}

// Peers は、IpcGet の出力をピアの公開鍵ごとの状態にする。ピアの節は public_key の行で始まる。
// 公開鍵として読めない public_key の行に続く節と、最初の public_key の行より前の行は読まない。
// 値の読めない行はその項目をゼロ値のまま残す。
func Peers(ipcGet string) map[wgtypes.Key]Peer {
	res := map[wgtypes.Key]Peer{}
	var cur *Peer
	flush := func() {
		if cur != nil {
			res[cur.PublicKey] = *cur
		}
	}
	for _, line := range strings.Split(ipcGet, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "public_key":
			flush()
			raw, err := hex.DecodeString(v)
			if err != nil || len(raw) != wgtypes.KeyLen {
				cur = nil
				continue
			}
			var key wgtypes.Key
			copy(key[:], raw)
			cur = &Peer{PublicKey: key}
		case "endpoint":
			if cur != nil {
				if ap, err := netip.ParseAddrPort(v); err == nil {
					cur.Endpoint = ap
				}
			}
		case "last_handshake_time_sec":
			if cur != nil {
				if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
					cur.LastHandshake = time.Unix(n, 0)
				}
			}
		case "rx_bytes":
			if cur != nil {
				cur.RxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		case "tx_bytes":
			if cur != nil {
				cur.TxBytes, _ = strconv.ParseInt(v, 10, 64)
			}
		}
	}
	flush()
	return res
}
