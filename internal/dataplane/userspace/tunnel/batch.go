package tunnel

import (
	"math/bits"
	"runtime"

	"golang.zx2c4.com/wireguard/device"

	"github.com/rahanahu/wgft/internal/wgstack"
)

// 送信の向きのバッチの大きさ(設計文書 wgstack-batching.md の「wireguard-go の滞留の上界」と「P_max の
// 決め方」)。wireguard-go の定数を読むのはこの package だけで、wgstack はここが渡す値で門を作る。依存の
// 値の前提は batch_test.go が確かめる。

// sendBatchSize は wgstack の Device の k_tx(BatchSize)。wgstack.MaxSendBatch 以下である。
const sendBatchSize = 32

// sendBatchCallers は C で、同じピアについて SendStagedPackets を同時に動かしうる呼び出しの数である。
// TUN の読み取り、ピアの受信の goroutine、ハンドシェイクの処理の goroutine(device を作る時の
// runtime.NumCPU() の数)、ピアのタイマーの 2 つ、設定の処理、SendKeepalivesToPeersWithCurrentKeypair の
// 呼び出し側の和である。
func sendBatchCallers() int { return runtime.NumCPU() + 6 }

// sendBatchSingles は N_tx で、送信の向きに滞留しうる入れ物の数である。送信のキュー、staged のキュー、
// 送信の goroutine が持つ 1 個、C 個の呼び出しが 1 つずつ持つ分の和である。
func sendBatchSingles() int {
	return device.QueueOutboundSize + device.QueueStagedSize + 1 + sendBatchCallers()
}

// SendBatchCap は P_upper = N_tx × k_tx で、すべての入れ物が k_tx 個を持っても門が閉じない予算である。
// これより大きな予算は P_upper と同じなので、設定の値はここで丸める。
func SendBatchCap() int { return sendBatchSingles() * sendBatchSize }

// SendBatchBufferBytes は S で、wireguard-go の buffer 1 つがヒープに持つ大きさである。MaxMessageSize
// (Linux と macOS で 65,535 byte、Windows で 2,016 byte)をヒープの区分の 64 KiB と 2 KiB に切り上げる。
func SendBatchBufferBytes() int64 { return 1 << bits.Len(uint(device.MaxMessageSize-1)) }

// sendBatchConfig は P_max が packets の wgstack の Device の送信の向きのバッチの設定である。packets が 0
// ならバッチを使わない。
func sendBatchConfig(packets int) wgstack.SendBatch {
	if packets <= 0 {
		return wgstack.SendBatch{}
	}
	return wgstack.SendBatch{
		Packets:    min(packets, SendBatchCap()),
		Size:       sendBatchSize,
		Callers:    sendBatchCallers(),
		BufferSize: device.MaxMessageSize,
	}
}
