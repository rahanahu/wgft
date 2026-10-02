// Package kernelmode はエージェントのカーネルモードの dataplane を持つ(設計文書 7a.7 節)。
// internal/dataplane/linuxkernel の部品で、カーネルの WireGuard インタフェースと table inet wgft_agent を
// 宣言へ収束させ、internal/agent/agentdp の Dataplane を満たす。停止中の agent doctor が読むカーネルの
// 読み取り ReadKernel も持ち、稼働中のエージェントも同じ読み方を使う。internal/agent の下では agentdp、
// allowtargets、credentials、controlapi だけを import する。カーネルモードは Linux だけにある。
//
// 本番のコードが package の外から使ってよい名前は New、Built、Prerequisites、ProcessNetAdmin、ReadKernel
// である。実行時の状態は New の結果を agentdp.Dataplane として持ち、型 Dataplane を名指さず、そのメソッドも
// 直接は呼ばない。ほかの公開した名前は internal/agent のテストのための口であり、型 Dataplane、その
// フィールド Ops、Priv、WG、Pub、ObserveErr とメソッド LinkConfig、関数 NewWithOps、型 Ops と DoctorOps と
// それぞれのフィールド、変数 DoctorKernelOps、定数 MaxUnconverged が当たる。
// internal/dataplane/deps_test.go の TestAgentModeTestSeamsStayInTests がこれを検査する。
package kernelmode

import (
	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// maxKernelItems は、Missing と Unexpected に並べる項目の数の上限である。範囲の広いルールや外から
// 加えた多数の行で、応答が大きくなりすぎないようにする。
const maxKernelItems = 8

// ReadKernel は、止まっているエージェントのカーネルの状態を、認証情報ファイル f と WireGuard
// インタフェースの名前 iface から直接読む(設計文書 10.2c 節)。稼働中のエージェントも同じ読み方を
// 使う。カーネルに何も書かない。
func ReadKernel(f *credentials.Credentials, iface string) *controlapi.DoctorKernel {
	return readKernel(kernelReadInput{iface: iface, creds: f, pub: f.KernelPublication})
}
