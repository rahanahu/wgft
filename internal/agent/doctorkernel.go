package agent

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
