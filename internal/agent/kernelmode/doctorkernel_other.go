//go:build !linux

package kernelmode

import (
	"encoding/json"

	"github.com/rahanahu/wgft/internal/agent/controlapi"
)

// kernelReadInput は readKernel の材料である(doctorkernel_linux.go)。
type kernelReadInput struct {
	iface string
	creds interface{}
	pub   json.RawMessage
}

// readKernel は Linux の外ではカーネルを読まない。カーネルモードは Linux だけである(仕様 7b.5 節)。
// 読めなかったことを 3 つの面の読み取りの誤りとして返す。
func readKernel(in kernelReadInput) *controlapi.DoctorKernel {
	const msg = "the agent's kernel mode exists only on Linux"
	return &controlapi.DoctorKernel{
		Interface:  controlapi.DoctorKernelInterface{Name: in.iface, ReadError: msg},
		Table:      controlapi.DoctorKernelTable{ReadError: msg},
		Forwarding: controlapi.DoctorKernelForwarding{IPForwardError: msg, PolicyError: msg},
	}
}

// ProcessNetAdmin は Linux の外では値を持たない。
func ProcessNetAdmin() *bool { return nil }
