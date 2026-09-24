//go:build !linux

package agent

import "encoding/json"

// kernelReadInput は readKernel の材料である(doctorkernel_linux.go)。
type kernelReadInput struct {
	iface string
	creds interface{}
	pub   json.RawMessage
}

// readKernel は Linux の外ではカーネルを読まない。カーネルモードは Linux だけである(仕様 7b.5 節)。
// 読めなかったことを 3 つの面の読み取りの誤りとして返す。
func readKernel(in kernelReadInput) *DoctorKernel {
	const msg = "the agent's kernel mode exists only on Linux"
	return &DoctorKernel{
		Interface:  DoctorKernelInterface{Name: in.iface, ReadError: msg},
		Table:      DoctorKernelTable{ReadError: msg},
		Forwarding: DoctorKernelForwarding{IPForwardError: msg, PolicyError: msg},
	}
}

// processNetAdmin は Linux の外では値を持たない。
func processNetAdmin() *bool { return nil }
