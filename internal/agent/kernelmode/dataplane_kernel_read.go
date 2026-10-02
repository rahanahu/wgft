//go:build linux

package kernelmode

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/proto"
)

// Read はインタフェースとルールの状態を 1 回ずつ読む(10.2c 節)。
func (d *Dataplane) Read() agentdp.Reading {
	var r agentdp.Reading
	if !d.have {
		return r
	}
	prev, _ := d.f.PreviousKey()
	st, err := d.Ops.InspectLink(d.iface, d.Priv, prev)
	switch {
	case err != nil:
		r.Tunnel = agentdp.TunnelReading{Present: d.converged, Err: fmt.Errorf("read %s: %w", d.iface, err)}
	case st.Exists && st.Ownership.Ours():
		r.Tunnel.Present = true
		for _, p := range st.Peers {
			r.Tunnel.Endpoint = p.Endpoint
			r.Tunnel.LastHandshake = p.LastHandshake
			r.Tunnel.RxBytes, r.Tunnel.TxBytes = p.ReceiveBytes, p.TransmitBytes
		}
		d.epMu.Lock()
		epErr := d.endpointEr
		d.epMu.Unlock()
		if !r.Tunnel.Endpoint.IsValid() && epErr != nil {
			r.Tunnel.Err = fmt.Errorf("endpoint %s: %w", d.WG.Endpoint, epErr)
		}
	}
	if d.Pub != nil {
		r.Rules = d.ruleStatuses()
	}
	return r
}

// ruleStatuses は公開の記録からルールごとの状態を作る(5.2・7b.3 節)。公開の記録の理由、試し接続の
// 誤り、ip_forward の順に見る。理由を持っていても DNAT を公開したルール(直前の解決の結果で転送を
// 続けているルールと、範囲の一部のポートだけを公開したルール)は、後ろの 2 つの誤りも理由に続ける
// (7b.2 節)。直前のアドレスの宛先が応えないことを、理由の先頭の文言が隠さないようにするためである。
// server doctor は、直前の解決の結果で転送を続けている文言の後ろの残りでこのルールの宛先を判定する
// (10.2a 節、internal/vpsd/doctor の StaleResolution)。
func (d *Dataplane) ruleStatuses() []proto.RuleStatus {
	out := make([]proto.RuleStatus, 0, len(d.Pub.Rules))
	for _, r := range d.Pub.Rules {
		s := proto.RuleStatus{ID: r.RuleID, State: proto.StatusOK}
		var parts []string
		if r.Reason != "" {
			parts = append(parts, r.Reason)
		}
		if len(r.Ranges) > 0 {
			if e := d.probeErr[r.RuleID]; e != "" {
				parts = append(parts, e)
			}
			if d.forwardErr != nil && !d.allLocal(r) {
				// 理由は server の診断、`status`、`agent ls`、Web UI で VPS の上で読まれる。「このホスト」と
				// 書くと VPS と読めるので、エージェントのホストであることを名指す(設計文書 10.2a 節)。
				parts = append(parts, "on the agent host, "+d.forwardErr.Error()+"; its kernel does not forward to a target other than the agent host itself")
			}
		}
		if len(parts) > 0 {
			s.State, s.Reason = proto.StatusError, strings.Join(parts, "; ")
		}
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (d *Dataplane) allLocal(r nft.AgentRuleResult) bool {
	for _, rg := range r.Ranges {
		if !d.local[rg.Dest.Addr()] {
			return false
		}
	}
	return len(r.Ranges) > 0
}

// DoctorKernel は agent doctor のためにカーネルを読む(設計文書 10.2c 節)。停止中の agent doctor と同じ
// readKernel を、メモリの上の認証情報ファイルと公開の記録で呼ぶ。記録は公開に成功するたびに d.f に
// 写すので、d.pub と同じ中身である。
func (d *Dataplane) DoctorKernel() *controlapi.DoctorKernel {
	return readKernel(kernelReadInput{iface: d.iface, creds: d.f, pub: d.f.KernelPublication})
}

func (d *Dataplane) CheckError() string { return d.ObserveErr }
