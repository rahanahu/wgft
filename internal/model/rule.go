package model

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/rahanahu/wgft/proto"
)

// Rule はルール 1 本の正規化した内部表現(設計文書 7a.2 節)。外部契約である proto.Rule の
// VPSMode/ProxyProtocol を Forwarding/SourceMetadata の 2 つの軸へ写し、それ以外のフィールドは
// そのまま引き継ぐ。AdmissionPolicy(internal/policy)が使う送信元制限とレートも、正規化した
// ルールの一部としてここに残る。ルール集合から AdmissionPolicy の IR を組み立てるのは
// internal/policy の役目であり、Rule 自身は IR を持たない。
//
// Group と Note は転送には影響しない管理用のメタデータだが、外部形式との往復を無損失にするため
// (設計文書 7a.8 節 Phase 1 の完了条件)にここでも保つ。
type Rule struct {
	ID             string
	Agent          string
	Group          string
	Note           string
	Proto          proto.Proto
	ListenPort     proto.PortRange
	Target         string
	Forwarding     Forwarding
	SourceMetadata SourceMetadata
	SourceAllow    []netip.Prefix
	SourceDeny     []netip.Prefix
	NewFlowRate    *proto.Rate
	PacketRate     *proto.Rate
	PerSourceRate  *proto.Rate
	Enabled        bool
}

// FromProto は 1 本の proto.Rule を正規化する。呼び出し側は、構造的な検査(ポート範囲の重なり、
// 予約ポートなど)を NormalizeRules/NormalizeUpsert 経由で proto.ValidateRules/ValidateUpsert に
// 先に通す前提である。FromProto 自身は Forwarding/SourceMetadata への写像だけを検査する
// (proto.Rule.Validate の「proxy_protocol は vps_mode=proxy でしか立てられない」という検査と
// 同じ制約を、モデル側の語彙である Transparent + ProxyV2 の禁止として言い換える)。
func FromProto(r proto.Rule) (Rule, error) {
	fwd, meta, err := forwardingFromProto(r.VPSMode, r.ProxyProtocol)
	if err != nil {
		return Rule{}, fmt.Errorf("rule %s: %w", r.ID, err)
	}
	return Rule{
		ID: r.ID, Agent: r.Agent, Group: r.Group, Note: r.Note,
		Proto: r.Proto, ListenPort: r.ListenPort, Target: r.Target,
		Forwarding: fwd, SourceMetadata: meta,
		SourceAllow: r.SourceAllow, SourceDeny: r.SourceDeny,
		NewFlowRate: r.NewFlowRate, PacketRate: r.PacketRate, PerSourceRate: r.PerSourceRate,
		Enabled: r.Enabled,
	}, nil
}

// ToProto は正規化したルールを外部契約の proto.Rule へ書き戻す。FromProto の逆写像であり、
// 常に成功する(Rule は既に有効な組み合わせしか表せないため)。
func (r Rule) ToProto() proto.Rule {
	mode, proxyProtocol := protoForwarding(r.Forwarding, r.SourceMetadata)
	return proto.Rule{
		ID: r.ID, Agent: r.Agent, Group: r.Group, Note: r.Note,
		Proto: r.Proto, ListenPort: r.ListenPort, Target: r.Target,
		VPSMode: mode, ProxyProtocol: proxyProtocol,
		SourceAllow: r.SourceAllow, SourceDeny: r.SourceDeny,
		NewFlowRate: r.NewFlowRate, PacketRate: r.PacketRate, PerSourceRate: r.PerSourceRate,
		Enabled: r.Enabled,
	}
}

// forwardingFromProto は vps_mode/proxy_protocol を Forwarding/SourceMetadata へ写す
// (設計文書 7a.2 節の表)。
//
//	vps_mode=kernel, proxy_protocol=false -> Transparent, NoSourceMetadata
//	vps_mode=proxy,  proxy_protocol=false -> Relay,       NoSourceMetadata
//	vps_mode=proxy,  proxy_protocol=true  -> Relay,       ProxyV2
//	vps_mode=kernel, proxy_protocol=true  -> 無効(Transparent + ProxyV2 は禁止の組み合わせ)
func forwardingFromProto(mode proto.VPSMode, proxyProtocol bool) (Forwarding, SourceMetadata, error) {
	switch mode {
	case proto.ModeKernel:
		if proxyProtocol {
			return 0, 0, errors.New("proxy_protocol can only be enabled when vps_mode=proxy")
		}
		return Transparent, NoSourceMetadata, nil
	case proto.ModeProxy:
		if proxyProtocol {
			return Relay, ProxyV2, nil
		}
		return Relay, NoSourceMetadata, nil
	default:
		return 0, 0, fmt.Errorf("vps_mode %q is neither kernel nor proxy", mode)
	}
}

// protoForwarding は forwardingFromProto の逆写像。Relay + ProxyV2 だけが proxy_protocol=true になる。
func protoForwarding(f Forwarding, m SourceMetadata) (proto.VPSMode, bool) {
	if f == Relay {
		return proto.ModeProxy, m == ProxyV2
	}
	return proto.ModeKernel, false
}

// NormalizeRules は proto.ValidateRules で構造を検査してから、外部のルール集合を正規化する
// (設計文書 5.3、7a.2 節)。検査の実装は proto パッケージのものをそのまま呼ぶ(重複させない)。
func NormalizeRules(rules []proto.Rule, reserved proto.Reserved) ([]Rule, error) {
	if err := proto.ValidateRules(rules, reserved); err != nil {
		return nil, err
	}
	return fromProtoAll(rules)
}

// NormalizeUpsert は proto.ValidateUpsert で検査してから正規化する。before と ID・内容が変わらない
// 行には Rule.Validate を掛け直さない規則(設計文書 5.4 節)を、そのまま proto.ValidateUpsert から引き継ぐ。
func NormalizeUpsert(rules, before []proto.Rule, reserved proto.Reserved) ([]Rule, error) {
	if err := proto.ValidateUpsert(rules, before, reserved); err != nil {
		return nil, err
	}
	return fromProtoAll(rules)
}

func fromProtoAll(rules []proto.Rule) ([]Rule, error) {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		m, err := FromProto(r)
		if err != nil {
			return nil, err
		}
		out[i] = m
	}
	return out, nil
}

// ToProtoRules は正規化したルール集合を外部契約へ書き戻す(NormalizeRules/NormalizeUpsert の逆写像)。
// ルールの並び順は保つ。
func ToProtoRules(rules []Rule) []proto.Rule {
	out := make([]proto.Rule, len(rules))
	for i, r := range rules {
		out[i] = r.ToProto()
	}
	return out
}
