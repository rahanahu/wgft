package proto

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ParseSplitPoint は分割位置の入力(CLI の引数、Web UI のフォーム値)を解釈する
// (仕様 10.1、10.2 節。CLI の `rule split` と Web UI の分割区画が共有する)。
// 解釈できないか、範囲でなく単一ポートでない入力は、どちらも同じ
// "split point must be a single port" で誤りとする(Rule.Split 自身の範囲外検査とは別に、
// 呼び出し側が Split を呼ぶ前に共通の形で弾む)。
func ParseSplitPoint(s string) (PortRange, error) {
	at, err := ParsePortRange(s)
	if err != nil || at.Lo != at.Hi {
		return PortRange{}, errors.New("split point must be a single port")
	}
	return at, nil
}

// Split は範囲の listen_port を持つルールを、ポート at の直前で 2 つに割る
// (仕様 10.1、10.2 節。CLI の `rule split` と Web UI の分割区画が共有する)。
// head は元の ID を保ち [Lo, at-1] を、tail は tailID を新たな ID として [at, Hi] を持つ。
// どちらの実効宛先も元のままなので(仕様 5.4、7 節)、通信中のセッションは切れない。
// at は単一ポートで、範囲の先頭を除く内側でなければならない。
// vps_mode=proxy のルールは単一ポート運用(Rule.Validate)なので、head・tail の両方が
// 単一ポートに収まる分割だけを受け付ける(2 ポートの範囲を境界で割る場合だけ両方が単一
// ポートになる)。3 ポート以上の proxy の範囲は、この関数を後から検査を増やす前に作られた
// 既存データとしてしか存在しえず、単発の分割では単一ポートまで割り切れないので拒否する。
// 直す手段は削除して単一ポートずつ作り直すことになる(改訂の記録参照)。
func (r Rule) Split(at PortRange, tailID string) (head, tail Rule, err error) {
	if at.Lo != at.Hi {
		return Rule{}, Rule{}, errors.New("split point must be a single port")
	}
	if at.Lo <= r.ListenPort.Lo || at.Lo > r.ListenPort.Hi {
		return Rule{}, Rule{}, fmt.Errorf("split point %d must be inside range %s, excluding the first port", at.Lo, r.ListenPort)
	}
	head = r
	head.ListenPort = PortRange{Lo: r.ListenPort.Lo, Hi: at.Lo - 1}
	tail = r
	tail.ID = tailID
	tail.ListenPort = PortRange{Lo: at.Lo, Hi: r.ListenPort.Hi}
	if r.VPSMode == ModeProxy && (head.ListenPort.IsRange() || tail.ListenPort.IsRange()) {
		return Rule{}, Rule{}, fmt.Errorf("split point %d would leave a vps_mode=proxy piece spanning a port range; delete and recreate the pieces as single ports instead", at.Lo)
	}
	// 後半の target は、元の target のポートに範囲内での位置を足したもの(実効宛先を変えない)
	eff, _ := r.ForAgent().EffectiveTarget(at.Lo)
	tail.Target = eff
	return head, tail, nil
}

// MergeBlocker はルール 2 つが統合できない理由の分類(仕様 10.1、10.2 節)。
// CLI の `rule merge` が失敗するときの判定と、Web UI の統合区画が候補に出さない
// 隣接ルールの理由を説明するのとで、同じ集合を共有する。
type MergeBlocker string

const (
	// BlockNone は理由が無い、つまり統合できることを表す。
	BlockNone        MergeBlocker = ""
	BlockAgent       MergeBlocker = "agent"
	BlockProto       MergeBlocker = "proto"
	BlockMode        MergeBlocker = "mode"
	BlockNotAdjacent MergeBlocker = "not_adjacent"
	BlockTargetGap   MergeBlocker = "target_gap"
	// BlockProxyRange は vps_mode=proxy の 2 つの統合を表す。統合は listen_port を必ず
	// 2 ポート以上の範囲に広げるため、proxy は単一ポート運用(Rule.Validate)の下では
	// 組み合わせを問わず常に統合できない(仕様 5.4、6.2 節)
	BlockProxyRange MergeBlocker = "proxy_range"
	// proxy_protocol は vps_mode=proxy でしか立てられない(Rule.Validate)ので、
	// 違いは BlockProxyRange で先に止まり、専用の理由は持たない
	BlockDenyList  MergeBlocker = "deny_list"
	BlockAllowList MergeBlocker = "allow_list"
	BlockRates     MergeBlocker = "rates"
	BlockEnabled   MergeBlocker = "enabled"
)

// FindMergeBlocker は a と b(順不同)が統合できない最初の理由を返す。すべて揃えば
// BlockNone(統合できる)を返す。listen_port が小さい方を lo、大きい方を hi として、
// エージェント、プロトコル、方式、隣接、実効宛先の連続、proxy かどうか、拒否/許可
// リスト、3 つのレート、enabled の順に見る。統合すると self の値だけが残るので、
// 拒否/許可リストから enabled までが揃わない組を統合すると、もう一方の設定が黙って
// 失われる。Merge も Web UI の候補の絞り込みも、この関数で同じ判定をする。
func FindMergeBlocker(a, b Rule) MergeBlocker {
	lo, hi := a, b
	if lo.ListenPort.Lo > hi.ListenPort.Lo {
		lo, hi = hi, lo
	}
	switch {
	case lo.Agent != hi.Agent:
		return BlockAgent
	case lo.Proto != hi.Proto:
		return BlockProto
	case lo.VPSMode != hi.VPSMode:
		return BlockMode
	case lo.ListenPort.Hi+1 != hi.ListenPort.Lo:
		return BlockNotAdjacent
	}
	if eff, ok := lo.ForAgent().EffectiveTarget(lo.ListenPort.Hi); !ok || eff == "" || nextPort(eff) != hi.Target {
		return BlockTargetGap
	}
	// mode は既に揃っている(上の switch)ので lo だけ見ればよい
	if lo.VPSMode == ModeProxy {
		return BlockProxyRange
	}
	switch {
	case !equalPrefixSet(lo.SourceDeny, hi.SourceDeny):
		return BlockDenyList
	case !equalPrefixSet(lo.SourceAllow, hi.SourceAllow):
		return BlockAllowList
	case !equalRate(lo.NewFlowRate, hi.NewFlowRate), !equalRate(lo.PacketRate, hi.PacketRate), !equalRate(lo.PerSourceRate, hi.PerSourceRate):
		return BlockRates
	case lo.Enabled != hi.Enabled:
		return BlockEnabled
	}
	return BlockNone
}

// errText は CLI の `rule merge` が返す誤りの本文(英語。仕様の約束によりツール出力は
// 英語のみ)。
func (b MergeBlocker) errText() string {
	switch b {
	case BlockAgent:
		return "rules must share the same agent"
	case BlockProto:
		return "rules must share the same protocol"
	case BlockMode:
		return "rules must share the same mode"
	case BlockNotAdjacent:
		return "listen ranges are not adjacent"
	case BlockTargetGap:
		return "effective targets are not contiguous"
	case BlockProxyRange:
		return "vps_mode=proxy rules cannot be merged into a port range"
	case BlockDenyList:
		return "deny list differs"
	case BlockAllowList:
		return "allow list differs"
	case BlockRates:
		return "rate limits differ"
	case BlockEnabled:
		return "enabled state differs"
	default:
		return "cannot merge"
	}
}

// Merge は self と other を 1 つに統合する(仕様 10.1、10.2 節。CLI の `rule merge
// <id1> <id2>` と Web UI の統合区画が共有する)。self の ID・group・note・拒否/許可
// リスト・レート・enabled をそのまま残し、listen_port と実効宛先だけを other の分を
// 含むように広げる。other は呼び出し側がバッチで削除する。FindMergeBlocker が
// BlockNone を返す組み合わせでなければ誤りを返す。
func Merge(self, other Rule) (merged Rule, err error) {
	if blk := FindMergeBlocker(self, other); blk != BlockNone {
		return Rule{}, fmt.Errorf("cannot merge: %s", blk.errText())
	}
	lo, hi := self, other
	if lo.ListenPort.Lo > hi.ListenPort.Lo {
		lo, hi = hi, lo
	}
	merged = self
	merged.ListenPort = PortRange{Lo: lo.ListenPort.Lo, Hi: hi.ListenPort.Hi}
	merged.Target = lo.Target
	return merged, nil
}

// nextPort は host:port の port を 1 つ進める(Merge と FindMergeBlocker が実効宛先の
// 連続を見るために使う)。
func nextPort(hostport string) string {
	i := strings.LastIndex(hostport, ":")
	if i < 0 {
		return hostport
	}
	var p int
	fmt.Sscanf(hostport[i+1:], "%d", &p)
	return fmt.Sprintf("%s:%d", hostport[:i], p+1)
}

// equalPrefixSet は a と b を集合として比べる(仕様 10.1、10.2 節。FindMergeBlocker と
// importdiff.go の fieldChanges が使う)。順序を無視するだけでなく、比べる前に重複を払う。
// 旧い CLI は同一 CIDR の重複エントリを許していたため、長さだけを見て一方向の包含を確かめる
// 形では [A, A] と [A, B] を等しいと誤判定しうる(長さが同じ 2 で、A は互いに含まれるため)。
// 重複を払った上で両方向の包含(≒長さと包含の一致)を見ることで、この誤判定を塞ぐ。
func equalPrefixSet(a, b []netip.Prefix) bool {
	da, db := dedupPrefixes(a), dedupPrefixes(b)
	if len(da) != len(db) {
		return false
	}
	for _, p := range da {
		if !containsPrefix(db, p) {
			return false
		}
	}
	return true
}

// dedupPrefixes は list から重複する CIDR を払い、初出の順で返す。
func dedupPrefixes(list []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(list))
	for _, p := range list {
		if !containsPrefix(out, p) {
			out = append(out, p)
		}
	}
	return out
}

func equalRate(a, b *Rate) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
