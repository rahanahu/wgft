// Package proto は vpsd と agent が共有する、ルールと全体状態の JSON スキーマを定める(仕様 5.2, 5.3 節)。
package proto

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strconv"
	"unicode"
	"unicode/utf8"
)

// validateGroup は group ラベルを検査する。空は許す。英数と - _ . のみ、32 文字以内。
func validateGroup(g string) error {
	if utf8.RuneCountInString(g) > 32 {
		return errors.New("group must be 32 characters or fewer")
	}
	for _, c := range g {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_', c == '.':
		default:
			return fmt.Errorf("invalid character %q in group; only alphanumerics and - _ . are allowed", c)
		}
	}
	return nil
}

// Proto は転送する L4 プロトコル。
type Proto string

const (
	TCP Proto = "tcp"
	UDP Proto = "udp"
)

// VPSMode は VPS 側の転送方式(仕様 6 節)。
type VPSMode string

const (
	// ModeKernel は nftables の DNAT でカーネルが転送する。
	ModeKernel VPSMode = "kernel"
	// ModeProxy は vpsd 自身が TCP を受けて中継する。TCP のみ。
	ModeProxy VPSMode = "proxy"
)

// Rule は「VPS の <proto>/<listen_port> を、エージェント <agent> 経由で <target> へ届ける」宣言(仕様 5.3 節)。
type Rule struct {
	ID            string         `json:"id"`
	Agent         string         `json:"agent"`
	Group         string         `json:"group"` // 任意。ルールを束ねるフラットなラベル 1 つ(仕様 5.3)
	Note          string         `json:"note"`  // 任意。何のためのルールかの自由記述
	Proto         Proto          `json:"proto"`
	ListenPort    PortRange      `json:"listen_port"`
	Target        string         `json:"target"` // host:port。範囲のときは先頭ポートに対応する
	VPSMode       VPSMode        `json:"vps_mode"`
	ProxyProtocol bool           `json:"proxy_protocol"`
	SourceAllow   []netip.Prefix `json:"source_allow"`
	SourceDeny    []netip.Prefix `json:"source_deny"`
	NewFlowRate   *Rate          `json:"new_flow_rate"`
	PacketRate    *Rate          `json:"packet_rate"`
	PerSourceRate *Rate          `json:"per_source_rate"`
	Enabled       bool           `json:"enabled"`
}

// isDotSegment は、s が URL のパスの区切りとして `.` か `..` に当たるかを返す。ルールの ID は
// validateRuleID の範囲の文字列を受けるが、この 2 つは拒む(仕様 10.2 節)。ブラウザは WHATWG URL 標準に従い、
// %2E と %2E%2E も区切りの `.` と `..` として扱うので、escape しても Web UI のボタンが別の経路へ
// 送信するためである。agent は書き込むときに登録済みのエージェントの名前であることも求められ、その
// 名前の文字種がこの 2 つを既に拒むので、agent の検査は多重の守りである。
func isDotSegment(s string) bool { return s == "." || s == ".." }

// MaxRuleIDLen はルールの ID に許す長さの上限で、UTF-8 のバイトで数える(仕様 5.3 節)。server の
// ハートビートの受け口がエージェントの報告するルール ID を切り詰める長さ(internal/vpsd/stream の
// maxHeartbeatIDLen)と同じ値である。超える ID のルールは、報告と一致せず状態が永久に届かない。
// nftables のカウンタのコメント "wgft:<ID>:<種類>" も、この上限の下で 256 バイトの userdata に収まる。
const MaxRuleIDLen = 128

// validateRuleID は ID の長さと文字を検査する(仕様 5.3 節、2026-10-03、所有者の決定)。長さは
// 文字数ではなくバイトで数える。上限を決めている受け口の切り詰めと nftables の userdata がバイトで
// 数えるためである。文字は unicode.IsGraphic が真のもの(文字、結合記号、数字、句読点、記号、
// Unicode の空白 Zs)だけを受ける。制御文字、不正な UTF-8、双方向の上書きやゼロ幅の文字(Cf)、
// 行と段落の区切り(Zl、Zp)、私用領域を拒む。ハートビートの受け口(internal/vpsd/stream)が
// 置き換えるのは同じ unicode.IsGraphic が偽の文字なので、受けた ID は報告と一致し、ログの行を偽る
// 改行や端末を操る値も入らない。空白を削ることも、全角と半角をそろえることもしない。この関数の
// エラーは ID の中身を繰り返さない。バッチの検査(validateRuleSet)は従来どおり "rule <ID>: " を前に付ける。
func validateRuleID(id string) error {
	if len(id) > MaxRuleIDLen {
		return fmt.Errorf("id is %d bytes long; the limit is %d bytes", len(id), MaxRuleIDLen)
	}
	if !utf8.ValidString(id) {
		return errors.New("id is not valid UTF-8")
	}
	for i, c := range id {
		if !unicode.IsGraphic(c) {
			return fmt.Errorf("id contains %U at byte %d; only letters, marks, numbers, punctuation, symbols and spaces are allowed", c, i)
		}
	}
	return nil
}

// Validate はルール単体で判定できる制約を検査する。ルール間の制約は ValidateRules が見る。
func (r *Rule) Validate() error {
	if r.ID == "" {
		return errors.New("id is empty")
	}
	if isDotSegment(r.ID) {
		return fmt.Errorf("id %q is not allowed: browsers read it as a dot segment in the Web UI's URLs, even when escaped", r.ID)
	}
	if err := validateRuleID(r.ID); err != nil {
		return err
	}
	if r.Agent == "" {
		return errors.New("agent is empty")
	}
	if isDotSegment(r.Agent) {
		return fmt.Errorf("agent %q is not allowed: browsers read it as a dot segment in the Web UI's URLs, even when escaped", r.Agent)
	}
	switch r.Proto {
	case TCP, UDP:
	default:
		return fmt.Errorf("proto %q is neither tcp nor udp", r.Proto)
	}
	if r.ListenPort.Lo == 0 {
		return errors.New("listen_port is empty")
	}
	_, port, err := splitTarget(r.Target)
	if err != nil {
		return fmt.Errorf("target: %w", err)
	}
	// 範囲の末尾に対応する実効宛先のポートが溢れないこと(仕様 5.3 節)
	if int(port)+r.ListenPort.Len()-1 > 65535 {
		return fmt.Errorf("target port %d plus the width of range %s exceeds 65535", port, r.ListenPort)
	}
	switch r.VPSMode {
	case ModeKernel:
	case ModeProxy:
		if r.Proto != TCP {
			return errors.New("vps_mode=proxy can only be used with tcp")
		}
		// proxy は単一ポート運用(vpsd の relayRules、userspace モードでも同じ経路。仕様
		// 6.2、6.3 節)。範囲を許すと先頭ポート以外が中継されないまま黙って失われるため拒否する
		if r.ListenPort.IsRange() {
			return fmt.Errorf("vps_mode=proxy cannot span a port range: listen_port %s; use a single port", r.ListenPort)
		}
	default:
		return fmt.Errorf("vps_mode %q is neither kernel nor proxy", r.VPSMode)
	}
	if r.ProxyProtocol && r.VPSMode != ModeProxy {
		return errors.New("proxy_protocol can only be enabled when vps_mode=proxy")
	}
	if err := validateGroup(r.Group); err != nil {
		return err
	}
	if utf8.RuneCountInString(r.Note) > 120 {
		return errors.New("note must be 120 characters or fewer")
	}
	for name, prefixes := range map[string][]netip.Prefix{"source_allow": r.SourceAllow, "source_deny": r.SourceDeny} {
		for _, p := range prefixes {
			if !p.IsValid() || !p.Addr().Is4() {
				return fmt.Errorf("%s %q is not an IPv4 CIDR", name, p)
			}
		}
	}
	return nil
}

// Reserved は listen_port に使えないポートと、その用途(エラーメッセージ用)。
// WireGuard、エージェント用 API、管理用 API のポートを vpsd が入れる(仕様 5.3 節)。
type Reserved map[uint16]string

// ValidateRules はルール集合全体の制約を検査する。
// listen_port の重複はプロトコルごとに、有効無効を問わず見る(無効なルールを有効に戻したときに衝突させないため)。
// 予約ポートはプロトコルを問わず拒否する。
func ValidateRules(rules []Rule, reserved Reserved) error {
	return validateRuleSet(rules, reserved, nil)
}

// ValidateUpsert は ValidateRules と同じだが、before と ID・内容がまったく同じ行には
// Rule.Validate() を掛け直さない(5.4 節)。store.ApplyBatch はバッチのたびに rules 全体を
// この関数で検査するため、Rule.Validate() に検査を後から増やすと、増やす前から保存されていた
// 触っていない行のせいで、以後の無関係なバッチまで失敗しかねない(例:proxy の範囲を拒否する
// 検査を追加した後、それ以前に作られた proxy の範囲ルールが 1 件あるだけで、他のルールの
// 有効無効を切り替えるだけのバッチも失敗する)。before に無い(新規)行や、値が変わった行は
// 通常どおり検査する。ID の重複・予約ポート・listen_port の重なりは before の有無に関わらず
// 全体に対して行う(これらは以前から常に全体を検査していたため、検査対象から外しても保存された
// データが既に満たしている)。
func ValidateUpsert(rules, before []Rule, reserved Reserved) error {
	return validateRuleSet(rules, reserved, UnchangedIDs(rules, before))
}

// UnchangedIDs は rules のうち、before に同じ ID で同じ内容の行がある ID の集合を返す。
// ValidateUpsert と、Web UI の読み込みの確認ページ(仕様 10.1 節)が、どの行に
// Rule.Validate() を掛け直すかを同じ規則で決めるために使う。空の接続元リストは nil と
// 空スライスを同じとみなす(経路によって表現が揺れるため。RulesDigest と同じ扱い)。
func UnchangedIDs(rules, before []Rule) map[string]bool {
	beforeByID := make(map[string]Rule, len(before))
	for _, b := range before {
		beforeByID[b.ID] = normalizeSources(b)
	}
	unchanged := make(map[string]bool, len(rules))
	for _, r := range rules {
		if b, ok := beforeByID[r.ID]; ok && reflect.DeepEqual(normalizeSources(r), b) {
			unchanged[r.ID] = true
		}
	}
	return unchanged
}

// normalizeSources は空の接続元リストを nil にそろえた写しを返す。
func normalizeSources(r Rule) Rule {
	if len(r.SourceAllow) == 0 {
		r.SourceAllow = nil
	}
	if len(r.SourceDeny) == 0 {
		r.SourceDeny = nil
	}
	return r
}

func validateRuleSet(rules []Rule, reserved Reserved, skipValidate map[string]bool) error {
	ids := make(map[string]bool, len(rules))
	for i := range rules {
		r := &rules[i]
		if !skipValidate[r.ID] {
			if err := r.Validate(); err != nil {
				return fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
		if ids[r.ID] {
			return fmt.Errorf("rule ID %s is duplicated", r.ID)
		}
		ids[r.ID] = true
		for p, use := range reserved {
			if r.ListenPort.Contains(p) {
				return fmt.Errorf("rule %s: listen_port %s includes %s port %d", r.ID, r.ListenPort, use, p)
			}
		}
		for j := range rules[:i] {
			o := &rules[j]
			if o.Proto == r.Proto && o.ListenPort.Overlaps(r.ListenPort) {
				return fmt.Errorf("rule %s %s/%s overlaps rule %s %s", r.ID, r.Proto, r.ListenPort, o.ID, o.ListenPort)
			}
		}
	}
	return nil
}

// splitTarget は "host:port" を分ける。ホストは IPv4 アドレスかホスト名(IPv4 のみ対応、仕様 4 節)。
func splitTarget(target string) (host string, port uint16, err error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("%q is not in host:port form", target)
	}
	if host == "" {
		return "", 0, fmt.Errorf("%q has an empty host", target)
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "", 0, fmt.Errorf("%q is an IPv6 address; only IPv4 is supported", target)
	}
	n, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || n == 0 {
		return "", 0, fmt.Errorf("%q port is not an integer in 1-65535", target)
	}
	return host, uint16(n), nil
}

// TargetDisplay は表示用の実効宛先。listen_port が範囲なら、target の先頭ポートから連番で写した
// 範囲を host:lo-hi の形で返す(仕様 5.3 節)。単一ポートや解釈できない値は target をそのまま返す。
func (r Rule) TargetDisplay() string {
	if r.ListenPort.Lo == r.ListenPort.Hi {
		return r.Target
	}
	host, port, err := splitTarget(r.Target)
	if err != nil {
		return r.Target
	}
	hi := int(port) + int(r.ListenPort.Hi) - int(r.ListenPort.Lo)
	return net.JoinHostPort(host, strconv.Itoa(int(port))) + "-" + strconv.Itoa(hi)
}
