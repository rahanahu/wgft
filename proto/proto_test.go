package proto

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		in      string
		want    PortRange
		wantErr bool
	}{
		{"2456", PortRange{2456, 2456}, false},
		{"2456-2457", PortRange{2456, 2457}, false},
		{"1-65535", PortRange{1, 65535}, false},
		{"2457-2456", PortRange{}, true},
		{"0", PortRange{}, true},
		{"65536", PortRange{}, true},
		{"abc", PortRange{}, true},
		{"", PortRange{}, true},
		{"1-2-3", PortRange{}, true},
	}
	for _, tt := range tests {
		got, err := ParsePortRange(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParsePortRange(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("ParsePortRange(%q) = %v, want %v", tt.in, got, tt.want)
		}
		if !tt.wantErr && got.String() != tt.in {
			t.Errorf("PortRange(%q).String() = %q", tt.in, got.String())
		}
	}
}

func TestPortRangeOverlaps(t *testing.T) {
	a := PortRange{2456, 2457}
	for _, tt := range []struct {
		b    PortRange
		want bool
	}{
		{PortRange{2457, 2460}, true},
		{PortRange{2450, 2456}, true},
		{PortRange{2456, 2457}, true},
		{PortRange{2458, 2458}, false},
		{PortRange{1, 2455}, false},
	} {
		if got := a.Overlaps(tt.b); got != tt.want {
			t.Errorf("%v.Overlaps(%v) = %v, want %v", a, tt.b, got, tt.want)
		}
	}
}

func TestParseRate(t *testing.T) {
	for _, tt := range []struct {
		in      string
		want    Rate
		wantErr bool
	}{
		{"100/second", Rate{100, PerSecond}, false},
		{"10/minute", Rate{10, PerMinute}, false},
		{"1/week", Rate{1, PerWeek}, false},
		{"0/second", Rate{}, true},
		{"100", Rate{}, true},
		{"100/fortnight", Rate{}, true},
		{"x/second", Rate{}, true},
	} {
		got, err := ParseRate(tt.in)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseRate(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseRate(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

// validRule は検査を通る基準のルール。各テストで 1 か所ずつ壊す。
func validRule() Rule {
	return Rule{
		ID: "r_1", Agent: "home", Proto: UDP,
		ListenPort: PortRange{2456, 2457}, Target: "192.168.1.20:2456",
		VPSMode: ModeKernel, Enabled: true,
	}
}

func TestRuleValidate(t *testing.T) {
	rate := Rate{10, PerSecond}
	tests := []struct {
		name    string
		mutate  func(*Rule)
		wantErr string // 空なら成功を期待
	}{
		{"基準", func(r *Rule) {}, ""},
		{"ホスト名の target", func(r *Rule) { r.Target = "nas.lan:2456" }, ""},
		{"ループバックの target", func(r *Rule) { r.Target = "127.0.0.1:2456" }, ""},
		{"proxy + proxy_protocol", func(r *Rule) {
			r.Proto = TCP
			r.ListenPort = PortRange{443, 443}
			r.VPSMode = ModeProxy
			r.ProxyProtocol = true
		}, ""},
		{"接続元制限とレート", func(r *Rule) {
			r.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
			r.SourceAllow = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
			r.NewFlowRate, r.PacketRate, r.PerSourceRate = &rate, &rate, &rate
		}, ""},
		{"範囲の末尾が 65535 にぴったり", func(r *Rule) { r.ListenPort = PortRange{1, 2}; r.Target = "h:65534" }, ""},
		{"id が空", func(r *Rule) { r.ID = "" }, "id is empty"},
		{"agent が空", func(r *Rule) { r.Agent = "" }, "agent is empty"},
		{"proto が不正", func(r *Rule) { r.Proto = "sctp" }, "proto"},
		{"listen_port が空", func(r *Rule) { r.ListenPort = PortRange{} }, "listen_port is empty"},
		{"target にポートがない", func(r *Rule) { r.Target = "192.168.1.20" }, "host:port"},
		{"target のホストが空", func(r *Rule) { r.Target = ":2456" }, "empty host"},
		{"target が IPv6", func(r *Rule) { r.Target = "[fd00::1]:2456" }, "IPv6"},
		{"target のポートが 0", func(r *Rule) { r.Target = "h:0" }, "port is not an integer"},
		{"実効宛先が溢れる", func(r *Rule) { r.ListenPort = PortRange{1, 2}; r.Target = "h:65535" }, "exceeds 65535"},
		{"vps_mode が不正", func(r *Rule) { r.VPSMode = "nat" }, "vps_mode"},
		{"proxy で udp", func(r *Rule) { r.VPSMode = ModeProxy }, "can only be used with tcp"},
		{"proxy が範囲", func(r *Rule) {
			r.Proto = TCP
			r.ListenPort = PortRange{443, 444}
			r.VPSMode = ModeProxy
		}, "cannot span a port range"},
		{"proxy_protocol を kernel で", func(r *Rule) { r.ProxyProtocol = true }, "proxy_protocol"},
		{"source_deny が IPv6", func(r *Rule) { r.SourceDeny = []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")} }, "IPv4"},
		{"source_allow が無効", func(r *Rule) { r.SourceAllow = []netip.Prefix{{}} }, "IPv4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := validRule()
			tt.mutate(&r)
			err := r.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateRules(t *testing.T) {
	reserved := Reserved{51820: "WireGuard", 8443: "エージェント用 API"}
	mk := func(id string, proto Proto, lo, hi uint16) Rule {
		r := validRule()
		r.ID, r.Proto, r.ListenPort = id, proto, PortRange{lo, hi}
		return r
	}
	tests := []struct {
		name    string
		rules   []Rule
		wantErr string
	}{
		{"空", nil, ""},
		{"重ならない", []Rule{mk("a", UDP, 2456, 2457), mk("b", UDP, 2458, 2459), mk("c", TCP, 25565, 25565)}, ""},
		{"同じポートでもプロトコルが違えばよい", []Rule{mk("a", UDP, 2456, 2456), mk("b", TCP, 2456, 2456)}, ""},
		{"無効なルールも重複に数える", func() []Rule {
			a, b := mk("a", UDP, 2456, 2457), mk("b", UDP, 2457, 2458)
			b.Enabled = false
			return []Rule{a, b}
		}(), "overlaps"},
		{"範囲が重なる", []Rule{mk("a", UDP, 2456, 2460), mk("b", UDP, 2460, 2461)}, "overlaps"},
		{"ID が重複", []Rule{mk("a", UDP, 2456, 2456), mk("a", UDP, 2457, 2457)}, "ID a is duplicated"},
		{"予約ポートを範囲が含む", []Rule{mk("a", UDP, 51800, 51900)}, "WireGuard"},
		{"予約ポートはプロトコルを問わない", []Rule{mk("a", UDP, 8443, 8443)}, "エージェント用 API"},
		{"単体の検査も通す", []Rule{mk("a", "sctp", 1, 1)}, "rule a: proto"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRules(tt.rules, reserved)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateRules() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("ValidateRules() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestValidateUpsertGrandfathersUnchanged は、ValidateUpsert が before と ID・内容の
// 変わらない行に Rule.Validate() を掛け直さないことを確かめる(5.4 節)。proxy の範囲を
// 拒否する検査を Rule.Validate() に追加した後も、それ以前に保存された proxy の範囲ルールが
// 1 件あるだけで、他のルールしか触っていないバッチまで失敗させないための仕組みである。
func TestValidateUpsertGrandfathersUnchanged(t *testing.T) {
	legacy := validRule()
	legacy.ID, legacy.Proto, legacy.ListenPort, legacy.VPSMode = "legacy", TCP, PortRange{443, 444}, ModeProxy
	other := validRule()
	other.ID, other.Proto, other.ListenPort = "other", UDP, PortRange{2456, 2457}

	// legacy 単体では Validate に落ちる(前提の確認)
	if err := legacy.Validate(); err == nil {
		t.Fatal("legacy proxy range rule unexpectedly passed Validate(); fix the test fixture")
	}

	// legacy をそのままに、無関係な other だけを変えるバッチは通る
	before := []Rule{legacy, other}
	changedOther := other
	changedOther.Enabled = false
	after := []Rule{legacy, changedOther}
	if err := ValidateUpsert(after, before, nil); err != nil {
		t.Errorf("an unrelated batch must not fail because of an untouched legacy row: %v", err)
	}

	// ValidateRules(全体検査)なら同じ集合が落ちることも確認しておく(対比用)
	if err := ValidateRules(after, nil); err == nil {
		t.Error("ValidateRules() should still reject the legacy row when checking the whole set")
	}

	// legacy 自身を変えるバッチは、変えた後の内容が Validate に落ちるので拒む
	changedLegacy := legacy
	changedLegacy.Note = "touched"
	if err := ValidateUpsert([]Rule{changedLegacy, other}, before, nil); err == nil {
		t.Error("touching the legacy row must re-run Validate() and fail")
	}
}

// 仕様 5.3 節の例をそのまま読めて、同じ JSON に書き戻せること。
func TestRuleJSONRoundTrip(t *testing.T) {
	const spec = `{
  "id": "r_01J",
  "agent": "home",
  "group": "valheim",
  "note": "週末サーバ。フレンド用",
  "proto": "udp",
  "listen_port": "2456-2457",
  "target": "192.168.1.20:2456",
  "vps_mode": "kernel",
  "proxy_protocol": false,
  "source_allow": [],
  "source_deny": ["203.0.113.0/24"],
  "new_flow_rate": "100/second",
  "packet_rate": null,
  "per_source_rate": "10/second",
  "enabled": true
}`
	var r Rule
	if err := json.Unmarshal([]byte(spec), &r); err != nil {
		t.Fatal(err)
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if r.ListenPort != (PortRange{2456, 2457}) || r.PacketRate != nil || *r.NewFlowRate != (Rate{100, PerSecond}) {
		t.Errorf("unexpected parse: %+v", r)
	}
	out, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err := json.Unmarshal([]byte(spec), &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	wantJSON, _ := json.Marshal(want)
	gotJSON, _ := json.Marshal(got)
	if string(wantJSON) != string(gotJSON) {
		t.Errorf("round trip differs:\n want %s\n got  %s", wantJSON, gotJSON)
	}
}

func TestForAgentAndEffectiveTarget(t *testing.T) {
	r := validRule()
	r.SourceDeny = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	a := r.ForAgent()
	out, _ := json.Marshal(a)
	for _, forbidden := range []string{"vps_mode", "source_deny", "rate", "proxy_protocol", "group", "note"} {
		if strings.Contains(string(out), forbidden) {
			t.Errorf("agent JSON contains %q: %s", forbidden, out)
		}
	}
	for _, tt := range []struct {
		port   uint16
		want   string
		wantOK bool
	}{
		{2456, "192.168.1.20:2456", true},
		{2457, "192.168.1.20:2457", true},
		{2458, "", false},
	} {
		got, ok := a.EffectiveTarget(tt.port)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("EffectiveTarget(%d) = %q, %v; want %q, %v", tt.port, got, ok, tt.want, tt.wantOK)
		}
	}
}

// 仕様 5.2 節の全体状態の例を読めること。
func TestStateJSON(t *testing.T) {
	const spec = `{
  "generation": 42,
  "wg": {
    "server_pubkey": "abc",
    "endpoint": "vps.example.com:51820",
    "address": "10.200.0.2/24",
    "mtu": 1420,
    "keepalive": 25,
    "udp_timeout": 30,
    "udp_timeout_stream": 120
  },
  "rules": [
    {"id": "r_01J", "proto": "udp", "listen_port": "2456-2457", "target": "192.168.1.20:2456", "enabled": true}
  ]
}`
	var s State
	if err := json.Unmarshal([]byte(spec), &s); err != nil {
		t.Fatal(err)
	}
	if s.Generation != 42 || s.WG.MTU != 1420 || s.WG.UDPTimeoutStream != 120 || len(s.Rules) != 1 || s.Rules[0].ListenPort != (PortRange{2456, 2457}) {
		t.Errorf("unexpected parse: %+v", s)
	}
	out, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"generation":42`, `"udp_timeout_stream":120`, `"listen_port":"2456-2457"`} {
		if !strings.Contains(string(out), key) {
			t.Errorf("marshal lacks %s: %s", key, out)
		}
	}
}

// group と note の検証。
func TestGroupNoteValidation(t *testing.T) {
	r := validRule()
	r.Group = strings.Repeat("a", 33)
	if r.Validate() == nil {
		t.Error("33 文字の group が通った")
	}
	r.Group = "bad space"
	if r.Validate() == nil {
		t.Error("空白入りの group が通った")
	}
	r.Group = "ok-1.2_x"
	r.Note = strings.Repeat("あ", 121)
	if r.Validate() == nil {
		t.Error("121 文字の note が通った")
	}
	r.Note = "問題ない説明"
	if err := r.Validate(); err != nil {
		t.Errorf("正当な group/note が弾かれた: %v", err)
	}
}

func TestTargetDisplay(t *testing.T) {
	cases := []struct {
		lo, hi       uint16
		target, want string
	}{
		{2456, 2457, "192.168.1.20:2456", "192.168.1.20:2456-2457"},
		{25565, 25565, "192.168.1.20:25565", "192.168.1.20:25565"},
		{80, 81, "nas.lan:8080", "nas.lan:8080-8081"},
		{1, 2, "broken", "broken"},
	}
	for _, c := range cases {
		r := Rule{ListenPort: PortRange{Lo: c.lo, Hi: c.hi}, Target: c.target}
		if got := r.TargetDisplay(); got != c.want {
			t.Errorf("%d-%d %s: got %q, want %q", c.lo, c.hi, c.target, got, c.want)
		}
	}
}
