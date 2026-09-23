package admin

import (
	"errors"
	"html"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

// ダッシュボードのエージェント行の IP の比較(仕様 5.2、10.1 節)。一致、確認済みでない食い違い、
// 確認済みの食い違いの 3 つを出し分ける。確認済みの食い違いは警告の色にせず、要対応の行にしない。
// 確認済みの組を読めなければ、確認済みでない食い違いとして描く。

func ackFor(agent, streamIP, wgIP string) store.Ack {
	return store.Ack{Agent: agent, Kind: store.WarnIPMismatch, StreamIP: streamIP, WGIP: wgIP}
}

// agentRow はダッシュボードから、そのエージェントの行(<tr> から </tr> まで)を切り出す。
func agentRow(t *testing.T, body, name string) string {
	t.Helper()
	i := strings.Index(body, "<strong>"+name+"</strong>")
	if i < 0 {
		t.Fatalf("no row for %s in body:\n%s", name, body)
	}
	start := strings.LastIndex(body[:i], "<tr")
	end := strings.Index(body[i:], "</tr>")
	return body[start : i+end]
}

func TestDashboardIPCompareStates(t *testing.T) {
	const (
		sIP  = "203.0.113.3"
		wIP  = "203.0.113.2"
		wEnd = "203.0.113.2:35835"
	)
	cases := []struct {
		name       string
		streamFrom string
		wgEndpoint string
		acks       []store.Ack
		acksErr    error
		wantLabel  string
		wantClass  string
		attention  bool
	}{
		{name: "match", streamFrom: wIP, wgEndpoint: wEnd, acks: []store.Ack{ackFor("home", sIP, wIP)},
			wantLabel: "ipMatch", wantClass: "success-text"},
		// IPv6 のエージェント:stream は SplitHostPort の結果(括弧なし)、wg は "[ip]:port"。
		// 以前の ipOnly は最後の ":" で切ったので、同じアドレスでも食い違いに見えていた
		{name: "IPv6 match", streamFrom: "2001:db8::1", wgEndpoint: "[2001:db8::1]:51820",
			wantLabel: "ipMatch", wantClass: "success-text"},
		{name: "mismatch without acknowledgement", streamFrom: sIP, wgEndpoint: wEnd,
			wantLabel: "ipMismatch", wantClass: "warning-text", attention: true},
		{name: "another pair and another agent are acknowledged", streamFrom: sIP, wgEndpoint: wEnd,
			acks:      []store.Ack{ackFor("home", "203.0.113.4", wIP), ackFor("office", sIP, wIP)},
			wantLabel: "ipMismatch", wantClass: "warning-text", attention: true},
		{name: "acknowledged", streamFrom: sIP, wgEndpoint: wEnd, acks: []store.Ack{ackFor("home", sIP, wIP)},
			wantLabel: "ipMismatchAcked", wantClass: "muted"},
		{name: "acknowledged, IPv4-mapped stream address", streamFrom: "::ffff:" + sIP, wgEndpoint: wEnd,
			acks: []store.Ack{ackFor("home", sIP, wIP)}, wantLabel: "ipMismatchAcked", wantClass: "muted"},
		// wg のエンドポイントをまだ観測していない:比較を出さない(ラベルは空)
		{name: "wg endpoint unobserved", streamFrom: sIP, wgEndpoint: "", acks: []store.Ack{ackFor("home", sIP, wIP)}},
		{name: "acknowledgements unreadable", streamFrom: sIP, wgEndpoint: wEnd, acks: []store.Ack{ackFor("home", sIP, wIP)},
			acksErr: errors.New("simulated store failure: acks"), wantLabel: "ipMismatch", wantClass: "warning-text", attention: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			agents := []AgentInfo{{
				Name: "home", Connected: true, LastHeartbeat: time.Now().Format(time.RFC3339),
				StreamFrom: tc.streamFrom, WGEndpoint: tc.wgEndpoint, Tunnel: TunnelStatus{State: proto.StatusOK},
			}}
			fb := &fakeBackend{st: st, agents: agents, warnings: []Warning{}, acks: tc.acks, acksErr: tc.acksErr}
			srv := httptest.NewServer(New(fb))
			defer srv.Close()
			for _, lang := range []string{"ja", "en"} {
				row := agentRow(t, getBody(t, srv.URL+"/?lang="+lang), "home")
				if tc.wantLabel == "" && strings.Contains(row, `<small class=""></small>`) {
					t.Errorf("%s: an unobserved pair must not render an empty comparison, row:\n%s", lang, row)
				}
				if tc.wantLabel != "" {
					want := `<small class="` + tc.wantClass + `">` + html.EscapeString(T(lang, tc.wantLabel)) + `</small>`
					if !strings.Contains(row, want) {
						t.Errorf("%s: row must contain %q, row:\n%s", lang, want, row)
					}
				}
				if got := strings.Contains(row, "attention-row"); got != tc.attention {
					t.Errorf("%s: attention-row = %v, want %v; row:\n%s", lang, got, tc.attention, row)
				}
				for _, other := range []string{"ipMatch", "ipMismatch", "ipMismatchAcked"} {
					if other != tc.wantLabel && strings.Contains(row, html.EscapeString(T(lang, other))+"<") {
						t.Errorf("%s: row must not show %q, row:\n%s", lang, T(lang, other), row)
					}
				}
			}
		})
	}
}
