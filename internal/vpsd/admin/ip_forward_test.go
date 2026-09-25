package admin

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// ipForwardBackend is a fakeBackend that reports net.ipv4.ip_forward like a kernel-mode server.
type ipForwardBackend struct {
	*fakeBackend
	st IPForwardStatus
	ok bool
}

func (b *ipForwardBackend) IPForward() (IPForwardStatus, bool) { return b.st, b.ok }

// ip_forward is additive to API v1 (design.md 10.2a、7a.11 節): a Backend without it, and a server
// that does not forward through the kernel, serve the rules without the field.
func TestRulesResponseIPForward(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := &fakeBackend{st: st}
	if _, ok := getRulesJSON(t, base, st)["ip_forward"]; ok {
		t.Error("a Backend without IPForwardBackend must not add ip_forward")
	}
	if _, ok := getRulesJSON(t, &ipForwardBackend{fakeBackend: base, ok: false}, st)["ip_forward"]; ok {
		t.Error("a server that does not forward through the kernel must not add ip_forward")
	}
	got := getRulesJSON(t, &ipForwardBackend{fakeBackend: base, st: IPForwardStatus{Value: "0"}, ok: true}, st)
	var back IPForwardStatus
	if err := json.Unmarshal(got["ip_forward"], &back); err != nil {
		t.Fatal(err)
	}
	if back.Value != "0" || back.Error != "" {
		t.Errorf("ip_forward = %+v, want value 0", back)
	}
}

// ダッシュボードの ip_forward の欄は今の値を先に示す(設計文書 10.1 節)。起動時の記録だけを示すと、
// 稼働中に外から 0 にされた server でも「wgft が設定」と出て、転送が止まっていることが見えない。
func TestIPForwardView(t *testing.T) {
	for _, tc := range []struct {
		name    string
		info    ServerInfo
		want    string
		wantBad bool
	}{
		{"older server, set by wgft", ServerInfo{IPForwardSetAt: "2026-09-25T00:00:00Z"}, "set by wgft", false},
		{"older server, unchanged", ServerInfo{}, "unchanged", false},
		{"on, set by wgft", ServerInfo{Mode: "kernel", IPForward: "1", IPForwardSetAt: "2026-09-25T00:00:00Z"}, "1, set by wgft", false},
		{"on, unchanged", ServerInfo{Mode: "kernel", IPForward: "1"}, "1, unchanged", false},
		{"off in kernel mode", ServerInfo{Mode: "kernel", IPForward: "0", IPForwardSetAt: "2026-09-25T00:00:00Z"}, "0: kernel forwarding is stopped", true},
		{"off in userspace mode", ServerInfo{Mode: "userspace", IPForward: "0"}, "0, not used in userspace mode", false},
	} {
		got, bad := ipForwardView(tc.info, "en")
		if !strings.HasPrefix(got, tc.want) || bad != tc.wantBad {
			t.Errorf("%s: %q bad=%v, want %q bad=%v", tc.name, got, bad, tc.want, tc.wantBad)
		}
		if ja, _ := ipForwardView(tc.info, "ja"); ja == got {
			t.Errorf("%s: the Japanese text is the English one: %q", tc.name, ja)
		}
	}
}
