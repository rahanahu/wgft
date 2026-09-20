package main

import (
	"strings"
	"testing"
)

// gc は netns の名前だけを頼りに自分の残骸を選ぶので、名前の読み方が間違うと
// 他のテストの netns や共有のトポロジ (client, vps, home...) に触りうる。
func TestParseNSNameOnlyMatchesOwnNamespaces(t *testing.T) {
	const prefix = "wgft-"
	for _, name := range []string{"client", "vps", "homerouter", "home", "lan", "wgft-", "wgft-abc", "wgft-abc-eth0", "wgft--vps", "other-abc-vps", "wgft-abc-runners"} {
		if id, role, ok := parseNSName(prefix, name); ok {
			t.Errorf("parseNSName(%q) = (%q, %q, true), want ok=false", name, id, role)
		}
	}
	id, role, ok := parseNSName(prefix, "wgft-a1b2c3-vps")
	if !ok || id != "a1b2c3" || role != "vps" {
		t.Errorf("parseNSName = (%q, %q, %v), want (a1b2c3, vps, true)", id, role, ok)
	}
	// ID に - が入っても、末尾の role だけを切り出す
	if id, role, ok := parseNSName(prefix, "wgft-run-7-lan"); !ok || id != "run-7" || role != "lan" {
		t.Errorf("parseNSName = (%q, %q, %v), want (run-7, lan, true)", id, role, ok)
	}
}

// 名前の組み立てと読み取りは往復する。シナリオの shell を入れる runner も含む。
func TestNSNameRoundTrip(t *testing.T) {
	for _, r := range allRoles() {
		n := nsName("wgft-", "zz9", r)
		id, role, ok := parseNSName("wgft-", n)
		if !ok || id != "zz9" || role != r {
			t.Errorf("%q -> (%q, %q, %v)", n, id, role, ok)
		}
	}
}

// ID は netns の名前に使うので、英小文字と数字だけの 6 文字。
func TestNewIDIsSafeForNamespaceNames(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 6 {
			t.Fatalf("id %q: length %d, want 6", id, len(id))
		}
		if strings.Trim(id, "abcdefghijklmnopqrstuvwxyz0123456789") != "" {
			t.Fatalf("id %q has characters outside [a-z0-9]", id)
		}
		seen[id] = true
	}
	if len(seen) < 90 {
		t.Errorf("only %d distinct ids out of 100", len(seen))
	}
}

// シナリオに渡す環境変数は 5 つの netns と作業ディレクトリと ID。
func TestSandboxEnv(t *testing.T) {
	s := &Sandbox{ID: "abc123", Prefix: "wgft-", Dir: "/tmp/wgft-lab/abc123", NS: map[string]string{}}
	for _, r := range roles {
		s.NS[r] = nsName(s.Prefix, s.ID, r)
	}
	want := map[string]string{
		"WGFT_LAB_SANDBOX":   "abc123",
		"WGFT_LAB_WORKDIR":   "/tmp/wgft-lab/abc123",
		"WGFT_LAB_CLIENT_NS": "wgft-abc123-client",
		"WGFT_LAB_VPS_NS":    "wgft-abc123-vps",
		"WGFT_LAB_ROUTER_NS": "wgft-abc123-router",
		"WGFT_LAB_HOME_NS":   "wgft-abc123-home",
		"WGFT_LAB_LAN_NS":    "wgft-abc123-lan",
	}
	got := map[string]string{}
	for _, kv := range s.Env() {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if len(got) != len(want) {
		t.Fatalf("Env() = %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}
