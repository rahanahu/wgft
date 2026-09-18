package main

import (
	"path/filepath"
	"testing"
)

func TestExemptFromJapaneseCheck(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		want bool
	}{
		{"internal/vpsd/admin/i18n.go", true},
		{"internal/vpsd/admin/webui.go", true},
		{`internal\vpsd\admin\i18n.go`, true},
		{`internal\vpsd\admin\webui.go`, true},
		{`C:\src\wgft\internal\vpsd\admin\i18n.go`, true},
		{`C:\src\wgft\internal\vpsd\admin\webui.go`, true},
		{filepath.Join("internal", "vpsd", "admin", "i18n.go"), true},
		{filepath.Join("internal", "vpsd", "admin", "webui.go"), true},
		{"./i18n.go", true},
		{"i18n.go", true},
		{"webui.go", true},
		{"internal/vpsd/admin/webui_agent.go", false},
		{"internal/vpsd/admin/other.go", false},
		{"cmd/wgft/main.go", false},
		{`internal\vpsd\admin\webui_agent.go`, false},
	}
	for _, tc := range cases {
		if got := exemptFromJapaneseCheck(tc.path); got != tc.want {
			t.Errorf("exemptFromJapaneseCheck(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
