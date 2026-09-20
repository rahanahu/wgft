//go:build !windows

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// warnInsecureConfigFile は、secret な値がファイルから読まれていて、かつそのファイルが other
// (このホストの誰からでも)読める場合だけ警告する。group だけが読める(agent.env の推奨である
// 0640)場合は、意図した共有なので警告しない(仕様 11a 節)。secret がファイル以外(env や既定値)
// から来た場合や、そもそも secret な spec を持たない config(server.env の想定)では、
// パーミッションに関わらず警告しない。
func TestWarnInsecureConfigFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(p, []byte("WGFT_JOIN=wgft://h:1/tok#sha256:ab\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	secretFromFile := &config{
		specs: []spec{{Env: "WGFT_JOIN", Secret: true}},
		vals:  map[string]resolved{"WGFT_JOIN": {value: "wgft://h:1/tok#sha256:ab", source: "file"}},
	}
	secretFromEnv := &config{
		specs: []spec{{Env: "WGFT_JOIN", Secret: true}},
		vals:  map[string]resolved{"WGFT_JOIN": {value: "wgft://h:1/tok#sha256:ab", source: "env"}},
	}
	noSecretSpec := &config{
		specs: []spec{{Env: "WGFT_WG_ENDPOINT"}},
		vals:  map[string]resolved{"WGFT_WG_ENDPOINT": {value: "vps.example.com:1", source: "file"}},
	}

	cases := []struct {
		name string
		mode os.FileMode
		cfg  *config
		want bool
	}{
		{"world readable (0644)", 0o644, secretFromFile, true},
		{"world writable only (0602)", 0o602, secretFromFile, true},
		{"owner and group only (0640, the documented agent.env deploy)", 0o640, secretFromFile, false},
		{"owner only (0600)", 0o600, secretFromFile, false},
		{"world readable but the value came from the environment, not the file", 0o644, secretFromEnv, false},
		{"world readable but this config has no secret spec (server.env-like)", 0o644, noSecretSpec, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(p, tc.mode); err != nil {
				t.Fatal(err)
			}
			var buf bytes.Buffer
			warnInsecureConfigFile(&buf, p, tc.cfg)
			got := buf.Len() > 0
			if got != tc.want {
				t.Errorf("mode %o: warned = %v (message %q), want warned = %v", tc.mode, got, buf.String(), tc.want)
			}
			if got {
				if !strings.Contains(buf.String(), p) {
					t.Errorf("warning does not name the file: %q", buf.String())
				}
				if !strings.Contains(buf.String(), "0600") {
					t.Errorf("warning does not mention a recommended mode: %q", buf.String())
				}
			}
		})
	}
}

// loadConfig は warnInsecureConfigFile を実際に呼ぶ(agentSpecs の WGFT_JOIN が Secret なので、
// agent 側の呼び出しで発火しうる経路)。
func TestLoadConfigWarnsOnInsecureSecretFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(p, []byte("WGFT_JOIN=wgft://h:1/tok#sha256:ab\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stderr
	os.Stderr = w
	cmd := testCmd()
	_, loadErr := loadConfig(cmd, testSpecs(), p)
	os.Stderr = orig
	w.Close()
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	out, _ := io.ReadAll(r)
	if !strings.Contains(string(out), "warning:") || !strings.Contains(string(out), p) {
		t.Errorf("loadConfig did not warn about the insecure, secret-holding file; stderr = %q", out)
	}
}
