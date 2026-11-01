package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// goAgentMarker は、ラボの台本で Go の wgft を agent のホストのコマンドとして意図して呼ぶ行の行末の印。
const goAgentMarker = "# lab: go agent"

// agentHostCall は、agent のホストで呼ぶコマンドを wgft の名前のまま呼ぶ形。`:-wgft}` のような
// 既定の値と、/usr/local/bin/wgft のようなパスを付けた呼び出しも拾う。VPS の側のコマンド (agent ls、join-string、enable など) は拾わない。
var agentHostCall = regexp.MustCompile("(^|[\\s;&|(`\"'=/-])wgft[}\"']?\\s+agent\\s+(run|doctor|rotate-key|pubkey|teardown)\\b")

// TestScenariosCallTheAgentThroughAgentWgft は、ラボの台本が agent のホストのコマンドを
// "$AGENT_WGFT" で呼ぶことを確かめる (docs/design/v2/agent-parity.md の「台本の継ぎ目」)。
// WGFT_LAB_AGENT_IMPL=rust の一式は AGENT_WGFT を Rust の wgft にするので、wgft のまま呼ぶ行は
// Rust の agent の組でも Go の agent を動かし、その確認を Go の結果のまま通してしまう。
// カーネルモードの agent に向けた呼び出しのように Go の wgft を意図して呼ぶ行は、行末に
// goAgentMarker を付ける。変数を通した呼び出し ("$bin" agent run) はこの検査には見えない。
func TestScenariosCallTheAgentThroughAgentWgft(t *testing.T) {
	scripts, err := filepath.Glob(filepath.Join("..", "..", "lab", "*.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if len(scripts) == 0 {
		t.Fatal("no lab scripts found")
	}
	for _, p := range scripts {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") || !agentHostCall.MatchString(line) {
				continue
			}
			if strings.HasSuffix(strings.TrimRight(line, " \t"), goAgentMarker) {
				continue
			}
			t.Errorf("%s:%d calls an agent-host command as plain wgft; call it as \"$AGENT_WGFT\", "+
				"or end the line with %q if it means the Go agent: %s", filepath.Base(p), i+1, goAgentMarker, strings.TrimSpace(line))
		}
	}
}

// The pattern itself: what it must catch and what it must leave alone.
func TestAgentHostCallPattern(t *testing.T) {
	for _, s := range []string{
		`ip netns exec "$HOME_NS" setsid nohup wgft agent run --data-dir "$ADATA" &`,
		`out=$(home wgft agent doctor --data-dir "$ADATA" 2>&1)`,
		`home runuser -u wgftlab -- wgft agent rotate-key --data-dir x`,
		`out=$(home $pre ${DOCTOR_BIN:-wgft} agent doctor --json)`,
		`k=$(home wgft agent pubkey --data-dir x)`,
		`out=$(home wgft agent teardown --data-dir x 2>&1)`,
		`home /usr/local/bin/wgft agent run --data-dir x &`,
	} {
		if !agentHostCall.MatchString(s) {
			t.Errorf("not caught: %s", s)
		}
	}
	for _, s := range []string{
		`ip netns exec "$HOME_NS" setsid nohup "$AGENT_WGFT" agent run --data-dir "$ADATA" &`,
		`vps wgft agent ls --admin "$ADMIN"`,
		`join=$(vps wgft agent join-string --name home --admin "$ADMIN")`,
		`vps wgft agent disable home --admin "$ADMIN"`,
		`ip netns exec "$HOME_NS" setsid nohup wgft-rs agent run --data-dir x &`,
		`vps wgft server run --mode kernel`,
	} {
		if agentHostCall.MatchString(s) {
			t.Errorf("caught by mistake: %s", s)
		}
	}
}
