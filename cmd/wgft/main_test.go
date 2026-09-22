package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/buildinfo"
	"github.com/rahanahu/wgft/proto"
)

// --version prints the version string alone, with nothing before or after it (no "wgft
// version" prefix). README's install-check commands and scripts rely on being able to
// compare `wgft --version`'s output as-is.
func TestVersionFlag(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"--version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	if got != buildinfo.Version {
		t.Errorf("--version = %q, want %q", got, buildinfo.Version)
	}
}

// `wgft version` prints the version string on its own first line (the same contract as
// --version), followed by the range of protocol versions this binary supports
// (design.md 7a.6 section). That range is a static property of the binary, not of any one
// agent connection, which is why it belongs next to the version rather than in `agent ls`.
func TestVersionSubcommand(t *testing.T) {
	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("version = %q, want 2 lines (version, protocol range)", buf.String())
	}
	if lines[0] != buildinfo.Version {
		t.Errorf("version line 1 = %q, want %q", lines[0], buildinfo.Version)
	}
	// Pinned as a literal rather than derived from proto.SupportedProtocol, so that a
	// change to the supported range has to be made here too instead of this test
	// silently following the implementation. (While Min and Max are both 1 no test can
	// catch the two being swapped, since either order prints "v1-v1".)
	const wantProto = "protocol range: v1-v1"
	if lines[1] != wantProto {
		t.Errorf("version line 2 = %q, want %q", lines[1], wantProto)
	}
}

// TestVersionSubcommandRangeComesFromProto pins the range line to proto.SupportedProtocol
// rather than to whatever string happens to be correct today. TestVersionSubcommand's
// literal alone cannot do that: while the supported range is v1-v1, an implementation that
// printed a hardcoded "protocol range: v1-v1" and never read proto.SupportedProtocol would
// satisfy it. Widening the range here and asserting the output follows is what makes the
// claim in design.md 7a.6 -- that the line reports the range built into this binary --
// actually checked. Min and Max are set to different values so their order is pinned too.
func TestVersionSubcommandRangeComesFromProto(t *testing.T) {
	saved := proto.SupportedProtocol
	t.Cleanup(func() { proto.SupportedProtocol = saved })
	proto.SupportedProtocol = proto.ProtocolRange{Min: 2, Max: 7}

	cmd := newRootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetArgs([]string{"version"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("version = %q, want 2 lines", buf.String())
	}
	if want := "protocol range: v2-v7"; lines[1] != want {
		t.Errorf("version line 2 = %q, want %q (the range must be read from proto.SupportedProtocol)", lines[1], want)
	}
}
