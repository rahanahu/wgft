//go:build linux

package servercheck

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// TestCheckRunsTheChecksOfTheMode checks that server check runs the kernel mode's checks of
// ip_forward and conntrack only in kernel mode, and the socket buffer check only in userspace mode
// (spec 6.1 and 6.3). The database is absent, so only the environment checks run.
func TestCheckRunsTheChecksOfTheMode(t *testing.T) {
	for _, tc := range []struct {
		mode          string
		want, without []string
	}{
		{store.ModeKernel, []string{"ip_forward:", "conntrack:"}, []string{"socket buffers:"}},
		{store.ModeUserspace, []string{"socket buffers:", "nft check: not used in userspace mode"}, []string{"ip_forward:", "conntrack:"}},
	} {
		opts := Options{Mode: tc.mode, DBPath: filepath.Join(t.TempDir(), "wgft.sqlite"), WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}
		var out bytes.Buffer
		if err := Check(opts, &out); err != nil {
			t.Fatal(err)
		}
		for _, w := range tc.want {
			if !strings.Contains(out.String(), w) {
				t.Errorf("%s: output lacks %q:\n%s", tc.mode, w, out.String())
			}
		}
		for _, w := range tc.without {
			if strings.Contains(out.String(), w) {
				t.Errorf("%s: output has %q:\n%s", tc.mode, w, out.String())
			}
		}
	}
}
