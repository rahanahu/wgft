//go:build linux

package servercheck

import (
	"errors"
	"strings"
	"testing"
)

// server check は、書ける ip_forward が 0 の場合も所見にする。稼働中の server は起動時にしか 1 に
// しないので、その横で 0 にされた値は戻らない(設計文書 6.1 節)。
func TestIPForwardFindingWhenWritable(t *testing.T) {
	f := ipForwardFinding("0", nil)
	if !strings.Contains(f.Problem, "a running server sets it only at its start") || len(f.Suggest) == 0 {
		t.Errorf("writable ip_forward 0: %s", f)
	}
	f = ipForwardFinding("0", errors.New("read-only file system"))
	if !strings.Contains(f.Problem, "not writable") {
		t.Errorf("unwritable ip_forward 0: %s", f)
	}
	var b strings.Builder
	writeIPForwardCheck(&b, "0", nil, nil)
	if !strings.Contains(b.String(), "ip_forward: 0\n  - net.ipv4.ip_forward: is 0;") {
		t.Errorf("server check is silent on a writable 0: %q", b.String())
	}
	b.Reset()
	writeIPForwardCheck(&b, "1", nil, nil)
	if b.String() != "ip_forward: 1\n" {
		t.Errorf("server check on 1: %q", b.String())
	}
}
