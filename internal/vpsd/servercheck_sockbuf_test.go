//go:build linux

package vpsd

import (
	"bytes"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/sockbuf"
)

// server check はユーザー空間モードで、ソケットのバッファの条件を人が判断できる形で示す。今の
// sysctl、CAP_NET_ADMIN を持たないプロセスが得る値、条件の値である(設計文書 6.3 節、7 節)。判定は
// 稼働中の server の測定に任せ、付属の unit が CAP_NET_ADMIN を与えることを理由に省かない。
func TestWriteSocketBufferCheck(t *testing.T) {
	cases := []struct {
		name   string
		l      sockbuf.Limits
		p      sockbuf.Probe
		want   []string
		absent []string
	}{
		{name: "defaults of an older kernel", l: sockbuf.Limits{RmemMax: 212992, WmemMax: 212992}, p: sockbuf.Probe{Recv: 425984, Send: 425984},
			want: []string{"requires 14680064 bytes each", "net.core.rmem_max: 212992", "net.core.wmem_max: 212992",
				"without CAP_NET_ADMIN: a socket gets receive 425984 and send 425984 bytes, below the requirement",
				"so 7340032 in each sysctl is what gives 14680064", "/etc/sysctl.d/90-wgft.conf", "sysctl --system", "container host",
				"on a VM or a dedicated host can get the required size", "inside a container or on an LXC-based VPS that capability does not lift the limit",
				"so the container host's sysctls decide",
				"whether a server in an LXC container or on an LXC-based VPS can meet the requirement has not been verified",
				"that measurement is what decides"},
			absent: []string{"can be met there"}},
		{name: "raised", l: sockbuf.Limits{RmemMax: 7340032, WmemMax: 7340032}, p: sockbuf.Probe{Recv: 14680064, Send: 14680064},
			want:   []string{"receive 14680064 and send 14680064 bytes, which meets the requirement", "with CAP_NET_ADMIN"},
			absent: []string{"sysctl --system"}},
		{name: "a newer kernel's default", l: sockbuf.Limits{RmemMax: 4194304, WmemMax: 4194304}, p: sockbuf.Probe{Recv: 8388608, Send: 8388608},
			want: []string{"receive 8388608 and send 8388608 bytes, below the requirement"}},
		{name: "not visible in a network namespace", l: sockbuf.Limits{RmemErr: &fs.PathError{Op: "open", Path: "/proc/sys/net/core/rmem_max", Err: fs.ErrNotExist},
			WmemErr: &fs.PathError{Op: "open", Path: "/proc/sys/net/core/wmem_max", Err: fs.ErrNotExist}}, p: sockbuf.Probe{Recv: 425984, Send: 425984},
			want: []string{"net.core.rmem_max: not visible in this network namespace; the host sets it", "below the requirement"}},
		{name: "unreadable", l: sockbuf.Limits{RmemErr: errors.New("read /proc/sys/net/core/rmem_max: input/output error"), WmemMax: 212992},
			p: sockbuf.Probe{Recv: 425984, Send: 425984}, want: []string{"net.core.rmem_max: cannot read: read", "net.core.wmem_max: 212992"}},
		{name: "no trial socket", l: sockbuf.Limits{RmemMax: 212992, WmemMax: 212992}, p: sockbuf.Probe{Err: errors.New("open a trial UDP socket: denied")},
			want: []string{"without CAP_NET_ADMIN: cannot tell: open a trial UDP socket: denied"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			writeSocketBufferCheck(&b, tc.l, tc.p)
			out := b.String()
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, w := range tc.absent {
				if strings.Contains(out, w) {
					t.Errorf("output has %q:\n%s", w, out)
				}
			}
			if strings.ContainsAny(out, "()") {
				t.Errorf("output has parentheses:\n%s", out)
			}
		})
	}
}
