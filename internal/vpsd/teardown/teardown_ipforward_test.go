//go:build linux

package teardown

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// The ip_forward line of the manual-restore list (design.md 10.3 節) reads the two-stage record
// the server keeps (6.1 節) and the current value, and says no more than they support.

func readValue(v string, err error) func() (string, error) {
	return func() (string, error) { return v, err }
}

func TestIPForwardLineByRecordsAndCurrentValue(t *testing.T) {
	const (
		confirmed = "2026-01-02T03:04:05Z"
		planned   = "2026-01-02T03:04:04Z"
	)
	unreadable := errors.New("permission denied")
	cases := []struct {
		name               string
		confirmed, planned string
		read               func() (string, error)
		want               string
		notWant            []string
	}{
		{"confirmed", confirmed, "", readValue("1", nil),
			"net.ipv4.ip_forward: wgft set it 0->1 at " + confirmed + "; if nothing else uses forwarding, restore with `sysctl -w net.ipv4.ip_forward=0`, and delete the file in /etc/sysctl.d if it was made persistent", nil},
		{"confirmed wins over a planned record", confirmed, planned, readValue("1", nil),
			"net.ipv4.ip_forward: wgft set it 0->1 at " + confirmed + ";", []string{"may have changed"}},
		{"planned only, now 1", "", planned, readValue("1", nil),
			"net.ipv4.ip_forward: wgft read 0 and started to set it to 1 at " + planned + ", but the result was not recorded, so wgft may have changed it; it is now 1; check the current value and decide; if wgft set it and nothing else uses forwarding, restore with `sysctl -w net.ipv4.ip_forward=0`", nil},
		{"planned only, now 0", "", planned, readValue("0", nil),
			"so wgft may have changed it; it is now 0; check the current value and decide", nil},
		{"planned only, unreadable", "", planned, readValue("", unreadable),
			"so wgft may have changed it; reading its current value failed: permission denied; check the current value and decide", nil},
		{"neither, now 1", "", "", readValue("1", nil),
			"net.ipv4.ip_forward: wgft did not change it, already 1; no action needed", nil},
		{"neither, now 0", "", "", readValue("0", nil),
			"net.ipv4.ip_forward: wgft did not change it, now 0; no action needed", []string{"already 1"}},
		{"neither, unreadable", "", "", readValue("", unreadable),
			"net.ipv4.ip_forward: wgft did not change it; no action needed; reading its current value failed: permission denied", []string{"already 1"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
			if err != nil {
				t.Fatal(err)
			}
			defer st.Close()
			for k, v := range map[string]string{store.MetaIPForwardSetAt: c.confirmed, store.MetaIPForwardWriteStartedAt: c.planned} {
				if v == "" {
					continue
				}
				if err := st.SetMeta(k, []byte(v)); err != nil {
					t.Fatal(err)
				}
			}
			got := ipForwardLine(st, c.read)
			if !strings.Contains(got, c.want) {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
			for _, nw := range c.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("got %q, which says %q", got, nw)
				}
			}
		})
	}
}

// TestIPForwardLineWhenTheRecordCannotBeRead checks that a record that cannot be read is not taken
// for "wgft did not change it".
func TestIPForwardLineWhenTheRecordCannotBeRead(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	st.Close() // every read fails
	got := ipForwardLine(st, readValue("1", nil))
	if !strings.Contains(got, "net.ipv4.ip_forward: reading wgft's record of changing it failed: ") || !strings.Contains(got, "it is now 1; check the current value and decide") {
		t.Errorf("got %q", got)
	}
	if strings.Contains(got, "did not change it") {
		t.Errorf("got %q, which claims wgft did not change it", got)
	}
}

// TestTeardownDryRunShowsThePlannedIPForwardRecord runs a dry-run teardown on a database left by a
// server that stopped between the write and the confirmed record, and checks that the output
// carries the "may have changed" line with the current value teardown read. A userspace-mode
// database reads no value and prints no ip_forward line.
func TestTeardownDryRunShowsThePlannedIPForwardRecord(t *testing.T) {
	for _, mode := range []string{store.ModeKernel, store.ModeUserspace} {
		path := filepath.Join(t.TempDir(), "s.sqlite")
		st, err := store.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		RecordHints(st, Hints{WGInterface: "wgtest0", WGPort: 51999, AgentAPIAddr: "0.0.0.0:9443"})
		for k, v := range map[string]string{store.MetaIPForwardWriteStartedAt: "2026-01-02T03:04:05Z", store.MetaMode: mode} {
			if err := st.SetMeta(k, []byte(v)); err != nil {
				t.Fatal(err)
			}
		}
		st.Close()

		o := fakeOps(&recorder{t: t, dbPath: path})
		reads := 0
		o.readIPForward = func() (string, error) { reads++; return "1", nil }
		var buf bytes.Buffer
		if err := run(o, Options{DBPath: path, DryRun: true}, &buf); err != nil {
			t.Fatalf("%s: teardown: %v\n%s", mode, err, buf.String())
		}
		out := buf.String()
		if mode == store.ModeUserspace {
			if reads != 0 || strings.Contains(out, "ip_forward") {
				t.Errorf("userspace: read the value %d times; output:\n%s", reads, out)
			}
			continue
		}
		if reads != 1 || !strings.Contains(out, "wgft read 0 and started to set it to 1 at 2026-01-02T03:04:05Z, but the result was not recorded, so wgft may have changed it; it is now 1;") {
			t.Errorf("kernel: read the value %d times; output:\n%s", reads, out)
		}
	}
}
