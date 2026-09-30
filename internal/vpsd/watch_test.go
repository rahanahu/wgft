//go:build linux

package vpsd

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/internal/vpsd/stream"
)

// errWGStatusDataplane is a stubDataplane whose WGStatus() always fails.
type errWGStatusDataplane struct {
	stubDataplane
}

func (errWGStatusDataplane) WGStatus() (*wgtypes.Device, error) {
	return nil, errFake("simulated wg status failure")
}

type errFake string

func (e errFake) Error() string { return string(e) }

// okWGStatusDataplane returns a real, empty device (not the nil stubDataplane returns), so the
// loop that ranges over dev.Peers does not dereference a nil pointer.
type okWGStatusDataplane struct {
	stubDataplane
}

func (okWGStatusDataplane) WGStatus() (*wgtypes.Device, error) {
	return &wgtypes.Device{}, nil
}

func newTestDaemon(t *testing.T, dp serverDataplane, st *store.Store) *Daemon {
	t.Helper()
	return &Daemon{dp: dp, st: st, hub: stream.New(nil), flaps: &flapState{hist: map[string]map[string][]ipObs{}}}
}

// captureLog redirects the standard logger into a buffer a test can inspect with String().
//
// The buffer is syncBuffer, not a plain bytes.Buffer: hold_test.go's serve-based tests never close
// the admin and agent APIs' listeners, only cancel serve's context, so each one's accept loop and
// http.Server keep running for the rest of the test binary. The admin API's server has no ErrorLog,
// so net/http falls back to the standard logger for its own errors; the agent API's server sets one
// (agentapi's handshakeErrorLog), and that one calls log.Print directly. Either way, a TLS handshake
// error on a connection that reaches such a leftover listener - a stray probe, or a client the
// owning test already stopped waiting on - writes into whatever the standard logger currently
// points to. A captureLog-based test running at that moment would race a plain bytes.Buffer's
// Write against its own String(), which can corrupt the buffer's internal slice and panic instead
// of just failing the assertion that expected a quiet log.
func captureLog(t *testing.T) *syncBuffer {
	t.Helper()
	return newSyncBuffer(t)
}

// TestIPMismatchTickLogsWGStatusFailure confirms that a failed wg-status read during the
// theft-detection tick (design.md 5.2 節) is skipped visibly: it must not panic, must not
// silently drop the tick with no trace, and must be findable in the log (design.md 10.5 節,
// the fail-open case for this specific security-relevant read).
func TestIPMismatchTickLogsWGStatusFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	d := newTestDaemon(t, errWGStatusDataplane{}, st)
	buf := captureLog(t)

	d.ipMismatchTick(map[string]int{})

	if !strings.Contains(buf.String(), "reading wg status") {
		t.Errorf("expected a log line naming the failed wg status read, got %q", buf.String())
	}
}

// TestIPMismatchTickLogsAgentsFailure is the same, for the agent-list read.
func TestIPMismatchTickLogsAgentsFailure(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	st.Close() // force every subsequent store call to fail
	d := newTestDaemon(t, okWGStatusDataplane{}, st)
	buf := captureLog(t)

	d.ipMismatchTick(map[string]int{})

	if !strings.Contains(buf.String(), "reading agents") {
		t.Errorf("expected a log line naming the failed agents read, got %q", buf.String())
	}
}
