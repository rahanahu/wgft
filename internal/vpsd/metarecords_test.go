//go:build linux

package vpsd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// TestServerInfoReadsTheIPForwardRecord checks that the admin API reports the time recorded under
// the key EnableIPForward writes.
func TestServerInfoReadsTheIPForwardRecord(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if err := st.SetMeta(store.MetaIPForwardSetAt, []byte("2026-01-02T03:04:05Z")); err != nil {
		t.Fatal(err)
	}
	info, err := (&Daemon{st: st}).ServerInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.IPForwardSetAt != "2026-01-02T03:04:05Z" {
		t.Errorf("IPForwardSetAt = %q", info.IPForwardSetAt)
	}
}

// TestServerKeyIsStoredAndReloaded checks that the server key made on the first start is stored
// and read back on the next one, so agents keep the server's public key.
func TestServerKeyIsStoredAndReloaded(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	first, err := serverKey(st)
	if err != nil {
		t.Fatal(err)
	}
	second, err := serverKey(st)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Error("the second start made a new server key")
	}
	if b, err := st.GetMeta(store.MetaServerKey); err != nil || !bytes.Equal(b, first[:]) {
		t.Errorf("meta %s does not hold the key: %v", store.MetaServerKey, err)
	}
}
