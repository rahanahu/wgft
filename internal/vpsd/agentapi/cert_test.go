package agentapi

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// TestLoadOrCreateCertReloadsTheStoredPair checks that the certificate and key made on the first
// start are read back on the next one. A key read from the certificate's record, or the other way
// round, would make every start after the first fail or present a new certificate, and agents
// pin its fingerprint.
func TestLoadOrCreateCertReloadsTheStoredPair(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "s.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	first, err := LoadOrCreateCert(st)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreateCert(st)
	if err != nil {
		t.Fatalf("reloading the stored pair: %v", err)
	}
	if !bytes.Equal(first.Certificate[0], second.Certificate[0]) {
		t.Error("the second start presents a different certificate")
	}
	for _, key := range []string{store.MetaAgentAPICert, store.MetaAgentAPIKey} {
		if b, err := st.GetMeta(key); err != nil || len(b) == 0 {
			t.Errorf("meta %s: %d bytes, %v", key, len(b), err)
		}
	}
}
