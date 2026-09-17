package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// newTestRegisterServer は登録 API のなりすまし(仕様 5.1 節)。渡された name が空でなければ
// boundName と比較し、違えば 401 を返す(vpsd の実装と同じ契約)。
func newTestRegisterServer(t *testing.T, boundName string) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/register", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req["token"] != "tok" {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if req["name"] != "" && req["name"] != boundName {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"permanent_token": "PERM",
			"address":         "10.200.0.2",
			"name":            boundName,
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	pin := sha256.Sum256(srv.Certificate().Raw)
	host := strings.TrimPrefix(srv.URL, "https://")
	join := fmt.Sprintf("wgft://%s/tok#sha256:%x", host, pin)
	return srv, join
}

// 名前を送らない初回登録は、応答に含まれる確定した名前を認証情報に保存する。
func TestEnsureRegisteredStoresConfirmedName(t *testing.T) {
	_, join := newTestRegisterServer(t, "home")
	path := filepath.Join(t.TempDir(), "agent.json")

	f := &credentials.Credentials{}
	opts := Options{CredentialsPath: path, Join: join} // Name は空
	if err := ensureRegistered(f, opts); err != nil {
		t.Fatal(err)
	}
	if f.Name != "home" || f.PermanentToken != "PERM" {
		t.Fatalf("f = %+v", f)
	}
	g, err := credentials.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.Name != "home" {
		t.Errorf("persisted name = %q, want %q", g.Name, "home")
	}
}

// 名前を送っても一致すれば通る。
func TestEnsureRegisteredWithMatchingName(t *testing.T) {
	_, join := newTestRegisterServer(t, "home")
	f := &credentials.Credentials{}
	opts := Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json"), Join: join, Name: "home"}
	if err := ensureRegistered(f, opts); err != nil {
		t.Fatal(err)
	}
	if f.Name != "home" {
		t.Errorf("f.Name = %q", f.Name)
	}
}

// 名前が食い違えば拒否される。
func TestEnsureRegisteredWithMismatchedName(t *testing.T) {
	_, join := newTestRegisterServer(t, "home")
	f := &credentials.Credentials{}
	opts := Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json"), Join: join, Name: "office"}
	if err := ensureRegistered(f, opts); err == nil {
		t.Error("mismatched name must be rejected")
	}
}

// 既に登録済みで WGFT_NAME が保存済みの名前と違えば、警告するだけで保存済みの名前を保つ。
func TestEnsureRegisteredKeepsStoredNameOnMismatch(t *testing.T) {
	f := &credentials.Credentials{Name: "home", PermanentToken: "PERM"}
	opts := Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json"), Name: "other"}
	if err := ensureRegistered(f, opts); err != nil {
		t.Fatal(err)
	}
	if f.Name != "home" {
		t.Errorf("f.Name = %q, want unchanged %q", f.Name, "home")
	}
}

// サーバ証明書が認証情報のピンと違うとき、stream の接続は ErrPinMismatch として区別できる。
func TestStreamOnceReportsPinMismatch(t *testing.T) {
	srv, _ := newTestRegisterServer(t, "home")
	rt := &runtime{f: &credentials.Credentials{
		Endpoint:       strings.TrimPrefix(srv.URL, "https://"),
		CertSHA256:     strings.Repeat("00", 32), // 立て直す前のサーバのピン
		PermanentToken: "OLD",
	}}
	err := rt.streamOnce(context.Background())
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("streamOnce = %v, want ErrPinMismatch", err)
	}
}

// ピンの不一致からの再登録に使うのは、未使用でピンの違う接続文字列だけ。
func TestJoinForNewPin(t *testing.T) {
	_, join := newTestRegisterServer(t, "home")
	j, err := ParseJoin(join)
	if err != nil {
		t.Fatal(err)
	}
	newPin := hex.EncodeToString(j.Pin[:])
	oldPin := strings.Repeat("00", 32)
	cases := []struct {
		name, join, storedPin, usedHash string
		want                            bool
	}{
		{"unused join with a new pin", join, oldPin, "", true},
		{"no join", "", oldPin, "", false},
		{"join already used", join, oldPin, j.TokenHash(), false},
		{"join has the stored pin", join, newPin, "", false},
		{"unparsable join", "wgft://broken", oldPin, "", false},
	}
	for _, c := range cases {
		rt := &runtime{opts: Options{Join: c.join}, f: &credentials.Credentials{CertSHA256: c.storedPin, UsedJoinTokenSHA256: c.usedHash}}
		if got := rt.joinForNewPin() != nil; got != c.want {
			t.Errorf("%s: joinForNewPin != nil is %v, want %v", c.name, got, c.want)
		}
	}
}

// 再登録が成功すると、認証情報のピンとトークンが新しいサーバのものに置き換わる。
func TestRecoverReplacesPinAndToken(t *testing.T) {
	_, join := newTestRegisterServer(t, "home")
	path := filepath.Join(t.TempDir(), "agent.json")
	rt := &runtime{
		opts: Options{Join: join, CredentialsPath: path},
		f:    &credentials.Credentials{Name: "home", CertSHA256: strings.Repeat("00", 32), PermanentToken: "OLD", WGPrivateKey: "keep"},
	}
	if err := rt.recover(); err != nil {
		t.Fatal(err)
	}
	j, _ := ParseJoin(join)
	saved, err := credentials.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.PermanentToken != "PERM" || saved.CertSHA256 != hex.EncodeToString(j.Pin[:]) || saved.UsedJoinTokenSHA256 != j.TokenHash() {
		t.Errorf("credentials not replaced: %+v", saved)
	}
	if saved.WGPrivateKey != "keep" {
		t.Errorf("wg private key changed: %q", saved.WGPrivateKey)
	}
}
