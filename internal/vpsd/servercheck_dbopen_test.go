//go:build linux

package vpsd

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// server check の終了コードは、サーバのデータベースを開けない場合も 0 のままである(7a.11 節の
// 保証)。運用者はこの失敗を出力から読み取る。schema too new の場合だけは、専用の見落としにくい
// 行で示す(改訂の記録参照)。

// TestCheckNotPresentIsNotAFailure は、初回起動で SQLite がまだ無い場合が今までどおり
// エラーではないことを確かめる(仕様 9 節)。
func TestCheckNotPresentIsNotAFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	opts := Options{Mode: modeUserspace, DBPath: path, WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}
	var out bytes.Buffer
	if err := Check(opts, &out); err != nil {
		t.Fatalf("Check returned %v for a database that does not exist yet", err)
	}
	if !strings.Contains(out.String(), "server database: not present yet") {
		t.Errorf("output lacks the not-present line:\n%s", out.String())
	}
}

// TestCheckOnNewerSchemaStaysExitZeroWithADedicatedLine は、新しい版が書いたスキーマを開けない
// 場合に、server check の終了コードが 0 のままであること(7a.11 節の保証)と、その失敗が専用の
// 見落としにくい行で、出力の最初のほうと最後の両方に現れることを確かめる。以前はここで
// "cannot open" の 1 行だけを出しており、他の行に紛れやすかった(改訂の記録参照)。
func TestCheckOnNewerSchemaStaysExitZeroWithADedicatedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		"CREATE TABLE meta (key TEXT PRIMARY KEY, value BLOB NOT NULL)",
		"PRAGMA user_version = 999",
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()

	opts := Options{Mode: modeUserspace, DBPath: path, WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}
	var out bytes.Buffer
	if err := Check(opts, &out); err != nil {
		t.Fatalf("Check returned %v for a database written by a newer schema; exit code must stay 0 (7a.11 section)", err)
	}
	got := out.String()
	wantHeadline := "server database: schema version 999 is newer than this binary; this binary supports up to"
	if !strings.Contains(got, wantHeadline) {
		t.Errorf("output lacks the dedicated newer-schema headline %q:\n%s", wantHeadline, got)
	}
	if n := strings.Count(got, wantHeadline); n < 2 {
		t.Errorf("dedicated headline appears %d times, want at least 2 (once near the top, once as the last line):\n%s", n, got)
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if last := lines[len(lines)-1]; !strings.Contains(last, wantHeadline) {
		t.Errorf("last line of output = %q, want it to contain the dedicated headline", last)
	}
	if !strings.Contains(got, "server database: cannot open:") {
		t.Errorf("output lacks the ordinary cannot-open line:\n%s", got)
	}
}

// TestCheckOnUnopenableDatabaseStaysExitZero は、スキーマ以外の理由(壊れたファイルの例)で
// サーバのデータベースを開けない場合も、終了コードは 0 のままで、今までどおりの 1 行だけを
// 出すことを確かめる。
func TestCheckOnUnopenableDatabaseStaysExitZero(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	if err := os.WriteFile(path, []byte("this is not a sqlite database"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := Options{Mode: modeUserspace, DBPath: path, WGInterface: "wgft0", WGAddress: "10.200.0.1/24"}
	var out bytes.Buffer
	if err := Check(opts, &out); err != nil {
		t.Fatalf("Check returned %v for a database it could not open; exit code must stay 0 (7a.11 section)", err)
	}
	got := out.String()
	if !strings.Contains(got, "server database: cannot open:") {
		t.Errorf("output lacks the cannot-open line:\n%s", got)
	}
	if strings.Contains(got, "newer than this binary") {
		t.Errorf("a corrupt file should not be reported as a newer schema:\n%s", got)
	}
}
