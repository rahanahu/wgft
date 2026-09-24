package agent

import (
	"bytes"
	"errors"
	"log"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// plantLeftover は、保存の途中で強制終了したときに残る一時ファイルを置く。
func plantLeftover(t *testing.T, dir string) string {
	t.Helper()
	p := filepath.Join(dir, ".wgft-credentials-4242")
	if err := os.WriteFile(p, []byte(`{"permanent_token":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) })
	return &buf
}

// 起動はロックを取った後に残りを消し、消した件数だけをログに出す。登録の情報が無いので
// 起動そのものは設定の誤りで止まるが、片付けはその前に済んでいる。
func TestRunRemovesLeftoverTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	leftover := plantLeftover(t, dir)
	buf := captureLog(t)

	err := Run(Options{CredentialsPath: path})
	if err == nil || errors.Is(err, credentials.ErrLocked) {
		t.Fatalf("Run = %v; want the not-registered refusal", err)
	}
	if _, err := os.Lstat(leftover); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("leftover is still there: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "removed leftover temporary copies of the credentials file left by interrupted saves: 1\n") {
		t.Errorf("log does not report the count:\n%s", out)
	}
	if strings.Contains(out, filepath.Base(leftover)) || strings.Contains(out, "secret") {
		t.Errorf("log names the leftover or its content:\n%s", out)
	}
}

// 別のプロセスがロックを持っている間は、片付けずに二重起動として止まる。
func TestRunKeepsLeftoverTempsWhileLocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	leftover := plantLeftover(t, dir)
	l, err := credentials.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	buf := captureLog(t)

	if err := Run(Options{CredentialsPath: path}); !errors.Is(err, credentials.ErrLocked) {
		t.Fatalf("Run = %v; want ErrLocked", err)
	}
	if _, err := os.Lstat(leftover); err != nil {
		t.Errorf("leftover was removed while another process held the lock: %v", err)
	}
	if strings.Contains(buf.String(), "leftover") {
		t.Errorf("log mentions a cleanup:\n%s", buf.String())
	}
}

// 片付けの警告は 1 行で、件数と誤りの種類だけを出し、一時ファイルのパスを出さない。ディレクトリを
// 読めなければ、残りの有無を確かめられなかったと言う。権限でファイル操作を拒ませるので、Unix の
// 非 root でだけ流す。
func TestRemoveLeftoverTempsWarnsInOneLineWithoutPaths(t *testing.T) {
	if goruntime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs Unix directory permissions and a non-root user")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	lock, err := credentials.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()
	leftover := plantLeftover(t, dir)
	second := filepath.Join(dir, ".wgft-credentials-4343")
	if err := os.WriteFile(second, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	for _, c := range []struct {
		mode os.FileMode
		want string
	}{
		{0o500, "warning: cannot remove leftover temporary copies of the credentials file: 2, first error: permission denied; "},
		{0o300, "warning: could not check the data directory for leftover temporary copies of the credentials file: permission denied; "},
	} {
		if err := os.Chmod(dir, c.mode); err != nil {
			t.Fatal(err)
		}
		buf := captureLog(t)
		removeLeftoverTemps(lock, path)
		out := buf.String()
		if strings.Count(out, "\n") != 1 || !strings.HasPrefix(out, c.want) {
			t.Errorf("mode %04o: log\n%s\nwant one line starting with %q", c.mode, out, c.want)
		}
		if strings.Contains(out, dir) || strings.Contains(out, filepath.Base(leftover)) {
			t.Errorf("mode %04o: log names a path:\n%s", c.mode, out)
		}
	}
}
