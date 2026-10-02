//go:build linux

package teardown

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/internal/vpsd/store"
)

// 撤去のロックの扱い(設計文書 10.3 節)を、カーネルに触れずに確かめる。カーネルの操作は fakeOps が
// 差し替え、各操作の時点でサーバのデータベースのロックを撤去が持っているかを記録する。flock のロックは
// 開いたファイルの記述ごとなので、同じプロセスの Inspect でも撤去が持つ排他ロックは Locked に見える。

// recorder は、撤去が呼んだ操作の名前と、その時点のロックの状態を順に記録する。
type recorder struct {
	t      *testing.T
	dbPath string
	calls  []string
	// unlocked は、ロックを持たずに呼ばれた操作の名前である。
	unlocked []string
	chowned  int
}

func (r *recorder) note(name string) {
	r.calls = append(r.calls, name)
	if st, err := flock.Inspect(r.dbPath); err != nil || st != flock.Locked {
		r.unlocked = append(r.unlocked, name)
	}
}

// fakeOps は、ロックとデータベースとファイルの操作を本物のまま使い、カーネルの操作だけを記録に置き換える。
// wg インタフェースは、自分の鍵を持つものがある、として答える。
func fakeOps(r *recorder) ops {
	o := defaultOps()
	acquire := o.acquireLock
	o.acquireLock = func(p string) (*flock.Lock, bool, error) {
		r.calls = append(r.calls, "acquire")
		return acquire(p)
	}
	o.adoptOwner = func(l *flock.Lock, dir string) error {
		r.chowned++
		r.note("adoptOwner")
		return adoptDirOwner(l, dir)
	}
	openStore := o.openStore
	o.openStore = func(p string) (*store.Store, error) {
		r.note("openStore")
		return openStore(p)
	}
	o.wgOwned = func(string, wgtypes.Key) (bool, bool, error) {
		r.note("wgOwned")
		return true, true, nil
	}
	o.deleteTable = func() error { r.note("deleteTable"); return nil }
	o.converge = func(netip.Prefix) (int, error) { r.note("converge"); return 0, nil }
	o.deleteLink = func(string) (bool, error) { r.note("deleteLink"); return true, nil }
	o.remove = func(p string) error {
		r.note("remove " + filepath.Base(p))
		return os.Remove(p)
	}
	return o
}

// newDB は、カーネルモードの記録を持つサーバのデータベースを作って閉じ、パスを返す。
func newDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	RecordHints(st, Hints{WGInterface: "wgft0", WGPort: 51820, AgentAPIAddr: "0.0.0.0:8443"})
	st.Close()
	return path
}

func exists(p string) bool {
	_, err := os.Lstat(p)
	return err == nil
}

// assertReleased は、撤去がロックを放したことを、別の取得が通ることで確かめる。
func assertReleased(t *testing.T, dbPath string) {
	t.Helper()
	if !exists(flock.LockPath(dbPath)) {
		return
	}
	l, err := flock.Acquire(dbPath)
	if err != nil {
		t.Fatalf("Acquire after teardown: %v; teardown must release the lock when it returns", err)
	}
	l.Release()
}

// ロックファイルが無ければ、撤去はロックファイルを作ってロックを取り、データベースを開く前から
// 最後のカーネルの操作まで持つ。作ったロックファイルの持ち主を置き場に合わせ、終われば放す。
func TestTeardownCreatesAndHoldsTheLockThroughout(t *testing.T) {
	path := newDB(t)
	if exists(flock.LockPath(path)) {
		t.Fatal("the test needs a database without a lock file")
	}
	r := &recorder{t: t, dbPath: path}
	var buf bytes.Buffer
	if err := run(fakeOps(r), Options{DBPath: path}, &buf); err != nil {
		t.Fatalf("teardown: %v\n%s", err, buf.String())
	}
	want := []string{"acquire", "adoptOwner", "openStore", "wgOwned", "deleteTable", "converge", "deleteLink"}
	if strings.Join(r.calls, ",") != strings.Join(want, ",") {
		t.Errorf("calls = %v, want %v", r.calls, want)
	}
	if len(r.unlocked) != 0 {
		t.Errorf("called without holding the lock: %v", r.unlocked)
	}
	if !exists(flock.LockPath(path)) {
		t.Error("the lock file is gone after a teardown without --purge")
	}
	if !exists(path) {
		t.Error("the server database is gone after a teardown without --purge")
	}
	assertReleased(t, path)
}

// ロックファイルが既にあれば、撤去はロックを取るが、持ち主には触れない。
func TestTeardownLeavesTheOwnerOfAnExistingLockFile(t *testing.T) {
	path := newDB(t)
	l, err := flock.Acquire(path) // ロックファイルを作るためだけに取る
	if err != nil {
		t.Fatal(err)
	}
	l.Release()
	r := &recorder{t: t, dbPath: path}
	var buf bytes.Buffer
	if err := run(fakeOps(r), Options{DBPath: path}, &buf); err != nil {
		t.Fatalf("teardown: %v\n%s", err, buf.String())
	}
	if r.chowned != 0 {
		t.Errorf("adoptOwner was called %d times for a lock file teardown did not create", r.chowned)
	}
	if len(r.unlocked) != 0 {
		t.Errorf("called without holding the lock: %v", r.unlocked)
	}
	assertReleased(t, path)
}

// --purge はデータベースの 3 つのファイルを消し、ロックファイルを最後に消す。どの削除の時点でも
// ロックを持っている。
func TestTeardownPurgeRemovesTheLockFileLast(t *testing.T) {
	path := newDB(t)
	for _, p := range []string{path + "-wal", path + "-shm"} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r := &recorder{t: t, dbPath: path}
	var buf bytes.Buffer
	if err := run(fakeOps(r), Options{DBPath: path, Purge: true, Yes: true}, &buf); err != nil {
		t.Fatalf("teardown: %v\n%s", err, buf.String())
	}
	var removes []string
	for _, c := range r.calls {
		if strings.HasPrefix(c, "remove ") {
			removes = append(removes, strings.TrimPrefix(c, "remove "))
		}
	}
	want := []string{"wgft.sqlite", "wgft.sqlite-wal", "wgft.sqlite-shm", "wgft.sqlite.lock"}
	if strings.Join(removes, ",") != strings.Join(want, ",") {
		t.Errorf("removed %v, want %v in this order", removes, want)
	}
	if last := r.calls[len(r.calls)-1]; last != "remove wgft.sqlite.lock" {
		t.Errorf("the last operation is %q, want the removal of the lock file", last)
	}
	if len(r.unlocked) != 0 {
		t.Errorf("called without holding the lock: %v", r.unlocked)
	}
	for _, p := range append([]string{flock.LockPath(path)}, path, path+"-wal", path+"-shm") {
		if exists(p) {
			t.Errorf("%s is left after --purge", p)
		}
	}
}

// ロックの状態を読めなければ、何も消さずに止まる。ロックファイルが FIFO と symlink の場合を見る。
// 以前は警告を出して撤去を続けた。
func TestTeardownStopsWhenTheLockCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(lockPath, dir string) error
	}{
		{"fifo", func(lp, _ string) error { return syscall.Mkfifo(lp, 0o600) }},
		{"symlink", func(lp, dir string) error { return os.Symlink(filepath.Join(dir, "elsewhere"), lp) }},
	} {
		for _, mode := range []struct {
			name string
			opts Options
		}{{"teardown", Options{}}, {"purge", Options{Purge: true, Yes: true}}, {"dry-run", Options{DryRun: true}}} {
			t.Run(tc.name+"/"+mode.name, func(t *testing.T) {
				path := newDB(t)
				if err := tc.make(flock.LockPath(path), filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
				r := &recorder{t: t, dbPath: path}
				opts := mode.opts
				opts.DBPath = path
				var buf bytes.Buffer
				err := run(fakeOps(r), opts, &buf)
				if err == nil || !strings.Contains(err.Error(), "cannot tell whether the server is running, so nothing was removed") {
					t.Fatalf("err = %v\n%s", err, buf.String())
				}
				if !errors.Is(err, flock.ErrNotRegular) {
					t.Errorf("err = %v, want one wrapping flock.ErrNotRegular", err)
				}
				for _, c := range r.calls {
					if c != "acquire" {
						t.Errorf("teardown went on to %q after failing to read the lock", c)
					}
				}
				if !exists(path) {
					t.Error("the server database is gone")
				}
				if exists(filepath.Join(filepath.Dir(path), "elsewhere")) {
					t.Error("teardown created the target of the symlink")
				}
			})
		}
	}
}

// 別のプロセスがロックを持っていれば、稼働中として何もせずに拒む。--dry-run も同じである。
func TestTeardownRefusesWhileLockedInEveryMode(t *testing.T) {
	for _, opts := range []Options{{}, {Purge: true, Yes: true}, {DryRun: true}, {Purge: true}} {
		path := newDB(t)
		held, err := flock.Acquire(path)
		if err != nil {
			t.Fatal(err)
		}
		r := &recorder{t: t, dbPath: path}
		opts.DBPath = path
		var buf bytes.Buffer
		err = run(fakeOps(r), opts, &buf)
		held.Release()
		if !errors.Is(err, errServerRunning) {
			t.Errorf("%+v: err = %v, want errServerRunning", opts, err)
		}
		for _, c := range r.calls {
			if c != "acquire" {
				t.Errorf("%+v: teardown went on to %q while the server holds the lock", opts, c)
			}
		}
		if buf.Len() != 0 {
			t.Errorf("%+v: teardown wrote output before refusing:\n%s", opts, buf.String())
		}
	}
}

// snapshot は、ディレクトリの中の名前ごとの種別、権限、更新時刻、中身のハッシュである。
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	got := map[string]string{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(p)
		got[e.Name()] = fmt.Sprintf("%v %v %x", fi.Mode(), fi.ModTime(), sha256.Sum256(b))
	}
	return got
}

// --dry-run は何も作らず、何も書かない。ロックファイルを作らず、古い版のスキーマのデータベースを
// 移行せず、権限も締め直さない(設計文書 10.3 節)。--yes の無い --purge も同じである。
func TestTeardownDryRunCreatesAndWritesNothing(t *testing.T) {
	for _, opts := range []Options{{DryRun: true}, {DryRun: true, Purge: true, Yes: true}, {Purge: true}} {
		path := newDB(t)
		dir := filepath.Dir(path)
		// 1 つ前の版のスキーマにし、WAL の補助ファイルを残さない
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		for _, q := range []string{"ALTER TABLE agents DROP COLUMN disabled_at", "PRAGMA user_version = 8", "PRAGMA journal_mode = DELETE"} {
			if _, err := db.Exec(q); err != nil {
				t.Fatalf("%s: %v", q, err)
			}
		}
		db.Close()
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		before := snapshot(t, dir)

		r := &recorder{t: t, dbPath: path}
		opts.DBPath = path
		var buf bytes.Buffer
		err = run(fakeOps(r), opts, &buf)
		if opts.DryRun && err != nil {
			t.Fatalf("%+v: %v\n%s", opts, err, buf.String())
		}
		if !opts.DryRun && (err == nil || !strings.Contains(err.Error(), "pass --yes")) {
			t.Fatalf("%+v: err = %v, want the --yes refusal", opts, err)
		}
		for _, c := range r.calls {
			switch c {
			case "openStore", "wgOwned":
			default:
				t.Errorf("%+v: a teardown that changes nothing called %q", opts, c)
			}
		}
		after := snapshot(t, dir)
		var names []string
		for n := range after {
			names = append(names, n)
		}
		sort.Strings(names)
		if len(before) != len(after) {
			t.Errorf("%+v: files before %d, after %v", opts, len(before), names)
		}
		for n, v := range before {
			if after[n] != v {
				t.Errorf("%+v: %s changed:\n before %s\n after  %s", opts, n, v, after[n])
			}
		}
		db, err = sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
		if err != nil {
			t.Fatal(err)
		}
		var v int
		if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil || v != 8 {
			t.Errorf("%+v: user_version = %d, %v; want 8, unchanged", opts, v, err)
		}
		db.Close()
	}
}

// 置き場のディレクトリが無ければ、ロックファイルを置けないので、ロックを取らずに進め、その旨を示す。
// ディレクトリは作らない。
func TestTeardownWithoutTheDirectoryRunsWithoutTheLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "never-created")
	path := filepath.Join(dir, "wgft.sqlite")
	r := &recorder{t: t, dbPath: path}
	var buf bytes.Buffer
	if err := run(fakeOps(r), Options{DBPath: path, Adopt: true}, &buf); err != nil {
		t.Fatalf("teardown: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "does not exist, so no server is using it; continuing without the server's lock") {
		t.Errorf("output does not say teardown runs without the lock:\n%s", buf.String())
	}
	if exists(dir) {
		t.Error("teardown created the directory of the server database")
	}
	if !strings.Contains(buf.String(), "deleted wg wgft0") {
		t.Errorf("teardown did not go on to the removal:\n%s", buf.String())
	}
}

// データベースが無くても置き場があれば、ロックファイルを作ってロックを取る。--purge はそのロック
// ファイルも最後に消す。
func TestTeardownWithoutTheDatabaseStillLocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	r := &recorder{t: t, dbPath: path}
	var buf bytes.Buffer
	if err := run(fakeOps(r), Options{DBPath: path, Adopt: true, Purge: true, Yes: true}, &buf); err != nil {
		t.Fatalf("teardown: %v\n%s", err, buf.String())
	}
	if r.calls[0] != "acquire" || r.chowned != 1 {
		t.Errorf("calls = %v, adoptOwner %d times; want the lock taken and the created file adopted", r.calls, r.chowned)
	}
	if len(r.unlocked) != 0 {
		t.Errorf("called without holding the lock: %v", r.unlocked)
	}
	if !strings.Contains(buf.String(), "is missing") {
		t.Errorf("output does not say the database is missing:\n%s", buf.String())
	}
	if exists(path) || exists(flock.LockPath(path)) {
		t.Error("teardown --purge left the database or the lock file")
	}
}

// カーネルの操作が途中で失敗しても、撤去はロックを放して誤りを返す。
func TestTeardownReleasesTheLockOnFailure(t *testing.T) {
	path := newDB(t)
	r := &recorder{t: t, dbPath: path}
	o := fakeOps(r)
	o.deleteLink = func(string) (bool, error) { return false, errors.New("boom") }
	var buf bytes.Buffer
	if err := run(o, Options{DBPath: path, Purge: true, Yes: true}, &buf); err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v", err)
	}
	if !exists(path) {
		t.Error("the database is gone although teardown stopped before --purge")
	}
	assertReleased(t, path)
}

// adoptDirOwner は、持ち主が置き場と同じなら何もしない。持ち主が違う場合の付け替えは root が要るので、
// ラボの TestTeardownGivesTheCreatedLockFileTheDirectoryOwner が確かめる。
func TestAdoptDirOwnerKeepsAMatchingOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	l, created, err := flock.AcquireCreating(path)
	if err != nil || !created {
		t.Fatalf("AcquireCreating = %v, %v", created, err)
	}
	defer l.Release()
	if err := adoptDirOwner(l, filepath.Dir(path)); err != nil {
		t.Errorf("adoptDirOwner with the owner already matching: %v", err)
	}
	if err := adoptDirOwner(l, filepath.Join(filepath.Dir(path), "missing")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("adoptDirOwner on a missing directory = %v, want ErrNotExist", err)
	}
}
