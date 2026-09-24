// Package store は vpsd の永続状態を SQLite 1 ファイルに保存する(仕様 9 節)。
// cgo なしの modernc.org/sqlite を使い、単一の静的バイナリにする。
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	sqlitedrv "modernc.org/sqlite"
)

// Store は開いた SQLite ファイル。
type Store struct {
	db       *sql.DB
	filePath string
}

func (s *Store) path() string { return s.filePath }

// スキーマは版ごとに追記する。起動時に、未適用の版だけを順に適用する。
// 順序が正本なので、ここに 1 つのリストとして持つ(init() で各ファイルから追記すると、
// ファイル名順で順序が決まってしまい、既存の DB と食い違う)。
var migrations = []string{
	// v1:単一の値(サーバ秘密鍵、世代など)
	`CREATE TABLE meta (
		key   TEXT PRIMARY KEY,
		value BLOB NOT NULL
	)`,
	// v2:ルール(JSON のまま保存し、列は並び順だけ持つ)
	`CREATE TABLE rules (
		id       TEXT PRIMARY KEY,
		position INTEGER NOT NULL,
		json     TEXT NOT NULL
	)`,
	// v3:エージェントと登録トークン(仕様 5.1 節)。トークンはハッシュ(SHA-256)だけを保存する
	`CREATE TABLE agents (
		name            TEXT PRIMARY KEY,
		address         TEXT NOT NULL UNIQUE,
		public_key      TEXT,                 -- declared over the stream; NULL while not connected
		token_hash      BLOB NOT NULL UNIQUE, -- SHA-256 of the permanent token
		created_at      INTEGER NOT NULL,     -- UNIX seconds
		registered_from TEXT NOT NULL         -- stream source IP at registration
	);
	CREATE TABLE join_tokens (
		token_hash BLOB PRIMARY KEY,
		agent      TEXT NOT NULL,
		expires_at INTEGER NOT NULL,
		used_at    INTEGER              -- UNIX seconds once used
	)`,
	// v4:既知エンドポイント IP 集合(仕様 5.2 節)。エージェントの削除で一緒に消す
	`CREATE TABLE agent_known_ips (
		agent    TEXT NOT NULL REFERENCES agents(name) ON DELETE CASCADE,
		ip       TEXT NOT NULL,
		source   TEXT NOT NULL,   -- register | handshake | admin
		added_at INTEGER NOT NULL,
		PRIMARY KEY (agent, ip)
	)`,
	// v5:ルールごと・種類ごとの累積 drop 数(仕様 6.1 節)
	`CREATE TABLE drop_counters (
		rule_id TEXT NOT NULL,
		kind    TEXT NOT NULL,
		packets INTEGER NOT NULL DEFAULT 0,
		bytes   INTEGER NOT NULL DEFAULT 0,
		PRIMARY KEY (rule_id, kind)
	)`,
	// v6:窃取検知の警告と、交互置き換え時の受け付け停止(仕様 5.2 節)
	`CREATE TABLE warnings (
		agent      TEXT NOT NULL,
		kind       TEXT NOT NULL,
		detail     TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		PRIMARY KEY (agent, kind, detail)
	);
	ALTER TABLE agents ADD COLUMN stream_blocked INTEGER NOT NULL DEFAULT 0`,
	// v7:窃取検知の簡素化(仕様 5.2 節)。既知 IP 集合と stream 受け付け停止をやめる
	`DROP TABLE IF EXISTS agent_known_ips;
	ALTER TABLE agents DROP COLUMN stream_blocked`,
	// v8:ip-mismatch の確認済みの組(仕様 5.2 節)。警告を消したときに、その 2 つの IP の組を
	// 正当と確認した記録として残す。エージェントの削除で一緒に消す
	`CREATE TABLE warning_acks (
		agent      TEXT NOT NULL,
		kind       TEXT NOT NULL,
		stream_ip  TEXT NOT NULL,  -- normalised stream source IP, no port
		wg_ip      TEXT NOT NULL,  -- normalised wg endpoint IP, no port
		created_at INTEGER NOT NULL,
		PRIMARY KEY (agent, kind, stream_ip, wg_ip)
	)`,
	// v9:エージェントの無効化(仕様 5.1 節)。NULL は有効、値は無効にした時刻。既存の行は NULL、
	// つまり有効のまま移る。版を上げるのは、旧い版の server がこの印を読み飛ばして無効な
	// エージェントの転送を再開しないよう、データベースを新しすぎるとして起動を拒ませるためである。
	// 値は UNIX 秒。ALTER TABLE の末尾に SQL のコメントを書くと、SQLite が表の定義を書き直すときに
	// 列の定義の続きとして読み、incomplete input で失敗するので、説明はここに置く
	`ALTER TABLE agents ADD COLUMN disabled_at INTEGER`,
}

// sqliteFileURI builds a "file:" URI for path with the given query string, for
// modernc.org/sqlite's SQLITE_OPEN_URI mode (the driver always passes that flag; see newConn in
// its sqlite.go). path is made absolute first: SQLite's own URI grammar (sqlite.org/uri.html)
// treats "file://" (two slashes right after the scheme) as introducing an authority (host)
// component, and net/url's URL.String always emits that double slash once Host is empty, even when
// Path does not begin with "/". A relative path such as "rel.db" therefore serialises to
// "file://rel.db?...", which SQLite parses as an authority named "rel.db" and rejects with
// "invalid uri authority"; this used to break every relative WGFT_DATA_DIR and every call from a
// process not already chdir'd to an absolute path (found in review; see
// TestSQLiteFileURIHandlesSpecialPaths, which fails on a plain url.URL{Scheme:"file", Path: path}
// without the Abs call). Once absolute, a Unix path always starts with "/", so the same
// construction yields the unambiguous three-slash form "file:///abs/path?..." (empty authority,
// absolute path). A Windows path (`C:\Users\a\s.sqlite`) needs converting first: see
// windowsPathToURIPath. Either way, url.URL's normal percent-encoding of Path (spaces, '?', '#',
// and a literal '%' so a name like "has%41percent.db" round-trips instead of decoding to
// "hasApercent.db") is exactly what a "file:" URI needs for those characters; a drive letter's ':'
// is left unescaped (verified: it is not the first path segment once the URI has an authority, so
// net/url does not treat it as a scheme separator).
func sqliteFileURI(path, query string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolving %s to an absolute path: %w", path, err)
	}
	return fileURIFromAbsPath(abs, query, runtime.GOOS == "windows")
}

// fileURIFromAbsPath builds the "file:" URI string from abs (already made absolute by
// filepath.Abs) and query. windows is passed in explicitly, rather than read from runtime.GOOS
// inside this function, so it stays a pure function testable on any host OS with inputs of either
// flavour; sqliteFileURI is its only real caller and is what actually consults runtime.GOOS.
func fileURIFromAbsPath(abs, query string, windows bool) (string, error) {
	uriPath := abs
	if windows {
		p, err := windowsPathToURIPath(abs)
		if err != nil {
			return "", err
		}
		uriPath = p
	}
	u := url.URL{Scheme: "file", Path: uriPath, RawQuery: query}
	return u.String(), nil
}

// windowsPathToURIPath converts abs, an absolute Windows path exactly as filepath.Abs returns it
// when GOOS=windows (for example `C:\Users\a\s.sqlite`), into the path component of a "file:" URI
// per sqlite.org/uri.html: backslashes become forward slashes, and since a drive-letter path does
// not start with "/" once converted, one is prepended so that, combined with the URI's own "//"
// after the scheme, the result reads file:///C:/Users/a/s.sqlite (three slashes: empty authority,
// then the absolute path).
//
// A UNC path (`\\server\share\...`) is rejected with a clear error instead of guessed at: how many
// leading slashes a UNC path needs inside a file: URI to round-trip correctly through SQLite's own
// URI parser on Windows is not something verifiable without a real Windows and SQLite environment
// (this repository has none to test against), and a wrong URI that silently opens the wrong file,
// or none, is worse than refusing to start with a clear message naming the setting to fix.
func windowsPathToURIPath(abs string) (string, error) {
	if strings.HasPrefix(abs, `\\`) || strings.HasPrefix(abs, "//") {
		return "", fmt.Errorf("%s is a UNC path; UNC paths are not supported for the server database path, use a local drive path instead", abs)
	}
	slashed := strings.ReplaceAll(abs, `\`, "/")
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	return slashed, nil
}

// sqliteDSN builds the modernc.org/sqlite DSN for Open, passing journal_mode, foreign_keys and
// busy_timeout as DSN parameters instead of PRAGMA statements sent one by one after the connection
// opens. The driver applies _busy_timeout before _journal_mode and _foreign_keys regardless of the
// order the parameters appear in the DSN (its documented apply order in sqlite.go's
// applyQueryParams), so this puts the busy timeout into effect for every ordinary statement before
// journal_mode or foreign_keys run, instead of after them as the old three separate PRAGMA
// statements did (改訂の記録 2026-09-20). This alone does not cover the one case Open still retries
// by hand below: switching journal_mode to WAL for the first time.
func sqliteDSN(path string) (string, error) {
	return sqliteFileURI(path, "_busy_timeout=5000&_journal_mode=WAL&_foreign_keys=on")
}

// sqliteBusy is SQLite's SQLITE_BUSY primary result code (https://sqlite.org/rescode.html#busy), a
// stable part of the C API. modernc.org/sqlite's *Error exposes it via Code().
const sqliteBusy = 5

// isSQLiteBusy reports whether err is SQLITE_BUSY, in any of its extended forms. modernc.org/sqlite
// enables extended result codes on every connection (conn.go's newConn calls
// extendedResultCodes(true) unconditionally) and step()'s default case returns whatever raw code
// sqlite3_step gave it, so a busy failure can arrive as the plain primary code (5) or as one of the
// SQLITE_BUSY_* extended codes: BUSY_RECOVERY (261, another connection recovering a WAL file after
// a crash, exactly a restart-time case), BUSY_SNAPSHOT (517, a stale read snapshot) or BUSY_TIMEOUT
// (773, busy_timeout itself expired). All three still encode the primary code in the low byte
// (SQLite's rescode.html: extended = primary | (specific << 8)), so isSQLiteBusyCode's mask catches
// all four forms with one comparison. Verified empirically that a real busy_timeout expiry (a 200ms
// _busy_timeout against a lock held 1.5s) still came back as plain 5 with this driver/SQLite
// version (v1.58.0, SQLite 3.53.4); the mask does not rely on that continuing to be true.
func isSQLiteBusy(err error) bool {
	var sqliteErr *sqlitedrv.Error
	return errors.As(err, &sqliteErr) && isSQLiteBusyCode(sqliteErr.Code())
}

// isSQLiteBusyCode is isSQLiteBusy's comparison, split out so it can be unit tested against literal
// result codes: modernc.org/sqlite's *Error has no exported constructor, so a test cannot build one
// with an arbitrary Code() to exercise the mask directly.
func isSQLiteBusyCode(code int) bool {
	return code&0xff == sqliteBusy
}

// openBusyRetryWindow bounds how long Open retries a connection whose setup hit SQLITE_BUSY (see
// below). It matches _busy_timeout (5s): the two mechanisms cover the same total span, one for
// ordinary statements once a connection is up, this one for the one setup step that is not subject
// to the busy handler at all.
const openBusyRetryWindow = 5 * time.Second

// Open はファイルを開き(なければ 0600 で作り)、スキーマを最新にする。本体と WAL の補助ファイルに
// グループかその他の権限があれば外す(仕様 9 節)。
//
// journal_mode を初めて WAL に切り替える接続確立の 1 手だけは、busy_timeout を先に効かせても
// SQLite 自身がリトライしない(手を動かして確認した。busytimeout_test.go の
// TestJournalModeWALDoesNotHonorBusyTimeout)。他の統計値ではなく他のプロセスがまさにファイルを
// 保持している数ミリ秒(再起動、バイナリの入れ替え、`wgft server teardown`、CLI の一操作)に
// ぶつかると、SQLITE_BUSY で即座に失敗する。そのため、この 1 手(sqliteDSN の適用を含む接続の確立、
// つまり最初の migrate 呼び出し全体)だけは、SQLITE_BUSY を検出して自前で待ち直す
// (改訂の記録 2026-09-20)。sqliteDSN の busy_timeout は、確立した後の通常の文(migrate が送る他の
// 文、以後のすべてのクエリ)を短いロックから守る、両者は補い合う。
func Open(path string) (*Store, error) {
	if err := ensureCreated(path); err != nil {
		return nil, err
	}
	if err := narrowMode(path); err != nil {
		return nil, err
	}
	dsn, err := sqliteDSN(path)
	if err != nil {
		return nil, err
	}

	start := time.Now()
	var s *Store
	for {
		db, err := sql.Open("sqlite", dsn)
		if err != nil {
			return nil, err
		}
		// 単一プロセスからしか使わないので接続は 1 本にし、トランザクションの直列化を SQLite に任せる
		db.SetMaxOpenConns(1)
		s = &Store{db: db, filePath: path}
		migErr := s.migrate()
		if migErr == nil {
			break
		}
		db.Close()
		if !isSQLiteBusy(migErr) || time.Since(start) >= openBusyRetryWindow {
			return nil, migErr
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, p := range []string{path + "-wal", path + "-shm"} {
		if err := narrowMode(p); err != nil {
			s.db.Close()
			return nil, err
		}
	}
	return s, nil
}

// OpenReadOnly は、何も変えずに読むために開く(server check 用。仕様 9 節)。スキーマの移行、
// journal_mode の設定、権限の変更をしない。mode=ro だけでは SQLite が WAL の補助ファイルを作って
// 閉じた後も残すので、補助ファイルが無い(server が止まっていて全データが本体にある)ときは
// immutable=1 でロックも補助ファイルも使わずに読む。補助ファイルがあれば mode=ro で、WAL にだけある
// 書き込みも読む。どちらも書き込みは拒否される。
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, err
	}
	q := "mode=ro&_pragma=busy_timeout(5000)"
	if !exists(path+"-wal") && !exists(path+"-shm") {
		q += "&immutable=1"
	}
	dsn, err := sqliteFileURI(path, q)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		db.Close()
		return nil, err
	}
	if version > len(migrations) {
		db.Close()
		return nil, &SchemaNewerError{Version: version, MaxSupported: len(migrations)}
	}
	return &Store{db: db, filePath: path}, nil
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ensureCreated は、本体が無ければ 0600 で作る。umask は権限を狭めることしかないので、作った後に直す必要はない。
func ensureCreated(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return f.Close()
}

// ExtraPerm は、0600(所有者の読み書き)に含まれない権限。グループとその他の権限と、所有者の実行権がこれに当たる。
func ExtraPerm(m os.FileMode) os.FileMode { return m.Perm() &^ 0o600 }

// narrowMode は、ファイルがあれば ExtraPerm の権限だけを外す。所有者の権限は変えないので、
// 0644 は 0600 になり、管理者が 0400 にしたファイルは 0400 のまま残る(仕様 9 節)。
func narrowMode(path string) error {
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	old := fi.Mode().Perm()
	if ExtraPerm(old) == 0 {
		return nil
	}
	narrowed := old &^ ExtraPerm(old)
	if err := os.Chmod(path, narrowed); err != nil {
		return err
	}
	log.Printf("server database: narrowed mode of %s from %04o to %04o", path, old, narrowed)
	return nil
}

// Close は SQLite を閉じる。
func (s *Store) Close() error { return s.db.Close() }

// ErrSchemaNewer is returned by Open and OpenReadOnly when the database was written by a newer
// wgft, whose schema this binary does not know. Open's caller (internal/vpsd.Run) turns it into a
// startup refusal: no amount of restarting teaches an older binary a newer schema, only installing
// that binary again or restoring a copy of the database does (design.md 11b 節). OpenReadOnly's
// caller (internal/vpsd.Check, "server check") cannot refuse: its exit code stays 0 by design
// (design.md 7a.11 節), so it prints a dedicated line instead (改訂の記録参照).
var ErrSchemaNewer = errors.New("server database schema is newer than this binary")

// SchemaNewerError wraps ErrSchemaNewer with the two version numbers behind it, so a caller can
// build a message that names them without re-parsing Error()'s text.
type SchemaNewerError struct {
	// Version is PRAGMA user_version, as found in the database.
	Version int
	// MaxSupported is the highest schema version this binary knows, that is len(migrations).
	MaxSupported int
}

func (e *SchemaNewerError) Error() string {
	return fmt.Sprintf("%s: version %d, while this binary supports up to %d", ErrSchemaNewer, e.Version, e.MaxSupported)
}

func (e *SchemaNewerError) Unwrap() error { return ErrSchemaNewer }

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return &SchemaNewerError{Version: version, MaxSupported: len(migrations)}
	}
	for i := version; i < len(migrations); i++ {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(migrations[i]); err != nil {
			tx.Rollback()
			return fmt.Errorf("applying schema version %d: %w", i+1, err)
		}
		// PRAGMA はプレースホルダを受け付けない
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ErrNotFound は meta のキーがないときの誤り。
var ErrNotFound = errors.New("not found")

// GetMeta は meta の値を返す。なければ ErrNotFound。
func (s *Store) GetMeta(key string) ([]byte, error) {
	var v []byte
	err := s.db.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return v, err
}

// SetMeta は meta の値を置く。
func (s *Store) SetMeta(key string, value []byte) error {
	_, err := s.db.Exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

// GetOrCreateMeta は値があればそれを返し、なければ gen で作って保存してから返す。
// 初回起動でのサーバ秘密鍵の生成に使う。作成は 1 トランザクションで行い、同時起動で二重に作らない。
func (s *Store) GetOrCreateMeta(key string, gen func() ([]byte, error)) ([]byte, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var v []byte
	err = tx.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&v)
	if err == nil {
		return v, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if v, err = gen(); err != nil {
		return nil, err
	}
	if _, err := tx.Exec("INSERT INTO meta (key, value) VALUES (?, ?)", key, v); err != nil {
		return nil, err
	}
	return v, tx.Commit()
}
