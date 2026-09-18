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

	_ "modernc.org/sqlite"
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
	// v4:既知エンドポイント IP 集合(仕様 5.2 節)。エージェントの無効化で一緒に消す
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
}

// Open はファイルを開き(なければ 0600 で作り)、スキーマを最新にする。本体と WAL の補助ファイルに
// グループかその他の権限があれば外す(仕様 9 節)。
func Open(path string) (*Store, error) {
	if err := ensureCreated(path); err != nil {
		return nil, err
	}
	if err := narrowMode(path); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// 単一プロセスからしか使わないので接続は 1 本にし、トランザクションの直列化を SQLite に任せる
	db.SetMaxOpenConns(1)
	s := &Store{db: db, filePath: path}
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON", "PRAGMA busy_timeout=5000"} {
		if _, err := db.Exec(q); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", q, err)
		}
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	for _, p := range []string{path + "-wal", path + "-shm"} {
		if err := narrowMode(p); err != nil {
			db.Close()
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
	u := url.URL{Scheme: "file", Path: path, RawQuery: q}
	db, err := sql.Open("sqlite", u.String())
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
		return nil, fmt.Errorf("SQLite schema version %d is newer than this binary, which supports up to %d", version, len(migrations))
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

func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > len(migrations) {
		return fmt.Errorf("SQLite schema version %d is newer than this binary, which supports up to %d", version, len(migrations))
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
