package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"time"
)

// agentNamePattern はエージェント名の文字種(仕様 5.1 節。DNS ラベル相当)。
// 英小文字・数字・ハイフンのみで、先頭と末尾はハイフン以外、最大 32 文字。
var agentNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$`)

// ValidAgentName はエージェント名が仕様 5.1 節の文字種に合うか。
// 名前はログ、CLI の表、UI、状態ファイルに出るため、改行や制御文字を含む名前を通さない。
func ValidAgentName(name string) bool {
	return agentNamePattern.MatchString(name)
}

// Agent は登録済みのエージェント。
type Agent struct {
	Name           string
	Address        netip.Addr
	PublicKey      string // base64。未接続なら空
	CreatedAt      time.Time
	RegisteredFrom string
}

// ErrInvalidToken はトークンが無効(未知、使用済み、期限切れ、名前違い)。
// 理由を分けて返すと総当たりの手がかりになるので、外向きには 1 つにまとめる。
var ErrInvalidToken = errors.New("invalid token")

// ErrAgentAlreadyRegistered は、登録トークンは有効だが、紐付いた名前のエージェントが
// すでに存在する(仕様 5.1 節)。IssueJoinToken と RevokeAgent が発行済みの未使用トークンを
// 無効化するので通常は起きないが、起きたときは 500 にせず、呼び出し側が個別に扱えるようにする。
var ErrAgentAlreadyRegistered = errors.New("agent already registered")

// NewToken は 128 ビットの乱数トークンを base64(URL 安全、パディングなし)で返す。
func NewToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func tokenHash(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// IssueJoinToken は名前に紐付いた 1 回限りの登録トークンを発行する。
// 同じ名前のエージェントがすでにいれば拒否する(無効化して名前を空けてから発行する)。
// 同じ名前に対する以前の未使用トークンはすべて無効化し、新しく発行した 1 本だけを有効にする
// (発行し直した後は、古い接続文字列が残っていても登録に使えない)。
func (s *Store) IssueJoinToken(agent string, ttl time.Duration) (string, error) {
	if agent == "" {
		return "", errors.New("agent name is empty")
	}
	if !ValidAgentName(agent) {
		return "", fmt.Errorf("agent name %q must match %s, DNS-label style: lowercase letters, digits and hyphens, not starting or ending with a hyphen, 32 characters max", agent, agentNamePattern)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	var n int
	if err := tx.QueryRow("SELECT count(*) FROM agents WHERE name = ?", agent).Scan(&n); err != nil {
		return "", err
	}
	if n > 0 {
		return "", fmt.Errorf("agent %q is already registered; revoke it before issuing", agent)
	}
	if _, err := tx.Exec("DELETE FROM join_tokens WHERE agent = ? AND used_at IS NULL", agent); err != nil {
		return "", err
	}
	tok, err := NewToken()
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec("INSERT INTO join_tokens (token_hash, agent, expires_at) VALUES (?, ?, ?)",
		tokenHash(tok), agent, time.Now().Add(ttl).Unix()); err != nil {
		return "", err
	}
	return tok, tx.Commit()
}

// Register は登録トークンを使ってエージェントを作り、恒久トークンを返す(仕様 5.1 節)。
// name が空ならトークンに紐付いた名前で登録する。name があってトークンに紐付いた名前と違えば ErrInvalidToken。
// トークンは有効でも、紐付いた名前のエージェントがすでにいれば ErrAgentAlreadyRegistered
// (IssueJoinToken と RevokeAgent が未使用トークンを無効化するので通常は起きないが、
// 起きても PRIMARY KEY 違反で 500 にせず、区別できる誤りとして返す)。
// 返す Agent.Name は確定した名前(トークンに紐付いた名前)。
// トークンの照合、名前の照合、アドレスの割り当て、トークンの使用済み化を 1 トランザクションで行う。
func (s *Store) Register(joinToken, name, from string, network netip.Prefix) (permanentToken string, agent *Agent, err error) {
	tx, err := s.db.Begin()
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()

	var (
		boundName string
		expiresAt int64
		usedAt    sql.NullInt64
	)
	err = tx.QueryRow("SELECT agent, expires_at, used_at FROM join_tokens WHERE token_hash = ?", tokenHash(joinToken)).Scan(&boundName, &expiresAt, &usedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrInvalidToken
	}
	if err != nil {
		return "", nil, err
	}
	now := time.Now()
	// 名前を送らなければトークンに紐付いた名前で登録する。送った場合の比較も定数時間で
	// (トークンが当たっていても名前で情報を漏らさない)
	if usedAt.Valid || now.Unix() > expiresAt {
		return "", nil, ErrInvalidToken
	}
	if name != "" && subtle.ConstantTimeCompare([]byte(boundName), []byte(name)) != 1 {
		return "", nil, ErrInvalidToken
	}
	name = boundName
	var existing int
	if err := tx.QueryRow("SELECT count(*) FROM agents WHERE name = ?", name).Scan(&existing); err != nil {
		return "", nil, err
	}
	if existing > 0 {
		return "", nil, ErrAgentAlreadyRegistered
	}
	addr, err := allocateAddress(tx, network)
	if err != nil {
		return "", nil, err
	}
	permanentToken, err = NewToken()
	if err != nil {
		return "", nil, err
	}
	if _, err := tx.Exec("INSERT INTO agents (name, address, token_hash, created_at, registered_from) VALUES (?, ?, ?, ?, ?)",
		name, addr.String(), tokenHash(permanentToken), now.Unix(), from); err != nil {
		return "", nil, err
	}
	if _, err := tx.Exec("UPDATE join_tokens SET used_at = ? WHERE token_hash = ?", now.Unix(), tokenHash(joinToken)); err != nil {
		return "", nil, err
	}
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	return permanentToken, &Agent{Name: name, Address: addr, CreatedAt: now, RegisteredFrom: from}, nil
}

// allocateAddress は network(10.200.0.0/24)の .2 以降で、使われていない最小のアドレスを返す。
// 無効化で回収されたアドレスは再利用される。
func allocateAddress(q querier, network netip.Prefix) (netip.Addr, error) {
	rows, err := q.Query("SELECT address FROM agents")
	if err != nil {
		return netip.Addr{}, err
	}
	defer rows.Close()
	used := map[netip.Addr]bool{}
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return netip.Addr{}, err
		}
		addr, err := netip.ParseAddr(a)
		if err != nil {
			// 解釈できない行を「使われていない」とみなすと、既にその行が持っているアドレスを
			// 新しいエージェントに二重に割り当てかねない(design.md 10.5 節)。安全側に倒し、
			// 割り当てそのものを拒む。
			return netip.Addr{}, fmt.Errorf("agents table has a row with an unparseable address %q: %w", a, err)
		}
		used[addr] = true
	}
	net := network.Masked()
	// .0 はネットワーク、.1 は vpsd。ブロードキャストの手前まで
	for a := net.Addr().Next().Next(); net.Contains(a); a = a.Next() {
		if last := a.Next(); !net.Contains(last) {
			break // ブロードキャストアドレス
		}
		if !used[a] {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no free address in %s", network)
}

// InvalidAgentNames は agents.name のうち仕様 5.1 節の文字種に合わないものを返す(起動時の警告用)。
// 検証は後から加えたので、それ以前に登録した名前が残っていることがある。消さずに警告だけする。
func (s *Store) InvalidAgentNames() ([]string, error) {
	rows, err := s.db.Query("SELECT name FROM agents")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		if !ValidAgentName(n) {
			out = append(out, n)
		}
	}
	return out, rows.Err()
}

// AuthenticateAgent は恒久トークンからエージェントを引く。なければ ErrInvalidToken。
func (s *Store) AuthenticateAgent(permanentToken string) (*Agent, error) {
	a, err := s.agentBy("token_hash = ?", tokenHash(permanentToken))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrInvalidToken
	}
	return a, err
}

// AgentByName は名前でエージェントを引く。なければ sql.ErrNoRows。
func (s *Store) AgentByName(name string) (*Agent, error) {
	return s.agentBy("name = ?", name)
}

func (s *Store) agentBy(where string, arg any) (*Agent, error) {
	var (
		a       Agent
		addr    string
		pub     sql.NullString
		created int64
	)
	err := s.db.QueryRow("SELECT name, address, public_key, created_at, registered_from FROM agents WHERE "+where, arg).
		Scan(&a.Name, &addr, &pub, &created, &a.RegisteredFrom)
	if err != nil {
		return nil, err
	}
	// a.Address feeds the wg peer AllowedIPs and the admin API/UI directly (vpsd.go's agents(),
	// admin_backend.go's Agents()). A row that cannot be parsed must not silently become the zero
	// address and flow into that plan as if it were a real, unused address (design.md 10.5 節).
	if a.Address, err = netip.ParseAddr(addr); err != nil {
		return nil, fmt.Errorf("agent %s: stored address %q: %w", a.Name, addr, err)
	}
	a.PublicKey = pub.String
	a.CreatedAt = time.Unix(created, 0)
	return &a, nil
}

// Agents は登録済みのエージェントを名前順で返す。
func (s *Store) Agents() ([]Agent, error) {
	rows, err := s.db.Query("SELECT name, address, public_key, created_at, registered_from FROM agents ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Agent
	for rows.Next() {
		var (
			a       Agent
			addr    string
			pub     sql.NullString
			created int64
		)
		if err := rows.Scan(&a.Name, &addr, &pub, &created, &a.RegisteredFrom); err != nil {
			return nil, err
		}
		// agentBy と同じ理由(上のコメント参照): 読めないアドレスを零値のまま先へ進めない。
		if a.Address, err = netip.ParseAddr(addr); err != nil {
			return nil, fmt.Errorf("agent %s: stored address %q: %w", a.Name, addr, err)
		}
		a.PublicKey = pub.String
		a.CreatedAt = time.Unix(created, 0)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetAgentPublicKey は stream で宣言された公開鍵を保存する(正本はエージェント側。仕様 9 節)。
func (s *Store) SetAgentPublicKey(name, publicKey string) error {
	_, err := s.db.Exec("UPDATE agents SET public_key = ? WHERE name = ?", publicKey, name)
	return err
}

// RevokeAgent は恒久トークンを無効化する(エージェントの行ごと消し、アドレスを回収する。仕様 11 節)。
// 名前は新しい接続文字列で再利用できる。その名前に対して発行済みの未使用トークンも合わせて
// 無効化するので、無効化の前に発行され、まだ使われていない古い接続文字列では登録できない。
func (s *Store) RevokeAgent(name string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.Exec("DELETE FROM agents WHERE name = ?", name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("agent %q not found", name)
	}
	if _, err := tx.Exec("DELETE FROM join_tokens WHERE agent = ? AND used_at IS NULL", name); err != nil {
		return err
	}
	return tx.Commit()
}

// PurgeExpiredJoinTokens は期限切れと使用済みの登録トークンを消す。
func (s *Store) PurgeExpiredJoinTokens() error {
	_, err := s.db.Exec("DELETE FROM join_tokens WHERE used_at IS NOT NULL OR expires_at < ?", time.Now().Unix())
	return err
}
