package store

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestJoinAndRegister(t *testing.T) {
	s := openTemp(t)
	net := netip.MustParsePrefix("10.200.0.0/24")

	tok, err := s.IssueJoinToken("home", time.Hour)
	if err != nil || len(tok) < 20 {
		t.Fatalf("issue: %q %v", tok, err)
	}
	// 名前違い
	if _, _, err := s.Register(tok, "office", "203.0.113.2", net); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("wrong name: %v", err)
	}
	// 未知のトークン
	if _, _, err := s.Register("nope", "home", "203.0.113.2", net); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("unknown token: %v", err)
	}
	perm, a, err := s.Register(tok, "home", "203.0.113.2", net)
	if err != nil || a.Address != netip.MustParseAddr("10.200.0.2") || a.RegisteredFrom != "203.0.113.2" {
		t.Fatalf("register: %+v %v", a, err)
	}
	// 2 回目は使用済み
	if _, _, err := s.Register(tok, "home", "203.0.113.2", net); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("reuse: %v", err)
	}
	// 恒久トークンで引ける。間違いは ErrInvalidToken
	if got, err := s.AuthenticateAgent(perm); err != nil || got.Name != "home" {
		t.Errorf("auth: %+v %v", got, err)
	}
	if _, err := s.AuthenticateAgent(perm + "x"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("bad perm: %v", err)
	}
	// 同じ名前への発行は拒否
	if _, err := s.IssueJoinToken("home", time.Hour); err == nil {
		t.Error("duplicate name must be rejected")
	}
	// 2 つ目は .3
	tok2, _ := s.IssueJoinToken("office", time.Hour)
	_, b, err := s.Register(tok2, "office", "198.51.100.7", net)
	if err != nil || b.Address != netip.MustParseAddr("10.200.0.3") {
		t.Fatalf("second: %+v %v", b, err)
	}
	// 削除で回収 → 次の登録は .2 を再利用し、名前も再利用できる
	if err := s.RevokeAgent("home"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateAgent(perm); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("revoked token must be invalid: %v", err)
	}
	tok3, err := s.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, c, err := s.Register(tok3, "home", "203.0.113.2", net)
	if err != nil || c.Address != netip.MustParseAddr("10.200.0.2") {
		t.Fatalf("reuse address: %+v %v", c, err)
	}
	if err := s.SetAgentPublicKey("home", "PUBKEY"); err != nil {
		t.Fatal(err)
	}
	agents, _ := s.Agents()
	if len(agents) != 2 || agents[0].Name != "home" || agents[0].PublicKey != "PUBKEY" || agents[1].Name != "office" {
		t.Errorf("agents: %+v", agents)
	}
}

// 名前を送らない登録は成功し、トークンに紐付いた名前が確定する。
func TestRegisterWithoutName(t *testing.T) {
	s := openTemp(t)
	net := netip.MustParsePrefix("10.200.0.0/24")

	tok, err := s.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, a, err := s.Register(tok, "", "203.0.113.2", net)
	if err != nil || a.Name != "home" {
		t.Fatalf("register without name: %+v %v", a, err)
	}
}

// TestIssueJoinTokenValidatesName は、接続文字列の発行を、仕様 5.1 節の文字種で拒否する。
func TestIssueJoinTokenValidatesName(t *testing.T) {
	s := openTemp(t)
	bad := []string{
		"Home",                  // 大文字
		"has space",             // 空白
		"new\nline",             // 改行
		strings.Repeat("a", 33), // 仕様 5.1 節の正規表現([a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?)が許す最大の 32 文字を超える
		"-leading",              // 先頭がハイフン
		"trailing-",             // 末尾がハイフン
	}
	for _, n := range bad {
		if _, err := s.IssueJoinToken(n, time.Hour); err == nil {
			t.Errorf("name %q: want error, got nil", n)
		}
	}
	// 境界: 正規表現が許す最大の 32 文字はちょうど許される
	if _, err := s.IssueJoinToken(strings.Repeat("a", 32), time.Hour); err != nil {
		t.Errorf("32-char name should be valid: %v", err)
	}
}

// TestInvalidAgentNames は、既存の SQLite にある不正な名前を、消さずに検出する。
func TestInvalidAgentNames(t *testing.T) {
	s := openTemp(t)
	net := netip.MustParsePrefix("10.200.0.0/24")
	// 検証を通った名前で 1 件登録する
	tok, err := s.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(tok, "home", "x", net); err != nil {
		t.Fatal(err)
	}
	// 検証より前に登録されたような不正な名前を直接書き込む(移行前のデータを模す)
	if _, err := s.db.Exec("INSERT INTO agents (name, address, token_hash, created_at, registered_from) VALUES (?, ?, ?, ?, ?)",
		"Bad Name\n", "10.200.0.9", []byte("x"), time.Now().Unix(), "x"); err != nil {
		t.Fatal(err)
	}
	bad, err := s.InvalidAgentNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 1 || bad[0] != "Bad Name\n" {
		t.Errorf("InvalidAgentNames = %q, want [\"Bad Name\\n\"]", bad)
	}
	// 消さない
	agents, err := s.Agents()
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 2 {
		t.Errorf("bad name must not be deleted: %d agents", len(agents))
	}
}

// TestAgentsRejectsUnparseableAddress は、agents テーブルの address 列が壊れている(手での書き
// 換えや取り違いを想定)ときに、Agents() がその行を空/零アドレスとして黙って返さず、読み取り
// 全体を失敗として返すことを確かめる(design.md 10.5 節)。零アドレスのまま先へ進むと、wg の
// ピア構成やアドレスの再割り当て判定にそのまま使われてしまう。
func TestAgentsRejectsUnparseableAddress(t *testing.T) {
	s := openTemp(t)
	net := netip.MustParsePrefix("10.200.0.0/24")
	tok, err := s.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(tok, "home", "x", net); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE agents SET address = ? WHERE name = ?", "not-an-address", "home"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Agents(); err == nil {
		t.Fatal("Agents() with a corrupt stored address returned no error; a corrupt row must not silently become the zero address")
	}
	if _, err := s.AgentByName("home"); err == nil {
		t.Fatal("AgentByName() with a corrupt stored address returned no error")
	}
}

// TestAllocateAddressRejectsUnparseableAddress は、既存の行に解釈できないアドレスがあるとき、
// allocateAddress がその行を「使われていない」とみなして新しいエージェントに同じアドレスを
// 割り当ててしまわないことを確かめる(design.md 10.5 節)。
func TestAllocateAddressRejectsUnparseableAddress(t *testing.T) {
	s := openTemp(t)
	net := netip.MustParsePrefix("10.200.0.0/24")
	tok, err := s.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(tok, "home", "x", net); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE agents SET address = ? WHERE name = ?", "garbage", "home"); err != nil {
		t.Fatal(err)
	}
	tok2, err := s.IssueJoinToken("office", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(tok2, "office", "y", net); err == nil {
		t.Fatal("Register() allocated a new address while an existing row's address could not be confirmed as used; want a refusal, not a possible address collision")
	}
}

func TestJoinTokenExpiry(t *testing.T) {
	s := openTemp(t)
	tok, _ := s.IssueJoinToken("home", -time.Second) // すでに期限切れ
	if _, _, err := s.Register(tok, "home", "x", netip.MustParsePrefix("10.200.0.0/24")); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expired: %v", err)
	}
	if err := s.PurgeExpiredJoinTokens(); err != nil {
		t.Fatal(err)
	}
}

// 名前に対して 2 本目のトークンを発行すると、1 本目(未使用)は無効化され、新しい方だけが使える。
func TestIssueJoinTokenSupersedesPreviousUnused(t *testing.T) {
	s := openTemp(t)
	net := netip.MustParsePrefix("10.200.0.0/24")

	tok1, err := s.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok2, err := s.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if tok1 == tok2 {
		t.Fatal("expected two distinct tokens")
	}
	// 1 本目はもう無効(古いトークンで登録しても、後から 2 本目で登録したときに
	// PRIMARY KEY 違反にならない)
	if _, _, err := s.Register(tok1, "home", "203.0.113.1", net); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("superseded token must be invalid: %v", err)
	}
	if _, a, err := s.Register(tok2, "home", "203.0.113.1", net); err != nil || a.Name != "home" {
		t.Fatalf("newest token must register: %+v %v", a, err)
	}
}

// エージェントの削除は、その名前に対する発行済みの未使用トークンも無効化する。
// (レースや移行前のデータで、登録済みの名前に対する未使用トークンが残っている場合を
// 直接作り、削除がそれを掃除することを確かめる)
func TestRevokeAgentInvalidatesOutstandingJoinToken(t *testing.T) {
	s := openTemp(t)
	net := netip.MustParsePrefix("10.200.0.0/24")

	tok1, err := s.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(tok1, "home", "203.0.113.1", net); err != nil {
		t.Fatal(err)
	}
	// 未使用の残存トークンを直接作る(通常は起きないが、レースや旧データを模す)
	leftover, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO join_tokens (token_hash, agent, expires_at) VALUES (?, ?, ?)",
		tokenHash(leftover), "home", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if err := s.RevokeAgent("home"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(leftover, "home", "203.0.113.2", net); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("leftover token must be invalid after revoke: %v", err)
	}
}

// 有効なトークンでも、紐付いた名前のエージェントがすでにいれば、PRIMARY KEY 違反の
// 生の SQL 誤りではなく ErrAgentAlreadyRegistered を返す。
func TestRegisterAgentAlreadyRegistered(t *testing.T) {
	s := openTemp(t)
	net := netip.MustParsePrefix("10.200.0.0/24")

	tok1, err := s.IssueJoinToken("home", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(tok1, "home", "203.0.113.1", net); err != nil {
		t.Fatal(err)
	}
	// 登録済みの名前に対する 2 本目の有効なトークンを直接作る(レースや旧データを模す。
	// IssueJoinToken はエージェントが存在する名前への発行を拒否するので、通常のこの経路では作れない)
	extra, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("INSERT INTO join_tokens (token_hash, agent, expires_at) VALUES (?, ?, ?)",
		tokenHash(extra), "home", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Register(extra, "home", "203.0.113.2", net); !errors.Is(err, ErrAgentAlreadyRegistered) {
		t.Errorf("register with a name that already has an agent: %v, want ErrAgentAlreadyRegistered", err)
	}
}

func TestAllocateAddressExhaustion(t *testing.T) {
	s := openTemp(t)
	net := netip.MustParsePrefix("10.200.0.0/30") // .1 が vpsd、.2 だけ空き、.3 はブロードキャスト
	tok, _ := s.IssueJoinToken("a", time.Hour)
	if _, a, err := s.Register(tok, "a", "x", net); err != nil || a.Address != netip.MustParseAddr("10.200.0.2") {
		t.Fatalf("first: %+v %v", a, err)
	}
	tok2, _ := s.IssueJoinToken("b", time.Hour)
	if _, _, err := s.Register(tok2, "b", "x", net); err == nil {
		t.Error("exhaustion must fail")
	}
}
