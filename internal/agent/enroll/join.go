// Package enroll はエージェントの登録のクライアントの側である。接続文字列の解釈、証明書の SHA-256 で
// サーバを確かめる HTTP クライアント、登録 API の呼び出し、登録の結果の認証情報への記録を持つ(仕様 5.1 節)。
// internal/agent の初回の登録と登録のし直し、cmd/wgft の接続文字列の検査が使う。internal/agent は
// import しない(設計文書 7a.7 節)。
package enroll

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/startup"
)

// Join は接続文字列 wgft://host:port/token#sha256:<hex> の中身(仕様 5.1 節)。
type Join struct {
	Endpoint string // host:port(エージェント用 API)
	Token    string // 1 回限りの登録トークン
	Pin      [32]byte
	raw      string
}

// ParseJoin のエラーはこの 6 つの値のどれかに固定する(下記のコメントと FuzzParseJoin の不変条件)。
// どれも接続文字列のどの部分も引用しない。トークンは秘密であり(scripts/check-log-tokens.sh の
// 約束)、host:port の形が崩れた入力では、トークンがどの断片に入り込むか判別できないためである。例えば
// ポートも "/" も無い "wgft://<token>" は、url.Parse のもとで u.Host がトークンそのものになる。
// net.SplitHostPort が host と port を切り離した後でも、host の側がトークンの断片である可能性は残る
// (host の許す文字集合と、base64url でエンコードするトークンの文字集合が大きく重なるため)。したがって
// host を「ホスト名らしい」形で検査して引用してよいことにはしない。この 6 つを固定の値として持つのは、
// 新しいエラーを足す人が、うっかり %q や %s で入力の断片を差し込むのを防ぐためである。
var (
	errJoinScheme    = errors.New("join string must look like wgft://host:port/token#sha256:HASH")
	errJoinNoPort    = errors.New("join string host has no port")
	errJoinPortRange = errors.New("join string port must be a number from 1 to 65535")
	errJoinNoToken   = errors.New("join string has no token")
	errJoinNoPin     = errors.New("join string has no #sha256 certificate hash")
	errJoinBadPin    = errors.New("join string certificate hash is invalid")
)

// parseJoinErrors is every error ParseJoin can return, for FuzzParseJoin's invariant that a
// rejection is always one of these fixed values and never echoes the input.
var parseJoinErrors = []error{errJoinScheme, errJoinNoPort, errJoinPortRange, errJoinNoToken, errJoinNoPin, errJoinBadPin}

// ParseJoin は接続文字列を解釈する。scheme、ポート、sha256 のピンをすべて要求する。
func ParseJoin(s string) (*Join, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "wgft" {
		return nil, errJoinScheme
	}
	_, port, err := net.SplitHostPort(u.Host)
	if err != nil {
		return nil, errJoinNoPort
	}
	if portNum, perr := strconv.ParseUint(port, 10, 32); perr != nil || portNum < 1 || portNum > 65535 {
		return nil, errJoinPortRange
	}
	tok := strings.TrimPrefix(u.Path, "/")
	if tok == "" || strings.Contains(tok, "/") {
		return nil, errJoinNoToken
	}
	algo, hexPin, ok := strings.Cut(u.Fragment, ":")
	if !ok || algo != "sha256" {
		return nil, errJoinNoPin
	}
	pin, err := hex.DecodeString(hexPin)
	if err != nil || len(pin) != 32 {
		return nil, errJoinBadPin
	}
	j := &Join{Endpoint: u.Host, Token: tok, raw: s}
	copy(j.Pin[:], pin)
	return j, nil
}

// TokenHash は使用済みトークンの記録用(仕様 5.1 節の復帰経路で比較する)。
func (j *Join) TokenHash() string {
	h := sha256.Sum256([]byte(j.Token))
	return hex.EncodeToString(h[:])
}

// ErrPinMismatch はサーバ証明書がピンと一致しない。teardown --purge のあとに立て直したサーバか、経路上の
// 第三者による TLS の終端で起きる。復帰は未使用の WGFT_JOIN による再登録(仕様 5.1 節)。
var ErrPinMismatch = errors.New("server certificate does not match the pinned hash")

// PinnedClient は証明書の SHA-256 がピンと一致するときだけ通す HTTP クライアント。
// 通常の検証(CA、ホスト名、期限)は使わない。IP 直打ちでも DNS 名でも同じ接続文字列が使える。
func PinnedClient(pin [32]byte) *http.Client {
	tc := &tls.Config{
		InsecureSkipVerify: true, // ピン留めで代替する(下の VerifyConnection)
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return errors.New("no server certificate")
			}
			if got := sha256.Sum256(cs.PeerCertificates[0].Raw); got != pin {
				return fmt.Errorf("%w: got sha256 %x", ErrPinMismatch, got[:4])
			}
			return nil
		},
		MinVersion: tls.VersionTLS12,
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 15 * time.Second} // サーバは HTTP/1.1 だけ
}

// ErrRegisterRejected は登録が認証で拒否された(トークンが無効、名前違い)。
var ErrRegisterRejected = errors.New("registration rejected: join string already used or expired, or the name differs")

// Register は登録 API を呼び、恒久トークン、割り当てアドレス、確定した名前を返す。
// name は任意(空なら送らない側に倣ってトークンに紐付いた名前で登録される)。
func Register(ctx context.Context, j *Join, name string) (permanentToken, address, confirmedName string, err error) {
	body, _ := json.Marshal(map[string]string{"token": j.Token, "name": name})
	req, err := http.NewRequestWithContext(ctx, "POST", "https://"+j.Endpoint+"/api/v1/agents/register", bytes.NewReader(body))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := PinnedClient(j.Pin).Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("cannot reach the registration API: %w", err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	// The server's answer says whether a retry can help. 401, 400 and 409 are judgements on the
	// values this agent sent, and no number of restarts changes them: the token is spent or expired,
	// the name breaks the naming rule, or that name is taken. They become startup refusals (exit
	// code 3), so the shipped agent.service stops retrying instead of asking the registration API
	// every 2 seconds forever. Everything else - 429 from the API's own rate limit, a 5xx, an
	// unreachable VPS - stays an ordinary error (exit code 1), because the next attempt may work
	// (design.md 11b 節).
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return "", "", "", startup.Conflict("WGFT_JOIN", "%v. Issue a new join string on the VPS with wgft agent join-string, and replace WGFT_JOIN", ErrRegisterRejected)
	case resp.StatusCode == http.StatusBadRequest:
		return "", "", "", startup.Config("WGFT_NAME", "the registration API rejected the request: HTTP 400, %s; an agent name may hold only lowercase letters, digits and hyphens, at most 32 of them, and may not begin or end with a hyphen", bytes.TrimSpace(data))
	case resp.StatusCode == http.StatusConflict:
		return "", "", "", startup.Conflict("WGFT_JOIN", "an agent is already registered under the name this join string carries: HTTP 409, %s. "+
			"If that agent is running, on this host with another data directory or on another host, point WGFT_DATA_DIR at its directory instead; revoking it on the VPS cuts it off. "+
			"Otherwise revoke it with wgft agent revoke <name>, or issue a join string for another name", bytes.TrimSpace(data))
	case resp.StatusCode != http.StatusOK:
		return "", "", "", fmt.Errorf("registration API: HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(data))
	}
	var out struct {
		PermanentToken string `json:"permanent_token"`
		Address        string `json:"address"`
		Name           string `json:"name"`
	}
	if err := json.Unmarshal(data, &out); err != nil || out.PermanentToken == "" || out.Name == "" {
		return "", "", "", fmt.Errorf("registration API returned an invalid response")
	}
	return out.PermanentToken, out.Address, out.Name, nil
}
