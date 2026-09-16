package agent

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
	"strings"
	"time"
)

// Join は接続文字列 wgft://host:port/token#sha256:<hex> の中身(仕様 5.1 節)。
type Join struct {
	Endpoint string // host:port(エージェント用 API)
	Token    string // 1 回限りの登録トークン
	Pin      [32]byte
	raw      string
}

// ParseJoin は接続文字列を解釈する。scheme、ポート、sha256 のピンをすべて要求する。
func ParseJoin(s string) (*Join, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme != "wgft" {
		return nil, errors.New("join string must look like wgft://host:port/token#sha256:HASH")
	}
	if _, _, err := net.SplitHostPort(u.Host); err != nil {
		return nil, fmt.Errorf("join string host has no port: %q", u.Host)
	}
	tok := strings.TrimPrefix(u.Path, "/")
	if tok == "" || strings.Contains(tok, "/") {
		return nil, errors.New("join string has no token")
	}
	algo, hexPin, ok := strings.Cut(u.Fragment, ":")
	if !ok || algo != "sha256" {
		return nil, errors.New("join string has no #sha256 certificate hash")
	}
	pin, err := hex.DecodeString(hexPin)
	if err != nil || len(pin) != 32 {
		return nil, errors.New("join string certificate hash is invalid")
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
				return fmt.Errorf("server certificate sha256 %x does not match the join string hash", got[:4])
			}
			return nil
		},
		MinVersion: tls.VersionTLS12,
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc, ForceAttemptHTTP2: true}, Timeout: 15 * time.Second}
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
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return "", "", "", ErrRegisterRejected
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
