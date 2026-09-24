package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/rahanahu/wgft/proto"
)

// clientTimeout は Client の既定の HTTP タイムアウト(仕様 11 節)。CLI のどの操作も、この時間内で
// 終わる応答しか待たない。管理用 API の応答はどれも束縛されている(バッチの本文の上限、ルール
// 一覧、TCP の疎通確認は server 側の dial の期限が既定 5 秒)ので、30 秒はどの正当な呼び出しにも
// 十分な余裕がある。HTTP を明示的に注入した呼び出し元(テストなど)はこの既定を受けない。
const clientTimeout = 30 * time.Second

// Client は CLI が使う管理用 API のクライアント。Base は http://host:port か
// unix:///path/to.sock(Unix ソケット。既定)。パスワードは持たない(仕様 11 節)。
type Client struct {
	Base string
	HTTP *http.Client
}

// requestURL は実際に投げる URL。Unix ソケットのときは Host を localhost にして
// サーバの Host 検査を通す(ダイヤル先はソケット)。
func (c *Client) requestURL(path string) string {
	if strings.HasPrefix(c.Base, "unix://") {
		return "http://localhost" + path
	}
	base := c.Base
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base // 素の host:port を許す
	}
	return base + path
}

// httpClient は Base に応じたクライアント。unix:// はソケットへダイヤルする。既定は clientTimeout
// で打ち切る(HTTP を注入していれば、それをそのまま使い、打ち切らない)。
func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	if socket, ok := strings.CutPrefix(c.Base, "unix://"); ok {
		return &http.Client{
			Timeout: clientTimeout,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "unix", socket)
				},
			},
		}
	}
	return &http.Client{Timeout: clientTimeout}
}

func (c *Client) do(method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.requestURL(path), body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		// os.ErrPermission is the portable sentinel: on Linux and macOS, syscall.Errno.Is maps
		// EACCES/EPERM to it, and on Windows the same happens for ERROR_ACCESS_DENIED, so this
		// works across every OS this package builds for. A string match risked misreading any
		// dial error whose text happened to mention "permission denied" for an unrelated reason.
		if errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("cannot access the admin api socket; run with sudo: %w", err)
		}
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return fmt.Errorf("admin api %s did not respond within %s; the server may be stuck or overloaded: %w", c.Base, clientTimeout, err)
		}
		return fmt.Errorf("cannot connect to admin api %s; this command is used against the admin api on the VPS, is server run running: %w", c.Base, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e ErrorBody
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			// 422 の saved は、エージェントの無効化と有効化が何も保存しなかったのか、保存は済んだが
			// 公開していないのかを表す(設計文書 7a.11 節)。呼び出し側が errors.As で読めるよう型に戻す
			if resp.StatusCode == http.StatusUnprocessableEntity && e.Saved != nil {
				return &AgentChangeError{Saved: *e.Saved, Err: errors.New(e.Error)}
			}
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, bytes.TrimSpace(data))
	}
	if out == nil {
		return nil
	}
	if s, ok := out.(*string); ok {
		*s = string(data)
		return nil
	}
	return json.Unmarshal(data, out)
}

// Rules は全ルールと世代と累積の拒否数を取る。
func (c *Client) Rules() (*BatchResponse, error) {
	var out BatchResponse
	return &out, c.do("GET", "/api/v1/rules", nil, &out)
}

// Batch は追加・変更・削除を 1 トランザクションで適用する(仕様 5.4 節)。
func (c *Client) Batch(req BatchRequest) (*BatchResponse, error) {
	var out BatchResponse
	return &out, c.do("POST", "/api/v1/rules/batch", req, &out)
}

// Agents は登録済みエージェントの一覧と接続状態を取る。
func (c *Client) Agents() ([]AgentInfo, error) {
	var out []AgentInfo
	return out, c.do("GET", "/api/v1/agents", nil, &out)
}

// JoinString は名前に紐付いた接続文字列を発行する(仕様 5.1 節)。
func (c *Client) JoinString(name string) (*JoinStringResponse, error) {
	var out JoinStringResponse
	return &out, c.do("POST", "/api/v1/agents/join-string", JoinStringRequest{Name: name}, &out)
}

// Revoke はエージェントを削除する。恒久トークンを使えなくし、ピアとアドレスを回収する(仕様 5.1、11 節)。
func (c *Client) Revoke(name string) error {
	return c.do("DELETE", "/api/v1/agents/"+name, nil, nil)
}

// DisableAgent はエージェントを無効にする(仕様 5.1 節)。422 の誤りは *AgentChangeError で、
// Saved が保存は済んだが公開していないことを表す。
func (c *Client) DisableAgent(name string) (*AgentDisabledResponse, error) {
	var out AgentDisabledResponse
	return &out, c.do("POST", "/api/v1/agents/"+name+"/disable", nil, &out)
}

// EnableAgent はエージェントを有効に戻す(仕様 5.1 節)。422 の誤りは *AgentChangeError で、
// Saved が false なら書き込みの時の検査が拒み、何も保存していない。
func (c *Client) EnableAgent(name string) (*AgentDisabledResponse, error) {
	var out AgentDisabledResponse
	return &out, c.do("POST", "/api/v1/agents/"+name+"/enable", nil, &out)
}

// Warnings は窃取検知の警告一覧を取る(仕様 5.2 節)。
func (c *Client) Warnings() ([]Warning, error) {
	var out []Warning
	return out, c.do("GET", "/api/v1/warnings", nil, &out)
}

// DismissWarning は警告を消す。ip-flapping は再検出されれば再び出る。ip-mismatch は消した警告の
// 2 つの IP の組を server が確認済みとして記録し、同じ組の食い違いが続く間は出さない(仕様 5.2 節)。
func (c *Client) DismissWarning(name, kind, detail string) error {
	return c.do("POST", "/api/v1/agents/"+name+"/dismiss-warning", map[string]string{"kind": kind, "detail": detail}, nil)
}

// CheckConnectivity は TCP ルールの疎通確認を server に依頼する(仕様 10.1 節)。
func (c *Client) CheckConnectivity(ruleID string) (*ConnCheck, error) {
	var out ConnCheck
	return &out, c.do("POST", "/api/v1/rules/"+ruleID+"/check", struct{}{}, &out)
}

// AgentState はそのエージェントに配られる全体状態を取る(確認用)。
func (c *Client) AgentState(name string) (*proto.State, error) {
	var out proto.State
	return &out, c.do("GET", "/api/v1/agents/"+name+"/state", nil, &out)
}

// NFT は適用中の table inet wgft を nft の表示形式で取る。
func (c *Client) NFT() (string, error) {
	var out string
	return out, c.do("GET", "/api/v1/nft", nil, &out)
}

// ServerInfo は vpsd/VPS の構成と環境を取る(仕様 10.1 節)。`rule add`/`rule set` の
// `--dry-run` はこれを使って proto.Reserved を組み立て、実際の Batch が拒む予約ポートと
// 同じ判定にする(design.md 11a 節)。
func (c *Client) ServerInfo() (*ServerInfo, error) {
	var out ServerInfo
	return &out, c.do("GET", "/api/v1/server", nil, &out)
}
