package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/rahanahu/wgft/proto"
)

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

// httpClient は Base に応じたクライアント。unix:// はソケットへダイヤルする。
func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	if socket, ok := strings.CutPrefix(c.Base, "unix://"); ok {
		return &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		}}
	}
	return http.DefaultClient
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
		if strings.Contains(err.Error(), "permission denied") {
			return fmt.Errorf("cannot access the admin api socket; run with sudo: %w", err)
		}
		return fmt.Errorf("cannot connect to admin api %s; this command is used against the admin api on the VPS, is server run running: %w", c.Base, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var e ErrorBody
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
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

// Revoke は恒久トークンを無効化し、ピアとアドレスを回収する(仕様 11 節)。
func (c *Client) Revoke(name string) error {
	return c.do("DELETE", "/api/v1/agents/"+name, nil, nil)
}

// Warnings は窃取検知の警告一覧を取る(仕様 5.2 節)。
func (c *Client) Warnings() ([]Warning, error) {
	var out []Warning
	return out, c.do("GET", "/api/v1/warnings", nil, &out)
}

// DismissWarning は警告 1 件を消す。再検出されれば再び出る。
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
