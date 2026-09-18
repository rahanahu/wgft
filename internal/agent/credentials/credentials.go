// Package credentials はエージェントの認証情報ファイル(agent.json)を扱う(仕様 9 節)。恒久トークン、wg の秘密鍵、
// 証明書のハッシュ、最後の全体状態を 1 ファイルに持つ。仕様書では「認証情報ファイル」と呼ぶ(仕様 3 節の用語)。
// 登録の情報、wg の秘密鍵、最後に処理した全体状態を持つ。
// 一時ファイルに書いて rename するので、途中でクラッシュしても壊れない。
package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/proto"
)

// Credentials は認証情報ファイルの中身。
type Credentials struct {
	Name                string       `json:"name"`                   // エージェント名(登録時に確定)
	Endpoint            string       `json:"endpoint"`               // エージェント用 API の host:port
	CertSHA256          string       `json:"cert_sha256"`            // エージェント用 API の証明書のハッシュ(hex)
	PermanentToken      string       `json:"permanent_token"`        // 恒久トークン
	UsedJoinTokenSHA256 string       `json:"used_join_token_sha256"` // 使用済み登録トークンのハッシュ(仕様 5.1 節)
	WGPrivateKey        string       `json:"wg_private_key"`         // base64
	LastState           *proto.State `json:"last_state"`             // 最後に処理した全体状態
}

// Load はファイルを読む。なければ os.ErrNotExist。Windows では、この修正より前に緩い ACL の
// 下で作られていた既存のファイルがありうるため、読むたびに secureExisting で単独に締め直す
// (仕様 9・11a 節)。隣のファイルやディレクトリには触れない。Unix では secureExisting は
// 何もしない no-op で、この修正の前後で Load の挙動は変わらない(Unix の chmod はこの修正
// より前から機能しており、締め直す理由が無いうえ、管理者が意図して絞った権限を緩めたり、
// ファイルを所有しない構成で失敗させたりしないため)。
func Load(path string) (*Credentials, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := secureExisting(path); err != nil {
		return nil, fmt.Errorf("secure credentials file: %w", err)
	}
	var f Credentials
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("state file %s: %w", path, err)
	}
	return &f, nil
}

// LoadOrNew はファイルを読み、なければ空の Credentials を返す。
func LoadOrNew(path string) (*Credentials, error) {
	f, err := Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return &Credentials{}, nil
	}
	return f, err
}

// Save は一時ファイルに書いて rename する。パーミッションは 0600(Windows は保護 DACL。
// 仕様 9・11a 節)。
func (f *Credentials) Save(path string) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".wgft-state-*")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename に成功していれば何も起きない
	// 秘密を書き込む前に、この一時ファイルだけを締める。同じディレクトリ内での rename は
	// このファイル自身の DACL(Windows)・パーミッション(Unix)をそのまま持ち越すので、
	// 緩い ACL のまま秘密が書かれる期間は生じない。
	if err := SecureFile(tmpName); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// EnsureKey は wg 鍵対がなければ生成する。鍵を作り直すのは agent rotate-key だけ。
func (f *Credentials) EnsureKey() (created bool, err error) {
	if f.WGPrivateKey != "" {
		_, err := f.PrivateKey()
		return false, err
	}
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return false, err
	}
	f.WGPrivateKey = k.String()
	return true, nil
}

// PrivateKey は wg の秘密鍵。
func (f *Credentials) PrivateKey() (wgtypes.Key, error) {
	k, err := wgtypes.ParseKey(f.WGPrivateKey)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("wg_private_key: %w", err)
	}
	return k, nil
}
