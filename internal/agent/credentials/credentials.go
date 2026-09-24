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
	"time"

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

	// Mode は転送の方式の記録である(仕様 9・11a 節)。起動のたびに設定の WGFT_MODE と照合する。
	// 空はユーザー空間モードの記録とみなす。記録の無い既存のファイルはユーザー空間モードで動いてきたので、
	// ユーザー空間モードのエージェントはこの項目を書かない
	Mode string `json:"mode,omitempty"`
	// PreviousWGPrivateKey は 1 つ前の wg の秘密鍵である(仕様 7b.4 節)。カーネルモードでだけ持つ。
	// rotate-key の途中で落ちて鍵がずれた wgft0 や、停止中の rotate-key の後に古い鍵のまま残った
	// wgft0 を、自分のものと判定するために使う。次に鍵を変えるまで残す。base64
	PreviousWGPrivateKey string `json:"previous_wg_private_key,omitempty"`
	// IPForwardEnabledAt は、カーネルモードのエージェントが net.ipv4.ip_forward を 0 から 1 に変えた
	// 日時である(仕様 7b.1・9 節)。撤去が戻す候補として示すために残す。エージェント自身は値を 0 に
	// 戻さず、この記録も消さない。変えたことが無ければ nil
	IPForwardEnabledAt *time.Time `json:"ip_forward_enabled_at,omitempty"`
	// KernelPublication は、カーネルモードの直近の公開の結果である(仕様 7b.4・9 節)。テーブルの公開に
	// 成功するたびに書き換える。止まっている間の agent doctor が実際のテーブルと比べる。中身は
	// internal/dataplane/linuxkernel/nft の AgentPublication の JSON で、その package は Linux でしか
	// ビルドしないので、ここでは形を持たずに保存する
	KernelPublication json.RawMessage `json:"kernel_publication,omitempty"`
	// KernelUnconverged は、conntrack の収束が済んでいない前の公開の列である(仕様 7b.4 節)。古い順に
	// 並ぶ。収束に失敗している間だけ持ち、収束が済めば消す。再起動の後も、その公開で成立したフローを
	// wgft のものと見分けるために残す。中身は KernelPublication と同じ形の JSON の配列である
	KernelUnconverged json.RawMessage `json:"kernel_unconverged,omitempty"`
}

// PreviousKey は 1 つ前の wg の秘密鍵である。記録が無ければゼロの鍵を返す。ゼロの鍵はどの
// インタフェースも自分のものにしない(仕様 7b.4 節)。
func (f *Credentials) PreviousKey() (wgtypes.Key, error) {
	if f.PreviousWGPrivateKey == "" {
		return wgtypes.Key{}, nil
	}
	k, err := wgtypes.ParseKey(f.PreviousWGPrivateKey)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("previous_wg_private_key: %w", err)
	}
	return k, nil
}

// ModeKernel と ModeUserspace は Mode の値である(仕様 11a 節の WGFT_MODE と同じ語)。
const (
	ModeKernel    = "kernel"
	ModeUserspace = "userspace"
)

// RecordedMode は記録されたモードである。記録が無ければユーザー空間モードとみなす(仕様 9 節)。
func (f *Credentials) RecordedMode() string {
	if f.Mode == "" {
		return ModeUserspace
	}
	return f.Mode
}

// KeepPreviousKey は、今の鍵を 1 つ前の鍵として移す(仕様 7b.4 節)。今の鍵が空なら、1 つ前の鍵を
// 空の値で上書きせずに残す。停止中の rotate-key を続けて 2 回実行した場合がこれに当たる。
// カーネルモードの記録を持つファイルでだけ移す。ユーザー空間モードはカーネルに鍵を残さないので、
// 1 つ前の鍵を持つ理由が無い。
func (f *Credentials) KeepPreviousKey() {
	if f.RecordedMode() != ModeKernel || f.WGPrivateKey == "" {
		return
	}
	f.PreviousWGPrivateKey = f.WGPrivateKey
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
		return nil, fmt.Errorf("credentials file %s: %w", path, err)
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
	// createSecureTemp は、Windows では作成の瞬間から保護 DACL を付けた状態でファイルを作る
	// (os.CreateTemp してから締め直すのでは、締め直すまでの間に別の利用者がハンドルを開けて
	// しまう、緩い ACL のままの期間ができ、後から DACL を締めても取り消せない。レビュー指摘、仕様 11a 節)。
	// Unix では os.CreateTemp そのもので、作成の瞬間から 0600 であることに変わりはない。
	tmp, err := createSecureTemp(dir, tempPrefix+"*")
	if err != nil {
		return fmt.Errorf("create temp credentials file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename に成功していれば何も起きない
	// 秘密を書き込む前に、この一時ファイルだけを締める。Windows では createSecureTemp が
	// 既に締めているので、ここでの SecureFile は重ねての確認(冪等)にすぎない。Unix では
	// これが唯一の締めで、この手順は変えていない。同じディレクトリ内での rename はこの
	// ファイル自身の DACL(Windows)・パーミッション(Unix)をそのまま持ち越すので、緩い
	// ACL のまま秘密が書かれる期間は生じない。
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
	if saveBeforeRenameHook != nil {
		saveBeforeRenameHook(tmpName)
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
