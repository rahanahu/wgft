// Package credentials はエージェントの認証情報ファイル(agent.json)を扱う(仕様 9 節)。恒久トークン、wg の秘密鍵、
// 証明書のハッシュ、最後の全体状態を 1 ファイルに持つ。仕様書では「認証情報ファイル」と呼ぶ(仕様 3 節の用語)。
// 登録の情報、wg の秘密鍵、最後に処理した全体状態を持つ。
// 一時ファイルに書いて rename するので、途中でクラッシュしても壊れない。
package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/flock"
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
	// TunnelAddress は、登録で割り当てられたトンネルのアドレスの記録である(仕様 9・11 節)。形は 2 つある。
	// "10.200.0.2/24" は帯の長さまで記録したもので、"10.200.0.2" は登録の応答だけから記録し、帯の長さを
	// まだ知らないものである。登録の応答はアドレスだけを返すので、長さは最初に適用した全体状態から記録する。
	// 記録の無いファイル(この項目より前の版が書いたもの)も、最初に適用した全体状態から記録する。
	// カーネルモードのエージェントは、記録と違う wg.address を拒む(CheckTunnelAddress)。登録のし直しだけが
	// 記録を置き換え、撤去は消さない
	TunnelAddress string `json:"tunnel_address,omitempty"`
}

// RegisteredTunnelAddress は、登録の応答のアドレス addr を TunnelAddress の値に写す。応答はアドレスだけを
// 返すが、帯の長さの付いた形も受け付ける。どちらでもなければ空を返し、記録は最初に適用した全体状態を待つ。
func RegisteredTunnelAddress(addr string) string {
	if a, err := netip.ParseAddr(addr); err == nil && a.Unmap().Is4() {
		return a.Unmap().String()
	}
	if p, err := netip.ParsePrefix(addr); err == nil && p.Addr().Is4() {
		return p.String()
	}
	return ""
}

// TunnelAddressMismatch は、server から届いたトンネルのアドレスが記録と違うことを表す(仕様 11 節)。
// 記録が読めない場合も、比べられないので同じ誤りにする。
type TunnelAddressMismatch struct {
	Recorded string       // agent.json の tunnel_address
	Got      netip.Prefix // 全体状態の wg.address
}

func (e *TunnelAddressMismatch) Error() string {
	if _, ok := parseTunnelAddress(e.Recorded); !ok {
		return fmt.Sprintf("the server sent the tunnel address %s, and the tunnel address recorded in agent.json, %q, cannot be read to compare it with", e.Got, e.Recorded)
	}
	return fmt.Sprintf("the server sent the tunnel address %s, but agent.json records %s, the address this agent was registered with", e.Got, e.Recorded)
}

// recordedTunnel は TunnelAddress を読んだ値である。bits が -1 なら、帯の長さはまだ記録していない。
type recordedTunnel struct {
	addr netip.Addr
	bits int
}

func parseTunnelAddress(s string) (recordedTunnel, bool) {
	if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() {
		return recordedTunnel{p.Addr(), p.Bits()}, true
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
		return recordedTunnel{a, -1}, true
	}
	return recordedTunnel{}, false
}

// CheckTunnelAddress は、server から届いたトンネルのアドレス got を記録と照合する(仕様 11 節)。記録が
// 無ければ通す。帯の長さを記録していなければアドレスだけを、記録していれば長さまで比べる。違えば、
// または記録が読めなければ *TunnelAddressMismatch を返す。記録は書き換えない。
func (f *Credentials) CheckTunnelAddress(got netip.Prefix) error {
	if f.TunnelAddress == "" {
		return nil
	}
	rec, ok := parseTunnelAddress(f.TunnelAddress)
	if !ok || rec.addr != got.Addr() || (rec.bits >= 0 && rec.bits != got.Bits()) {
		return &TunnelAddressMismatch{Recorded: f.TunnelAddress, Got: got}
	}
	return nil
}

// RecordTunnelAddress は、適用できたトンネルのアドレス p を記録する。記録が無いか、帯の長さを記録して
// いない同じアドレスの記録なら p で置き換えて真を返す。記録と違う p では何もしない。記録を置き換える
// のは、ここと登録だけである。
func (f *Credentials) RecordTunnelAddress(p netip.Prefix) bool {
	if f.CheckTunnelAddress(p) != nil || f.TunnelAddress == p.String() {
		return false
	}
	f.TunnelAddress = p.String()
	return true
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

// MaxFileSize は認証情報ファイルの大きさの上限である(仕様 9 節)。Load と ReadFile はこれより大きい
// ファイルを読まずに拒み、Save はこれより大きい中身を書かずに拒む。wgft が書いたファイルを wgft が
// 読めなくなることはない。
//
// 値は、エージェントが書きうる最大の大きさを上回るように決める。last_state は制御ストリームの
// 1 通の読み取りの上限の内に収まる。カーネルモードの公開の記録は、直近の公開と、収束が済んでいない
// 前の公開の列の上限の数の分だけ並び、1 つの公開の大きさは last_state のルールの数で決まる。許可一覧が
// 範囲のルールを多数の範囲に分ける場合と、公開しなかった理由の文言の長さは見積もりの外である(仕様 9 節)。
// 見積もりの外で上限を超える中身は、Save が誤りとして拒む。
// 最大の大きさの見積もりと、この値が上回ることは、internal/agent のテスト
// TestCredentialsFileSizeLimitCoversTheLargestFile が確かめる。
const MaxFileSize = 512 << 20

// fileSizeLimit は読み書きで使う上限である。値は MaxFileSize で、テストだけが小さくする。
var fileSizeLimit int64 = MaxFileSize

// ErrTooLarge は、認証情報ファイルが MaxFileSize を超えることを示す。
var ErrTooLarge = errors.New("the credentials file is larger than wgft ever writes")

// ReadFile は認証情報ファイルの中身を読む。最後の要素が symlink なら辿らず、通常のファイルでなければ
// 拒み、MaxFileSize を超えれば読まずに拒む(仕様 9・11 節)。種別と大きさは開いた記述子で確かめる。
// 返す FileInfo はその記述子の fstat である。root の CLI は、エージェントの利用者が書けるデータ
// ディレクトリの agent.json を読むので、パスの先を信頼しない。無ければ os.ErrNotExist を包んだ誤りを返す。
// 中身の締め直しはしないので、副作用を持たない読み取り(agent doctor)にも使える。
func ReadFile(path string) ([]byte, os.FileInfo, error) {
	fh, fi, err := flock.OpenRegular(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	defer fh.Close()
	b, err := readLimited(fh, fi, path)
	if err != nil {
		return nil, nil, err
	}
	return b, fi, nil
}

// readLimited は開いた認証情報ファイルを fileSizeLimit まで読む。fstat の大きさで先に拒み、読んでいる
// 間に伸びた場合も上限を超えた時点で拒む。
func readLimited(fh *os.File, fi os.FileInfo, path string) ([]byte, error) {
	if fi.Size() > fileSizeLimit {
		return nil, fmt.Errorf("%s is %d bytes: %w", path, fi.Size(), ErrTooLarge)
	}
	b, err := io.ReadAll(io.LimitReader(fh, fileSizeLimit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > fileSizeLimit {
		return nil, fmt.Errorf("%s grew while being read: %w", path, ErrTooLarge)
	}
	return b, nil
}

// Load はファイルを読む。なければ os.ErrNotExist。読み方の制限は ReadFile と同じである。Windows では、
// この修正より前に緩い ACL の下で作られていた既存のファイルがありうるため、読むたびに secureExisting で
// 単独に締め直す(仕様 9・11a 節)。締め直しは開いたファイルを閉じる前に行う。Windows の os.OpenFile は
// 削除の共有を許さずに開くので、開いている間はその名前を別のファイルに差し替えられず、締め直すのは
// 種別を確かめたファイルである。隣のファイルやディレクトリには触れない。Unix では secureExisting は
// 何もしない no-op で、この修正の前後で Load の挙動は変わらない(Unix の chmod はこの修正
// より前から機能しており、締め直す理由が無いうえ、管理者が意図して絞った権限を緩めたり、
// ファイルを所有しない構成で失敗させたりしないため)。
func Load(path string) (*Credentials, error) {
	fh, fi, err := flock.OpenRegular(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	b, err := readLimited(fh, fi, path)
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
//
// root の CLI(停止中の rotate-key、agent pubkey、agent teardown)も Save を呼ぶ。データディレクトリは
// エージェントの利用者のもので、その利用者は一時ファイルや path の名前を書き込みの途中で差し替えられる。
// そのため、一時ファイルの権限と持ち主はパスではなく開いた記述子に対して設定する。path が既にあれば
// Lstat で種別を確かめ、通常のファイルでなければ何も書かずに拒む(仕様 9・11 節)。
func (f *Credentials) Save(path string) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if int64(len(b)) > fileSizeLimit {
		return fmt.Errorf("the credentials file %s would be %d bytes: %w", path, len(b), ErrTooLarge)
	}
	old, err := existingRegular(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	// createSecureTemp は、Windows では作成の瞬間から保護 DACL を付けた状態でファイルを作る
	// (os.CreateTemp してから締め直すのでは、締め直すまでの間に別の利用者がハンドルを開けて
	// しまう、緩い ACL のままの期間ができ、後から DACL を締めても取り消せない。レビュー指摘、仕様 11a 節)。
	// Unix では os.CreateTemp そのもので、作成の瞬間から 0600 であることに変わりはない。
	// どちらも既存の名前を開かずに新しく作るので、symlink を辿らない。
	tmp, err := createSecureTemp(dir, tempPrefix+"*")
	if err != nil {
		return fmt.Errorf("create temp credentials file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename に成功していれば何も起きない
	if saveAfterCreateHook != nil {
		saveAfterCreateHook(tmpName)
	}
	// 秘密を書き込む前に、この一時ファイルだけを締める。Windows では createSecureTemp が
	// 既に締めているので、ここでの締めは重ねての確認(冪等)にすぎない。Unix では
	// これが唯一の締めである。同じディレクトリ内での rename はこのファイル自身の
	// DACL(Windows)・パーミッション(Unix)をそのまま持ち越すので、緩い
	// ACL のまま秘密が書かれる期間は生じない。
	if err := secureTemp(tmp); err != nil {
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
	if err := keepOwner(tmp, old, path); err != nil {
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

// existingRegular は、置き換える前の path を Lstat で見る。無ければ nil を返す。symlink、FIFO、デバイス、
// ディレクトリなら flock.ErrNotRegular を包んだ誤りを返す。Lstat は symlink を辿らないので、root の
// Save が symlink の先の持ち主を読むことはない。
func existingRegular(path string) (os.FileInfo, error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file, so it was left untouched: %w", path, flock.ErrNotRegular)
	}
	return fi, nil
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
