package agent

import (
	"errors"
	"os"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// errKeyNotSavedYet は、別のプロセスがロックを持っていて、認証情報ファイルに鍵がまだ無いことを示す。
// ロックの持ち主はエージェントとは限らない。起動の途中で鍵をまだ保存していないエージェントのほか、
// 停止中に書いている別の CLI(別の agent pubkey や停止中の rotate-key)でもありうる。どちらでも、
// 少し後に実行し直せば鍵を読める。
var errKeyNotSavedYet = errors.New("the credentials file has no key yet and another process is using the data directory, " +
	"such as an agent that is still starting; run this again in a moment")

// publicKeyLockedHook は、停止中の agent pubkey が鍵を保存した後、ロックを放す前に呼ばれる。
// テストだけが、読んでから書き終えるまでロックを持っていることを確かめるために設定する。
var publicKeyLockedHook func()

// PublicKey は認証情報ファイルの鍵の公開鍵を返す。エージェントが止まっていて鍵が無ければ、生成して
// 保存する。別のプロセスがロックを持っていれば読むだけで書かない(仕様 9 節)。排他の取り方は停止中の
// rotate-key と同じで、lockWhileStopped にある。
func PublicKey(path string) (wgtypes.Key, error) {
	release, running, err := lockWhileStopped(path)
	if err != nil {
		return wgtypes.Key{}, err
	}
	if running {
		return lockedPublicKey(path)
	}
	defer release()
	f, err := credentials.LoadOrNew(path)
	if err != nil {
		return wgtypes.Key{}, err
	}
	created, err := f.EnsureKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	if created {
		if err := f.Save(path); err != nil {
			return wgtypes.Key{}, err
		}
	}
	if publicKeyLockedHook != nil {
		publicKeyLockedHook()
	}
	priv, err := f.PrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	return priv.PublicKey(), nil
}

// lockedPublicKey は、別のプロセスがロックを持つ間に、認証情報ファイルから公開鍵を読む。鍵が無くても
// 作らない。ファイルがまだ無い場合も、鍵が無い場合と同じに扱う。一度も起動していないデータディレクトリで、
// ユーザー空間モードのエージェントがロックを取ってから最初に保存するまでの間がこれに当たる。
// 稼働中のエージェントは起動の途中で鍵を作って保存し、rotate-key でも新しい鍵を保存してから使うので、
// 保存済みの鍵はエージェントが使う鍵である。
func lockedPublicKey(path string) (wgtypes.Key, error) {
	f, err := credentials.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		return wgtypes.Key{}, errKeyNotSavedYet
	}
	if err != nil {
		return wgtypes.Key{}, err
	}
	if f.WGPrivateKey == "" {
		return wgtypes.Key{}, errKeyNotSavedYet
	}
	priv, err := f.PrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	return priv.PublicKey(), nil
}
