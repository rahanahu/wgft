package agent

import (
	"errors"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// errKeyNotSavedYet は、稼働中のエージェントがまだ鍵を認証情報ファイルに保存していないことを示す。
// 起動の途中、鍵を作って保存するまでの間に当たる。
var errKeyNotSavedYet = errors.New("the running agent has not saved its key to the credentials file yet; it is still starting, so run this again in a moment")

// publicKeyLockedHook は、停止中の agent pubkey が認証情報ファイルを読んだ後、書く前に呼ばれる。
// テストだけが、この区間でロックを持っていることを確かめるために設定する。
var publicKeyLockedHook func()

// PublicKey は認証情報ファイルの鍵の公開鍵を返す。エージェントが止まっていて鍵が無ければ、生成して
// 保存する。稼働中なら読むだけで書かない(仕様 9 節)。排他の取り方は停止中の rotate-key と同じで、
// lockWhileStopped にある。
func PublicKey(path string) (wgtypes.Key, error) {
	release, running, err := lockWhileStopped(path)
	if err != nil {
		return wgtypes.Key{}, err
	}
	if running {
		return runningPublicKey(path)
	}
	defer release()
	f, err := credentials.LoadOrNew(path)
	if err != nil {
		return wgtypes.Key{}, err
	}
	if publicKeyLockedHook != nil {
		publicKeyLockedHook()
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
	priv, err := f.PrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	return priv.PublicKey(), nil
}

// runningPublicKey は、稼働中のエージェントの認証情報ファイルから公開鍵を読む。鍵が無くても作らない。
// 稼働中のエージェントは起動の途中で鍵を作って保存し、rotate-key でも新しい鍵を保存してから使うので、
// 保存済みの鍵はエージェントが使う鍵である。
func runningPublicKey(path string) (wgtypes.Key, error) {
	f, err := credentials.Load(path)
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
