package agent

import (
	"log"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// rotateKey は wg 鍵対を作り直し、トンネルを新しい鍵で張り直し、stream を張り直す(新しい公開鍵を宣言する)。
func (rt *runtime) rotateKey() (wgtypes.Key, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	rt.mu.Lock()
	// カーネルモードでは、今の鍵を 1 つ前の鍵として新しい鍵と同じ保存で残す(仕様 7b.4 節)。wgft0 を
	// 新しい鍵へ書き換える前に落ちても、次の起動は 1 つ前の鍵で wgft0 を自分のものと判定できる。
	// 保存に失敗したら、メモリの上の 2 つの鍵も元に戻す。戻さないと、使われていない新しい鍵が今の鍵に、
	// 使っている鍵が 1 つ前の鍵に残り、次の rotate-key の後に落ちると、wgft0 の鍵はどちらとも一致しない
	oldKey, oldPrev := rt.f.WGPrivateKey, rt.f.PreviousWGPrivateKey
	rt.f.KeepPreviousKey()
	rt.f.WGPrivateKey = key.String()
	if err := rt.f.Save(rt.opts.CredentialsPath); err != nil {
		rt.f.WGPrivateKey, rt.f.PreviousWGPrivateKey = oldKey, oldPrev
		rt.mu.Unlock()
		return wgtypes.Key{}, err
	}
	rt.setPrivKey(key)
	last := rt.f.LastState
	rt.closeLocked()
	rt.mu.Unlock()
	log.Printf("regenerated wg key pair; public key: %s", key.PublicKey())
	if last != nil {
		if err := rt.apply(last); err != nil {
			log.Printf("wireguard: rebuild tunnel with the new key: %v", err)
		} else {
			log.Printf("wireguard: tunnel rebuilt with the new key")
		}
	}
	// stream を張り直すと streamOnce が新しい公開鍵を送る(stream: connected to ... で確認できる)
	rt.reconnect()
	return key.PublicKey(), nil
}
