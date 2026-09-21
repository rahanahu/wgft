//go:build linux

package vpsd

import (
	"github.com/rahanahu/wgft/proto"
	"log"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Register は agentapi.Backend の実装(仕様 5.1 節)。この時点では wg ピアはまだ作らない。
// name が空ならトークンに紐付いた名前で登録し、確定した名前を返す。
func (d *Daemon) Register(joinToken, name, from string) (string, string, netip.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tok, a, err := d.st.Register(joinToken, name, from, d.network)
	if err != nil {
		return "", "", netip.Addr{}, err
	}
	// アドレスが決まったので、この名前のルール(無効化中は行を持たなかった)を nftables に戻す
	if rules, err := d.st.Rules(); err == nil {
		if err := d.applyNFT(rules); err != nil {
			log.Printf("applying nftables after registration: %v", err)
		}
	}
	return tok, a.Name, a.Address, nil
}

// Authenticate / ServerPublicKey / OtherAgentHasKey / SetPublicKey / StateFor は stream.Backend の実装。
func (d *Daemon) Authenticate(token string) (string, error) {
	a, err := d.st.AuthenticateAgent(token)
	if err != nil {
		return "", err
	}
	return a.Name, nil
}

func (d *Daemon) ServerPublicKey() wgtypes.Key { return d.serverKey.PublicKey() }

func (d *Daemon) OtherAgentHasKey(agent string, key wgtypes.Key) (bool, error) {
	list, err := d.st.Agents()
	if err != nil {
		return false, err
	}
	for _, a := range list {
		if a.Name != agent && a.PublicKey == key.String() {
			return true, nil
		}
	}
	return false, nil
}

// SetPublicKey は宣言された公開鍵を保存し、wg0 のピアを置き換える(初回なら作る)。ピアの変更は
// トランザクション(applyNFT)の一部で、新しいピアをテーブルの差し替えの前に足し、古いピアを差し替えの
// 後に外す(設計文書 7a.3 節)。テーブルの中身は変わらない(アドレスは同じ)が、差し替えは行う。
func (d *Daemon) SetPublicKey(agent string, key wgtypes.Key) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	cur, err := d.st.AgentByName(agent)
	if err != nil {
		return err
	}
	if cur.PublicKey == key.String() {
		return nil
	}
	if err := d.st.SetAgentPublicKey(agent, key.String()); err != nil {
		return err
	}
	if cur.PublicKey == "" {
		log.Printf("agent %s declared its public key", agent)
	} else {
		log.Printf("agent %s rotated its public key", agent)
	}
	rules, err := d.st.Rules()
	if err != nil {
		return err
	}
	return d.applyNFT(rules)
}

// StateFor は stream.Backend の実装。AgentState が組み立てた全体状態に、sel(この接続で交渉した
// 版と機能。仕様 7a.6 節)を足す。sel.Legacy な agent には版のフィールドを載せない(今の形のまま)。
func (d *Daemon) StateFor(agent string, sel proto.Negotiated) (*proto.State, error) {
	st, err := d.AgentState(agent)
	if err != nil {
		return nil, err
	}
	if !sel.Legacy {
		version := sel.Version
		caps := proto.SupportedCapabilities
		st.ServerProtocolVersion = &version
		st.ServerCapabilities = &caps
	}
	return st, nil
}
