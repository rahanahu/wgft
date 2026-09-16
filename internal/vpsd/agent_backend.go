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

// SetPublicKey は宣言された公開鍵を保存し、wg0 のピアを置き換える(初回なら作る)。
// 公開鍵が変われば古いピアは Ensure が消す。テーブルは変わらない(アドレスは同じ)。
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
	return d.reconcileWG()
}

func (d *Daemon) StateFor(agent string) (*proto.State, error) { return d.AgentState(agent) }
