//go:build linux

package agent

import (
	"encoding/json"
	"fmt"
	"net/netip"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	ctconv "github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
)

func defaultTeardownOps() teardownOps {
	return teardownOps{
		inspectLock: credentials.Inspect,
		acquire:     credentials.Acquire,
		keyHolders: func(current, previous wgtypes.Key) ([]string, error) {
			// 空の名前のインタフェースは無いので、どの名前も除かずに数える
			return wg.AgentKeyHolders("", current, previous)
		},
		link:        teardownLink,
		stagingName: wg.AgentStagingName,
		wireGuardLinks: func() ([]string, error) {
			// ゼロの鍵を 2 つ渡すと AgentKeyHolders は何も返さないので、ここでは名前を直接並べる
			return wg.KernelDeviceNames()
		},
		deleteLink:   teardownDeleteLink,
		tablePresent: nft.AgentTablePresent,
		deleteTable:  nft.DeleteAgentTable,
		closeFlows:   teardownCloseFlows,
	}
}

// teardownLink は名前で見たリンクを撤去の判定に写す。
func teardownLink(name string, current, previous wgtypes.Key) (linkState, error) {
	st, err := wg.InspectAgent(name, current, previous)
	if err != nil {
		return linkState{}, err
	}
	var addr string
	if len(st.Addresses) > 0 {
		addr = st.Addresses[0].String()
	}
	switch st.Ownership {
	case wg.Absent:
		return linkState{owner: linkAbsent}, nil
	case wg.OwnedByCurrentKey:
		return linkState{owner: linkCurrentKey, address: addr}, nil
	case wg.OwnedByPreviousKey:
		return linkState{owner: linkPreviousKey, address: addr}, nil
	case wg.NotWireGuard:
		return linkState{owner: linkNotWireGuard, kind: st.Kind}, nil
	}
	if st.PublicKey == (wgtypes.Key{}) {
		return linkState{owner: linkKeyless}, nil
	}
	return linkState{owner: linkForeignKey}, nil
}

// teardownDeleteLink は、name が今か前の鍵を持つときだけ消す。判定の後に鍵が変わっていれば消さずに
// 誤りを返す。
func teardownDeleteLink(name string, current, previous wgtypes.Key) (bool, error) {
	own, deleted, err := wg.DeleteAgentLink(name, current, previous)
	if err != nil {
		return false, err
	}
	if own == wg.Absent {
		return false, nil
	}
	return deleted, nil
}

// teardownCloseFlows は、公開の記録を前の公開とし、空の公開を今の公開として conntrack の収束を走らせる
// (設計文書 7b.4・10.3 節)。前の公開のどれかが宣言したフローは、今の公開が宣言しないので消える。
// 許可一覧は渡さない。空の公開に合うフローは無いので、許可一覧で残るフローも無い。
func teardownCloseFlows(raw []json.RawMessage, address string) (string, error) {
	pubs := make([]nft.AgentPublication, 0, len(raw))
	for _, r := range raw {
		var p nft.AgentPublication
		if err := json.Unmarshal(r, &p); err != nil {
			return "", fmt.Errorf("the publication record in agent.json cannot be read: %w", err)
		}
		pubs = append(pubs, p)
	}
	prefix, err := netip.ParsePrefix(address)
	if err != nil || !prefix.Addr().Is4() {
		return "", fmt.Errorf("the tunnel address %q in last_state is not an IPv4 prefix", address)
	}
	scope := ctconv.AgentScope{Local: prefix.Addr(), Peer: prefix.Masked().Addr().Next()}
	res, err := ctconv.ConvergeAgent(pubs, nft.AgentPublication{}, scope)
	if err != nil {
		return "", err
	}
	return res.String(), nil
}
