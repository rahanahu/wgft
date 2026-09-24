//go:build !linux

package agent

import (
	"encoding/json"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/startup"
)

// defaultTeardownOps は Linux 以外では何も読まずに拒否する。カーネルモードは Linux だけであり
// (設計文書 7b.5 節)、入口(cmd/wgft)が先に拒むので、ここには届かない。
func defaultTeardownOps() teardownOps {
	refuse := func() error {
		return startup.Prerequisite("operating system", "the agent's kernel mode, which agent teardown cleans up after, runs on Linux only")
	}
	return teardownOps{
		inspectLock:  credentials.Inspect,
		acquire:      credentials.Acquire,
		keyHolders:   func(wgtypes.Key, wgtypes.Key) ([]string, error) { return nil, refuse() },
		link:         func(string, wgtypes.Key, wgtypes.Key) (linkState, error) { return linkState{}, refuse() },
		stagingName:  func(iface string) string { return iface },
		deleteLink:   func(string, wgtypes.Key, wgtypes.Key) (bool, error) { return false, refuse() },
		tablePresent: func() (bool, error) { return false, refuse() },
		deleteTable:  func() (bool, error) { return false, refuse() },
		closeFlows:   func([]json.RawMessage, string) (string, error) { return "", refuse() },
	}
}
