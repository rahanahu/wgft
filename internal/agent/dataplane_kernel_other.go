//go:build !linux

package agent

import (
	"context"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/startup"
)

// kernelModeBuilt は、このビルドがカーネルモードの dataplane を持つかどうかである(mode.go)。
// カーネルモードは Linux だけである(仕様 7b.5 節)。
const kernelModeBuilt = false

// kernelPrerequisites は Linux 以外では何も確かめない。kernelModeBuilt が偽なので、enterMode は
// これを呼ぶ前に拒む。
var kernelPrerequisites = func() error { return nil }

// newKernelDataplane は Linux 以外では作れない。入口が kernel の指定を先に拒むので、ここには届かない。
func newKernelDataplane(context.Context, string, *allowtargets.List, *credentials.Credentials, func() error) (agentDataplane, error) {
	return nil, startup.Prerequisite("WGFT_MODE", "the agent's kernel mode needs Linux; leave WGFT_MODE unset or set it to userspace")
}
