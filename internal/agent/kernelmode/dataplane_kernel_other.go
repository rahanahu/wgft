//go:build !linux

package kernelmode

import (
	"context"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/startup"
)

// Built は、このビルドがカーネルモードの dataplane を持つかどうかである(internal/agent の mode.go)。
// カーネルモードは Linux だけである(仕様 7b.5 節)。
const Built = false

// Prerequisites は Linux 以外では何も確かめない。Built が偽なので、internal/agent の enterMode は
// これを呼ぶ前に拒む。
var Prerequisites = func() error { return nil }

// New は Linux 以外では作れない。入口が kernel の指定を先に拒むので、ここには届かない。
func New(context.Context, string, *allowtargets.List, *credentials.Credentials, func() error) (agentdp.Dataplane, error) {
	return nil, startup.Prerequisite("WGFT_MODE", "the agent's kernel mode needs Linux; leave WGFT_MODE unset or set it to userspace")
}
