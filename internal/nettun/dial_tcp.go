// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This file was copied from gVisor v0.0.0-20250503011706-39ed1f5ac29c, pkg/tcpip/adapters/gonet/gonet.go (DialTCPWithBind), and modified by the wgft authors: the local bind was removed, the endpoint is closed when the context is already done before Connect, and the result is the package's dialedConn, which keeps the endpoint but has no Abort.

// このファイルは、固定版の gVisor(gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c)の
// pkg/tcpip/adapters/gonet/gonet.go にある DialTCPWithBind を写したものである。上の著作権表示と
// Apache License 2.0 の注記は、その写しに対するものであり、wgft 自身のライセンス(MIT)とは別に
// 保つ。写した理由は、gonet の TCPConn が接続の tcpip.Endpoint を公開せず、vpsd が dial した接続に
// 閉じた後の endpoint の天井(tcp_closing.go)と keepalive を当てるには endpoint が要るためである
// (設計文書 7 節「閉じた後の TCP の endpoint の上限」)。写しからの変更は次の 3 つである。
// ローカルアドレスへの Bind を持たない(wgft は使わない)。Connect の前に ctx が済んでいた場合も
// endpoint を Close する(元は Close せずに戻る)。戻り値が endpoint を持つ dialedConn(Abort を持たない)である。

package nettun

import (
	"context"
	"errors"
	"net"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// dialTCP は remote へ接続し、その endpoint を持つ dialedConn を返す。
func (t *Device) dialTCP(ctx context.Context, remote tcpip.FullAddress) (*dialedConn, error) {
	// Create TCP endpoint, then connect.
	var wq waiter.Queue
	ep, err := t.stack.NewEndpoint(tcp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}

	// Create wait queue entry that notifies a channel.
	//
	// We do this unconditionally as Connect will always return an error.
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.WritableEvents)
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)

	select {
	case <-ctx.Done():
		ep.Close()
		return nil, ctx.Err()
	default:
	}

	err = ep.Connect(remote)
	if _, ok := err.(*tcpip.ErrConnectStarted); ok {
		select {
		case <-ctx.Done():
			ep.Close()
			return nil, ctx.Err()
		case <-notifyCh:
		}

		err = ep.LastError()
	}
	if err != nil {
		ep.Close()
		return nil, &net.OpError{
			Op:   "connect",
			Net:  "tcp",
			Addr: &net.TCPAddr{IP: net.IP(remote.Addr.AsSlice()), Port: int(remote.Port)},
			Err:  errors.New(err.String()),
		}
	}

	return &dialedConn{TCPConn: gonet.NewTCPConn(&wq, ep), ep: ep, dev: t}, nil
}
