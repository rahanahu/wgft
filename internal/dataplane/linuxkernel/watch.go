//go:build linux

package linuxkernel

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/nftables"
	mdnetlink "github.com/mdlayher/netlink"
	"github.com/vishvananda/netlink"

	"github.com/rahanahu/wgft/internal/dataplane"
)

var (
	_ dataplane.Sensor = (*Backend)(nil)
	_ dataplane.Sensor = Notifications{}
)

// Notifications is the same subscription as Backend.Watch, for a control plane that converges the
// kernel without a Backend: the agent's kernel mode (design.md 7b.4 節: 変更の通知). It holds no
// state, so its zero value is ready to use.
type Notifications struct{}

// Watch is Backend.Watch; see there.
func (Notifications) Watch(ctx context.Context, wake func()) error { return watch(ctx, wake) }

// notifyReceiveBuffer is the receive buffer requested for the netlink socket that carries the
// nftables change notifications (NFNLGRP_NFTABLES) subscribed below. Publishing a large Admission
// Policy source list creates a set with thousands of elements (design.md 7a.4 節), and the kernel's
// notification of that change can arrive as more data than the socket's default receive buffer
// (net.core.rmem_default, normally 212992 bytes) holds; the kernel then drops it and returns
// ENOBUFS from the read, the same wall internal/dataplane/linuxkernel/nft/batch.go documents and
// sizes around for a Commit's reply socket. Sized generously and bounded the same way: a fixed
// request well above the default, clamped so it never asks the kernel for an unbounded amount.
// Requested with SO_RCVBUFFORCE where the process has CAP_NET_ADMIN in the init user namespace,
// and falls back to SO_RCVBUF (capped at 2x net.core.rmem_max) otherwise; see batch.go's sizeSocket
// for the same fallback on the reply socket. Losing this subscription is not silent either way:
// Watch below reports the failure once and the caller resubscribes within about 1 s (design.md
// 7a.3 節 安全網).
const notifyReceiveBuffer = 8 << 20 // 8 MiB: comfortable headroom over a several-thousand-element set's notification.

// sizeNotifySocket requests notifyReceiveBuffer for c's receive buffer. It never fails c's dial:
// see notifyReceiveBuffer's comment for why a request that falls back to SO_RCVBUF, or that the
// kernel otherwise cannot grant, still leaves the subscription usable.
func sizeNotifySocket(c *mdnetlink.Conn) error {
	_ = c.SetReadBuffer(notifyReceiveBuffer)
	return nil
}

// Watch subscribes to the kernel's change notifications that can mean the kernel no longer has
// what the last Commit left (design.md 7a.3 節: 実際の状態への収束), and calls wake after each:
//
//   - nftables changes (NFNLGRP_NFTABLES on NETLINK_NETFILTER, what `nft monitor` reads), one wake
//     per nftables transaction: a rule, set, chain or table edited or deleted, `flush ruleset`, or
//     another process's table inet wgft released when that process exits
//   - link changes (RTNLGRP_LINK), such as the wg interface deleted or set down
//   - IPv4 address changes (RTNLGRP_IPV4_IFADDR), such as the wg interface's address removed
//
// The notifications are never read for what they say; any of them only wakes the control plane,
// which then Observes. wgft's own Commits notify too, and the Observe after them finds no drift.
// WireGuard itself has no notifications (a peer removed with `wg set` sends none); the periodic
// Observe of the control plane catches those.
//
// Watch returns nil when ctx is done. A failed subscription (a receive buffer overflow, ENOBUFS,
// loses notifications) wakes once more and returns the error, for the caller to restart it.
func (b *Backend) Watch(ctx context.Context, wake func()) error { return watch(ctx, wake) }

func watch(ctx context.Context, wake func()) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	failed := make(chan error, 3)
	fail := func(err error) {
		wake()
		select {
		case failed <- err:
		default:
		}
	}

	conn, err := nftables.New(nftables.WithSockOptions(sizeNotifySocket))
	if err != nil {
		return fmt.Errorf("nftables notifications: %w", err)
	}
	mon := nftables.NewMonitor(nftables.WithMonitorEventBuffer(64))
	events, err := conn.AddGenerationalMonitor(mon)
	if err != nil {
		return fmt.Errorf("nftables notifications: %w", err)
	}
	defer mon.Close()
	go func() {
		// 読み続ける。止めると monitor の goroutine が送信で詰まり、Close の後も残る
		var gone error = errors.New("stopped")
		for ev := range events {
			if ev.GeneratedBy != nil && ev.GeneratedBy.Type == nftables.MonitorEventTypeOOB && ev.GeneratedBy.Error != nil {
				gone = ev.GeneratedBy.Error
				continue
			}
			wake()
		}
		fail(fmt.Errorf("nftables notifications: %w", gone))
	}()

	done := make(chan struct{})
	defer close(done)
	var mu sync.Mutex
	var lastErr error
	onErr := func(err error) {
		mu.Lock()
		lastErr = err
		mu.Unlock()
	}
	stopped := func(what string) error {
		mu.Lock()
		defer mu.Unlock()
		if lastErr != nil {
			return fmt.Errorf("%s notifications: %w", what, lastErr)
		}
		return fmt.Errorf("%s notifications: stopped", what)
	}
	links := make(chan netlink.LinkUpdate, 64)
	if err := netlink.LinkSubscribeWithOptions(links, done, netlink.LinkSubscribeOptions{ErrorCallback: onErr}); err != nil {
		return fmt.Errorf("link notifications: %w", err)
	}
	go func() {
		for range links {
			wake()
		}
		fail(stopped("link"))
	}()
	addrs := make(chan netlink.AddrUpdate, 64)
	if err := netlink.AddrSubscribeWithOptions(addrs, done, netlink.AddrSubscribeOptions{ErrorCallback: onErr}); err != nil {
		return fmt.Errorf("address notifications: %w", err)
	}
	go func() {
		for range addrs {
			wake()
		}
		fail(stopped("address"))
	}()

	select {
	case <-ctx.Done():
		return nil
	case err := <-failed:
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}
