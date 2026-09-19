package linuxkernel

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/google/nftables"
	"github.com/vishvananda/netlink"

	"github.com/rahanahu/wgft/internal/dataplane"
)

var _ dataplane.Sensor = (*Backend)(nil)

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
func (b *Backend) Watch(ctx context.Context, wake func()) error {
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

	conn, err := nftables.New()
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
