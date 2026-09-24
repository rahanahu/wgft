package agent

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/proto"
)

// fakeSensedDataplane は、通知の後の見直しを呼ばれた時刻を記録する dataplane である。
type fakeSensedDataplane struct {
	*fakeDataplane
	mu    sync.Mutex
	calls []time.Time
}

func (d *fakeSensedDataplane) sensor() dataplane.Sensor { return nil }
func (d *fakeSensedDataplane) observeNotified(uint64, []proto.AgentRule) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls = append(d.calls, time.Now())
	return false, nil
}
func (d *fakeSensedDataplane) observed() []time.Time {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]time.Time(nil), d.calls...)
}

// serve は、続けて届いたカーネルの変更の通知を、最初の通知から notifyDebounce 待ってまとめ、通知の後の
// 見直しを 1 回だけ呼ぶ(仕様 7b.4 節の変更の通知。vpsd の reconcile.Triggers と同じまとめ方)。
// 通知の群れは待ちも挟まずに送るので、まとめの窓より長くはならない。
func TestServeDebouncesKernelNotifications(t *testing.T) {
	dp := &fakeSensedDataplane{fakeDataplane: &fakeDataplane{up: true}}
	rt := newFakeDataplaneRuntime(t, dp.fakeDataplane)
	rt.dp = dp
	rt.f.LastState = &proto.State{Generation: 1}
	const debounce = 100 * time.Millisecond
	rt.kernelWake, rt.notifyDebounce = make(chan struct{}, 1), debounce
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.serve(ctx, make(chan error), make(chan time.Time)) }()
	defer func() { cancel(); <-done }()

	start := time.Now()
	for i := 0; i < 20; i++ {
		rt.pokeKernel()
	}
	deadline := time.Now().Add(5 * time.Second)
	for len(dp.observed()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a burst of notifications led to no check")
		}
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(3 * debounce)
	calls := dp.observed()
	if len(calls) != 1 {
		t.Fatalf("a burst of notifications led to %d checks, want 1", len(calls))
	}
	if waited := calls[0].Sub(start); waited < debounce {
		t.Errorf("the check ran %v after the first notification, before the %v debounce ended", waited, debounce)
	}
	// 次の通知は新しい窓を開く
	rt.pokeKernel()
	deadline = time.Now().Add(5 * time.Second)
	for len(dp.observed()) < 2 {
		if time.Now().After(deadline) {
			t.Fatal("a later notification led to no second check")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// ユーザー空間モードの dataplane は通知を購読せず、通知の後の見直しも何もしない。
func TestUserspaceDoesNotWatchTheKernel(t *testing.T) {
	rt := newRuntime(Options{}, nil, [32]byte{})
	if _, ok := rt.dp.(sensed); ok {
		t.Fatal("the userspace dataplane subscribes to kernel notifications")
	}
	rt.watchKernel(context.Background())
	rt.observeNotified()
}
