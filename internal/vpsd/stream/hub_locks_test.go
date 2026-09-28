package stream

import (
	"fmt"
	"runtime"
	"testing"
	"time"
)

func lockEntry(t *testing.T, h *Hub, name string, refs int) *agentLocks {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		h.mu.Lock()
		entry := h.locks[name]
		got := 0
		if entry != nil {
			got = entry.refs
		}
		h.mu.Unlock()
		if got == refs {
			return entry
		}
		if time.Now().After(deadline) {
			t.Fatalf("lock refs for %q = %d, want %d", name, got, refs)
		}
		runtime.Gosched()
	}
}

func receiveLock(t *testing.T, ch <-chan *heldAgentLock) *heldAgentLock {
	t.Helper()
	select {
	case lock := <-ch:
		return lock
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for lock")
		return nil
	}
}

func TestAgentLockWaiterPinsEntry(t *testing.T) {
	for _, kind := range []string{"agent", "hook"} {
		t.Run(kind, func(t *testing.T) {
			h := New(nil)
			acquire := h.agentLock
			if kind == "hook" {
				acquire = h.hookLock
			}
			first := acquire("home")
			entry := lockEntry(t, h, "home", 1)
			secondCh := make(chan *heldAgentLock, 1)
			go func() { secondCh <- acquire("home") }()
			if got := lockEntry(t, h, "home", 2); got != entry {
				t.Fatal("waiter used a different lock entry")
			}
			// The waiter has a ref but cannot own the mutex yet.
			select {
			case <-secondCh:
				t.Fatal("waiter acquired the held mutex")
			default:
			}
			other := acquire("other")
			other.unlock()
			first.unlock()
			second := receiveLock(t, secondCh)
			if got := lockEntry(t, h, "home", 1); got != entry {
				t.Fatal("entry was deleted before waiter released it")
			}
			thirdCh := make(chan *heldAgentLock, 1)
			go func() { thirdCh <- acquire("home") }()
			if got := lockEntry(t, h, "home", 2); got != entry {
				t.Fatal("third caller used a different lock entry")
			}
			select {
			case <-thirdCh:
				t.Fatal("third caller passed the held mutex")
			default:
			}
			second.unlock()
			third := receiveLock(t, thirdCh)
			third.unlock()
			if got := lockEntry(t, h, "home", 0); got != nil {
				t.Fatal("entry remained after the last release")
			}
		})
	}
}

func TestAgentAndHookLocksShareEntryLifetime(t *testing.T) {
	h := New(nil)
	agent := h.agentLock("home")
	entry := lockEntry(t, h, "home", 1)
	hook := h.hookLock("home")
	if got := lockEntry(t, h, "home", 2); got != entry {
		t.Fatal("agent and hook locks used different entries")
	}
	hook.unlock()
	if got := lockEntry(t, h, "home", 1); got != entry {
		t.Fatal("entry was deleted while agent lock was held")
	}
	agent.unlock()
	if got := lockEntry(t, h, "home", 0); got != nil {
		t.Fatal("entry remained after both releases")
	}
}

func TestStatusWithHookDoesNotRetainHistoricalNames(t *testing.T) {
	h := New(nil)
	for i := range 100 {
		name := fmt.Sprintf("agent-%d", i)
		h.StatusWithHook(name, func(s Status) {
			if s.Connected || h.Status(name).Connected {
				t.Errorf("unexpected status for %s", name)
			}
		})
	}
	h.status["home"] = &Status{Connected: true}
	h.StatusWithHook("home", func(s Status) {
		if !s.Connected || !h.Status("home").Connected {
			t.Error("StatusWithHook changed the stored status")
		}
	})
	if got := lockEntry(t, h, "home", 0); got != nil {
		t.Fatal("idle status retained a lock entry")
	}
	h.Disconnect("home", 1, "revoked")
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.locks) != 0 || len(h.status) != 0 {
		t.Fatalf("idle locks = %d, statuses = %d", len(h.locks), len(h.status))
	}
}
