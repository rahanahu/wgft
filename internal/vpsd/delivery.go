//go:build linux

package vpsd

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"sync"

	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/vpsd/store"
	"github.com/rahanahu/wgft/proto"
)

var ErrDeliveryProjectionMismatch = errors.New("agent delivery projection differs from the data plane publication")

type deliveryEntry struct {
	identity string
	key      string
	state    proto.State
}

type deliverySnapshot struct {
	entries    map[string]deliveryEntry
	generation uint64
}

type disableOverlay struct {
	identity   string
	generation uint64
}

// deliveryOwner is the single selection point for every agent State. Writers
// hold Daemon.mu; the separate lock lets stream writers select without holding
// that lock across a network operation. A selection made before a later commit
// may already be in flight, but every selection after the commit sees its P/D.
type deliveryOwner struct {
	mu       sync.RWMutex
	latest   *deliverySnapshot // successful Commit, including before bootstrap binding
	full     *deliverySnapshot // nil until bootstrap timeout binding succeeds
	disabled map[string]disableOverlay
	revision uint64
	pending  bool // saved full declaration lacks a successful matching Commit
}

func (d *Daemon) deliveryCandidate(rules []proto.Rule, agents []store.Agent, gen uint64) *deliverySnapshot {
	entries := make(map[string]deliveryEntry, len(agents))
	for _, a := range agents {
		st := proto.State{Generation: gen, AgentDisabled: a.Disabled(), Rules: []proto.AgentRule{}}
		st.WG = proto.WGConfig{
			ServerPubkey: d.serverKey.PublicKey().String(), Endpoint: d.opts.WGEndpoint,
			Address: netip.PrefixFrom(a.Address, d.network.Bits()).String(),
			MTU:     d.opts.MTU, Keepalive: 25,
		}
		if t := d.timeouts.Load(); t != nil {
			st.WG.UDPTimeout, st.WG.UDPTimeoutStream = t.Timeout, t.TimeoutStream
		}
		for i := range rules {
			if rules[i].Agent == a.Name {
				st.Rules = append(st.Rules, store.DeliveredRule(&rules[i], a.Disabled()))
			}
		}
		entries[a.Name] = deliveryEntry{identity: a.Identity, key: a.PublicKey, state: st}
	}
	return &deliverySnapshot{entries: entries, generation: gen}
}

func equalDelivery(a, b *deliverySnapshot) bool {
	if a == nil || b == nil {
		return a == b
	}
	return reflect.DeepEqual(a.entries, b.entries)
}

// overlayGeneration is the highest generation among the disable overlays, or
// zero when there are none.
func overlayGeneration(disabled map[string]disableOverlay) uint64 {
	var generation uint64
	for _, d := range disabled {
		if d.generation > generation {
			generation = d.generation
		}
	}
	return generation
}

// applyOverlay returns the State that the published entry for name delivers
// under the disable overlays: the generation is raised to generation, the
// result of overlayGeneration, and an overlay whose identity matches the
// entry disables the agent and every rule. Rules is copied, so the published
// snapshot is never modified. It takes no lock; the caller holds
// deliveryOwner.mu while disabled is the owner's map.
func applyOverlay(name string, entry deliveryEntry, disabled map[string]disableOverlay, generation uint64) proto.State {
	st := entry.state
	st.Rules = append([]proto.AgentRule{}, st.Rules...)
	if generation > st.Generation {
		st.Generation = generation
	}
	if d, ok := disabled[name]; ok && d.identity == entry.identity {
		st.AgentDisabled = true
		for i := range st.Rules {
			st.Rules[i].Enabled = false
		}
	}
	return st
}

func effectiveDelivery(s *deliverySnapshot, disabled map[string]disableOverlay) map[string]deliveryEntry {
	if s == nil {
		return nil
	}
	out := make(map[string]deliveryEntry, len(s.entries))
	generation := overlayGeneration(disabled)
	for name, entry := range s.entries {
		entry.state = applyOverlay(name, entry, disabled, generation)
		out[name] = entry
	}
	return out
}

func (o *deliveryOwner) currentFull() *deliverySnapshot {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.full != nil {
		return o.full
	}
	return o.latest
}

// committed installs only a successful full Commit. A new full publication
// incorporates the serialized disable bits and removes their older overlays.
// It returns, sorted, the agents whose effective entry (registration, key and
// State) is new or differs from the previous publication: the only agents a
// delivery has anything new for (design.md 5.2 節). A key declaration changes
// only the declaring agent's key, so no other agent is in the list.
func (o *deliveryOwner) committed(candidate *deliverySnapshot) []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	previous := o.full
	if previous == nil {
		previous = o.latest
	}
	before, after := effectiveDelivery(previous, o.disabled), effectiveDelivery(candidate, nil)
	var changed []string
	for name, entry := range after {
		if old, ok := before[name]; !ok || !reflect.DeepEqual(old, entry) {
			changed = append(changed, name)
		}
	}
	sort.Strings(changed)
	o.latest = candidate
	if o.full != nil {
		o.full = candidate
	}
	o.disabled = nil
	o.pending = false
	if !reflect.DeepEqual(before, after) {
		o.revision++
	}
	return changed
}

func (o *deliveryOwner) disable(name, identity string, generation uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.disabled == nil {
		o.disabled = make(map[string]disableOverlay)
	}
	o.disabled[name] = disableOverlay{identity: identity, generation: generation}
	o.pending = true
	o.revision++
}

func (o *deliveryOwner) revoke(name string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	// Copy the maps: a reader may have selected the previous immutable P.
	remove := func(s *deliverySnapshot) *deliverySnapshot {
		if s == nil {
			return nil
		}
		entries := make(map[string]deliveryEntry, len(s.entries))
		for n, e := range s.entries {
			if n != name {
				entries[n] = e
			}
		}
		return &deliverySnapshot{entries: entries, generation: s.generation}
	}
	o.latest = remove(o.latest)
	o.full = remove(o.full)
	delete(o.disabled, name)
	o.pending = true
	o.revision++
}

func (o *deliveryOwner) markPending() {
	o.mu.Lock()
	o.pending = true
	o.mu.Unlock()
}

func (o *deliveryOwner) clearPending() {
	o.mu.Lock()
	o.pending = false
	o.mu.Unlock()
}

func (o *deliveryOwner) status() (*uint64, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.full == nil {
		return nil, true
	}
	g := o.full.generation
	return &g, o.pending
}

// state checks the current registration identity. Stream selections additionally
// require the key declared by that connection to match the successful token.
// An admin read has no connection key and observes that token directly.
func (o *deliveryOwner) state(name, identity string, key *string) (*proto.State, error) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	if o.full == nil {
		return nil, errors.New("agent state is not published")
	}
	e, ok := o.full.entries[name]
	if !ok || e.identity != identity || (key != nil && e.key != *key) {
		return nil, fmt.Errorf("agent %q has no published state for this registration and key", name)
	}
	st := applyOverlay(name, e, o.disabled, overlayGeneration(o.disabled))
	return &st, nil
}

// withTimeouts returns a new snapshot with the same entries and generation,
// whose every State carries the conntrack UDP timeouts t. The entries map is
// new and s is not modified, so a snapshot stays as committed installed it.
// Only WG, a value, changes; Rules still shares its backing array with s,
// which nothing writes to.
func (s *deliverySnapshot) withTimeouts(t linux.UDPTimeouts) *deliverySnapshot {
	entries := make(map[string]deliveryEntry, len(s.entries))
	for name, e := range s.entries {
		e.state.WG.UDPTimeout = t.Timeout
		e.state.WG.UDPTimeoutStream = t.TimeoutStream
		entries[name] = e
	}
	return &deliverySnapshot{entries: entries, generation: s.generation}
}

// bindDeliveryTimeouts makes the latest successful token serviceable. The
// caller owns Daemon.mu, so no in-process apply can interleave with the read.
// It replaces latest with a copy that carries the timeouts instead of writing
// into the published snapshot.
func (d *Daemon) bindDeliveryTimeouts(read func() (linux.UDPTimeouts, error)) (linux.UDPTimeouts, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, err := read()
	if err != nil {
		return linux.UDPTimeouts{}, err
	}
	d.delivery.mu.Lock()
	defer d.delivery.mu.Unlock()
	if d.delivery.latest == nil {
		return linux.UDPTimeouts{}, errors.New("no successful agent state publication")
	}
	d.delivery.latest = d.delivery.latest.withTimeouts(t)
	d.timeouts.Store(&t)
	d.delivery.full = d.delivery.latest
	return t, nil
}
