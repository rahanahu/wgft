//go:build qbench

package qbench

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/tun"
)

// fakeDev is a tun.Device that records a write after its close. Read blocks until the close, as
// a device's read does.
type fakeDev struct {
	closed     atomic.Bool
	lateWrites atomic.Int32
	done       chan struct{}
	once       sync.Once
	events     chan tun.Event
}

func newFakeDev() *fakeDev {
	return &fakeDev{done: make(chan struct{}), events: make(chan tun.Event)}
}

func (f *fakeDev) File() *os.File           { return nil }
func (f *fakeDev) MTU() (int, error)        { return mtu, nil }
func (f *fakeDev) Name() (string, error)    { return "fake", nil }
func (f *fakeDev) Events() <-chan tun.Event { return f.events }
func (f *fakeDev) BatchSize() int           { return 1 }
func (f *fakeDev) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	<-f.done
	return 0, os.ErrClosed
}
func (f *fakeDev) Write(bufs [][]byte, offset int) (int, error) {
	if f.closed.Load() {
		f.lateWrites.Add(1)
		return 0, os.ErrClosed
	}
	return len(bufs), nil
}
func (f *fakeDev) Close() error {
	f.closed.Store(true)
	f.once.Do(func() { close(f.done) })
	return nil
}

// TestRigCloseHaltsLinkFirst closes a rig while the DUT still sends a packet toward the client:
// the client's close sends it into the link after the client has closed and waits for the link
// to deliver it. A rig that closes the client before it halts the link delivers the packet into
// the closed client, which a gVisor client answers into its closed queue with a panic. The rig
// must halt the link first, so the packet is never delivered.
func TestRigCloseHaltsLinkFirst(t *testing.T) {
	cdev, ddev := newFakeDev(), newFakeDev()
	r := &Rig{}
	r.L = NewLink(Impair{}, 1, writeTo(ddev), writeTo(cdev))
	r.C = &Client{Name: "fake", Dev: cdev, close: func() {
		cdev.Close()
		r.L.Send(1, []byte{0x45}) // a packet from the DUT, due at once
		deadline := time.Now().Add(200 * time.Millisecond)
		for cdev.lateWrites.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	}}
	r.D = &DUT{Name: "fake", Dev: ddev, Close: func() { ddev.Close() }}
	pump(cdev, func(p []byte) { r.L.Send(0, p) }, &r.wg)
	pump(ddev, func(p []byte) { r.L.Send(1, p) }, &r.wg)
	r.Close()
	if n := cdev.lateWrites.Load(); n != 0 {
		t.Fatalf("the link delivered %d packet(s) into the client after it closed", n)
	}
}
