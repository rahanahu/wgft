package nettun

import (
	"encoding/binary"
	"sync"
	"testing"
	"time"
)

// 再組み立ての表を internal/ipv4frag に移した後、この package の試験が表の上限と処理の長さを変えるための口。

// setReassemblyLifetime と setReassemblyBytesToBaseCost は package の変数を書き換えるので、これを使う試験は並列にしない。
// setReassemblyLifetime は、この試験の間に作る Device の表の期限を d にする。
func setReassemblyLifetime(t *testing.T, d time.Duration) {
	t.Helper()
	old := reassemblyLimits
	reassemblyLimits.Lifetime = d
	t.Cleanup(func() { reassemblyLimits = old })
}

// setReassemblyBytesToBaseCost は、この試験の間に作る Device の表の保持 byte を固定の管理領域だけにする。
// 断片の中身を置く余地は残らない。
func setReassemblyBytesToBaseCost(t *testing.T) {
	t.Helper()
	tab, err := newIPv4Reassembly(reassemblyLimits)
	if err != nil {
		t.Fatal(err)
	}
	base := tab.Snapshot().BaseCost
	tab.Close()
	old := reassemblyLimits
	reassemblyLimits.Bytes = base
	t.Cleanup(func() { reassemblyLimits = old })
}

// holdReassembly は、Device が表の Process と Sweep を呼ぶ前で止まるようにし、止めを解く関数を返す。
// 表の処理が長くかかる場合を模す。
// package の reassemblyHook を差し替えるので、止めている間は process のすべての Device の掃除と断片の処理が
// 止まり、Close も掃除の終わりを待って止まる。これを使う試験は並列にしない。
func holdReassembly(t *testing.T) (release func()) {
	t.Helper()
	gate := make(chan struct{})
	wait := func() { <-gate }
	reassemblyHook.Store(&wait)
	var once sync.Once
	release = func() {
		once.Do(func() {
			reassemblyHook.Store(nil)
			close(gate)
		})
	}
	t.Cleanup(release)
	return release
}

// reasmIPv4Fragment は IPv4 の断片を作る。internal/ipv4frag の試験の同じ名前の関数と同じものである。
func reasmIPv4Fragment(proto byte, id uint16, offset int, more bool, tos byte, options, data []byte) []byte {
	hlen := 20 + len(options)
	p := make([]byte, hlen+len(data))
	p[0] = 0x40 | byte(hlen/4)
	p[1] = tos
	binary.BigEndian.PutUint16(p[2:], uint16(len(p)))
	binary.BigEndian.PutUint16(p[4:], id)
	flags := uint16(offset / 8)
	if more {
		flags |= 0x2000
	}
	binary.BigEndian.PutUint16(p[6:], flags)
	p[8], p[9] = 64, proto
	copy(p[12:16], []byte{10, 1, 1, 1})
	copy(p[16:20], []byte{10, 1, 1, 2})
	copy(p[20:], options)
	copy(p[hlen:], data)
	ipv4SetChecksum(p[:hlen])
	return p
}
