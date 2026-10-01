//go:build linux

package vpsd

import (
	"net/netip"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel"
	"github.com/rahanahu/wgft/internal/dataplane/userspace"
	"github.com/rahanahu/wgft/internal/resource"
)

// このファイルは、nil なら黙って何もしない差し込み口と、型アサーションだけで探す任意の機能が、
// server の組み立てで外れていないことを確かめる。外れてもコンパイルは通り、他の単体テストも通るためである。

// TestParticipantsKeepTheirOptionalInterfaces は、各モードの participant() が、vpsd が型アサーション
// で探す任意の機能を満たす値を返すことを確かめる。カーネルモードで外れると、外からの変更の通知
// (apply.go)と UDP の応答のカウンタの読み取り(udpreplies.go)が黙って止まる。
func TestParticipantsKeepTheirOptionalInterfaces(t *testing.T) {
	kernel := (&kernelDataplane{b: linuxkernel.New(linuxkernel.Options{Interface: "wgft0"})}).participant()
	if _, ok := kernel.(dataplane.Sensor); !ok {
		t.Error("kernel mode: participant() is not a dataplane.Sensor; outside changes would wait for the periodic check")
	}
	if _, ok := kernel.(udpReplyPoller); !ok {
		t.Error("kernel mode: participant() is not a udpReplyPoller; the reply counters would never be read")
	}
	if _, ok := kernel.(dataplane.UDPReplyObserver); !ok {
		t.Error("kernel mode: participant() is not a dataplane.UDPReplyObserver; udp_replies would be left out")
	}
	user := (&userspaceDataplane{b: userspace.New(userspace.Options{Logf: t.Logf})}).participant()
	if _, ok := user.(dataplane.UDPReplyObserver); !ok {
		t.Error("userspace mode: participant() is not a dataplane.UDPReplyObserver; udp_replies would be left out")
	}
}

// TestRelayFrontendOptionsPerMode は、Relay のルールの中継の設定がモードごとに組まれることを
// 確かめる。ユーザー空間モードで Admit が外れると、Admission Policy が黙って効かなくなる
// (proxyrelay は nil なら通す)。FloorAtAccept が外れると、受信のバッファを floor に固定しない。
func TestRelayFrontendOptionsPerMode(t *testing.T) {
	b := userspace.New(userspace.Options{Logf: t.Logf})
	o := relayFrontendOptions(resource.Limits{}, b)
	if o.Admit == nil {
		t.Error("userspace mode: the Relay frontend has no Admit; the Admission Policy would admit every connection")
	} else if release, ok := o.Admit("r_any", netip.MustParseAddr("198.51.100.1")); ok {
		// 最初の Commit の前の評価器はすべてのフローを拒む(userspace.New)。ここで通るなら、Admit は
		// Backend の評価器を呼んでいない
		release()
		t.Error("userspace mode: Admit admitted a flow before any admission policy was committed; it does not reach the Backend's evaluator")
	}
	if !o.FloorAtAccept {
		t.Error("userspace mode: FloorAtAccept is false; accepted connections would not be held at the floor")
	}
	if o.Pool != b.TCPPool() {
		t.Error("userspace mode: the Relay frontend does not share the relay's TCP pool")
	}
	if o.Dial == nil {
		t.Error("userspace mode: the Relay frontend does not dial through the netstack")
	}

	k := relayFrontendOptions(resource.Limits{}, nil)
	if k.Admit != nil || k.FloorAtAccept || k.Dial != nil {
		t.Errorf("kernel mode: Admit set %v, FloorAtAccept %v, Dial set %v; want none of them", k.Admit != nil, k.FloorAtAccept, k.Dial != nil)
	}
	if k.Pool == nil {
		t.Error("kernel mode: the Relay frontend has no pool")
	}
}

// TestNewHubRecordsStreamSources は、newHub が stream の接続の事象を IP の往復の検知(仕様 5.2 節)
// へつなぐことを、hub に接続して確かめる。外れると、stream の接続元の往復の警告が黙って止まる。
func TestNewHubRecordsStreamSources(t *testing.T) {
	_, d := registerHome(t)
	server, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	d.hub = d.newHub(&fakeStreamBackend{server: server})
	srv := serveHub(t, d.hub)
	c, _, err := websocketDial(t, "ws"+strings.TrimPrefix(srv.URL, "http"), "home")
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	// hub は OnStreamConnect を最初の全体状態を送る前に呼ぶ。websocketDial はその全体状態を読んで
	// から戻るので、ここでは記録が済んでいる
	d.flaps.mu.Lock()
	got := d.flaps.hist["home"]["stream"]
	d.flaps.mu.Unlock()
	if len(got) != 1 || got[0].IP == "" {
		t.Errorf("stream sources recorded for home: %+v; want the one connection's source", got)
	}
}
