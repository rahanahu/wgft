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
// 確かめる。ユーザー空間モードでは、Admit が Backend の評価器の判定を返すこと、FloorAtAccept が
// 立つこと、Dial が Backend の netstack を通ること、Pool が relay の TCP の Pool であることを見る。
// カーネルモードでは、この 3 つが無く、Pool の予算が設定の TCPTotal であることを見る。Admit が
// 外れると Admission Policy が黙って効かなくなり(proxyrelay は nil なら通す)、FloorAtAccept が
// 外れると受信のバッファを floor に固定しない。
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
	// トンネルを立てていない Backend の Dial は "tunnel is not up" で失敗する。ホストの dial なら
	// ループバックの閉じたポートへの接続の拒否になる
	if o.Dial == nil {
		t.Error("userspace mode: the Relay frontend does not dial through the netstack")
	} else if c, err := o.Dial("127.0.0.1:1"); err == nil {
		c.Close()
		t.Error("userspace mode: the Relay frontend's Dial reached 127.0.0.1:1; it does not go through the Backend's netstack")
	} else if !strings.Contains(err.Error(), "tunnel is not up") {
		t.Errorf("userspace mode: the Relay frontend's Dial failed with %q; want the Backend's \"tunnel is not up\"", err)
	}

	const tcpTotal = 123
	k := relayFrontendOptions(resource.Limits{TCPTotal: tcpTotal}, nil)
	if k.Admit != nil || k.FloorAtAccept || k.Dial != nil {
		t.Errorf("kernel mode: Admit set %v, FloorAtAccept %v, Dial set %v; want none of them", k.Admit != nil, k.FloorAtAccept, k.Dial != nil)
	}
	if k.Pool == nil {
		t.Error("kernel mode: the Relay frontend has no pool")
	} else if got := k.Pool.Total(); got != tcpTotal {
		t.Errorf("kernel mode: the Relay frontend's pool holds %d flows; want the configured TCPTotal %d", got, tcpTotal)
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
