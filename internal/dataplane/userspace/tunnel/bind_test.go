package tunnel

import (
	"fmt"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/wgbind"
)

// device に渡すバインドは utun と共有する wgbind.New である。Windows の受信の永久停止の回避と
// 受信の 1 回の件数(設計文書 7 節)は wgbind の試験が確かめるので、ここでは差し込み口の既定値が
// その関数であることだけを確かめる。
func TestBindForDeviceIsTheSharedBind(t *testing.T) {
	if reflect.ValueOf(bindForDevice).Pointer() != reflect.ValueOf(wgbind.New).Pointer() {
		t.Fatal("bindForDevice is not wgbind.New")
	}
}

// Status は IpcGet の VPS のピアの節から、最終ハンドシェイクと転送量を読む。
func TestStatusReadsTheServerPeer(t *testing.T) {
	srvKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	agentKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	agentAddr := netip.MustParseAddr("10.200.0.2")
	serverAddr := netip.MustParseAddr("10.200.0.1")
	srv, port := newServerTunnel(t, srvKey, serverAddr)
	if _, err := srv.SetPeers([]dataplane.Peer{{PublicKey: agentKey.PublicKey(), Address: agentAddr}}); err != nil {
		t.Fatalf("declare the agent peer: %v", err)
	}
	tun, err := New(Config{
		PrivateKey: agentKey, ServerPublicKey: srvKey.PublicKey(),
		Endpoint:      fmt.Sprintf("127.0.0.1:%d", port),
		Address:       agentAddr,
		ServerAddress: serverAddr,
		MTU:           1420,
		Keepalive:     time.Second,
		Logf:          func(string, ...any) {},
	})
	if err != nil {
		t.Fatalf("agent tunnel: %v", err)
	}
	defer tun.Close()
	before := time.Now().Add(-time.Second)
	waitPing(t, tun, true, 20*time.Second, "for the status check")
	st := tun.Status()
	if st.Err != nil {
		t.Fatalf("Status().Err = %v", st.Err)
	}
	if st.LastHandshake.Before(before.Truncate(time.Second)) || st.LastHandshake.After(time.Now()) {
		t.Errorf("LastHandshake = %v, want a time since %v", st.LastHandshake, before)
	}
	if st.RxBytes <= 0 || st.TxBytes <= 0 {
		t.Errorf("RxBytes %d, TxBytes %d; want both positive after a ping round trip", st.RxBytes, st.TxBytes)
	}
	if st.Endpoint != netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port)) {
		t.Errorf("Endpoint = %v, want 127.0.0.1:%d", st.Endpoint, port)
	}
}
