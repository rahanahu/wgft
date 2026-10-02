package usermode

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// A hijacked VPS can send wg.udp_timeout_stream or wg.keepalive in the global state as a
// seconds value large enough to overflow int64 nanoseconds when multiplied by time.Second,
// wrapping to a tiny or negative time.Duration; for example 20211507185753197 wraps to 512ns.
// secondsToDuration rejects such values before the multiplication's result can reach a
// ticker. The overflow value itself does not fit in a 32-bit int, so the cases that use it
// are skipped rather than failed on a platform where int is 32 bits: a real server value that
// large would already fail to decode into the int fields of proto.WGConfig there.

// fitsInt reports whether v fits in the platform's int type.
func fitsInt(v int64) bool { return v >= math.MinInt && v <= math.MaxInt }

func TestSecondsToDuration(t *testing.T) {
	const def = 25 * time.Second
	tests := []struct {
		name    string
		seconds int64
		max     int64
		want    time.Duration
	}{
		{"typical value in range", 120, udpTimeoutStreamMaxSeconds, 120 * time.Second},
		{"zero falls back to default", 0, udpTimeoutStreamMaxSeconds, def},
		{"negative falls back to default", -1, udpTimeoutStreamMaxSeconds, def},
		{"exactly at max is accepted", agentdp.KeepaliveMaxSeconds, agentdp.KeepaliveMaxSeconds, agentdp.KeepaliveMaxSeconds * time.Second},
		{"one past max falls back to default", agentdp.KeepaliveMaxSeconds + 1, agentdp.KeepaliveMaxSeconds, def},
		// The reported overflow value: 20211507185753197 seconds wraps to 512ns under
		// `* time.Second` (int64 nanoseconds overflow). It is far above
		// udpTimeoutStreamMaxSeconds, so the upper-bound check alone rejects it.
		{"overflow value that wraps to 512ns falls back to default", 20211507185753197, udpTimeoutStreamMaxSeconds, def},
		// A large value just above the int64-nanosecond overflow point (MaxInt64/1e9 is about
		// 9223372036.85) is rejected the same way.
		{"value just above the int64-nanosecond overflow point falls back to default", 9223372037, udpTimeoutStreamMaxSeconds, def},
		// Even if max itself were chosen above the overflow point (the two real call sites
		// use math.MaxInt32 and 65535, so this does not happen today), the post-multiplication
		// floor check still rejects a value whose result wraps.
		{"even with an oversized max, the converted result is still checked", 9223372037, math.MaxInt64, def},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !fitsInt(tt.seconds) || !fitsInt(tt.max) {
				t.Skip("seconds or max does not fit in int on this platform")
			}
			if got := secondsToDuration("test", int(tt.seconds), int(tt.max), def); got != tt.want {
				t.Errorf("secondsToDuration(%d, %d, %v) = %v, want %v", tt.seconds, tt.max, def, got, tt.want)
			}
		})
	}
}

// RelayOptions が wg.udp_timeout_stream をそのまま `* time.Second` していた場合、この巻き戻った
// 512ns が UDPIdleTimeout に渡り、relay.New はそれを 0 以下としては直さない(relay.go:189-191)。
func TestRelayOptionsUDPTimeoutStreamOverflow(t *testing.T) {
	d := New(nil, resource.Limits{})

	var overflowSeconds int64 = 20211507185753197
	if !fitsInt(overflowSeconds) {
		t.Skip("the overflow value does not fit in int on this platform")
	}
	o := d.RelayOptions(proto.WGConfig{UDPTimeoutStream: int(overflowSeconds)})
	if o.UDPIdleTimeout != 120*time.Second {
		t.Errorf("overflowing udp_timeout_stream: UDPIdleTimeout = %v, want the 120s default", o.UDPIdleTimeout)
	}

	// 正当な値はそのまま通る
	o = d.RelayOptions(proto.WGConfig{UDPTimeoutStream: 300})
	if o.UDPIdleTimeout != 300*time.Second {
		t.Errorf("in-range udp_timeout_stream: UDPIdleTimeout = %v, want 300s", o.UDPIdleTimeout)
	}

	// 0(値が無い旧い server)も既定値に落ちる
	o = d.RelayOptions(proto.WGConfig{UDPTimeoutStream: 0})
	if o.UDPIdleTimeout != 120*time.Second {
		t.Errorf("zero udp_timeout_stream: UDPIdleTimeout = %v, want the 120s default", o.UDPIdleTimeout)
	}
}

// tunnelConfig が wg.keepalive をそのまま `* time.Second` していた場合も同じ型で巻き戻り、
// tunnel.Run の ticker (Keepalive をそのまま period に使う) が回り続ける。
func TestTunnelConfigKeepaliveOverflow(t *testing.T) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	serverPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	base := proto.WGConfig{
		ServerPubkey: serverPriv.PublicKey().String(),
		Address:      "10.200.0.2/24",
		MTU:          1420,
	}

	tests := []struct {
		name      string
		keepalive int64
		want      time.Duration
	}{
		{"typical value in range", 25, 25 * time.Second},
		{"overflow value that wraps to 512ns falls back to default", 20211507185753197, 25 * time.Second},
		{"above the kernel-mode-matching range falls back to default", 65536, 25 * time.Second},
		{"zero falls back to default", 0, 25 * time.Second},
		{"negative falls back to default", -1, 25 * time.Second},
		{"at the kernel-mode-matching upper bound is accepted", 65535, 65535 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !fitsInt(tt.keepalive) {
				t.Skip("the keepalive value does not fit in int on this platform")
			}
			w := base
			w.Keepalive = int(tt.keepalive)
			cfg, err := tunnelConfig(priv, w)
			if err != nil {
				t.Fatalf("tunnelConfig: %v", err)
			}
			if cfg.Keepalive != tt.want {
				t.Errorf("Keepalive = %v, want %v", cfg.Keepalive, tt.want)
			}
		})
	}
}

// 宛先の許可一覧を設定しなければ、中継に判定を渡さない(仕様 7 節の「一覧が無いときは制限しない」)。
// 設定したときは判定と設定の名前を渡す。
func TestRelayOptionsAllowTargets(t *testing.T) {
	st := &proto.State{WG: proto.WGConfig{UDPTimeoutStream: 120}}
	if o := New(nil, resource.Limits{}).RelayOptions(st.WG); o.AllowTarget != nil || o.AllowTargetSource != "" {
		t.Errorf("without a list: AllowTarget=%v source=%q, want none", o.AllowTarget != nil, o.AllowTargetSource)
	}
	list, err := allowtargets.Parse("192.168.1.20:25565")
	if err != nil {
		t.Fatal(err)
	}
	o := New(list, resource.Limits{}).RelayOptions(st.WG)
	if o.AllowTarget == nil {
		t.Fatal("with a list: AllowTarget is nil")
	}
	if o.AllowTargetSource != allowtargets.Env {
		t.Errorf("source = %q, want %q", o.AllowTargetSource, allowtargets.Env)
	}
	if !o.AllowTarget(netip.MustParseAddrPort("192.168.1.20:25565")) {
		t.Error("the listed target must be allowed")
	}
	if o.AllowTarget(netip.MustParseAddrPort("192.168.1.1:22")) {
		t.Error("a target outside the list must be denied")
	}
}

// closeProbeNetwork は relay.Network で、開いた TCP リスナーが Close された時点で onClose を呼ぶ。
// 中継が閉じた瞬間を、本物の Close の中で観測するための差し替えである。
type closeProbeNetwork struct{ onClose func() }

func (n *closeProbeNetwork) ListenUDP(uint16) (net.PacketConn, error) {
	return net.ListenPacket("udp4", "127.0.0.1:0")
}

func (n *closeProbeNetwork) ListenTCP(uint16) (net.Listener, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return &closeProbeListener{Listener: l, onClose: n.onClose}, nil
}

type closeProbeListener struct {
	net.Listener
	onClose func()
	once    sync.Once
}

func (l *closeProbeListener) Close() error {
	l.once.Do(l.onClose)
	return l.Listener.Close()
}

// Close は中継、context の取り消し、トンネルの順に閉じる。順序は、古い device と netstack と
// goroutine を次の Build の前に片付けるために要る。入れ替えると、中継がまだ使うトンネルを先に
// 閉じる、または取り消しの前にトンネルを閉じる、のどちらかになる。3 つの段階はそれぞれの中で
// 観測し、段階ごとに「先の段階は済み、後の段階はまだ」を確かめる。
func TestCloseOrder(t *testing.T) {
	var tun *tunnel.Tunnel
	real := NewTunnel
	NewTunnel = func(cfg tunnel.Config) (*tunnel.Tunnel, error) {
		tt, err := real(cfg)
		tun = tt
		return tt, err
	}
	t.Cleanup(func() { NewTunnel = real })

	srvKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	wg := proto.WGConfig{
		ServerPubkey: srvKey.PublicKey().String(), Endpoint: "127.0.0.1:9",
		Address: "10.200.0.2/24", MTU: 1420, Keepalive: 1, UDPTimeoutStream: 120,
	}
	d := New(nil, resource.Limits{})
	if _, err := d.Build(priv, wg); err != nil {
		t.Fatalf("Build: %v", err)
	}
	t.Cleanup(d.Close)

	// 中継は、Close を観測できるネットワークの上に作り直す。Build が作った中継はリスナーを持たない
	d.Relay.Close()
	tunnelClosed := func() bool {
		l, err := tun.ListenTCP(18080)
		if err != nil {
			return true
		}
		l.Close()
		return false
	}
	if tunnelClosed() {
		t.Fatal("the probe reports a closed tunnel before Close; it cannot tell the steps apart")
	}

	var mu sync.Mutex
	var order []string
	var bad []string
	step := func(name string, relayDone, cancelDone, tunDone bool) {
		mu.Lock()
		defer mu.Unlock()
		have := map[string]bool{"relay": false, "cancel": false}
		for _, s := range order {
			have[s] = true
		}
		if have["relay"] != relayDone {
			bad = append(bad, fmt.Sprintf("%s: relay closed = %v, want %v", name, have["relay"], relayDone))
		}
		if have["cancel"] != cancelDone {
			bad = append(bad, fmt.Sprintf("%s: context cancelled = %v, want %v", name, have["cancel"], cancelDone))
		}
		if got := tunnelClosed(); got != tunDone {
			bad = append(bad, fmt.Sprintf("%s: tunnel closed = %v, want %v", name, got, tunDone))
		}
		order = append(order, name)
	}

	d.Relay = relay.New(&closeProbeNetwork{onClose: func() { step("relay", false, false, false) }}, d.RelayOptions(wg))
	d.Relay.Apply(relay.DesiredFromRules([]proto.AgentRule{{
		ID: "r", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 18081, Hi: 18081},
		Target: "127.0.0.1:9", Enabled: true,
	}}))
	if len(d.Relay.Status()) != 1 {
		t.Fatalf("the probe listener did not open: %d listeners", len(d.Relay.Status()))
	}

	cancel := d.tunCancel
	d.tunCancel = func() {
		step("cancel", true, false, false)
		cancel()
	}

	d.Close()

	mu.Lock()
	defer mu.Unlock()
	if got := strings.Join(order, ","); got != "relay,cancel" {
		t.Fatalf("observed steps = %q, want relay,cancel", got)
	}
	if !tunnelClosed() {
		bad = append(bad, "after Close: the tunnel is still open")
	}
	for _, b := range bad {
		t.Error(b)
	}
	if d.Relay != nil || d.Tun != nil || d.tunCancel != nil {
		t.Error("Close must reset Relay, Tun and tunCancel to nil")
	}
}
