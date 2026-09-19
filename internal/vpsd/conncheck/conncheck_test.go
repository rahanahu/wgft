package conncheck

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/proto"
)

// pipeConn はテスト用の net.Conn。Read の挙動を制御する。
type fakeConn struct {
	net.Conn
	readErr  error
	readData []byte
	closed   bool
}

func (c *fakeConn) Read(b []byte) (int, error) {
	if len(c.readData) > 0 {
		n := copy(b, c.readData)
		c.readData = c.readData[n:]
		return n, nil
	}
	return 0, c.readErr
}
func (c *fakeConn) Close() error                      { c.closed = true; return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error { return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestCheck(t *testing.T) {
	tests := []struct {
		name      string
		dialErr   error
		readErr   error
		readData  []byte
		wantOK    bool
		wantReach string
	}{
		{"接続できない(refused)", errors.New("connect: connection refused"), nil, nil, false, ReachNone},
		{"接続できない(timeout)", errors.New("dial tcp: i/o timeout"), nil, nil, false, ReachNone},
		{"接続後すぐ EOF(target 不達)", nil, io.EOF, nil, false, ReachAgent},
		{"接続後 reset(target 不達)", nil, errors.New("read: connection reset by peer"), nil, false, ReachAgent},
		{"無言で生存(到達)", nil, timeoutErr{}, nil, true, ReachTarget},
		{"バナーを返す(到達)", nil, nil, []byte("SSH-2.0"), true, ReachTarget},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dial := func(network, addr string) (net.Conn, error) {
				if tt.dialErr != nil {
					return nil, tt.dialErr
				}
				return &fakeConn{readErr: tt.readErr, readData: tt.readData}, nil
			}
			r := Check("10.200.0.2:25565", Options{Dial: dial, ObserveTime: 10 * time.Millisecond})
			if r.OK != tt.wantOK || r.Reach != tt.wantReach {
				t.Errorf("got OK=%v reach=%s (%s), want OK=%v reach=%s", r.OK, r.Reach, r.Detail, tt.wantOK, tt.wantReach)
			}
		})
	}
}

// loopbackNet はエージェントの中継を模す Network。本番の netstack の代わりに 127.0.0.1 に開く。
type loopbackNet struct{}

func (loopbackNet) ListenUDP(port uint16) (net.PacketConn, error) {
	return net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
}

func (loopbackNet) ListenTCP(port uint16) (net.Listener, error) {
	return net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
}

// 疎通確認はエージェントの中継を通るので、エージェントの宛先の許可一覧に従う(仕様 7 節)。
// 一覧の外の宛先へのルールでは中継が接続を拒み、確認は「エージェントまでは届くが宛先に届かない」になる。
func TestCheckObeysAgentAllowList(t *testing.T) {
	m := relay.New(loopbackNet{}, relay.Options{
		Logf:              t.Logf,
		AllowTarget:       func(ap netip.AddrPort) bool { return false },
		AllowTargetSource: "WGFT_AGENT_ALLOW_TARGETS",
		LookupTarget: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	})
	defer m.Close()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	ln.Close() // 中継の待ち受けに使うポートを空ける
	m.Apply(map[relay.Key]relay.Desired{{Proto: proto.TCP, Port: port}: {Target: "nas.lan:25565", RuleID: "r1"}})

	// 拒否は RST なので、結果は「エージェントまでは届く」か、RST が接続の途中に届いた場合の
	// 「届かない」のどちらにもなる。どちらでも疎通は失敗で、宛先には届かない
	r := Check(net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), Options{ObserveTime: time.Second})
	if r.OK || (r.Reach != ReachAgent && r.Reach != ReachNone) {
		t.Errorf("got OK=%v reach=%s (%s), want OK=false and reach %s or %s", r.OK, r.Reach, r.Detail, ReachAgent, ReachNone)
	}
}
