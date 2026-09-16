package conncheck

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
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
