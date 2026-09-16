package wg

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// UDPTimeouts は VPS の conntrack の UDP タイムアウト 2 値(秒)。全体状態でエージェントに渡す(仕様 4 節)。
type UDPTimeouts struct {
	Timeout       int // nf_conntrack_udp_timeout(既定 30)
	TimeoutStream int // nf_conntrack_udp_timeout_stream(既定 120)
}

// ReadUDPTimeouts は起動時に sysctl を読む。
func ReadUDPTimeouts() (UDPTimeouts, error) {
	t, err := readIntSysctl("/proc/sys/net/netfilter/nf_conntrack_udp_timeout")
	if err != nil {
		return UDPTimeouts{}, err
	}
	ts, err := readIntSysctl("/proc/sys/net/netfilter/nf_conntrack_udp_timeout_stream")
	if err != nil {
		return UDPTimeouts{}, err
	}
	return UDPTimeouts{Timeout: t, TimeoutStream: ts}, nil
}

func readIntSysctl(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w; is the nf_conntrack module loaded", path, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("%s value is not an integer: %w", path, err)
	}
	return n, nil
}
