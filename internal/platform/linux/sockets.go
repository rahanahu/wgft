package linux

// bind 中のポートの検査(仕様 5.3, 6.1 節)。自動では何も書き換えず、拒否か警告と提示に留める。

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/rahanahu/wgft/proto"
)

// Bound はプロトコルごとの、公開側で bind 中のポート → bind アドレスの一覧。
// ループバックだけに bind しているものは含めない(SSH のポートを塞ぐ事故を防ぐための検査なので、外から見えるものだけ)。
type Bound map[proto.Proto]map[uint16][]netip.Addr

// BoundPorts は /proc/net/{tcp,tcp6,udp,udp6} を読む。TCP は LISTEN だけ、UDP は bind されていれば待ち受けとみなす。
func BoundPorts() (Bound, error) {
	b := Bound{proto.TCP: {}, proto.UDP: {}}
	for _, f := range []struct {
		path       string
		p          proto.Proto
		listenOnly bool
	}{
		{"/proc/net/tcp", proto.TCP, true}, {"/proc/net/tcp6", proto.TCP, true},
		{"/proc/net/udp", proto.UDP, false}, {"/proc/net/udp6", proto.UDP, false},
	} {
		fh, err := os.Open(f.path)
		if os.IsNotExist(err) {
			continue // IPv6 が無効など
		}
		if err != nil {
			return nil, err
		}
		err = parseProcNet(fh, f.listenOnly, func(addr netip.Addr, port uint16) {
			b[f.p][port] = append(b[f.p][port], addr)
		})
		fh.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f.path, err)
		}
	}
	return b, nil
}

// Conflicts は範囲内で bind 中のポートを返す。
func (b Bound) Conflicts(p proto.Proto, r proto.PortRange) map[uint16][]netip.Addr {
	out := map[uint16][]netip.Addr{}
	for port, addrs := range b[p] {
		if r.Contains(port) {
			out[port] = addrs
		}
	}
	return out
}

// parseProcNet は /proc/net/tcp の形(local_address が 16 進、リトルエンディアン)を読み、
// 公開側(unspecified か非ループバック)で bind 中のものだけ fn に渡す。
func parseProcNet(r io.Reader, listenOnly bool, fn func(netip.Addr, uint16)) error {
	sc := bufio.NewScanner(r)
	sc.Scan() // ヘッダ
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 4 {
			continue
		}
		if listenOnly && fields[3] != "0A" { // TCP_LISTEN
			continue
		}
		addr, port, err := parseProcAddr(fields[1])
		if err != nil {
			return err
		}
		if addr.IsLoopback() {
			continue
		}
		fn(addr, port)
	}
	return sc.Err()
}

func parseProcAddr(s string) (netip.Addr, uint16, error) {
	h, p, ok := strings.Cut(s, ":")
	if !ok {
		return netip.Addr{}, 0, fmt.Errorf("address %q has an invalid form", s)
	}
	port, err := strconv.ParseUint(p, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return netip.Addr{}, 0, err
	}
	switch len(b) {
	case 4:
		return netip.AddrFrom4([4]byte{b[3], b[2], b[1], b[0]}), uint16(port), nil
	case 16:
		// 32 ビットごとにホストバイトオーダー(リトルエンディアン)で並んでいる
		var a [16]byte
		for i := 0; i < 4; i++ {
			binary.BigEndian.PutUint32(a[i*4:], binary.LittleEndian.Uint32(b[i*4:]))
		}
		return netip.AddrFrom16(a).Unmap(), uint16(port), nil
	}
	return netip.Addr{}, 0, fmt.Errorf("address %q has an invalid length", s)
}
