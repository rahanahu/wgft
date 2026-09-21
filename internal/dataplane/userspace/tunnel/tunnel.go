// Package tunnel は、エージェント側が wireguard-go と gVisor の netstack でユーザー空間に持つトンネル
// (仕様 7 節)。カーネルの設定は変更しないので、特権も NET_ADMIN も要らない。VPS 側の
// internal/dataplane/userspace/utun と対になる。
package tunnel

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/nettun"
)

// Config はトンネルの宣言。全体状態の wg 節から作る。
type Config struct {
	PrivateKey      wgtypes.Key
	ServerPublicKey wgtypes.Key
	Endpoint        string     // host:port。ホスト名なら起動時と引き直しのときに解決する
	Address         netip.Addr // 自分のアドレス(10.200.0.x)
	ServerAddress   netip.Addr // vpsd のアドレス(10.200.0.1)。AllowedIPs はこれの /32 だけ
	MTU             int
	Keepalive       time.Duration
	Logf            func(format string, args ...any)
}

// Tunnel は動いているトンネル。relay.Network として netstack 上にリスナーを開ける。
type Tunnel struct {
	cfg  Config
	dev  *device.Device
	tnet *nettun.Device

	mu       sync.Mutex
	endpoint netip.AddrPort
	lastErr  error
}

// Status はハートビートに載せるトンネルの状態。
type Status struct {
	Endpoint      netip.AddrPort // 解決済みのエンドポイント
	LastHandshake time.Time      // ゼロなら未確立
	RxBytes       int64
	TxBytes       int64
	Err           error // エンドポイントの解決失敗など
}

// bindForDevice は device に渡す UDP バインドを作る。値は GOOS ごとの newBind
// (bind_other.go と bind_windows.go)で、テストだけが受信の停止を模すために差し替える。
var bindForDevice = newBind

// New はトンネルを作って up する。エンドポイントの解決に失敗しても起こし、引き直しに任せる。
func New(cfg Config) (*Tunnel, error) {
	if cfg.Logf == nil {
		cfg.Logf = log.Printf
	}
	if cfg.Keepalive <= 0 {
		cfg.Keepalive = 25 * time.Second
	}
	tnet, err := nettun.Create(cfg.Address, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("netstack: %w", err)
	}
	t := &Tunnel{cfg: cfg, tnet: tnet}
	t.dev = device.NewDevice(tnet, bindForDevice(), device.NewLogger(device.LogLevelError, "wg: "))

	ep, err := resolve(cfg.Endpoint)
	if err != nil {
		t.lastErr = err
		cfg.Logf("tunnel: cannot resolve endpoint %s: %v; will keep re-resolving", cfg.Endpoint, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(cfg.PrivateKey[:]))
	fmt.Fprintf(&b, "public_key=%s\n", hex.EncodeToString(cfg.ServerPublicKey[:]))
	fmt.Fprintf(&b, "allowed_ip=%s/32\n", cfg.ServerAddress)
	fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(cfg.Keepalive/time.Second))
	if ep.IsValid() {
		fmt.Fprintf(&b, "endpoint=%s\n", ep)
		t.endpoint = ep
	}
	if err := t.dev.IpcSet(b.String()); err != nil {
		t.dev.Close()
		return nil, fmt.Errorf("configure wireguard: %w", err)
	}
	if err := t.dev.Up(); err != nil {
		t.dev.Close()
		return nil, fmt.Errorf("start wireguard: %w", err)
	}
	cfg.Logf("tunnel: up addr=%s mtu=%d endpoint=%s", cfg.Address, cfg.MTU, cfg.Endpoint)
	return t, nil
}

// ListenUDP / ListenTCP は relay.Network の実装。
func (t *Tunnel) ListenUDP(port uint16) (net.PacketConn, error) {
	return t.tnet.ListenUDP(netip.AddrPortFrom(t.cfg.Address, port))
}

// ListenTCP は netstack 上の自分のアドレスで TCP を待ち受ける。返す net.Listener の Accept は
// *nettun.TCPConn を返し、上限で拒む接続を Abort (RST) できる(仕様 7 節、GitHub issue #25)。
func (t *Tunnel) ListenTCP(port uint16) (net.Listener, error) {
	return t.tnet.ListenTCP(netip.AddrPortFrom(t.cfg.Address, port))
}

// Status は IpcGet から最終ハンドシェイクと転送量を読む。
func (t *Tunnel) Status() Status {
	t.mu.Lock()
	st := Status{Endpoint: t.endpoint, Err: t.lastErr}
	t.mu.Unlock()
	out, err := t.dev.IpcGet()
	if err != nil {
		st.Err = err
		return st
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, _ := strings.Cut(line, "=")
		switch k {
		case "last_handshake_time_sec":
			if sec, _ := strconv.ParseInt(v, 10, 64); sec > 0 {
				st.LastHandshake = time.Unix(sec, 0)
			}
		case "rx_bytes":
			st.RxBytes, _ = strconv.ParseInt(v, 10, 64)
		case "tx_bytes":
			st.TxBytes, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return st
}

// ReResolve はエンドポイントの名前を引き直し、変わっていればピアに設定し直す(仕様 4 節)。
// update_only=true で既存ピアのエンドポイントだけを書き換える。
func (t *Tunnel) ReResolve() error {
	ep, err := resolve(t.cfg.Endpoint)
	t.mu.Lock()
	defer t.mu.Unlock()
	if err != nil {
		t.lastErr = err
		return err
	}
	t.lastErr = nil
	if ep == t.endpoint {
		return nil
	}
	set := fmt.Sprintf("public_key=%s\nupdate_only=true\nendpoint=%s\n", hex.EncodeToString(t.cfg.ServerPublicKey[:]), ep)
	if err := t.dev.IpcSet(set); err != nil {
		t.lastErr = err
		return err
	}
	t.cfg.Logf("tunnel: changed endpoint %s → %s", t.endpoint, ep)
	t.endpoint = ep
	return nil
}

// Run は keepalive ごとに、トンネル内へ ping を 1 つ送り、ハンドシェイクが keepalive の 5 倍の間
// 成功していなければエンドポイントを引き直す。
//
// ping はデータパケットなので、VPS 側がセッションを失っていれば 15 秒以内に再ハンドシェイクが始まる。
// keepalive だけだと鍵の寿命(120 秒)まで待つ(実験で確認)。
func (t *Tunnel) Run(ctx context.Context) {
	tick := time.NewTicker(t.cfg.Keepalive)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		st := t.Status()
		if st.LastHandshake.IsZero() || time.Since(st.LastHandshake) > 5*t.cfg.Keepalive {
			if err := t.ReResolve(); err != nil {
				t.cfg.Logf("tunnel: re-resolve endpoint: %v", err)
			}
		}
		if rtt, err := t.Ping(2 * time.Second); err == nil {
			_ = rtt
		}
	}
}

// Ping は vpsd のアドレスへ ICMP echo を 1 つ送り、往復時間を返す。
func (t *Tunnel) Ping(timeout time.Duration) (time.Duration, error) {
	pc, err := t.tnet.DialPing(t.cfg.Address, t.cfg.ServerAddress)
	if err != nil {
		return 0, err
	}
	defer pc.Close()
	msg, err := (&icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: 1, Seq: int(time.Now().UnixNano() & 0xffff), Data: []byte("wgft")}}).Marshal(nil)
	if err != nil {
		return 0, err
	}
	start := time.Now()
	if _, err := pc.Write(msg); err != nil {
		return 0, err
	}
	pc.SetReadDeadline(start.Add(timeout))
	buf := make([]byte, 1500)
	if _, err := pc.Read(buf); err != nil {
		return 0, err
	}
	return time.Since(start), nil
}

// Close はトンネルを閉じる。
func (t *Tunnel) Close() { t.dev.Close() }

// resolve は host:port を IPv4 の AddrPort にする。ホスト名は A レコードを引き、決定的に先頭を選ぶ。
func resolve(endpoint string) (netip.AddrPort, error) {
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q is not in host:port form", endpoint)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("%q has an invalid port", endpoint)
	}
	if a, err := netip.ParseAddr(host); err == nil {
		if !a.Is4() {
			return netip.AddrPort{}, errors.New("IPv6 endpoints are not supported")
		}
		return netip.AddrPortFrom(a, uint16(port)), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(addrs) == 0 {
		return netip.AddrPort{}, fmt.Errorf("no A record for %s", host)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
	return netip.AddrPortFrom(addrs[0].Unmap(), uint16(port)), nil
}
