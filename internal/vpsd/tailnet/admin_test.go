//go:build linux

package tailnet

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"reflect"
	"strings"
	"testing"
	"time"
)

// adminStart は listenAdmin を実際の tailnet なしに 1 回呼んだ結果である。
type adminStart struct {
	err    error
	opened []string // listen に渡した ip:port
	hosts  []string
	served chan net.Listener
	logged string
}

// startAdmin は、detect が ip、dnsName、other を返し、listen が listenErr で失敗するか待ち受けを返す
// 条件で listenAdmin を呼ぶ。見張りの goroutine は t の終わりに止める。
func startAdmin(t *testing.T, ip, dnsName, other string, listenErr error) *adminStart {
	t.Helper()
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := &adminStart{served: make(chan net.Listener, 1)}
	detect := func(context.Context) (string, string, string, string, bool) {
		return ip, dnsName, "test", other, dnsName != ""
	}
	listen := func(_ context.Context, ip, port string) (net.Listener, tailnetIface, error) {
		r.opened = append(r.opened, net.JoinHostPort(ip, port))
		if listenErr != nil {
			return nil, tailnetIface{}, listenErr
		}
		return &blockingListener{closed: make(chan struct{})}, tailnetIface{name: "tailscale0", index: 4}, nil
	}
	serve := func(ln net.Listener) error {
		r.served <- ln
		_, err := ln.Accept()
		return err
	}
	links := &fakeLinks{index: map[string]int{}}
	r.err = listenAdmin(ctx, detect, listen, links, serve, func(hs []string) { r.hosts = hs }, make(chan error, 1))
	r.logged = logs.String()
	return r
}

// listenAdmin:tailnet のアドレスが見つかれば、その番号のポートで待ち受けを開き、Host の許可に
// アドレスと MagicDNS 名を入れ、応答を始める。
func TestListenAdminOpensOnTheDetectedAddress(t *testing.T) {
	r := startAdmin(t, "100.100.1.1", "vps.example.ts.net", "", nil)
	if r.err != nil {
		t.Fatal(r.err)
	}
	if want := []string{"100.100.1.1:8686"}; !reflect.DeepEqual(r.opened, want) {
		t.Errorf("opened %v, want %v", r.opened, want)
	}
	if want := []string{"100.100.1.1", "vps.example.ts.net"}; !reflect.DeepEqual(r.hosts, want) {
		t.Errorf("hosts %v, want %v", r.hosts, want)
	}
	select {
	case <-r.served:
	case <-time.After(time.Second):
		t.Fatal("the listener was not served")
	}
	if !strings.Contains(r.logged, "also listening for the admin API on Tailscale 100.100.1.1:8686, test; bound to interface tailscale0 index 4") {
		t.Errorf("log: %q", r.logged)
	}
}

// listenAdmin:見つけたアドレスで開けなければ誤りを返し、Host の許可を変えない。
func TestListenAdminReturnsTheListenError(t *testing.T) {
	r := startAdmin(t, "100.100.1.1", "", "", errors.New("boom"))
	if r.err == nil || r.err.Error() != "admin API tailscale: boom" {
		t.Errorf("err = %v", r.err)
	}
	if r.hosts != nil {
		t.Errorf("hosts set to %v after a failed listen", r.hosts)
	}
}

// listenAdmin:tailnet のアドレスが無ければ待ち受けを開かず、警告を出して続ける。
func TestListenAdminWarnsWithoutAnAddress(t *testing.T) {
	for _, tc := range []struct{ other, want string }{
		{"eth1", "warning: --admin-tailscale set but eth1 has a 100.64.0.0/10 address and is not a Tailscale interface"},
		{"", "warning: --admin-tailscale set but no tailnet address within 100.64.0.0/10 found"},
	} {
		r := startAdmin(t, "", "", tc.other, nil)
		if r.err != nil || len(r.opened) != 0 || r.hosts != nil {
			t.Errorf("other %q: err %v, opened %v, hosts %v", tc.other, r.err, r.opened, r.hosts)
		}
		if !strings.Contains(r.logged, tc.want) {
			t.Errorf("other %q: log %q", tc.other, r.logged)
		}
	}
}
