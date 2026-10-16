//go:build linux

package kernelmode

import (
	"bytes"
	"errors"
	"log"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/proto"
)

// ループバックの宛先は、許可一覧がループバックの項目で名指すときだけ公開し、公開した後に wgft0 の
// route_localnet を 1 にする。最後のループバックの宛先が消えたら 0 に戻す(7b.2 節)。
func TestKernelLoopbackTargetSetsRouteLocalnet(t *testing.T) {
	allow, err := allowtargets.Parse("127.0.0.1:25565,192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	k := &fakeKernel{forwardOn: true}
	d := newTestKernel(t, k, nil, allow)
	k.link = ours(t, d)
	lo := tcpRule("lo", "127.0.0.1:25565", 39975, 39975)
	lan := tcpRule("lan", "192.168.1.20:80", 80, 80)
	if _, err := d.ApplyRules(1, []proto.AgentRule{lan}, nil); err != nil {
		t.Fatal(err)
	}
	if len(k.localnetWrites) != 0 || k.localnet {
		t.Fatalf("a table without a loopback target wrote route_localnet: %v", k.localnetWrites)
	}
	var publishedBefore int
	d.Ops.WriteRouteLocalnet = func(_ string, on bool) error {
		publishedBefore = len(k.published)
		k.localnetWrites = append(k.localnetWrites, on)
		k.localnet = on
		return nil
	}
	if _, err := d.ApplyRules(2, []proto.AgentRule{lan, lo}, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(k.localnetWrites, []bool{true}) || !k.localnet {
		t.Fatalf("route_localnet writes = %v, want one write of 1", k.localnetWrites)
	}
	if publishedBefore != 2 {
		t.Errorf("route_localnet was set with %d tables published, want it set after the table with the loopback DNAT", publishedBefore)
	}
	last := k.published[len(k.published)-1]
	if !last.HasLoopback() {
		t.Fatalf("the loopback rule was not published: %+v", last.Rules)
	}
	if s := statusOf(t, d, "lo"); s.State != proto.StatusOK {
		t.Errorf("lo = %+v, want ok", s)
	}
	// 同じ宣言の適用と見直しは書き直さない
	if _, err := d.ApplyRules(3, []proto.AgentRule{lan, lo}, nil); err != nil {
		t.Fatal(err)
	}
	observeOnce(t, d, 3, []proto.AgentRule{lan, lo})
	if len(k.localnetWrites) != 1 {
		t.Errorf("route_localnet writes = %v, want no rewrite of an unchanged value", k.localnetWrites)
	}
	if _, err := d.ApplyRules(4, []proto.AgentRule{lan}, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(k.localnetWrites, []bool{true, false}) || k.localnet {
		t.Errorf("route_localnet writes = %v, want it back at 0 once no loopback target is published", k.localnetWrites)
	}
}

// 許可一覧が無いか、ループバックの項目で名指さない宛先は公開せず、route_localnet にも触れない。
func TestKernelLoopbackTargetNeedsAnExplicitEntry(t *testing.T) {
	wide, err := allowtargets.Parse("0.0.0.0/0")
	if err != nil {
		t.Fatal(err)
	}
	for name, allow := range map[string]*allowtargets.List{"no allowlist": nil, "a wide entry": wide} {
		t.Run(name, func(t *testing.T) {
			k := &fakeKernel{forwardOn: true}
			d := newTestKernel(t, k, nil, allow)
			if _, err := d.ApplyRules(1, []proto.AgentRule{tcpRule("lo", "127.0.0.1:25565", 39975, 39975)}, nil); err != nil {
				t.Fatal(err)
			}
			if s := statusOf(t, d, "lo"); s.State != proto.StatusError || !strings.Contains(s.Reason, allowtargets.Env) {
				t.Errorf("lo = %+v, want an error that names %s", s, allowtargets.Env)
			}
			if k.published[0].HasLoopback() || len(k.localnetWrites) != 0 {
				t.Errorf("published a loopback DNAT or wrote route_localnet: %+v, %v", k.published[0].Rules, k.localnetWrites)
			}
		})
	}
}

// テーブルが消えた見直しは、公開し直す前に route_localnet を 0 にし、公開し直した後に 1 に戻す。外から
// 0 にされた値は、テーブルが宣言どおりの見直しで 1 に戻す(7b.2 節)。
func TestKernelLoopbackRouteLocalnetFollowsTheTable(t *testing.T) {
	allow, err := allowtargets.Parse("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	k := &fakeKernel{forwardOn: true}
	d := newTestKernel(t, k, nil, allow)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("lo", "127.0.0.1:25565", 39975, 39975)}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.localnetWrites = nil
	k.tableGone = true
	var order []string
	d.Ops.WriteRouteLocalnet = func(_ string, on bool) error {
		order = append(order, map[bool]string{true: "1", false: "0"}[on]+"@"+map[bool]string{true: "gone", false: "back"}[k.tableGone])
		k.localnet = on
		return nil
	}
	if !observeOnce(t, d, 1, rules) {
		t.Fatal("the missing table was not published again")
	}
	if !reflect.DeepEqual(order, []string{"0@gone", "1@back"}) {
		t.Errorf("route_localnet writes = %v, want 0 while the table is gone, then 1 after it is back", order)
	}
	order = nil
	k.localnet = false // 外から 0 にされた
	observeOnce(t, d, 1, rules)
	if !reflect.DeepEqual(order, []string{"1@back"}) {
		t.Errorf("route_localnet writes = %v, want it set back to 1", order)
	}
	order = nil
	k.localnet = false
	if _, err := d.ObserveNotified(1, rules); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(order, []string{"1@back"}) {
		t.Errorf("the check after a notification wrote %v, want it set back to 1", order)
	}
}

// route_localnet を 1 にできなければ、ループバックの宛先のルールだけを error として報告し、DNAT は残す。
// 警告は同じ誤りの間 1 行だけ出す。
func TestKernelLoopbackRouteLocalnetWriteFailure(t *testing.T) {
	allow, err := allowtargets.Parse("127.0.0.1,192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	k := &fakeKernel{forwardOn: true, localnetWriteEr: os.ErrPermission}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, allow)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("lo", "127.0.0.1:25565", 39975, 39975), tcpRule("lan", "192.168.1.20:80", 80, 80)}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	s := statusOf(t, d, "lo")
	if s.State != proto.StatusError || !strings.HasPrefix(s.Reason, "on the agent host, net.ipv4.conf.wgft0.route_localnet cannot be set to 1") {
		t.Errorf("lo = %+v, want a route_localnet error that names the agent host", s)
	}
	if s := statusOf(t, d, "lan"); s.State != proto.StatusOK {
		t.Errorf("lan = %+v, want ok", s)
	}
	if !k.published[len(k.published)-1].HasLoopback() {
		t.Error("the loopback DNAT was not kept")
	}
	observeOnce(t, d, 1, rules)
	if n := strings.Count(buf.String(), "cannot be set to 1"); n != 1 {
		t.Errorf("logged the failure %d times, want once:\n%s", n, buf.String())
	}
	k.localnetWriteEr = nil
	observeOnce(t, d, 1, rules)
	if s := statusOf(t, d, "lo"); s.State != proto.StatusOK {
		t.Errorf("lo = %+v after the write succeeded, want ok", s)
	}
}

// ループバックの宛先はホスト自身なので、ip_forward が 0 でも error にしない。conntrack の収束は、
// ループバックの宛先のフローを、許可一覧が明示している間だけ残す。
func TestKernelLoopbackIsLocal(t *testing.T) {
	allow, err := allowtargets.Parse("127.0.0.0/8:25565,0.0.0.0/0:80")
	if err != nil {
		t.Fatal(err)
	}
	k := &fakeKernel{forwardWriteEr: os.ErrPermission, local: map[netip.Addr]bool{netip.MustParseAddr("127.0.0.1"): true}}
	d := newTestKernel(t, k, nil, allow)
	if err := d.enableForwarding(func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	rules := []proto.AgentRule{tcpRule("lo5", "127.0.0.5:25565", 39975, 39975)}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	if s := statusOf(t, d, "lo5"); s.State != proto.StatusOK {
		t.Errorf("lo5 = %+v, want ok: a loopback target does not need ip_forward", s)
	}
	if _, err := d.ApplyRules(2, append(rules, tcpRule("x", "192.168.1.20:80", 80, 80)), nil); err != nil {
		t.Fatal(err)
	}
	if len(k.converged) == 0 {
		t.Fatal("no conntrack convergence")
	}
	scope := k.converged[len(k.converged)-1].scope
	for ap, keep := range map[string]bool{"127.0.0.5:25565": true, "127.0.0.5:80": false, "192.168.1.20:80": true} {
		if got := scope.AllowTarget(netip.MustParseAddrPort(ap)); got != keep {
			t.Errorf("conntrack keeps flows to %s = %v, want %v", ap, got, keep)
		}
	}
}

// ループバックの宛先を公開していない間、30 秒ごとの見直しと通知の後の見直しは route_localnet に 1 を
// 書かず、外から 1 にされた値を 0 に戻す(7b.2 節)。
func TestKernelChecksKeepRouteLocalnetOffWithoutLoopback(t *testing.T) {
	allow, err := allowtargets.Parse("127.0.0.0/8,192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	k := &fakeKernel{forwardOn: true}
	d := newTestKernel(t, k, nil, allow)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("lan", "192.168.1.20:80", 80, 80)}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	observeOnce(t, d, 1, rules)
	if _, err := d.ObserveNotified(1, rules); err != nil {
		t.Fatal(err)
	}
	for _, w := range k.localnetWrites {
		if w {
			t.Fatalf("route_localnet writes = %v, want no write of 1 without a loopback target", k.localnetWrites)
		}
	}
	for name, check := range map[string]func(){
		"the 30-second check": func() { observeOnce(t, d, 1, rules) },
		"the check after a notification": func() {
			if _, err := d.ObserveNotified(1, rules); err != nil {
				t.Fatal(err)
			}
		},
	} {
		k.localnet, k.localnetWrites = true, nil // 外から 1 にされた
		check()
		if k.localnet || !reflect.DeepEqual(k.localnetWrites, []bool{false}) {
			t.Errorf("%s: route_localnet writes = %v, want it put back to 0", name, k.localnetWrites)
		}
	}
}

// 起動時に自分の wgft0 があってテーブルが無いか読めなければ、route_localnet を 0 にする。全体状態が
// 届くまで最初の公開は始まらないためである。テーブルがあれば値を残す(7b.2 節)。
func TestKernelStartupClosesRouteLocalnetWithoutTheTable(t *testing.T) {
	for _, tc := range []struct {
		name      string
		gone      bool
		fpErr     error
		wantWrite []bool
	}{
		{"table present", false, nil, nil},
		{"table gone", true, nil, []bool{false}},
		{"table unreadable", false, errors.New("netlink: busy"), []bool{false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &fakeKernel{forwardOn: true, localnet: true, tableGone: tc.gone, fpErr: tc.fpErr}
			d := newTestKernel(t, k, nil, nil)
			k.link = ours(t, d)
			if err := d.Startup(d.Priv, func() error { return nil }); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(k.localnetWrites, tc.wantWrite) {
				t.Errorf("route_localnet writes = %v, want %v", k.localnetWrites, tc.wantWrite)
			}
		})
	}
	// 自分のものでない wgft0 にも、無い wgft0 にも触れない
	k := &fakeKernel{forwardOn: true, localnet: true, tableGone: true, link: wg.AgentState{Ownership: wg.Absent}}
	d := newTestKernel(t, k, nil, nil)
	if err := d.Startup(d.Priv, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	if len(k.localnetWrites) != 0 {
		t.Errorf("an absent wgft0 got route_localnet writes %v", k.localnetWrites)
	}
}

// 0 に戻すときに値を読めず、直前の公開にループバックの宛先も無ければ書かず、警告も出さない。テーブルが
// 消えた間に 0 に戻せなければ、守りの行が落とすとは言わない警告を出す。
func TestKernelRouteLocalnetOffFailures(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	k := &fakeKernel{forwardOn: true, localnetReadEr: os.ErrPermission}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("lan", "192.168.1.20:80", 80, 80)}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.tableGone = true
	observeOnce(t, d, 1, rules)
	if len(k.localnetWrites) != 0 || strings.Contains(buf.String(), "route_localnet") {
		t.Errorf("writes %v, log:\n%s\nwant nothing without a loopback target", k.localnetWrites, buf.String())
	}

	allow, err := allowtargets.Parse("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	k = &fakeKernel{forwardOn: true}
	d = newTestKernel(t, k, nil, allow)
	k.link = ours(t, d)
	lo := []proto.AgentRule{tcpRule("lo", "127.0.0.1:25565", 39975, 39975)}
	if _, err := d.ApplyRules(1, lo, nil); err != nil {
		t.Fatal(err)
	}
	buf.Reset()
	k.tableGone, k.localnetWriteEr = true, os.ErrPermission
	observeOnce(t, d, 1, lo)
	got := buf.String()
	if !strings.Contains(got, "cannot be set to 0") || !strings.Contains(got, "may reach services that listen on this host's loopback") ||
		strings.Contains(got, "still drop") {
		t.Errorf("log after a failed write of 0 while the table was gone:\n%s", got)
	}
}
