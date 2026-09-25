//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/proto"
)

// fakeKernel は kernelOps の記録器である。カーネルにも DNS にも触れずに、カーネルモードの dataplane が
// 何をどの順で呼ぶかを確かめる。
type fakeKernel struct {
	ensured   []wg.AgentConfig
	ensureErr error
	link      wg.AgentState
	linkErr   error
	holders   []string

	published  []nft.AgentPublication
	publishErr error
	// table は実際のテーブルの指紋の元である。公開のたびに進み、外からの変更は tableEdit を進めて模す
	tableGen  int
	tableEdit int
	tableGone bool
	// fpErr は、次の指紋の読みを 1 回だけ失敗させる
	fpErr error

	dns    map[string][]netip.Addr // 無い名前は解決できない
	dnsErr error                   // 設定すれば、どの名前も解決できない
	// probed は試し接続の宛先である。probeAll は同時に試すので、mu が守る
	mu       sync.Mutex
	probed   []netip.AddrPort
	probeErr map[netip.AddrPort]error
	// forwardOn は ip_forward の今の値、forwardReadEr と forwardWriteEr は読み書きの誤りである
	forwardOn      bool
	forwardReadEr  error
	forwardWriteEr error
	forwardWrites  int
	local          map[netip.Addr]bool
	// datagrams は keepalive ごとのデータグラムの宛先である。別の goroutine が送るので、mu が守る
	datagrams []netip.AddrPort
	// sendErr は、設定すればデータグラムの n 回目(0 から)の送信の誤りを返す。mu が守る
	sendErr func(n int) error
	// route は vpsd のトンネルアドレスへの経路が出るインタフェースである。空なら wgft0
	route    string
	routeErr error
	// onEnsure は、設定すれば wgft0 の収束が成功したときに呼ばれる
	onEnsure func()
	// lookups は引いた名前の記録である
	lookups []string
	// converged は conntrack の収束の呼び出しの記録である。convergeErr を設定すれば失敗させる
	converged   []convergeCall
	convergeErr error
	convergeRes conntrack.AgentResult
}

type convergeCall struct {
	prev  []nft.AgentPublication
	cur   nft.AgentPublication
	scope conntrack.AgentScope
}

func (k *fakeKernel) ops() kernelOps {
	return kernelOps{
		ensureLink: func(cfg wg.AgentConfig) ([]string, error) {
			k.ensured = append(k.ensured, cfg)
			if k.ensureErr == nil && k.onEnsure != nil {
				k.onEnsure()
			}
			return nil, k.ensureErr
		},
		inspectLink: func(string, wgtypes.Key, wgtypes.Key) (wg.AgentState, error) { return k.link, k.linkErr },
		keyHolders:  func(string, wgtypes.Key, wgtypes.Key) ([]string, error) { return k.holders, nil },
		publish: func(p nft.AgentPublication, _ nft.AgentConfig) error {
			if k.publishErr != nil {
				return k.publishErr
			}
			k.published = append(k.published, p)
			k.tableGen++
			k.tableGone = false
			return nil
		},
		fingerprint: func(string) (string, bool, error) {
			if err := k.fpErr; err != nil {
				k.fpErr = nil
				return "", false, err
			}
			if k.tableGone {
				return "", false, nil
			}
			return fmt.Sprintf("fp-%d-%d", k.tableGen, k.tableEdit), true, nil
		},
		lookup: func(_ context.Context, host string) ([]netip.Addr, error) {
			k.mu.Lock()
			k.lookups = append(k.lookups, host)
			k.mu.Unlock()
			if k.dnsErr != nil {
				return nil, k.dnsErr
			}
			a, ok := k.dns[host]
			if !ok {
				return nil, fmt.Errorf("no such host %s", host)
			}
			return a, nil
		},
		probe: func(_ context.Context, d netip.AddrPort) error {
			k.mu.Lock()
			defer k.mu.Unlock()
			k.probed = append(k.probed, d)
			return k.probeErr[d]
		},
		readIPForward: func() (bool, error) { return k.forwardOn, k.forwardReadEr },
		writeIPForward: func() error {
			k.forwardWrites++
			if k.forwardWriteEr != nil {
				return k.forwardWriteEr
			}
			k.forwardOn = true
			return nil
		},
		localAddrs: func() (map[netip.Addr]bool, error) { return k.local, nil },
		sendDatagram: func(dst netip.AddrPort) error {
			k.mu.Lock()
			defer k.mu.Unlock()
			k.datagrams = append(k.datagrams, dst)
			if k.sendErr != nil {
				return k.sendErr(len(k.datagrams) - 1)
			}
			return nil
		},
		convergeFlows: func(prev []nft.AgentPublication, cur nft.AgentPublication, scope conntrack.AgentScope) (conntrack.AgentResult, error) {
			k.converged = append(k.converged, convergeCall{append([]nft.AgentPublication(nil), prev...), cur, scope})
			return k.convergeRes, k.convergeErr
		},
		routeIface: func(netip.Addr) (string, error) {
			if k.route == "" {
				return "wgft0", k.routeErr
			}
			return k.route, k.routeErr
		},
		now: func() time.Time { return time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC) },
	}
}

// newTestKernel は fakeKernel を使うカーネルモードの dataplane を、wg 設定を受け取った状態で作る。
func newTestKernel(t *testing.T, k *fakeKernel, f *credentials.Credentials, allow *allowtargets.List) *kernelDataplane {
	t.Helper()
	if f == nil {
		f = &credentials.Credentials{}
	}
	d := &kernelDataplane{ops: k.ops(), iface: "wgft0", allow: allow, f: f, ctx: context.Background(),
		lkg: map[string]lkgEntry{}, probeErr: map[string]string{}}
	d.loadRecord()
	if _, err := d.build(testKey(t), testWG(t)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.close)
	return d
}

func testKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testWG(t *testing.T) proto.WGConfig {
	return proto.WGConfig{ServerPubkey: testKey(t).PublicKey().String(), Endpoint: "203.0.113.1:51820",
		Address: "10.200.0.2/24", MTU: 1420, Keepalive: 25}
}

func tcpRule(id, target string, lo, hi uint16) proto.AgentRule {
	return proto.AgentRule{ID: id, Proto: proto.TCP, ListenPort: proto.PortRange{Lo: lo, Hi: hi}, Target: target, Enabled: true}
}

func statusOf(t *testing.T, d *kernelDataplane, id string) proto.RuleStatus {
	t.Helper()
	for _, s := range d.read().rules {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("no status for rule %s in %+v", id, d.read().rules)
	return proto.RuleStatus{}
}

// 公開は wgft0 の収束の後に行い、成功したら記録を認証情報ファイルへ写し、ルールを ok にする。
// wgft0 のピアは vpsd のトンネルアドレス(帯の先頭)で、エンドポイントは解決した結果である(7b.1 節)。
func TestKernelApplyPublishesAndRecords(t *testing.T) {
	k := &fakeKernel{}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	if _, err := d.applyRules(7, []proto.AgentRule{tcpRule("r1", "192.168.1.20:25565", 25565, 25565)}, nil); err != nil {
		t.Fatal(err)
	}
	if len(k.ensured) != 1 || len(k.published) != 1 {
		t.Fatalf("ensured %d times, published %d times; want 1 and 1", len(k.ensured), len(k.published))
	}
	cfg := k.ensured[0]
	if cfg.Server.Address != netip.MustParseAddr("10.200.0.1") || cfg.Server.Endpoint != netip.MustParseAddrPort("203.0.113.1:51820") ||
		cfg.Server.Keepalive != 25*time.Second || cfg.Interface != "wgft0" {
		t.Errorf("wgft0 config = %+v", cfg)
	}
	var rec nft.AgentPublication
	if err := json.Unmarshal(f.KernelPublication, &rec); err != nil || rec.Generation != 7 || len(rec.Rules) != 1 {
		t.Fatalf("record = %s (%v)", f.KernelPublication, err)
	}
	if s := statusOf(t, d, "r1"); s.State != proto.StatusOK {
		t.Errorf("r1 = %+v, want ok", s)
	}
}

// テーブル全体の公開の失敗は誤りとして返し、直前の記録を残す(7b.3 節の 3 つ目の種類)。
func TestKernelPublishFailureKeepsTheRecord(t *testing.T) {
	k := &fakeKernel{}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	if _, err := d.applyRules(1, []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}, nil); err != nil {
		t.Fatal(err)
	}
	before := string(f.KernelPublication)
	k.publishErr = errors.New("batch refused")
	_, err := d.applyRules(2, []proto.AgentRule{tcpRule("r2", "192.168.1.21:81", 81, 81)}, nil)
	if err == nil || isFatal(err) {
		t.Fatalf("err = %v, want a plain error", err)
	}
	if string(f.KernelPublication) != before || d.pub.Generation != 1 {
		t.Errorf("a failed publication replaced the record: %s", f.KernelPublication)
	}
	if s := statusOf(t, d, "r1"); s.State != proto.StatusOK {
		t.Errorf("r1 = %+v; a table-wide failure must not rewrite rule states", s)
	}
}

// このプロセスの最初の wgft0 の収束では、所有の衝突、アドレス帯の重なり、前提の欠如はプロセスを終える
// 誤りになる。一度収束させた後は、同じ誤りも試し直す誤りである(11b 節、2026-09-24 の所有者の決定)。
func TestKernelFirstConvergenceFailuresAreFatal(t *testing.T) {
	cases := map[string]error{
		"not ours":     &wg.NotOursError{Interface: "wgft0", Ownership: wg.ForeignKey, Kind: "wireguard"},
		"overlap":      &wg.OverlapError{Range: netip.MustParsePrefix("10.200.0.0/24"), What: "10.200.0.0/24 on eth1", Server: netip.MustParseAddr("10.200.0.1"), Interface: "wgft0"},
		"prerequisite": startup.Prerequisite("CAP_NET_ADMIN", "kernel mode needs CAP_NET_ADMIN"),
	}
	for name, cause := range cases {
		t.Run(name, func(t *testing.T) {
			k := &fakeKernel{ensureErr: cause}
			d := newTestKernel(t, k, nil, nil)
			_, err := d.applyRules(1, nil, nil)
			if !isFatal(err) {
				t.Fatalf("first convergence: err = %v, want fatal", err)
			}
			if (name == "prerequisite") != (startup.Of(err) != nil) {
				t.Errorf("refusal = %v; only the prerequisite case exits 3", startup.Of(err))
			}
			k.ensureErr = nil
			if _, err := d.applyRules(1, nil, nil); err != nil {
				t.Fatal(err)
			}
			k.ensureErr = cause
			if _, err := d.applyRules(2, nil, nil); err == nil || isFatal(err) {
				t.Errorf("after a convergence: err = %v, want a retried error", err)
			}
		})
	}
	t.Run("other errors are retried even first", func(t *testing.T) {
		k := &fakeKernel{ensureErr: errors.New("netlink: device or resource busy")}
		d := newTestKernel(t, k, nil, nil)
		if _, err := d.applyRules(1, nil, nil); err == nil || isFatal(err) {
			t.Errorf("err = %v, want a retried error", err)
		}
	})
}

// 名前の解決に失敗したルールは、宣言の宛先の文字列が同じ間だけ、直前に解決できたアドレスを使い続け、
// そのことを理由に示す。宛先の文字列が変われば、ポートだけの変更でも新しい宛先として公開しない。
// 一度も解決できていないルールも公開しない(7b.2 節、2026-09-24 の所有者の決定)。
func TestKernelLastKnownGoodResolution(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.30")}}}
	d := newTestKernel(t, k, nil, nil)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.dnsErr = errors.New("server misbehaving")
	if _, err := d.applyRules(2, rules, nil); err != nil {
		t.Fatal(err)
	}
	pub := k.published[len(k.published)-1]
	if len(pub.Rules[0].Ranges) != 1 || pub.Rules[0].Ranges[0].Dest != netip.MustParseAddrPort("192.168.1.30:25565") {
		t.Fatalf("with a failed lookup the rule published %+v, want the last good address", pub.Rules[0])
	}
	s := statusOf(t, d, "r1")
	if s.State != proto.StatusError || !strings.Contains(s.Reason, "name resolution") || !strings.Contains(s.Reason, "still forwarding to 192.168.1.30") {
		t.Errorf("r1 = %+v, want an error that says the name did not resolve and the old address is used", s)
	}

	// 同じ名前でもポートが変われば新しい宛先であり、公開しない
	moved := []proto.AgentRule{tcpRule("r1", "game.lan:25566", 25565, 25565)}
	if _, err := d.applyRules(3, moved, nil); err != nil {
		t.Fatal(err)
	}
	if got := k.published[len(k.published)-1].Rules[0]; len(got.Ranges) != 0 || !strings.Contains(got.Reason, "name resolution") {
		t.Errorf("a changed target used the old resolution: %+v", got)
	}
	// 一度も解決できていないルールも公開しない
	fresh := []proto.AgentRule{tcpRule("r2", "new.lan:80", 80, 80)}
	if _, err := d.applyRules(4, fresh, nil); err != nil {
		t.Fatal(err)
	}
	if got := k.published[len(k.published)-1].Rules[0]; len(got.Ranges) != 0 {
		t.Errorf("a never-resolved rule was published: %+v", got)
	}
}

// 直前の解決の結果を使うときも、今の許可一覧を当てはめ直す。一覧が狭まって通らなければ公開せず、
// 理由は解決の失敗と、直前のアドレスも使えないことの両方を示す(7b.2 節)。
func TestKernelLastKnownGoodHonoursTheAllowlist(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.30")}}}
	d := newTestKernel(t, k, nil, nil)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	narrow, err := allowtargets.Parse("192.168.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	d.allow = narrow
	k.dnsErr = errors.New("timeout")
	if _, err := d.applyRules(2, rules, nil); err != nil {
		t.Fatal(err)
	}
	got := k.published[len(k.published)-1].Rules[0]
	if len(got.Ranges) != 0 || !strings.Contains(got.Reason, "name resolution") || !strings.Contains(got.Reason, "not usable") {
		t.Errorf("rule = %+v, want no DNAT and a reason naming both failures", got)
	}
}

// 起動時は、認証情報ファイルの公開の記録から、直前に解決できたアドレスを読み直す。DNS が止まっている
// 間に再起動しても、動いていた DNAT を消さない(7b.2 節)。
func TestKernelLastKnownGoodSurvivesARestart(t *testing.T) {
	rec := nft.AgentPublication{Generation: 5, Rules: []nft.AgentRuleResult{{
		RuleID: "r1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2457}, Target: "game.lan:2456",
		Ranges: []nft.AgentRange{{Ports: proto.PortRange{Lo: 2456, Hi: 2457}, Dest: netip.MustParseAddrPort("192.168.1.30:2456")}},
	}}}
	b, _ := json.Marshal(rec)
	k := &fakeKernel{dnsErr: errors.New("no route to the resolver")}
	d := newTestKernel(t, k, &credentials.Credentials{KernelPublication: b}, nil)
	rules := []proto.AgentRule{{ID: "r1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2457}, Target: "game.lan:2456", Enabled: true}}
	if _, err := d.applyRules(5, rules, nil); err != nil {
		t.Fatal(err)
	}
	got := k.published[0].Rules[0]
	if len(got.Ranges) != 1 || got.Ranges[0].Dest != netip.MustParseAddrPort("192.168.1.30:2456") {
		t.Errorf("after a restart during a DNS outage the rule published %+v, want the recorded address", got)
	}
}

// TCP の試し接続は、連続するポートと宛先の範囲ごとに、先頭のポートの 1 つだけを試す(7b.3 節、
// 2026-09-24 の所有者の決定)。UDP は試さない。失敗は error として報告するが、DNAT は残す。
func TestKernelProbesOnePortPerRange(t *testing.T) {
	k := &fakeKernel{probeErr: map[netip.AddrPort]error{netip.MustParseAddrPort("192.168.1.21:2000"): errors.New("connection refused")}}
	d := newTestKernel(t, k, nil, nil)
	rules := []proto.AgentRule{
		tcpRule("wide", "192.168.1.20:1000", 1000, 1999),
		tcpRule("down", "192.168.1.21:2000", 2000, 2000),
		{ID: "udp", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 3000, Hi: 3000}, Target: "192.168.1.22:3000", Enabled: true},
	}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	want := map[netip.AddrPort]bool{netip.MustParseAddrPort("192.168.1.20:1000"): true, netip.MustParseAddrPort("192.168.1.21:2000"): true}
	if len(k.probed) != len(want) {
		t.Fatalf("probed %v, want exactly %v", k.probed, want)
	}
	for _, p := range k.probed {
		if !want[p] {
			t.Errorf("probed %s, which is not the first port of a range", p)
		}
	}
	if s := statusOf(t, d, "down"); s.State != proto.StatusError || !strings.Contains(s.Reason, "connection refused") {
		t.Errorf("down = %+v", s)
	}
	if got := k.published[0]; len(got.Rules) != 3 {
		t.Errorf("the probe failure removed a DNAT: %+v", got)
	}
	if s := statusOf(t, d, "wide"); s.State != proto.StatusOK {
		t.Errorf("wide = %+v", s)
	}
}

// ip_forward を 1 にできなければ、宛先がホスト自身でないルールを error として報告し、DNAT は残す。
// ip_forward を 1 にできなければ、記録を残さず、宛先がホスト自身でないルールを error として報告し、
// DNAT は残す。30 秒ごとに読み直し、1 になれば error を消す(7b.1 節)。
func TestKernelIPForwardFailureReportsOnlyRemoteTargets(t *testing.T) {
	k := &fakeKernel{forwardWriteEr: os.ErrPermission, local: map[netip.Addr]bool{netip.MustParseAddr("192.168.1.10"): true}}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	saves := 0
	if err := d.enableForwarding(func() error { saves++; return nil }); err != nil {
		t.Fatal(err)
	}
	rules := []proto.AgentRule{tcpRule("self", "192.168.1.10:80", 80, 80), tcpRule("other", "192.168.1.20:81", 81, 81)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	if s := statusOf(t, d, "self"); s.State != proto.StatusOK {
		t.Errorf("self = %+v, want ok: the kernel delivers to this host without forwarding", s)
	}
	if s := statusOf(t, d, "other"); s.State != proto.StatusError || !strings.Contains(s.Reason, "ip_forward") {
		t.Errorf("other = %+v, want an ip_forward error", s)
	}
	if f.IPForwardEnabledAt != nil {
		t.Error("a failed write left a record of a change")
	}
	if saves != 2 {
		t.Errorf("saved %d times, want the record saved before the write and removed after it failed", saves)
	}
	k.forwardOn = true
	d.refresh()
	if s := statusOf(t, d, "other"); s.State != proto.StatusOK {
		t.Errorf("other = %+v after ip_forward became 1", s)
	}
}

// 0 から 1 に変えるときは、値を書く前に日時を記録して保存する。保存できなければ値を書かずに誤りを
// 返す。今の値を読めなければ、1 を書いても記録しない。既に 1 なら何もしない(7b.1 節)。
func TestKernelRecordsTheIPForwardChangeBeforeMakingIt(t *testing.T) {
	when := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	t.Run("0 is recorded before the write", func(t *testing.T) {
		k := &fakeKernel{}
		f := &credentials.Credentials{}
		d := newTestKernel(t, k, f, nil)
		var writesAtSave int
		err := d.enableForwarding(func() error {
			writesAtSave = k.forwardWrites
			if f.IPForwardEnabledAt == nil || !f.IPForwardEnabledAt.Equal(when) {
				t.Errorf("saved without the record: %v", f.IPForwardEnabledAt)
			}
			return nil
		})
		if err != nil || !k.forwardOn || writesAtSave != 0 {
			t.Errorf("err %v on %v writes-before-save %d; want the save first, then the write", err, k.forwardOn, writesAtSave)
		}
	})
	t.Run("a failed save writes nothing", func(t *testing.T) {
		k := &fakeKernel{}
		f := &credentials.Credentials{}
		d := newTestKernel(t, k, f, nil)
		err := d.enableForwarding(func() error { return errors.New("disk full") })
		if err == nil || k.forwardWrites != 0 || f.IPForwardEnabledAt != nil {
			t.Errorf("err %v writes %d record %v; want an error, no write and no record", err, k.forwardWrites, f.IPForwardEnabledAt)
		}
	})
	t.Run("an unreadable value is not recorded", func(t *testing.T) {
		k := &fakeKernel{forwardReadEr: os.ErrPermission}
		f := &credentials.Credentials{}
		d := newTestKernel(t, k, f, nil)
		if err := d.enableForwarding(func() error { t.Error("saved a record for an unreadable value"); return nil }); err != nil {
			t.Fatal(err)
		}
		if k.forwardWrites != 1 || f.IPForwardEnabledAt != nil {
			t.Errorf("writes %d record %v; want 1 written and nothing recorded", k.forwardWrites, f.IPForwardEnabledAt)
		}
	})
	t.Run("already 1", func(t *testing.T) {
		k := &fakeKernel{forwardOn: true}
		f := &credentials.Credentials{}
		d := newTestKernel(t, k, f, nil)
		if err := d.enableForwarding(func() error { t.Error("saved although nothing changed"); return nil }); err != nil {
			t.Fatal(err)
		}
		if k.forwardWrites != 0 || f.IPForwardEnabledAt != nil {
			t.Errorf("writes %d record %v; want nothing", k.forwardWrites, f.IPForwardEnabledAt)
		}
	})
}

// 起動時の所有の判定:他の所有者のインタフェースは終了コード 1 の誤り、読む権限が無ければ種別
// prerequisite の拒否、無いか自分のものなら通す(7b.4 節)。
func TestKernelStartupJudgesOwnership(t *testing.T) {
	priv := testKey(t)
	cases := []struct {
		name    string
		link    wg.AgentState
		linkErr error
		want    string // "ok"、"not ours"、"refusal"
	}{
		{"absent", wg.AgentState{Ownership: wg.Absent}, nil, "ok"},
		{"ours", wg.AgentState{Exists: true, Kind: "wireguard", Ownership: wg.OwnedByCurrentKey}, nil, "ok"},
		{"previous key", wg.AgentState{Exists: true, Kind: "wireguard", Ownership: wg.OwnedByPreviousKey}, nil, "ok"},
		{"foreign", wg.AgentState{Exists: true, Kind: "wireguard", Ownership: wg.ForeignKey, PublicKey: testKey(t).PublicKey()}, nil, "not ours"},
		{"keyless", wg.AgentState{Exists: true, Kind: "wireguard", Ownership: wg.ForeignKey}, nil, "not ours"},
		{"not wireguard", wg.AgentState{Exists: true, Kind: "dummy", Ownership: wg.NotWireGuard}, nil, "not ours"},
		{"no privilege", wg.AgentState{}, os.ErrPermission, "refusal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			k := &fakeKernel{link: c.link, linkErr: c.linkErr}
			d := newTestKernel(t, k, nil, nil)
			err := d.startup(priv, func() error { return nil })
			var notOurs *wg.NotOursError
			switch c.want {
			case "ok":
				if err != nil {
					t.Errorf("err = %v", err)
				}
			case "not ours":
				if !errors.As(err, &notOurs) || startup.Of(err) != nil {
					t.Errorf("err = %v, want *wg.NotOursError, exit 1", err)
				}
				if c.name == "keyless" && !notOurs.Keyless {
					t.Error("a keyless link was not reported as keyless")
				}
			case "refusal":
				if r := startup.Of(err); r == nil || r.Category != startup.CategoryPrerequisite {
					t.Errorf("err = %v, want a prerequisite refusal", err)
				}
			}
			if len(k.ensured) != 0 || len(k.published) != 0 {
				t.Error("startup wrote to the kernel")
			}
		})
	}
}

// 停止で取り消された解決の結果では公開しない。取り消された解決を失敗と見て DNAT を消さないためである。
func TestKernelDoesNotPublishWhileStopping(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.30")}}}
	d := newTestKernel(t, k, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	d.ctx = ctx
	cancel()
	if _, err := d.applyRules(1, []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}, nil); err == nil {
		t.Fatal("applyRules succeeded while stopping")
	}
	if len(k.published) != 0 {
		t.Errorf("published %d tables while stopping", len(k.published))
	}
}

// close はカーネルに触れず、鍵を忘れるだけである。rotate-key が次の build で渡す新しい鍵で wgft0 を
// 収束させ、1 つ前の鍵を認証情報ファイルから渡す(7b.4 節)。
func TestKernelCloseAndRebuildUsesTheNewKey(t *testing.T) {
	k := &fakeKernel{}
	old, next := testKey(t), testKey(t)
	f := &credentials.Credentials{Mode: "kernel", WGPrivateKey: old.String()}
	d := newTestKernel(t, k, f, nil)
	d.close()
	if d.built() {
		t.Fatal("still built after close")
	}
	f.KeepPreviousKey()
	f.WGPrivateKey = next.String()
	if _, err := d.build(next, testWG(t)); err != nil {
		t.Fatal(err)
	}
	if _, err := d.applyRules(1, nil, nil); err != nil {
		t.Fatal(err)
	}
	got := k.ensured[len(k.ensured)-1]
	if got.PrivateKey != next || got.PreviousKey != old {
		t.Errorf("wgft0 converged with key %v and previous %v; want the new key and the old one as previous", got.PrivateKey.PublicKey(), got.PreviousKey.PublicKey())
	}
}

// 名前を引いている最中に停止で取り消されたら、公開せず、動いている DNAT を消さない。取り消された
// 解決を失敗と見て公開すると、動いていたルールを閉じてしまう。
func TestKernelCancelDuringResolutionPublishesNothing(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.30")}}}
	d := newTestKernel(t, k, nil, nil)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	d.ctx = ctx
	d.ops.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		cancel() // SIGTERM が名前の解決の最中に届く
		<-ctx.Done()
		return nil, ctx.Err()
	}
	prepared := d.prepareApply(&proto.State{Generation: 2, WG: d.wg, Rules: rules})
	if _, err := d.applyRules(2, rules, prepared); err == nil {
		t.Fatal("applyRules published with a resolution cancelled by stopping")
	}
	if len(k.published) != 1 || d.pub.Generation != 1 || len(d.pub.Rules[0].Ranges) != 1 {
		t.Errorf("published %d tables, record %+v; want the first publication kept as it was", len(k.published), d.pub)
	}
}

// 解決の失敗が続いても、直前に解決できたアドレスを使い続ける。1 回目の失敗の公開が、次の失敗の
// ときの直前のアドレスを引き継ぐ(7b.2 節)。
func TestKernelLastKnownGoodAcrossRepeatedFailures(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.30")}}}
	d := newTestKernel(t, k, nil, nil)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.dnsErr = errors.New("timeout")
	for gen := uint64(2); gen <= 4; gen++ {
		if _, err := d.applyRules(gen, rules, nil); err != nil {
			t.Fatal(err)
		}
		got := k.published[len(k.published)-1].Rules[0]
		if len(got.Ranges) != 1 || got.Ranges[0].Dest != netip.MustParseAddrPort("192.168.1.30:80") {
			t.Fatalf("failure %d in a row published %+v, want the last good address", gen-1, got)
		}
	}
}

// 宛先の名前は同時に引く。1 つの遅い名前が、他の名前の期限を使い切らない。
func TestKernelResolvesTargetsConcurrently(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	started := make(chan string, 2)
	release := make(chan struct{})
	d.ops.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		started <- host
		<-release
		return []netip.Addr{netip.MustParseAddr("192.168.1.40")}, nil
	}
	rules := []proto.AgentRule{tcpRule("a", "a.lan:80", 80, 80), tcpRule("b", "b.lan:81", 81, 81)}
	done := make(chan any, 1)
	go func() { done <- d.prepareApply(&proto.State{WG: d.wg, Rules: rules}) }()
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("the second name waited for the first")
		}
	}
	close(release)
	p := (<-done).(*kernelPrepared)
	if len(p.resolved) != 2 || p.resolved["a.lan"].Err != nil || p.resolved["b.lan"].Err != nil {
		t.Errorf("resolved = %+v", p.resolved)
	}
}

// ours は、宣言どおりの wgft0 の状態を返す。
func ours(t *testing.T, d *kernelDataplane) wg.AgentState {
	t.Helper()
	cfg, err := d.linkConfig()
	if err != nil {
		t.Fatal(err)
	}
	return wg.AgentState{Exists: true, Kind: "wireguard", Ownership: wg.OwnedByCurrentKey, Up: true, MTU: cfg.MTU,
		Addresses: []netip.Prefix{cfg.Address},
		Peers: []wg.PeerState{{PublicKey: cfg.Server.PublicKey, AllowedIPs: []netip.Prefix{netip.PrefixFrom(cfg.Server.Address, 32)},
			Keepalive: cfg.Server.Keepalive, Endpoint: netip.MustParseAddrPort("198.51.100.200:51820")}}}
}

func observeOnce(t *testing.T, d *kernelDataplane, gen uint64, rules []proto.AgentRule) bool {
	t.Helper()
	saved, err := d.observeCommit(gen, rules, d.observePrepare(rules))
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	return saved
}

// 30 秒ごとの見直しは、PlanAgent の結果の DNAT が変わったときだけ公開し直す。名前の解決の結果が
// 変わっても、選ぶアドレスが同じなら公開し直さない(7b.2 節)。エンドポイントの違いは食い違いにしない。
func TestKernelObserveRepublishesOnlyWhenTheDNATChanges(t *testing.T) {
	a3, a4, a9 := netip.MustParseAddr("192.168.1.3"), netip.MustParseAddr("192.168.1.4"), netip.MustParseAddr("192.168.1.9")
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {a3, a9}}}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	if observeOnce(t, d, 1, rules) || len(k.published) != 1 {
		t.Fatalf("an unchanged check published %d tables", len(k.published)-1)
	}
	k.dns["game.lan"] = []netip.Addr{a3} // 集合は変わったが、最も小さいアドレスは同じ
	if observeOnce(t, d, 1, rules) || len(k.published) != 1 {
		t.Errorf("a resolution change that keeps the chosen address republished")
	}
	k.dns["game.lan"] = []netip.Addr{a4, a9}
	if !observeOnce(t, d, 1, rules) || len(k.published) != 2 {
		t.Fatalf("a changed chosen address did not republish")
	}
	if got := k.published[1].Rules[0].Ranges[0].Dest.Addr(); got != a4 {
		t.Errorf("republished to %s, want %s", got, a4)
	}
	if len(k.ensured) != 1 {
		t.Errorf("a resolution change converged wgft0 again: %d times", len(k.ensured))
	}
}

// 見直しは、テーブルが外で変えられたか消えたとき、同じ公開をやり直す。wgft0 が宣言と違えば、先に
// wgft0 を収束させる(7b.4 節)。
func TestKernelObserveRepairsDrift(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.tableEdit++ // nft で行を消したなど
	if !observeOnce(t, d, 1, rules) || len(k.published) != 2 || len(k.ensured) != 1 {
		t.Fatalf("a changed table: published %d, ensured %d; want the table again without touching wgft0", len(k.published), len(k.ensured))
	}
	if observeOnce(t, d, 1, rules) || len(k.published) != 2 {
		t.Fatal("the check after a repair published again")
	}
	k.tableGone = true // systemctl reload nftables など
	if !observeOnce(t, d, 1, rules) || len(k.published) != 3 {
		t.Fatal("a missing table was not published again")
	}
	link := ours(t, d)
	link.MTU = 1280
	k.link = link
	if !observeOnce(t, d, 1, rules) || len(k.ensured) != 2 || len(k.published) != 4 {
		t.Fatalf("a changed MTU: ensured %d, published %d; want wgft0 converged and the table published", len(k.ensured), len(k.published))
	}
	k.link = ours(t, d)
	k.link.Peers[0].Endpoint = netip.MustParseAddrPort("203.0.113.99:40000")
	if observeOnce(t, d, 1, rules) || len(k.published) != 4 {
		t.Error("an endpoint that moved was treated as drift")
	}
}

// 見直しの公開が失敗したら、旧い記録を残し、同じ誤りでは 1 行だけ出し、次の見直しで試し直す。
func TestKernelObserveFailureKeepsTheRecord(t *testing.T) {
	k := &fakeKernel{}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	before := string(f.KernelPublication)
	k.tableGone = true
	k.publishErr = errors.New("table is owned by another process")
	if _, err := d.observeCommit(1, rules, d.observePrepare(rules)); err == nil {
		t.Fatal("a failed republish returned no error")
	}
	if string(f.KernelPublication) != before {
		t.Error("a failed republish replaced the record")
	}
	k.publishErr = nil
	if !observeOnce(t, d, 1, rules) || k.tableGone {
		t.Error("the next check did not publish again")
	}
}

// 理由の文言だけが変わったとき(DNS の誤りの文面など)は、記録を書き換えるが、テーブルは差し替えない。
func TestKernelObserveReasonOnlyChangeDoesNotRepublish(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.30")}}}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.dnsErr = errors.New("i/o timeout")
	if !observeOnce(t, d, 1, rules) || len(k.published) != 1 {
		t.Fatalf("published %d tables; a failed lookup that keeps the last good address changes only the reason", len(k.published))
	}
	if !strings.Contains(string(f.KernelPublication), "i/o timeout") {
		t.Error("the record does not carry the new reason")
	}
	k.dnsErr = errors.New("server misbehaving")
	if !observeOnce(t, d, 1, rules) || len(k.published) != 1 {
		t.Error("a new error text republished the table")
	}
}

// runtime の見直しは、名前を引く間に処理済みの全体状態が変われば、その解決の結果を捨てる。古い宣言の
// 解決の結果で新しい公開を上書きしないためである。試し直しを待つ間も見直しを行わない。
func TestObserveDiscardsAStaleResolution(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.3")}}}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	rt := &runtime{opts: Options{CredentialsPath: t.TempDir() + "/agent.json", Mode: "kernel"}, f: f, priv: d.priv, dp: d, wgCfg: d.wg}
	old := &proto.State{Generation: 1, WG: d.wg, Rules: []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}}
	rt.mu.Lock()
	if err := rt.finishApplyLocked(old, nil); err != nil {
		t.Fatal(err)
	}
	rt.mu.Unlock()
	published := len(k.published)

	newer := &proto.State{Generation: 2, WG: d.wg, Rules: []proto.AgentRule{tcpRule("r1", "192.168.1.50:80", 80, 80)}}
	d.ops.lookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		// 名前を引いている間に、stream が新しい全体状態を適用し終える
		rt.mu.Lock()
		if err := rt.finishApplyLocked(newer, nil); err != nil {
			t.Error(err)
		}
		rt.mu.Unlock()
		return []netip.Addr{netip.MustParseAddr("192.168.1.99")}, nil
	}
	rt.observe()
	if len(k.published) != published+1 {
		t.Fatalf("published %d tables during the check, want only the new state's 1", len(k.published)-published)
	}
	if got := d.pub.Rules[0].Ranges[0].Dest.Addr(); got != netip.MustParseAddr("192.168.1.50") {
		t.Errorf("the check overwrote the new state with the old one's resolution: DNAT to %s", got)
	}

	rt.mu.Lock()
	rt.pendingSt = &proto.State{Generation: 3}
	rt.mu.Unlock()
	k.tableGone = true
	before := len(k.published)
	rt.observe()
	if len(k.published) != before {
		t.Error("the check published while a pending state waits for its retry")
	}
	rt.mu.Lock()
	rt.pendingSt = nil
	rt.mu.Unlock()
	rt.stateNotify = make(chan struct{}, 1)
	rt.observe()
	if len(k.published) != before+1 {
		t.Error("the check did not repair the missing table once nothing was pending")
	}
	// 見直しが公開し直したら、次の 30 秒を待たずにハートビートを送らせる
	select {
	case <-rt.stateNotify:
	default:
		t.Error("the repair did not ask for a heartbeat")
	}
}

// 公開の後に指紋を読めなければ、比べる基準が無いので、次の見直しは同じ公開をやり直して指紋を読み直す
// (7a.3 節の指紋の読み直しの失敗と同じ扱い)。
func TestKernelObserveRepublishesAfterAnUnreadFingerprint(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}
	k.fpErr = errors.New("netlink: message truncated")
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	if !observeOnce(t, d, 1, rules) || len(k.published) != 2 {
		t.Fatalf("published %d tables; an unread fingerprint must be published and read again", len(k.published))
	}
	if !strings.Contains(d.driftSeen, "was not read after the last publication") {
		t.Errorf("drift = %q, want it to name the unread fingerprint", d.driftSeen)
	}
	if observeOnce(t, d, 1, rules) || len(k.published) != 2 {
		t.Error("the check after the fingerprint was read again published again")
	}
}

// DNAT が変わって公開し直したら、TCP の宛先へ試し接続し直す。新しい宛先の結果をすぐに報告するためである。
func TestKernelObserveProbesAfterADNATChange(t *testing.T) {
	a3, a4 := netip.MustParseAddr("192.168.1.3"), netip.MustParseAddr("192.168.1.4")
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {a3}}}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.dns["game.lan"] = []netip.Addr{a4}
	k.probeErr = map[netip.AddrPort]error{netip.AddrPortFrom(a4, 80): errors.New("connection refused")}
	if !observeOnce(t, d, 1, rules) {
		t.Fatal("the changed address did not republish")
	}
	if last := k.probed[len(k.probed)-1]; last != netip.AddrPortFrom(a4, 80) {
		t.Errorf("last probe %s, want the new target", last)
	}
	if s := statusOf(t, d, "r1"); s.State != proto.StatusError {
		t.Errorf("r1 = %+v, want the new target's probe error at once", s)
	}
}

// 停止で名前の解決が取り消されたら、見直しは何もしない。取り消しの誤りを解決の失敗として理由に
// 書いた記録も作らない。
func TestKernelObserveDoesNothingWhenStopping(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.3")}}}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	before := string(f.KernelPublication)
	ctx, cancel := context.WithCancel(context.Background())
	d.ctx = ctx
	d.ops.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		cancel()
		return nil, ctx.Err()
	}
	k.tableGone = true
	if observeOnce(t, d, 1, rules) {
		t.Error("a check cancelled by stopping reported a change")
	}
	if len(k.published) != 1 || string(f.KernelPublication) != before || strings.Contains(string(f.KernelPublication), "context canceled") {
		t.Errorf("published %d tables, record %s; want nothing done", len(k.published), f.KernelPublication)
	}
}

// wgft0 の keepalive、アドレス、up のどれかが宣言と違えば、wgft0 を収束させてからテーブルを公開し直す。
func TestKernelObserveFindsEachLinkDrift(t *testing.T) {
	cases := map[string]func(*wg.AgentState){
		"keepalive":  func(st *wg.AgentState) { st.Peers[0].Keepalive = 0 },
		"address":    func(st *wg.AgentState) { st.Addresses = []netip.Prefix{netip.MustParsePrefix("10.200.0.9/24")} },
		"extra addr": func(st *wg.AgentState) { st.Addresses = append(st.Addresses, netip.MustParsePrefix("10.9.9.9/32")) },
		"down":       func(st *wg.AgentState) { st.Up = false },
		"key":        func(st *wg.AgentState) { st.Ownership = wg.OwnedByPreviousKey },
		"allowed":    func(st *wg.AgentState) { st.Peers[0].AllowedIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")} },
		"extra peer": func(st *wg.AgentState) { st.Peers = append(st.Peers, wg.PeerState{PublicKey: testKey(t).PublicKey()}) },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			k := &fakeKernel{}
			d := newTestKernel(t, k, nil, nil)
			k.link = ours(t, d)
			rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}
			if _, err := d.applyRules(1, rules, nil); err != nil {
				t.Fatal(err)
			}
			st := ours(t, d)
			change(&st)
			k.link = st
			if !observeOnce(t, d, 1, rules) || len(k.ensured) != 2 || len(k.published) != 2 {
				t.Errorf("ensured %d, published %d; want wgft0 converged and the table published", len(k.ensured), len(k.published))
			}
		})
	}
}

// 他のプロセスが同じ変更を繰り返すと、見直しは 30 秒ごとに直し続けるが、ログは食い違いの無い見直しを
// 挟むまで 1 行だけにする。
func TestKernelObserveLogsARecurringDriftOnce(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	for i := 0; i < 3; i++ {
		k.tableEdit++ // 他のプロセスがまた書き換える
		observeOnce(t, d, 1, rules)
	}
	if n := strings.Count(buf.String(), "changed outside wgft"); n != 1 {
		t.Errorf("logged the recurring drift %d times, want 1:\n%s", n, buf.String())
	}
	if len(k.published) != 4 {
		t.Errorf("published %d tables, want a repair on every check", len(k.published))
	}
	observeOnce(t, d, 1, rules) // 食い違いの無い見直し
	k.tableEdit++
	observeOnce(t, d, 1, rules)
	if n := strings.Count(buf.String(), "changed outside wgft"); n != 2 {
		t.Errorf("a drift after a clean check logged %d lines in all, want 2", n)
	}
	// 直らないうちに別の食い違いが続けば、その食い違いも 1 行出す
	k.tableGone = true
	observeOnce(t, d, 1, rules)
	if !strings.Contains(buf.String(), "table inet wgft_agent is gone") {
		t.Errorf("a different drift right after another was not logged:\n%s", buf.String())
	}
	link := ours(t, d)
	link.MTU = 1280
	k.link = link
	k.tableEdit++
	observeOnce(t, d, 1, rules)
	if !strings.Contains(buf.String(), "differs from the declaration in the MTU") {
		t.Errorf("an MTU drift right after a table drift was not logged:\n%s", buf.String())
	}
}

// runtime の見直しは、名前を引く間に公開できなかった全体状態の控えが現れたら、解決の結果を捨てる。
// 控えの試し直しが公開を担うためである。
func TestObserveDiscardsAResolutionWhenAPendingStateAppears(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.3")}}}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	rt := &runtime{opts: Options{CredentialsPath: t.TempDir() + "/agent.json", Mode: "kernel"}, f: f, priv: d.priv, dp: d, wgCfg: d.wg}
	st := &proto.State{Generation: 1, WG: d.wg, Rules: []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}}
	rt.mu.Lock()
	if err := rt.finishApplyLocked(st, nil); err != nil {
		t.Fatal(err)
	}
	rt.mu.Unlock()
	k.tableGone = true
	d.ops.lookup = func(context.Context, string) ([]netip.Addr, error) {
		rt.mu.Lock()
		rt.pendingSt = &proto.State{Generation: 2}
		rt.mu.Unlock()
		return []netip.Addr{netip.MustParseAddr("192.168.1.3")}, nil
	}
	published := len(k.published)
	rt.observe()
	if len(k.published) != published {
		t.Error("the check published although a pending state appeared while it resolved names")
	}
}

// 名前の解決の誤りが送信元のポートだけ違う場合は、理由の変化にしない。変化にすると、30 秒ごとに記録を
// 書き換え、ハートビートとルールのログを出す。
func TestKernelObserveSameLookupErrorFromANewPortSavesNothing(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": {netip.MustParseAddr("192.168.1.30")}}}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:80", 80, 80)}
	if _, err := d.applyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	refused := func(port int) error {
		return &net.DNSError{Name: "game.lan", Server: "192.168.1.1:53",
			Err: fmt.Sprintf("read udp 192.168.1.10:%d->192.168.1.1:53: read: connection refused", port)}
	}
	k.dnsErr = refused(54285)
	if !observeOnce(t, d, 1, rules) {
		t.Fatal("the first failed lookup did not record its reason")
	}
	k.dnsErr = refused(48346)
	if observeOnce(t, d, 1, rules) {
		t.Errorf("the same lookup error from another source port changed the record: %s", f.KernelPublication)
	}
	if strings.Contains(string(f.KernelPublication), "->") {
		t.Errorf("the recorded reason keeps the socket pair: %s", f.KernelPublication)
	}
}

// keepalive ごとに、vpsd のトンネルアドレスのポート 9 へデータグラムを 1 つ送る。close で止まり、
// build で立て直す。keepalive が 0 なら送らない(7b.1 節のセッションの回復)。
func TestKernelSendsTheKeepaliveDatagram(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	d.close()
	d.kaUnit = 10 * time.Millisecond
	if _, err := d.build(d.priv, testWG(t)); err != nil { // keepalive 25 → 250 ms
		t.Fatal(err)
	}
	count := func() int {
		k.mu.Lock()
		defer k.mu.Unlock()
		return len(k.datagrams)
	}
	deadline := time.Now().Add(5 * time.Second)
	for count() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	k.mu.Lock()
	got := append([]netip.AddrPort(nil), k.datagrams...)
	k.mu.Unlock()
	if len(got) < 2 || got[0] != netip.MustParseAddrPort("10.200.0.1:9") {
		t.Fatalf("datagrams = %v, want repeated datagrams to 10.200.0.1:9", got)
	}
	d.close()
	time.Sleep(50 * time.Millisecond)
	stopped := count()
	time.Sleep(600 * time.Millisecond)
	if count() != stopped {
		t.Error("datagrams kept going after close")
	}
	w := testWG(t)
	w.Keepalive = 0
	if _, err := d.build(d.priv, w); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	if count() != stopped {
		t.Error("a keepalive of 0 sent datagrams")
	}
}

// ハンドシェイクが keepalive の 5 倍の間新しくならなければ、次の見直しがエンドポイントの名前を引き直し、
// アドレスが変わっていれば wgft0 のピアへ設定する。引き直した後は、さらに 5 倍の間は引かない(7b.1 節)。
func TestKernelReResolvesTheEndpointWithoutHandshakes(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	k := &fakeKernel{dns: map[string][]netip.Addr{"vps.example": {netip.MustParseAddr("203.0.113.1")}}}
	d := newTestKernel(t, k, nil, nil)
	d.ops.now = func() time.Time { return now }
	w := testWG(t)
	w.Endpoint = "vps.example:51820"
	if _, err := d.build(d.priv, w); err != nil {
		t.Fatal(err)
	}
	k.link = ours(t, d)
	if _, err := d.applyRules(1, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got := k.ensured[len(k.ensured)-1].Server.Endpoint; got != netip.MustParseAddrPort("203.0.113.1:51820") {
		t.Fatalf("first endpoint %s", got)
	}
	k.link = ours(t, d)
	lookups := 0
	lookup := d.ops.lookup
	d.ops.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		lookups++
		return lookup(ctx, host)
	}
	observeOnce(t, d, 1, nil) // ハンドシェイクを見始める
	now = now.Add(100 * time.Second)
	observeOnce(t, d, 1, nil)
	if lookups != 0 {
		t.Fatalf("looked up the endpoint %d times before 5 times the keepalive", lookups)
	}
	k.dns["vps.example"] = []netip.Addr{netip.MustParseAddr("203.0.113.7")}
	now = now.Add(25 * time.Second) // ちょうど 125 秒で引き直す
	observeOnce(t, d, 1, nil)       // 印を付ける
	ensured := len(k.ensured)
	observeOnce(t, d, 1, nil) // 引き直す
	if lookups != 1 || len(k.ensured) != ensured+1 {
		t.Fatalf("lookups %d, convergences %d; want one lookup and one convergence", lookups, len(k.ensured)-ensured)
	}
	if got := k.ensured[len(k.ensured)-1].Server.Endpoint; got != netip.MustParseAddrPort("203.0.113.7:51820") {
		t.Errorf("converged to endpoint %s, want the new address", got)
	}
	now = now.Add(30 * time.Second)
	observeOnce(t, d, 1, nil)
	observeOnce(t, d, 1, nil)
	if lookups != 1 {
		t.Errorf("looked up again %d times within 5 times the keepalive after a re-resolution", lookups-1)
	}
	// 新しいハンドシェイクがあれば引き直さない
	link := ours(t, d)
	link.Peers[0].LastHandshake = now
	k.link = link
	now = now.Add(200 * time.Second)
	observeOnce(t, d, 1, nil)
	observeOnce(t, d, 1, nil)
	if lookups != 1 {
		t.Error("looked up the endpoint although a new handshake was seen")
	}
}

// keepalive が 0 の設定では、ハンドシェイクが途絶えてもエンドポイントを引き直さない。5 倍の期間が 0 に
// なり、見直しのたびに名前を引くことになるためである(7b.1 節)。
func TestKernelDoesNotReResolveWithAKeepaliveOfZero(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	k := &fakeKernel{dns: map[string][]netip.Addr{"vps.example": {netip.MustParseAddr("203.0.113.1")}}}
	d := newTestKernel(t, k, nil, nil)
	d.ops.now = func() time.Time { return now }
	w := testWG(t)
	w.Endpoint = "vps.example:51820"
	w.Keepalive = 0
	if _, err := d.build(d.priv, w); err != nil {
		t.Fatal(err)
	}
	if _, err := d.applyRules(1, nil, nil); err != nil {
		t.Fatal(err)
	}
	k.link = ours(t, d)
	lookups := 0
	lookup := d.ops.lookup
	d.ops.lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
		lookups++
		return lookup(ctx, host)
	}
	for i := 0; i < 4; i++ {
		observeOnce(t, d, 1, nil)
		now = now.Add(200 * time.Second)
	}
	if lookups != 0 {
		t.Errorf("looked up the endpoint %d times with a keepalive of 0", lookups)
	}
}

// 引き直せなかったエンドポイントは、控えたアドレスを使い続ける。
func TestKernelKeepsTheCachedEndpointWhenReResolutionFails(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	k := &fakeKernel{dns: map[string][]netip.Addr{"vps.example": {netip.MustParseAddr("203.0.113.1")}}}
	d := newTestKernel(t, k, nil, nil)
	d.ops.now = func() time.Time { return now }
	w := testWG(t)
	w.Endpoint = "vps.example:51820"
	if _, err := d.build(d.priv, w); err != nil {
		t.Fatal(err)
	}
	if _, err := d.applyRules(1, nil, nil); err != nil {
		t.Fatal(err)
	}
	k.link = ours(t, d)
	observeOnce(t, d, 1, nil)
	now = now.Add(200 * time.Second)
	k.dnsErr = errors.New("no route to the resolver")
	ensured := len(k.ensured)
	observeOnce(t, d, 1, nil)
	observeOnce(t, d, 1, nil)
	if got := d.cachedEndpoint(); got != netip.MustParseAddrPort("203.0.113.1:51820") {
		t.Errorf("cached endpoint %s after a failed re-resolution, want the old address", got)
	}
	if n := len(k.ensured) - ensured; n != 0 {
		t.Errorf("a failed re-resolution converged %s %d times", d.iface, n)
	}
}

// vpsd のトンネルアドレスへの経路が wgft0 を通らなければ警告し、戻れば戻ったことを出す。起動は止めない。
func TestKernelWarnsWhenTheRouteToTheServerLeavesElsewhere(t *testing.T) {
	k := &fakeKernel{route: "tailscale0"}
	d := newTestKernel(t, k, nil, nil)
	if _, err := d.applyRules(1, nil, nil); err != nil {
		t.Fatalf("a policy route stopped the apply: %v", err)
	}
	if !strings.Contains(d.routeFinding, "tailscale0") || !strings.Contains(d.routeFinding, "10.200.0.1") {
		t.Errorf("finding = %q", d.routeFinding)
	}
	k.route = "wgft0"
	k.link = ours(t, d)
	observeOnce(t, d, 1, nil)
	if d.routeFinding != "" {
		t.Errorf("finding = %q after the route came back", d.routeFinding)
	}
	// 経路を引けないことも警告し、止めない
	k.routeErr = errors.New("network is unreachable")
	observeOnce(t, d, 1, nil)
	if !strings.Contains(d.routeFinding, "cannot look up the route") || !strings.Contains(d.routeFinding, "network is unreachable") {
		t.Errorf("finding = %q when the route lookup failed", d.routeFinding)
	}
}

// syncBuffer は、別の goroutine が書くログを受ける。
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// データグラムを送れない間は、理由が変わったときだけ 1 行出す。net の書き込みの誤りは送るたびに送信元の
// ポートが違うので、下層の errno で比べる。ピアにエンドポイントが無い間は、そのことを出し、鍵の寿命の
// 話はしない(7b.1 節)。
func TestKernelLogsAKeepaliveSendFailureOncePerReason(t *testing.T) {
	var buf syncBuffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	sendErr := func(n int, errno syscall.Errno) error {
		return &net.OpError{Op: "write", Net: "udp",
			Source: net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("10.200.0.2"), uint16(40000+n))),
			Addr:   net.UDPAddrFromAddrPort(netip.MustParseAddrPort("10.200.0.1:9")),
			Err:    os.NewSyscallError("write", errno)}
	}
	k := &fakeKernel{}
	k.sendErr = func(n int) error {
		switch {
		case n < 4:
			return sendErr(n, syscall.EDESTADDRREQ)
		case n < 8:
			return sendErr(n, syscall.ENOKEY)
		}
		return nil
	}
	d := newTestKernel(t, k, nil, nil)
	d.close()
	d.kaUnit = 5 * time.Millisecond
	if _, err := d.build(d.priv, testWG(t)); err != nil { // keepalive 25 → 125 ms
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		k.mu.Lock()
		n := len(k.datagrams)
		k.mu.Unlock()
		if n >= 10 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	d.close()
	time.Sleep(20 * time.Millisecond)
	out := buf.String()
	if n := strings.Count(out, "has no endpoint"); n != 1 {
		t.Errorf("the missing endpoint was logged %d times, want once:\n%s", n, out)
	}
	if n := strings.Count(out, "required key not available"); n != 1 {
		t.Errorf("the second reason was logged %d times, want once:\n%s", n, out)
	}
	if n := strings.Count(out, "is sent again"); n != 1 {
		t.Errorf("the recovery was logged %d times, want once:\n%s", n, out)
	}
	if strings.Contains(out, "40001") || strings.Count(out, "keys expire") != 1 {
		t.Errorf("the log repeats the source port or blames the keys for a missing endpoint:\n%s", out)
	}
}

// 引き直しが成功したら、アドレスが同じでも wgft0 を収束させる。外から書き換えられたカーネルのピアの
// エンドポイントはここで戻る。収束に失敗したら、次の見直しで引き直しと収束を試し直す(7b.1 節)。
func TestKernelReResolutionConvergesUntilItSucceeds(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	k := &fakeKernel{dns: map[string][]netip.Addr{"vps.example": {netip.MustParseAddr("203.0.113.1")}}}
	d := newTestKernel(t, k, nil, nil)
	d.ops.now = func() time.Time { return now }
	w := testWG(t)
	w.Endpoint = "vps.example:51820"
	if _, err := d.build(d.priv, w); err != nil {
		t.Fatal(err)
	}
	if _, err := d.applyRules(1, nil, nil); err != nil {
		t.Fatal(err)
	}
	k.link = ours(t, d)
	observeOnce(t, d, 1, nil)
	// 同じアドレスでも収束させる
	now = now.Add(200 * time.Second)
	observeOnce(t, d, 1, nil) // 印を付ける
	ensured := len(k.ensured)
	observeOnce(t, d, 1, nil) // 引き直す
	if len(k.ensured) != ensured+1 {
		t.Fatalf("a re-resolution to the same address converged %s %d times, want once", d.iface, len(k.ensured)-ensured)
	}
	// 変わったアドレスの収束が 1 回失敗しても、次の見直しで収束させる
	k.dns["vps.example"] = []netip.Addr{netip.MustParseAddr("203.0.113.7")}
	now = now.Add(200 * time.Second)
	observeOnce(t, d, 1, nil) // 印を付ける
	k.ensureErr = errors.New("netlink: device busy")
	if _, err := d.observeCommit(1, nil, d.observePrepare(nil)); err == nil {
		t.Fatal("a failed convergence was not reported")
	}
	k.ensureErr = nil
	ensured = len(k.ensured)
	now = now.Add(30 * time.Second)
	observeOnce(t, d, 1, nil)
	if len(k.ensured) != ensured+1 || k.ensured[len(k.ensured)-1].Server.Endpoint != netip.MustParseAddrPort("203.0.113.7:51820") {
		t.Errorf("after a failed convergence the next check converged %d times; want once to the new address", len(k.ensured)-ensured)
	}
}

// 30 秒ごとの見直しが引き直すのは宣言のエンドポイントの名前であり、最後に解決できた名前ではない。
func TestKernelReResolvesTheDeclaredEndpointName(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	k := &fakeKernel{dns: map[string][]netip.Addr{"old.example": {netip.MustParseAddr("203.0.113.1")}}}
	d := newTestKernel(t, k, nil, nil)
	d.ops.now = func() time.Time { return now }
	w := testWG(t)
	w.Endpoint = "old.example:51820"
	if _, err := d.build(d.priv, w); err != nil {
		t.Fatal(err)
	}
	st := &proto.State{WG: w}
	if _, err := d.applyRules(1, nil, d.prepareApply(st)); err != nil {
		t.Fatal(err)
	}
	// 宣言が、まだ解決できない新しい名前に変わる。控えは旧い名前のアドレスのまま
	w.Endpoint = "new.example:51820"
	if _, err := d.build(d.priv, w); err != nil {
		t.Fatal(err)
	}
	st = &proto.State{WG: w}
	if _, err := d.applyRules(2, nil, d.prepareApply(st)); err != nil {
		t.Fatal(err)
	}
	k.link = ours(t, d)
	observeOnce(t, d, 2, nil)
	now = now.Add(200 * time.Second)
	k.dns["new.example"] = []netip.Addr{netip.MustParseAddr("203.0.113.9")}
	k.lookups = nil
	observeOnce(t, d, 2, nil) // 印を付ける
	observeOnce(t, d, 2, nil) // 引き直す
	if len(k.lookups) != 1 || k.lookups[0] != "new.example" {
		t.Errorf("the check looked up %v, want the declared name new.example", k.lookups)
	}
	if got := d.cachedEndpoint(); got != netip.MustParseAddrPort("203.0.113.9:51820") {
		t.Errorf("cached endpoint %s, want the declared name's address", got)
	}
}

// 経路は wgft0 が宣言どおりになってから確かめる。wgft0 が消えている間の経路は既定経路へ出るが、それを
// 警告しない(7b.1 節)。
func TestKernelChecksTheRouteAfterRepairingWgft0(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	if _, err := d.applyRules(1, nil, nil); err != nil {
		t.Fatal(err)
	}
	// wgft0 が消え、経路は既定経路の eth0 へ出る。収束させると wgft0 へ戻る
	k.link = wg.AgentState{}
	k.route = "eth0"
	k.onEnsure = func() { k.route = "" }
	observeOnce(t, d, 1, nil)
	if d.routeFinding != "" {
		t.Errorf("warned about the route while %s was gone: %q", d.iface, d.routeFinding)
	}
	// 収束に失敗した間は経路を確かめない
	k.route = "eth0"
	k.ensureErr = errors.New("netlink: operation not permitted")
	if _, err := d.observeCommit(1, nil, d.observePrepare(nil)); err == nil {
		t.Fatal("a failed convergence was not reported")
	}
	if d.routeFinding != "" {
		t.Errorf("warned about the route while %s could not be converged: %q", d.iface, d.routeFinding)
	}
}

// 引き直したエンドポイントの収束に失敗し続けても、30 秒ごとの見直しは表の修復と経路の確認へ進み、誤りは
// 最後に返す。印は残るので、次の見直しも引き直しと収束を試し直す(7b.1 節)。稼働中に現れた重なりで
// 収束が書かずに失敗し続け、ハンドシェイクも途絶えている場合に当たる。
func TestKernelObserveRepairsTheTableWhileTheEndpointCannotConverge(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	k := &fakeKernel{dns: map[string][]netip.Addr{"vps.example": {netip.MustParseAddr("203.0.113.1")}}}
	d := newTestKernel(t, k, nil, nil)
	d.ops.now = func() time.Time { return now }
	w := testWG(t)
	w.Endpoint = "vps.example:51820"
	if _, err := d.build(d.priv, w); err != nil {
		t.Fatal(err)
	}
	if _, err := d.applyRules(1, nil, nil); err != nil {
		t.Fatal(err)
	}
	k.link = ours(t, d)
	observeOnce(t, d, 1, nil)
	now = now.Add(200 * time.Second)
	observeOnce(t, d, 1, nil) // 印を付ける
	k.ensureErr = &wg.OverlapError{Interface: "wgft0", Range: netip.MustParsePrefix("10.200.0.0/24"),
		What: "route 10.200.0.0/25 dev br0", Server: netip.MustParseAddr("10.200.0.1")}
	k.route = "br0"
	k.tableGone = true
	published := len(k.published)
	for i := 0; i < 10; i++ {
		saved, err := d.observeCommit(1, nil, d.observePrepare(nil))
		if err == nil {
			t.Fatalf("check %d: the failed convergence was not reported", i)
		}
		if i == 0 && !saved {
			t.Error("the check that published the table again did not ask to save the record")
		}
		now = now.Add(30 * time.Second)
	}
	if n := len(k.published) - published; n != 1 {
		t.Errorf("the table was published again %d times over 10 checks, want once", n)
	}
	if !strings.Contains(d.routeFinding, "br0") {
		t.Errorf("the route was not checked: finding %q", d.routeFinding)
	}
	d.epMu.Lock()
	stale := d.endpointStale
	d.epMu.Unlock()
	if !stale {
		t.Error("the mark was cleared although the convergence failed")
	}
}

// runtime は、見直しが誤りを返しても記録が変わっていれば認証情報ファイルを保存し、ハートビートを送らせる。
// 引き直したエンドポイントの収束に失敗した見直しも、表を公開し直していることがあるためである。
func TestObserveSavesARepairThatAlsoReturnsAnError(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	k := &fakeKernel{dns: map[string][]netip.Addr{"vps.example": {netip.MustParseAddr("203.0.113.1")}}}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, nil)
	d.ops.now = func() time.Time { return now }
	w := testWG(t)
	w.Endpoint = "vps.example:51820"
	if _, err := d.build(d.priv, w); err != nil {
		t.Fatal(err)
	}
	k.link = ours(t, d)
	path := t.TempDir() + "/agent.json"
	rt := &runtime{opts: Options{CredentialsPath: path, Mode: "kernel"}, f: f, priv: d.priv, dp: d, wgCfg: d.wg}
	st := &proto.State{Generation: 1, WG: w}
	rt.mu.Lock()
	if err := rt.finishApplyLocked(st, nil); err != nil {
		t.Fatal(err)
	}
	rt.mu.Unlock()
	k.link = ours(t, d)
	rt.observe()
	now = now.Add(200 * time.Second)
	rt.observe() // 印を付ける
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	k.ensureErr = errors.New("netlink: operation not permitted")
	k.tableGone = true
	rt.stateNotify = make(chan struct{}, 1)
	rt.observe()
	if _, err := os.Stat(path); err != nil {
		t.Errorf("the repair was not saved: %v", err)
	}
	select {
	case <-rt.stateNotify:
	default:
		t.Error("the repair did not ask for a heartbeat")
	}
}

func gens(ps []nft.AgentPublication) []uint64 {
	var out []uint64
	for _, p := range ps {
		out = append(out, p.Generation)
	}
	return out
}

// 公開のたびに、直前の公開を前の公開として conntrack を収束させる。前の公開が無ければ呼ばない。
// 範囲は wgft0 のアドレスと vpsd のトンネルアドレスと今の許可一覧である(7b.4 節)。
func TestKernelConvergesConntrackAfterEachPublication(t *testing.T) {
	allow, err := allowtargets.Parse("192.168.1.0/24")
	if err != nil {
		t.Fatal(err)
	}
	k := &fakeKernel{}
	f := &credentials.Credentials{}
	d := newTestKernel(t, k, f, allow)
	if _, err := d.applyRules(1, []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}, nil); err != nil {
		t.Fatal(err)
	}
	if len(k.converged) != 0 {
		t.Fatalf("converged %d times with no earlier publication", len(k.converged))
	}
	if _, err := d.applyRules(2, []proto.AgentRule{tcpRule("r1", "192.168.1.21:80", 80, 80)}, nil); err != nil {
		t.Fatal(err)
	}
	if len(k.converged) != 1 {
		t.Fatalf("converged %d times, want once", len(k.converged))
	}
	c := k.converged[0]
	if got := gens(c.prev); len(got) != 1 || got[0] != 1 || c.cur.Generation != 2 {
		t.Errorf("converged from %v to %d, want from [1] to 2", got, c.cur.Generation)
	}
	if c.scope.Local != netip.MustParseAddr("10.200.0.2") || c.scope.Peer != netip.MustParseAddr("10.200.0.1") || c.scope.AllowTarget == nil {
		t.Errorf("scope = %+v", c.scope)
	}
	if len(f.KernelUnconverged) != 0 {
		t.Errorf("a converged publication left an unconverged list: %s", f.KernelUnconverged)
	}
}

// 収束に失敗したら前の公開の列を残して認証情報ファイルに写し、30 秒ごとの見直しで、テーブルを
// 差し替えずに同じ列で試し直す。その間に公開が進めば、列はその公開も含めて伸びる(7b.4 節)。
func TestKernelKeepsUnconvergedPublicationsUntilConverged(t *testing.T) {
	k := &fakeKernel{}
	f := &credentials.Credentials{}
	saves := 0
	d := newTestKernel(t, k, f, nil)
	d.save = func() error { saves++; return nil }
	rule := func(target string) []proto.AgentRule { return []proto.AgentRule{tcpRule("r1", target, 80, 80)} }
	if _, err := d.applyRules(1, rule("192.168.1.20:80"), nil); err != nil {
		t.Fatal(err)
	}
	k.convergeErr = errors.New("conntrack: operation not permitted")
	if _, err := d.applyRules(2, rule("192.168.1.21:80"), nil); err != nil {
		t.Fatalf("a failed convergence failed the apply: %v", err)
	}
	if _, err := d.applyRules(3, rule("192.168.1.22:80"), nil); err != nil {
		t.Fatal(err)
	}
	last := k.converged[len(k.converged)-1]
	if got := gens(last.prev); len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Errorf("the third publication converged from %v, want [1 2]", got)
	}
	var persisted []nft.AgentPublication
	if err := json.Unmarshal(f.KernelUnconverged, &persisted); err != nil || len(persisted) != 2 {
		t.Fatalf("persisted %s (%v), want two publications", f.KernelUnconverged, err)
	}
	published := len(k.published)
	d.refresh()
	if len(k.published) != published {
		t.Error("the retry replaced the table")
	}
	if got := gens(k.converged[len(k.converged)-1].prev); len(got) != 2 {
		t.Errorf("the retry converged from %v, want the same list", got)
	}
	k.convergeErr = nil
	d.refresh()
	if len(d.unconverged) != 0 || len(f.KernelUnconverged) != 0 || saves != 1 {
		t.Errorf("after a good retry: list %v, persisted %s, saves %d; want it cleared and saved once", gens(d.unconverged), f.KernelUnconverged, saves)
	}
}

// 再起動の後は、認証情報ファイルの公開の記録と、収束が済んでいない前の公開の列から収束させる。
// エージェントが止まっている間に無効化された場合も、再起動後の公開がその前の公開のフローを消す。
func TestKernelConvergesFromTheRecordAfterARestart(t *testing.T) {
	older := nft.AgentPublication{Generation: 4, Rules: []nft.AgentRuleResult{{RuleID: "r1", Proto: proto.TCP,
		ListenPort: proto.PortRange{Lo: 80, Hi: 80}, Target: "192.168.1.19:80",
		Ranges: []nft.AgentRange{{Ports: proto.PortRange{Lo: 80, Hi: 80}, Dest: netip.MustParseAddrPort("192.168.1.19:80")}}}}}
	rec := nft.AgentPublication{Generation: 5, Rules: []nft.AgentRuleResult{{RuleID: "r1", Proto: proto.TCP,
		ListenPort: proto.PortRange{Lo: 80, Hi: 80}, Target: "192.168.1.20:80",
		Ranges: []nft.AgentRange{{Ports: proto.PortRange{Lo: 80, Hi: 80}, Dest: netip.MustParseAddrPort("192.168.1.20:80")}}}}}
	b, _ := json.Marshal(rec)
	u, _ := json.Marshal([]nft.AgentPublication{older})
	k := &fakeKernel{}
	d := newTestKernel(t, k, &credentials.Credentials{KernelPublication: b, KernelUnconverged: u}, nil)
	// 止まっている間にエージェントが無効にされ、すべてのルールが enabled:false で届く
	disabled := []proto.AgentRule{{ID: "r1", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 80, Hi: 80}, Target: "192.168.1.20:80"}}
	if _, err := d.applyRules(6, disabled, nil); err != nil {
		t.Fatal(err)
	}
	if len(k.converged) != 1 {
		t.Fatalf("converged %d times, want once", len(k.converged))
	}
	c := k.converged[0]
	if got := gens(c.prev); len(got) != 2 || got[0] != 4 || got[1] != 5 {
		t.Errorf("converged from %v, want the persisted list and the record, [4 5]", got)
	}
	if len(c.cur.DNATs()) != 0 {
		t.Errorf("the disabled agent's publication has DNATs: %+v", c.cur.DNATs())
	}
}

// 再起動の後、wgft0 を一度も収束させていない間の見直しは、残った列で conntrack を収束させない。
// 最初の公開が、記録を列に加えてから収束させる。
func TestKernelWaitsForTheFirstConvergenceBeforeRetrying(t *testing.T) {
	rec := nft.AgentPublication{Generation: 5, Rules: []nft.AgentRuleResult{{RuleID: "r1", Proto: proto.TCP,
		ListenPort: proto.PortRange{Lo: 80, Hi: 80}, Target: "192.168.1.20:80",
		Ranges: []nft.AgentRange{{Ports: proto.PortRange{Lo: 80, Hi: 80}, Dest: netip.MustParseAddrPort("192.168.1.20:80")}}}}}
	older := rec
	older.Generation = 4
	older.Rules = []nft.AgentRuleResult{{RuleID: "r1", Proto: proto.TCP,
		ListenPort: proto.PortRange{Lo: 80, Hi: 80}, Target: "192.168.1.19:80",
		Ranges: []nft.AgentRange{{Ports: proto.PortRange{Lo: 80, Hi: 80}, Dest: netip.MustParseAddrPort("192.168.1.19:80")}}}}
	b, _ := json.Marshal(rec)
	u, _ := json.Marshal([]nft.AgentPublication{older})
	k := &fakeKernel{}
	d := newTestKernel(t, k, &credentials.Credentials{KernelPublication: b, KernelUnconverged: u}, nil)
	d.refresh()
	if len(k.converged) != 0 {
		t.Fatalf("the check converged conntrack %d times before wgft0 was converged", len(k.converged))
	}
	if _, err := d.applyRules(6, []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}, nil); err != nil {
		t.Fatal(err)
	}
	if len(k.converged) != 1 {
		t.Fatalf("converged %d times, want once", len(k.converged))
	}
}

// 読めない列は無いものとして扱い、途中まで読めた要素も使わない。
func TestKernelIgnoresAnUnreadableUnconvergedList(t *testing.T) {
	rec := nft.AgentPublication{Generation: 5, Rules: []nft.AgentRuleResult{{RuleID: "r1", Proto: proto.TCP,
		ListenPort: proto.PortRange{Lo: 80, Hi: 80}, Target: "192.168.1.20:80",
		Ranges: []nft.AgentRange{{Ports: proto.PortRange{Lo: 80, Hi: 80}, Dest: netip.MustParseAddrPort("192.168.1.20:80")}}}}}
	b, _ := json.Marshal(rec)
	k := &fakeKernel{}
	d := newTestKernel(t, k, &credentials.Credentials{KernelPublication: b,
		KernelUnconverged: json.RawMessage(`[{"generation":4,"rules":[]},"not a publication"]`)}, nil)
	if _, err := d.applyRules(6, []proto.AgentRule{tcpRule("r1", "192.168.1.21:80", 80, 80)}, nil); err != nil {
		t.Fatal(err)
	}
	if len(k.converged) != 1 {
		t.Fatalf("converged %d times, want once", len(k.converged))
	}
	if got := gens(k.converged[0].prev); len(got) != 1 || got[0] != 5 {
		t.Errorf("converged from %v, want only the record, [5]", got)
	}
}

// 列の上限と、DNAT の同じ公開をまとめること。
func TestAppendUnconverged(t *testing.T) {
	pub := func(g uint64, dest string) nft.AgentPublication {
		return nft.AgentPublication{Generation: g, Rules: []nft.AgentRuleResult{{RuleID: "r", Proto: proto.TCP,
			ListenPort: proto.PortRange{Lo: 80, Hi: 80}, Target: dest,
			Ranges: []nft.AgentRange{{Ports: proto.PortRange{Lo: 80, Hi: 80}, Dest: netip.MustParseAddrPort(dest)}}}}}
	}
	var list []nft.AgentPublication
	list = appendUnconverged(list, pub(1, "192.168.1.1:80"))
	reasoned := pub(2, "192.168.1.1:80")
	reasoned.Rules[0].Reason = "probe failed" // 理由は比べない
	list = appendUnconverged(list, reasoned)
	if got := gens(list); len(got) != 1 || got[0] != 2 {
		t.Errorf("same DNATs: %v, want [2]", got)
	}
	// DNAT が同じでも宣言の宛先が違えば畳まない
	named := pub(3, "192.168.1.1:80")
	named.Rules[0].Target = "nas.lan:80"
	if got := gens(appendUnconverged(append([]nft.AgentPublication(nil), list...), named)); len(got) != 2 {
		t.Errorf("same DNATs, another declared target: %v, want both kept", got)
	}
	for g := uint64(3); g < 3+maxUnconverged+5; g++ {
		list = appendUnconverged(list, pub(g, fmt.Sprintf("192.168.1.%d:80", g%200+2)))
	}
	if len(list) != maxUnconverged || list[len(list)-1].Generation != 3+maxUnconverged+4 {
		t.Errorf("list of %d ending at %d, want %d ending at the newest", len(list), list[len(list)-1].Generation, maxUnconverged)
	}
}

// DNAT が同じでも宣言の宛先の文字列が違う公開は畳まない。ホスト名の宛先を IP リテラルへ変えてから同じ
// ホスト名へ戻すと、戻した公開は中間の公開と DNAT が同じになる。中間の公開を落とすと、収束は宣言が
// 変わっていないと見て、最初の宛先へのフローを残す(7b.4 節)。
func TestKernelKeepsARetargetThatReturnsToTheSameDNAT(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{"nas.lan": {netip.MustParseAddr("192.168.1.30")}}}
	d := newTestKernel(t, k, nil, nil)
	rule := func(target string) []proto.AgentRule { return []proto.AgentRule{tcpRule("r", target, 8443, 8443)} }
	apply := func(gen uint64, target string) {
		t.Helper()
		st := &proto.State{WG: testWG(t), Rules: rule(target)}
		if _, err := d.applyRules(gen, st.Rules, d.prepareApply(st)); err != nil {
			t.Fatal(err)
		}
	}
	apply(1, "nas.lan:80") // X: .30
	k.convergeErr = errors.New("conntrack: operation not permitted")
	apply(2, "192.168.1.31:80") // A
	k.dns["nas.lan"] = []netip.Addr{netip.MustParseAddr("192.168.1.31")}
	apply(3, "nas.lan:80") // B: A と DNAT が同じ
	apply(4, "nas.lan:80") // C: B と DNAT も宣言も同じ
	last := k.converged[len(k.converged)-1]
	if got := gens(last.prev); len(got) != 3 || got[0] != 1 || got[1] != 2 || got[2] != 3 {
		t.Errorf("C converged from %v, want X, A and B, [1 2 3]", got)
	}
	apply(5, "nas.lan:80") // D。列に加わる C は、DNAT も宣言も同じ B を置き換える
	last = k.converged[len(k.converged)-1]
	if got := gens(last.prev); len(got) != 3 || got[2] != 4 {
		t.Errorf("D converged from %v, want [1 2 4]: C replaces B", got)
	}
}

// 同じ削除の失敗が続く間、閉じたフローの無い結果を 30 秒ごとに出さない。誤りは変わったときだけ出す。
func TestKernelLogsARepeatedConvergenceFailureOnce(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, nil, nil)
	rule := func(target string) []proto.AgentRule { return []proto.AgentRule{tcpRule("r1", target, 80, 80)} }
	if _, err := d.applyRules(1, rule("192.168.1.20:80"), nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	k.convergeRes = conntrack.AgentResult{Failed: 2}
	k.convergeErr = errors.New("conntrack delete: closing 2 of the agent's flows failed, the first with: operation not permitted")
	if _, err := d.applyRules(2, rule("192.168.1.21:80"), nil); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		d.refresh()
	}
	out := buf.String()
	if n := strings.Count(out, "closing 2 of the agent's flows failed"); n != 1 {
		t.Errorf("the failure was logged %d times, want once:\n%s", n, out)
	}
	if strings.Contains(out, "closed 0 flows") {
		t.Errorf("a result that closed nothing was logged:\n%s", out)
	}
	k.convergeRes = conntrack.AgentResult{Retargeted: 2}
	k.convergeErr = nil
	d.refresh()
	if out := buf.String(); !strings.Contains(out, "closed 2 flows") || !strings.Contains(out, "converges again") {
		t.Errorf("the recovery did not log the closed flows:\n%s", out)
	}
}

// カーネルモードの前提の検査は、前提の欠如と言い切れる誤りだけを拒否にする(設計文書 7b.5 節)。
// テーブルの読み出しの権限の誤りは CAP_NET_ADMIN の拒否で、WireGuard の検査より先に止まる。他の
// 誤りでは止めず、後の最初の収束に分類を任せる。
func TestCheckKernelPrerequisites(t *testing.T) {
	eperm := fmt.Errorf("listing tables: netlink receive: %w", syscall.EPERM)
	noWG := startup.Prerequisite("wireguard module", "this kernel has no WireGuard support")
	cases := []struct {
		name      string
		tables    error
		wireGuard error
		want      string // 拒否の対象。空なら止めない
		wgCalled  bool
	}{
		{"both met", nil, nil, "", true},
		{"no CAP_NET_ADMIN", eperm, nil, "CAP_NET_ADMIN", false},
		{"no CAP_NET_ADMIN and no WireGuard", eperm, noWG, "CAP_NET_ADMIN", false},
		{"no WireGuard", nil, noWG, "wireguard module", true},
		{"another table error is left to the first convergence", fmt.Errorf("listing tables: %w", syscall.EAFNOSUPPORT), nil, "", true},
		{"another family error is left to the first convergence", nil, fmt.Errorf("netlink: %w", syscall.EAFNOSUPPORT), "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			called := false
			err := checkKernelPrerequisites(
				func() (bool, error) { return false, c.tables },
				func() error { called = true; return c.wireGuard })
			if called != c.wgCalled {
				t.Errorf("WireGuard checked = %v, want %v", called, c.wgCalled)
			}
			if c.want == "" {
				if err != nil {
					t.Fatalf("err = %v, want nil", err)
				}
				return
			}
			r := startup.Of(err)
			if r == nil || r.Category != startup.CategoryPrerequisite || r.Subject != c.want {
				t.Fatalf("err = %v, want a prerequisite refusal about %s", err, c.want)
			}
			if c.want == "CAP_NET_ADMIN" && !strings.Contains(err.Error(), "WGFT_MODE=userspace") {
				t.Errorf("refusal %q does not name the way back to userspace mode", err)
			}
		})
	}
}

// 既定の検査は、CAP_NET_ADMIN を持たないプロセスでは、本物のテーブルの読み出しで権限の拒否になる。
// 権限を持つプロセス(root での実行)では確かめられないので飛ばす。
func TestKernelPrerequisitesWithoutNetAdmin(t *testing.T) {
	if has := processNetAdmin(); has == nil || *has {
		t.Skip("this process may hold CAP_NET_ADMIN")
	}
	err := kernelPrerequisites()
	if r := startup.Of(err); r == nil || r.Category != startup.CategoryPrerequisite || r.Subject != "CAP_NET_ADMIN" {
		t.Fatalf("kernelPrerequisites = %v; want the CAP_NET_ADMIN prerequisite refusal", err)
	}
}
