//go:build linux

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
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
}

func (k *fakeKernel) ops() kernelOps {
	return kernelOps{
		ensureLink: func(cfg wg.AgentConfig) ([]string, error) {
			k.ensured = append(k.ensured, cfg)
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
		now:        func() time.Time { return time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC) },
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
