//go:build linux

package kernelmode

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/conntrack"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/proto"
)

var (
	fo3 = netip.MustParseAddr("192.168.1.3")
	fo4 = netip.MustParseAddr("192.168.1.4")
	fo5 = netip.MustParseAddr("192.168.1.5")
)

// tick は runtime の 30 秒ごとの見直しの 1 回を模す。名前の解決と公開し直し(observe)の後に、
// 接続確認(Refresh)を行う(internal/agent の serve)。
func tick(t *testing.T, d *Dataplane, rules []proto.AgentRule) {
	t.Helper()
	observeOnce(t, d, 1, rules)
	d.Refresh()
}

// lastDest は、直近に公開したテーブルの、ルール id の最初の範囲の宛先である。
func lastDest(t *testing.T, k *fakeKernel, id string) netip.AddrPort {
	t.Helper()
	p := k.published[len(k.published)-1]
	for _, r := range p.Rules {
		if r.RuleID == id && len(r.Ranges) > 0 {
			return r.Ranges[0].Dest
		}
	}
	t.Fatalf("rule %s has no DNAT in %+v", id, p)
	return netip.AddrPort{}
}

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old, flags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(old); log.SetFlags(flags) })
	return &buf
}

func failoverKernel(t *testing.T, f *credentials.Credentials, allow *allowtargets.List, addrs ...netip.Addr) (*fakeKernel, *Dataplane) {
	t.Helper()
	k := &fakeKernel{dns: map[string][]netip.Addr{"game.lan": addrs}, forwardOn: true, probeErr: map[netip.AddrPort]error{}}
	d := newTestKernel(t, k, f, allow)
	k.link = ours(t, d)
	return k, d
}

var errRefused = syscall.ECONNREFUSED

// 宛先がホスト名の TCP のルールは、使っているアドレスが 30 秒ごとの見直しの接続確認に 2 回続けて
// 失敗し、他の候補が応えれば、応えた候補のうち最も小さいアドレスへ切り替える(7b.2 節)。1 回の
// 失敗では切り替えない。切り替えたアドレスは公開の記録に残り、ルールの状態は新しいアドレスの
// 接続確認で決まる。
func TestKernelFailoverMovesToAnotherAddress(t *testing.T) {
	buf := captureLog(t)
	f := &credentials.Credentials{}
	k, d := failoverKernel(t, f, nil, fo5, fo3, fo4)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	k.probeErr[netip.AddrPortFrom(fo4, 25565)] = errRefused
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	if got := lastDest(t, k, "r1"); got.Addr() != fo3 {
		t.Fatalf("first publication to %s, want the smallest %s", got, fo3)
	}
	// 適用の直後の接続確認は数えない。30 秒ごとの見直しの 1 回目の失敗でも切り替えない
	tick(t, d, rules)
	if len(k.published) != 1 {
		t.Fatalf("one failed check published %d more tables", len(k.published)-1)
	}
	if s := statusOf(t, d, "r1"); s.State != proto.StatusError || !strings.Contains(s.Reason, "target 192.168.1.3:25565") {
		t.Errorf("r1 = %+v, want the probe error of 192.168.1.3", s)
	}
	// 2 回目の失敗:.4 も応えないので、応える .5 へ移る
	tick(t, d, rules)
	if len(k.published) != 2 {
		t.Fatalf("the second failed check published %d tables, want 2", len(k.published))
	}
	if got := lastDest(t, k, "r1"); got != netip.AddrPortFrom(fo5, 25565) {
		t.Errorf("moved to %s, want 192.168.1.5:25565, the smallest address that answers", got)
	}
	if s := statusOf(t, d, "r1"); s.State != proto.StatusOK {
		t.Errorf("r1 = %+v, want ok once the new address answers", s)
	}
	var rec nft.AgentPublication
	if err := json.Unmarshal(f.KernelPublication, &rec); err != nil || rec.Rules[0].Pinned != fo5 {
		t.Errorf("record = %s (%v), want pinned 192.168.1.5", f.KernelPublication, err)
	}
	want := `rule r1: target 192.168.1.3:25565 failed the TCP check twice in a row; new flows go to 192.168.1.5:25565, another address of "game.lan" that answers`
	if !strings.Contains(buf.String(), want) {
		t.Errorf("log = %q, want a line %q", buf.String(), want)
	}
	if strings.ContainsAny(want, "()") {
		t.Errorf("the log line has parentheses")
	}
	// 切り替えた宛先が応える間は、最も小さいアドレスが応えるようになっても戻さない
	delete(k.probeErr, netip.AddrPortFrom(fo3, 25565))
	for range 3 {
		tick(t, d, rules)
	}
	if len(k.published) != 2 || lastDest(t, k, "r1").Addr() != fo5 {
		t.Fatalf("the switched address moved while it answered: %d tables, last %s", len(k.published), lastDest(t, k, "r1"))
	}
	// 再起動の後も記録から切り替えたアドレスを使い、DNAT を変えない
	k2 := &fakeKernel{dns: k.dns, forwardOn: true, probeErr: k.probeErr}
	d2 := newTestKernel(t, k2, f, nil)
	k2.link = ours(t, d2)
	if _, err := d2.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	if got := lastDest(t, k2, "r1"); got.Addr() != fo5 {
		t.Errorf("after a restart published to %s, want the recorded 192.168.1.5", got)
	}
	// 切り替えた宛先が 2 回続けて失敗すれば、応える候補のうち最も小さい .3 へ戻り、記録から切り替えが消える
	k2.probeErr[netip.AddrPortFrom(fo5, 25565)] = errRefused
	tick(t, d2, rules)
	tick(t, d2, rules)
	if got := lastDest(t, k2, "r1"); got.Addr() != fo3 {
		t.Errorf("moved back to %s, want 192.168.1.3", got)
	}
	var back nft.AgentPublication
	if err := json.Unmarshal(f.KernelPublication, &back); err != nil || back.Rules[0].Pinned.IsValid() {
		t.Errorf("record = %s (%v), want no pinned address once the smallest is in use", f.KernelPublication, err)
	}
}

// 1 回だけ失敗して次の見直しで応えた宛先は、切り替えない。どの候補も応えなければ切り替えず、
// そのことを 1 行だけ出す(7b.2 節)。
func TestKernelFailoverNeedsTwoFailuresAndAnAnswer(t *testing.T) {
	buf := captureLog(t)
	k, d := failoverKernel(t, nil, nil, fo3, fo4)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	d.Refresh()
	delete(k.probeErr, netip.AddrPortFrom(fo3, 25565))
	tick(t, d, rules)
	if len(k.published) != 1 {
		t.Fatalf("a single failure moved the rule: %d tables", len(k.published))
	}
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	k.probeErr[netip.AddrPortFrom(fo4, 25565)] = errRefused
	for range 4 {
		tick(t, d, rules)
	}
	if len(k.published) != 1 {
		t.Fatalf("moved although no other address answers: %d tables", len(k.published))
	}
	if s := statusOf(t, d, "r1"); s.State != proto.StatusError {
		t.Errorf("r1 = %+v, want error", s)
	}
	line := `rule r1: target 192.168.1.3:25565 failed the TCP check twice in a row and no other allowed address of "game.lan" that was tried answers; it stays in use`
	if n := strings.Count(buf.String(), line); n != 1 {
		t.Errorf("the line %q appears %d times, want once:\n%s", line, n, buf.String())
	}
}

// 同じ名前の TCP のルールが無い UDP のルールと、IP リテラルの宛先は切り替えない。候補は許可一覧が通す
// アドレスだけである(7b.2 節)。
func TestKernelFailoverScope(t *testing.T) {
	allow, err := allowtargets.Parse("192.168.1.3,192.168.1.5")
	if err != nil {
		t.Fatal(err)
	}
	k, d := failoverKernel(t, nil, allow, fo3, fo4, fo5)
	k.dns["voice.lan"] = []netip.Addr{fo3, fo5}
	rules := []proto.AgentRule{
		tcpRule("r1", "game.lan:25565", 25565, 25565),
		udpRule("r2", "voice.lan:27015", 27015),
		tcpRule("r3", "192.168.1.3:80", 80, 80),
	}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	k.probeErr[netip.AddrPortFrom(fo3, 80)] = errRefused
	tick(t, d, rules)
	tick(t, d, rules)
	if got := lastDest(t, k, "r1"); got.Addr() != fo5 {
		t.Errorf("r1 moved to %s, want 192.168.1.5: .4 answers but is outside the allowlist", got)
	}
	if got := lastDest(t, k, "r2"); got.Addr() != fo3 {
		t.Errorf("the UDP rule of a name without a TCP rule moved to %s, want it to stay on 192.168.1.3", got)
	}
	if got := lastDest(t, k, "r3"); got.Addr() != fo3 {
		t.Errorf("the IP literal moved to %s", got)
	}
	for _, p := range k.probed {
		if p.Addr() == fo4 {
			t.Errorf("probed %s, which the allowlist refuses", p)
		}
		if p.Port() == 27015 {
			t.Errorf("probed the UDP target %s", p)
		}
	}
}

// 切り替えたアドレスが解決の結果から外れたら、最も小さいアドレスの規則へ戻る。名前の解決に失敗している
// 間は、直前に解決できた結果から候補を選ぶ。宣言の宛先が変われば切り替えを忘れる(7b.2 節)。
func TestKernelFailoverWithResolutionChanges(t *testing.T) {
	k, d := failoverKernel(t, nil, nil, fo3, fo4, fo5)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	// 名前を引けない間も、直前の結果の .4 へ切り替える
	k.dnsErr = errors.New("server misbehaving")
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	tick(t, d, rules)
	tick(t, d, rules)
	if got := lastDest(t, k, "r1"); got.Addr() != fo4 {
		t.Fatalf("with the name failing moved to %s, want 192.168.1.4 from the last resolution", got)
	}
	if s := statusOf(t, d, "r1"); !strings.Contains(s.Reason, "still forwarding to 192.168.1.4") {
		t.Errorf("r1 = %+v, want the stale reason naming 192.168.1.4", s)
	}
	// 名前が戻り、.4 が外れたら、最も小さい .3 へ戻る
	k.dnsErr = nil
	k.dns["game.lan"] = []netip.Addr{fo3, fo5}
	delete(k.probeErr, netip.AddrPortFrom(fo3, 25565))
	tick(t, d, rules)
	if got := lastDest(t, k, "r1"); got.Addr() != fo3 {
		t.Fatalf("after .4 left the resolution published %s, want 192.168.1.3", got)
	}
	if len(d.pin) != 0 {
		t.Errorf("pins = %v, want none", d.pin)
	}
	// 宣言の宛先を変えれば、切り替えは引き継がない
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	tick(t, d, rules)
	tick(t, d, rules)
	if got := lastDest(t, k, "r1"); got.Addr() != fo5 {
		t.Fatalf("moved to %s, want 192.168.1.5", got)
	}
	k.dns["game2.lan"] = []netip.Addr{fo3, fo5}
	other := []proto.AgentRule{tcpRule("r1", "game2.lan:25565", 25565, 25565)}
	if _, err := d.ApplyRules(2, other, nil); err != nil {
		t.Fatal(err)
	}
	if got := lastDest(t, k, "r1"); got.Addr() != fo3 {
		t.Errorf("a new target kept the switch: %s, want 192.168.1.3", got)
	}
}

// 名前を引けない間に再起動しても、記録の切り替えたアドレスを使い続け、名前が戻った後も最も小さい
// アドレスへ戻らない(7b.2 節)。記録から作る直前の解決の結果は記録のアドレスだけなので、そのアドレスが
// その中で最も小さくても、切り替えは残す。
func TestKernelFailoverSurvivesARestartWithDNSDown(t *testing.T) {
	f := &credentials.Credentials{}
	k, d := failoverKernel(t, f, nil, fo3, fo4)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	tick(t, d, rules)
	tick(t, d, rules)
	if got := lastDest(t, k, "r1"); got.Addr() != fo4 {
		t.Fatalf("moved to %s, want 192.168.1.4", got)
	}
	delete(k.probeErr, netip.AddrPortFrom(fo3, 25565))
	k2 := &fakeKernel{dns: k.dns, forwardOn: true, probeErr: k.probeErr, dnsErr: errors.New("server misbehaving")}
	d2 := newTestKernel(t, k2, f, nil)
	k2.link = ours(t, d2)
	if _, err := d2.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	if got := lastDest(t, k2, "r1"); got.Addr() != fo4 {
		t.Fatalf("a restart with DNS down published %s, want 192.168.1.4", got)
	}
	var rec nft.AgentPublication
	if err := json.Unmarshal(f.KernelPublication, &rec); err != nil || rec.Rules[0].Pinned != fo4 {
		t.Fatalf("record after the restart = %s (%v), want pinned 192.168.1.4", f.KernelPublication, err)
	}
	k2.dnsErr = nil
	tick(t, d2, rules)
	tick(t, d2, rules)
	if got := lastDest(t, k2, "r1"); got.Addr() != fo4 {
		t.Errorf("after DNS came back the DNAT moved to %s, want it to stay on 192.168.1.4", got)
	}
}

// 切り替えは TCP のルールだけである。同じ ID と宛先のまま UDP に変わったルールは、切り替えを忘れて
// 最も小さいアドレスを使い、TCP に戻しても引き継がない(7b.2 節)。
func TestKernelFailoverPinIsForTCPOnly(t *testing.T) {
	k, d := failoverKernel(t, nil, nil, fo3, fo4)
	rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	tick(t, d, rules)
	tick(t, d, rules)
	if got := lastDest(t, k, "r1"); got.Addr() != fo4 {
		t.Fatalf("moved to %s, want 192.168.1.4", got)
	}
	udp := []proto.AgentRule{{ID: "r1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, Target: "game.lan:25565", Enabled: true}}
	if _, err := d.ApplyRules(2, udp, nil); err != nil {
		t.Fatal(err)
	}
	if got := lastDest(t, k, "r1"); got.Addr() != fo3 {
		t.Errorf("the UDP rule uses %s, want the smallest 192.168.1.3", got)
	}
	if _, err := d.ApplyRules(3, rules, nil); err != nil {
		t.Fatal(err)
	}
	if got := lastDest(t, k, "r1"); got.Addr() != fo3 {
		t.Errorf("back to TCP the rule uses %s, want 192.168.1.3", got)
	}
}

// 控えた失敗は、控えた宛先にだけ効く。適用で宛先のアドレスか宣言の宛先が変わったルールは、次の
// 見直しで切り替えない(7b.2 節)。
func TestKernelFailoverForgetsAFailureAfterTheTargetChanges(t *testing.T) {
	t.Run("a new address", func(t *testing.T) {
		fo2 := netip.MustParseAddr("192.168.1.2")
		k, d := failoverKernel(t, nil, nil, fo3, fo4)
		rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
		if _, err := d.ApplyRules(1, rules, nil); err != nil {
			t.Fatal(err)
		}
		k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
		d.Refresh()
		// 名前に .2 が加わり、適用が .2 を公開する。.2 は 1 回だけ失敗し、.3 は失敗し続け、.4 は応える
		k.dns["game.lan"] = []netip.Addr{fo2, fo3, fo4}
		k.probeErr[netip.AddrPortFrom(fo2, 25565)] = errRefused
		if _, err := d.ApplyRules(2, rules, nil); err != nil {
			t.Fatal(err)
		}
		observeOnce(t, d, 2, rules)
		if got := lastDest(t, k, "r1"); got.Addr() != fo2 {
			t.Errorf("the failure noted for 192.168.1.3 moved the rule from 192.168.1.2 to %s", got)
		}
	})
	t.Run("a new declared target with the same address", func(t *testing.T) {
		k, d := failoverKernel(t, nil, nil, fo3, fo4)
		k.dns["other.lan"] = []netip.Addr{fo3, fo5}
		rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
		if _, err := d.ApplyRules(1, rules, nil); err != nil {
			t.Fatal(err)
		}
		k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
		d.Refresh()
		other := []proto.AgentRule{tcpRule("r1", "other.lan:25565", 25565, 25565)}
		if _, err := d.ApplyRules(2, other, nil); err != nil {
			t.Fatal(err)
		}
		observeOnce(t, d, 2, other)
		if got := lastDest(t, k, "r1"); got.Addr() != fo3 {
			t.Errorf("one failure under the old target moved the new target to %s", got)
		}
	})
}

// 切り替えの試し接続は、1 つのルールで使っているアドレスと 8 つの候補まで、1 回の見直しで 64 の宛先まで
// に限る。上限に収まらないルールは後の見直しで試す(7b.2 節)。
func TestKernelFailoverProbesAreBounded(t *testing.T) {
	addrsOf := func(rule, n int) []netip.Addr {
		var out []netip.Addr
		for i := 1; i <= n; i++ {
			out = append(out, netip.AddrFrom4([4]byte{10, byte(rule), byte(i / 250), byte(i % 250)}))
		}
		return out
	}
	t.Run("one rule with many addresses", func(t *testing.T) {
		addrs := addrsOf(1, 200)
		k, d := failoverKernel(t, nil, nil, addrs...)
		rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565)}
		for _, a := range addrs {
			k.probeErr[netip.AddrPortFrom(a, 25565)] = errRefused
		}
		if _, err := d.ApplyRules(1, rules, nil); err != nil {
			t.Fatal(err)
		}
		tick(t, d, rules)
		before := len(k.probed)
		observeOnce(t, d, 1, rules)
		if n := len(k.probed) - before; n != 1+failoverMaxCandidates {
			t.Errorf("one failover probed %d destinations, want %d", n, 1+failoverMaxCandidates)
		}
	})
	t.Run("many rules", func(t *testing.T) {
		k := &fakeKernel{dns: map[string][]netip.Addr{}, forwardOn: true, probeErr: map[netip.AddrPort]error{}}
		d := newTestKernel(t, k, nil, nil)
		k.link = ours(t, d)
		var rules []proto.AgentRule
		for i := 1; i <= 10; i++ {
			addrs := addrsOf(i, 20)
			name := fmt.Sprintf("r%d.lan", i)
			k.dns[name] = addrs
			port := uint16(30000 + i)
			rules = append(rules, tcpRule(fmt.Sprintf("r%02d", i), fmt.Sprintf("%s:%d", name, port), port, port))
			for _, a := range addrs[:8] {
				k.probeErr[netip.AddrPortFrom(a, port)] = errRefused
			}
		}
		if _, err := d.ApplyRules(1, rules, nil); err != nil {
			t.Fatal(err)
		}
		d.Refresh()
		for range 4 {
			before := len(k.probed)
			observeOnce(t, d, 1, rules)
			// 公開し直した後の接続確認は、ルールごとに 1 つである
			if len(k.probed)-before > failoverMaxProbes+len(rules) {
				t.Errorf("one check probed %d destinations, want at most %d for the failover and %d for the checks after it",
					len(k.probed)-before, failoverMaxProbes, len(rules))
			}
			d.Refresh()
		}
		for _, r := range rules {
			if got := lastDest(t, k, r.ID); k.probeErr[got] != nil {
				t.Errorf("rule %s still uses %s, which fails", r.ID, got)
			}
		}
	})
	t.Run("rules without an answer do not starve the others", func(t *testing.T) {
		k := &fakeKernel{dns: map[string][]netip.Addr{}, forwardOn: true, probeErr: map[netip.AddrPort]error{}}
		d := newTestKernel(t, k, nil, nil)
		k.link = ours(t, d)
		var rules []proto.AgentRule
		for i := 1; i <= 8; i++ {
			addrs := addrsOf(i, 9)
			name := fmt.Sprintf("r%d.lan", i)
			k.dns[name] = addrs
			port := uint16(30000 + i)
			rules = append(rules, tcpRule(fmt.Sprintf("r%02d", i), fmt.Sprintf("%s:%d", name, port), port, port))
			// r08 だけは .2 が応える。他のルールはどのアドレスも応えず、毎回の見直しで上限を使う
			for j, a := range addrs {
				if i != 8 || j != 1 {
					k.probeErr[netip.AddrPortFrom(a, port)] = errRefused
				}
			}
		}
		if _, err := d.ApplyRules(1, rules, nil); err != nil {
			t.Fatal(err)
		}
		d.Refresh()
		for range 8 {
			tick(t, d, rules)
		}
		if got := lastDest(t, k, "r08"); k.probeErr[got] != nil {
			t.Errorf("r08 still uses %s, which fails", got)
		}
	})
}

// 上限に収まらないルールは、前の見直しが最後に試したルールの次から試すので、どのルールもおよそ一巡の
// 回数の見直しのうちに試される(7b.2 節)。1 つのルールは 9 つの宛先を使い、1 回の見直しで 7 つのルールを試す。
func TestKernelFailoverRotationReachesEveryRule(t *testing.T) {
	k := &fakeKernel{dns: map[string][]netip.Addr{}, forwardOn: true, probeErr: map[netip.AddrPort]error{}}
	d := newTestKernel(t, k, nil, nil)
	k.link = ours(t, d)
	const n = 40
	perCheck := failoverMaxProbes / (1 + failoverMaxCandidates)
	var rules []proto.AgentRule
	for i := 1; i <= n; i++ {
		var addrs []netip.Addr
		for j := 1; j <= 9; j++ {
			addrs = append(addrs, netip.AddrFrom4([4]byte{10, byte(i), 0, byte(j)}))
		}
		name := fmt.Sprintf("r%d.lan", i)
		k.dns[name] = addrs
		port := uint16(30000 + i)
		rules = append(rules, tcpRule(fmt.Sprintf("r%02d", i), fmt.Sprintf("%s:%d", name, port), port, port))
		// 最後のルールの最後のアドレスだけが応える。他のルールは毎回の見直しで上限を使い続ける
		for j, a := range addrs {
			if i != n || j != 8 {
				k.probeErr[netip.AddrPortFrom(a, port)] = errRefused
			}
		}
	}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	d.Refresh()
	last := fmt.Sprintf("r%02d", n)
	limit := (n+perCheck-1)/perCheck + 1
	for check := 1; check <= limit; check++ {
		tick(t, d, rules)
		if lastDest(t, k, last).Addr() != netip.AddrFrom4([4]byte{10, n, 0, 1}) {
			return
		}
	}
	t.Errorf("rule %s did not switch within %d checks", last, limit)
}

func udpRule(id, target string, port uint16) proto.AgentRule {
	return proto.AgentRule{ID: id, Proto: proto.UDP, ListenPort: proto.PortRange{Lo: port, Hi: port}, Target: target, Enabled: true}
}

// UDP のルールは、宛先の名前が同じ TCP のルールが切り替えたアドレスに従い、切り替えが動けば一緒に動き、
// 切り替えが消えれば最も小さいアドレスへ戻る。許可一覧が UDP のポートでそのアドレスを通さなければ従わない。
// 再起動の後も、TCP のルールの記録から同じアドレスに従う(7b.2 節、2026-10-17 の所有者の決定)。
func TestKernelFailoverUDPFollowsTheTCPRule(t *testing.T) {
	f := &credentials.Credentials{}
	allow, err := allowtargets.Parse("192.168.1.3,192.168.1.4,192.168.1.5:25565,192.168.1.5:27015,192.168.1.5:27016")
	if err != nil {
		t.Fatal(err)
	}
	k, d := failoverKernel(t, f, allow, fo3, fo4, fo5)
	rules := []proto.AgentRule{
		tcpRule("r1", "game.lan:25565", 25565, 25565),
		udpRule("r2", "game.lan:27015", 27015),
		udpRule("r3", "GAME.lan:27016", 27016), // 名前は大文字と小文字を区別しない
		udpRule("r4", "game.lan:27017", 27017), // .5 は 27017 で一覧の外
	}
	k.dns["GAME.lan"] = k.dns["game.lan"]
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	k.probeErr[netip.AddrPortFrom(fo4, 25565)] = errRefused
	tick(t, d, rules)
	tick(t, d, rules)
	want := map[string]netip.Addr{"r1": fo5, "r2": fo5, "r3": fo5, "r4": fo3}
	for id, a := range want {
		if got := lastDest(t, k, id); got.Addr() != a {
			t.Errorf("%s uses %s, want %s", id, got, a)
		}
	}
	// 再起動の後も従う。UDP のルールの記録の切り替えは自分の切り替えとしては持たない
	k2 := &fakeKernel{dns: k.dns, forwardOn: true, probeErr: k.probeErr}
	d2 := newTestKernel(t, k2, f, allow)
	k2.link = ours(t, d2)
	if _, err := d2.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	if got := lastDest(t, k2, "r2"); got.Addr() != fo5 {
		t.Errorf("after a restart r2 uses %s, want 192.168.1.5", got)
	}
	// TCP のルールの切り替えが動けば従う:.5 も失敗し、.3 は応えないので .4 へ
	k2.probeErr[netip.AddrPortFrom(fo5, 25565)] = errRefused
	delete(k2.probeErr, netip.AddrPortFrom(fo4, 25565))
	tick(t, d2, rules)
	tick(t, d2, rules)
	if got := lastDest(t, k2, "r2"); got.Addr() != fo4 {
		t.Errorf("after the TCP rule moved to .4, r2 uses %s", got)
	}
	if _, ok := d2.pin["r2"]; ok || len(d2.pin) != 1 {
		t.Errorf("pins = %v, want only r1's", d2.pin)
	}
	// TCP のルールの切り替えが消えれば戻る:.3 へ戻ると、切り替えは忘れられる
	delete(k2.probeErr, netip.AddrPortFrom(fo3, 25565))
	k2.probeErr[netip.AddrPortFrom(fo4, 25565)] = errRefused
	tick(t, d2, rules)
	tick(t, d2, rules)
	if got := lastDest(t, k2, "r2"); got.Addr() != fo3 {
		t.Errorf("after the TCP rule returned to .3, r2 uses %s", got)
	}
}

// TCP のルールが無くなるか、宛先を変えるか、UDP に変わると、UDP のルールは最も小さいアドレスへ戻る。
// 同じ名前の TCP のルールが別々のアドレスへ切り替えていれば、公開の記録の順で最初のルールに従う(7b.2 節)。
func TestKernelFailoverUDPFollowsOnlyACurrentTCPPin(t *testing.T) {
	switched := func(t *testing.T) (*fakeKernel, *Dataplane, []proto.AgentRule) {
		t.Helper()
		k, d := failoverKernel(t, nil, nil, fo3, fo4, fo5)
		k.dns["other.lan"] = []netip.Addr{fo3}
		rules := []proto.AgentRule{
			tcpRule("r1", "game.lan:25565", 25565, 25565),
			tcpRule("r5", "game.lan:26000", 26000, 26000),
			udpRule("r2", "game.lan:27015", 27015),
		}
		if _, err := d.ApplyRules(1, rules, nil); err != nil {
			t.Fatal(err)
		}
		// r1 は .4 へ、r5 は .5 へ切り替わる
		k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
		k.probeErr[netip.AddrPortFrom(fo3, 26000)] = errRefused
		k.probeErr[netip.AddrPortFrom(fo4, 26000)] = errRefused
		tick(t, d, rules)
		tick(t, d, rules)
		if a, b := lastDest(t, k, "r1").Addr(), lastDest(t, k, "r5").Addr(); a != fo4 || b != fo5 {
			t.Fatalf("r1 on %s and r5 on %s, want .4 and .5", a, b)
		}
		if got := lastDest(t, k, "r2"); got.Addr() != fo4 {
			t.Fatalf("r2 uses %s, want .4 from r1, the first TCP rule in publication order", got)
		}
		return k, d, rules
	}
	t.Run("the first TCP rule is removed", func(t *testing.T) {
		k, d, rules := switched(t)
		if _, err := d.ApplyRules(2, rules[1:], nil); err != nil {
			t.Fatal(err)
		}
		if got := lastDest(t, k, "r2"); got.Addr() != fo5 {
			t.Errorf("r2 uses %s, want .5 from r5", got)
		}
	})
	for name, change := range map[string]proto.AgentRule{
		"a new target": tcpRule("r1", "other.lan:25565", 25565, 25565),
		"now UDP":      udpRule("r1", "game.lan:25565", 25565),
	} {
		t.Run("the TCP rules lose their pins: "+name, func(t *testing.T) {
			k, d, _ := switched(t)
			r5 := tcpRule("r5", "other.lan:26000", 26000, 26000)
			rules := []proto.AgentRule{change, r5, udpRule("r2", "game.lan:27015", 27015)}
			if _, err := d.ApplyRules(2, rules, nil); err != nil {
				t.Fatal(err)
			}
			if got := lastDest(t, k, "r2"); got.Addr() != fo3 {
				t.Errorf("r2 uses %s, want the smallest .3", got)
			}
			if len(d.pin) != 0 {
				t.Errorf("pins = %v, want none", d.pin)
			}
		})
	}
}

// 宛先の数の違うルールが混ざっても、上限に収まらないルールを飛ばし続けない。1 回の見直しは前の見直しが
// 最後に試したルールの次から順に試し、収まらないルールで止まるので、続けて失敗しているルールが n 個なら、
// どのルールも n/7 を切り上げた回数の見直しのうちに試される(7b.2 節)。最初の並びは、後ろの小さいルールで
// 埋める作りでは 9 つの宛先のルール r12 を一度も試さない例である。
func TestKernelFailoverRotationWithMixedSizes(t *testing.T) {
	run := func(t *testing.T, sizes []int) {
		t.Helper()
		k := &fakeKernel{dns: map[string][]netip.Addr{}, forwardOn: true, probeErr: map[netip.AddrPort]error{}}
		d := newTestKernel(t, k, nil, nil)
		k.link = ours(t, d)
		var rules []proto.AgentRule
		curs := map[netip.AddrPort]string{}
		for i, na := range sizes {
			var addrs []netip.Addr
			for j := 1; j <= na; j++ {
				addrs = append(addrs, netip.AddrFrom4([4]byte{10, byte(i + 1), 0, byte(j)}))
			}
			name := fmt.Sprintf("r%d.lan", i+1)
			k.dns[name] = addrs
			port := uint16(30001 + i)
			id := fmt.Sprintf("r%02d", i+1)
			rules = append(rules, tcpRule(id, fmt.Sprintf("%s:%d", name, port), port, port))
			for _, a := range addrs {
				k.probeErr[netip.AddrPortFrom(a, port)] = errRefused
			}
			curs[netip.AddrPortFrom(addrs[0], port)] = id
		}
		if _, err := d.ApplyRules(1, rules, nil); err != nil {
			t.Fatal(err)
		}
		d.Refresh()
		n := len(sizes)
		bound := (n + 6) / 7
		const checks = 40
		last := map[string]int{}
		for c := 1; c <= checks; c++ {
			k.probed = nil
			observeOnce(t, d, 1, rules)
			for _, p := range k.probed {
				if id, ok := curs[p]; ok {
					if gap := c - last[id]; gap > bound {
						t.Fatalf("sizes %v: %s waited %d checks, want at most %d", sizes, id, gap, bound)
					}
					last[id] = c
				}
			}
			d.Refresh()
		}
		for _, r := range rules {
			if gap := checks - last[r.ID]; gap >= bound {
				t.Fatalf("sizes %v: %s was last probed at check %d of %d", sizes, r.ID, last[r.ID], checks)
			}
		}
	}
	run(t, []int{2, 2, 7, 3, 3, 3, 8, 4, 9, 7, 8, 9, 8})
	for seed := uint64(0); seed < 50; seed++ {
		rng := rand.New(rand.NewPCG(seed, 1))
		sizes := make([]int, 5+rng.IntN(30))
		for i := range sizes {
			sizes[i] = 2 + rng.IntN(8) // 使っているアドレスと 1 から 8 の候補
		}
		run(t, sizes)
	}
}

// UDP のルールが TCP のルールの切り替えに従ったときは、離れたアドレスへのそのルールの UDP のフローの
// conntrack のエントリを消す。従わなかった UDP のルール、他の名前のルール、TCP のルールのフローには触れず、
// 切り替え以外の理由で UDP のルールが動いたときも消さない(7b.2 節)。
func TestKernelFailoverClosesUDPFlowsToTheLeftAddress(t *testing.T) {
	allow, err := allowtargets.Parse("192.168.1.3,192.168.1.4:25565,192.168.1.4:27015")
	if err != nil {
		t.Fatal(err)
	}
	k, d := failoverKernel(t, nil, allow, fo3, fo4)
	k.dns["other.lan"] = []netip.Addr{fo3}
	rules := []proto.AgentRule{
		tcpRule("r1", "game.lan:25565", 25565, 25565),
		udpRule("r2", "game.lan:27015", 27015),
		udpRule("r3", "game.lan:27016", 27016), // .4 は 27016 で一覧の外なので従わない
		udpRule("r4", "other.lan:27017", 27017),
	}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	tick(t, d, rules)
	if len(k.closedLeft) != 0 {
		t.Fatalf("closed flows before any switch: %v", k.closedLeft)
	}
	tick(t, d, rules)
	if got := lastDest(t, k, "r2"); got.Addr() != fo4 {
		t.Fatalf("r2 uses %s, want .4", got)
	}
	want := []conntrack.AgentLeft{{Proto: proto.UDP, Range: nft.AgentRange{Ports: proto.PortRange{Lo: 27015, Hi: 27015}, Dest: netip.AddrPortFrom(fo3, 27015)}}}
	if len(k.closedLeft) != 1 || !reflect.DeepEqual(k.closedLeft[0], want) {
		t.Fatalf("closed %v, want only r2's flows to 192.168.1.3:27015", k.closedLeft)
	}
	// TCP のルールが無くなって UDP のルールが戻るのは、切り替えではないので消さない
	if _, err := d.ApplyRules(2, rules[1:], nil); err != nil {
		t.Fatal(err)
	}
	observeOnce(t, d, 2, rules[1:])
	if got := lastDest(t, k, "r2"); got.Addr() != fo3 || len(k.closedLeft) != 1 {
		t.Errorf("r2 on %s after the TCP rule left, closed %d times; want .3 and no more closing", got, len(k.closedLeft))
	}
}

// UDP の範囲のルールが一部のポートだけで従ったときは、従って宛先が変わったポートのフローだけを消す
// (7b.2 節)。
func TestKernelFailoverClosesOnlyTheUDPPortsThatMoved(t *testing.T) {
	allow, err := allowtargets.Parse("192.168.1.3,192.168.1.4:25565,192.168.1.4:19132")
	if err != nil {
		t.Fatal(err)
	}
	k, d := failoverKernel(t, nil, allow, fo3, fo4)
	rules := []proto.AgentRule{
		tcpRule("r1", "game.lan:25565", 25565, 25565),
		{ID: "u1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 27015, Hi: 27016}, Target: "game.lan:19132", Enabled: true},
	}
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	tick(t, d, rules)
	tick(t, d, rules)
	want := [][]conntrack.AgentLeft{{{Proto: proto.UDP, Range: nft.AgentRange{Ports: proto.PortRange{Lo: 27015, Hi: 27015}, Dest: netip.AddrPortFrom(fo3, 19132)}}}}
	if !reflect.DeepEqual(k.closedLeft, want) {
		t.Errorf("closed %v, want only port 27015's flows to 192.168.1.3:19132; 27016 stays on .3", k.closedLeft)
	}
}

// 同じ名前の 2 つの TCP のルールが 1 回の見直しで別々のアドレスから離れたら、どちらのアドレスから離れた
// UDP のフローも消す(7b.2 節)。
func TestKernelFailoverClosesEveryLeftAddressOfAName(t *testing.T) {
	allow, err := allowtargets.Parse("192.168.1.3,192.168.1.5,192.168.1.4:26000,192.168.1.4:27015")
	if err != nil {
		t.Fatal(err)
	}
	k, d := failoverKernel(t, nil, allow, fo3, fo4, fo5)
	rules := []proto.AgentRule{
		tcpRule("r1", "game.lan:25565", 25565, 25565),
		tcpRule("r5", "game.lan:26000", 26000, 26000),
		udpRule("u1", "game.lan:27015", 27015), // r5 の .4 に従う
		udpRule("u2", "game.lan:27016", 27016), // .4 は一覧の外なので .3 のまま
	}
	if _, err := d.ApplyRules(1, rules, nil); err != nil {
		t.Fatal(err)
	}
	// まず r5 だけが .4 へ切り替わる
	k.probeErr[netip.AddrPortFrom(fo3, 26000)] = errRefused
	tick(t, d, rules)
	tick(t, d, rules)
	if a, b := lastDest(t, k, "u1").Addr(), lastDest(t, k, "u2").Addr(); a != fo4 || b != fo3 {
		t.Fatalf("u1 on %s and u2 on %s, want .4 and .3", a, b)
	}
	k.closedLeft = nil
	// 同じ見直しで、r1 は .3 から、r5 は .4 から .5 へ移る
	k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
	k.probeErr[netip.AddrPortFrom(fo4, 26000)] = errRefused
	tick(t, d, rules)
	tick(t, d, rules)
	if a, b := lastDest(t, k, "u1").Addr(), lastDest(t, k, "u2").Addr(); a != fo5 || b != fo5 {
		t.Fatalf("u1 on %s and u2 on %s, want both on .5", a, b)
	}
	want := [][]conntrack.AgentLeft{{
		{Proto: proto.UDP, Range: nft.AgentRange{Ports: proto.PortRange{Lo: 27015, Hi: 27015}, Dest: netip.AddrPortFrom(fo4, 27015)}},
		{Proto: proto.UDP, Range: nft.AgentRange{Ports: proto.PortRange{Lo: 27016, Hi: 27016}, Dest: netip.AddrPortFrom(fo3, 27016)}},
	}}
	if !reflect.DeepEqual(k.closedLeft, want) {
		t.Errorf("closed %v, want u1's flows to .4 and u2's flows to .3", k.closedLeft)
	}
}

// 切り替えた見直しの公開し直しが失敗したら、離れたアドレスを持ち続け、DNAT を変える公開に後で成功した
// ときに消す。同じ DNAT を置き直す修復の公開では使わない。使った後は忘れるので、後で切り替えによらずに
// そのアドレスから離れても消さない。持っている間に同じ宛先へ戻ったポートも消さない(7b.2 節)。
func TestKernelFailoverClosesAfterAFailedRepublish(t *testing.T) {
	setup := func(t *testing.T) (*fakeKernel, *Dataplane, []proto.AgentRule) {
		t.Helper()
		k, d := failoverKernel(t, nil, nil, fo3, fo4)
		rules := []proto.AgentRule{tcpRule("r1", "game.lan:25565", 25565, 25565), udpRule("u1", "game.lan:27015", 27015)}
		if _, err := d.ApplyRules(1, rules, nil); err != nil {
			t.Fatal(err)
		}
		k.probeErr[netip.AddrPortFrom(fo3, 25565)] = errRefused
		tick(t, d, rules)
		// 切り替えた見直しの公開し直しが失敗する
		k.publishErr = errors.New("batch refused")
		if _, err := d.ObserveCommit(1, rules, d.ObservePrepare(rules)); err == nil {
			t.Fatal("the republish did not fail")
		}
		// .3 がまた応えるので、後の見直しは切り替え直さない。消すのは失敗した見直しで離れたアドレスだけである
		delete(k.probeErr, netip.AddrPortFrom(fo3, 25565))
		d.Refresh()
		k.publishErr = nil
		if len(k.closedLeft) != 0 {
			t.Fatalf("closed %v before any publication succeeded", k.closedLeft)
		}
		return k, d, rules
	}
	t.Run("a later republish closes", func(t *testing.T) {
		k, d, rules := setup(t)
		// テーブルを外で変えられ、通知の後の修復が同じ DNAT を置き直す。ここでは消さない
		k.tableEdit++
		if _, err := d.ObserveNotified(1, rules); err != nil {
			t.Fatal(err)
		}
		if len(k.closedLeft) != 0 {
			t.Fatalf("a repair with the same DNAT closed %v", k.closedLeft)
		}
		tick(t, d, rules)
		if got := lastDest(t, k, "u1"); got.Addr() != fo4 {
			t.Fatalf("u1 on %s, want .4", got)
		}
		want := [][]conntrack.AgentLeft{{{Proto: proto.UDP, Range: nft.AgentRange{Ports: proto.PortRange{Lo: 27015, Hi: 27015}, Dest: netip.AddrPortFrom(fo3, 27015)}}}}
		if !reflect.DeepEqual(k.closedLeft, want) {
			t.Errorf("closed %v, want u1's flows to .3", k.closedLeft)
		}
	})
	t.Run("a port back on the address is not closed, and the address is forgotten", func(t *testing.T) {
		k, d, rules := setup(t)
		// TCP のルールが無くなり、u1 は .3 のまま公開される
		if _, err := d.ApplyRules(2, rules[1:], nil); err != nil {
			t.Fatal(err)
		}
		if got := lastDest(t, k, "u1"); got.Addr() != fo3 || len(k.closedLeft) != 0 {
			t.Fatalf("u1 on %s, closed %v; want .3 and nothing closed", got, k.closedLeft)
		}
		// 後で名前から .3 が外れて u1 が .4 へ動いても、切り替えではないので消さない
		k.dns["game.lan"] = []netip.Addr{fo4}
		tick(t, d, rules[1:])
		if got := lastDest(t, k, "u1"); got.Addr() != fo4 || len(k.closedLeft) != 0 {
			t.Errorf("u1 on %s, closed %v; want .4 and nothing closed", got, k.closedLeft)
		}
	})
}
