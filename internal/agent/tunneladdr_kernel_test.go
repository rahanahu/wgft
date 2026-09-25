//go:build linux

package agent

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/proto"
)

// kernelRuntime は、fakeKernel を使うカーネルモードの dataplane を持つ runtime を作る。d は wg 設定を
// 受け取った状態で、wgft0 は宣言どおりである。
func kernelRuntime(t *testing.T, k *fakeKernel, f *credentials.Credentials) (*runtime, *kernelDataplane) {
	t.Helper()
	d := newTestKernel(t, k, f, nil)
	k.link = ours(t, d)
	rt := &runtime{opts: Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json"), Mode: "kernel"}, f: f, priv: d.priv, dp: d, wgCfg: d.wg}
	return rt, d
}

func withAddress(w proto.WGConfig, addr string) proto.WGConfig {
	w.Address = addr
	return w
}

// 記録と違うトンネルのアドレスを持つ全体状態は、wgft0 にも表にも触る前に拒み、適用しない。処理済み世代、
// last_state、記録、今の wg 設定はそのまま残り、ハートビートのトンネルの状態が拒んだことを示す。30 秒ごとの
// 見直しは直前の全体状態の表を直し続ける。記録と同じアドレスの全体状態が届けば、拒んだ印は消える
// (設計文書 7b.1・11 節)。違う帯、違う長さ、LAN の帯の一部を覆う細かい帯の 3 つを確かめる。
func TestKernelRefusesAnAddressItWasNotRegisteredWith(t *testing.T) {
	for _, bad := range []string{"10.201.0.2/24", "10.200.0.2/16", "10.200.0.2/25", "192.168.1.100/25"} {
		t.Run(bad, func(t *testing.T) {
			k := &fakeKernel{}
			f := &credentials.Credentials{TunnelAddress: "10.200.0.2/24"}
			rt, d := kernelRuntime(t, k, f)
			good := &proto.State{Generation: 1, WG: d.wg, Rules: []proto.AgentRule{tcpRule("r1", "192.168.1.20:80", 80, 80)}}
			if err := rt.apply(good); err != nil {
				t.Fatal(err)
			}
			ensured, published := len(k.ensured), len(k.published)

			st := &proto.State{Generation: 2, WG: withAddress(d.wg, bad), Rules: []proto.AgentRule{tcpRule("r2", "192.168.1.21:81", 81, 81)}}
			err := rt.apply(st)
			var mm *credentials.TunnelAddressMismatch
			if !errors.As(err, &mm) {
				t.Fatalf("apply = %v, want a tunnel address mismatch", err)
			}
			if len(k.ensured) != ensured || len(k.published) != published {
				t.Errorf("the refused state touched the kernel: %d convergences and %d publications after it", len(k.ensured)-ensured, len(k.published)-published)
			}
			if rt.gen != 1 || rt.f.LastState != good || f.TunnelAddress != "10.200.0.2/24" {
				t.Errorf("gen=%d last_state=%v record=%q; want 1, the good state and the old record", rt.gen, rt.f.LastState, f.TunnelAddress)
			}
			if !d.built() || d.wg.Address != "10.200.0.2/24" || rt.wgCfg.Address != "10.200.0.2/24" {
				t.Errorf("the tunnel changed: built=%v address=%s applied=%s", d.built(), d.wg.Address, rt.wgCfg.Address)
			}
			hb := rt.heartbeat()
			if hb.Tunnel.State != proto.StatusError || !strings.Contains(hb.Tunnel.Reason, "refused") || !strings.Contains(hb.Tunnel.Reason, bad) || hb.Generation != 1 {
				t.Errorf("heartbeat = %+v", hb)
			}
			if len(hb.Rules) != 1 || hb.Rules[0].ID != "r1" {
				t.Errorf("heartbeat rules = %+v, want the rules of generation 1", hb.Rules)
			}

			// 拒んでいる間も、30 秒ごとの見直しは直前の全体状態の表を直す
			k.tableGone = true
			rt.observe()
			if len(k.published) != published+1 || k.published[len(k.published)-1].Generation != 1 {
				t.Errorf("the 30-second check did not repair the table of generation 1 while refusing: %v", gens(k.published))
			}

			ok := &proto.State{Generation: 3, WG: d.wg, Rules: []proto.AgentRule{tcpRule("r3", "192.168.1.22:82", 82, 82)}}
			if err := rt.apply(ok); err != nil {
				t.Fatal(err)
			}
			if hb := rt.heartbeat(); strings.Contains(hb.Tunnel.Reason, "refused") || hb.Generation != 3 {
				t.Errorf("after a state with the recorded address: heartbeat = %+v", hb)
			}
		})
	}
}

// 記録の無い認証情報ファイル(この項目より前の版が書いたもの)では、最初に適用できた全体状態のアドレスを
// 記録して保存し、以後はそれと違うアドレスを拒む。登録の応答のアドレスだけの記録は、同じアドレスの
// 全体状態で帯の長さまで記録する。表の公開に失敗した全体状態のアドレスは記録しない(設計文書 9・11 節)。
func TestKernelRecordsTheFirstAppliedAddress(t *testing.T) {
	for _, before := range []string{"", "10.200.0.2"} {
		t.Run("record "+before, func(t *testing.T) {
			k := &fakeKernel{}
			f := &credentials.Credentials{TunnelAddress: before}
			rt, d := kernelRuntime(t, k, f)
			k.publishErr = errors.New("batch refused")
			if err := rt.apply(&proto.State{Generation: 1, WG: d.wg}); err == nil {
				t.Fatal("the failed publication was not reported")
			}
			if f.TunnelAddress != before {
				t.Errorf("a state that was not applied was recorded: %q", f.TunnelAddress)
			}
			k.publishErr = nil
			if err := rt.apply(&proto.State{Generation: 1, WG: d.wg}); err != nil {
				t.Fatal(err)
			}
			saved, err := credentials.Load(rt.opts.CredentialsPath)
			if err != nil {
				t.Fatal(err)
			}
			if f.TunnelAddress != "10.200.0.2/24" || saved.TunnelAddress != "10.200.0.2/24" {
				t.Errorf("record = %q, saved %q; want 10.200.0.2/24", f.TunnelAddress, saved.TunnelAddress)
			}
			if err := rt.apply(&proto.State{Generation: 2, WG: withAddress(d.wg, "10.200.0.2/23")}); err == nil {
				t.Error("an address other than the recorded one was accepted")
			}
		})
	}
}

// トンネルが無い間に届いた全体状態の記録と違うアドレスは、他の wg 設定の誤りと同じく作成の失敗になり、
// wgft0 には触れない。登録の応答のアドレスだけの記録でも、違うアドレスを拒む。
func TestKernelRefusesAnAddressBeforeTheFirstTunnel(t *testing.T) {
	k := &fakeKernel{}
	f := &credentials.Credentials{TunnelAddress: "10.200.0.2"}
	d := &kernelDataplane{ops: k.ops(), iface: "wgft0", f: f, ctx: context.Background(), lkg: map[string]lkgEntry{}, probeErr: map[string]string{}}
	rt := &runtime{opts: Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json"), Mode: "kernel"}, f: f, priv: testKey(t), dp: d}
	st := &proto.State{Generation: 1, WG: withAddress(testWG(t), "192.168.1.100/25")}
	err := rt.apply(st)
	var mm *credentials.TunnelAddressMismatch
	if !errors.As(err, &mm) {
		t.Fatalf("apply = %v, want a tunnel address mismatch", err)
	}
	if d.built() || len(k.ensured) != 0 || len(k.published) != 0 || f.TunnelAddress != "10.200.0.2" {
		t.Errorf("built=%v ensured=%d published=%d record=%q", d.built(), len(k.ensured), len(k.published), f.TunnelAddress)
	}
	if hb := rt.heartbeat(); hb.Tunnel.Reason != "no tunnel; building it failed" {
		t.Errorf("heartbeat = %+v", hb)
	}
}

// 拒むときの文面は、触らないものと、帯を変える正規の道(登録のし直し)を示し、丸括弧を使わない。
func TestKernelRefusalText(t *testing.T) {
	k := &fakeKernel{}
	d := newTestKernel(t, k, &credentials.Credentials{TunnelAddress: "10.200.0.2/24"}, nil)
	_, err := d.checkWG(withAddress(d.wg, "192.168.1.100/25"))
	if err == nil {
		t.Fatal("no refusal")
	}
	s := err.Error()
	for _, want := range []string{"192.168.1.100/25", "10.200.0.2/24", "wgft0", "register this agent again", "wgft server teardown --purge"} {
		if !strings.Contains(s, want) {
			t.Errorf("%q lacks %q", s, want)
		}
	}
	if strings.ContainsAny(s, "()") {
		t.Errorf("parentheses in output: %q", s)
	}
}

// 公開に失敗した古い世代を試し直して通しても、新しい世代の拒否の表示は消えない。表示を消すのは、拒んだ
// 世代と同じか新しい世代の wg 設定を受け入れたときだけである。古い世代の試し直しが拒まれても、新しい
// 世代の拒否の表示を古い世代で置き換えない。
func TestKernelRefusalSurvivesARetryOfAnOlderGeneration(t *testing.T) {
	k := &fakeKernel{}
	f := &credentials.Credentials{TunnelAddress: "10.200.0.2/24"}
	rt, d := kernelRuntime(t, k, f)
	if err := rt.apply(&proto.State{Generation: 1, WG: d.wg}); err != nil {
		t.Fatal(err)
	}
	k.publishErr = errors.New("batch refused")
	if err := rt.apply(&proto.State{Generation: 2, WG: d.wg, Rules: []proto.AgentRule{tcpRule("r2", "192.168.1.21:81", 81, 81)}}); err == nil {
		t.Fatal("the failed publication was not reported")
	}
	if rt.pendingSt == nil || rt.pendingSt.Generation != 2 {
		t.Fatalf("pending = %+v, want generation 2", rt.pendingSt)
	}
	if err := rt.apply(&proto.State{Generation: 3, WG: withAddress(d.wg, "192.168.1.100/25")}); err == nil {
		t.Fatal("generation 3 was not refused")
	}
	k.publishErr = nil
	if err := rt.retryPending(); err != nil {
		t.Fatal(err)
	}
	if rt.gen != 2 {
		t.Fatalf("gen = %d after the retry, want 2", rt.gen)
	}
	hb := rt.heartbeat()
	if !strings.Contains(hb.Tunnel.Reason, "refused the wg configuration of generation 3") || !strings.Contains(hb.Tunnel.Reason, "192.168.1.100/25") {
		t.Errorf("the retry of generation 2 cleared the refusal of generation 3: %+v", hb.Tunnel)
	}

	// 古い世代が拒まれても、表示は新しい世代のまま
	rt.mu.Lock()
	_ = rt.checkWGLocked(&proto.State{Generation: 2, WG: withAddress(d.wg, "10.9.0.2/24")})
	rt.mu.Unlock()
	if hb := rt.heartbeat(); !strings.Contains(hb.Tunnel.Reason, "generation 3") {
		t.Errorf("an older refusal replaced the newer one: %+v", hb.Tunnel)
	}

	if err := rt.apply(&proto.State{Generation: 4, WG: d.wg}); err != nil {
		t.Fatal(err)
	}
	if hb := rt.heartbeat(); strings.Contains(hb.Tunnel.Reason, "refused") {
		t.Errorf("a newer accepted state did not clear the refusal: %+v", hb.Tunnel)
	}
}

// トンネルが立っている間に届いた、形の誤った wg 設定(mtu、keepalive、公開鍵)も、アドレスの拒否と同じく
// インタフェースと表を残したまま拒み、ハートビートに示す(設計文書 7b.1 節)。
func TestKernelRefusesAMalformedConfigWhileUp(t *testing.T) {
	bad := map[string]func(*proto.WGConfig){
		"mtu":       func(w *proto.WGConfig) { w.MTU = 0 },
		"keepalive": func(w *proto.WGConfig) { w.Keepalive = -1 },
		"pubkey":    func(w *proto.WGConfig) { w.ServerPubkey = "not a key" },
	}
	for name, mutate := range bad {
		t.Run(name, func(t *testing.T) {
			k := &fakeKernel{}
			rt, d := kernelRuntime(t, k, &credentials.Credentials{})
			if err := rt.apply(&proto.State{Generation: 1, WG: d.wg}); err != nil {
				t.Fatal(err)
			}
			w := d.wg
			mutate(&w)
			ensured := len(k.ensured)
			if err := rt.apply(&proto.State{Generation: 2, WG: w}); err == nil {
				t.Fatal("not refused")
			}
			if !d.built() || len(k.ensured) != ensured || rt.gen != 1 {
				t.Errorf("built=%v convergences=%d gen=%d", d.built(), len(k.ensured)-ensured, rt.gen)
			}
			if hb := rt.heartbeat(); !strings.Contains(hb.Tunnel.Reason, ReasonWGRefused) {
				t.Errorf("heartbeat = %+v", hb.Tunnel)
			}
		})
	}
}
