package agent

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// us は runtime の dataplane をユーザー空間モードの実装として返す。トンネルと中継を直接確かめる
// 試験のための口である。
func (rt *runtime) us() *userspaceDataplane { return rt.dp.(*userspaceDataplane) }

// newTestUserspace は、宛先の許可一覧も予算の指定も持たないユーザー空間モードの dataplane を作る。
func newTestUserspace() *userspaceDataplane { return newUserspaceDataplane(nil, resource.Limits{}) }

// fakeDataplane は runtime の境目の試験に使う記録器である。トンネルを本当に立てずに、runtime が
// 境目をどう呼ぶかを確かめる。
type fakeDataplane struct {
	up       bool
	applyErr error
	applied  [][]proto.AgentRule
	reading  dataplaneReading
	reads    int
}

func (d *fakeDataplane) build(wgtypes.Key, proto.WGConfig) (bool, error) {
	d.up = true
	return true, nil
}
func (d *fakeDataplane) built() bool { return d.up }
func (d *fakeDataplane) applyRules(rules []proto.AgentRule) (string, error) {
	if d.applyErr != nil {
		return "", d.applyErr
	}
	d.applied = append(d.applied, rules)
	return "fake", nil
}
func (d *fakeDataplane) refresh()                 {}
func (d *fakeDataplane) close()                   { d.up = false }
func (d *fakeDataplane) lastHandshake() time.Time { return d.reading.tunnel.lastHandshake }
func (d *fakeDataplane) read() dataplaneReading {
	d.reads++
	return d.reading
}

func newFakeDataplaneRuntime(t *testing.T, dp *fakeDataplane) *runtime {
	t.Helper()
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &runtime{
		opts: Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json")},
		f:    &credentials.Credentials{},
		priv: priv,
		dp:   dp,
	}
}

// dataplane が宣言をまとめて公開できなかったときは、処理済み世代も認証情報ファイルの last_state も
// 進めない(設計文書 7a.3 節の backend 全体の失敗)。トンネルが既にある場合と、立てた直後の場合の
// 両方を確かめ、失敗が消えた後に同じ全体状態を適用し直せば世代が進むことも確かめる。
func TestApplyKeepsTheGenerationWhenTheDataplaneFails(t *testing.T) {
	t.Run("with a tunnel already up", func(t *testing.T) {
		dp := &fakeDataplane{}
		rt := newFakeDataplaneRuntime(t, dp)
		first := &proto.State{Generation: 1, Rules: []proto.AgentRule{{ID: "r1"}}}
		if err := rt.apply(first); err != nil {
			t.Fatal(err)
		}
		if rt.gen != 1 || rt.f.LastState != first {
			t.Fatalf("after a good apply: gen=%d last_state=%v, want 1 and the applied state", rt.gen, rt.f.LastState)
		}
		saved, err := os.ReadFile(rt.opts.CredentialsPath)
		if err != nil {
			t.Fatal(err)
		}

		dp.applyErr = errors.New("table rejected")
		second := &proto.State{Generation: 2, Rules: []proto.AgentRule{{ID: "r2"}}}
		if err := rt.apply(second); err == nil {
			t.Fatal("apply returned no error when the dataplane failed")
		}
		if rt.gen != 1 || rt.f.LastState != first {
			t.Errorf("after a failed apply: gen=%d, last_state is the new state: %v; want generation 1 and the previous state", rt.gen, rt.f.LastState == second)
		}
		after, err := os.ReadFile(rt.opts.CredentialsPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(after, saved) {
			t.Error("the credentials file was rewritten after a failed apply")
		}

		dp.applyErr = nil
		if err := rt.apply(second); err != nil {
			t.Fatal(err)
		}
		if rt.gen != 2 || rt.f.LastState != second {
			t.Errorf("after applying the same state again: gen=%d, want 2 and the state recorded", rt.gen)
		}
	})

	t.Run("right after building the tunnel", func(t *testing.T) {
		dp := &fakeDataplane{applyErr: errors.New("table rejected")}
		rt := newFakeDataplaneRuntime(t, dp)
		first := &proto.State{Generation: 1, Rules: []proto.AgentRule{{ID: "r1"}}}
		err := rt.apply(first)
		if err == nil {
			t.Fatal("apply returned no error when the dataplane failed")
		}
		// トンネルは立っているので、WireGuard の失敗には見せない
		if strings.HasPrefix(err.Error(), "wireguard:") {
			t.Errorf("error = %q; a dataplane failure after a successful build must not read as a wireguard failure", err)
		}
		if rt.gen != 0 || rt.f.LastState != nil {
			t.Errorf("after a failed apply: gen=%d last_state set=%v, want generation 0 and none", rt.gen, rt.f.LastState != nil)
		}
		if _, err := os.Stat(rt.opts.CredentialsPath); !os.IsNotExist(err) {
			t.Errorf("the credentials file was written after a failed apply: %v", err)
		}

		dp.applyErr = nil
		if err := rt.apply(first); err != nil {
			t.Fatal(err)
		}
		if rt.gen != 1 || rt.f.LastState != first {
			t.Errorf("after applying the same state again: gen=%d, want 1 and the state recorded", rt.gen)
		}
	})
}

// 閾値を持たない rebuildState でも、checkTunnel は同じハンドシェイクを 1 度しか新しいと数えない。
// 数え直すと、stream の再接続の待ちを 30 秒ごとに打ち切ってしまう(仕様 5.2 節)。
func TestCheckTunnelWakesOncePerHandshakeWithoutAThreshold(t *testing.T) {
	hs := time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)
	dp := &fakeDataplane{up: true, reading: dataplaneReading{tunnel: tunnelReading{present: true, lastHandshake: hs}}}
	rt := newFakeDataplaneRuntime(t, dp)
	rt.f.LastState = &proto.State{Generation: 1}
	rt.handshakeWake = make(chan struct{}, 1)
	wakes := 0
	now := time.Now()
	for i := 0; i < 5; i++ {
		rt.checkTunnel(now.Add(time.Duration(i) * 30 * time.Second))
		select {
		case <-rt.handshakeWake:
			wakes++
		default:
		}
	}
	if wakes != 1 {
		t.Errorf("wakes = %d over 5 checks of one handshake, want 1", wakes)
	}
	// 新しいハンドシェイクは、閾値が無くても再び数える
	dp.reading.tunnel.lastHandshake = hs.Add(2 * time.Minute)
	rt.checkTunnel(now.Add(5 * 30 * time.Second))
	select {
	case <-rt.handshakeWake:
	default:
		t.Error("a new handshake did not wake the stream")
	}
	if !dp.up {
		t.Error("the watchdog closed the tunnel without a threshold")
	}
}

// Run が組む runtime は、宛先の許可一覧とフロー数の予算を dataplane に渡す。doctor が示す一覧も
// 同じ opts.AllowTargets なので、中継が守る一覧と食い違わない(設計文書 10.2c 節)。
func TestNewRuntimePassesTheAllowlistToTheDataplane(t *testing.T) {
	list, err := allowtargets.Parse("192.168.1.20:25565")
	if err != nil {
		t.Fatal(err)
	}
	limits := resource.Limits{UDPTotal: 16, TCPTotal: 8}
	rt := newRuntime(Options{AllowTargets: list, Limits: limits}, &credentials.Credentials{}, wgtypes.Key{})
	us, ok := rt.dp.(*userspaceDataplane)
	if !ok {
		t.Fatalf("dataplane is %T, want *userspaceDataplane", rt.dp)
	}
	if us.allow != list || us.allow != rt.opts.AllowTargets {
		t.Errorf("dataplane allowlist = %v, want the same list as opts.AllowTargets (%v)", us.allow, list)
	}
	if us.limits != limits {
		t.Errorf("dataplane limits = %+v, want %+v", us.limits, limits)
	}
}

// ハートビートは dataplane を 1 回だけ読み、トンネルの状態とルールごとの状態をその読みから組む
// (設計文書 10.2c 節)。中継を持たない dataplane の doctor の応答は、ルールとフロー予算を載せない。
func TestHeartbeatAndDoctorReadTheDataplaneOnce(t *testing.T) {
	hs := time.Date(2026, 9, 24, 9, 0, 0, 0, time.UTC)
	dp := &fakeDataplane{up: true, reading: dataplaneReading{
		tunnel: tunnelReading{present: true, lastHandshake: hs, rxBytes: 5, txBytes: 7},
		rules:  []proto.RuleStatus{{ID: "r1", State: proto.StatusError, Reason: "target refused"}},
	}}
	rt := newFakeDataplaneRuntime(t, dp)
	rt.gen = 4
	// 中継が無ければ拒否の累計の起点は無い。起点に使う時刻が立っていても載せないことを確かめる
	rt.tunStart = time.Date(2026, 9, 24, 8, 0, 0, 0, time.UTC)

	hb := rt.heartbeat()
	if dp.reads != 1 {
		t.Errorf("heartbeat read the dataplane %d times, want 1", dp.reads)
	}
	if hb.Generation != 4 || hb.Tunnel.State != proto.StatusOK || !hb.Tunnel.LastHandshake.Equal(hs) {
		t.Errorf("heartbeat = %+v, want generation 4 and an ok tunnel with the handshake", hb)
	}
	if len(hb.Rules) != 1 || hb.Rules[0].ID != "r1" || hb.Rules[0].State != proto.StatusError {
		t.Errorf("heartbeat rules = %+v, want the dataplane's rule state", hb.Rules)
	}

	dp.reads = 0
	st := rt.collectDoctor().RuntimeState
	if dp.reads != 1 {
		t.Errorf("doctor read the dataplane %d times, want 1", dp.reads)
	}
	if st == nil || st.Tunnel.RxBytes != 5 || st.Tunnel.TxBytes != 7 {
		t.Fatalf("doctor runtime state = %+v, want the transfer counters from the same read", st)
	}
	if st.Rules != nil || st.Budgets != nil || !st.RefusalsSince.IsZero() {
		t.Errorf("a dataplane without a relay: rules=%v budgets=%v refusals_since=%v, want none", st.Rules, st.Budgets, st.RefusalsSince)
	}
}
