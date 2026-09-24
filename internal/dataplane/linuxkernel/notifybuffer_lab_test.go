//go:build lab && linux

package linuxkernel

// 変更の通知のソケットの受信バッファが足りないと、大きな Admission Policy の送信元一覧(数千要素
// の set)を続けて公開したとき、購読が ENOBUFS で失敗する(設計文書 7a.3 節「変更の通知」)。
// ラボの vps ns で root として実行し
// (lab/lab test internal/dataplane/linuxkernel vps -test.run TestLabWatchSurvivesLargeSourceListBursts)、
// 5000 要素の一覧を 5 回続けて公開しても Watch がその失敗を返さないことを確かめる。直したのは
// watch.go の notifyReceiveBuffer である。

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// spreadPrefixes は base から 4 つおきに並べた n 個の /32 を返す。隣り合わないので併合されず、
// set の要素も n 個のままになる(internal/dataplane/linuxkernel/nft の同名のテスト用関数と同じ形。
// このラボ試験だけのために公開すみでなく、ここに写した)。
func spreadPrefixes(base netip.Addr, n int) []netip.Prefix {
	b := binary.BigEndian.Uint32(base.AsSlice())
	out := make([]netip.Prefix, n)
	for i := range out {
		out[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, b+uint32(i)*4))), 32)
	}
	return out
}

// labSourceListPlan は、送信元の deny 一覧を持つ UDP のルール 1 本の Plan を組み立てる
// (internal/dataplane/linuxkernel/nft の planFromRules と同じ経路を、公開されている関数だけで通す)。
func labSourceListPlan(t *testing.T, ruleID string, port uint16, deny []netip.Prefix) planner.Plan {
	t.Helper()
	rules := []proto.Rule{{
		ID: ruleID, Agent: "home", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: port, Hi: port},
		Target: "192.168.1.20:9999", VPSMode: proto.ModeKernel, Enabled: true, SourceDeny: deny,
	}}
	normalized, err := model.NormalizeRules(rules, nil)
	if err != nil {
		t.Fatalf("model.NormalizeRules: %v", err)
	}
	agents := []planner.Agent{{Name: "home", Addr: netip.MustParseAddr("10.200.0.2")}}
	return planner.Build(planner.Input{Rules: normalized, Limits: policy.AdmissionLimits{}, Agents: agents})
}

func TestLabWatchSurvivesLargeSourceListBursts(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft がない")
	}
	t.Cleanup(func() { exec.Command("nft", "delete", "table", "inet", nft.TableName).Run() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b := &Backend{}
	watchErr := make(chan error, 1)
	var wakes atomic.Int32
	go func() { watchErr <- b.Watch(ctx, func() { wakes.Add(1) }) }()
	time.Sleep(200 * time.Millisecond) // 購読が成立するまで待つ

	base := netip.MustParseAddr("100.96.0.0")
	const lists, elems = 5, 5000
	for i := 0; i < lists; i++ {
		plan := labSourceListPlan(t, fmt.Sprintf("r_burst%d", i), uint16(24000+i), spreadPrefixes(base, elems))
		start := time.Now()
		if err := nft.Apply(plan, nil, nft.Config{WGInterface: "wg0"}); err != nil {
			t.Fatalf("Apply #%d of %d prefixes: %v", i, elems, err)
		}
		t.Logf("Apply #%d of %d prefixes took %v", i, elems, time.Since(start))
	}

	// 最後の Apply が生む通知は、この時点ではまだ読み取り側に届いていないかもしれない。ここで
	// cancel すると、その通知の受信で ENOBUFS が起きても、読み取り側がそれを見る前に Watch が
	// 止まってしまい、失敗を見逃す。wakes が公開した数に届くか、Watch 自身が失敗を返すまで待つ。
	deadline := time.Now().Add(10 * time.Second)
	for wakes.Load() < lists {
		select {
		case err := <-watchErr:
			if err != nil {
				t.Fatalf("Watch failed while publishing %d source lists of %d prefixes back to back: %v", lists, elems, err)
			}
			t.Fatal("Watch returned before ctx was cancelled")
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("only %d of %d wakes arrived within the timeout", wakes.Load(), lists)
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-watchErr:
		if err != nil {
			t.Fatalf("Watch failed while publishing %d source lists of %d prefixes back to back: %v", lists, elems, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Watch did not return after ctx was cancelled")
	}
	t.Logf("woke %d times for %d publications of %d prefixes each", wakes.Load(), lists, elems)
}
