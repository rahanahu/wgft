//go:build linux

package nft

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"

	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// defaultRcvbuf は Linux の net.core.rmem_default / wmem_default の既定値。バッファを合わせない
// 版の vpsd はこの値の中で送受信していた(設計文書 6.1 節)。
const defaultRcvbuf = 212992

// scaleRules は、ポートを 1 つずつずらした n 本のルールを作る。wide が真なら、送信元の集合と
// レートを持たせて、1 ルールあたりの行と set の要素を増やす。
func scaleRules(n int, wide bool) []proto.Rule {
	out := make([]proto.Rule, 0, n)
	for i := 0; i < n; i++ {
		p := uint16(20000 + i)
		pp := proto.UDP
		if i != n-1 {
			pp = proto.TCP
		}
		r := proto.Rule{
			ID: fmt.Sprintf("r_scale%05d", i), Agent: "home", Proto: pp, ListenPort: pr(p, p),
			Target: fmt.Sprintf("192.168.50.2:%d", p), VPSMode: proto.ModeKernel, Enabled: true,
		}
		if wide {
			for j := 0; j < 200; j++ {
				r.SourceAllow = append(r.SourceAllow, netip.MustParsePrefix(fmt.Sprintf("10.0.%d.0/24", j)))
				r.SourceDeny = append(r.SourceDeny, netip.MustParsePrefix(fmt.Sprintf("203.0.%d.0/24", j)))
			}
			r.NewFlowRate = rate("100/second")
			r.PerSourceRate = rate("10/second")
			if pp == proto.UDP {
				r.PacketRate = rate("5000/second")
			}
		}
		out = append(out, r)
	}
	return out
}

// sentBatch は、plan から組み立てたバッチを、カーネルに送らずに数える。nltest のソケットは
// SendMessages で渡された列をそのまま関数に渡すので、Flush が実際に送る形のまま測れる。
// 返すのは、バッチの本体のメッセージ数と、その全体の長さである。
func sentBatch(t *testing.T, n int, wide bool) (msgs, bytes int, size batchSize) {
	t.Helper()
	plan := buildTestPlan(t, scaleRules(n, wide),
		map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}, policy.AdmissionLimits{})
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		for _, m := range req {
			msgs++
			bytes += 16 + ((len(m.Data) + 3) &^ 3) // netlink のヘッダと 4 バイト境界への切り上げ
		}
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := emit(&sizing{to: conn, size: &size}, plan, nil, testCfg); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatalf("flush into the test socket: %v", err)
	}
	// google/nftables の batch() が前後に BATCH_BEGIN と BATCH_END を足す。
	return msgs - 2, bytes, size
}

// TestBatchSizeIsAnUpperBound は、数えた大きさが実際に送るバッチを下回らないことを確かめる。
// 下回ると sendmsg が EMSGSIZE で失敗するので、この上限がソケットの設定の前提になる。
func TestBatchSizeIsAnUpperBound(t *testing.T) {
	for _, tc := range []struct {
		n    int
		wide bool
	}{{1, false}, {10, false}, {100, false}, {1000, false}, {10, true}, {100, true}} {
		t.Run(fmt.Sprintf("n=%d_wide=%v", tc.n, tc.wide), func(t *testing.T) {
			msgs, bytes, size := sentBatch(t, tc.n, tc.wide)
			if size.messages != msgs {
				t.Errorf("counted %d messages, the batch has %d", size.messages, msgs)
			}
			if size.bytes < bytes {
				t.Errorf("counted %d bytes, the batch is %d bytes long", size.bytes, bytes)
			}
			t.Logf("messages=%d bytes=%d counted=%d", msgs, bytes, size.bytes)
		})
	}
}

// TestBufferSizesCoverTheReplies は、要求する受信側の大きさが、カーネルが返す ACK と ECHO の
// 量を上回ることを確かめる。上回らないと ENOBUFS で応答を取りこぼす。
// 100 本のルールは、既定のバッファ(212992)のままでは受信側があふれる大きさである。
func TestBufferSizesCoverTheReplies(t *testing.T) {
	msgs, bytes, size := sentBatch(t, 100, false)
	send, receive := size.bufferSizes()

	// ECHO で返るルールの写しはバッチ自身とほぼ同じ大きさで、ACK は 1 通につき 1 つ返る。
	replies := bytes + msgs*ackBytes
	if replies <= defaultRcvbuf {
		t.Fatalf("100 rules produce %d bytes of replies, which the default %d already covers; this test no longer exercises the wall", replies, defaultRcvbuf)
	}
	if receive < replies {
		t.Errorf("receive buffer %d does not cover %d bytes of replies", receive, replies)
	}
	if send < bytes {
		t.Errorf("send buffer %d does not cover the %d byte batch", send, bytes)
	}
}

// TestBufferSizesStayWithinBounds は、下限と上限を確かめる。小さなバッチでも既定値を下回らせず、
// 大きなバッチでもカーネルに際限のない大きさを要求しない。
func TestBufferSizesStayWithinBounds(t *testing.T) {
	small := batchSize{messages: 1, bytes: 100}
	if send, receive := small.bufferSizes(); send != minBuffer || receive != minBuffer {
		t.Errorf("small batch asks for send=%d receive=%d, want %d for both", send, receive, minBuffer)
	}
	if minBuffer <= defaultRcvbuf {
		t.Errorf("the floor %d is not above the default %d", minBuffer, defaultRcvbuf)
	}
	huge := batchSize{messages: 1 << 20, bytes: 1 << 30}
	if send, receive := huge.bufferSizes(); send != maxBuffer || receive != maxBuffer {
		t.Errorf("huge batch asks for send=%d receive=%d, want %d for both", send, receive, maxBuffer)
	}
}

// TestStageCountsTheBatch は、Stage が組み立てたバッチの大きさを Staged に残すことを確かめる。
// nftables.Conn は Flush までソケットを開かないので、この確認は root もカーネルも要らない。
func TestStageCountsTheBatch(t *testing.T) {
	plan := buildTestPlan(t, scaleRules(100, false),
		map[string]netip.Addr{"home": netip.MustParseAddr("10.200.0.2")}, policy.AdmissionLimits{})
	s, err := Stage(plan, nil, testCfg)
	if err != nil {
		t.Fatal(err)
	}
	if s.size.messages == 0 || s.size.bytes == 0 {
		t.Fatalf("Stage left the batch size unset: %+v", s.size)
	}
	if _, receive := s.size.bufferSizes(); receive <= defaultRcvbuf {
		t.Errorf("Stage of 100 rules asks for a %d byte receive buffer, which is not above the default %d", receive, defaultRcvbuf)
	}
}
