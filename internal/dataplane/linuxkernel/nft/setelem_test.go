//go:build linux

package nft

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"

	"github.com/rahanahu/wgft/internal/policy"
	"github.com/rahanahu/wgft/proto"
)

// spreadPrefixes は、base から 4 つおきに並べた n 個の /32 を返す。隣り合わないので併合されず、
// 1 つの /32 が区間 1 つ(開始と終端の印の 2 要素)になる。
func spreadPrefixes(base netip.Addr, n int) []netip.Prefix {
	b := binary.BigEndian.Uint32(base.AsSlice())
	out := make([]netip.Prefix, n)
	for i := range out {
		out[i] = netip.PrefixFrom(netip.AddrFrom4([4]byte(binary.BigEndian.AppendUint32(nil, b+uint32(i)*4))), 32)
	}
	return out
}

// 要素を分けても、つなげば元の列に戻り、どの通も n 個以下で、区間の開始と終端の印が別の通に
// 分かれない(次の通が終端の印から始まらない)。
func TestElementChunksKeepIntervalsTogether(t *testing.T) {
	inputs := map[string][]nftables.SetElement{
		"empty":           nil,
		"whole space":     intervalElements([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}),
		"up to the end":   intervalElements([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("255.255.255.0/24")}),
		"1637 prefixes":   intervalElements(spreadPrefixes(netip.MustParseAddr("100.64.0.0"), 1637)),
		"1638 prefixes":   intervalElements(spreadPrefixes(netip.MustParseAddr("100.64.0.0"), 1638)),
		"20000 prefixes":  intervalElements(spreadPrefixes(netip.MustParseAddr("100.64.0.0"), 20000)),
		"starts from 0.0": intervalElements(append(spreadPrefixes(netip.MustParseAddr("0.0.0.0"), 5), netip.MustParsePrefix("255.255.255.255/32"))),
	}
	for name, els := range inputs {
		for _, n := range []int{2, 3, 4, 7, elemsPerMessage} {
			t.Run(fmt.Sprintf("%s/n=%d", name, n), func(t *testing.T) {
				chunks := elementChunks(els, n)
				var joined []nftables.SetElement
				for i, c := range chunks {
					if len(c) == 0 || len(c) > n {
						t.Fatalf("chunk %d has %d elements, want 1 to %d", i, len(c), n)
					}
					if i > 0 && c[0].IntervalEnd {
						t.Fatalf("chunk %d starts with the end of an interval whose start is in chunk %d", i, i-1)
					}
					joined = append(joined, c...)
				}
				if !slices.EqualFunc(joined, els, func(a, b nftables.SetElement) bool {
					return slices.Equal(a.Key, b.Key) && a.IntervalEnd == b.IntervalEnd
				}) {
					t.Fatalf("the chunks joined are not the input: %d elements, want %d", len(joined), len(els))
				}
			})
		}
	}
}

// setElemMessage は、バッチの中の NEWSETELEM 1 通を読んだ結果である。
type setElemMessage struct {
	set       string
	listBytes int // NFTA_SET_ELEM_LIST_ELEMENTS の属性の長さ(見出しの 4 バイトを含む)
	elems     int // 一覧の中の要素の数
	dataBytes int // メッセージの本体(nfgenmsg と属性)の長さ
}

// sentSetElems は plan から組み立てたバッチを、カーネルに送らずに読み、NEWSETELEM の各通を返す。
// バッチ全体のメッセージの数と長さ、sizing が数えた大きさも返す。
func sentSetElems(t *testing.T, plan func() []proto.Rule) (out []setElemMessage, msgs, total int, size batchSize) {
	t.Helper()
	p := buildTestPlan(t, plan(), testAgentAddr, policy.AdmissionLimits{})
	newSetElem := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSETELEM)
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		for _, m := range req {
			msgs++
			total += 16 + ((len(m.Data) + 3) &^ 3)
			if m.Header.Type != newSetElem {
				continue
			}
			got := setElemMessage{dataBytes: len(m.Data)}
			ad, err := netlink.NewAttributeDecoder(m.Data[4:])
			if err != nil {
				return nil, err
			}
			for ad.Next() {
				switch ad.Type() {
				case unix.NFTA_SET_ELEM_LIST_SET:
					got.set = ad.String()
				case unix.NFTA_SET_ELEM_LIST_ELEMENTS:
					got.listBytes = 4 + len(ad.Bytes())
					list, err := netlink.NewAttributeDecoder(ad.Bytes())
					if err != nil {
						return nil, err
					}
					for list.Next() {
						got.elems++
					}
					if err := list.Err(); err != nil {
						return nil, err
					}
				}
			}
			if err := ad.Err(); err != nil {
				return nil, err
			}
			out = append(out, got)
		}
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := emit(&sizing{to: conn, size: &size}, p, nil, testCfg); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatalf("flush into the test socket: %v", err)
	}
	return out, msgs - 2, total, size // google/nftables が前後に BATCH_BEGIN と BATCH_END を足す
}

// 大きな送信元の一覧でも、1 通の要素の一覧は 32 KiB(16 ビットの属性の長さの上限のおよそ半分)に
// 収まり、各通を合わせた要素の数は送るべき要素の数と一致する。属性の長さがあふれると、ここで読める
// 要素の数が減るので、あふれも数の食い違いとして見える(設計文書 6.1 節)。上限は elemListLimit を
// 使わずにここで固定する。定数と実際の符号化が一緒にずれても見逃さないためである。
func TestSetElementMessagesStayUnderTheAttributeLimit(t *testing.T) {
	const maxListBytes = 32 << 10
	for _, n := range []int{1, 1637, 1638, 1700, 5000, 20000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			deny := spreadPrefixes(netip.MustParseAddr("100.64.0.0"), n)
			allow := spreadPrefixes(netip.MustParseAddr("100.66.0.1"), n)
			rules := func() []proto.Rule {
				return []proto.Rule{{ID: "r_big", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2456),
					Target: "192.168.1.20:2456", VPSMode: proto.ModeKernel, Enabled: true, SourceDeny: deny, SourceAllow: allow}}
			}
			sent, msgs, total, size := sentSetElems(t, rules)
			perSet := map[string]int{}
			for _, m := range sent {
				if m.listBytes > maxListBytes {
					t.Errorf("set %s: an element list of %d bytes, over the %d byte limit", m.set, m.listBytes, maxListBytes)
				}
				if m.dataBytes > 65535 {
					t.Errorf("set %s: a message body of %d bytes", m.set, m.dataBytes)
				}
				perSet[m.set] += m.elems
			}
			want := map[string]int{"deny_1": len(intervalElements(deny)), "allow_1": len(intervalElements(allow))}
			for name, w := range want {
				if perSet[name] != w {
					t.Errorf("set %s: the batch carries %d elements, want %d", name, perSet[name], w)
				}
			}
			// sizing は分けた通も 1 通ずつ数え、長さを下回らない(batch.go)
			if size.messages != msgs {
				t.Errorf("counted %d messages, the batch has %d", size.messages, msgs)
			}
			if size.bytes < total {
				t.Errorf("counted %d bytes, the batch is %d bytes long", size.bytes, total)
			}
		})
	}
}

// バッチの中で、送信元の一覧の set の宣言(NEWSET)は、その set の要素のどの通(NEWSETELEM)よりも
// 前にある。宣言より前の要素の通は、カーネルが存在しない set への追加として拒む。
func TestSetDeclaredBeforeItsElements(t *testing.T) {
	deny := spreadPrefixes(netip.MustParseAddr("100.64.0.0"), 5000)
	allow := spreadPrefixes(netip.MustParseAddr("100.66.0.1"), 5000)
	plan := buildTestPlan(t, []proto.Rule{
		{ID: "r_a", Agent: "home", Proto: proto.UDP, ListenPort: pr(2456, 2456), Target: "192.168.1.20:2456",
			VPSMode: proto.ModeKernel, Enabled: true, SourceDeny: deny, SourceAllow: allow},
		{ID: "r_b", Agent: "home", Proto: proto.TCP, ListenPort: pr(25565, 25565), Target: "192.168.1.22:25565",
			VPSMode: proto.ModeKernel, Enabled: true, SourceDeny: allow},
	}, testAgentAddr, policy.AdmissionLimits{})
	newSet := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSET)
	newSetElem := netlink.HeaderType(unix.NFNL_SUBSYS_NFTABLES<<8 | unix.NFT_MSG_NEWSETELEM)
	declared := map[string]int{} // set の名前 → 宣言の通の位置
	chunks := map[string]int{}   // set の名前 → 要素の通の数
	var problems []string
	conn, err := nftables.New(nftables.WithTestDial(func(req []netlink.Message) ([]netlink.Message, error) {
		for i, m := range req {
			if m.Header.Type != newSet && m.Header.Type != newSetElem {
				continue
			}
			ad, err := netlink.NewAttributeDecoder(m.Data[4:])
			if err != nil {
				return nil, err
			}
			name := ""
			for ad.Next() {
				// NFTA_SET_NAME と NFTA_SET_ELEM_LIST_SET はどちらも 2 番の属性である
				if ad.Type() == unix.NFTA_SET_NAME {
					name = ad.String()
				}
			}
			if m.Header.Type == newSet {
				if _, dup := declared[name]; dup {
					problems = append(problems, fmt.Sprintf("set %s is declared twice", name))
				}
				declared[name] = i
				continue
			}
			at, ok := declared[name]
			if !ok || at > i {
				problems = append(problems, fmt.Sprintf("elements of set %s at message %d come before its declaration", name, i))
			}
			chunks[name]++
		}
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := emit(conn, plan, nil, testCfg); err != nil {
		t.Fatal(err)
	}
	if err := conn.Flush(); err != nil {
		t.Fatal(err)
	}
	for _, p := range problems {
		t.Error(p)
	}
	if len(chunks) != 3 {
		t.Errorf("element messages for the sets %v, want the three source lists", chunks)
	}
	for name, n := range chunks {
		if n < 2 {
			t.Errorf("set %s: %d element messages, want its 10001 elements split into several", name, n)
		}
	}
}

// verifySets は、読み直した set が送った要素と同じなら何も返さず、欠けた要素、空の set、
// 違う要素、読めない set を set の名前とともに誤りとして返す。
func TestVerifySets(t *testing.T) {
	deny := intervalElements(spreadPrefixes(netip.MustParseAddr("100.64.0.0"), 1700))
	allow := intervalElements([]netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")})
	sent := map[string][]nftables.SetElement{"deny_1": deny, "allow_2": allow}
	reversed := slices.Clone(deny)
	slices.Reverse(reversed)
	other := slices.Clone(allow)
	other[1] = nftables.SetElement{Key: []byte{198, 51, 101, 0}}

	for _, tc := range []struct {
		name string
		held map[string][]nftables.SetElement
		fail map[string]error
		want string // "" は誤りが無いこと
	}{
		{"same elements in another order", map[string][]nftables.SetElement{"deny_1": reversed, "allow_2": allow}, nil, ""},
		{"elements missing", map[string][]nftables.SetElement{"deny_1": deny[:125], "allow_2": allow}, nil,
			fmt.Sprintf("set deny_1 holds 125 set elements, but %d were sent", len(deny))},
		{"an empty set", map[string][]nftables.SetElement{"deny_1": deny, "allow_2": nil}, nil,
			"set allow_2 holds 0 set elements, but 3 were sent"},
		{"other elements", map[string][]nftables.SetElement{"deny_1": deny, "allow_2": other}, nil,
			"set allow_2 holds 3 set elements, but not the ones sent"},
		{"an interval end read as a start", map[string][]nftables.SetElement{"deny_1": deny,
			"allow_2": {allow[0], allow[1], {Key: allow[2].Key}}}, nil, "set allow_2 holds 3 set elements, but not the ones sent"},
		{"a set that cannot be read", map[string][]nftables.SetElement{"allow_2": allow},
			map[string]error{"deny_1": errors.New("no such file or directory")}, "set deny_1 cannot be read back: no such file or directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := verifySets(sent, func(name string) ([]nftables.SetElement, error) {
				if e := tc.fail[name]; e != nil {
					return nil, e
				}
				return tc.held[name], nil
			})
			if tc.want == "" {
				if err != nil {
					t.Fatalf("verifySets: %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "table inet wgft was replaced") {
				t.Fatalf("verifySets: %v, want an error naming %q", err, tc.want)
			}
		})
	}
}

// Flush は送った後に set を読み直し、カーネルが要素を欠いていれば、送信が成功していても誤りを返す
// (kernel backend では Commit の失敗、すなわち backend 全体の失敗になる。設計文書 6.1 節、7a.3 節)。
// 比べる相手は、組み立てのときに実際に送った要素である。
func TestFlushFailsWhenTheKernelDropsElements(t *testing.T) {
	deny := spreadPrefixes(netip.MustParseAddr("100.64.0.0"), 1700)
	allow := spreadPrefixes(netip.MustParseAddr("100.66.0.1"), 10)
	plan := buildTestPlan(t, []proto.Rule{{ID: "r_big", Agent: "home", Proto: proto.TCP, ListenPort: pr(25565, 25565),
		Target: "192.168.1.22:25565", VPSMode: proto.ModeKernel, Enabled: true, SourceDeny: deny, SourceAllow: allow}},
		testAgentAddr, policy.AdmissionLimits{})
	for _, tc := range []struct {
		name string
		keep func(name string, els []nftables.SetElement) []nftables.SetElement
		want string
	}{
		{"all kept", func(_ string, els []nftables.SetElement) []nftables.SetElement { return els }, ""},
		{"deny truncated", func(name string, els []nftables.SetElement) []nftables.SetElement {
			if name == "deny_1" {
				return els[:62]
			}
			return els
		}, fmt.Sprintf("set deny_1 holds 62 set elements, but %d were sent", len(intervalElements(deny)))},
		{"allow emptied", func(name string, els []nftables.SetElement) []nftables.SetElement {
			if name == "allow_1" {
				return nil
			}
			return els
		}, fmt.Sprintf("set allow_1 holds 0 set elements, but %d were sent", len(intervalElements(allow)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// カーネルが受け取った要素を、送った通ごとに記録する
			held := map[string][]nftables.SetElement{}
			conn, err := nftables.New(nftables.WithTestDial(func([]netlink.Message) ([]netlink.Message, error) { return nil, nil }))
			if err != nil {
				t.Fatal(err)
			}
			s := &Staged{}
			s.readSet = func(name string) ([]nftables.SetElement, error) {
				if _, ok := held[name]; !ok {
					return nil, fmt.Errorf("set %s does not exist", name)
				}
				return tc.keep(name, held[name]), nil
			}
			if err := s.build(conn, plan, nil, testCfg); err != nil {
				t.Fatal(err)
			}
			// 組み立てた要素をそのまま受け取ったカーネル(recorder で同じ plan を組み立て直す)
			rec := newRecorder()
			if err := emit(rec, plan, nil, testCfg); err != nil {
				t.Fatal(err)
			}
			for name, els := range rec.sets {
				if strings.HasPrefix(name, "deny_") || strings.HasPrefix(name, "allow_") {
					held[name] = els
				}
			}
			if len(s.sent) != 2 {
				t.Fatalf("Stage recorded the sets %v, want deny_1 and allow_1 only", keysOf(s.sent))
			}
			err = s.Flush()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Flush: %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Flush: %v, want an error naming %q", err, tc.want)
			}
		})
	}
}

func keysOf(m map[string][]nftables.SetElement) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}
