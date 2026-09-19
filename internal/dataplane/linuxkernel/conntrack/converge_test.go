package conntrack

import (
	"net/netip"
	"testing"

	"github.com/ti-mo/conntrack"

	"github.com/rahanahu/wgft/proto"
)

// fakeConn は Dump を固定で返し、Delete されたフローを記録する。
type fakeConn struct {
	flows   []conntrack.Flow
	deleted []conntrack.Flow
}

func (c *fakeConn) Dump(*conntrack.DumpOptions) ([]conntrack.Flow, error) { return c.flows, nil }
func (c *fakeConn) Delete(f conntrack.Flow) error {
	c.deleted = append(c.deleted, f)
	return nil
}

// flow は orig src:sport -> dst:dport、reply src(DNAT 先)を持つ Flow を組む。dnat=true で DNAT フラグ。
func flow(protoNum uint8, src string, sport uint16, dst string, dport uint16, replySrc string, dnat bool) conntrack.Flow {
	f := conntrack.Flow{}
	f.TupleOrig.IP.SourceAddress = netip.MustParseAddr(src)
	f.TupleOrig.IP.DestinationAddress = netip.MustParseAddr(dst)
	f.TupleOrig.Proto.Protocol = protoNum
	f.TupleOrig.Proto.SourcePort = sport
	f.TupleOrig.Proto.DestinationPort = dport
	f.TupleReply.IP.SourceAddress = netip.MustParseAddr(replySrc)
	if dnat {
		f.Status |= conntrack.StatusDstNAT
	}
	return f
}

var wgNet = netip.MustParsePrefix("10.200.0.0/24")

func TestConverge(t *testing.T) {
	home := netip.MustParseAddr("10.200.0.2")
	office := netip.MustParseAddr("10.200.0.3")
	rules := []Rule{
		{Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 2456, Hi: 2457}, AgentAddr: home,
			SourceDeny: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		{Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, AgentAddr: office,
			SourceAllow: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}},
	}

	tests := []struct {
		name       string
		flow       conntrack.Flow
		wantDelete bool
	}{
		{"許可された UDP フロー", flow(17, "198.51.100.2", 5000, "198.51.100.1", 2456, "10.200.0.2", true), false},
		{"deny に該当する UDP", flow(17, "203.0.113.9", 5000, "198.51.100.1", 2456, "10.200.0.2", true), true},
		{"ルールのない宛先ポート", flow(17, "198.51.100.2", 5000, "198.51.100.1", 9999, "10.200.0.2", true), true},
		{"agent が変わった(reply 先が違う)", flow(17, "198.51.100.2", 5000, "198.51.100.1", 2456, "10.200.0.99", true), true},
		{"TCP 許可(allow 内)", flow(6, "198.51.100.2", 5000, "198.51.100.1", 25565, "10.200.0.3", true), false},
		{"TCP allow 外", flow(6, "192.0.2.9", 5000, "198.51.100.1", 25565, "10.200.0.3", true), true},
		{"DNAT でないフローは対象外(消さない)", flow(17, "198.51.100.2", 5000, "203.0.113.5", 2456, "203.0.113.5", false), false},
		{"vpsd 起点(orig 宛先が wg 帯の中)は対象外", flow(6, "10.200.0.1", 5000, "10.200.0.2", 25565, "10.200.0.2", true), false},
		{"proto 違い(同じポートの TCP を UDP ルールが拾わない)", flow(6, "198.51.100.2", 5000, "198.51.100.1", 2456, "10.200.0.2", true), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &fakeConn{flows: []conntrack.Flow{tt.flow}}
			n, err := converge(c, rules, wgNet)
			if err != nil {
				t.Fatal(err)
			}
			if tt.wantDelete && (n != 1 || len(c.deleted) != 1) {
				t.Errorf("want delete, got n=%d deleted=%d", n, len(c.deleted))
			}
			if !tt.wantDelete && (n != 0 || len(c.deleted) != 0) {
				t.Errorf("want keep, got n=%d deleted=%d", n, len(c.deleted))
			}
		})
	}
}

// ルールが空(全ルール削除・全エージェント無効化)なら、対象フローはすべて消える。
func TestConvergeNoRules(t *testing.T) {
	c := &fakeConn{flows: []conntrack.Flow{
		flow(17, "198.51.100.2", 5000, "198.51.100.1", 2456, "10.200.0.2", true),
		flow(6, "10.200.0.1", 5000, "10.200.0.2", 25565, "10.200.0.2", true), // vpsd 起点は残る
	}}
	n, err := converge(c, nil, wgNet)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("deleted = %d, want 1(転送フローだけ消え、vpsd 起点は残る)", n)
	}
}
