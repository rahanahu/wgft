//go:build lab

package check

// ラボの vps ns で root として実行する(lab/lab test internal/vpsd/check)。
// iptables-nft(Docker 風)とネイティブ nft(firewalld 風)の疑似環境を自分で作って検査する。

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/proto"
)

func run(t *testing.T, cmd ...string) {
	t.Helper()
	if out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput(); err != nil {
		t.Fatalf("%v: %v\n%s", cmd, err, out)
	}
}

func TestInspectSynthetic(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	for _, b := range []string{"iptables", "nft", "socat"} {
		if _, err := exec.LookPath(b); err != nil {
			t.Skipf("%s がない", b)
		}
	}
	cleanup := func() {
		exec.Command("iptables", "-P", "FORWARD", "ACCEPT").Run()
		exec.Command("iptables", "-P", "INPUT", "ACCEPT").Run()
		exec.Command("iptables", "-F").Run()
		exec.Command("iptables", "-X").Run()
		exec.Command("iptables", "-t", "nat", "-F").Run()
		exec.Command("nft", "delete", "table", "inet", "labfw").Run()
	}
	cleanup()
	t.Cleanup(cleanup)

	run(t, "iptables", "-N", "DOCKER-USER")
	run(t, "iptables", "-P", "FORWARD", "DROP")
	run(t, "iptables", "-A", "FORWARD", "-j", "DOCKER-USER")
	run(t, "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "udp", "--dport", "7777", "-j", "DNAT", "--to-destination", "192.0.2.9")
	run(t, "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp", "--dport", "8000:8010", "-j", "DNAT", "--to-destination", "192.0.2.9:80")
	run(t, "iptables", "-P", "INPUT", "DROP")
	run(t, "iptables", "-A", "INPUT", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	c := exec.Command("nft", "-f", "-")
	c.Stdin = strings.NewReader(`table inet labfw {
  chain filter_FORWARD {
    type filter hook forward priority filter + 10; policy accept;
    ct state { established, related } accept
    reject with icmpx admin-prohibited
  }
  chain filter_INPUT {
    type filter hook input priority filter + 10; policy accept;
    ct state { established, related } accept
    reject with icmpx admin-prohibited
  }
  chain nat_PREROUTING {
    type nat hook prerouting priority dstnat + 10; policy accept;
    tcp dport 9090 dnat ip to 192.0.2.10
    udp dport { 6000, 6001 } dnat ip to 192.0.2.11
  }
}
`)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v\n%s", err, out)
	}

	rep, err := Inspect("wg0")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range rep.Findings {
		t.Logf("finding: %s", f)
	}
	for _, d := range rep.DNATs {
		t.Logf("dnat: %+v", d)
	}
	want := map[string]string{
		"ip filter FORWARD":         "iptables -I DOCKER-USER -o wg0 -j ACCEPT",
		"inet labfw filter_FORWARD": `nft insert rule inet labfw filter_FORWARD oifname "wg0" accept`,
	}
	for where, sug := range want {
		found := false
		for _, f := range rep.Findings {
			if f.Where == where {
				found = true
				if f.Suggest[0] != sug {
					t.Errorf("%s: suggest %q, want %q", where, f.Suggest[0], sug)
				}
			}
		}
		if !found {
			t.Errorf("no finding for %s", where)
		}
	}
	// input は両方とも established の accept を持つので警告しない
	for _, f := range rep.Findings {
		if strings.Contains(f.Where, "INPUT") {
			t.Errorf("unexpected input finding: %s", f)
		}
	}
	expectDNAT := []struct {
		p      proto.Proto
		lo, hi uint16
	}{{proto.UDP, 7777, 7777}, {proto.TCP, 8000, 8010}, {proto.TCP, 9090, 9090}, {proto.UDP, 6000, 6001}}
	for _, e := range expectDNAT {
		if c := rep.DNATConflicts(e.p, proto.PortRange{Lo: e.lo, Hi: e.hi}); len(c) == 0 {
			t.Errorf("DNAT %s/%d-%d not detected", e.p, e.lo, e.hi)
		}
	}
	if c := rep.DNATConflicts(proto.UDP, proto.PortRange{Lo: 2456, Hi: 2457}); len(c) != 0 {
		t.Errorf("unexpected conflict for 2456-2457: %+v", c)
	}

	// bind 中のポート:0.0.0.0:2222/tcp は衝突、127.0.0.1:3333/tcp は除外
	for _, l := range [][]string{{"TCP4-LISTEN:2222,fork,reuseaddr"}, {"TCP4-LISTEN:3333,bind=127.0.0.1,fork,reuseaddr"}} {
		cmd := exec.Command("socat", l[0], "SYSTEM:true")
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cmd.Process.Kill() })
	}
	// socat の bind は非同期なので、/proc/net/tcp に現れるまで最大 2 秒待つ(起動直後に読むと競合する)
	var bound Bound
	deadline := time.Now().Add(2 * time.Second)
	for {
		var err error
		bound, err = BoundPorts()
		if err != nil {
			t.Fatal(err)
		}
		if len(bound.Conflicts(proto.TCP, proto.PortRange{Lo: 2222, Hi: 2222})) == 1 || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if len(bound.Conflicts(proto.TCP, proto.PortRange{Lo: 2222, Hi: 2222})) != 1 {
		t.Errorf("0.0.0.0:2222 not detected: %v", bound[proto.TCP])
	}
	if len(bound.Conflicts(proto.TCP, proto.PortRange{Lo: 3333, Hi: 3333})) != 0 {
		t.Errorf("loopback 3333 should be excluded: %v", bound[proto.TCP])
	}
}
