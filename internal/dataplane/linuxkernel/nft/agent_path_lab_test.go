//go:build lab && linux

package nft

// エージェントの表の、大きな範囲の読み込みと、wgft0 から届く面のラボのテスト。ラボの vps ns で root として
// 実行する(lab/lab test internal/dataplane/linuxkernel/nft)。

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/google/nftables"

	"github.com/rahanahu/wgft/proto"
)

// 何千ものポートを持つ範囲と全幅の範囲も、map の要素が欠けずに入り、他のルールの公開も進む。
// google/nftables v0.3.0 に要素を 1 通で渡すと、8,001 ポートでは先頭の 1,857 個だけが黙って入り、
// 60,000 ポートではバッチ全体が拒まれた。
func TestAgentLargeRanges(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	t.Cleanup(func() { exec.Command("nft", "delete", "table", "inet", AgentTableName).Run() })
	cfg := AgentConfig{WGInterface: "wgft0"}
	for _, tc := range []struct {
		name   string
		lo, hi uint16
	}{
		{"8001 ports", 20000, 28000},
		{"60000 ports", 2000, 61999},
		{"full width", 1, 65535},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := []proto.AgentRule{
				{ID: "r_wide", Proto: proto.UDP, ListenPort: pr(tc.lo, tc.hi), Target: "192.168.1.20:1", Enabled: true},
				{ID: "r_tcp", Proto: proto.TCP, ListenPort: pr(25565, 25565), Target: "192.168.1.22:25565", Enabled: true},
			}
			if tc.hi < 65535 {
				rules[0].Target = fmt.Sprintf("192.168.1.20:%d", tc.lo)
			}
			pub := PlanAgent(AgentInput{Generation: 1, Rules: rules}, cfg)
			start := time.Now()
			if err := ApplyAgent(pub, cfg); err != nil {
				t.Fatalf("ApplyAgent: %v", err)
			}
			t.Logf("applied %d ports in %v", int(tc.hi)-int(tc.lo)+1, time.Since(start))
			// map の要素を直接数える
			c, err := nftables.New()
			if err != nil {
				t.Fatal(err)
			}
			tbl := &nftables.Table{Family: nftables.TableFamilyINet, Name: AgentTableName}
			sets, err := c.GetSets(tbl)
			if err != nil || len(sets) != 1 {
				t.Fatalf("GetSets = %d sets, %v; want the one map", len(sets), err)
			}
			els, err := c.GetSetElements(sets[0])
			if want := int(tc.hi) - int(tc.lo) + 1; err != nil || len(els) != want {
				t.Fatalf("map %s holds %d elements, %v; want %d", sets[0].Name, len(els), err, want)
			}
			ins, _, err := InspectAgent(pub, cfg.WGInterface)
			if err != nil || !ins.Matches() {
				t.Errorf("InspectAgent = %+v, %v; want the table to match its record", ins, err)
			}
		})
	}
}

// TestAgentHelperApply は、別の network namespace の中で表を公開するために、テストの実行ファイルを
// その namespace で起動し直したときにだけ動く。公開の記録は環境変数で受け取る。
func TestAgentHelperApply(t *testing.T) {
	spec := os.Getenv("WGFT_AGENT_LAB_APPLY")
	if spec == "" {
		t.Skip("only run by the other lab tests")
	}
	var pub AgentPublication
	if err := json.Unmarshal([]byte(spec), &pub); err != nil {
		t.Fatal(err)
	}
	if err := ApplyAgent(pub, AgentConfig{WGInterface: "wgft0"}); err != nil {
		t.Fatal(err)
	}
}

// labTopo は、VPS の側(peer)、エージェントのホスト(agent)、LAN のホスト(lan)の 3 つの network namespace
// である。peer と agent の間の veth の agent の側を wgft0 と名付けて、トンネルに見立てる。
type labTopo struct {
	t     *testing.T
	procs []*exec.Cmd
}

const (
	nsPeer  = "wgk4peer"
	nsAgent = "wgk4agent"
	nsLAN   = "wgk4lan"
)

func (l *labTopo) run(args ...string) {
	l.t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		l.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func (l *labTopo) in(ns string, args ...string) {
	l.t.Helper()
	l.run(append([]string{"ip", "netns", "exec", ns}, args...)...)
}

// start は ns の中でプロセスを起動し、テストの終わりに止める。
func (l *labTopo) start(ns string, args ...string) *exec.Cmd {
	l.t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.procs = append(l.procs, cmd)
	return cmd
}

func newLabTopo(t *testing.T) *labTopo {
	for _, tool := range []string{"ip", "socat", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s がない", tool)
		}
	}
	l := &labTopo{t: t}
	t.Cleanup(func() {
		for _, p := range l.procs {
			if p.Process != nil {
				p.Process.Kill()
				p.Wait()
			}
		}
		for _, ns := range []string{nsPeer, nsAgent, nsLAN} {
			exec.Command("ip", "netns", "del", ns).Run()
		}
	})
	for _, ns := range []string{nsPeer, nsAgent, nsLAN} {
		exec.Command("ip", "netns", "del", ns).Run()
		l.run("ip", "netns", "add", ns)
		l.in(ns, "ip", "link", "set", "lo", "up")
	}
	l.run("ip", "link", "add", "wgk4p0", "netns", nsPeer, "type", "veth", "peer", "name", "wgft0", "netns", nsAgent)
	l.run("ip", "link", "add", "wgk4l0", "netns", nsAgent, "type", "veth", "peer", "name", "wgk4l1", "netns", nsLAN)
	l.in(nsPeer, "ip", "addr", "add", "10.200.0.1/24", "dev", "wgk4p0")
	l.in(nsPeer, "ip", "link", "set", "wgk4p0", "up")
	l.in(nsAgent, "ip", "addr", "add", "10.200.0.2/24", "dev", "wgft0")
	l.in(nsAgent, "ip", "link", "set", "wgft0", "mtu", "1420", "up")
	l.in(nsAgent, "ip", "addr", "add", "192.168.61.1/24", "dev", "wgk4l0")
	l.in(nsAgent, "ip", "link", "set", "wgk4l0", "up")
	l.in(nsLAN, "ip", "addr", "add", "192.168.61.2/24", "dev", "wgk4l1")
	l.in(nsLAN, "ip", "link", "set", "wgk4l1", "up")
	// LAN のホストの既定の経路はエージェントのホストを向く。Docker のコンテナと同じく、他のテーブルの
	// DNAT の返りがエージェントのホストを通る
	l.in(nsLAN, "ip", "route", "add", "default", "via", "192.168.61.1")
	l.in(nsAgent, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	return l
}

// apply は agent の namespace で表を公開する。
func (l *labTopo) apply(pub AgentPublication) {
	l.t.Helper()
	b, err := json.Marshal(pub)
	if err != nil {
		l.t.Fatal(err)
	}
	cmd := exec.Command("ip", "netns", "exec", nsAgent, os.Args[0], "-test.run=^TestAgentHelperApply$")
	cmd.Env = append(os.Environ(), "WGFT_AGENT_LAB_APPLY="+string(b))
	if out, err := cmd.CombinedOutput(); err != nil {
		l.t.Fatalf("applying in %s: %v\n%s", nsAgent, err, out)
	}
}

// reach は peer から addr へ TCP で繋ぎ、1 行を送って同じ行が返るかどうかである。
func (l *labTopo) reach(addr string) bool { return l.reachFrom(nsPeer, addr) }

// reachFrom は ns から addr へ TCP で繋ぎ、1 行を送って同じ行が返るかどうかである。
func (l *labTopo) reachFrom(ns, addr string) bool {
	host, port, _ := strings.Cut(addr, ":")
	script := fmt.Sprintf(`import socket
s = socket.create_connection((%q, %s), timeout=2)
s.sendall(b"ping\n")
print(s.recv(100).decode().strip())`, host, port)
	out, err := exec.Command("ip", "netns", "exec", ns, "python3", "-c", script).CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "ping"
}

// filter_pre は wgft0 から入る新しい接続のうち、公開した (プロトコル, ポート) だけを通す(7b.1 節)。
// 他のテーブルの DNAT(Docker がホストのすべてのアドレスに公開したポート)には wgft0 から届かない。
// 公開したポートには届き、公開が変わっても成立済みのフローは続く。
func TestAgentPrefilterClosesOtherDNAT(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	l := newLabTopo(t)
	// LAN のホストのエコーのサービス:Docker のコンテナに見立てた 80 と、wgft が公開する 25565
	l.start(nsLAN, "socat", "TCP-LISTEN:80,fork,reuseaddr", "EXEC:cat")
	l.start(nsLAN, "socat", "TCP-LISTEN:25565,fork,reuseaddr", "EXEC:cat")
	// VPS の側のサービス。エージェントのホストが wgft0 越しに自分から繋ぐ接続の返りを確かめる
	l.start(nsPeer, "socat", "TCP-LISTEN:9999,fork,reuseaddr", "EXEC:cat")
	// Docker の `-p 8080:80` と同じく、ホストのすべてのアドレスの 8080 をコンテナへ DNAT する
	cmd := exec.Command("ip", "netns", "exec", nsAgent, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(`table ip dockerlike {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    fib daddr type local tcp dport 8080 dnat to 192.168.61.2:80
  }
}
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v\n%s", err, out)
	}
	time.Sleep(300 * time.Millisecond) // socat の待ち受けを待つ

	// wgft の表が無ければ、VPS の側から wgft0 のアドレスの 8080 で Docker のサービスに届く。この穴を塞ぐ
	if !l.reach("10.200.0.2:8080") {
		t.Fatal("baseline: the Docker-like port is not reachable from the peer even without the wgft table; the test proves nothing")
	}

	cfg := AgentConfig{WGInterface: "wgft0"}
	mc := proto.AgentRule{ID: "r_mc", Proto: proto.TCP, ListenPort: pr(25565, 25565), Target: "192.168.61.2:25565", Enabled: true}
	l.apply(PlanAgent(AgentInput{Generation: 1, Rules: []proto.AgentRule{mc}}, cfg))
	if l.reach("10.200.0.2:8080") {
		t.Error("the Docker-like port is reachable from the peer through wgft0 with the wgft table")
	}
	if !l.reach("10.200.0.2:25565") {
		t.Error("the wgft-published port is not reachable from the peer")
	}
	// エージェントのホストが自分から wgft0 越しに繋いだ接続の返りは、公開していないポートに届くが通る
	if !l.reachFrom(nsAgent, "10.200.0.1:9999") {
		t.Error("the replies of a connection the agent host opened over wgft0 are dropped")
	}

	// 成立済みのフローは、公開が変わっても続く
	client := exec.Command("ip", "netns", "exec", nsPeer, "python3", "-c", `import socket, sys
s = socket.create_connection(("10.200.0.2", 25565), timeout=5)
s.sendall(b"one\n"); print(s.recv(100).decode().strip(), flush=True)
sys.stdin.readline()
s.sendall(b"two\n"); print(s.recv(100).decode().strip(), flush=True)`)
	stdin, err := client.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := client.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	client.Stderr = os.Stderr
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	l.procs = append(l.procs, client)
	lines := bufio.NewScanner(stdout)
	if !lines.Scan() || lines.Text() != "one" {
		t.Fatalf("the long-lived flow did not start: %q", lines.Text())
	}
	other := proto.AgentRule{ID: "r_other", Proto: proto.UDP, ListenPort: pr(5000, 5001), Target: "192.168.61.2:5000", Enabled: true}
	l.apply(PlanAgent(AgentInput{Generation: 2, Rules: []proto.AgentRule{mc, other}}, cfg))
	io.WriteString(stdin, "go\n")
	if !lines.Scan() || lines.Text() != "two" {
		t.Errorf("the established flow did not survive the publication change: %q", lines.Text())
	}
	if l.reach("10.200.0.2:8080") {
		t.Error("the Docker-like port is reachable after the publication change")
	}
}
