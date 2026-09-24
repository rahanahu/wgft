//go:build lab && linux

package conntrack

// エージェントの conntrack の収束のラボのテスト。ラボの vps ns で root として実行する
// (lab/lab test internal/dataplane/linuxkernel/conntrack vps -test.run TestAgentConvergeLab)。
// VPS の側(peer)、エージェントのホスト(agent)、LAN のホスト(lan)の 3 つの network namespace を作り、
// peer と agent の間の veth の agent の側を wgft0 と名付けてトンネルに見立てる。

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/proto"
)

const (
	ctNSPeer  = "wgk5peer"
	ctNSAgent = "wgk5agent"
	ctNSLAN   = "wgk5lan"
)

// ctLabStep は、agent の namespace で動かし直したテストの実行ファイルに渡す 1 手である。
type ctLabStep struct {
	Apply    *nft.AgentPublication  `json:"apply,omitempty"`
	Prev     []nft.AgentPublication `json:"prev,omitempty"`
	Converge *nft.AgentPublication  `json:"converge,omitempty"`
}

// TestAgentConntrackLabHelper は、別の network namespace の中で表を公開するか収束させるために、
// テストの実行ファイルをその namespace で起動し直したときにだけ動く。
func TestAgentConntrackLabHelper(t *testing.T) {
	spec := os.Getenv("WGFT_AGENT_CT_LAB")
	if spec == "" {
		t.Skip("only run by the other lab tests")
	}
	var step ctLabStep
	if err := json.Unmarshal([]byte(spec), &step); err != nil {
		t.Fatal(err)
	}
	if step.Apply != nil {
		if err := nft.ApplyAgent(*step.Apply, nft.AgentConfig{WGInterface: "wgft0"}); err != nil {
			t.Fatal(err)
		}
	}
	if step.Converge != nil {
		res, err := ConvergeAgent(step.Prev, *step.Converge, AgentScope{
			Local: netip.MustParseAddr("10.200.0.2"),
			Peer:  netip.MustParseAddr("10.200.0.1"),
		})
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(res)
		fmt.Printf("RESULT %s\n", b)
	}
}

type ctLab struct {
	t     *testing.T
	procs []*exec.Cmd
}

func (l *ctLab) run(args ...string) {
	l.t.Helper()
	if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
		l.t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func (l *ctLab) in(ns string, args ...string) {
	l.t.Helper()
	l.run(append([]string{"ip", "netns", "exec", ns}, args...)...)
}

func (l *ctLab) start(ns string, args ...string) {
	l.t.Helper()
	cmd := exec.Command("ip", append([]string{"netns", "exec", ns}, args...)...)
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.procs = append(l.procs, cmd)
}

func newCtLab(t *testing.T) *ctLab {
	for _, tool := range []string{"ip", "nft", "socat", "python3"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s がない", tool)
		}
	}
	l := &ctLab{t: t}
	t.Cleanup(func() {
		for _, p := range l.procs {
			if p.Process != nil {
				p.Process.Kill()
				p.Wait()
			}
		}
		for _, ns := range []string{ctNSPeer, ctNSAgent, ctNSLAN} {
			exec.Command("ip", "netns", "del", ns).Run()
		}
	})
	for _, ns := range []string{ctNSPeer, ctNSAgent, ctNSLAN} {
		exec.Command("ip", "netns", "del", ns).Run()
		l.run("ip", "netns", "add", ns)
		l.in(ns, "ip", "link", "set", "lo", "up")
	}
	l.run("ip", "link", "add", "wgk5p0", "netns", ctNSPeer, "type", "veth", "peer", "name", "wgft0", "netns", ctNSAgent)
	l.run("ip", "link", "add", "wgk5l0", "netns", ctNSAgent, "type", "veth", "peer", "name", "wgk5l1", "netns", ctNSLAN)
	l.in(ctNSPeer, "ip", "addr", "add", "10.200.0.1/24", "dev", "wgk5p0")
	l.in(ctNSPeer, "ip", "link", "set", "wgk5p0", "up")
	l.in(ctNSAgent, "ip", "addr", "add", "10.200.0.2/24", "dev", "wgft0")
	l.in(ctNSAgent, "ip", "link", "set", "wgft0", "up")
	l.in(ctNSAgent, "ip", "addr", "add", "192.168.62.1/24", "dev", "wgk5l0")
	l.in(ctNSAgent, "ip", "link", "set", "wgk5l0", "up")
	l.in(ctNSLAN, "ip", "addr", "add", "192.168.62.2/24", "dev", "wgk5l1")
	l.in(ctNSLAN, "ip", "addr", "add", "192.168.62.3/24", "dev", "wgk5l1")
	l.in(ctNSLAN, "ip", "link", "set", "wgk5l1", "up")
	// LAN のホストの既定の経路はエージェントのホストを向く。Docker のコンテナと同じく、他のテーブルの
	// DNAT の返りがエージェントのホストを通る
	l.in(ctNSLAN, "ip", "route", "add", "default", "via", "192.168.62.1")
	l.in(ctNSAgent, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	return l
}

// step は agent の namespace でテストの実行ファイルを動かし直し、1 手を行う。収束の結果を返す。
func (l *ctLab) step(s ctLabStep) AgentResult {
	l.t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		l.t.Fatal(err)
	}
	cmd := exec.Command("ip", "netns", "exec", ctNSAgent, os.Args[0], "-test.run=^TestAgentConntrackLabHelper$")
	cmd.Env = append(os.Environ(), "WGFT_AGENT_CT_LAB="+string(b))
	out, err := cmd.CombinedOutput()
	if err != nil {
		l.t.Fatalf("step in %s: %v\n%s", ctNSAgent, err, out)
	}
	var res AgentResult
	for _, line := range strings.Split(string(out), "\n") {
		if j, ok := strings.CutPrefix(line, "RESULT "); ok {
			if err := json.Unmarshal([]byte(j), &res); err != nil {
				l.t.Fatal(err)
			}
		}
	}
	return res
}

// ctClient は長く続くフローである。1 行を送って返りを読み、以後は合図の行ごとにその行を送って返りを読む。
type ctClient struct {
	name  string
	stdin io.WriteCloser
	lines *bufio.Scanner
}

const ctClientScript = `import socket, sys
kind, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
if kind == "tcp":
    s = socket.create_connection((host, port), timeout=3)
else:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3)
    s.connect((host, port))
def echo(word):
    try:
        s.send(word.encode() + b"\n")
        print(s.recv(100).decode().strip(), flush=True)
    except Exception as e:
        print("ERR " + type(e).__name__, flush=True)
echo("one")
for line in sys.stdin:
    echo(line.strip())
`

// open は ns から addr へのフローを始め、最初の 1 行が返ることを確かめる。
func (l *ctLab) open(name, ns, kind, addr string) *ctClient {
	l.t.Helper()
	host, port, _ := strings.Cut(addr, ":")
	cmd := exec.Command("ip", "netns", "exec", ns, "python3", "-c", ctClientScript, kind, host, port)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		l.t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		l.t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		l.t.Fatal(err)
	}
	l.procs = append(l.procs, cmd)
	c := &ctClient{name: name, stdin: stdin, lines: bufio.NewScanner(stdout)}
	if !c.lines.Scan() || c.lines.Text() != "one" {
		l.t.Fatalf("%s: the flow did not start: %q", name, c.lines.Text())
	}
	return c
}

// alive は、フローに word を送って同じ行が返るかどうかである。
func (c *ctClient) alive(word string) (bool, string) {
	io.WriteString(c.stdin, word+"\n")
	if !c.lines.Scan() {
		return false, "no output"
	}
	return c.lines.Text() == word, c.lines.Text()
}

// 公開を変えた後の収束は、宛先を変えたポートと宣言から消えたポートのフローを消し、変わらないポート、
// 名前の解決だけが変わったポート、他のテーブルが DNAT したフロー、エージェントのホスト自身の接続を残す。
func TestAgentConvergeLab(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root が必要")
	}
	l := newCtLab(t)
	for _, port := range []string{"80", "25565", "25566", "25567", "25568"} {
		l.start(ctNSLAN, "socat", "TCP-LISTEN:"+port+",fork,reuseaddr", "EXEC:cat")
	}
	l.start(ctNSLAN, "python3", "-c", `import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 5000))
while True:
    b, a = s.recvfrom(100)
    s.sendto(b, a)`)
	l.start(ctNSPeer, "socat", "TCP-LISTEN:9999,fork,reuseaddr", "EXEC:cat")
	// Docker の `-p` と同じく、ホストのすべてのアドレスの 8080 と 25567 を LAN のコンテナに見立てた 80 へ DNAT する
	cmd := exec.Command("ip", "netns", "exec", ctNSAgent, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(`table ip dockerlike {
  chain pre {
    type nat hook prerouting priority dstnat; policy accept;
    fib daddr type local tcp dport { 8080, 25567 } dnat to 192.168.62.2:80
  }
}
`)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("nft -f: %v\n%s", err, out)
	}
	time.Sleep(300 * time.Millisecond) // 待ち受けを待つ

	// wgft の表がまだ無い間に、他のテーブルの DNAT のフローが wgft0 から入る。25567 は後で wgft が宣言するポートである
	foreign := l.open("foreign 8080", ctNSPeer, "tcp", "10.200.0.2:8080")
	foreignSame := l.open("foreign on wgft's 25567", ctNSPeer, "tcp", "10.200.0.2:25567")

	keep := proto.AgentRule{ID: "r_keep", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25565, Hi: 25565}, Target: "192.168.62.2:25565", Enabled: true}
	move := proto.AgentRule{ID: "r_move", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25566, Hi: 25566}, Target: "192.168.62.2:25566", Enabled: true}
	gone := proto.AgentRule{ID: "r_gone", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25567, Hi: 25567}, Target: "192.168.62.2:25567", Enabled: true}
	dns := proto.AgentRule{ID: "r_dns", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: 25568, Hi: 25568}, Target: "svc.lan:25568", Enabled: true}
	udp := proto.AgentRule{ID: "r_udp", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: 5000, Hi: 5000}, Target: "192.168.62.2:5000", Enabled: true}
	resolved := func(addr string) map[string]nft.Resolution {
		return map[string]nft.Resolution{"svc.lan": {Addrs: []netip.Addr{netip.MustParseAddr(addr)}}}
	}
	cfg := nft.AgentConfig{WGInterface: "wgft0"}
	gen1 := nft.PlanAgent(nft.AgentInput{Generation: 1, Rules: []proto.AgentRule{keep, move, gone, dns, udp}, Resolved: resolved("192.168.62.2")}, cfg)
	l.step(ctLabStep{Apply: &gen1})

	flowKeep := l.open("unchanged rule", ctNSPeer, "tcp", "10.200.0.2:25565")
	flowMove := l.open("retargeted rule", ctNSPeer, "tcp", "10.200.0.2:25566")
	flowGone := l.open("deleted rule", ctNSPeer, "tcp", "10.200.0.2:25567")
	flowDNS := l.open("re-resolved rule", ctNSPeer, "tcp", "10.200.0.2:25568")
	flowUDP := l.open("disabled UDP rule", ctNSPeer, "udp", "10.200.0.2:5000")
	own := l.open("the agent host's own connection", ctNSAgent, "tcp", "10.200.0.1:9999")

	move2 := move
	move2.Target = "192.168.62.3:25566"
	udp2 := udp
	udp2.Enabled = false
	gen2 := nft.PlanAgent(nft.AgentInput{Generation: 2, Rules: []proto.AgentRule{keep, move2, dns, udp2}, Resolved: resolved("192.168.62.3")}, cfg)
	l.step(ctLabStep{Apply: &gen2})
	// テーブルの差し替えだけでは成立済みのフローは切れない。切るのは収束である
	for _, c := range []*ctClient{flowMove, flowGone, flowUDP} {
		if ok, line := c.alive("before"); !ok {
			t.Fatalf("%s: the flow ended with the table swap alone (%q); the test proves nothing", c.name, line)
		}
	}
	res := l.step(ctLabStep{Prev: []nft.AgentPublication{gen1}, Converge: &gen2})
	t.Logf("convergence: %s", res)
	if want := (AgentResult{Kept: 2, Removed: 2, Retargeted: 1}); res != want {
		t.Errorf("result = %+v, want %+v", res, want)
	}
	// 2 回目は何も消さない
	if again := l.step(ctLabStep{Prev: []nft.AgentPublication{gen2}, Converge: &gen2}); again.Deleted() != 0 || again.Failed != 0 {
		t.Errorf("second convergence = %+v, want nothing closed", again)
	}

	for _, tc := range []struct {
		c    *ctClient
		want bool
	}{
		{flowKeep, true},
		{flowDNS, true},
		{foreign, true},
		{foreignSame, true},
		{own, true},
		{flowMove, false},
		{flowGone, false},
		{flowUDP, false},
	} {
		got, line := tc.c.alive("after")
		t.Logf("%s: %q", tc.c.name, line)
		if got != tc.want {
			t.Errorf("%s: alive = %v (%q), want %v", tc.c.name, got, line, tc.want)
		}
	}
}
