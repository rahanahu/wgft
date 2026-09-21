package utun

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/policy/goengine"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// TestAgentServerInProcessForwarding は、エージェント側のトンネルと中継 (internal/agent が
// internal/dataplane/userspace/tunnel と internal/dataplane/userspace/relay を組む配線、
// internal/agent/agent.go の runtime.apply を見よ) と、VPS 側のユーザー空間モードの Backend が
// 組む配線 (internal/dataplane/userspace/userspace.go の Backend.New / EnsureDevice / Prepare /
// Commit) を、1 プロセスの中で実 UDP (127.0.0.1) で繋ぎ、TCP と UDP を実際に転送して確かめる。
//
// これは docs/testing.md 「実機の確認を小さな回帰テストに置き換えた範囲」が説明しているテストで、
// Linux (build-test)、macOS の CI runner (B8)、Windows の CI runner (B4) の 3 つで、D1/D2
// (Windows/macOS の実機 smoke) の一部、「転送」と「大きな UDP」を PR ごとに確かめる。
//
// このテストは userspace.Backend という型そのものは呼ばない。Backend は Prepare/Commit の帳簿
// (Plan の差分、fail-closed の記録) をエージェントの持たない形で持つだけで、実際に転送する
// コードは utun.Tunnel、tunnel.Tunnel、relay.Manager、goengine.Engine の 4 つであり (Backend.New
// のコメントと本体を見よ)、Backend 自身に Close が無く 1 プロセスで何度も (-count=3 で) 後始末
// しながら流すテストの土台にならない。そこでこの 4 つを Backend.New / EnsureDevice / Prepare /
// Commit と同じ手順で直接組む。VPS の「公開ポート」は Backend の非公開の hostNetwork
// (net.ListenUDP/net.Listen で全インタフェースに bind する) の代わりに、このテストの
// serverNetwork (127.0.0.1 だけに bind する) を使う。理由は 2 つ。ループバックだけを使うという
// このテストの制約と、VPS 側の実装は Linux でしか動かない (internal/vpsd がその唯一の呼び出し元で、
// カーネルの nftables に依存して Linux 限定) ため、本番では公開ポートが darwin の 9216 バイトの
// 既定送信バッファに当たる場面が無いこと。エージェント側が実際の宛先 (このテストでは echo の
// 対象) へ書き込む中継の dial 用ソケットだけは internal/dataplane/userspace/relay/sndbuf_darwin.go
// の修正の対象で、そちらは一切変えていない (raiseUDPSendBuffer は relay パッケージの非公開関数の
// ままで、この修正が効くかどうかを 12000 バイトのケースで確かめる)。
//
// Windows では newBind() が conn.NewStdNetBind() を使う (bind_windows.go)。wireguard-go の既定の
// WinRingBind では、このテストのエージェント側が受信を止めた (docs/design.md の改訂の記録)。
func TestAgentServerInProcessForwarding(t *testing.T) {
	quiet := func(string, ...any) {}

	// 1. echo の対象 (TCP と UDP)。エージェントの中継が実際に接続する宛先で、実機の LAN の機器の
	// 代わり。ここで SetWriteBuffer を上げるのは、relay/relay_test.go の bigSendBuffer と同じ理由
	// (テスト側の宛先ソケットで、production のコードではない)。
	targetTCPAddr := startTCPEcho(t)
	targetUDPAddr := startUDPEcho(t)

	// goroutine の基準値は、常駐する echo の対象を先に立ててから取る。以後増えた分だけが
	// トンネルと中継のものになる。
	baseline := runtime.NumGoroutine()

	// 2. VPS 側 (userspace の Backend が組むのと同じ 4 つの部品)。
	srvPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate server key: %v", err)
	}
	agentPriv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}
	agentPub := agentPriv.PublicKey()
	serverAddr := netip.MustParseAddr("10.200.0.1")
	agentAddr := netip.MustParseAddr("10.200.0.2")

	srvTun, wgPort := newServerTunnel(t, srvPriv, serverAddr)
	t.Cleanup(srvTun.Close)
	if _, err := srvTun.SetPeers([]dataplane.Peer{{PublicKey: agentPub, Address: agentAddr}}); err != nil {
		t.Fatalf("declare the agent peer: %v", err)
	}

	udpPool := resource.NewPool(1000)
	tcpPool := resource.NewPool(1000)
	policyEngine := goengine.New(nil)
	dialViaTunnel := func(network, addr string) (net.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srvTun.DialContext(ctx, network, addr)
	}
	serverRelay := relay.New(serverNetwork{}, relay.Options{
		UDPIdleTimeout: 30 * time.Second,
		Dial:           dialViaTunnel,
		Logf:           quiet,
		Admit: func(ruleID string, src netip.Addr, size int) (func(), bool) {
			d, tk := policyEngine.AdmitFlow(ruleID, src, size)
			return tk.Release, d.Allow
		},
		AdmitPacket: func(ruleID string, size int) bool { return policyEngine.AdmitPacket(ruleID, size).Allow },
		UDPPool:     udpPool,
		TCPPool:     tcpPool,
	})
	t.Cleanup(serverRelay.Close)

	tcpPort, udpPort, plan := prepareServerRelay(t, serverRelay, agentAddr)
	policyEngine.Update(plan.Admission)

	tcpAddr := fmt.Sprintf("127.0.0.1:%d", tcpPort)
	udpAddr := fmt.Sprintf("127.0.0.1:%d", udpPort)

	// 3. エージェント側 (internal/agent/agent.go の runtime.apply と同じ組み方)。
	agentRules := []proto.AgentRule{
		{ID: "tcp1", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: tcpPort, Hi: tcpPort}, Target: targetTCPAddr, Enabled: true},
		{ID: "udp1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: udpPort, Hi: udpPort}, Target: targetUDPAddr, Enabled: true},
	}
	agentTun, agentCancel := newAgentTunnel(t, agentPriv, srvPriv.PublicKey(), wgPort, agentAddr, serverAddr)
	agentRelay := relay.New(agentTun, relay.Options{Logf: quiet})
	agentRelay.Apply(relay.DesiredFromRules(agentRules))

	// 4. 握手を待ってから (壁時計の窓に入る前に状態の到達を確かめる。docs/testing.md
	// 「壁時計の窓を使うテストの規範」)、TCP と UDP を確かめる。予算は handshakeBudget を参照
	// (再送の間隔は wireguard-go の RekeyTimeout=5 秒で、遅い CI runner ではさらに伸びうる)。
	waitForHandshake(t, srvTun, agentTun, agentPub, wgPort, handshakeBudget, time.Time{})

	checkTCPRoundTrip(t, tcpAddr, []byte("hello over the tunnel"))
	for _, size := range []int{100, 1400, 3000, 12000} {
		checkUDPRoundTrip(t, udpAddr, size)
	}

	// 5. エージェント側を落とし、転送が止まることを確かめてから (否定の主張なので区間そのものが
	// 要る。同じ規範)、同じ鍵で立て直して転送が戻ることを確かめる。
	teardownAt := time.Now()
	agentRelay.Close()
	agentCancel()
	agentTun.Close()

	checkUDPRoundTripFails(t, udpAddr, 2*time.Second)

	agentTun2, agentCancel2 := newAgentTunnel(t, agentPriv, srvPriv.PublicKey(), wgPort, agentAddr, serverAddr)
	agentRelay2 := relay.New(agentTun2, relay.Options{Logf: quiet})
	agentRelay2.Apply(relay.DesiredFromRules(agentRules))

	waitForHandshake(t, srvTun, agentTun2, agentPub, wgPort, handshakeBudget, teardownAt)

	checkTCPRoundTrip(t, tcpAddr, []byte("hello again after the agent restarted"))
	checkUDPRoundTrip(t, udpAddr, 1400)

	// 6. 後始末してから、goroutine が基準値まで戻ることを確かめる (-count=3 を跨いで漏れないため)。
	agentRelay2.Close()
	agentCancel2()
	agentTun2.Close()
	serverRelay.Close()
	srvTun.Close()

	assertGoroutinesSettle(t, baseline)
}

// serverNetwork は relay.Network の VPS 側の実装。production の
// internal/dataplane/userspace/userspace.go の非公開の hostNetwork に相当するが、全インタフェース
// ではなく 127.0.0.1 だけに bind する (このテストの「ループバックだけ」という制約のため)。production
// の hostNetwork はホストの公開ポートを開くので全インタフェースに bind する。
type serverNetwork struct{}

func (serverNetwork) ListenUDP(port uint16) (net.PacketConn, error) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err == nil {
		// テスト側の「公開ポート」の送信バッファを上げる。production の VPS 側は Linux でしか
		// 動かないので、darwin の既定 9216 バイトに実際に当たることは無い
		// (このファイル冒頭のコメントを参照)。relay/relay_test.go の bigSendBuffer と同じ理由。
		_ = c.SetWriteBuffer(65535)
	}
	return c, err
}

func (serverNetwork) ListenTCP(port uint16) (net.Listener, error) {
	return net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
}

// newServerTunnel は VPS 側のトンネルを listen_port=0 で立て、OS が選んだ実際のポートを
// IpcGet で読み返す。wireguard-go の device.BindUpdate は net.ListenUDP と同じ規則で port 0 を
// 実際の空きポートに解決し (golang.zx2c4.com/wireguard の device/device.go)、device.IpcGet は
// net.port が非 0 になった時点でその実際の値を listen_port として返す (device/uapi.go)。
//
// 連続するポートを順に試す走査は、Windows の実機で空きが見つからずに失敗することがあった。
// OS に選ばせる形は走査の幅に依存しない。
func newServerTunnel(t *testing.T, priv wgtypes.Key, addr netip.Addr) (*Tunnel, uint16) {
	t.Helper()
	quiet := func(string, ...any) {}
	tun, err := New(Config{PrivateKey: priv, ListenPort: 0, Address: addr, MTU: 1420, Logf: quiet})
	if err != nil {
		t.Fatalf("server tunnel: %v", err)
	}
	port, err := boundListenPort(tun)
	if err != nil {
		tun.Close()
		t.Fatalf("read back the OS-assigned listen_port: %v", err)
	}
	if port == 0 {
		tun.Close()
		t.Fatal("server tunnel bound but IpcGet reports listen_port=0")
	}
	return tun, port
}

// boundListenPort reads tun's actual wg listen port back through IpcGet. It exists because
// Config.ListenPort=0 lets the OS pick the port, and Tunnel has no exported way to read it back;
// this test file is in package utun, so it reaches the unexported dev field directly instead of
// adding one to production code (utun.Tunnel).
func boundListenPort(tun *Tunnel) (uint16, error) {
	out, err := tun.dev.IpcGet()
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok || k != "listen_port" {
			continue
		}
		n, err := strconv.ParseUint(v, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("parse listen_port %q: %w", v, err)
		}
		return uint16(n), nil
	}
	return 0, fmt.Errorf("IpcGet output has no listen_port line")
}

// newAgentTunnel はエージェント側のトンネルを立てて Run を回す (internal/agent/agent.go の
// runtime.apply と同じ: tunnel.New に続けて Run を goroutine で回す)。戻り値の cancel は Run を
// 止めるだけで、Close は呼び出し側が行う (internal/agent/agent.go の runtime.closeLocked と同じ順序)。
func newAgentTunnel(t *testing.T, priv, serverPub wgtypes.Key, serverPort uint16, addr, serverAddr netip.Addr) (*tunnel.Tunnel, context.CancelFunc) {
	t.Helper()
	quiet := func(string, ...any) {}
	tun, err := tunnel.New(tunnel.Config{
		PrivateKey: priv, ServerPublicKey: serverPub,
		Endpoint:      fmt.Sprintf("127.0.0.1:%d", serverPort),
		Address:       addr,
		ServerAddress: serverAddr,
		MTU:           1420,
		Keepalive:     time.Second, // 短くして、握手を待つ区間を短く保つ (utun_test.go と同じ)
		Logf:          quiet,
	})
	if err != nil {
		t.Fatalf("agent tunnel: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go tun.Run(ctx)
	return tun, cancel
}

// prepareServerRelay は VPS 側の中継の待ち受けを空いているポートで開く。userspace.go の
// relayTargets と同じ展開 (Plan の Transparent なポートを 1 つずつ relay.Desired にする) を、
// テスト用に決めたポートで行う。失敗したら (bind の衝突) 新しいポートで作り直す。
func prepareServerRelay(t *testing.T, rl *relay.Manager, agentAddr netip.Addr) (tcpPort, udpPort uint16, plan planner.Plan) {
	t.Helper()
	for attempt := 0; attempt < 20; attempt++ {
		tcpPort = freeTCPPort(t)
		udpPort = freeUDPPort(t)
		p := planner.Build(planner.Input{
			Generation: 1,
			Rules: []model.Rule{
				{ID: "tcp1", Agent: "agent1", Proto: proto.TCP, ListenPort: proto.PortRange{Lo: tcpPort, Hi: tcpPort}, Forwarding: model.Transparent, Enabled: true},
				{ID: "udp1", Agent: "agent1", Proto: proto.UDP, ListenPort: proto.PortRange{Lo: udpPort, Hi: udpPort}, Forwarding: model.Transparent, Enabled: true},
			},
			Agents: []planner.Agent{{Name: "agent1", Addr: agentAddr}},
		})
		staged := rl.Prepare(relayTargetsFromPlan(p))
		if len(staged.Failed()) == 0 {
			staged.Commit(nil)
			return tcpPort, udpPort, p
		}
		staged.Rollback()
	}
	t.Fatal("could not bind free loopback ports for the relay after 20 attempts")
	return 0, 0, planner.Plan{}
}

// relayTargetsFromPlan は userspace.go の非公開の relayTargets と同じ展開。Plan.Transparent の
// 各ポートを、エージェントの wg アドレスの同じポートへの relay.Desired にする (DNAT はアドレス
// だけを書き換え、ポートは書き換えない。design.md 6.1 節)。
func relayTargetsFromPlan(plan planner.Plan) map[relay.Key]relay.Desired {
	desired := map[relay.Key]relay.Desired{}
	for _, pp := range plan.Transparent() {
		for port := int(pp.ListenPort.Lo); port <= int(pp.ListenPort.Hi); port++ {
			desired[relay.Key{Proto: pp.Proto, Port: uint16(port)}] = relay.Desired{
				Target: net.JoinHostPort(pp.AgentAddr.String(), fmt.Sprintf("%d", port)),
				RuleID: pp.RuleID,
			}
		}
	}
	return desired
}

// freeTCPPort と freeUDPPort は 127.0.0.1 上の空きポートを 1 つ返す。呼び出し側はすぐに使う側に
// 渡すので、閉じてから実際に使うまでの隙間は短い。それでも衝突したら (relay/relay_test.go の
// loopback のコメントが記録している既知の隙間) prepareServerRelay が新しいポートで作り直す。
func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find a free tcp port: %v", err)
	}
	defer ln.Close()
	return uint16(ln.Addr().(*net.TCPAddr).Port)
}

func freeUDPPort(t *testing.T) uint16 {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("find a free udp port: %v", err)
	}
	defer c.Close()
	return uint16(c.LocalAddr().(*net.UDPAddr).Port)
}

// startTCPEcho は 127.0.0.1 上に TCP の echo (受け取ったバイト列をそのまま返す) を立てる。
func startTCPEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("tcp echo target: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

// startUDPEcho は 127.0.0.1 上に UDP の echo を立てる。SetWriteBuffer の理由は、このファイル冒頭の
// コメントと relay/relay_test.go の bigSendBuffer を参照 (テスト側の宛先ソケットで、production の
// コードではない)。
func startUDPEcho(t *testing.T) string {
	t.Helper()
	pc, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp echo target: %v", err)
	}
	_ = pc.SetWriteBuffer(65535)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pc.WriteToUDP(buf[:n], addr)
		}
	}()
	t.Cleanup(func() { pc.Close() })
	return pc.LocalAddr().String()
}

// handshakeBudget is the ceiling waitForHandshake waits for a handshake. wireguard-go retries a
// lost handshake initiation every RekeyTimeout (5s, plus up to 334ms of jitter;
// golang.zx2c4.com/wireguard/device's timers.go and constants.go), so a budget of a few multiples
// of that leaves room for several retries plus this process's own startup cost (creating two
// netstack devices) before concluding the handshake is genuinely stuck rather than merely late.
const handshakeBudget = 40 * time.Second

// waitForHandshake は、after より後の握手が成立するまで待つ (壁時計の窓に入る前に状態の到達を
// 確かめる。docs/testing.md 「壁時計の窓を使うテストの規範」)。上限を超えたら失敗させ、診断のため
// 両側の IpcGet 相当の状態を出す (Logf は失敗したテストでだけ表示されるので、通ったときの費用は無い)。
func waitForHandshake(t *testing.T, srv *Tunnel, agent *tunnel.Tunnel, peer wgtypes.Key, wgPort uint16, budget time.Duration, after time.Time) PeerStatus {
	t.Helper()
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		peers, err := srv.Peers()
		if err != nil {
			t.Fatalf("read server peers: %v", err)
		}
		if st, ok := peers[peer]; ok && st.LastHandshake.After(after) {
			return st
		}
		time.Sleep(50 * time.Millisecond)
	}
	logHandshakeDiagnostics(t, srv, agent, peer, wgPort)
	t.Fatalf("no handshake with the agent tunnel within %s", budget)
	return PeerStatus{}
}

// logHandshakeDiagnostics prints both sides' IpcGet-derived status (endpoint, last handshake,
// rx/tx bytes: tx>0 with rx=0 on the other side says packets are sent and not received, tx=0
// says never sent) plus the server's bound wg port, runtime.GOOS, and which conn.Bind this
// package's and tunnel's newBind() gives on it, to help diagnose a failed handshake without
// another blind CI round. It is called only from the failure path, so it costs nothing when the
// test passes.
func logHandshakeDiagnostics(t *testing.T, srv *Tunnel, agent *tunnel.Tunnel, peer wgtypes.Key, wgPort uint16) {
	t.Helper()
	t.Logf("GOOS=%s; newBind() gives %s", runtime.GOOS, boundKindDescription())
	t.Logf("server tunnel bound at 127.0.0.1:%d (agent's tunnel.Config.Endpoint points here)", wgPort)
	if peers, err := srv.Peers(); err != nil {
		t.Logf("server side: reading peers failed: %v", err)
	} else if st, ok := peers[peer]; ok {
		t.Logf("server side of the agent peer: endpoint=%s last_handshake=%s rx=%d tx=%d",
			st.Endpoint, st.LastHandshake, st.RxBytes, st.TxBytes)
	} else {
		t.Logf("server side of the agent peer: not present in IpcGet output (peer never configured or already removed)")
	}
	ast := agent.Status()
	t.Logf("agent side of the server peer: endpoint=%s last_handshake=%s rx=%d tx=%d err=%v",
		ast.Endpoint, ast.LastHandshake, ast.RxBytes, ast.TxBytes, ast.Err)
}

// boundKindDescription documents, rather than detects, which conn.Bind this package's newBind()
// (bind_windows.go, bind_other.go) gives on this GOOS: utun.Tunnel and tunnel.Tunnel do not
// expose the device's private bind, so this cannot read it back from either type.
func boundKindDescription() string {
	if runtime.GOOS == "windows" {
		return "*conn.StdNetBind (newBind() calls conn.NewStdNetBind() explicitly on Windows; see bind_windows.go)"
	}
	return "whatever conn.NewDefaultBind() gives on this GOOS (newBind() calls it unchanged; see bind_other.go)"
}

// checkTCPRoundTrip はクライアントとして接続し、payload を書いて半クローズし、echo された同じ
// バイト列が届いて綺麗に閉じることを確かめる。
func checkTCPRoundTrip(t *testing.T, addr string, payload []byte) {
	t.Helper()
	conn, err := net.Dial("tcp4", addr)
	if err != nil {
		t.Fatalf("dial the server's tcp port: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("tcp write: %v", err)
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		if err := tc.CloseWrite(); err != nil {
			t.Fatalf("tcp half-close: %v", err)
		}
	}
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("tcp read: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("tcp echo mismatch: got %d bytes, want %d bytes", len(got), len(payload))
	}
}

// checkUDPRoundTrip は size バイトのデータグラムを送り、同じ内容が丸ごと戻ることを確かめる。
func checkUDPRoundTrip(t *testing.T, addr string, size int) {
	t.Helper()
	conn, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatalf("dial the server's udp port: %v", err)
	}
	defer conn.Close()
	if uc, ok := conn.(*net.UDPConn); ok {
		// テスト側のクライアントのソケット。理由は startUDPEcho のコメントと同じ。
		_ = uc.SetWriteBuffer(65535)
	}
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i)
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("udp write %d bytes: %v", size, err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("udp read reply for %d bytes: %v", size, err)
	}
	if n != size || !bytes.Equal(buf[:n], payload) {
		t.Fatalf("udp echo mismatch for %d bytes: got %d bytes", size, n)
	}
}

// checkUDPRoundTripFails は、否定の主張(転送が戻らない)を確かめる。区間そのものが要る
// (docs/testing.md「壁時計の窓を使うテストの規範」)ので、timeout は主張の根拠ではなく上限。
func checkUDPRoundTripFails(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	conn, err := net.Dial("udp4", addr)
	if err != nil {
		t.Fatalf("dial the server's udp port: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte("probe while the agent tunnel is down")); err != nil {
		t.Fatalf("udp write: %v", err)
	}
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("udp echo succeeded while the agent tunnel was torn down")
	}
}

// assertGoroutinesSettle は、明示的に片付けた後に goroutine 数が基準値まで戻ることを確かめる
// (-count=3 を跨いで漏れないため)。wireguard-go とネットスタックの後片付けは非同期なので、
// 収束を待ってから比べる(壁時計の窓を使うテストの規範と同じ考え方)。
func assertGoroutinesSettle(t *testing.T, baseline int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if n := runtime.NumGoroutine(); n <= baseline+2 {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("goroutines did not settle after close: now %d, baseline %d", runtime.NumGoroutine(), baseline)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}
