package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/proto"
)

// newTestRegisterServer は登録 API のなりすまし(仕様 5.1 節)。渡された name が空でなければ
// boundName と比較し、違えば 401 を返す(vpsd の実装と同じ契約)。
func newTestRegisterServer(t *testing.T, boundName string) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/register", func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req["token"] != "tok" {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		if req["name"] != "" && req["name"] != boundName {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{
			"permanent_token": "PERM",
			"address":         "10.200.0.2",
			"name":            boundName,
		})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	pin := sha256.Sum256(srv.Certificate().Raw)
	host := strings.TrimPrefix(srv.URL, "https://")
	join := fmt.Sprintf("wgft://%s/tok#sha256:%x", host, pin)
	return srv, join
}

// 名前を送らない初回登録は、応答に含まれる確定した名前を認証情報に保存する。
func TestEnsureRegisteredStoresConfirmedName(t *testing.T) {
	_, join := newTestRegisterServer(t, "home")
	path := filepath.Join(t.TempDir(), "agent.json")

	f := &credentials.Credentials{}
	opts := Options{CredentialsPath: path, Join: join} // Name は空
	if err := ensureRegistered(f, opts); err != nil {
		t.Fatal(err)
	}
	if f.Name != "home" || f.PermanentToken != "PERM" {
		t.Fatalf("f = %+v", f)
	}
	g, err := credentials.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if g.Name != "home" {
		t.Errorf("persisted name = %q, want %q", g.Name, "home")
	}
}

// 名前を送っても一致すれば通る。
func TestEnsureRegisteredWithMatchingName(t *testing.T) {
	_, join := newTestRegisterServer(t, "home")
	f := &credentials.Credentials{}
	opts := Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json"), Join: join, Name: "home"}
	if err := ensureRegistered(f, opts); err != nil {
		t.Fatal(err)
	}
	if f.Name != "home" {
		t.Errorf("f.Name = %q", f.Name)
	}
}

// 名前が食い違えば拒否される。
func TestEnsureRegisteredWithMismatchedName(t *testing.T) {
	_, join := newTestRegisterServer(t, "home")
	f := &credentials.Credentials{}
	opts := Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json"), Join: join, Name: "office"}
	if err := ensureRegistered(f, opts); err == nil {
		t.Error("mismatched name must be rejected")
	}
}

// 既に登録済みで WGFT_NAME が保存済みの名前と違えば、警告するだけで保存済みの名前を保つ。
func TestEnsureRegisteredKeepsStoredNameOnMismatch(t *testing.T) {
	f := &credentials.Credentials{Name: "home", PermanentToken: "PERM"}
	opts := Options{CredentialsPath: filepath.Join(t.TempDir(), "agent.json"), Name: "other"}
	if err := ensureRegistered(f, opts); err != nil {
		t.Fatal(err)
	}
	if f.Name != "home" {
		t.Errorf("f.Name = %q, want unchanged %q", f.Name, "home")
	}
}

// サーバ証明書が認証情報のピンと違うとき、stream の接続は ErrPinMismatch として区別できる。
func TestStreamOnceReportsPinMismatch(t *testing.T) {
	srv, _ := newTestRegisterServer(t, "home")
	rt := &runtime{f: &credentials.Credentials{
		Endpoint:       strings.TrimPrefix(srv.URL, "https://"),
		CertSHA256:     strings.Repeat("00", 32), // 立て直す前のサーバのピン
		PermanentToken: "OLD",
	}}
	err := rt.streamOnce(context.Background())
	if !errors.Is(err, ErrPinMismatch) {
		t.Fatalf("streamOnce = %v, want ErrPinMismatch", err)
	}
}

// ピンの不一致からの再登録に使うのは、未使用でピンの違う接続文字列だけ。
func TestJoinForNewPin(t *testing.T) {
	_, join := newTestRegisterServer(t, "home")
	j, err := ParseJoin(join)
	if err != nil {
		t.Fatal(err)
	}
	newPin := hex.EncodeToString(j.Pin[:])
	oldPin := strings.Repeat("00", 32)
	cases := []struct {
		name, join, storedPin, usedHash string
		want                            bool
	}{
		{"unused join with a new pin", join, oldPin, "", true},
		{"no join", "", oldPin, "", false},
		{"join already used", join, oldPin, j.TokenHash(), false},
		{"join has the stored pin", join, newPin, "", false},
		{"unparsable join", "wgft://broken", oldPin, "", false},
	}
	for _, c := range cases {
		rt := &runtime{opts: Options{Join: c.join}, f: &credentials.Credentials{CertSHA256: c.storedPin, UsedJoinTokenSHA256: c.usedHash}}
		if got := rt.joinForNewPin() != nil; got != c.want {
			t.Errorf("%s: joinForNewPin != nil is %v, want %v", c.name, got, c.want)
		}
	}
}

// 再登録が成功すると、認証情報のピンとトークンが新しいサーバのものに置き換わる。
func TestRecoverReplacesPinAndToken(t *testing.T) {
	_, join := newTestRegisterServer(t, "home")
	path := filepath.Join(t.TempDir(), "agent.json")
	rt := &runtime{
		opts: Options{Join: join, CredentialsPath: path},
		f:    &credentials.Credentials{Name: "home", CertSHA256: strings.Repeat("00", 32), PermanentToken: "OLD", WGPrivateKey: "keep"},
	}
	if err := rt.recover(); err != nil {
		t.Fatal(err)
	}
	j, _ := ParseJoin(join)
	saved, err := credentials.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if saved.PermanentToken != "PERM" || saved.CertSHA256 != hex.EncodeToString(j.Pin[:]) || saved.UsedJoinTokenSHA256 != j.TokenHash() {
		t.Errorf("credentials not replaced: %+v", saved)
	}
	if saved.WGPrivateKey != "keep" {
		t.Errorf("wg private key changed: %q", saved.WGPrivateKey)
	}
}

// versionOrDev と nameOrUnregistered は起動ログの 1 行(wgft <version> agent starting: name <name>, ...)を組み立てる材料。
func TestVersionOrDev(t *testing.T) {
	if got := versionOrDev(""); got != "dev" {
		t.Errorf("versionOrDev(\"\") = %q, want dev", got)
	}
	if got := versionOrDev("v1.2.3"); got != "v1.2.3" {
		t.Errorf("versionOrDev(v1.2.3) = %q, want v1.2.3", got)
	}
}

func TestNameOrUnregistered(t *testing.T) {
	if got := nameOrUnregistered(""); got != "not registered yet" {
		t.Errorf("nameOrUnregistered(\"\") = %q, want %q", got, "not registered yet")
	}
	if got := nameOrUnregistered("home"); got != "home" {
		t.Errorf("nameOrUnregistered(home) = %q, want home", got)
	}
}

// logStatus は 30 秒ごとに呼ばれる定期ログ(heartbeat と同じ内容)なので、状態が変わらない間は黙り、
// ジャーナルを埋めない(仕様の運用ログの節)。
func TestLogStatusDedup(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0) // 時刻を外し、行数だけを見る
	defer func() { log.SetOutput(old); log.SetFlags(oldFlags) }()

	rt := &runtime{}
	rt.logStatus()
	first := buf.String()
	if first == "" {
		t.Fatal("first call must log the status")
	}

	rt.logStatus() // 状態が同じなら何も足さない
	if got := buf.String(); got != first {
		t.Errorf("unchanged status logged again:\nfirst: %q\nafter: %q", first, got)
	}

	rt.mu.Lock()
	rt.gen = 5
	rt.mu.Unlock()
	rt.logStatus() // 世代が変われば出す
	if got := buf.String(); got == first {
		t.Error("changed status (generation) was not logged")
	}
}

// notifyNonBlocking は、streamOnce のハートビート goroutine への通知をサイズ 1 のチャネルにまとめる
// (仕様 5.2 節)。読み出される前に何度呼んでも高々 1 件しか溜まらないことを確かめる。
func TestNotifyNonBlockingCoalesces(t *testing.T) {
	ch := make(chan struct{}, 1)
	for i := 0; i < 5; i++ {
		notifyNonBlocking(ch) // 詰まっていても待たない。ブロックすればテストがタイムアウトする
	}
	if len(ch) != 1 {
		t.Fatalf("len(ch) = %d, want 1 after a burst of notifications", len(ch))
	}
	select {
	case <-ch:
	default:
		t.Fatal("expected exactly one pending notification")
	}
	select {
	case <-ch:
		t.Fatal("channel should be empty after a single receive")
	default:
	}

	// 消費した後にまた呼べば、次の通知が届く
	notifyNonBlocking(ch)
	select {
	case <-ch:
	default:
		t.Fatal("expected a fresh notification after the channel was drained")
	}
}

// needsHandshakeFollowUp は、ハンドシェイク待ちの誤りだけを追送りの対象にする(仕様 5.2 節)。
// トンネルが無い、bind に失敗した、といった本当の誤りは対象にしない。
func TestNeedsHandshakeFollowUp(t *testing.T) {
	cases := []struct {
		name string
		t    proto.TunnelStatus
		want bool
	}{
		{"ok", proto.TunnelStatus{State: proto.StatusOK}, false},
		{"handshake not established", proto.TunnelStatus{State: proto.StatusError, Reason: reasonHandshakePending}, true},
		{"no tunnel", proto.TunnelStatus{State: proto.StatusError, Reason: "no tunnel; full state not received"}, false},
		{"real tunnel error", proto.TunnelStatus{State: proto.StatusError, Reason: "wireguard: listen: address already in use"}, false},
	}
	for _, c := range cases {
		if got := needsHandshakeFollowUp(c.t); got != c.want {
			t.Errorf("%s: needsHandshakeFollowUp = %v, want %v", c.name, got, c.want)
		}
	}
}

// runHeartbeats は、適用直後の送信(notify)がハンドシェイク待ちを報告した間だけ、通常のティッカーを
// 待たずに retryInterval ごとに送り直し、ハンドシェイクが済んだ次の送信で止まる(仕様 5.2 節)。
func TestRunHeartbeatsFollowsUpUntilHandshake(t *testing.T) {
	var calls int
	established := false // 3 回目の送信からハンドシェイクが済んだことにする
	sendCh := make(chan proto.Heartbeat, 10)
	send := func() (proto.Heartbeat, bool) {
		calls++
		if calls >= 3 {
			established = true
		}
		hb := proto.Heartbeat{Generation: uint64(calls)}
		if established {
			hb.Tunnel = proto.TunnelStatus{State: proto.StatusOK}
		} else {
			hb.Tunnel = proto.TunnelStatus{State: proto.StatusError, Reason: reasonHandshakePending}
		}
		sendCh <- hb
		return hb, true
	}

	done := make(chan struct{})
	defer close(done)
	tick := make(chan time.Time) // 使わない。ティッカーでは追送りが起きないことの対照
	notify := make(chan struct{}, 1)
	go runHeartbeats(done, tick, notify, 5*time.Millisecond, time.Second, send)

	notify <- struct{}{}

	// 送信 1、2 回目はまだハンドシェイク待ちなので追送りが続き、3 回目で済む
	for i := 0; i < 3; i++ {
		select {
		case hb := <-sendCh:
			if i < 2 && hb.Tunnel.State != proto.StatusError {
				t.Fatalf("send %d: tunnel = %+v, want a handshake-not-established error", i+1, hb.Tunnel)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("send %d: no follow-up heartbeat arrived", i+1)
		}
	}
	select {
	case hb := <-sendCh:
		t.Fatalf("unexpected extra heartbeat after the handshake was established: %+v", hb)
	case <-time.After(50 * time.Millisecond):
	}
}

// ハンドシェイクが最後まで済まなければ、追送りは retryTimeout で止まり、後始末して通常のティッカー待ちに戻る。
func TestRunHeartbeatsStopsFollowUpAfterTimeout(t *testing.T) {
	var calls atomic.Int32
	send := func() (proto.Heartbeat, bool) {
		calls.Add(1)
		return proto.Heartbeat{Tunnel: proto.TunnelStatus{State: proto.StatusError, Reason: reasonHandshakePending}}, true
	}

	done := make(chan struct{})
	tick := make(chan time.Time)
	notify := make(chan struct{}, 1)
	go runHeartbeats(done, tick, notify, 5*time.Millisecond, 30*time.Millisecond, send)

	notify <- struct{}{}
	time.Sleep(200 * time.Millisecond) // retryTimeout(30ms)をまたぐ間、追送りが続くのを待つ
	stopped := calls.Load()
	time.Sleep(100 * time.Millisecond) // 追送りが止まっていれば、この間に送信は増えない
	close(done)
	if got := calls.Load(); got != stopped {
		t.Errorf("follow-up did not stop after the timeout: calls went from %d to %d", stopped, got)
	}
	if stopped < 2 {
		t.Fatalf("expected more than one follow-up heartbeat before the timeout, got %d", stopped)
	}
}

// newTestStreamServer は vpsd 側の stream(仕様 5.2 節)の薄いなりすまし。公開鍵の受信までは検証せず、
// test から送った全体状態をそのまま転送し、エージェントが送るハートビートを hbCh へ流し、
// 受け取った最初のメッセージ(pubkey、版と機能の交渉を含む)を firstCh へ流す。
func newTestStreamServer(t *testing.T) (srv *httptest.Server, pin [32]byte, stateCh chan<- *proto.State, hbCh <-chan *proto.Heartbeat, firstCh <-chan proto.Message) {
	t.Helper()
	states := make(chan *proto.State)
	heartbeats := make(chan *proto.Heartbeat, 8)
	firsts := make(chan proto.Message, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agents/stream", func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		ctx := r.Context()
		var first proto.Message
		if _, b, err := ws.Read(ctx); err != nil || json.Unmarshal(b, &first) != nil || first.Type != proto.MsgPublicKey {
			return
		}
		select {
		case firsts <- first:
		default:
		}
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case st, ok := <-states:
					if !ok {
						return
					}
					b, _ := json.Marshal(proto.Message{Type: proto.MsgState, State: st})
					wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
					err := ws.Write(wctx, websocket.MessageText, b)
					cancel()
					if err != nil {
						return
					}
				}
			}
		}()
		for {
			_, b, err := ws.Read(ctx)
			if err != nil {
				return
			}
			var m proto.Message
			if json.Unmarshal(b, &m) != nil {
				continue
			}
			if m.Type == proto.MsgHeartbeat && m.Heartbeat != nil {
				select {
				case heartbeats <- m.Heartbeat:
				default:
				}
			}
		}
	})
	srv = httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	pin = sha256.Sum256(srv.Certificate().Raw)
	return srv, pin, states, heartbeats, firsts
}

// streamOnce は、stream の接続直後に全体状態を適用した直後と、以後の世代を適用するたびにも
// ハートビートを送る(30 秒のティッカーを待たない。仕様 5.2 節)。ここではティッカーを実質無効にした
// runtime を使い、適用のたびにハートビートが届くことだけを確かめる。
func TestStreamOnceSendsHeartbeatAfterApply(t *testing.T) {
	srv, pin, stateCh, hbCh, _ := newTestStreamServer(t)

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rt := &runtime{
		f: &credentials.Credentials{
			Endpoint:       strings.TrimPrefix(srv.URL, "https://"),
			CertSHA256:     hex.EncodeToString(pin[:]),
			PermanentToken: "tok",
		},
		priv:              priv,
		heartbeatInterval: time.Hour, // 十分長くし、ティッカーではなく適用の通知で届くことを確かめる
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.streamOnce(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitHeartbeat := func(wantGen uint64) {
		t.Helper()
		select {
		case hb := <-hbCh:
			if hb.Generation != wantGen {
				t.Errorf("heartbeat generation = %d, want %d", hb.Generation, wantGen)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("no heartbeat within 5s of applying a state; it must not wait for the 30s ticker")
		}
	}

	// wg の公開鍵が不正なので apply は早期に失敗し、世代は進まない。それでも接続直後の適用の
	// 直後にハートビートが届くことを確かめる(登録直後・再接続直後に空の行が最大 30 秒見える不具合の再現条件)。
	stateCh <- &proto.State{Generation: 1, WG: proto.WGConfig{ServerPubkey: "not-a-valid-key"}}
	waitHeartbeat(0)

	// 2 つ目の世代を適用した直後にも、ティッカーを待たずに次のハートビートが届く。
	stateCh <- &proto.State{Generation: 2, WG: proto.WGConfig{ServerPubkey: "not-a-valid-key"}}
	waitHeartbeat(0)
}

// TestStreamOnceSendsProtocolRange は、agent が pubkey メッセージに話せる版の範囲と、
// 空(だが非 nil)の capabilities を載せることを確かめる(仕様 7a.6 節)。
func TestStreamOnceSendsProtocolRange(t *testing.T) {
	srv, pin, _, _, firstCh := newTestStreamServer(t)

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rt := &runtime{
		f: &credentials.Credentials{
			Endpoint:       strings.TrimPrefix(srv.URL, "https://"),
			CertSHA256:     hex.EncodeToString(pin[:]),
			PermanentToken: "tok",
		},
		priv:              priv,
		heartbeatInterval: time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.streamOnce(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	select {
	case m := <-firstCh:
		if m.ProtocolMin == nil || *m.ProtocolMin != proto.SupportedProtocol.Min {
			t.Errorf("protocol_min = %v, want %d", m.ProtocolMin, proto.SupportedProtocol.Min)
		}
		if m.ProtocolMax == nil || *m.ProtocolMax != proto.SupportedProtocol.Max {
			t.Errorf("protocol_max = %v, want %d", m.ProtocolMax, proto.SupportedProtocol.Max)
		}
		if m.Capabilities == nil {
			t.Error("capabilities: want a non-nil (possibly empty) array, got nil (indistinguishable from a legacy v0 agent)")
		} else if len(*m.Capabilities) != 0 {
			t.Errorf("capabilities = %v, want empty", *m.Capabilities)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no pubkey message received within 5s")
	}
}

// TestStreamOnceRejectsOutOfRangeServerVersion confirms the agent disconnects (returning an
// error, which streamLoop then logs and retries with the normal backoff) if the server claims
// to have selected a protocol version outside the agent's own supported range -- a defensive
// check, since a correct server only ever selects from the intersection (spec 7a.6 section).
func TestStreamOnceRejectsOutOfRangeServerVersion(t *testing.T) {
	srv, pin, stateCh, _, _ := newTestStreamServer(t)

	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rt := &runtime{
		f: &credentials.Credentials{
			Endpoint:       strings.TrimPrefix(srv.URL, "https://"),
			CertSHA256:     hex.EncodeToString(pin[:]),
			PermanentToken: "tok",
		},
		priv:              priv,
		heartbeatInterval: time.Hour,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- rt.streamOnce(ctx) }()

	outOfRange := 5
	stateCh <- &proto.State{Generation: 1, ServerProtocolVersion: &outOfRange, WG: proto.WGConfig{ServerPubkey: "not-a-valid-key"}}

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "outside the agent's supported range") {
			t.Errorf("streamOnce error = %v, want a message about the out-of-range version", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("streamOnce did not return after an out-of-range server_protocol_version")
	}
}

// TestCheckServerProtocolVersion is a table test for the pure validation function used above.
func TestCheckServerProtocolVersion(t *testing.T) {
	local := proto.ProtocolRange{Min: 1, Max: 1}
	inRange := 1
	outOfRange := 2
	zero := 0
	negative := -1
	tests := []struct {
		name    string
		st      *proto.State
		wantErr bool
	}{
		{"legacy v0 state (no field): nothing to check", &proto.State{}, false},
		{"in range", &proto.State{ServerProtocolVersion: &inRange}, false},
		{"out of range", &proto.State{ServerProtocolVersion: &outOfRange}, true},
		// Versions start at 1 (design 7a.6); 0 or negative is not a valid numbered version at
		// all, distinct from a valid version that happens to fall outside the agent's range.
		{"zero: not a valid numbered version", &proto.State{ServerProtocolVersion: &zero}, true},
		{"negative: not a valid numbered version", &proto.State{ServerProtocolVersion: &negative}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkServerProtocolVersion(local, tt.st)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkServerProtocolVersion() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// 宛先の許可一覧を設定しなければ、中継に判定を渡さない(仕様 7 節の「一覧が無いときは制限しない」)。
// 設定したときは判定と設定の名前を渡す。
func TestRelayOptionsAllowTargets(t *testing.T) {
	st := &proto.State{WG: proto.WGConfig{UDPTimeoutStream: 120}}
	rt := &runtime{}
	if o := rt.relayOptions(st); o.AllowTarget != nil || o.AllowTargetSource != "" {
		t.Errorf("without a list: AllowTarget=%v source=%q, want none", o.AllowTarget != nil, o.AllowTargetSource)
	}
	list, err := allowtargets.Parse("192.168.1.20:25565")
	if err != nil {
		t.Fatal(err)
	}
	rt = &runtime{opts: Options{AllowTargets: list}}
	o := rt.relayOptions(st)
	if o.AllowTarget == nil {
		t.Fatal("with a list: AllowTarget is nil")
	}
	if o.AllowTargetSource != allowtargets.Env {
		t.Errorf("source = %q, want %q", o.AllowTargetSource, allowtargets.Env)
	}
	if !o.AllowTarget(netip.MustParseAddrPort("192.168.1.20:25565")) {
		t.Error("the listed target must be allowed")
	}
	if o.AllowTarget(netip.MustParseAddrPort("192.168.1.1:22")) {
		t.Error("a target outside the list must be denied")
	}
}
