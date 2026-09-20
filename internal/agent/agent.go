// Package agent は自宅側のエージェント(仕様 7 節)。
// 認証情報ファイルの鍵と最後の全体状態でトンネルとリスナーを先に立て、その後 stream に繋いで全体状態を受け取る。
package agent

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"net/netip"
	"os/signal"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/tunnel"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/internal/startup"
	"github.com/rahanahu/wgft/proto"
)

// Options は agent の起動オプション。
type Options struct {
	// AllowTargets は接続してよい宛先の許可一覧(仕様 7 節、WGFT_AGENT_ALLOW_TARGETS)。
	// nil なら制限せず、vpsd が配るどの宛先へも接続する
	AllowTargets    *allowtargets.List
	CredentialsPath string          // 認証情報ファイル
	Join            string          // 接続文字列(WGFT_JOIN か --join)。初回登録に使う
	Limits          resource.Limits // 同時フロー数のプロセス全体の予算(仕様 7 節)。ゼロ値は既定値
	Name            string          // エージェント名(WGFT_NAME か --name)。任意。接続文字列の発行時の名前に紐付いているので、与えなければトークンに紐付いた名前で登録される
	Version         string          // 起動ログに出す wgft の版(cmd 側の effectiveVersion())。空なら "dev" として出す
}

// runtime は動いているエージェント。全体状態を「宣言された状態に収束させる」方式で適用する。
type runtime struct {
	opts              Options
	f                 *credentials.Credentials
	priv              wgtypes.Key
	heartbeatInterval time.Duration

	// handshakeRetryInterval と handshakeRetryTimeout は、適用直後のハートビートがハンドシェイク待ちの
	// 誤りを報告したときの追送りの間隔と期限(仕様 5.2 節)。既定はそれぞれ 1 秒と 10 秒。テストで
	// 短くできるよう runtime に持たせる。handshakeRetryInterval が 0 以下なら追送りしない
	handshakeRetryInterval time.Duration
	handshakeRetryTimeout  time.Duration

	mu        sync.Mutex
	tun       *tunnel.Tunnel
	tunCancel context.CancelFunc
	rl        *relay.Manager
	wgCfg     proto.WGConfig // 適用済みの wg 設定
	gen       uint64         // 処理済み世代

	streamMu     sync.Mutex
	streamCancel context.CancelFunc // 今の stream 接続を切る(rotate-key で張り直すとき)
	reconnectNow bool               // 切った直後はバックオフせずに繋ぎ直す

	// lastStatusLines は logStatus が前回出した内容(30 秒ごとの定期ログの重複を防ぐ。Run のループの
	// 単一の goroutine からしか呼ばれないので、別途の mutex は持たない)
	lastStatusLines []string
}

// Run は認証情報ファイルを読み、登録を確かめ、トンネルとリスナーを立て、stream に繋ぎ、シグナルまで動く。
func Run(opts Options) error {
	// 二重起動の検出。取れなければ別のプロセスが動いている(仕様 9 節)
	lock, err := credentials.Acquire(opts.CredentialsPath)
	if err != nil {
		return err
	}
	defer lock.Release()

	f, err := credentials.LoadOrNew(opts.CredentialsPath)
	if err != nil {
		return err
	}
	log.Printf("wgft %s agent starting: name %s, data dir %s", versionOrDev(opts.Version), nameOrUnregistered(f.Name), filepath.Dir(opts.CredentialsPath))
	logAllowTargets(opts.AllowTargets)
	created, err := f.EnsureKey()
	if err != nil {
		return err
	}
	if created {
		if err := f.Save(opts.CredentialsPath); err != nil {
			return err
		}
	}
	priv, _ := f.PrivateKey()
	if created {
		log.Printf("generated wg key pair; public key: %s", priv.PublicKey())
	}
	if err := ensureRegistered(f, opts); err != nil {
		return err
	}
	rt := &runtime{
		opts: opts, f: f, priv: priv,
		heartbeatInterval:      30 * time.Second,
		handshakeRetryInterval: time.Second,
		handshakeRetryTimeout:  10 * time.Second,
	}
	defer rt.close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// vpsd が停止中でも、VPS 側にピアが残っていれば転送が復旧するよう、先に立てる(仕様 9 節)
	if f.LastState != nil {
		if err := rt.apply(f.LastState); err != nil {
			log.Printf("apply saved generation %d: %v; waiting for full state from stream", f.LastState.Generation, err)
		}
	} else {
		log.Printf("no saved full state; waiting for full state from stream")
	}
	errc := make(chan error, 1)
	go func() { errc <- rt.streamLoop(ctx) }()
	go rt.serveControl(ctx)

	// 30 秒ごと:開けなかったリスナーの再試行と、状態のログ
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("shutting down")
			return nil
		case err := <-errc:
			// 復帰できない認証拒否。鍵と認証情報ファイルは残したまま止まる(仕様 5.1 節)
			return err
		case <-tick.C:
			rt.mu.Lock()
			if rt.rl != nil {
				rt.rl.Retry()
			}
			rt.mu.Unlock()
			rt.logStatus()
		}
	}
}

func (rt *runtime) generation() uint64 {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.gen
}

// apply は全体状態を適用する。wg 設定が変わればトンネルを張り直し(セッションは切れる)、
// リスナーは変わったものだけを開閉する(仕様 5.2, 7 節)。部分失敗でも世代は進め、認証情報ファイルに保存する。
func (rt *runtime) apply(st *proto.State) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	var firstErr error
	if rt.tun == nil || !reflect.DeepEqual(rt.wgCfg, st.WG) {
		if rt.tun != nil {
			log.Printf("wg config changed; rebuilding tunnel")
		}
		rt.closeLocked()
		cfg, err := tunnelConfig(rt.priv, st.WG)
		if err != nil {
			return fmt.Errorf("wireguard: %w", err)
		}
		tun, err := tunnel.New(cfg)
		if err != nil {
			return fmt.Errorf("wireguard: %w", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go tun.Run(ctx)
		rt.tun, rt.tunCancel, rt.wgCfg = tun, cancel, st.WG
		rt.rl = relay.New(tun, rt.relayOptions(st))
	}
	acts := rt.rl.Apply(relay.DesiredFromRules(st.Rules))
	rt.gen = st.Generation
	rt.f.LastState = st
	if err := rt.f.Save(rt.opts.CredentialsPath); err != nil {
		firstErr = fmt.Errorf("save credentials file: %w", err)
	}
	log.Printf("applied generation %d (%d actions, %d listeners)", st.Generation, len(acts), len(rt.rl.Status()))
	return firstErr
}

// relayOptions は中継の調整値を作る。宛先の許可一覧があれば、中継が宛先へ接続するときに
// 使う判定として渡す(仕様 7 節)。一覧が無ければ渡さないので、中継の挙動は一覧の導入前と同じになる。
func (rt *runtime) relayOptions(st *proto.State) relay.Options {
	o := relay.Options{
		UDPIdleTimeout: time.Duration(st.WG.UDPTimeoutStream) * time.Second,
		Limits:         rt.opts.Limits,
	}
	if rt.opts.AllowTargets != nil {
		o.AllowTarget = rt.opts.AllowTargets.Allows
		o.AllowTargetSource = allowtargets.Env
	}
	return o
}

// logAllowTargets は宛先の許可一覧の有無を起動時に 1 行で出す(仕様 7 節)。
// 一覧が無いときに何も出さないと、制限が無いことが運用者に見えないので、無いことも出す。
func logAllowTargets(l *allowtargets.List) {
	if l == nil {
		log.Printf("no target allowlist (%s is not set); the server can direct this agent to any address it can reach", allowtargets.Env)
		return
	}
	log.Printf("target allowlist %s=%s; the server can direct this agent only to these addresses", allowtargets.Env, l)
}

func (rt *runtime) closeLocked() {
	if rt.rl != nil {
		rt.rl.Close()
		rt.rl = nil
	}
	if rt.tunCancel != nil {
		rt.tunCancel()
		rt.tunCancel = nil
	}
	if rt.tun != nil {
		rt.tun.Close()
		rt.tun = nil
	}
}

func (rt *runtime) close() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.closeLocked()
}

// heartbeat は処理済み世代、トンネルの状態、ルールごとの状態をまとめる(仕様 5.2 節)。
// reasonHandshakePending は、トンネルはあるが WireGuard のハンドシェイクがまだ済んでいないときの理由。
// 適用直後の追送り(needsHandshakeFollowUp)がこの値で判定するので、文言を変えるときは両方に効く。
const reasonHandshakePending = "handshake not established"

func (rt *runtime) heartbeat() proto.Heartbeat {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	hb := proto.Heartbeat{Generation: rt.gen, Rules: []proto.RuleStatus{}}
	if rt.tun == nil {
		hb.Tunnel = proto.TunnelStatus{State: proto.StatusError, Reason: "no tunnel; full state not received"}
		return hb
	}
	ts := rt.tun.Status()
	hb.Tunnel = proto.TunnelStatus{State: proto.StatusOK, LastHandshake: ts.LastHandshake}
	if ts.Endpoint.IsValid() {
		hb.Tunnel.Endpoint = ts.Endpoint.String()
	}
	if ts.Err != nil {
		hb.Tunnel.State, hb.Tunnel.Reason = proto.StatusError, ts.Err.Error()
	} else if ts.LastHandshake.IsZero() {
		hb.Tunnel.State, hb.Tunnel.Reason = proto.StatusError, reasonHandshakePending
	}
	// ルールの状態は所属リスナーの合成。1 つでも error なら error
	byRule := map[string]*proto.RuleStatus{}
	for _, s := range rt.rl.Status() {
		r := byRule[s.RuleID]
		if r == nil {
			r = &proto.RuleStatus{ID: s.RuleID, State: proto.StatusOK}
			byRule[s.RuleID] = r
		}
		if s.Err != nil && r.State == proto.StatusOK {
			r.State, r.Reason = proto.StatusError, fmt.Sprintf("%s: %v", s.Key, s.Err)
		}
	}
	for _, r := range byRule {
		hb.Rules = append(hb.Rules, *r)
	}
	sort.Slice(hb.Rules, func(i, j int) bool { return hb.Rules[i].ID < hb.Rules[j].ID })
	return hb
}

// logStatus は 30 秒ごとに呼ばれる(Run のティッカー)。毎回は出さず、前回のログと同じ内容なら黙る
// (トンネルとルールの状態が変わらない定常運転でジャーナルを埋めないため)。
func (rt *runtime) logStatus() {
	hb := rt.heartbeat()
	lines := make([]string, 0, 1+len(hb.Rules))
	lines = append(lines, fmt.Sprintf("generation %d tunnel=%s %s endpoint=%s", hb.Generation, hb.Tunnel.State, hb.Tunnel.Reason, hb.Tunnel.Endpoint))
	for _, r := range hb.Rules {
		lines = append(lines, fmt.Sprintf("rule %s %s %s", r.ID, r.State, r.Reason))
	}
	if reflect.DeepEqual(lines, rt.lastStatusLines) {
		return
	}
	rt.lastStatusLines = lines
	for _, l := range lines {
		log.Printf("%s", l)
	}
}

// recover は stream の認証が拒否(401)されたときの復帰経路(仕様 5.1 節)。
// WGFT_JOIN があり、使用済みでなければ初回登録をやり直す。認証情報ファイルは登録が成功した時点で置き換え、
// 失敗したら既存のファイルを残したまま止まる(期限切れのトークンで鍵まで失わないため)。
// この 3 つの分岐は、ensureRegistered の同じ 3 つと同じ理由で拒否として返す。稼働中に起きても、
// 直すには運用者が新しい接続文字列を発行するしかなく、再起動の繰り返しでは直らない(設計文書 11b 節)。
func (rt *runtime) recover() error {
	if rt.opts.Join == "" {
		return startup.Config("WGFT_JOIN", "permanent token was revoked; provide a new join string via WGFT_JOIN and restart")
	}
	j, err := ParseJoin(rt.opts.Join)
	if err != nil {
		return startup.Config("WGFT_JOIN", "%v", err)
	}
	if j.TokenHash() == rt.f.UsedJoinTokenSHA256 {
		return startup.Conflict("WGFT_JOIN", "permanent token was revoked and the local join string is already used; issue a new join string and replace WGFT_JOIN")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, addr, name, err := Register(ctx, j, rt.opts.Name)
	if err != nil {
		return fmt.Errorf("re-register failed: %w", err)
	}
	rt.mu.Lock()
	rt.f.Name, rt.f.Endpoint, rt.f.PermanentToken = name, j.Endpoint, tok
	rt.f.CertSHA256 = hex.EncodeToString(j.Pin[:])
	rt.f.UsedJoinTokenSHA256 = j.TokenHash()
	err = rt.f.Save(rt.opts.CredentialsPath)
	rt.mu.Unlock()
	if err != nil {
		return err
	}
	log.Printf("re-registered as agent %s; assigned %s", name, addr)
	return nil
}

// joinForNewPin は、ピンの不一致からの再登録に使える接続文字列を返す(仕様 5.1 節)。
// 未使用で、かつピンが認証情報のピンと違うものだけ。なければ nil。
func (rt *runtime) joinForNewPin() *Join {
	if rt.opts.Join == "" {
		return nil
	}
	j, err := ParseJoin(rt.opts.Join)
	if err != nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if j.TokenHash() == rt.f.UsedJoinTokenSHA256 || hex.EncodeToString(j.Pin[:]) == rt.f.CertSHA256 {
		return nil
	}
	return j
}

// reconnect は今の stream 接続を切り、バックオフなしで繋ぎ直させる。
func (rt *runtime) reconnect() {
	rt.streamMu.Lock()
	defer rt.streamMu.Unlock()
	rt.reconnectNow = true
	if rt.streamCancel != nil {
		rt.streamCancel()
	}
}

// ensureRegistered は初回登録を行う(仕様 5.1 節)。恒久トークンがあれば何もしない。
// WGFT_JOIN が compose に残ったまま再起動されるのが普通なので、使用済みの接続文字列は黙って無視する。
// WGFT_NAME / --name は任意。接続文字列の発行時の名前に紐付いているので、与えなければトークンに
// 紐付いた名前で登録される。与えて既に登録済みの名前と違えば警告して登録済みの名前を使う。
func ensureRegistered(f *credentials.Credentials, opts Options) error {
	if f.PermanentToken != "" {
		if opts.Name != "" && opts.Name != f.Name {
			log.Printf("WGFT_NAME=%s differs from the registered name %s; keeping %s", opts.Name, f.Name, f.Name)
		}
		if opts.Join != "" {
			if j, err := ParseJoin(opts.Join); err == nil && j.TokenHash() != f.UsedJoinTokenSHA256 {
				log.Printf("already registered; ignoring the provided join string and using the existing permanent token")
			}
		}
		return nil
	}
	// この 3 つはどれも再試行では直らない。cmd/wgft は *startup.Refusal を終了コード 3 に写すので、
	// 同梱の agent.service の RestartPreventExitStatus=3 が 2 秒おきの再起動を止める。値だけから
	// 判定できる 2 つ目(構文)を入口ではなく登録の直前で判定するのは、登録済みの agent では
	// compose に残った古い WGFT_JOIN を読まないためである(設計文書 11a・11b 節)。
	if opts.Join == "" {
		return startup.Config("WGFT_JOIN", "not registered and no join string; provide via WGFT_JOIN or --join")
	}
	j, err := ParseJoin(opts.Join)
	if err != nil {
		return startup.Config("WGFT_JOIN", "%v", err)
	}
	if j.TokenHash() == f.UsedJoinTokenSHA256 {
		return startup.Conflict("WGFT_JOIN", "this join string is already used; issue a new join string")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tok, addr, name, err := Register(ctx, j, opts.Name)
	if err != nil {
		return err
	}
	// 登録が成功した時点で認証情報ファイルを置き換える(失敗したら既存のファイルはそのまま)
	f.Name, f.Endpoint, f.PermanentToken = name, j.Endpoint, tok
	f.CertSHA256 = hex.EncodeToString(j.Pin[:])
	f.UsedJoinTokenSHA256 = j.TokenHash()
	if err := f.Save(opts.CredentialsPath); err != nil {
		return err
	}
	log.Printf("registered as agent %s; assigned %s, API %s", name, addr, j.Endpoint)
	return nil
}

// tunnelConfig は全体状態の wg 節からトンネルの宣言を作る。
// vpsd のアドレスは全体状態にないので、自分のアドレスの帯の先頭(10.200.0.1)とする(仕様 4 節)。
func tunnelConfig(priv wgtypes.Key, w proto.WGConfig) (tunnel.Config, error) {
	serverPub, err := wgtypes.ParseKey(w.ServerPubkey)
	if err != nil {
		return tunnel.Config{}, fmt.Errorf("server_pubkey: %w", err)
	}
	addr, err := netip.ParsePrefix(w.Address)
	if err != nil || !addr.Addr().Is4() {
		return tunnel.Config{}, fmt.Errorf("address %q is not an IPv4 CIDR", w.Address)
	}
	server := addr.Masked().Addr().Next()
	return tunnel.Config{
		PrivateKey: priv, ServerPublicKey: serverPub, Endpoint: w.Endpoint,
		Address: addr.Addr(), ServerAddress: server, MTU: w.MTU,
		Keepalive: time.Duration(w.Keepalive) * time.Second,
	}, nil
}

// versionOrDev は起動ログに出す版。cmd 側から渡らなければ(単体テストなど)"dev" とする。
func versionOrDev(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}

// nameOrUnregistered は起動ログに出すエージェント名。まだ登録前(認証情報ファイルに名前がない)なら
// その旨を出す(仕様 5.1 節の初回登録より前)。
func nameOrUnregistered(name string) string {
	if name == "" {
		return "not registered yet"
	}
	return name
}

// PublicKey は認証情報ファイルの鍵(なければ生成して保存)の公開鍵を返す。
func PublicKey(path string) (wgtypes.Key, error) {
	f, err := credentials.LoadOrNew(path)
	if err != nil {
		return wgtypes.Key{}, err
	}
	created, err := f.EnsureKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	if created {
		if err := f.Save(path); err != nil {
			return wgtypes.Key{}, err
		}
	}
	priv, err := f.PrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	return priv.PublicKey(), nil
}
