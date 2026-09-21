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

	tunStart time.Time    // 今のトンネルを立てた時刻。ハンドシェイクが一度も成立していないときの起点
	rebuild  rebuildState // トンネルを作り直す判定の閾値と、次の作り直しまでの間隔(仕様 7 節)

	// retrySt は、トンネルの作成に失敗したときの全体状態。試し直しはこの全体状態から立てる。
	// 認証情報ファイルの last_state は適用を終えた全体状態しか指さないので、新しい全体状態の適用が
	// 失敗した後の試し直しには使えない(仕様 7 節)。メモリの上だけに持ち、保存はしない
	retrySt *proto.State

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
		rebuild:                rebuildState{after: defaultRebuildAfter, backoffMax: defaultRebuildBackoffMax},
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
			rt.checkTunnel(time.Now())
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
	if rt.tun == nil || !reflect.DeepEqual(rt.wgCfg, st.WG) {
		if rt.tun != nil {
			log.Printf("wg config changed; rebuilding tunnel")
		}
		// 作成に失敗したら、世代も認証情報ファイルも進めずに返す。作成そのものの失敗なら
		// buildLocked が試し直しを控えるので、次の全体状態を待たずに watchdog が立て直す(仕様 7 節)
		if err := rt.buildLocked(time.Now(), st, false); err != nil {
			return fmt.Errorf("wireguard: %w", err)
		}
		return nil
	}
	return rt.finishApplyLocked(st)
}

// finishApplyLocked はトンネルが立った後の共通の後始末である。リスナーを宣言に合わせ、処理済み世代を
// 進め、認証情報ファイルに保存する(仕様 5.2 節)。呼び出し側は rt.mu を持つ。
func (rt *runtime) finishApplyLocked(st *proto.State) error {
	var firstErr error
	acts := rt.rl.Apply(relay.DesiredFromRules(st.Rules))
	rt.gen = st.Generation
	rt.f.LastState = st
	if err := rt.f.Save(rt.opts.CredentialsPath); err != nil {
		firstErr = fmt.Errorf("save credentials file: %w", err)
	}
	log.Printf("applied generation %d (%d actions, %d listeners)", st.Generation, len(acts), len(rt.rl.Status()))
	return firstErr
}

// defaultRebuildAfter と defaultRebuildBackoffMax は、トンネルを作り直す判定の既定の閾値(仕様 7 節)。
// 300 秒は WireGuard の時定数から決めた値で、健全なトンネルでは最終ハンドシェイクが 145 秒
// (RekeyAfterTime 120 秒 + keepalive 25 秒)より古くならず、180 秒(RejectAfterTime)を過ぎた鍵は
// 送信にも使えないため、300 秒の時点のトンネルは既に 120 秒以上まったく通信していない。
// keepalive の倍数にしないのは、WireGuard のこの 3 つの時定数が keepalive の値によらず一定だからである。
const (
	defaultRebuildAfter      = 300 * time.Second
	defaultRebuildBackoffMax = 900 * time.Second
)

// rebuildState はトンネルを作り直す判定の状態。after はハンドシェイクが新しくならないまま最初の
// 作り直しに至るまでの時間、backoffMax は作り直しの間隔の上限、wait は次の作り直しに要する時間である。
// テストで短くできるよう、閾値は定数ではなくこの値で持つ。
//
// lastHandshake と observedAt は、経過時間を壁時計の差ではなく観測からの単調な時間で測るために持つ。
// IpcGet が返す最終ハンドシェイクは壁時計の秒で、NTP の補正や手動の変更で飛ぶ値であり、その値と
// 現在時刻の差で測ると、前方への飛びが健全なトンネルを古く見せてしまう(仕様 7 節)。
type rebuildState struct {
	after      time.Duration
	backoffMax time.Duration
	wait       time.Duration

	lastHandshake time.Time // 直近に観測した最終ハンドシェイクの値
	observedAt    time.Time // その値を最初に観測した時刻

	// retryAt と retryWait は、作り直しがトンネルの作成そのものに失敗したときの再試行の予定。
	// retryAt がゼロなら再試行を待っているトンネルは無い。閉じたトンネルを watchdog が勝手に
	// 立て直さないよう、この印を付けるのは checkTunnel の失敗だけで、closeLocked が必ず消す
	retryAt   time.Time
	retryWait time.Duration
}

// failedBuild は、トンネルの作成に失敗したことを記録し、次に試す時刻を決める(仕様 7 節)。
// トンネルが 1 つも無い状態なので、最初の 1 回は次のティッカーで試し、続けて失敗するほど
// 間隔を after から上限まで広げる。
func (s *rebuildState) failedBuild(now time.Time) {
	if s.retryAt.IsZero() {
		s.retryAt, s.retryWait = now, s.after
		return
	}
	s.retryAt = now.Add(s.retryWait)
	s.retryWait = min(2*s.retryWait, max(s.backoffMax, s.after))
}

// clearRetry は再試行の予定を捨てる。closeLocked から呼ぶので、作成に成功した場合も、
// rotate-key や停止でトンネルを閉じた場合も消える。
func (s *rebuildState) clearRetry() { s.retryAt, s.retryWait = time.Time{}, 0 }

// step は、今の最終ハンドシェイクの値 handshake を観測し、その値が新しくならないまま経った時間で
// トンネルを作り直すかどうかを決める(仕様 7 節)。作り直すときは次の間隔を倍にし、ゼロでない新しい
// ハンドシェイクを観測したときは間隔を初期値に戻す。
//
// 起点には、値を観測した時刻とトンネルを立てた時刻 start の遅い方を使う。作り直した直後の device は
// ハンドシェイクがゼロで、前の値もゼロだったときは値が変わらず、観測の時刻が更新されないためである。
// now と start は time.Now が返す単調な読みを持つので、両者の差は壁時計の飛びに左右されない。
//
// サーバが停止しているだけの場合と、受信の経路が死んだ場合は、エージェントからは区別できない。
// そこで、作り直しても戻らない間は間隔を広げ、上限で頭打ちにする。
func (s *rebuildState) step(now, start, handshake time.Time) (idle time.Duration, rebuild bool) {
	if s.after <= 0 {
		return 0, false // 閾値を持たない runtime では作り直さない
	}
	if !handshake.Equal(s.lastHandshake) {
		s.lastHandshake, s.observedAt = handshake, now
		if !handshake.IsZero() {
			s.wait = s.after
		}
	}
	since := s.observedAt
	if since.IsZero() || start.After(since) {
		since = start
	}
	idle = now.Sub(since)
	wait := max(s.wait, s.after)
	if idle < wait {
		return idle, false
	}
	s.wait = min(2*wait, max(s.backoffMax, s.after))
	return idle, true
}

// newTunnel はトンネルを作る。値は tunnel.New で、テストだけが作成の失敗を模すために差し替える。
var newTunnel = tunnel.New

// startTunnelLocked は今のトンネルと中継を閉じてから、全体状態の wg 設定で立て直す(仕様 7 節)。
// 呼び出し側は rt.mu を持つ。リスナーは開かないので、呼び出し側が続けて rl.Apply を呼ぶ。
// 閉じるのが先なので、古い device と netstack、その goroutine は新しいものを作る前に必ず片付く。
//
// retryable は、失敗が試し直す価値のあるものかどうかを表す。誤りが無いときの値に意味は無い。
// wg 設定の誤りは同じ全体状態では何度試しても同じ結果になるので、試し直しの対象にしない。
func (rt *runtime) startTunnelLocked(st *proto.State) (retryable bool, err error) {
	rt.closeLocked()
	rt.tunStart = time.Now()
	cfg, err := tunnelConfig(rt.priv, st.WG)
	if err != nil {
		return false, err
	}
	tun, err := newTunnel(cfg)
	if err != nil {
		return true, err // 資源の不足など、環境による失敗
	}
	ctx, cancel := context.WithCancel(context.Background())
	go tun.Run(ctx)
	rt.tun, rt.tunCancel, rt.wgCfg = tun, cancel, st.WG
	rt.rl = relay.New(tun, rt.relayOptions(st))
	return true, nil
}

// checkTunnel は 30 秒ごとに呼ばれ(Run のティッカー)、ハンドシェイクが新しくならない時間が作り直しの
// 間隔を超えたらトンネルを作り直す(仕様 7 節)。第 1 段の軽い回復(エンドポイントの引き直しと
// トンネル内への ping)は tunnel.Run が keepalive ごとに行うので、checkTunnel は第 2 段だけを担う。
//
// 作り直しが要るのは、wireguard-go の受信ループが回復不能な誤りで終わったまま戻らない状態である。
// そのトンネルは送信を続けるが二度と受信しないので、ハンドシェイクは永久に成立しない。サーバが単に
// 停止している場合もエージェントから見た症状は同じで区別できないため、作り直しの間隔はバックオフで
// 広げ、ハンドシェイクが成立したら初期値に戻す。
//
// トンネルの作成そのものに失敗するとトンネルが 1 つも無い状態になるので、予定の時刻に作成だけを
// 試し直す。対象は、作り直しの作成が失敗した場合と、全体状態の適用の中で作成が失敗した場合である。
// rotate-key・停止・最初の全体状態を受け取る前の「トンネルが無い」状態には手を出さない。
func (rt *runtime) checkTunnel(now time.Time) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if rt.tun == nil {
		rt.retryBuildLocked(now)
		return
	}
	if rt.f == nil || rt.f.LastState == nil {
		return
	}
	st := rt.f.LastState
	// Status が読むのは今の device なので、ゼロでない最終ハンドシェイクは必ず今のトンネルのものである
	idle, rebuild := rt.rebuild.step(now, rt.tunStart, rt.tun.Status().LastHandshake)
	if !rebuild {
		return
	}
	log.Printf("no new wireguard handshake for %s; rebuilding the tunnel (the next rebuild needs %s without one)",
		idle.Round(time.Second), rt.rebuild.wait.Round(time.Second))
	// 既に適用を終えた全体状態なので、世代の記録はやり直さない。誤りは buildLocked が 1 行出す
	rt.buildLocked(now, st, true) //nolint:errcheck // 誤りは buildLocked が出す
}

// retryBuildLocked は、作成に失敗して残ったトンネルの無い状態を、予定の時刻に試し直す(仕様 7 節)。
// 予定が無ければ何もしないので、rotate-key や停止で閉じたトンネルは立て直さない。
//
// 立てるのは、作成に失敗したときの全体状態(retrySt)からである。認証情報ファイルの last_state は
// 適用を終えた全体状態しか指さず、新しい全体状態の適用が失敗した後は 1 つ前の全体状態を指したままな
// ので、そちらから立てるとサーバが想定していないトンネルになる。成功したときは世代の記録まで行う。
// 既に適用を終えた全体状態なら、同じ値を書き直すだけで害は無い。呼び出し側は rt.mu を持つ。
func (rt *runtime) retryBuildLocked(now time.Time) {
	if rt.retrySt == nil || rt.rebuild.retryAt.IsZero() || now.Before(rt.rebuild.retryAt) {
		return
	}
	log.Printf("no tunnel since the last build failed %s ago; building it again", now.Sub(rt.tunStart).Round(time.Second))
	rt.buildLocked(now, rt.retrySt, false) //nolint:errcheck // 誤りは buildLocked が出す
}

// buildLocked はトンネルを立ててリスナーを開き直す。applied は、渡した全体状態の適用が世代の記録まで
// 済んでいるかを表す。済んでいなければ、作成に成功した時点で finishApplyLocked まで行う。
//
// 作成に失敗したときは理由を 1 行出し、作成そのものの失敗なら次に試す時刻と全体状態を控える。
// wg 設定の誤りは控えず、次の全体状態を待つ。呼び出し側は rt.mu を持つ。
func (rt *runtime) buildLocked(now time.Time, st *proto.State, applied bool) error {
	// startTunnelLocked は最初に closeLocked を呼び、closeLocked は試し直しの控えを消す。続けて失敗した
	// ときに間隔を広げられるよう、予定は呼ぶ前に控えておき、失敗したら戻してから次を決める
	retryAt, retryWait := rt.rebuild.retryAt, rt.rebuild.retryWait
	retryable, err := rt.startTunnelLocked(st)
	if err != nil {
		rt.retrySt = st // 失敗した全体状態は、試し直さない場合もハートビートの理由のために控える
		if !retryable {
			log.Printf("build tunnel: %v; not retrying until a new full state arrives", err)
			return err
		}
		rt.rebuild.retryAt, rt.rebuild.retryWait = retryAt, retryWait
		rt.rebuild.failedBuild(now)
		if d := rt.rebuild.retryAt.Sub(now); d > 0 {
			log.Printf("build tunnel: %v; trying again in %s", err, d.Round(time.Second))
		} else {
			log.Printf("build tunnel: %v; trying again at the next check", err)
		}
		return err
	}
	if applied {
		rt.rl.Apply(relay.DesiredFromRules(st.Rules))
		return nil
	}
	return rt.finishApplyLocked(st)
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
	// 閉じたトンネルは watchdog の試し直しの対象にしない(仕様 7 節)。作成に失敗した直後に
	// buildLocked が控え直す
	rt.rebuild.clearRetry()
	rt.retrySt = nil
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
		// トンネルが無い理由は 4 通りある。作成に失敗して試し直しを待っている場合(仕様 7 節)、
		// 作成が wg 設定の誤りで終わって次の全体状態を待っている場合、全体状態をまだ受け取っていない
		// 場合、rotate-key や停止で閉じた直後の場合である
		reason := "no tunnel"
		switch {
		case !rt.rebuild.retryAt.IsZero():
			reason = "no tunnel; building it failed and will be retried"
		case rt.retrySt != nil:
			reason = "no tunnel; building it failed"
		case rt.f == nil || rt.f.LastState == nil:
			reason = "no tunnel; full state not received"
		}
		hb.Tunnel = proto.TunnelStatus{State: proto.StatusError, Reason: reason}
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
