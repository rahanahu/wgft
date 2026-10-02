package agent

import (
	"context"
	"log"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/agentdp"
	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/agent/usermode"
	"github.com/rahanahu/wgft/internal/reconcile"
)

// Run は認証情報ファイルを読み、登録を確かめ、トンネルとリスナーを立て、stream に繋ぎ、シグナルまで動く。
func Run(opts Options) error {
	// 二重起動の検出。取れなければ別のプロセスが動いている(仕様 9 節)
	lock, err := credentials.Acquire(opts.CredentialsPath)
	if err != nil {
		return err
	}
	defer lock.Release()
	removeLeftoverTemps(lock, opts.CredentialsPath)

	f, err := credentials.LoadOrNew(opts.CredentialsPath)
	if err != nil {
		return err
	}
	// モードの照合とカーネルモードの前提の検査は、鍵を作るよりも、登録よりも前に行う。関門か前提で
	// 止まる起動は、認証情報ファイルに何も書かず、接続文字列も使わない(仕様 7b.5・11a 節)
	mode, err := enterMode(f, opts.Mode, opts.CredentialsPath)
	if err != nil {
		return err
	}
	opts.Mode = mode
	log.Printf("wgft %s agent starting: name %s, mode %s, data dir %s", versionOrDev(opts.Version), nameOrUnregistered(f.Name), mode, filepath.Dir(opts.CredentialsPath))
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
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rt, err := newModeRuntime(ctx, opts, f, priv)
	if err != nil {
		return err
	}
	defer rt.close()

	// カーネルモードでは、stream に繋ぐ前に wgft0 の所有を判定する(仕様 7b.4 節)。他の所有者の
	// インタフェースなら、何も書かずに終わる
	if sc, ok := rt.dp.(agentdp.StartupChecker); ok {
		if err := sc.Startup(priv, func() error { return f.Save(opts.CredentialsPath) }); err != nil {
			return err
		}
		if err := f.Save(opts.CredentialsPath); err != nil {
			return err
		}
	}

	// vpsd が停止中でも、VPS 側にピアが残っていれば転送が復旧するよう、先に立てる(仕様 9 節)。
	// カーネルモードでは、このプロセスの最初の wgft0 の収束が起動の失敗に当たれば終わる(11b 節)
	if f.LastState != nil {
		if err := rt.apply(f.LastState); err != nil {
			if agentdp.IsFatal(err) {
				return err
			}
			log.Printf("apply saved generation %d: %v; waiting for full state from stream", f.LastState.Generation, err)
		}
	} else {
		log.Printf("no saved full state; waiting for full state from stream")
	}
	rt.watchKernel(ctx)
	errc := make(chan error, 1)
	go func() { errc <- rt.streamLoop(ctx) }()
	go rt.serveControl(ctx)

	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	return rt.serve(ctx, errc, tick.C)
}

// serve は Run の本体のループである。stream の復帰できない誤り errc か、プロセスを終える適用の誤り
// (rt.fatal)が届くか、ctx が取り消されるまで動く。tick ごとに、トンネルの見張り、公開できなかった
// 全体状態の試し直し、開けなかったリスナーの再試行と宛先の試し接続、状態のログを行う。カーネルの
// 変更の通知(rt.kernelWake)は、最初の通知から rt.notifyDebounce 待ってまとめ、observeNotified を
// 呼ぶ。まとめ方は vpsd の reconcile.Triggers と同じである。
func (rt *runtime) serve(ctx context.Context, errc <-chan error, tick <-chan time.Time) error {
	var settle <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			log.Printf("shutting down")
			return nil
		case err := <-errc:
			// 復帰できない認証拒否。鍵と認証情報ファイルは残したまま止まる(仕様 5.1 節)
			return err
		case err := <-rt.fatal:
			// stream の側の適用が、このプロセスの最初の wgft0 の収束で起動の失敗に当たった(11b 節)
			return err
		case <-rt.kernelWake:
			if settle == nil {
				settle = time.After(rt.notifyDebounce)
			}
		case <-settle:
			settle = nil
			rt.observeNotified()
		case <-tick:
			rt.checkTunnel(time.Now())
			if err := rt.retryPending(); err != nil {
				return err
			}
			rt.observe()
			rt.mu.Lock()
			rt.dp.Refresh()
			rt.mu.Unlock()
			rt.logStatus()
		}
	}
}

// newRuntime は Run が動かす runtime を組む。dataplane の宛先の許可一覧とフロー数の予算は opts から
// 渡す。doctor が示す許可一覧も同じ opts.AllowTargets を読み、opts は起動の後に変わらないので、
// 中継が守る一覧と doctor が示す一覧は食い違わない(設計文書 10.2c 節)。
func newRuntime(opts Options, f *credentials.Credentials, priv wgtypes.Key) *runtime {
	return &runtime{
		opts: opts, f: f, priv: priv,
		fatal:                    make(chan error, 1),
		stateNotify:              make(chan struct{}, 1),
		heartbeatInterval:        30 * time.Second,
		handshakeRetryInterval:   time.Second,
		handshakeRetryTimeout:    10 * time.Second,
		pingInterval:             30 * time.Second,
		pongTimeout:              20 * time.Second,
		reconnectBackoffMin:      defaultReconnectBackoffMin,
		reconnectBackoffMax:      defaultReconnectBackoffMax,
		reconnectBackoffFreshMax: defaultReconnectBackoffFreshMax,
		doctorLockWait:           defaultDoctorLockWait,
		handshakeWake:            make(chan struct{}, 1),
		kernelWake:               make(chan struct{}, 1),
		notifyDebounce:           reconcile.DefaultTriggers.Debounce,
		dp:                       usermode.New(opts.AllowTargets, opts.Limits),
		rebuild:                  rebuildState{after: defaultRebuildAfter, backoffMax: defaultRebuildBackoffMax},
	}
}

// newModeRuntime は opts.Mode の dataplane で runtime を組む。カーネルモードの dataplane は
// カーネルに何も書かずに作られ、ctx が取り消されると名前の解決を打ち切る。カーネルモードには
// トンネルの作り直しが無い(仕様 7b.1 節)ので、watchdog の閾値を 0 にする。最終ハンドシェイクの
// 観測は続くので、stream の再接続の待ちを打ち切る合図は変わらない。
func newModeRuntime(ctx context.Context, opts Options, f *credentials.Credentials, priv wgtypes.Key) (*runtime, error) {
	rt := newRuntime(opts, f, priv)
	if opts.Mode != credentials.ModeKernel {
		return rt, nil
	}
	dp, err := newKernelDataplane(ctx, opts.WGInterface, opts.AllowTargets, f, func() error { return f.Save(opts.CredentialsPath) })
	if err != nil {
		return nil, err
	}
	rt.dp = dp
	rt.rebuild = rebuildState{}
	return rt, nil
}

// reportFatal は、プロセスを終える誤りを Run に伝える。既に 1 つ届いていれば捨てる。
func (rt *runtime) reportFatal(err error) {
	if rt.fatal == nil {
		return
	}
	select {
	case rt.fatal <- err:
	default:
	}
}

// logAllowTargets は宛先の許可一覧の有無を起動時に 1 行で出す(仕様 7 節)。
// 一覧が無いときに何も出さないと、制限が無いことが運用者に見えないので、無いことも出す。
func logAllowTargets(l *allowtargets.List) {
	if l == nil {
		log.Printf("no target allowlist: %s is not set; the server can direct this agent to any address it can reach", allowtargets.Env)
		return
	}
	log.Printf("target allowlist %s=%s; the server can direct this agent only to these addresses", allowtargets.Env, l)
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
