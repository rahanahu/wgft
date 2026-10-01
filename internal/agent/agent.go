// Package agent は自宅側のエージェント(仕様 7 節)。
// 認証情報ファイルの鍵と最後の全体状態でトンネルとリスナーを先に立て、その後 stream に繋いで全体状態を受け取る。
package agent

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/allowtargets"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/resource"
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

	// Mode は設定の WGFT_MODE の値である(仕様 11a 節)。kernel か userspace で、空なら省略されており
	// userspace を指す。起動時に認証情報ファイルの記録と照合する(mode.go)
	Mode string
	// WGInterface はカーネルモードの WireGuard インタフェースの名前である(WGFT_WG_INTERFACE、既定 wgft0。
	// 仕様 7b.1・11a 節)。ユーザー空間モードでは使わない
	WGInterface string
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

	// pingInterval と pongTimeout は、接続中の stream に送る WebSocket の ping の間隔と、pong を
	// 待つ期限(仕様 5.2 節)。既定は 30 秒と 20 秒で、経路が死んでから判定までに要する時間は
	// 最長 50 秒になる。テストで短くできるよう runtime に持たせる。pingInterval が 0 以下なら
	// ping を送らない
	pingInterval time.Duration
	pongTimeout  time.Duration

	// reconnectBackoffMin と reconnectBackoffMax は stream を繋ぎ直す間隔の初期値と上限
	// (仕様 5.2 節)。既定は 1 秒と 5 分。テストで短くできるよう runtime に持たせる
	reconnectBackoffMin time.Duration
	reconnectBackoffMax time.Duration
	// reconnectBackoffFreshMax は、WireGuard の最終ハンドシェイクが新しい間の再接続の待ちの上限
	// (仕様 5.2 節)。既定は 10 秒で、0 以下なら既定を使う。テストで短くできるよう runtime に持たせる
	reconnectBackoffFreshMax time.Duration

	// handshakeSeen は、checkTunnel が直近に読んだ最終ハンドシェイクの値と、その値を最初に観測した
	// 時刻である(仕様 5.2 節)。streamLoop が、再接続の待ちの上限を決めるときに rt.mu の外から読む。
	// rt.mu は全体状態の適用の間じゅう保たれるので、その後ろで再接続を待たせないよう atomic に置く。
	// nil なら一度も観測していない
	handshakeSeen atomic.Pointer[handshakeObservation]

	// doctorLockWait は制御ソケットの doctor が実行時の状態を守る排他を待つ期限
	// (設計文書 10.2c 節)。0 以下なら defaultDoctorLockWait を使う。テストで短くできるよう
	// runtime に持たせる
	doctorLockWait time.Duration

	// handshakeWake は、WireGuard の新しいハンドシェイクを checkTunnel が観測したことを streamLoop に
	// 伝えるサイズ 1 の非ブロッキングチャネル(仕様 5.2 節)。streamLoop はこれを受けて再接続の待ちを
	// 打ち切る。チャネルにしてあるのは、rt.mu を持ったまま streamMu を取らないためである。
	// nil なら送信も受信も起きないので、チャネルを持たない runtime を組むテストはそのまま動く
	handshakeWake chan struct{}

	// kernelWake は、カーネルの変更の通知を受けたことを serve に伝えるサイズ 1 の非ブロッキングチャネル
	// である(仕様 7b.4 節の変更の通知)。serve は最初の通知から notifyDebounce 待って続く通知をまとめ、
	// observeNotified を 1 回呼ぶ。見直しの間に届いた通知は、もう 1 回の見直しになる。nil なら何も
	// 届かないので、チャネルを持たない runtime を組むテストはそのまま動く
	kernelWake     chan struct{}
	notifyDebounce time.Duration

	// applySeq は、stream の読みの for ループが全体状態の適用に入るたびと出るたびに 1 つ進む
	// (仕様 5.2 節)。奇数なら適用の最中である。適用の間は読みが止まって pong を処理できないので、
	// pingLoop は、値が奇数なら ping を送らず、ping を送ってから pong を待つ間に値が変わった場合も
	// 判定を見送る。適用の中の宛先への試し接続は宛先 1 つにつき最長 10 秒かかるので、適用は
	// pong の期限より長くなりうる
	applySeq atomic.Uint64

	// mu(rt.mu)は以下の値と dataplane を守り、全体状態の適用の間じゅう持つ。ただし rt.mu の外で行う
	// 準備(名前の解決)はこの間に含まない。
	//
	// agentDataplane のメソッドは rt.mu を持って呼び、dataplane の中の排他はその内側で取る。ユーザー
	// 空間モードでは relay.Manager の排他、カーネルモードでは epMu(dataplane_kernel.go)である。
	// 任意の interface の prepareApply と observePrepare は rt.mu の外で呼び、その中でも epMu を取る。
	// epMu を持ったまま rt.mu を取ることは無いので、順は rt.mu -> epMu である。epMu の中では値の
	// 読み書きとログの出力だけを行う。streamMu は rt.mu を持ったまま取らず、streamMu を持ったまま
	// wgft の他の排他を取らない(streamobs.go)。rt.mu の中の checkTunnel から streamLoop へは、
	// handshakeWake の待たない送信と handshakeSeen の atomic で伝える。agent doctor は rt.mu を期限付きで取る(doctor.go の lockRuntime)。rotate-key は rt.mu を
	// 放してから適用し直し、その後に streamMu を取って stream を張り直す(control.go の rotateKey)。
	mu sync.Mutex
	// dp はトンネルと転送を担う dataplane である(設計文書 7a.7 節の境目)。rt.mu が守る
	dp    agentDataplane
	wgCfg proto.WGConfig // 適用済みの wg 設定
	gen   uint64         // 処理済み世代

	tunStart time.Time    // 今のトンネルを立てた時刻。ハンドシェイクが一度も成立していないときの起点
	rebuild  rebuildState // トンネルを作り直す判定の閾値と、次の作り直しまでの間隔(仕様 7 節)

	// pendingSt は、dataplane が宣言をまとめて公開できなかった全体状態である(仕様 7a.3 節、7b.3 節の
	// 3 つ目の種類)。処理済み世代も last_state も進めず、30 秒ごとに試し直す。新しい全体状態が届けば
	// そちらに置き換わる。pendingErr は直前の試し直しの誤りで、同じ誤りが続く間はログを出さない。
	// メモリの上だけに持ち、保存はしない。ユーザー空間モードの dataplane はこの失敗を持たない
	pendingSt  *proto.State
	pendingErr string

	// stateNotify は、stream の外の経路(公開できなかった全体状態の試し直しなど)が処理済み世代か
	// ルールの状態を変えたことを、接続中の stream のハートビートに伝える。大きさ 1 の非ブロッキングの
	// チャネルで、次の 30 秒を待たずにハートビートを 1 回送らせる。nil なら何も伝えない
	stateNotify chan struct{}

	// fatal は、stream の側の適用がプロセスを終える誤り(fatalError)に当たったことを Run に伝える。
	// 大きさ 1 の非ブロッキングのチャネルで、最初の 1 つだけが届けば足りる
	fatal chan error

	// retrySt は、トンネルの作成に失敗したときの全体状態。試し直しはこの全体状態から立てる。
	// 認証情報ファイルの last_state は適用を終えた全体状態しか指さないので、新しい全体状態の適用が
	// 失敗した後の試し直しには使えない(仕様 7 節)。メモリの上だけに持ち、保存はしない
	retrySt *proto.State

	// refused は、トンネルが立っている間に届き、dataplane が wg 設定を拒んだ全体状態の世代と理由である
	// (wgChecker、設計文書 7b.1・11 節)。拒んだ全体状態は適用せず、今のトンネルとルールを残す。
	// ハートビートのトンネルの状態に載せ、wg 設定を受け入れた次の全体状態で消す。メモリの上だけに持つ
	refused *refusedState
	// tunnelWarned は、記録と違うトンネルのアドレスとして直前に警告した値である(recordTunnelAddressLocked)
	tunnelWarned string

	streamMu     sync.Mutex
	streamCancel context.CancelFunc // 今の stream 接続を切る(rotate-key で張り直すとき)
	reconnectNow bool               // 切った直後はバックオフせずに繋ぎ直す

	// streamObs は制御ストリームの観測(設計文書 10.2c 節)。streamObs と streamEpoch は streamMu が
	// 守る。書き手と読み手、mutex を選んだ理由は internal/agent/streamobs.go にある
	streamObs   streamObservation
	streamEpoch uint64 // 接続の通し番号。前の接続の pingLoop の遅れた書き込みを捨てるために使う

	// lastStatusLines は logStatus が前回出した内容(30 秒ごとの定期ログの重複を防ぐ。Run のループの
	// 単一の goroutine からしか呼ばれないので、別途の mutex は持たない)
	lastStatusLines []string
}

func (rt *runtime) closeLocked() {
	// 閉じたトンネルは watchdog の試し直しの対象にしない(仕様 7 節)。作成に失敗した直後に
	// buildLocked が控え直す
	rt.rebuild.clearRetry()
	rt.retrySt = nil
	rt.dp.close()
}

func (rt *runtime) close() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.closeLocked()
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
