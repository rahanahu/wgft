// Package agentdp は、エージェントの制御プレーン(internal/agent の runtime)と、転送を担う
// dataplane の実装との境目である(設計文書 7a.7 節)。境目の interface Dataplane、カーネルモードの
// 実装だけが持つ任意の interface、1 回の読みの型、起動の失敗の型を持つ。2 つのモードの実装は
// internal/agent にあり、この package を import して境目を満たす。internal/agent の下では
// controlapi だけを import する。
package agentdp

import (
	"errors"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/dataplane/userspace/sockbuf"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// Dataplane は、エージェントの制御プレーン(runtime)と、転送を担う実装との境目である
// (設計文書 7a.7 節)。実装は、ユーザー空間モードの internal/agent/usermode の Dataplane と、
// カーネルモードの internal/agent/kernelmode の Dataplane である。
//
// 境目の手前の runtime は、処理済み世代と認証情報ファイルの last_state の記録、適用した wg 設定、
// トンネルの作成に失敗したときの試し直しの予定、トンネルを作り直す判定(watchdog)を持つ。
// 境目の後ろの実装は、トンネルと転送の資源そのものを持ち、いつ立て直すかを自分では決めない。
//
// どのメソッドも、呼び出し側が rt.mu を持った状態で呼ぶ。実装は runtime の排他を前提にする。
// 実装が自分の排他を持つときの順は rt.mu -> 実装の排他である。実装の排他は、カーネルモードの
// epMu と、ユーザー空間モードの relay.Manager の排他である(internal/agent の runtime の mu の注釈)。
type Dataplane interface {
	// Build は wg 設定 wg と鍵 priv でトンネルを立て、ルールを受け付けられる状態にする。
	// 呼び出し側は先に Close を呼ぶ。成功したら Built が真を返す。失敗したときは何も立っていない。
	//
	// retryable は、失敗が同じ全体状態で試し直す価値のあるものかどうかを表す。wg 設定の誤りは
	// 何度試しても同じ結果になるので偽である。誤りが無いときの値に意味は無い
	Build(priv wgtypes.Key, wg proto.WGConfig) (retryable bool, err error)

	// Built は、Build で立てたトンネルが今あるかどうかを返す。
	Built() bool

	// ApplyRules は転送するルールを宣言 rules に合わせる。Built が真のときだけ呼ぶ。
	// summary は適用のログの 1 行に載せる要約である。
	//
	// err は、宣言をまとめて公開できなかった backend 全体の失敗を表す(設計文書 7a.3 節、
	// 7b.3 節の 3 つ目の種類)。呼び出し側は処理済み世代を進めない。ルール単位の失敗は err に
	// せず、Read が返すルールごとの状態に載せる。ユーザー空間モードの実装は、ルール単位の
	// 失敗しか持たないので、常に nil を返す
	//
	// gen はルールを受け取った全体状態の世代である。カーネルモードは公開の記録に写す。prepared は
	// Preparer の結果で、持たない実装と、準備を経ない呼び出しでは nil である
	ApplyRules(gen uint64, rules []proto.AgentRule, prepared any) (summary string, err error)

	// Refresh は 30 秒ごとに呼ぶ見直しである(Run のティッカー)。ユーザー空間モードでは、
	// 開けなかったリスナーを開き直し、TCP の宛先へ試し接続し直す。Built が偽なら何もしない。
	Refresh()

	// Close はトンネルと転送を閉じる。何も立っていなければ何もしない。
	Close()

	// LastHandshake は今のトンネルの最終ハンドシェイクを読む。watchdog が作り直しの判定と、
	// stream の再接続の待ちを打ち切る判定に使う。Built が真のときだけ呼ぶ。
	LastHandshake() time.Time

	// Read はハートビートと agent doctor が共有する 1 回の読みである(設計文書 10.2c 節)。
	// トンネルの状態とルールの状態を 1 回ずつだけ読むので、1 つの応答に異なる時点の値が混ざらない。
	Read() Reading
}

// Preparer は、全体状態の適用の前に rt.mu の外で行う準備を持つ dataplane である。カーネルモードの
// 実装だけが持ち、エンドポイントと宛先の名前を引く(仕様 7b.1・7b.2 節)。DNS を待つ間に排他を持つと、
// ハートビートと agent doctor が最長で名前の解決の期限まで待たされるためである。準備は渡した全体状態
// だけから決まるので、排他を取り直した後にその全体状態を適用する限り、結果は古くならない。
type Preparer interface {
	PrepareApply(st *proto.State) any
}

// WGChecker は、server から届いた wg 設定を、今のトンネルに手を付ける前に検証する dataplane である。
// カーネルモードの実装だけが持つ(設計文書 7b.1・11 節)。runtime は、トンネルが立っている間に届いた
// 全体状態の wg 設定をこれで確かめ、拒んだ全体状態は適用しない。今のトンネルとルールはそのまま残し、
// 30 秒ごとの見直しも続ける。Build も同じ検証を通すので、トンネルが無い間に届いた全体状態は、他の
// wg 設定の誤りと同じく作成の失敗になる。
type WGChecker interface {
	CheckWG(w proto.WGConfig) (netip.Prefix, error)
}

// Observer は、30 秒ごとに実際の状態を宣言と比べ直す dataplane である。カーネルモードの実装だけが
// 持つ(仕様 7b.2 節の名前の解決し直し、7b.4 節の外からの変更)。見直しは 2 つに分かれる。
// ObservePrepare は名前の解決だけを行い、rt.mu の外で呼ぶ。DNS を待つ間に排他を持たないためである。
// ObserveCommit は rt.mu を持って呼び、ObservePrepare の結果で公開し直すかを決める。saved が真なら
// 呼び出し側が認証情報ファイルを保存する。err が nil でなくても saved が真なら保存する。誤りのログは
// ObserveCommit が出す。
type Observer interface {
	ObservePrepare(rules []proto.AgentRule) any
	ObserveCommit(gen uint64, rules []proto.AgentRule, prepared any) (saved bool, err error)
}

// Sensed は、カーネルの変更の通知を購読できる dataplane である。カーネルモードの実装だけが持つ
// (仕様 7b.4 節の変更の通知)。Sensor は購読の口で、runtime が vpsd と同じ reconcile.Watch で動かす。
// runtime は通知をまとめてから ObserveNotified を rt.mu を持って呼ぶ。ObserveNotified は名前を引かず、
// 直前の公開と宣言を実際のテーブルと wgft0 に比べ、食い違えば直す。saved の意味は
// Observer.ObserveCommit と同じである。
type Sensed interface {
	Sensor() dataplane.Sensor
	ObserveNotified(gen uint64, rules []proto.AgentRule) (saved bool, err error)
}

// StartupChecker は、起動時に stream へ繋ぐ前に行う検査を持つ dataplane である。カーネルモードの
// 実装だけが持つ(仕様 7b.4 節の所有の判定)。誤りを返せば起動は失敗し、*startup.Refusal なら
// 終了コード 3、他は 1 で終わる。
type StartupChecker interface {
	Startup(priv wgtypes.Key, save func() error) error
}

// KernelDoctor は、agent doctor のためにカーネルの状態を読む dataplane である。カーネルモードの実装だけが
// 持つ(設計文書 10.2c 節)。呼び出し側は rt.mu を持つ。
type KernelDoctor interface {
	// DoctorKernel はカーネルを読む。停止中の agent doctor の ReadKernel と同じ読み方である
	DoctorKernel() *controlapi.DoctorKernel
	// CheckError は直前の見直しの誤りである。30 秒ごとの見直しと変更の通知の後の見直しの両方を指す。
	// 無ければ空
	CheckError() string
}

// FatalError は、このプロセスの最初の wgft0 の収束が、起動の失敗として扱う誤りで終わったことを表す
// (仕様 11b 節、2026-09-24 の所有者の決定)。stream に繋いだ後の収束でも、それがプロセスの最初の
// 収束なら起動の一部として扱い、runtime はプロセスを終える。所有の衝突とアドレス帯の重なりは終了
// コード 1、前提の欠如(権限、WireGuard のモジュール)は終了コード 3 である。最初の収束の後の同じ
// 誤りは、7b.3 節の 3 つ目の種類として旧い設定を残したまま試し直す。
type FatalError struct{ Err error }

func (e *FatalError) Error() string { return e.Err.Error() }
func (e *FatalError) Unwrap() error { return e.Err }

// IsFatal は err がプロセスを終える誤りかどうかである。
func IsFatal(err error) bool {
	var f *FatalError
	return errors.As(err, &f)
}

// Reading は Dataplane.Read の結果である。
type Reading struct {
	Tunnel TunnelReading

	// Rules はハートビートに載せるルールごとの状態である。ルールを受け付ける資源が無ければ nil
	Rules []proto.RuleStatus

	// Relay はユーザー空間の中継だけが持つ値である。中継が無ければ nil
	Relay *RelayReading
}

// TunnelReading はトンネルを 1 回読んだ値である。Present が偽のとき、残りの値に意味は無い。
type TunnelReading struct {
	Present bool

	// Endpoint は解決済みのエンドポイントである。初回の名前解決に失敗したトンネルは持たない
	Endpoint netip.AddrPort
	// LastHandshake は最終ハンドシェイクである。ゼロなら未確立
	LastHandshake time.Time
	// RxBytes と TxBytes はトンネルの送受信バイト数である。ハートビートには載らず、doctor だけが使う
	RxBytes, TxBytes int64
	// Err はトンネルの誤り(エンドポイントの解決の失敗など)である
	Err error
	// SocketBuffers は、トンネルを立てた直後に測った WireGuard の UDP ソケットのバッファである
	// (設計文書 7 節)。ユーザー空間モードのトンネルだけが持ち、doctor だけが使う
	SocketBuffers *sockbuf.Reading
	// UDPAccounting は netstack の UDP の受信の会計の状態である(設計文書 7 節)。ユーザー空間モードの
	// トンネルだけが持ち、doctor だけが使う
	UDPAccounting *UDPAccountingReading
}

// UDPAccountingReading は UDP の受信の会計を 1 回読んだ値である。Fault が nil でなければ、会計が
// 不変条件の違反を検出してトンネルの UDP を止めている。
type UDPAccountingReading struct {
	Fault error
}

// RelayReading はユーザー空間の中継を 1 回読んだ値である。Listeners は Rules と同じ 1 回の読みから
// 来る。TCP と UDP はフロー予算で、doctor が読む。
type RelayReading struct {
	Listeners []relay.Status
	TCP, UDP  *resource.Pool
}

// KeepaliveMaxSeconds は wg.keepalive として受け入れる上限で、カーネルモードの CheckWG
// (internal/agent/kernelmode の dataplane_kernel.go)がすでに同じ全体状態の値に課している範囲(0 から 65535 秒、
// WireGuard の persistent_keepalive_interval の幅)と揃える。ユーザー空間モードの実装と、agent doctor の
// カーネルの読み取りが使う。
const KeepaliveMaxSeconds = 65535
