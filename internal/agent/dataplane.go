package agent

import (
	"errors"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/dataplane/userspace/relay"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// agentDataplane は、エージェントの制御プレーン(runtime)と、転送を担う実装との境目である
// (設計文書 7a.7 節)。今ある実装はユーザー空間モードの userspaceDataplane だけである。
//
// 境目の手前の runtime は、処理済み世代と認証情報ファイルの last_state の記録、適用した wg 設定、
// トンネルの作成に失敗したときの試し直しの予定、トンネルを作り直す判定(watchdog)を持つ。
// 境目の後ろの実装は、トンネルと転送の資源そのものを持ち、いつ立て直すかを自分では決めない。
//
// どのメソッドも、呼び出し側が rt.mu を持った状態で呼ぶ。実装は runtime の排他を前提にし、
// 自分では排他を取らない。
type agentDataplane interface {
	// build は wg 設定 wg と鍵 priv でトンネルを立て、ルールを受け付けられる状態にする。
	// 呼び出し側は先に close を呼ぶ。成功したら built が真を返す。失敗したときは何も立っていない。
	//
	// retryable は、失敗が同じ全体状態で試し直す価値のあるものかどうかを表す。wg 設定の誤りは
	// 何度試しても同じ結果になるので偽である。誤りが無いときの値に意味は無い
	build(priv wgtypes.Key, wg proto.WGConfig) (retryable bool, err error)

	// built は、build で立てたトンネルが今あるかどうかを返す。
	built() bool

	// applyRules は転送するルールを宣言 rules に合わせる。built が真のときだけ呼ぶ。
	// summary は適用のログの 1 行に載せる要約である。
	//
	// err は、宣言をまとめて公開できなかった backend 全体の失敗を表す(設計文書 7a.3 節、
	// 7b.3 節の 3 つ目の種類)。呼び出し側は処理済み世代を進めない。ルール単位の失敗は err に
	// せず、read が返すルールごとの状態に載せる。ユーザー空間モードの実装は、ルール単位の
	// 失敗しか持たないので、常に nil を返す
	//
	// gen はルールを受け取った全体状態の世代である。カーネルモードは公開の記録に写す。prepared は
	// preparer の結果で、持たない実装と、準備を経ない呼び出しでは nil である
	applyRules(gen uint64, rules []proto.AgentRule, prepared any) (summary string, err error)

	// refresh は 30 秒ごとに呼ぶ見直しである(Run のティッカー)。ユーザー空間モードでは、
	// 開けなかったリスナーを開き直し、TCP の宛先へ試し接続し直す。built が偽なら何もしない。
	refresh()

	// close はトンネルと転送を閉じる。何も立っていなければ何もしない。
	close()

	// lastHandshake は今のトンネルの最終ハンドシェイクを読む。watchdog が作り直しの判定と、
	// stream の再接続の待ちを打ち切る判定に使う。built が真のときだけ呼ぶ。
	lastHandshake() time.Time

	// read はハートビートと agent doctor が共有する 1 回の読みである(設計文書 10.2c 節)。
	// トンネルの状態とルールの状態を 1 回ずつだけ読むので、1 つの応答に異なる時点の値が混ざらない。
	read() dataplaneReading
}

// preparer は、全体状態の適用の前に rt.mu の外で行う準備を持つ dataplane である。カーネルモードの
// 実装だけが持ち、エンドポイントと宛先の名前を引く(仕様 7b.1・7b.2 節)。DNS を待つ間に排他を持つと、
// ハートビートと agent doctor が最長で名前の解決の期限まで待たされるためである。準備は渡した全体状態
// だけから決まるので、排他を取り直した後にその全体状態を適用する限り、結果は古くならない。
type preparer interface {
	prepareApply(st *proto.State) any
}

// wgChecker は、server から届いた wg 設定を、今のトンネルに手を付ける前に検証する dataplane である。
// カーネルモードの実装だけが持つ(設計文書 7b.1・11 節)。runtime は、トンネルが立っている間に届いた
// 全体状態の wg 設定をこれで確かめ、拒んだ全体状態は適用しない。今のトンネルとルールはそのまま残し、
// 30 秒ごとの見直しも続ける。build も同じ検証を通すので、トンネルが無い間に届いた全体状態は、他の
// wg 設定の誤りと同じく作成の失敗になる。
type wgChecker interface {
	checkWG(w proto.WGConfig) (netip.Prefix, error)
}

// observer は、30 秒ごとに実際の状態を宣言と比べ直す dataplane である。カーネルモードの実装だけが
// 持つ(仕様 7b.2 節の名前の解決し直し、7b.4 節の外からの変更)。見直しは 2 つに分かれる。
// observePrepare は名前の解決だけを行い、rt.mu の外で呼ぶ。DNS を待つ間に排他を持たないためである。
// observeCommit は rt.mu を持って呼び、observePrepare の結果で公開し直すかを決める。saved が真なら
// 呼び出し側が認証情報ファイルを保存する。err が nil でなくても saved が真なら保存する。誤りのログは
// observeCommit が出す。
type observer interface {
	observePrepare(rules []proto.AgentRule) any
	observeCommit(gen uint64, rules []proto.AgentRule, prepared any) (saved bool, err error)
}

// startupChecker は、起動時に stream へ繋ぐ前に行う検査を持つ dataplane である。カーネルモードの
// 実装だけが持つ(仕様 7b.4 節の所有の判定)。誤りを返せば起動は失敗し、*startup.Refusal なら
// 終了コード 3、他は 1 で終わる。
type startupChecker interface {
	startup(priv wgtypes.Key, save func() error) error
}

// fatalError は、このプロセスの最初の wgft0 の収束が、起動の失敗として扱う誤りで終わったことを表す
// (仕様 11b 節、2026-09-24 の所有者の決定)。stream に繋いだ後の収束でも、それがプロセスの最初の
// 収束なら起動の一部として扱い、runtime はプロセスを終える。所有の衝突とアドレス帯の重なりは終了
// コード 1、前提の欠如(権限、WireGuard のモジュール)は終了コード 3 である。最初の収束の後の同じ
// 誤りは、7b.3 節の 3 つ目の種類として旧い設定を残したまま試し直す。
type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }

// isFatal は err がプロセスを終える誤りかどうかである。
func isFatal(err error) bool {
	var f *fatalError
	return errors.As(err, &f)
}

// dataplaneReading は agentDataplane.read の結果である。
type dataplaneReading struct {
	tunnel tunnelReading

	// rules はハートビートに載せるルールごとの状態である。ルールを受け付ける資源が無ければ nil
	rules []proto.RuleStatus

	// relay はユーザー空間の中継だけが持つ値である。中継が無ければ nil
	relay *relayReading
}

// tunnelReading はトンネルを 1 回読んだ値である。present が偽のとき、残りの値に意味は無い。
type tunnelReading struct {
	present bool

	// endpoint は解決済みのエンドポイントである。初回の名前解決に失敗したトンネルは持たない
	endpoint netip.AddrPort
	// lastHandshake は最終ハンドシェイクである。ゼロなら未確立
	lastHandshake time.Time
	// rxBytes と txBytes はトンネルの送受信バイト数である。ハートビートには載らず、doctor だけが使う
	rxBytes, txBytes int64
	// err はトンネルの誤り(エンドポイントの解決の失敗など)である
	err error
}

// relayReading はユーザー空間の中継を 1 回読んだ値である。listeners は rules と同じ 1 回の読みから
// 来る。tcp と udp はフロー予算で、doctor が読む。
type relayReading struct {
	listeners []relay.Status
	tcp, udp  *resource.Pool
}
