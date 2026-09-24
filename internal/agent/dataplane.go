package agent

import (
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
	applyRules(rules []proto.AgentRule) (summary string, err error)

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
