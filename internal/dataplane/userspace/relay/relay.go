// Package relay は、エージェントの netstack 上のリスナーと、LAN 内の target への中継を持つ(仕様 7 節)。
// vpsd のユーザー空間モード(仕様 6.3 節)も、向きを反転して同じコードを使う(ホストの公開ポートで受け、
// netstack 越しにエージェントへ中継する)。どちらも使う共有の中継なので、userspace の dataplane の
// 下位実装として internal/dataplane/userspace に置く(設計文書 7a.7 節)。
//
// 収束の単位はポートで、宣言 (proto, port) → (実効宛先, 所属ルール ID) と現在のリスナーを突き合わせる。
// リスナーをどこに開くかは Network で差し替えられるので、単体テストはホストのループバックで行う。
package relay

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rahanahu/wgft/internal/lograte"
	"github.com/rahanahu/wgft/internal/reasontext"
	"github.com/rahanahu/wgft/internal/resource"
	"github.com/rahanahu/wgft/proto"
)

// Network はリスナーを開く先。本番は netstack、テストはホストのループバック。
type Network interface {
	ListenUDP(port uint16) (net.PacketConn, error)
	ListenTCP(port uint16) (net.Listener, error)
}

// Options は中継の調整値。
type Options struct {
	UDPIdleTimeout time.Duration // 無通信でセッションを閉じるまで(全体状態の udp_timeout_stream)
	// Limits はプロセス全体の予算(設定値)。UDPPool と TCPPool の既定値を導くのに使う
	Limits resource.Limits
	// UDPPool と TCPPool はプロセス全体の予算と、そこから導くルールごとの上限と最低分
	// (仕様 7 節、設計文書 7a.10 節の Resource Guard)。nil なら Limits から作る。
	// 今の呼び出し側はどちらも渡さない。vpsd は Limits だけを渡し、この Manager が作った Pool を
	// TCPPool() から読んでプロキシモードの中継に渡すので、同時接続数は合計で数える(仕様 7 節)
	UDPPool *resource.Pool
	TCPPool *resource.Pool
	Dial    func(network, addr string) (net.Conn, error)
	Logf    func(format string, args ...any)
	// Admit は新しいフロー(TCP の accept、UDP の新しいセッションの最初のデータグラム)を通すかを、
	// Admission Policy のすべての段で判定する(設計文書 7a.9 節の AdmitFlow)。size は最初のパケットの
	// 大きさ(UDP はデータグラムの長さ、TCP は 0)。通すときは、送信元ごとの同時フロー数の枠を返す
	// release も返し、中継はフローの終わりに 1 回呼ぶ。後の Resource Guard(プロセス全体の予算、
	// ルール 1 本の上限、最低分と予備)が拒んだときも、その場で呼ぶ。nil なら全部通す。
	// VPS 側のユーザー空間モード(仕様 6.3 節)が使う。エージェントでは nil。
	Admit func(ruleID string, src netip.Addr, size int) (release func(), ok bool)
	// AdmitPacket は成立済みの UDP セッションのデータグラム 1 つを通すか(packet_rate)。nil なら全部通す。
	AdmitPacket func(ruleID string, size int) bool
	// AllowTarget は宛先への接続を許すかを判定する(エージェントの宛先の許可一覧。設計文書 7 節)。
	// nil なら制限せず、宛先の名前解決も中継では行わない。nil でなければ、TCP の接続 1 本ごと、
	// UDP のセッション 1 つごとに、実際に接続するアドレスとポートで呼ぶ。エージェントだけが渡す
	AllowTarget func(netip.AddrPort) bool
	// AllowTargetSource は許可一覧の出どころ。拒否の理由に添える(エージェントでは
	// WGFT_AGENT_ALLOW_TARGETS)。AllowTarget が nil なら使わない
	AllowTargetSource string
	// RefuseTarget は、宛先のアドレスへ接続しない理由を返す。接続してよければ空を返す。エージェントが
	// ブロードキャストとマルチキャストの宛先を拒むために渡す(設計文書 7 節)。報告は AllowTarget と同じで、
	// AllowTarget より先に呼ぶ。IP リテラルの宛先は適用のときに判定し、拒めば待ち受けを開かない。ホスト名の宛先は、
	// 許可一覧があれば中継が自分で解決したアドレスで、無ければ既定の Dial の Control が Go の接続の
	// 解決したアドレスで判定する。Dial を渡した場合、許可一覧の無いホスト名の判定はその Dial に任せる。
	// nil なら判定しない
	RefuseTarget func(netip.Addr) string
	// LookupTarget は宛先のホスト名を解決する。nil なら net.DefaultResolver。AllowTarget を
	// 渡したときだけ使う(許可一覧は実際に接続するアドレスで判定するため)
	LookupTarget func(ctx context.Context, host string) ([]netip.Addr, error)
}

// Key はリスナーの同一性。
type Key struct {
	Proto proto.Proto
	Port  uint16
}

// String は "udp/2456" の形で返す。ログとテストの表示用。
func (k Key) String() string { return fmt.Sprintf("%s/%d", k.Proto, k.Port) }

// Desired はリスナー 1 つの宣言値。
type Desired struct {
	Target string // 実効宛先 host:port
	RuleID string
}

// targetDialTimeout は、中継が実際の通信のために target へ接続するときの期限(既定の Options.Dial)。
// 許可一覧があるときは、解決したアドレスの全体でこの期限を分け合う(設計文書 7 節、dialAddrs)。
const targetDialTimeout = 10 * time.Second

// targetFallbackDelay は、許可一覧があるときの TCP の接続で、先に試す族のアドレスが繋がらないまま
// もう一方の族のアドレスを並行して試し始めるまでの待ち。net.Dialer の FallbackDelay の既定と同じ値である。
const targetFallbackDelay = 300 * time.Millisecond

// targetProbeTimeout は target への到達確認 1 件の期限(設計文書 5.2 節)。
// 中継が実際の通信のために target へ接続するときの期限(targetDialTimeout)とは別に持つ。
// LAN の target の TCP のハンドシェイクは 1 ミリ秒の桁で済むので 2 秒には三桁の余裕があり、
// 黙って捨てる target 1 つが確認を延ばす長さもこの値で決まる。ハンドシェイクに 2 秒を超える
// target は、接続を受け付けていても error として報告される。error は報告にだけ使い、中継そのものは
// 止めないので、誤って error になったルールも転送を続ける。
const targetProbeTimeout = 2 * time.Second

// targetProbeConcurrency は 1 回の確認で同時に試みる target の数の上限(設計文書 5.2 節)。
// 確認を錠の外へ出すだけでは 1 周期が target の数に比例したままなので、同時に試みる。
// 32 と 2 秒の組み合わせでは、黙って捨てる target が 480 件あっても 1 周期が 30 秒に収まる。
// 上限を置くのは、確認が中継そのものと資源を取り合わないためである。32 本の接続は TCP の
// フローのプロセス全体の既定の上限(2048)の 2 パーセントに満たない。なお 1 件の待ちを期限で
// 打ち切っても、その下の Dial は自分の期限まで走り続けるので、target がすべて黙って捨てる
// 間は、実際に開いている接続がこの上限の数倍まで一時的に増える。
const targetProbeConcurrency = 32

// Manager は現在のリスナー集合を持ち、宣言に収束させる。
//
// 本番では、1 つの Manager を Apply と Retry の経路(apply.go)か、Prepare と Commit の経路(staged.go)の
// どちらか一方だけで使い、両方を混ぜない。エージェントは前者を、vpsd のユーザー空間モードは後者を使う。
//
// Manager の錠は mu と、待ち受けごとの錠(TCP は tcpServer の mu、UDP は serveUDP の局所の mu。
// 接続かセッションの表と、TCP の closed と cut、UDP の pending を守る)の 2 段で、順は mu -> 待ち受けの錠
// である。Apply、Staged.Commit、Close、Status は mu を持ったまま待ち受けの closeF、sweep、sessions のどれかを呼び、
// それらが待ち受けの錠を取る。中継の goroutine(accept と読み取りのループ、接続ごとの goroutine)は、
// 待ち受けの錠を持たずに ruleOf、targetOf、noteTargetAllowErr で mu を取る。CloseSessions は mu を
// 放してから sweep を呼ぶ。
//
// mu の内側では、待ち受けの budget を通して resource.Pool の錠を取り、Options.Logf を呼び、Apply、
// Retry、Prepare では Network で bind する。Apply と Retry は、IP の宛先を bind の前に mu の内側で
// Options.AllowTarget に問う。closeF と Staged.Commit の sweep は、mu の内側で待ち受けとセッションの
// ソケットを閉じる。nettun の UDP のソケットを閉じると、nettun の UDP の錠(接続ごとの opMu と受信の
// 会計の錠)を取る。nettun の UDP のソケットは、エージェントの待ち受けの UDP と、vpsd の宛先への
// UDP である。順は relay の錠 -> nettun の錠である。待ち受けの錠の内側では、sweep が keep を呼ぶ。ユーザー空間モードの
// vpsd が Staged.Commit に渡す keep は dataplane.Retiring.SourceAllowed で錠を取らない。CloseSessions に
// 渡す keep は、Retiring のルールでなければ評価器(goengine)の錠を取る。TCP の待ち受けの錠の内側では
// cutConn も呼び、netstack の接続の Abort が nettun の接続の錠を取る。Options の Admit、AdmitPacket、
// Dial、LookupTarget と、中継と到達確認の中の AllowTarget と RefuseTarget は、relay の錠を持たずに呼ぶ。
//
// 次の 2 つの説明は、中継の goroutine が mu を待つことに依っている。udp.go の新しいセッションの
// 登録(Apply が mu を持つ間、ruleOf と targetOf が待たされる)と、Staged.Commit の Retiring からの
// 再開(読み取りの goroutine は受け付けの印を見た後に ruleOf で mu を待つ)である。
type Manager struct {
	net  Network
	opts Options
	// probeTimeout は到達確認 1 件の期限。単体テストだけが New の後に書き換える
	probeTimeout time.Duration
	// dialCtx は、許可一覧があるときに解決したアドレス 1 つへ接続する(dialAddrs)。既定の Dial なら
	// その net.Dialer の DialContext で、渡された Dial なら期限を無視してそれを呼ぶ。dialTimeout は
	// そのアドレスの全体で分け合う接続の期限である。どちらも単体テストだけが New の後に書き換える
	dialCtx     func(ctx context.Context, network, addr string) (net.Conn, error)
	dialTimeout time.Duration

	mu        sync.Mutex
	listeners map[Key]*listener

	// 次の 3 つは単体テストだけが New の後に書き換える差し込み口で、本番では nil である。停止や適用と
	// 取得が重なる窓は、止める位置を外から決められないと繰り返して確かめられないので残す
	// (設計文書 7a.10 節の「受け付けていない」の拒否と帰属の規則の試験)。
	// testHookAfterTake は取得の直後、停止の印を確かめる前に worker が呼ぶ。
	testHookAfterTake func(l *listener)
	// testHookRevive は、Retiring の UDP の待ち受けを再開する Commit の中で、受け付けの印を立てた後、
	// Pool の Accept の前に呼ぶ。
	testHookRevive func(l *listener)
	// testHookCommitStep は、Staged.Commit が既存の待ち受けを 1 つ閉じるか止めるか付け替えるたびに呼ぶ。
	// 1 回の適用の中の順(listeners の表の順)を試験が記録するためのもの。
	testHookCommitStep func(k Key, op string)
	// retiring は fail-closed にしたルールの待ち受け(新しいフローを受けず、成立済みのフローだけを
	// 残す。設計文書 7a.3 節)。Prepare/Commit の経路(vpsd のユーザー空間モード)だけが使う。
	retiring map[Key]*listener
	// bindFail は Prepare の経路で bind に失敗し続けているキーの記録。同じ理由の失敗はログに 1 回だけ
	// 出し、開けたときに 1 回だけ回復を出す(適用は 30 秒ごとに再試行されるため)。
	bindFail map[Key]*bindFailure

	// replies は UDP の応答のバッファの貸し出し(設計文書 7 節)。プロセス全体で 1 つの
	// defaultReplyPool を指す。単体テストだけが New の後に差し替える
	replies *replyPool
	// replyDrops は公開側の送信バッファの満杯で捨てた応答の累計とログの門(設計文書 7 節)
	replyDrops replyDropReport
	// testUDPRegistering は、UDP の新しいセッションの登録で、セッションの錠を取った直後に呼ぶ。
	// 単体テストだけが New の後、中継を始める前に設定する。nil なら呼ばない
	testUDPRegistering func()
}

// bindFailure は bind の失敗が続いている 1 つのキーの記録。
type bindFailure struct {
	reason   string
	attempts int
}

// listener は待ち受け 1 つ。状態(設計文書 7a.3 節の Active、Retiring、閉じた状態)は、どちらの表
// (Manager の listeners か retiring)に入っているか、UDP の accepting、budget の受け付けの状態、
// tcpServer と serveUDP が持つ待ち受けソケットで表す。閉じる、付け替える、退役させる、再開する
// 操作は次の名前の付いたメソッドで行い、どれも呼び出し側が Manager の mu を持つ。待ち受けを開く経路
// (openLocked と、Commit が Prepare で bind したソケットから待ち受けを作る箇所)は、これらのメソッドを
// 通さず、budget の受け付けと表への登録をその場で行う。
//   - shutdownLocked:待ち受けを閉じる。この後、listeners の表からは closeLocked が、retiring の表からは
//     closeRetiringLocked が消す。retireLocked が閉じる古い Retiring の待ち受けは、同じキーへの新しい
//     待ち受けの代入で表から外れる
//   - setRuleLocked:所属ルールを付け替える
//   - retireLocked:Active から Retiring へ移す
//   - reviveLocked:Retiring の UDP の待ち受けを Active へ戻す
//
// Apply の経路の Retry が開き直す、bind に失敗した待ち受けは例外で、budget を閉じて表から消すだけである。
// その closeF は何もしない関数なので呼ばない。
type listener struct {
	key    Key
	target string
	ruleID string
	closeF func()
	// stopAccept は新しいフローの受け付けだけをやめ、成立済みのフローを残す(TCP は待ち受けソケットを
	// 閉じ、UDP は新しい送信元のデータグラムを捨てる)。
	stopAccept func()
	// accepting は UDP が新しいセッションを作るか(stopAccept で偽になる)。
	accepting atomic.Bool
	// sweep は keep が偽を返す接続元のセッションを閉じ、閉じた数を返す(接続元制限の変更の即時反映。仕様 6.2 節)
	sweep func(keep func(src netip.Addr) bool) int
	// セッション数(ハートビートの表示用)
	sessions func() int
	// budget は Resource Guard の枠(プロセス全体の予算と、ルールの登録ごとの最低分と予備。設計文書 7a.10 節)。
	// 上限の対象になるフロー(UDP はセッション、TCP は公開側の接続)を 1 つずつここで取る。
	// 既存のフローは受け付けたときのルールの登録に数え、ルール 1 本の上限は登録の待ち受けが運ぶ
	// 数で見る。分割と統合で元のルールの登録が退役すれば、既存のフローは移動先の登録へ移る
	budget *resource.Listener
	// bindErr は待ち受けを開けなかったこと。bind の失敗のほか、宛先が許可一覧の外にある IP
	// リテラルで bind を試みなかった場合の誤りもここに入る(設計文書 7 節の openLocked)。
	// どちらも待ち受けを持たない状態を表すので、Status.Listening はこの値が nil かどうかである。
	// Retry で開き直す
	bindErr error
	// targetErr は TCP ルールで target への接続確認が失敗したときの誤り(仕様 5.2 節)。
	// リスナー自体は開いているので、Retry では開き直さず再確認だけする。
	// vpsd のユーザー空間モードは Status と Retry を呼ばず許可一覧も渡さないので、Prepare と Commit の
	// 経路では Commit が書いても読まれず、到達確認の結果が表に出るのは Commit のログの 1 行だけである
	targetErr error
	// allowDenied は targetErr が今、宛先の許可一覧による拒否かどうか(設計文書 7 節)。
	// 接続ごとに呼ばれる noteTargetAllowErr が、状態が変わらないときに Manager の錠を
	// 取らずに済ませるための印で、targetErr と合わせて setTargetErrLocked が更新する
	allowDenied atomic.Bool
	// lastReply は、UDP の待ち受けが宛先から最後に応答を読んだ時刻(UnixNano。0 は未観測)である。
	// forwardReply が 1 秒に 1 回まで書く。待ち受けとともに生まれて消えるので、開き直しで捨てられる
	// (設計文書 10.2a 節「UDP の応答の観測」)。TCP の待ち受けでは使わない
	lastReply atomic.Int64
}

// err は報告する状態。bind 失敗が優先(リスナーがないので)。
func (l *listener) err() error {
	if l.bindErr != nil {
		return l.bindErr
	}
	return l.targetErr
}

// shutdownLocked は待ち受けを閉じる。closeF で待ち受けソケットと中継中のフローを閉じ、その後に
// Resource Guard の枠を Pool から外す。呼び出し側は m.mu を持ち、この後に待ち受けを表から外す。
// 外し方は、delete で消すか、同じキーへ別の待ち受けを代入して置き換えるかである(retireLocked)。
func (l *listener) shutdownLocked() {
	l.closeF()
	l.budget.Close()
}

// setRuleLocked は所属ルールを付け替える。relay の ruleID と Pool の登録のルールは同じ値でなければ
// ならないので、対で変える。中継の goroutine は ruleOf で m.mu を取って ruleID を読むので、呼び出し側は
// m.mu を持つ。
func (l *listener) setRuleLocked(id string) {
	l.ruleID = id
	l.budget.SetRule(id)
}

// New は空の Manager を作る。
func New(n Network, opts Options) *Manager {
	if opts.UDPIdleTimeout <= 0 {
		opts.UDPIdleTimeout = 120 * time.Second
	}
	lim := opts.Limits.WithDefaults()
	if opts.UDPPool == nil {
		opts.UDPPool = resource.NewPool(lim.UDPTotal)
	}
	if opts.TCPPool == nil {
		opts.TCPPool = resource.NewPool(lim.TCPTotal)
	}
	var dialCtx func(ctx context.Context, network, addr string) (net.Conn, error)
	if opts.Dial == nil {
		d := &net.Dialer{Timeout: targetDialTimeout}
		if opts.RefuseTarget != nil {
			d.ControlContext = refuseControl(opts.RefuseTarget)
		}
		opts.Dial = d.Dial
		dialCtx = d.DialContext
	} else {
		// 渡された Dial は期限を受け取らないので、アドレスごとの期限と打ち切りは効かない
		dial := opts.Dial
		dialCtx = func(_ context.Context, network, addr string) (net.Conn, error) { return dial(network, addr) }
	}
	if opts.Logf == nil {
		opts.Logf = log.Printf
	}
	return &Manager{net: n, opts: opts, dialCtx: dialCtx, dialTimeout: targetDialTimeout, probeTimeout: targetProbeTimeout, listeners: map[Key]*listener{}, retiring: map[Key]*listener{}, bindFail: map[Key]*bindFailure{}, replies: defaultReplyPool}
}

// DesiredFromRules は全体状態のルールから、ポートごとの宣言値を計算する。
// 無効なルールは宣言に現れない。実効宛先は target のポートに範囲内での位置を足したもの。
func DesiredFromRules(rules []proto.AgentRule) map[Key]Desired {
	out := map[Key]Desired{}
	for i := range rules {
		r := &rules[i]
		if !r.Enabled {
			continue
		}
		for p := int(r.ListenPort.Lo); p <= int(r.ListenPort.Hi); p++ {
			target, ok := r.EffectiveTarget(uint16(p))
			if !ok {
				continue
			}
			out[Key{Proto: r.Proto, Port: uint16(p)}] = Desired{Target: target, RuleID: r.ID}
		}
	}
	return out
}

func (m *Manager) closeLocked(k Key) {
	if l, ok := m.listeners[k]; ok {
		l.shutdownLocked()
		delete(m.listeners, k)
		m.opts.Logf("listener %s closed", k)
	}
}

// newListener は待ち受け 1 つ分の記録を作り、Resource Guard の枠を受け付けていない状態で登録する。
// そのルールが受け付けているルールの集合 A に入るのは、呼び出し側が bind の済んだソケットを持って
// budget.Accept を呼んだ時点である(設計文書 7a.10 節)。中継を始めるのは serveUDP/serveTCP で、
// Accept より後に始める。
func (m *Manager) newListener(k Key, d Desired) *listener {
	zero := func() int { return 0 }
	pool := m.opts.UDPPool
	if k.Proto == proto.TCP {
		pool = m.opts.TCPPool
	}
	return &listener{key: k, target: d.Target, ruleID: d.RuleID, sessions: zero, budget: pool.PendingListener(d.RuleID)}
}

// checkTarget は TCP の target へ試し接続する(接続してすぐ閉じる)。UDP は到達確認ができないので呼ばない。
// 許可一覧があれば、この試し接続も一覧に従う(一覧の外のアドレスへ接続を試みないため)。
func (m *Manager) checkTarget(target string) error {
	c, err := m.dialTarget("tcp", target)
	if err != nil {
		return err
	}
	c.Close()
	return nil
}

// targetProbe は target への到達確認 1 件。錠を放しているあいだに待ち受けが閉じることも、開き直される
// ことも、宛先が変わることもあるので、確認したときの待ち受けと宛先を持つ。結果を反映するのは、
// その 2 つが今も同じ場合だけである(設計文書 5.2 節)。
type targetProbe struct {
	key    Key
	l      *listener
	target string
	err    error
}

// runProbes は錠を持たない状態で到達確認を行う。同時に試みる数は targetProbeConcurrency までで、
// 1 件の期限は m.probeTimeout である。
func (m *Manager) runProbes(probes []targetProbe) {
	if len(probes) == 0 {
		return
	}
	sem := make(chan struct{}, targetProbeConcurrency)
	var wg sync.WaitGroup
	for i := range probes {
		sem <- struct{}{}
		wg.Add(1)
		go func(p *targetProbe) {
			defer wg.Done()
			defer func() { <-sem }()
			// 誤りの文面はルールの理由になり、ハートビートのログは理由の変化で出る。名前の解決の誤りから
			// 問い合わせごとに変わる送信元のポートを除き、同じ誤りを 30 秒ごとの変化にしない
			p.err = lograte.StableError(m.probeTarget(p.target))
		}(&probes[i])
	}
	wg.Wait()
}

// probeTarget は target への試し接続を 1 件、期限付きで行う。Options.Dial は期限を受け取らないので、
// 別の goroutine で呼び出して期限で待つのをやめる。打ち切った後も下の Dial は自分の期限まで走り、
// 繋がれば checkTarget がその接続を閉じる。
func (m *Manager) probeTarget(target string) error {
	res := make(chan error, 1)
	go func() { res <- m.checkTarget(target) }()
	t := time.NewTimer(m.probeTimeout)
	defer t.Stop()
	select {
	case err := <-res:
		return err
	case <-t.C:
		return fmt.Errorf("target %s "+reasontext.DidNotAnswer+" within %s", target, m.probeTimeout)
	}
}

// Status はリスナーごとの状態(ハートビート用)。
type Status struct {
	Key    Key
	Target string
	RuleID string
	// Listening は待ち受けを開けているかどうか。偽なら待ち受けが無く、Err はその理由、つまり
	// bind の失敗か、宛先が許可一覧の外で bind を試みなかったことである。真で Err が非 nil なら、
	// 待ち受けは開いていて宛先に届かない。Err だけでは bind の失敗が宛先の失敗に優先するので
	// 2 つを区別できず、bind の失敗はポートの衝突を、宛先の失敗は宛先の機器を指すため、
	// 運用者の次の行動が違う(設計文書 10.2c 節)
	Listening bool
	// Sessions は中継が持っている接続の数。TCP は公開側と宛先側の両方を数えるので、フロー予算の
	// 上限の対象とは一致しない。上限の対象の数は Flows である
	Sessions int
	// Flows はこの待ち受けがフロー予算から取っている枠の数、つまり上限の判定の対象になる数である
	// (TCP は公開側の接続 1 本、UDP はセッション 1 つにつき 1)。判定を行う resource.Listener の
	// 帳簿をそのまま読むので、上限と同じ量になる(設計文書 7a.10、10.2c 節)
	Flows int
	Err   error
}

// Status は現在のリスナーごとの宣言値と状態を返す(ハートビートの材料)。
func (m *Manager) Status() []Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Status, 0, len(m.listeners))
	for _, l := range m.listeners {
		out = append(out, Status{
			Key: l.key, Target: l.target, RuleID: l.ruleID,
			Listening: l.bindErr == nil,
			Sessions:  l.sessions(),
			Flows:     l.budget.Flows(),
			Err:       l.err(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key.String() < out[j].Key.String() })
	return out
}

// LastReplies は、UDP の待ち受けが宛先から最後に応答を読んだ時刻を、所属ルール ID ごとの最大値で
// 返す(設計文書 10.2a 節「UDP の応答の観測」)。範囲のルールはポートごとに待ち受けを持つので、
// そのうち最も新しいものがルールの値になる。応答を 1 度も読んでいないルールは含まない。
// Retiring の待ち受けは含まない。そのルールは公開していない値だからである。
func (m *Manager) LastReplies() map[string]time.Time {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]time.Time{}
	for _, l := range m.listeners {
		if l.key.Proto != proto.UDP {
			continue
		}
		ns := l.lastReply.Load()
		if ns == 0 {
			continue
		}
		if t := time.Unix(0, ns); t.After(out[l.ruleID]) {
			out[l.ruleID] = t
		}
	}
	return out
}

// TCPPool は TCP のフロー予算(設計文書 7a.10 節の Resource Guard)。上限とその使用量、ルールごと、
// 理由ごとの拒否の数を持つ。Options で渡された Pool があればそれで、無ければ New が Limits から
// 作った Pool である。エージェントは Pool を渡さないので、この入口だけが読み出しの経路になる。
func (m *Manager) TCPPool() *resource.Pool { return m.opts.TCPPool }

// UDPPool は UDP のフロー予算。読み方は TCPPool と同じ。
func (m *Manager) UDPPool() *resource.Pool { return m.opts.UDPPool }

// CloseSessions は、keep が偽を返す(ルール ID、接続元)のセッションを閉じ、閉じた数を返す。
// 接続元制限を変えたときに進行中のフローを切るために VPS 側のユーザー空間モードが使う。
func (m *Manager) CloseSessions(keep func(ruleID string, src netip.Addr) bool) int {
	m.mu.Lock()
	ls := make([]*listener, 0, len(m.listeners))
	for _, l := range m.listeners {
		ls = append(ls, l)
	}
	m.mu.Unlock()
	n := 0
	for _, l := range ls {
		if l.sweep == nil {
			continue
		}
		id := m.ruleOf(l)
		n += l.sweep(func(src netip.Addr) bool { return keep(id, src) })
	}
	return n
}

// addrOf は接続の相手のアドレスを netip.Addr にする(IPv4 射影は外す)。a が nil のときはゼロ値を返す。
// gVisor の gonet の RemoteAddr は、エンドポイントが接続中の状態でなくなると nil を返す。
func addrOf(a net.Addr) netip.Addr {
	var ip net.IP
	switch v := a.(type) {
	case nil:
		return netip.Addr{}
	case *net.TCPAddr:
		ip = v.IP
	case *net.UDPAddr:
		ip = v.IP
	default:
		if ap, err := netip.ParseAddrPort(a.String()); err == nil {
			return ap.Addr().Unmap()
		}
		return netip.Addr{}
	}
	if addr, ok := netip.AddrFromSlice(ip); ok {
		return addr.Unmap()
	}
	return netip.Addr{}
}

// Close は全リスナーを閉じる。Retiring の待ち受けも閉じる。
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k := range m.listeners {
		m.closeLocked(k)
	}
	for k, l := range m.retiring {
		m.closeRetiringLocked(k, l)
	}
}

// targetOf は現在の実効宛先(Prepare/Commit の経路では宛先の変更を待ち受けを開き直さずに
// 反映するので、その都度読む)。
func (m *Manager) targetOf(l *listener) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return l.target
}

// ruleOf は現在の所属ルール ID(relabel で変わりうるので、その都度読む)。
func (m *Manager) ruleOf(l *listener) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return l.ruleID
}
