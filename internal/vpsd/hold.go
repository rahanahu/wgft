//go:build linux

package vpsd

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/rahanahu/wgft/internal/platform/linux"
	"github.com/rahanahu/wgft/internal/reconcile"
	"github.com/rahanahu/wgft/proto"
)

// errHoldStopped は、起動の保留の間に ctx が切れたことを serve に伝える印である。保留の失敗の
// うち、これだけが終了コードを持たずに静かに終わる(設計文書 11b 節)。
var errHoldStopped = errors.New("the startup hold stopped")

// errReadingRules は、保留の試し直しが宣言そのものを読めなかったことを表す。適用が失敗したときと
// 違い、宣言を小さくしても直らないので、この失敗の行には holdGuidance を添えない(retryHold)。
var errReadingRules = errors.New("reading the rules again")

// holdGuidance は、保留の行が運用者に示す状況と出口である。入るときの行と、適用の失敗の理由が
// 変わったときの行の両方が同じ形で持つ(設計文書 11b 節のログの規則)。
//
// 「前回の宣言のまま転送が続く」とも「転送が止まる」とも書かない。カーネルが差し替えを行わないまま
// 失敗した場合はテーブルは本当に旧いままで前回の宣言が転送を続けるが、カーネルが差し替えを終えたのに
// vpsd が応答を受け取れなかった場合(ENOBUFS、6.1 節の受信側の壁)はテーブルは既に差し替わっており、
// 失敗と報告した新しい宣言のほうが転送している。vpsd の側からはどちらが起きたか確定できない(11b 節の
// 「転送」の項)。冒頭も「宣言が公開されていない」とは書かない。受信側の壁ではカーネルは既に新しい
// テーブルを受け取っているので、公開の失敗を運用者が「旧いテーブルが残る」と読み違える。vpsd が
// 観測した事実、すなわち適用そのものが失敗したことだけを述べる。
const holdGuidance = "the apply did not succeed; which declaration the kernel is forwarding cannot be told here. Check it with wgft server nft. Read the state with wgft status, then shrink the declaration with wgft rule rm or wgft rule disable"

// applyFirst は起動時の最初のルールの適用である。d.mu を取るのは、apply の「呼び出し側が d.mu を
// 持つ」という約束を守るためである(apply.go)。この時点では他に適用を試すものが無い。
func (d *Daemon) applyFirst(rules []proto.Rule) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.applyNFT(rules)
}

// hold は起動の保留である(設計文書 11b 節)。起動時の最初の適用が失敗したときだけ呼ばれ、終了せずに
// 管理用 API だけを開き、適用が成功するまで 30 秒ごとに試し直す。成功したら nil を返し、呼び出し側が
// 起動の残り(conntrack の読み取り、エージェント用 API の待ち受け、起動完了の行、収束のループ)に進む。
//
// ログは、保留に入るときの 1 行と解けるときの 1 行、そして試し直しの理由が変わったときの 1 行である。
// 同じ理由で失敗し続けるあいだは何も出さない(7a.3 節の抑制と同じ)。入るときの行は、適用の失敗の
// 理由と、状態の読み方と、宣言を小さくする手段を運用者に示す。
func (d *Daemon) hold(ctx context.Context, cause error, openAdmin func() error, serveErr <-chan error) error {
	// 保留のループを起こす channel は、管理用 API が応答を始める前に作る。Batch は自分で適用を試す
	// ので、その成功をここで取りこぼすと、試し直しが公開するものを持たないまま保留が残る。
	applied := d.beginHold(cause)
	// 入るときの行は、待ち受けを開けた後に出す。先に出すと、開けなかった場合に「管理用 API だけが
	// 待ち受けている」と書いた行が journal に残る。開けなかったときは保留に入れないので、返す誤りに
	// 最初の適用の失敗を添えて、運用者が理由を失わないようにする。
	if err := openAdmin(); err != nil {
		return fmt.Errorf("%w; the startup was about to hold after the first apply failed: %v", err, cause)
	}
	log.Printf("startup hold: %v; %s; only the admin API is listening, and the apply is retried every %s",
		cause, holdGuidance, reconcile.DefaultTriggers.Retry)
	if err := waitForApply(ctx, applied, serveErr, reconcile.DefaultTriggers.Retry, d.retryHold); err != nil {
		return err
	}
	log.Printf("startup hold over: the rules applied; continuing with the rest of the startup")
	return nil
}

// waitForApply は保留のループである。applied が閉じる(どの経路のものであれ適用が成功した)まで、
// interval ごとに retry を呼んで待つ。ctx が切れたら errHoldStopped を返し、管理用 API の応答が
// 終わったらその失敗を返す。ループ自身は何もログに出さない。試し直しの失敗を出すかどうかは retry が
// 決める(retryHold)。間隔と試し直しを引数で受け取るのは、単体テストが実際の 30 秒と転送面なしで
// この待ち方を確かめられるようにするためである(hold_test.go)。
func waitForApply(ctx context.Context, applied <-chan struct{}, serveErr <-chan error, interval time.Duration, retry func()) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-applied:
			return nil
		case <-ctx.Done():
			return fmt.Errorf("%w: %w", errHoldStopped, ctx.Err())
		case err := <-serveErr:
			return err
		case <-t.C:
			retry()
			// 試し直しが成功していれば applied は閉じている。次の周回の select に任せると、
			// 同じ時刻に届いた次の tick を選びうるので、ここで確かめる
			select {
			case <-applied:
				return nil
			default:
			}
		}
	}
}

// beginHold は、適用の成功を保留のループへ伝える channel を作り、保留に入った理由を記録する。
// 記録した理由は、試し直しが同じ失敗をしたときに黙るための基準になる(retryHold)。
func (d *Daemon) beginHold(cause error) <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.applied = make(chan struct{})
	d.holdReason = cause.Error()
	return d.applied
}

// noteApplied は、適用が成功したことを保留のループへ伝える。保留に入っていなければ何もしない。
// 適用と同じ排他(d.mu)の下で呼ぶので、保留のループと管理用 API のどちらの適用でも取りこぼさない。
// channel を nil に戻すのは、保留が解けた後の適用が閉じ済みの channel を閉じないためである。
func (d *Daemon) noteApplied() {
	if d.applied != nil {
		close(d.applied)
		d.applied = nil
		d.holdReason = ""
	}
}

// retryHold は保留の間の試し直しである。稼働中の再試行(apply.go の reapply)と同じく宣言を読み直して
// 適用し、成功すれば apply が noteApplied で保留のループを起こす。失敗したときは、理由が前回と違う
// ときだけ 1 行出す(設計文書 11b 節のログの規則。7a.3 節の抑制と同じ)。エージェントへの配信は、
// まだ誰も接続していないので行わない。
//
// 宣言を読めなかった失敗には、宣言を小さくする案内を添えない。サーバのデータベースを読めない状態は
// `wgft rule rm` でも直らず、的外れな案内になるためである。行の形は揃える。
func (d *Daemon) retryHold() {
	d.mu.Lock()
	defer d.mu.Unlock()
	err := d.applyStoredRules()
	if err == nil {
		return
	}
	reason := err.Error()
	if reason == d.holdReason {
		return
	}
	d.holdReason = reason
	if errors.Is(err, errReadingRules) {
		log.Printf("startup hold: %v; the reason changed and the apply is still retried every %s",
			err, reconcile.DefaultTriggers.Retry)
		return
	}
	log.Printf("startup hold: %v; %s; the reason changed and the apply is still retried every %s",
		err, holdGuidance, reconcile.DefaultTriggers.Retry)
}

// applyStoredRules は、保存された宣言を読み直して再試行として適用する。呼び出し側は d.mu を持つ。
func (d *Daemon) applyStoredRules() error {
	rules, err := d.st.Rules()
	if err != nil {
		return fmt.Errorf("%w: %w", errReadingRules, err)
	}
	_, err = d.apply(rules, true)
	return err
}

// udpTimeouts は、エージェントに配る conntrack の UDP タイムアウト 2 値を返す。起動の保留の間は
// まだ読んでいないので、ゼロ値を返す(設計文書 11b 節。読み取りはテーブルの適用の後にある)。
func (d *Daemon) udpTimeouts() linux.UDPTimeouts {
	if t := d.timeouts.Load(); t != nil {
		return *t
	}
	return linux.UDPTimeouts{}
}
