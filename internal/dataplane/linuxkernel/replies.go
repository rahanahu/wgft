//go:build linux

package linuxkernel

import (
	"errors"
	"fmt"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane"
	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/nft"
	"github.com/rahanahu/wgft/internal/model"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/proto"
)

// UDPReplyPollInterval は、UDP の応答のカウンタを読む周期である(設計文書 10.2a 節「UDP の応答の
// 観測」)。応答の時刻は、カウンタが増えたことを読んだ時刻にするので、この長さまでの誤差を持つ。
// パケットごとに Go を起こさないため、カーネルからの通知は使わない。
const UDPReplyPollInterval = 10 * time.Second

// errReplyRowMissing は、公開したはずのルールの応答のカウンタの行がテーブルに無いことである。
var errReplyRowMissing = errors.New("its reply counter row is missing from table inet " + nft.TableName)

// replyWatch は 1 本の UDP のルールの応答の観測である。
//
// カウンタの値そのものは時刻を持たない。そこで、読んだ値が前回より増えていれば、その読み取りの
// 時刻を最後の応答の時刻とする。前回の値(base)が分からないときの読み取りは基準にしかならず、
// 0 でない値から過去の応答の時刻を推定しない(所有者の決定)。
type replyWatch struct {
	rule  string // ルール ID。カウンタの行のコメントの持ち主
	ident string // dataplane.UDPReplyIdentity
	// since は途切れずに観測している始まりで、0 は「次の基準の読み取りで始め直す」を表す
	since time.Time
	last  time.Time
	// base は前回読んだカウンタの値で、haveBase が偽なら分からない(起動の直後、テーブルの差し替えの
	// 直後、読み取りの失敗の後)
	base     uint64
	haveBase bool
	// err はこのルールだけを観測できないこと(行が無い)である
	err error
}

// restart は観測を捨て、次の基準の読み取りから始め直す。
func (w *replyWatch) restart() {
	w.since, w.last, w.base, w.haveBase = time.Time{}, time.Time{}, 0, false
}

// observeRepliesLocked は、読んだカウンタ(または読み取りの誤り)を観測に写す。b.replyMu を持って呼ぶ。
//
// 読み取りに失敗すると、その間の増加が分からないので、どのルールも観測を捨てて始め直す。
// 値が前回より減った場合(wgft の外でカウンタが 0 に戻された場合)も、その間の応答が分からないので
// 始め直す。どちらも「連続性が途切れたら基準から始め直す」の規則である。
func (b *Backend) observeRepliesLocked(counts map[string]uint64, err error, now time.Time) {
	if err != nil {
		for _, w := range b.replies {
			w.restart()
			w.err = nil
		}
		b.replyErr = err
		return
	}
	b.replyErr = nil
	for _, w := range b.replies {
		v, ok := counts[w.rule]
		if !ok {
			w.restart()
			w.err = errReplyRowMissing
			continue
		}
		w.err = nil
		switch {
		case !w.haveBase:
			w.base, w.haveBase = v, true
			if w.since.IsZero() {
				w.since = now
			}
		case v > w.base:
			w.base, w.last = v, now
		case v < w.base:
			w.restart()
			w.base, w.haveBase, w.since = v, true, now
		}
	}
}

// readRepliesLocked は、観測しているルールがあるときだけカウンタを読んで観測に写す。
func (b *Backend) readRepliesLocked(now time.Time) {
	if len(b.replies) == 0 {
		b.replyErr = nil
		return
	}
	counts, err := b.ops.readReplies()
	if err != nil {
		err = fmt.Errorf("reading the reply counters: %w", err)
	}
	b.observeRepliesLocked(counts, err, now)
}

// syncRepliesLocked は、公開したテーブルの UDP のルールに観測を揃える。新しいルールと、同一性
// (dataplane.UDPReplyIdentity)が変わったルールは観測を捨てて始め直し、公開しなくなったルールの
// 観測は消す。テーブルを差し替えたので、どのルールもカウンタの基準は分からなくなる。
func (b *Backend) syncRepliesLocked(plan planner.Plan) {
	next := map[string]*replyWatch{}
	for _, pp := range plan.Ports {
		if pp.Proto != proto.UDP || pp.Forwarding != model.Transparent {
			continue
		}
		ident := dataplane.UDPReplyIdentity(pp)
		w, ok := b.replies[pp.RuleID]
		if !ok || w.ident != ident {
			w = &replyWatch{ident: ident, rule: pp.RuleID}
		}
		w.base, w.haveBase = 0, false
		next[pp.RuleID] = w
	}
	b.replies = next
}

// PollUDPReplies は UDP の応答のカウンタを 1 回読み、読めなかった場合はその誤りを返す。vpsd が
// UDPReplyPollInterval ごとに呼ぶ。テーブルの差し替えと並行しないよう、Commit と同じ錠を取る。
func (b *Backend) PollUDPReplies() error {
	b.replyMu.Lock()
	defer b.replyMu.Unlock()
	b.readRepliesLocked(b.clock())
	return b.replyErr
}

// UDPReplies implements dataplane.UDPReplyObserver (design.md 10.2a 節「UDP の応答の観測」): for each
// UDP rule of the published table, when the watch began and the read at which its reply counter
// last grew.
func (b *Backend) UDPReplies() map[string]dataplane.UDPReply {
	b.replyMu.Lock()
	defer b.replyMu.Unlock()
	out := make(map[string]dataplane.UDPReply, len(b.replies))
	for id, w := range b.replies {
		switch {
		case b.replyErr != nil:
			out[id] = dataplane.UDPReply{Err: b.replyErr}
		case w.err != nil:
			out[id] = dataplane.UDPReply{Err: w.err}
		case w.since.IsZero():
			// 基準をまだ読んでいない。差し替えの直後の読み取りが失敗した場合だけ起き、次の周期で埋まる
			out[id] = dataplane.UDPReply{Err: errors.New("the first reading of the reply counters has not happened yet")}
		default:
			out[id] = dataplane.UDPReply{Since: w.since, Last: w.last}
		}
	}
	return out
}
