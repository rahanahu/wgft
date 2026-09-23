// Package conncheck は、管理者が UI から行う疎通確認(仕様 10.1 節)。
// vpsd から wg0 経由でエージェントのリスナー(10.200.0.x:listen_port)に TCP 接続し、
// エージェントの中継を通して target に届くかを見る。TCP のみ。
//
// 確かめられるのは「VPS →(トンネル)→ エージェント → 自宅サービス」の内側の経路まで。
// 外のインターネット利用者からの到達(公開ポート → DNAT → wg0)は、DNAT が外部入力にしか
// 効かないため vpsd 自身からは試せない。そこは実機で外から接続して確かめる。
package conncheck

import (
	"errors"
	"io"
	"net"
	"syscall"
	"time"
)

// Result は疎通確認の結果。
type Result struct {
	OK bool
	// Reach は到達段階。"target"(自宅サービスまで到達)/ "agent"(エージェントまでは行くが
	// target に届かない)/ "none"(エージェントのリスナーに繋がらない)。
	Reach  string
	Detail string
}

const (
	ReachTarget = "target"
	ReachAgent  = "agent"
	ReachNone   = "none"
)

// Dialer は接続に使う関数(テストで差し替える)。本番は net.Dialer.Dial。
type Dialer func(network, addr string) (net.Conn, error)

// Options は調整値。
type Options struct {
	DialTimeout time.Duration // エージェントのリスナーへの接続のタイムアウト(既定 5 秒)
	ObserveTime time.Duration // 接続後、切れないか様子を見る時間(既定 3 秒)
	Dial        Dialer
}

// Check は addr(エージェントのリスナー 10.200.0.x:port)へ接続し、3 分類で結果を返す。
//
// 判定:エージェントの中継は、接続を受けると target へダイヤルし、失敗すると即座にこちらの接続を閉じる。
//   - 接続自体が失敗 → none(トンネル/エージェント/リスナーの問題)
//   - 接続でき、ObserveTime の間に切れない(or 相手がデータを返す)→ target(内側の経路 OK)
//   - 接続でき、すぐ EOF/RST → agent(エージェントまでは行くが target に届かない)
func Check(addr string, opts Options) Result {
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 5 * time.Second
	}
	if opts.ObserveTime <= 0 {
		opts.ObserveTime = 3 * time.Second
	}
	dial := opts.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: opts.DialTimeout}
		dial = d.Dial
	}
	conn, err := dial("tcp", addr)
	if err != nil {
		return Result{OK: false, Reach: ReachNone, Detail: friendlyDialErr(err)}
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(opts.ObserveTime))
	buf := make([]byte, 1)
	_, rerr := conn.Read(buf)
	switch {
	case rerr == nil:
		// 相手がバナー等を返した=target まで生きている
		return Result{OK: true, Reach: ReachTarget, Detail: "home service responded"}
	case isTimeout(rerr):
		// 無言のまま接続が生きている=中継が target へ繋がり、応答待ち(多くのプロトコルは正常)
		return Result{OK: true, Reach: ReachTarget, Detail: "connection established, awaiting response; normal for many protocols"}
	case errors.Is(rerr, io.EOF) || isConnReset(rerr):
		// 直後に閉じられた=エージェントは target へ繋げなかった
		return Result{OK: false, Reach: ReachAgent, Detail: "reached the agent but could not reach the home service; service down or refused"}
	default:
		return Result{OK: false, Reach: ReachAgent, Detail: rerr.Error()}
	}
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func isConnReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}

// friendlyDialErr は dial の失敗を運用者向けの短い文にする。Linux でしか動かない package なので
// (internal/vpsd はカーネルの netlink を直接使う。docs/design.md の 7a.7 節)、syscall の型で判定して
// 差し支えない。errors.Is は net.OpError・os.SyscallError を辿って元の errno まで見る
func friendlyDialErr(err error) string {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return "the agent's listener refused the connection; rule may not be applied"
	case isTimeout(err):
		return "cannot reach the agent; tunnel is down or agent is offline"
	case errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH):
		return "no route to the agent; tunnel not established"
	}
	return err.Error()
}
