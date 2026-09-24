package agent

import (
	"errors"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// lockWhileStopped は、エージェントが止まっている間に CLI が認証情報ファイルを書くための排他を取る
// (仕様 9 節)。停止中の rotate-key と agent pubkey が使う。
//
// 稼働中のエージェントは認証情報ファイルの中身をメモリの上に持ち、保存のたびに全体を書き直す。
// CLI が外から書くと、エージェントが書いた新しい内容を CLI が読んだ古い内容で上書きしうるうえ、
// CLI の変更もエージェントの次の保存で消える。そこで、稼働中なら running を true で返し、呼び出し側は
// 書かない。
//
// 判定はロックファイルを作らない Inspect で行う(設計 10.2c 節)。
//   - Locked: 稼働中。
//   - Unlocked: ロックを取ってから返す。既にあるロックファイルを開くだけなので、持ち主は変わらない。
//     判定の後に起動したエージェントがロックを持っていれば、稼働中として扱う。
//   - Absent: ロックを取らずに返す。取ろうとするとロックファイルを呼び出し元の権限で作り、非特権で
//     動くエージェントの起動を塞ぐ。バックアップからの戻しやホストの移し替えの後、運用者がロックファイル
//     を消した後、一度も起動していないデータディレクトリがこの場合に当たる。判定の直後に起動した
//     エージェントの書き込みを上書きしうる狭い隙間は許容する(仕様 9 節)。
//
// release は、ロックを取った場合はそれを放し、取らなかった場合は何もしない。running が true か err が
// nil でなければ、release は nil である。
func lockWhileStopped(path string) (release func(), running bool, err error) {
	state, err := inspectLock(path)
	if err != nil {
		return nil, false, err
	}
	switch state {
	case credentials.Locked:
		return nil, true, nil
	case credentials.Unlocked:
		lock, err := credentials.Acquire(path)
		if errors.Is(err, credentials.ErrLocked) {
			return nil, true, nil
		}
		if err != nil {
			return nil, false, err
		}
		return func() { lock.Release() }, false, nil
	}
	return func() {}, false, nil
}
