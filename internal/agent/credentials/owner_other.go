//go:build !windows

package credentials

import (
	"log"
	"os"
	"syscall"
)

// geteuid は実効 uid である。テストだけが root の実行を模すために差し替える。
var geteuid = os.Geteuid

// logf は警告の出力先である。テストだけが差し替える。
var logf = log.Printf

// fchown は開いたファイルの記述子に対する chown である。テストだけが root でない実行で呼ばれた値を
// 確かめるために差し替える。
var fchown = func(f *os.File, uid, gid int) error { return f.Chown(uid, gid) }

// keepOwner は、root のプロセスが path を書き換えるとき、元のファイルの持ち主とグループを一時ファイル
// tmp に移す(仕様 9 節)。同梱の unit はエージェントを User=wgft で動かすので、root で実行した停止中の
// rotate-key や agent teardown が持ち主を root に変えると、エージェントは次の起動で agent.json を
// 読めなくなる。持ち主を移せなければ警告して保存を続ける。root でないプロセスは他の持ち主のファイルを作れないので、何もしない。元のファイルが
// 無ければ(old が nil なら)何もしない。
//
// old は Save が path を Lstat で見た結果で、通常のファイルであることを確かめてある。持ち主は tmp の
// 名前ではなく開いた記述子に移す。データディレクトリはエージェントの利用者のもので、その利用者は
// 書き込みの途中で一時ファイルの名前を別のファイルへの symlink に差し替えられる。名前で chown すると、
// root がその先の持ち主をエージェントの利用者に変えてしまう(仕様 11 節)。
func keepOwner(tmp *os.File, old os.FileInfo, path string) error {
	if geteuid() != 0 || old == nil {
		return nil
	}
	st, ok := old.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid == 0 && st.Gid == 0) {
		return nil
	}
	// chown の失敗は警告にとどめ、保存は続ける。root で常駐するエージェントも Save を呼ぶので、失敗を
	// 保存の誤りにすると、持ち主を移せないだけで全体状態や鍵を保存できなくなる
	if err := fchown(tmp, int(st.Uid), int(st.Gid)); err != nil {
		logf("warning: cannot keep the owner %d:%d of %s: %v; the file is now owned by root, so an agent running as that user cannot read it until it is changed back with chown %d:%d %s",
			st.Uid, st.Gid, path, err, st.Uid, st.Gid, path)
	}
	return nil
}
