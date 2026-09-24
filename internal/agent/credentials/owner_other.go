//go:build !windows

package credentials

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// geteuid は実効 uid である。テストだけが root の実行を模すために差し替える。
var geteuid = os.Geteuid

// chown は os.Chown である。テストだけが root でない実行で呼ばれた値を確かめるために差し替える。
var chown = os.Chown

// keepOwner は、root のプロセスが path を書き換えるとき、元のファイルの持ち主とグループを一時ファイル
// tmp に移す(仕様 9 節)。同梱の unit はエージェントを User=wgft で動かすので、root で実行した停止中の
// rotate-key や agent teardown が持ち主を root に変えると、エージェントは次の起動で agent.json を
// 読めなくなる。root でないプロセスは他の持ち主のファイルを作れないので、何もしない。元のファイルが
// 無ければ何もしない。
func keepOwner(tmp, path string) error {
	if geteuid() != 0 {
		return nil
	}
	fi, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok || (st.Uid == 0 && st.Gid == 0) {
		return nil
	}
	if err := chown(tmp, int(st.Uid), int(st.Gid)); err != nil {
		return fmt.Errorf("keep the owner %d:%d of %s: %w", st.Uid, st.Gid, path, err)
	}
	return nil
}
