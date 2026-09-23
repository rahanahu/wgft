//go:build !windows

package main

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

// warnInsecureConfigFile は、path に secret な spec の値が実際にファイルから読まれていて、かつ
// そのファイルが other(世界)から読めるパーミッションのとき、起動時に 1 行だけ英語で警告する
// (仕様 11a 節)。止めはしない。
//
// group のビットは対象にしない。agent.env の推奨パーミッションは root 所有・グループ wgft の
// 0640 であり(仕様 11a 節。固定の User=wgft で動く unit がこれを読む)、これは意図した共有で
// あって穴ではない。0640 のような、意図して選んだ配置に対して起動のたびに警告を出すと、
// 正しく設定した環境でもログが埋まり、運用者が「直そう」として world 権限より緩い方(誰でも
// 読める場所への配置など)へ倒れかねない。ここで捕まえたいのは、その group の外、つまり
// このホストの誰からでも読める配置である。
func warnInsecureConfigFile(w io.Writer, path string, c *config) {
	if !hasSecretFromFile(c) {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		return // 直前に読めているのでここでは通常起きない。読めないなら他のエラー経路が扱う
	}
	if info.Mode().Perm()&0o007 != 0 {
		fmt.Fprintf(w, "warning: %s is readable by other users on this host and holds a secret value, WGFT_JOIN; recommended mode is 0600, or 0640 owned by root and a dedicated group; see docs/design.md 11a\n", path)
	}
}

// configFilePermFacts は、設定ファイルを読めなかったときに、原因を見分けるための事実を 1 句で
// 返す。読んだプロセスの実効 uid と gid、ファイルの持ち主とパーミッションを並べる。どちらの側に
// 原因があるかは述べない。ファイル自身のパーミッションが読み手を拒んでいるのか、読み手が
// エージェントと違う利用者なのかは、この 2 つを見比べれば運用者が判断できる。
//
// ファイルの stat 自体が失敗する場合は、上の階層のディレクトリが通り抜けを拒んでいる場合である。
// ファイル自身のパーミッションの話ではないので、そう書き分ける。
func configFilePermFacts(path string) string {
	who := fmt.Sprintf("this process runs as uid %d, gid %d", os.Geteuid(), os.Getegid())
	fi, err := os.Stat(path)
	if err != nil {
		return who + ", and the file's own owner and mode could not be read, so a directory above it refuses the way in: " + err.Error()
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Sprintf("%s, and the file is mode %#o", who, fi.Mode().Perm())
	}
	return fmt.Sprintf("%s, and the file is mode %#o with owner uid %d and group gid %d", who, fi.Mode().Perm(), st.Uid, st.Gid)
}

func hasSecretFromFile(c *config) bool {
	for _, sp := range c.specs {
		if sp.Secret && c.vals[sp.Env].source == "file" && c.vals[sp.Env].value != "" {
			return true
		}
	}
	return false
}
