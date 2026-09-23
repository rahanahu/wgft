//go:build windows

package main

import "io"

// warnInsecureConfigFile は Windows では何もしない。Windows の権限モデルは Unix のパーミッション
// ビットと異なり、DACL による別の扱いがある(仕様 11a 節)。ここでの Unix 向けの other/group の
// 判定は Windows にはそのまま移せない。
func warnInsecureConfigFile(w io.Writer, path string, c *config) {}

// configFilePermFacts は、設定ファイルを読めなかった理由を Windows で述べられる範囲で返す。
// 読み手を決めるのは DACL であり、wgft はそれを評価しない。Unix 側と同じく、原因がどちら側に
// あるかを断定しない。
//
// 第 2 の返り値は常に偽である。ファイル自身の持ち主とパーミッションを読んでいないので、呼び出し
// 側はファイル自身を名指しする文を添えない。
func configFilePermFacts(path string) (string, bool) {
	return "who may read it is decided by the file's DACL, which this build does not evaluate", false
}
