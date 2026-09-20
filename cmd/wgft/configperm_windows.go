//go:build windows

package main

import "io"

// warnInsecureConfigFile は Windows では何もしない。Windows の権限モデルは Unix のパーミッション
// ビットと異なり、DACL による別の扱いがある(仕様 11a 節)。ここでの Unix 向けの other/group の
// 判定は Windows にはそのまま移せない。
func warnInsecureConfigFile(w io.Writer, path string, c *config) {}
