//go:build unix

package main

import (
	"errors"
	"io/fs"

	"golang.org/x/sys/unix"
)

// dirCreateAccess は、そのディレクトリに新しいファイルを作れるかどうかを、何も作らずに判定する
// (設計文書 10.2c 節)。`wgft agent doctor` は読み取りだけを既定とするので、実際にファイルを
// 作って消す形は採らない。
//
// unix.Access は呼び出し元の実 uid と実 gid で判定する。10.2c 節は `agent doctor` をエージェントと
// 同じ実行主体で動かすことを前提としており、sudo も実 uid と実効 uid の両方を root にするので、
// この判定と実効権限が食い違う配置はこの前提の外にある。
func dirCreateAccess(dir string) (accessResult, error) {
	err := unix.Access(dir, unix.W_OK|unix.X_OK)
	switch {
	case err == nil:
		return accessAllowed, nil
	case errors.Is(err, fs.ErrPermission):
		return accessDenied, err
	default:
		return accessNotDetermined, err
	}
}
