//go:build linux

package main

import "testing"

// server のコマンドが、設定を解決する spec の一覧のフラグ別名を、その一覧から登録していることを
// 確かめる。
func TestServerCommandsRegisterTheSpecsTheyResolve(t *testing.T) {
	root := newRootCmd()
	assertRegistersSpecs(t, commandAt(t, root, "server", "run"), serverSpecs(), nil)
	assertRegistersSpecs(t, commandAt(t, root, "server", "check"), serverSpecs(), nil)
	assertRegistersSpecs(t, commandAt(t, root, "server", "teardown"), serverTeardownSpecs(), nil)
}
