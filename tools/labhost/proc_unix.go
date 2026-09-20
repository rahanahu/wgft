//go:build unix

// proc_unix.go は labhost がプロセスを所有するための Unix 依存の部分。labhost が動くのは
// ラボの VM (Linux) だけだが、リポジトリは Windows と macOS 向けにもビルドできる必要があるので、
// syscall に触る部分をこのファイルに閉じ込める。
package main

import (
	"os/exec"
	"syscall"
)

// setProcessGroup は子プロセスを独立したプロセスグループに入れる。シナリオの shell は
// sleep や socat を子に持つので、shell 1 つに合図を送っても止まらないことがある。
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateGroup はプロセスグループ全体に SIGTERM を送る。
func terminateGroup(pid int) error {
	return syscall.Kill(-pid, syscall.SIGTERM)
}

// signalPid は 1 つのプロセスに SIGTERM (graceful) か SIGKILL を送る。
func signalPid(pid int, graceful bool) {
	if graceful {
		_ = syscall.Kill(pid, syscall.SIGTERM)
		return
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
}
