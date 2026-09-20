//go:build !unix

// proc_other.go は Unix 以外でもリポジトリ全体がビルドできるようにするための実装。
// labhost はラボの VM (Linux) でしか動かないので、ここでは何もしない。main が GOOS を見て
// 先に止まる。
package main

import (
	"errors"
	"os/exec"
)

var errNotLinux = errors.New("labhost runs only on Linux")

func setProcessGroup(cmd *exec.Cmd) {}

func terminateGroup(pid int) error { return errNotLinux }

func signalPid(pid int, graceful bool) {}
