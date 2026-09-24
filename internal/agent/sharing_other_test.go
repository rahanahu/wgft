//go:build !windows

package agent

// retrySharingViolation は Windows 以外では f を 1 回呼ぶだけである。共有違反は Windows にしか無い。
func retrySharingViolation(f func() error) error { return f() }
