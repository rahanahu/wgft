//go:build qbench && !linux

package qbench

import (
	"errors"
	"runtime"
	"testing"
)

func newLinux() (*DUT, error) { return nil, errors.New("the linux engine needs Linux") }

func newLinuxClient() (*Client, error) { return nil, errors.New("the linux client needs Linux") }

func pinLinux(t *testing.T, engines []string) string { return runtime.GOOS }

func inNetns(t *testing.T) bool {
	t.Skip("the linux engine needs Linux")
	return false
}
