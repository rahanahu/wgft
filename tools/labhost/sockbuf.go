package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// labSocketBufferMin は lab/lab net up が VM 全体に設定する net.core.rmem_max と
// net.core.wmem_max の値で、ユーザー空間モードの動作条件の値 (docs/manual/socket-buffers.md)。
// シナリオは server と agent を権限のない wgftlab でも動かすので、これを下回る VM では
// WireGuard の UDP の受信のバッファが溢れ、userspace の転送がときどき遅くなる。
const labSocketBufferMin = 7340032

// socketBufferSysctls は確かめる 2 つの sysctl の /proc/sys の位置。VM 全体で 1 つの値である
var socketBufferSysctls = []struct{ name, path string }{
	{"net.core.rmem_max", "/proc/sys/net/core/rmem_max"},
	{"net.core.wmem_max", "/proc/sys/net/core/wmem_max"},
}

// sockbufWatch は VM の基準の値を、プールの前と単独の仕事の前に確かめる。基準を下回る VM は、
// net up の前に立てた VM か、lifecycle.sh の check 12 が値を戻せずに止まった VM である。
// どちらも仕事は失敗しないまま遅くなるので、失敗にはせず警告として残す。同じ値が続く間は
// 1 度だけ警告し、値が変わるか基準に戻ったら次を警告する
type sockbufWatch struct {
	read func(path string) (string, error)
	last string
}

func newSockbufWatch() *sockbufWatch {
	return &sockbufWatch{read: func(p string) (string, error) {
		b, err := os.ReadFile(p)
		return string(b), err
	}}
}

// check は基準を下回るときだけ警告の文を返す。読めない値は判断しない
func (w *sockbufWatch) check(before string) string {
	var low []string
	for _, s := range socketBufferSysctls {
		raw, err := w.read(s.path)
		if err != nil {
			continue
		}
		v, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil || v >= labSocketBufferMin {
			continue
		}
		low = append(low, fmt.Sprintf("%s is %d", s.name, v))
	}
	if len(low) == 0 {
		w.last = ""
		return ""
	}
	state := strings.Join(low, " and ")
	if state == w.last {
		return ""
	}
	w.last = state
	return fmt.Sprintf("before %s, %s, below the lab baseline of %d; "+
		"jobs that run the server or the agent as wgftlab do not meet the userspace socket buffer requirement, "+
		"so run lab/lab net up", before, state, labSocketBufferMin)
}
