//go:build linux

package linuxkernel

import (
	"os"
	"strconv"
	"strings"
	"testing"

	mdnetlink "github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

// readIntSysctl は整数の sysctl ファイルを読む。internal/platform/linux が持つ同名の(公開されて
// いない)関数と同じ形で、このテストのためだけにここへ写した。
func readIntSysctl(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatalf("%s value is not an integer: %v", path, err)
	}
	return n
}

// TestSizeNotifySocketRaisesTheBuffer は、本物の netlink ソケットを開き(開くだけなら特別な権限は
// 要らない。net.core.rmem_max を超えて上げることだけが権限を要る)、sizeNotifySocket が
// SO_RCVBUFFORCE を拒まれても誤りを返さないこと(batch.go の sizeSocket と同じ落ち方)、受信
// バッファが縮まないことを確かめる。
//
// このサンドボックス(および設計文書 7a.3 節が注記する、非特権の LXC のような init の user
// namespace の CAP_NET_ADMIN が無い配置)では、mdlayher/netlink の SO_RCVBUFFORCE は拒まれて
// SO_RCVBUF に落ちる。カーネルはその要求を net.core.rmem_max で頭打ちにし、通った値を 2 倍にして
// 返す(socket(7))。したがって、このテストで確かめられる値は notifyReceiveBuffer そのものではなく
// 2 * min(notifyReceiveBuffer, rmem_max) であり、rmem_max が小さいホスト(CI の実行機など)では
// notifyReceiveBuffer よりはるかに小さくなりうる。CAP_NET_ADMIN がある配置で実際に 8 MiB まで
// 伸びることは、root で動く notifybuffer_lab_test.go のラボ試験が確かめる。
func TestSizeNotifySocketRaisesTheBuffer(t *testing.T) {
	conn, err := mdnetlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		t.Skipf("cannot open a netlink socket in this sandbox: %v", err)
	}
	defer conn.Close()

	before, err := conn.ReadBuffer()
	if err != nil {
		t.Fatalf("ReadBuffer before sizing: %v", err)
	}

	if err := sizeNotifySocket(conn); err != nil {
		t.Fatalf("sizeNotifySocket must not fail the dial even when the kernel cannot grant the full request: %v", err)
	}

	after, err := conn.ReadBuffer()
	if err != nil {
		t.Fatalf("ReadBuffer after sizing: %v", err)
	}
	if after < before {
		t.Errorf("read buffer shrank from %d to %d", before, after)
	}

	rmemMax := readIntSysctl(t, "/proc/sys/net/core/rmem_max")
	want := notifyReceiveBuffer
	if rmemMax < want {
		want = rmemMax
	}
	want *= 2
	if after < want {
		t.Errorf("read buffer %d did not grow toward %d (2x min(%d requested, %d rmem_max)); "+
			"sizeNotifySocket may not be requesting SO_RCVBUF at all", after, want, notifyReceiveBuffer, rmemMax)
	}
}
