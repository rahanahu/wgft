//go:build lab

package vpsd

// ラボの vps ns で root として実行する(lab/lab test internal/vpsd)。
// 撤去が「自分の作ったものだけ消す」を守るかを、他人の wg0 と他テーブルを置いた状態で確かめる。

import (
	"bytes"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/flock"
	"github.com/rahanahu/wgft/internal/planner"
	"github.com/rahanahu/wgft/internal/vpsd/nft"
	"github.com/rahanahu/wgft/internal/vpsd/store"
)

func delLinks(names ...string) {
	for _, n := range names {
		if l, err := netlink.LinkByName(n); err == nil {
			_ = netlink.LinkDel(l)
		}
	}
}

// mkWG は指定した鍵・アドレスで wg インタフェースを作る。
func mkWG(t *testing.T, name string, key wgtypes.Key, addr string) {
	t.Helper()
	if err := netlink.LinkAdd(&netlink.Wireguard{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	link, _ := netlink.LinkByName(name)
	a, _ := netlink.ParseAddr(addr)
	_ = netlink.AddrAdd(link, a)
	c, _ := wgctrl.New()
	defer c.Close()
	port := 0
	if err := c.ConfigureDevice(name, wgtypes.Config{PrivateKey: &key, ListenPort: &port}); err != nil {
		t.Fatalf("%s の設定: %v", name, err)
	}
	_ = netlink.LinkSetUp(link)
}

func linkExists(name string) bool {
	_, err := netlink.LinkByName(name)
	return err == nil
}

func nftTableExists(family, name string) bool {
	return exec.Command("nft", "list", "table", family, name).Run() == nil
}

// setupStore は key と iface を meta に持つ状態ファイルを作って閉じ、パスを返す。
func setupStore(t *testing.T, iface string, key wgtypes.Key) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wgft.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SetMeta(serverKeyMeta, key[:])
	_ = st.SetMeta(metaWGInterface, []byte(iface))
	_ = st.SetMeta(metaWGPort, []byte("51820"))
	st.Close()
	return path
}

// 自分の table inet wgft と wgft0 は消し、他人の wg0 と他テーブルは無傷。
func TestTeardownRemovesOwnOnly(t *testing.T) {
	delLinks("wgft0", "wg0")
	defer delLinks("wgft0", "wg0")
	_ = exec.Command("nft", "delete", "table", "inet", "wgft").Run()
	_ = exec.Command("nft", "add", "table", "ip", "foreigntest").Run()
	defer exec.Command("nft", "delete", "table", "ip", "foreigntest").Run()

	key, _ := wgtypes.GeneratePrivateKey()
	foreign, _ := wgtypes.GeneratePrivateKey()
	path := setupStore(t, "wgft0", key)
	mkWG(t, "wgft0", key, "10.200.0.1/24")  // 自分
	mkWG(t, "wg0", foreign, "10.99.0.1/24") // 他人
	if err := nft.Apply(planner.Plan{}, nil, nft.Config{WGInterface: "wgft0"}); err != nil {
		t.Fatalf("wgft テーブル作成: %v", err)
	}

	var buf bytes.Buffer
	if err := Teardown(TeardownOptions{DBPath: path}, &buf); err != nil {
		t.Fatalf("teardown: %v\n%s", err, buf.String())
	}
	if linkExists("wgft0") {
		t.Error("自分の wgft0 が消えていない")
	}
	if nftTableExists("inet", "wgft") {
		t.Error("table inet wgft が消えていない")
	}
	if !linkExists("wg0") {
		t.Error("他人の wg0 を消してしまった")
	}
	if !nftTableExists("ip", "foreigntest") {
		t.Error("他テーブル foreigntest を消してしまった")
	}
}

// wgft0 が他人のもの(鍵不一致)なら、--adopt-existing なしでは何も消さず拒否する。
func TestTeardownRefusesForeignInterface(t *testing.T) {
	delLinks("wgft0")
	defer delLinks("wgft0")
	_ = exec.Command("nft", "delete", "table", "inet", "wgft").Run()

	key, _ := wgtypes.GeneratePrivateKey()
	other, _ := wgtypes.GeneratePrivateKey()
	path := setupStore(t, "wgft0", key)
	mkWG(t, "wgft0", other, "10.200.0.1/24") // 鍵が meta と一致しない
	_ = nft.Apply(planner.Plan{}, nil, nft.Config{WGInterface: "wgft0"})

	var buf bytes.Buffer
	err := Teardown(TeardownOptions{DBPath: path}, &buf)
	if err == nil {
		t.Fatal("鍵不一致なのに拒否しなかった")
	}
	if !linkExists("wgft0") {
		t.Error("拒否したのに wgft0 を消した")
	}
	if !nftTableExists("inet", "wgft") {
		t.Error("拒否したのに table inet wgft を消した")
	}
	_ = exec.Command("nft", "delete", "table", "inet", "wgft").Run()
}

// vpsd 稼働中(flock 保持)なら拒否する。
func TestTeardownRefusesWhenRunning(t *testing.T) {
	key, _ := wgtypes.GeneratePrivateKey()
	path := setupStore(t, "wgft0", key)
	lock, err := flock.Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release()

	var buf bytes.Buffer
	err = Teardown(TeardownOptions{DBPath: path}, &buf)
	if err == nil || !strings.Contains(err.Error(), "running") {
		t.Fatalf("稼働中の拒否にならない: %v", err)
	}
}

// --dry-run は何も消さない。
func TestTeardownDryRun(t *testing.T) {
	delLinks("wgft0")
	defer delLinks("wgft0")
	_ = exec.Command("nft", "delete", "table", "inet", "wgft").Run()

	key, _ := wgtypes.GeneratePrivateKey()
	path := setupStore(t, "wgft0", key)
	mkWG(t, "wgft0", key, "10.200.0.1/24")
	_ = nft.Apply(planner.Plan{}, nil, nft.Config{WGInterface: "wgft0"})
	defer exec.Command("nft", "delete", "table", "inet", "wgft").Run()

	var buf bytes.Buffer
	if err := Teardown(TeardownOptions{DBPath: path, DryRun: true}, &buf); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !linkExists("wgft0") || !nftTableExists("inet", "wgft") {
		t.Error("dry-run なのに消した")
	}
	if !strings.Contains(buf.String(), "restore by hand") {
		t.Errorf("手で戻す一覧が出ていない:\n%s", buf.String())
	}
}
