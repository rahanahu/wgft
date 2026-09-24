package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// 稼働中のエージェントへの指示は、認証情報ファイルの隣の Unix ソケットで受ける(仕様 9 節の rotate-key)。
// 稼働中の認証情報ファイルは flock で守られているので、外から書き換えない。

// ControlPath は認証情報ファイルに対応する制御ソケットの場所。
func ControlPath(path string) string { return path + ".sock" }

// ControlPathLimit は、どの OS でも収まる制御ソケットのパスの長さ(バイト)。sockaddr_un の sun_path は
// Linux と Windows で 108 バイト、macOS で 104 バイトで、終端の NUL を含む(仕様 11a 節)。
//
// 公開しているのは、繋げなかった理由が長さにあるかどうかを外から判定する読み手がいるためである
// (設計文書 10.2c 節の agent.control)。写しを持たせると、片方だけを直したときに判定が食い違う。
const ControlPathLimit = 103

// explainControlErr は、パスが長すぎて開けない・つなげない場合に原因と対処を添える。Go の net は
// sun_path に収まらない名前を OS を呼ぶ前に EINVAL で拒否するので、元のエラーは "invalid argument" しか言わない。
func explainControlErr(path string, err error) error {
	if err == nil || !errors.Is(err, syscall.EINVAL) || len(path) <= ControlPathLimit {
		return err
	}
	return fmt.Errorf("%w: the socket path is %d bytes; Unix socket paths hold at most 107 bytes on Linux and Windows and 103 on macOS, so use a shorter data directory", err, len(path))
}

// listenControl は制御ソケットを開く。
func listenControl(path string) (net.Listener, error) {
	ln, err := net.Listen("unix", path)
	return ln, explainControlErr(path, err)
}

// serveControl は制御ソケットで 1 行の指示を受ける。今あるのは rotate-key と doctor である。
// 応答の形式は指示ごとに定める。rotate-key は 1 行のテキスト、doctor は 1 行の JSON を返す
// (設計文書 10.2c 節)。要求は今までどおり行ベースで、ソケットの framing は変わらない。
func (rt *runtime) serveControl(ctx context.Context) {
	path := ControlPath(rt.opts.CredentialsPath)
	os.Remove(path)
	ln, err := listenControl(path)
	if err != nil {
		log.Printf("cannot open control socket %s: %v; rotate-key works only while the agent is stopped, and agent doctor cannot read this agent's live state", path, err)
		return
	}
	// credentials.SecureSocket はこのソケットだけを単独で締める(Windows は保護 DACL で
	// 失敗を伝える。Unix はこの修正より前と同じく 0600 の chmod で、失敗は無視する。
	// 仕様 9・11a 節)。秘密は持たないが、agent.json と同じ基準にそろえる。
	if err := credentials.SecureSocket(path); err != nil {
		log.Printf("cannot secure control socket %s: %v; rotate-key works only while the agent is stopped, and agent doctor cannot read this agent's live state", path, err)
		ln.Close()
		os.Remove(path)
		return
	}
	go func() { <-ctx.Done(); ln.Close(); os.Remove(path) }()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			rt.serveControlConn(c)
		}()
	}
}

// serveControlConn は制御ソケットの接続を 1 つ処理する。panic を受け止めるのは doctor の枝だけで、
// その受け止めは doctorResponseLine の中にある。
func (rt *runtime) serveControlConn(c net.Conn) {
	c.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	switch strings.TrimSpace(line) {
	case "rotate-key":
		// この枝には recover を置かない。抜けではなく、意図してそうしている。
		//
		// 設計文書 10.2c 節が recover を置く根拠は「rotate-key が触る値は少ないが、doctor は
		// 多くの値を触る」であり、対象は doctor の枝である。rotateKey は rt.mu を defer では
		// なく手で放し、その区間で認証情報ファイルの保存とトンネルの後始末を行う。この区間の
		// panic をここで受け止めると、常駐プロセスは rt.mu を誰も放さないまま生き続ける。
		// 既存の待ち受けは転送を続ける一方、ハートビート、トンネルの見張り、全体状態の適用、
		// リスナーの再試行、次の doctor がすべて永久に止まり、service は active のまま無応答に
		// なる。再起動の契機がどこにも無いので、落ちるより静かに悪い。落ちれば同梱の
		// agent.service の Restart=on-failure が立て直す
		pub, err := rt.rotateKey()
		if err != nil {
			fmt.Fprintf(c, "error: %v\n", err)
			return
		}
		fmt.Fprintf(c, "ok %s\n", pub)
	case DoctorCommand:
		c.Write(rt.doctorResponseLine())
	default:
		// 新しい実行ファイルを置いてから常駐プロセスを再起動するまでの間、新しい CLI が送る
		// doctor は古い常駐プロセスのこの分岐に当たる。CLI はこれを、稼働中の診断が取れない
		// 場合として扱う(設計文書 10.2c 節)。版の交渉も capability も要らない
		fmt.Fprintf(c, "error: unknown command\n")
	}
}

// rotateKey は wg 鍵対を作り直し、トンネルを新しい鍵で張り直し、stream を張り直す(新しい公開鍵を宣言する)。
func (rt *runtime) rotateKey() (wgtypes.Key, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	rt.mu.Lock()
	// カーネルモードでは、今の鍵を 1 つ前の鍵として新しい鍵と同じ保存で残す(仕様 7b.4 節)。wgft0 を
	// 新しい鍵へ書き換える前に落ちても、次の起動は 1 つ前の鍵で wgft0 を自分のものと判定できる。
	// 保存に失敗したら、メモリの上の 2 つの鍵も元に戻す。戻さないと、使われていない新しい鍵が今の鍵に、
	// 使っている鍵が 1 つ前の鍵に残り、次の rotate-key の後に落ちると、wgft0 の鍵はどちらとも一致しない
	oldKey, oldPrev := rt.f.WGPrivateKey, rt.f.PreviousWGPrivateKey
	rt.f.KeepPreviousKey()
	rt.f.WGPrivateKey = key.String()
	if err := rt.f.Save(rt.opts.CredentialsPath); err != nil {
		rt.f.WGPrivateKey, rt.f.PreviousWGPrivateKey = oldKey, oldPrev
		rt.mu.Unlock()
		return wgtypes.Key{}, err
	}
	rt.priv = key
	last := rt.f.LastState
	rt.closeLocked()
	rt.mu.Unlock()
	log.Printf("regenerated wg key pair; public key: %s", key.PublicKey())
	if last != nil {
		if err := rt.apply(last); err != nil {
			log.Printf("wireguard: rebuild tunnel with the new key: %v", err)
		} else {
			log.Printf("wireguard: tunnel rebuilt with the new key")
		}
	}
	// stream を張り直すと streamOnce が新しい公開鍵を送る(stream: connected to ... で確認できる)
	rt.reconnect()
	return key.PublicKey(), nil
}

// RotateKey は CLI から呼ぶ。稼働中なら制御ソケット経由で、停止中なら認証情報ファイルの鍵と last_state を直接消す。
func RotateKey(path string) (string, error) {
	// 判定とロックの取り方は lockWhileStopped にある。判定はロックファイルを作らない Inspect で行う
	// (設計 10.2c 節)。Acquire 経由の判定は、ロックファイルの無いデータディレクトリで rotate-key を
	// 打っただけで、呼び出し元の権限のロックファイルを残し、後から非特権で動くエージェントの起動を塞いだ。
	// ロックファイルがあって誰も持っていなければ、ロックを取ってから書き換える。取らないと、判定の後に
	// 起動したエージェントが書いた記録(カーネルモードへの切り替えの記録など)を、この書き換えが古い
	// 内容で上書きしうる(仕様 9 節)
	release, running, err := lockWhileStopped(path)
	if err != nil {
		return "", err
	}
	if running {
		return rotateKeyRunning(path)
	}
	defer release()
	f, err := credentials.Load(path)
	if err != nil {
		return "", err
	}
	if rotateKeyLockedHook != nil {
		rotateKeyLockedHook()
	}
	// カーネルモードでは、消す鍵を 1 つ前の鍵として残す(仕様 7b.4 節)。wgft0 はまだその鍵を持つので、
	// 次の起動は 1 つ前の鍵で wgft0 を自分のものと判定し、新しい鍵へ書き換える
	kernel := f.RecordedMode() == credentials.ModeKernel
	f.KeepPreviousKey()
	f.WGPrivateKey, f.LastState = "", nil
	if err := f.Save(path); err != nil {
		return "", err
	}
	msg := "agent stopped: cleared the key and last_state in the credentials file, agent.json; the next start regenerates the key and receives full state over the stream"
	if kernel {
		msg += "; the old key is kept as the previous key, so the next start still recognises the kernel WireGuard interface that holds it and moves it to the new key"
	}
	return msg, nil
}

// rotateKeyLockedHook は、停止中の rotate-key が認証情報ファイルを読んだ後、書く前に呼ばれる。
// テストだけが、この区間でロックを持っていることを確かめるために設定する。
var rotateKeyLockedHook func()

// inspectLock はロックの状態を読む。値は credentials.Inspect で、テストだけが、判定と取得の間に
// エージェントが起動した場合を模すために差し替える。
var inspectLock = credentials.Inspect

// rotateKeyRunning は、稼働中のエージェントに制御ソケットで鍵の作り直しを指示する。
func rotateKeyRunning(path string) (string, error) {
	c, err := net.DialTimeout("unix", ControlPath(path), 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("agent is running but the control socket is unreachable: %w", explainControlErr(ControlPath(path), err))
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	fmt.Fprintln(c, "rotate-key")
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, "ok ") {
		return "", errors.New(strings.TrimPrefix(line, "error: "))
	}
	return "running agent regenerated its key; public key: " + strings.TrimPrefix(line, "ok "), nil
}
