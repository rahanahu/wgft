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

	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// 稼働中のエージェントへの指示は、認証情報ファイルの隣の Unix ソケットで受ける(仕様 9 節の rotate-key)。
// 稼働中の認証情報ファイルは flock で守られているので、外から書き換えない。
// ソケットのパスの規則と応答の読み取りは internal/agent/controlapi にある。

// explainControlErr は、パスが長すぎて開けない・つなげない場合に原因と対処を添える。Go の net は
// sun_path に収まらない名前を OS を呼ぶ前に EINVAL で拒否するので、元のエラーは "invalid argument" しか言わない。
func explainControlErr(path string, err error) error {
	if err == nil || !errors.Is(err, syscall.EINVAL) || len(path) <= controlapi.ControlPathLimit {
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
	path := controlapi.ControlPath(rt.opts.CredentialsPath)
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
	case controlapi.DoctorCommand:
		c.Write(rt.doctorResponseLine())
	default:
		// 新しい実行ファイルを置いてから常駐プロセスを再起動するまでの間、新しい CLI が送る
		// doctor は古い常駐プロセスのこの分岐に当たる。CLI はこれを、稼働中の診断が取れない
		// 場合として扱う(設計文書 10.2c 節)。版の交渉も capability も要らない
		fmt.Fprintf(c, "error: unknown command\n")
	}
}
