package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"runtime/debug"
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

// controlPathLimit は、どの OS でも収まる制御ソケットのパスの長さ(バイト)。sockaddr_un の sun_path は
// Linux と Windows で 108 バイト、macOS で 104 バイトで、終端の NUL を含む(仕様 11a 節)。
const controlPathLimit = 103

// explainControlErr は、パスが長すぎて開けない・つなげない場合に原因と対処を添える。Go の net は
// sun_path に収まらない名前を OS を呼ぶ前に EINVAL で拒否するので、元のエラーは "invalid argument" しか言わない。
func explainControlErr(path string, err error) error {
	if err == nil || !errors.Is(err, syscall.EINVAL) || len(path) <= controlPathLimit {
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

// serveControlConn は制御ソケットの接続を 1 つ処理する。
//
// 応答を組む処理が panic しても、常駐プロセスごと落とさない(設計文書 10.2c 節)。診断のために
// 転送を止めないためである。rotate-key が触る値は少ないが、doctor は多くの値を触る。受け止めた
// 場合は接続だけを閉じ、まだ応答を書いていなければ、何が起きたかが分かる応答を返す。
func (rt *runtime) serveControlConn(c net.Conn) {
	var cmd string
	answered := false
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		log.Printf("control socket: recovered from a panic while answering %q: %v\n%s", cmd, r, debug.Stack())
		if answered {
			// 途中まで書いた応答に足すと、読み手には壊れた 1 行になる。接続を閉じるだけにする
			return
		}
		c.Write(controlPanicAnswer(cmd, r))
	}()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	cmd = strings.TrimSpace(line)
	answer := rt.answerControl(cmd)
	answered = true
	c.Write(answer)
}

// answerControl は 1 つの指示に対する応答を組む。応答の形式は指示ごとに定める。rotate-key は
// 1 行のテキスト、doctor は 1 行の JSON である(設計文書 10.2c 節)。
func (rt *runtime) answerControl(cmd string) []byte {
	switch cmd {
	case "rotate-key":
		pub, err := rt.rotateKey()
		if err != nil {
			return []byte(fmt.Sprintf("error: %v\n", err))
		}
		return []byte(fmt.Sprintf("ok %s\n", pub))
	case DoctorCommand:
		return rt.doctorResponseLine()
	}
	// 新しい実行ファイルを置いてから常駐プロセスを再起動するまでの間、新しい CLI が送る doctor は
	// 古い常駐プロセスのこの分岐に当たる。CLI はこれを、稼働中の診断が取れない場合として扱う
	// (設計文書 10.2c 節)。版の交渉も capability も要らない
	return []byte("error: unknown command\n")
}

// controlPanicAnswer は panic を受け止めたときの応答である。形式は指示に合わせる。
func controlPanicAnswer(cmd string, r any) []byte {
	msg := fmt.Sprintf("the agent panicked while answering this request: %v", r)
	if cmd == DoctorCommand {
		return doctorErrorLine(msg)
	}
	return []byte("error: " + msg + "\n")
}

// rotateKey は wg 鍵対を作り直し、トンネルを新しい鍵で張り直し、stream を張り直す(新しい公開鍵を宣言する)。
func (rt *runtime) rotateKey() (wgtypes.Key, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	rt.mu.Lock()
	rt.f.WGPrivateKey = key.String()
	if err := rt.f.Save(rt.opts.CredentialsPath); err != nil {
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
	// 判定はロックファイルを作らない Inspect で行う(設計 10.2c 節)。Acquire 経由の判定は、
	// 一度も起動していないホストで rotate-key を打っただけで、呼び出し元の権限のロックファイルを
	// 残し、後から非特権で動くエージェントの起動を塞いだ。
	state, err := credentials.Inspect(path)
	if err != nil {
		return "", err
	}
	if state == credentials.Locked {
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
	f, err := credentials.Load(path)
	if err != nil {
		return "", err
	}
	f.WGPrivateKey, f.LastState = "", nil
	if err := f.Save(path); err != nil {
		return "", err
	}
	return "agent stopped: cleared the key and last_state in the credentials file, agent.json; the next start regenerates the key and receives full state over the stream", nil
}
