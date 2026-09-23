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

// serveControl は制御ソケットで 1 行の指示を受ける。今あるのは rotate-key だけ。
func (rt *runtime) serveControl(ctx context.Context) {
	path := ControlPath(rt.opts.CredentialsPath)
	os.Remove(path)
	ln, err := listenControl(path)
	if err != nil {
		log.Printf("cannot open control socket %s: %v; rotate-key only works while the agent is stopped", path, err)
		return
	}
	// credentials.SecureSocket はこのソケットだけを単独で締める(Windows は保護 DACL で
	// 失敗を伝える。Unix はこの修正より前と同じく 0600 の chmod で、失敗は無視する。
	// 仕様 9・11a 節)。秘密は持たないが、agent.json と同じ基準にそろえる。
	if err := credentials.SecureSocket(path); err != nil {
		log.Printf("cannot secure control socket %s: %v; rotate-key only works while the agent is stopped", path, err)
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
			c.SetDeadline(time.Now().Add(30 * time.Second))
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				return
			}
			switch strings.TrimSpace(line) {
			case "rotate-key":
				pub, err := rt.rotateKey()
				if err != nil {
					fmt.Fprintf(c, "error: %v\n", err)
					return
				}
				fmt.Fprintf(c, "ok %s\n", pub)
			default:
				fmt.Fprintf(c, "error: unknown command\n")
			}
		}()
	}
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
	locked, err := credentials.IsLocked(path)
	if err != nil {
		return "", err
	}
	if locked {
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
