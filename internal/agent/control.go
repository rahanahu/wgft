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
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/rahanahu/wgft/internal/agent/credentials"
)

// 稼働中のエージェントへの指示は、認証情報ファイルの隣の Unix ソケットで受ける(仕様 9 節の rotate-key)。
// 稼働中の認証情報ファイルは flock で守られているので、外から書き換えない。

// ControlPath は認証情報ファイルに対応する制御ソケットの場所。
func ControlPath(path string) string { return path + ".sock" }

// serveControl は制御ソケットで 1 行の指示を受ける。今あるのは rotate-key だけ。
func (rt *runtime) serveControl(ctx context.Context) {
	path := ControlPath(rt.opts.CredentialsPath)
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		log.Printf("cannot open control socket %s: %v; rotate-key only works while the agent is stopped", path, err)
		return
	}
	os.Chmod(path, 0o600)
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
			log.Printf("tunnel with the new key: %v", err)
		}
	}
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
			return "", fmt.Errorf("agent is running but the control socket is unreachable: %w", err)
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
	return "agent stopped: cleared the key and last_state in the credentials file (agent.json); the next start regenerates the key and receives full state over the stream", nil
}
