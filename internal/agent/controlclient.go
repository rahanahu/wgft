package agent

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/rahanahu/wgft/internal/agent/controlapi"
	"github.com/rahanahu/wgft/internal/agent/credentials"
	"github.com/rahanahu/wgft/internal/textsafe"
)

// RotateKey は CLI から呼ぶ。稼働中なら制御ソケット経由で、停止中なら認証情報ファイルの鍵と last_state を直接消す。
func RotateKey(path string) (string, error) {
	// 判定とロックの取り方は credentials.LockWhileStopped にある。判定はロックファイルを作らない Inspect で行う
	// (設計 10.2c 節)。Acquire 経由の判定は、ロックファイルの無いデータディレクトリで rotate-key を
	// 打っただけで、呼び出し元の権限のロックファイルを残し、後から非特権で動くエージェントの起動を塞いだ。
	// ロックファイルがあって誰も持っていなければ、ロックを取ってから書き換える。取らないと、判定の後に
	// 起動したエージェントが書いた記録(カーネルモードへの切り替えの記録など)を、この書き換えが古い
	// 内容で上書きしうる(仕様 9 節)
	release, running, err := credentials.LockWhileStopped(path, inspectLock)
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
	// カーネルモードでは、消す鍵を 1 つ前の鍵として残す(仕様 7b.4 節)。wgft0 はまだその鍵を持つので、
	// 次の起動は 1 つ前の鍵で wgft0 を自分のものと判定し、新しい鍵へ書き換える
	kernel := f.RecordedMode() == credentials.ModeKernel
	f.KeepPreviousKey()
	f.WGPrivateKey, f.LastState = "", nil
	if err := f.Save(path); err != nil {
		return "", err
	}
	if rotateKeyLockedHook != nil {
		rotateKeyLockedHook()
	}
	msg := "agent stopped: cleared the key and last_state in the credentials file, agent.json; the next start regenerates the key and receives full state over the stream"
	if kernel {
		msg += "; the old key is kept as the previous key, so the next start still recognises the kernel WireGuard interface that holds it and moves it to the new key"
	}
	return msg, nil
}

// rotateKeyLockedHook は、停止中の rotate-key が認証情報ファイルを書いた後、ロックを放す前に呼ばれる。
// テストだけが、読んでから書き終えるまでロックを持っていることを確かめるために設定する。
var rotateKeyLockedHook func()

// inspectLock はロックの状態を読む。値は credentials.Inspect で、テストだけが、判定と取得の間に
// エージェントが起動した場合を模すために差し替える。
var inspectLock = credentials.Inspect

// rotateKeyReplyLimit は、稼働中の rotate-key が制御ソケットから読む応答の大きさの上限である。
const rotateKeyReplyLimit = 64 << 10

// rotateKeyRunning は、稼働中のエージェントに制御ソケットで鍵の作り直しを指示する。
func rotateKeyRunning(path string) (string, error) {
	c, err := net.DialTimeout("unix", controlapi.ControlPath(path), 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("agent is running but the control socket is unreachable: %w", explainControlErr(controlapi.ControlPath(path), err))
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	fmt.Fprintln(c, "rotate-key")
	// 応答の 1 行は "ok <公開鍵>" か "error: <文言>" で短い。読む量に上限を置き、root の CLI が
	// 改行を送らない相手にメモリを使い切られないようにする(仕様 11 節)。上限に当たった場合は
	// controlapi.ReadControlReply がそのことを名指す誤りを返す(design.md 11 節、レビューの指摘)。
	line, err := controlapi.ReadControlReply(c, rotateKeyReplyLimit)
	if err != nil {
		return "", err
	}
	// design.md 11 節: a compromised running agent answers this socket itself, so its reply is
	// not trusted text before it reaches the operator's terminal, regardless of the "ok "/
	// "error: " shape a well-behaved agent always uses.
	line = textsafe.SanitizeForTerminal(strings.TrimSpace(line))
	if !strings.HasPrefix(line, "ok ") {
		return "", errors.New(strings.TrimPrefix(line, "error: "))
	}
	return "running agent regenerated its key; public key: " + strings.TrimPrefix(line, "ok "), nil
}
