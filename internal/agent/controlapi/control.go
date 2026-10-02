package controlapi

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
)

// ControlPath は認証情報ファイルに対応する制御ソケットの場所。
func ControlPath(path string) string { return path + ".sock" }

// ControlPathLimit は、どの OS でも収まる制御ソケットのパスの長さ(バイト)。sockaddr_un の sun_path は
// Linux と Windows で 108 バイト、macOS で 104 バイトで、終端の NUL を含む(仕様 11a 節)。
//
// 公開しているのは、繋げなかった理由が長さにあるかどうかを外から判定する読み手がいるためである
// (設計文書 10.2c 節の agent.control)。写しを持たせると、片方だけを直したときに判定が食い違う。
const ControlPathLimit = 103

// DoctorReplyMaxBytes bounds how much of a reply `wgft agent doctor` reads from the control
// socket before giving up (cmd/wgft/agentdoctorlive.go's readAgentLive). Both sides of this socket
// run on the same host, but design.md 11 節 treats the agent process as outside the trust
// boundary: a compromised agent binary could otherwise hold the line open and never send the
// newline bufio.Reader.ReadString waits for, growing its internal buffer without bound. The value
// matches internal/agent/stream.go's SetReadLimit for the full state this agent reads from the
// server over the WebSocket stream, which is the same order of magnitude as the largest
// legitimate reply this socket carries: a doctor response listing every rule this agent holds.
// internal/agent/control's rotate-key read uses a much smaller limit, rotateKeyReplyLimit, since
// its reply is always a short "ok <key>" or "error: <text>" line.
const DoctorReplyMaxBytes = 4 << 20

// ReadControlReply reads one line from a control-socket connection under max bytes, shared by
// internal/agent/control's rotateKeyRunning (with rotateKeyReplyLimit) and
// cmd/wgft/agentdoctorlive.go's readAgentLive (with DoctorReplyMaxBytes): both connect to this
// socket by their own means, but both read a line off it, under their own size limit, the same
// way.
//
// A reply that hits the cap without ever sending the newline bufio.Reader.ReadString waits for
// comes back as a plain io.EOF from the underlying reader, indistinguishable on its face from a
// well-behaved agent that simply closed the connection early after a short reply. That distinction
// matters to an operator reading the error: an early close points at the agent process (it stopped
// answering), while hitting the cap points at this size limit itself. This function tells them
// apart by the byte count actually read: an early close reads fewer than max bytes before EOF,
// while hitting the cap reads exactly that many (レビューの指摘, 2026-09-26).
func ReadControlReply(c net.Conn, max int64) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(c, max)).ReadString('\n')
	if err != nil {
		if errors.Is(err, io.EOF) && int64(len(line)) >= max {
			return "", fmt.Errorf("the agent's reply exceeded the %d-byte limit without a newline", max)
		}
		return "", err
	}
	return line, nil
}
