//go:build !unix

package relay

import "net"

// newReplySender は unix でない GOOS では常に WriteTo で送る。vpsd は Linux でしか動かず
// (設計文書 6.3 節)、エージェントの公開側は netstack の待ち受けなので、待たずに 1 回だけ送る形は
// 要らない。
func newReplySender(pc net.PacketConn, from net.Addr) replySender {
	return waitingSender{pc: pc, to: from}
}
