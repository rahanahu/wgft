//go:build linux

package kernelmode

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"github.com/rahanahu/wgft/internal/dataplane/linuxkernel/wg"
)

// startKeepalive は、keepalive ごとに wgft0 を通して vpsd のトンネルアドレスへ小さな UDP のデータ
// グラムを 1 つ送る goroutine を立て直す(7b.1 節のセッションの回復)。keepalive のパケットだけでは、
// vpsd の側がセッションを失ったときに新しいハンドシェイクが鍵の寿命まで始まらない。データを送れば、
// 応答が無いまま 15 秒たったところで WireGuard がハンドシェイクをやり直す。応答は要らない。
// keepalive が 0 なら送らない。goroutine は ops と、立てたときの宛先と間隔だけを使い、排他を取らない。
// 送れない間は、理由が変わったときだけ 1 行出す。ピアにエンドポイントが無い間(名前がまだ解決できて
// いないとき)は、そのことを出す。
func (d *Dataplane) startKeepalive() {
	d.stopKeepalive()
	if d.WG.Keepalive <= 0 {
		return
	}
	unit := d.kaUnit
	if unit <= 0 {
		unit = time.Second
	}
	every := time.Duration(d.WG.Keepalive) * unit
	dst := netip.AddrPortFrom(d.server, kernelSessionPort)
	send, iface := d.Ops.SendDatagram, d.iface
	ctx, cancel := context.WithCancel(d.ctx)
	d.kaStop = cancel
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		last := ""
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			err := send(dst)
			reason := sendFailure(err)
			if reason == last {
				continue
			}
			switch {
			case err == nil:
				log.Printf("kernel mode: the keepalive datagram to %s is sent again", dst)
			case errors.Is(err, syscall.EDESTADDRREQ):
				log.Printf("kernel mode: cannot send the keepalive datagram to %s yet: the server peer on %s has no endpoint, as when the endpoint name has not resolved; it is sent once the peer has one", dst, iface)
			default:
				log.Printf("kernel mode: cannot send the keepalive datagram to %s: %s; until this works, a session the server lost may recover only when its keys expire", dst, reason)
			}
			last = reason
		}
	}()
}

// sendFailure は、データグラムを送れなかった理由を、ログを出し直すかの比べに使う形にする。送れたら空で
// ある。net の書き込みの誤りは送信元のポートを含み、送るたびに違うので、下層の errno があればそれで
// 比べる。
func sendFailure(err error) string {
	if err == nil {
		return ""
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	var op *net.OpError
	if errors.As(err, &op) && op.Err != nil {
		return op.Err.Error()
	}
	return err.Error()
}

func (d *Dataplane) stopKeepalive() {
	if d.kaStop != nil {
		d.kaStop()
		d.kaStop = nil
	}
}

// watchHandshake は、wgft0 の最終ハンドシェイクが keepalive の 5 倍の間新しくならなければ、次の見直しで
// エンドポイントの名前を引き直すよう印を付ける(7b.1 節、4 節と同じ契機)。カーネルの WireGuard は
// 名前を自分では引き直さない。IP リテラルのエンドポイントと keepalive が 0 の設定では引き直さない。
func (d *Dataplane) watchHandshake(st wg.AgentState) {
	var hs time.Time
	for _, p := range st.Peers {
		hs = p.LastHandshake
	}
	now := d.Ops.Now()
	if !hs.Equal(d.hsValue) || d.hsSince.IsZero() {
		d.hsValue, d.hsSince = hs, now
	}
	if d.WG.Keepalive <= 0 {
		return
	}
	host, _, err := net.SplitHostPort(d.WG.Endpoint)
	if err != nil {
		return
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return
	}
	if now.Sub(d.hsSince) >= 5*time.Duration(d.WG.Keepalive)*time.Second {
		d.epMu.Lock()
		d.endpointStale = true
		d.epMu.Unlock()
	}
}

// reResolved は、見直しが引き直したエンドポイントを控えに入れ、wgft0 のピアへ設定する。引けなかった
// 場合は控えを使い続ける。どちらの場合も、次に引き直すのはさらに keepalive の 5 倍の後である。ただし
// wgft0 の収束に失敗したら、次の見直しで試し直す。
func (d *Dataplane) reResolved(p *kernelPrepared) error {
	d.epMu.Lock()
	before := d.endpoint
	d.epMu.Unlock()
	d.useEndpoint(p)
	if p.endpointEr != nil {
		d.resolvedAgain()
		return nil
	}
	if p.endpoint != before {
		log.Printf("kernel mode: no new handshake for 5 times the keepalive; resolved the server endpoint %s again to %s", p.endpointOf, p.endpoint)
	}
	// アドレスが変わらなくても wgft0 を収束させる。カーネルのピアのエンドポイントが外から書き換えられて
	// いれば、ここで戻る。収束に失敗したら印を残し、次の見直しで引き直しと収束を試し直す
	cfg, err := d.LinkConfig()
	if err != nil {
		return err
	}
	changes, err := d.Ops.EnsureLink(cfg)
	if err != nil {
		return fmt.Errorf("converge %s: %w", d.iface, err)
	}
	if len(changes) > 0 {
		log.Printf("kernel mode: %s: %s", d.iface, strings.Join(changes, "; "))
	}
	d.resolvedAgain()
	return nil
}

// resolvedAgain は引き直しの印を消し、次に引き直すまでの keepalive の 5 倍を数え直す。
func (d *Dataplane) resolvedAgain() {
	d.epMu.Lock()
	d.endpointStale = false
	d.epMu.Unlock()
	d.hsSince = d.Ops.Now()
}
