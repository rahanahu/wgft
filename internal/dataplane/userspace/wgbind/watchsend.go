package wgbind

import "golang.zx2c4.com/wireguard/conn"

// WatchSend は inner を包み、Send ごとに、内側の Send を呼ぶ前に observe へ message の列を渡すバインドを
// 返す。wgstack を使うトンネルの送信の向きの予算が、送った番号を知るための層である(設計文書
// wgstack-batching.md の「Device の約束」)。observe は message を読むだけで、書き換えず、保持しない。
//
// observe を内側の Send より前に呼ぶのは、Linux の IPv6 の宛先で内側の GSO のまとめがまとまりの最初の
// buffer の末尾を書く前に、末尾の印を読むためである。Send の誤りは内側のものをそのまま返す。受信と BatchSize
// は内側のものをそのまま使うので、受信の 1 回の件数は変わらない。
//
// wgbind は wgstack を import しないので、observe はトンネルの package が関数の値で渡す。
func WatchSend(inner conn.Bind, observe func(bufs [][]byte)) conn.Bind {
	return &sendWatch{Bind: inner, observe: observe}
}

type sendWatch struct {
	conn.Bind
	observe func(bufs [][]byte)
}

func (w *sendWatch) Send(bufs [][]byte, ep conn.Endpoint) error {
	w.observe(bufs)
	return w.Bind.Send(bufs, ep)
}
