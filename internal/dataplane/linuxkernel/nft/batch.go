//go:build linux

package nft

import (
	"github.com/google/nftables"
	"github.com/mdlayher/netlink"
)

// テーブルの差し替えは、nftables のバッチ 1 つ、すなわち netlink のデータグラム 1 つとして送る
// (設計文書 6.1 節)。カーネルの nfnetlink は 1 つの skb の中だけでバッチを読むため、
// NFNL_MSG_BATCH_BEGIN から NFNL_MSG_BATCH_END までを複数のデータグラムに分ける余地は無い。
// そのため、バッチの大きさと、カーネルが返す応答の量は、どちらも 1 つのソケットの
// バッファに収まらなければならない。既定のバッファのままだと次の 2 つで失敗する。
//
//   - 送信側: netlink は sk_sndbuf を超える長さの sendmsg を EMSGSIZE で拒む
//   - 受信側: バッチの 1 通ごとに ACK が返り、google/nftables はルールの 1 通ごとに
//     NLM_F_ECHO も立てるので、応答はバッチ自身より大きくなる。送り終えるまで読み出さない
//     作りなので、応答は受信キューに積み上がり、あふれるとカーネルが ENOBUFS を立てて捨てる
//
// そこで、組み立てながらバッチの大きさを数え、送る直前にソケットのバッファをその大きさに
// 合わせる。nft コマンド自身も同じ手順を取り、送信側を SO_SNDBUFFORCE でバッチの長さに、
// 受信側を SO_RCVBUFFORCE で命令の数に比例した大きさにしてから、1 回の sendmsg で送る。
const (
	// msgOverhead は 1 通あたりの固定部分の上限。netlink のヘッダ 16 バイト、nfgenmsg 4 バイト、
	// テーブル名、チェーン名、set 名、種類ごとの固定の属性を含む。
	msgOverhead = 256
	// exprBytes は式 1 つの上限。最も大きい式(set への add と、その中に入れるレートの式)でも
	// この値に収まる。
	exprBytes = 160
	// elemBytes は set の要素 1 つの上限。map の要素の値を含めても収まる。要素は 1 通に入る数ずつ
	// 分けて送る(server の送信元の一覧は elemsPerMessage、agent の map は setElemChunk)。
	elemBytes = 48
	// ackBytes は応答 1 通あたりにカーネルが受信キューで使う量の見積もり。ACK 自身は数十バイトだが、
	// skb 1 つ分の管理領域が加わるため、この値で数える。
	ackBytes = 1024
	// minBuffer は要求するバッファの下限。既定値(Linux の rmem_default / wmem_default は 212992)を
	// 下回らせないために置く。
	minBuffer = 1 << 20
	// maxBuffer は要求するバッファの上限。見積もりが大きくなりすぎても、カーネルに際限のない
	// 大きさを要求しないために置く。
	maxBuffer = 64 << 20
)

// batchSize は、組み立て中のバッチが占める netlink のメッセージの数と大きさの見積もりである。
// 大きさは上限として数えるので、実際のバッチより小さくなることは無い。
type batchSize struct {
	messages int
	bytes    int
}

func (b *batchSize) add(extra int) {
	b.messages++
	b.bytes += msgOverhead + extra
}

// bufferSizes は、setsockopt で要求する送信側と受信側の大きさを返す。カーネルは要求された値を
// 2 倍にして上限とするので、この値自体に余裕を持たせる必要は無い。
//
// 受信側は、ECHO で返るルールの写し(バッチとほぼ同じ大きさ)と、1 通ごとの ACK の分を足す。
func (b batchSize) bufferSizes() (send, receive int) {
	return clampBuffer(b.bytes), clampBuffer(b.bytes + ackBytes*b.messages)
}

func clampBuffer(n int) int {
	switch {
	case n < minBuffer:
		return minBuffer
	case n > maxBuffer:
		return maxBuffer
	default:
		return n
	}
}

// sizing は emitter を包んで、組み立てたメッセージの数と大きさを数える。数えるだけで、
// 組み立ての結果は変えない。
type sizing struct {
	to   emitter
	size *batchSize
}

var _ emitter = (*sizing)(nil)

func (s *sizing) AddTable(t *nftables.Table) *nftables.Table {
	s.size.add(0)
	return s.to.AddTable(t)
}

func (s *sizing) DelTable(t *nftables.Table) {
	s.size.add(0)
	s.to.DelTable(t)
}

func (s *sizing) AddChain(c *nftables.Chain) *nftables.Chain {
	s.size.add(0)
	return s.to.AddChain(c)
}

func (s *sizing) AddSet(set *nftables.Set, els []nftables.SetElement) error {
	s.size.add(0) // set の宣言
	if len(els) > 0 {
		s.size.add(len(els) * elemBytes) // AddSet に渡した要素は 1 通にまとめて入る
	}
	return s.to.AddSet(set, els)
}

func (s *sizing) SetAddElements(set *nftables.Set, els []nftables.SetElement) error {
	s.size.add(len(els) * elemBytes)
	return s.to.SetAddElements(set, els)
}

func (s *sizing) AddRule(r *nftables.Rule) *nftables.Rule {
	s.size.add(len(r.Exprs)*exprBytes + len(r.UserData))
	return s.to.AddRule(r)
}

// sizeSocket は、バッチを送る netlink のソケットのバッファを数えた大きさに合わせる。
// nftables.Conn は Flush の中でソケットを開くので、この関数が呼ばれるのは組み立てが
// 終わった後であり、s.size は確定している。
//
// 上げられなかった場合も誤りを返さず、そのまま送る。mdlayher/netlink は SO_RCVBUFFORCE と
// SO_SNDBUFFORCE を先に試し、権限が無ければ SO_RCVBUF と SO_SNDBUF に落とす。FORCE の側は
// init の user namespace での CAP_NET_ADMIN を要するので、user namespace を分けた非特権の
// コンテナでは落ちる。落ちた場合は net.core.rmem_max / wmem_max の 2 倍で頭打ちになり、
// 要求した大きさに届かないことがある。届かなければ、これまでと同じ netlink の誤りが
// Flush から返る。
func (s *Staged) sizeSocket(c *netlink.Conn) error {
	send, receive := s.size.bufferSizes()
	_ = c.SetWriteBuffer(send)
	_ = c.SetReadBuffer(receive)
	return nil
}

// set の要素は、1 通の NFT_MSG_NEWSETELEM の中で NFTA_SET_ELEM_LIST_ELEMENTS という 1 つの入れ子の
// 属性にまとめて入る。netlink の属性の長さは 16 ビットなので、この属性は 65535 バイトを超えられない。
// google/nftables v0.3.0 は 1 回の呼び出しの要素をすべてこの 1 つの属性に入れ、mdlayher/netlink は
// 長さが 16 ビットに収まるかを検査せずに下位 16 ビットだけを書く。カーネルはその短い長さの分だけを
// 要素の一覧として読むので、要素の欠けた set が誤りを返さずに公開される。重なり合わない /32 を
// 1638 個持つ送信元の一覧で set が空になり、1700 個で 62 要素だけが残った(ラボで確かめた。設計文書
// 6.1 節)。そこで要素を elemsPerMessage 個ずつ別の NEWSETELEM に分け、同じバッチで送る。分けても
// 同じバッチの中なので、差し替えの不可分性は変わらない。
const (
	// elemListLimit は、1 通の要素の一覧(NFTA_SET_ELEM_LIST_ELEMENTS の属性の全体)に許す長さ。
	// 16 ビットの上限の半分にして、要素の符号化が少し長くなっても上限に届かない余裕を持たせる。
	elemListLimit = 32 << 10
	// elemListBytes は、IPv4 のキーの要素 1 つが一覧の中で占める長さの上限。区間の終端の印を持つ
	// 要素が最も長く、要素の見出し 4 バイト、flags の属性 8 バイト、key の属性 12 バイトの計 24 バイトになる。
	elemListBytes = 24
)

// elemsPerMessage は 1 通の NEWSETELEM に入れる要素の数の上限で、一覧の見出しの 4 バイトを足しても
// elemListLimit に収まる。変数にしてあるのは、分けずに送っていた以前の形をラボのテストが再現する
// ためだけであり、本番のコードは書き換えない。
var elemsPerMessage = (elemListLimit - 4) / elemListBytes

// elementChunks は set の要素の列を n 個以下ずつに分ける。区間の開始と、その直後の終端の印は同じ
// 通に入れる。どの通も区間を丸ごと持つので、通と通の間に、開始だけがあって終端の無い区間ができない。
// 切れ目の直後が終端の印なら、1 つ手前で切る。先頭の 0.0.0.0 の終端の印は最初の通に入る。
// n は 2 以上でなければならない。
func elementChunks(els []nftables.SetElement, n int) [][]nftables.SetElement {
	var out [][]nftables.SetElement
	for len(els) > n {
		cut := n
		for cut > 1 && els[cut].IntervalEnd {
			cut--
		}
		out = append(out, els[:cut])
		els = els[cut:]
	}
	if len(els) > 0 {
		out = append(out, els)
	}
	return out
}
