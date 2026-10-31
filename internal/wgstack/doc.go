// Package wgstack は、ユーザー空間モードのエージェントが gVisor の netstack の代わりに選べる、wgft が持つ
// netstack である(docs/design/userspace/wgstack.md)。TCP の核と Device に加えて、UDP、ICMP の echo と ping、
// internal/nettun と共有する断片の再組み立ての表(internal/ipv4frag)を持つ。エージェントは
// WGFT_AGENT_NETSTACK=wgstack でこれを選び、トンネルは非公開の interface を通して使う。
//
// # 構造
//
// 決定的な核(stack)は goroutine を作らず、時計と乱数を直接読まない(例外は stack の説明にある)。操作は「packet と時刻を受けて状態を
// 変え、出力を返す」「時刻を受けてタイマーを進める」「アプリケーションの操作」の 3 種類だけである。表と固定の
// 配列は作成の時に確保し、バッファの中身は予約した量まで 16 KiB の chunk で確保する。Device は核を
// wireguard-go の tun.Device として動かし、タイマーを進める goroutine を 1 つだけ持つ。入力は Write の中で
// 同期して処理し、出力は Read の中でその場で作る。
//
// # 適合の試験のための構成
//
// 試験は Config に手で進める時計(ManualClock)と固定の乱数の種を渡して New を呼ぶ。そのとき Device は
// goroutine を作らず、呼び出し側が時刻を進める。
//
//	clk := wgstack.NewManualClock()
//	dev, err := wgstack.New(wgstack.Config{
//		Addr:  netip.MustParseAddr("10.0.0.1"),
//		MTU:   1420,
//		Clock: clk,
//		Rand:  bytes.NewReader(seed), // 64 byte 以上
//	})
//	l, err := dev.ListenTCP(netip.AddrPortFrom(addr, 80))
//	dev.Write([][]byte{pkt}, 0)        // トンネルからの packet を入れる。出力はその場で作られる
//	n := dev.Poll(buf)                 // 送る packet を待たずに 1 つ取り出す。無ければ 0
//	clk.Advance(10 * time.Millisecond) // 時刻を進め、
//	dev.Tick()                         // 期限の来たタイマーを動かす
//
// Write と Tick が送らせた packet は、呼び出しが戻った時点で Poll から読める。アプリケーションの操作
// (Accept が返す *Conn の Read、Write、CloseWrite、Close、Abort)の読み書きの期限だけは壁時計で測る。
// Config.Clock を渡さない Device は本番と同じく単調な時計と crypto/rand を使い、Read は送るものができるまで
// 待つ。Create(addr, mtu) は internal/nettun.Create と同じ形の本番の構成である。
//
// Accept が返す *Conn は net.Conn に加えて、中継と internal/netpipe が型アサーションで探す Abort、
// CloseWrite、Delivered、CloseForDelivery、OnBoost を持つ。Stats は会計が数える保持と拒否の数を、Bound は
// 上界の式の値を返す。
package wgstack
