package wgstack

import "time"

// 値はどれも設定項目にしない(設計文書 wgstack.md の「メモリの模型」と「上界の式」)。初期の値は動作を
// 確かめるための値であり、最適値として探した値ではない。

// バッファと boost の値。今の TCP バッファ(tcp-buffers.md)と同じ値である。
const (
	chunkShift = 14
	chunkSize  = 1 << chunkShift // バッファの中身を持つ chunk。Go のメモリの大きさの区分と一致する

	sendFloor  = 256 << 10 // f_s
	recvFloor  = 256 << 10 // f_r
	boostSize  = 4 << 20   // floor + d_s、floor + d_r
	boostSlots = 16        // B。プロセスで 1 つの枠の集まり

	// minSegPayload は送り残しを分ける大きさの下限(packet-validation.md の TCP の MSS の下限)。
	// 送信の記録の輪の容量は、送信のバッファの予約をこの値で割った数である
	minSegPayload = 472
	floorRecords  = (sendFloor + minSegPayload - 1) / minSegPayload // 556
	boostRecords  = (boostSize + minSegPayload - 1) / minSegPayload // 8,887

	demandWindow = 250 * time.Millisecond // 需要の区間
	demandBytes  = 64 << 10               // 区間に読めたか受け入れた byte がこの値以上なら需要がある
	idleReclaim  = time.Second            // 需要の無い保有者を floor に戻せるまでの時間
)

// 表の大きさ。
const (
	defaultMaxFlows = 2048  // K の既定値(WGFT_MAX_TCP_FLOWS の既定値と同じ)
	acceptQueueAll  = 512   // Q。Device 全体の accept の待ち行列
	synRowsAll      = 1024  // N_syn。握手の途中の表の行
	twRowsAll       = 65536 // M。TIME_WAIT と FIN_WAIT_2 の行
	oooIntervals    = 32    // H。受信のバッファの順序外の区間
	ctlSlots        = 256   // Q_ctl。制御の出力の輪の枠
)

// TCP の値。参照の実装の Linux の既定に合わせる(設計文書の「TCP の機能」)。
const (
	minMSS        = 536 // SYN の MSS の下限で、MSS の option が無いときの値(RFC 1122)
	minPMTU       = 552 // Fragmentation Needed の next-hop MTU の下限(Linux の min_pmtu)
	ipHeaderLen   = 20
	tcpHeaderLen  = 20
	maxOptionLen  = 40
	tsOptionLen   = 12 // NOP NOP TS の 12 byte
	rcvWindowShft = 7  // boost の 4 MiB を広告できる窓の scale

	rtoInit = time.Second
	rtoMin  = 200 * time.Millisecond
	rtoMax  = 120 * time.Second

	delackTimeout = 40 * time.Millisecond // Linux の TCP_DELACK_MIN
	twTimeout     = 60 * time.Second      // TIME_WAIT(Linux の TCP_TIMEWAIT_LEN)
	finTimeout    = 60 * time.Second      // 閉じた後の FIN_WAIT_2(Linux の tcp_fin_timeout)

	synackRetries = 5           // Linux の tcp_synack_retries
	synackRTO     = time.Second // 最初の SYN-ACK の再送までの時間(Linux の TCP_TIMEOUT_INIT)
	retries2      = 15          // Linux の tcp_retries2
	probeRetries  = 15          // 応答の無い窓の probe の上限(Linux の tcp_retries2 を使う)
	orphanRetries = 8           // 閉じた接続の窓の probe の後退の上限(Linux の tcp_orphan_retries の既定 0 が使う値)

	initialWindowSegs = 10 // IW10(RFC 6928、Linux の既定)

	challengeAckLimit = 1000 // 1 秒あたりの challenge ACK(Linux の tcp_challenge_ack_limit)

	defaultTTL = 64
)

// retransmitDeadline は、Linux の tcp_model_timeout と同じく、最小の RTO から倍にしていった
// retries2 回の再送が使う時間。握手の後の再送はこの時間で打ち切る。
var retransmitDeadline = func() time.Duration {
	var total time.Duration
	rto := rtoMin
	for i := 0; i <= retries2; i++ {
		total += rto
		rto = min(rto*2, rtoMax)
	}
	return total
}()
