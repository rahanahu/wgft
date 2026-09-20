package policy

// 仕様 7 節の値。接続元 IP ごとの上限(WGFT_MAX_UDP_FLOWS_PER_SOURCE、
// WGFT_MAX_TCP_FLOWS_PER_SOURCE。vpsd だけの設定。11a 節)の既定値。
const (
	UDPPerSource = 256
	TCPPerSource = 128
)

// PerSourceOff は AdmissionLimits.UDPPerSource/TCPPerSource で、接続元 IP ごとの上限を外すことを
// 表す。設定の 0(上限なし)は設定層がこれに写す。
const PerSourceOff = -1

// AdmissionLimits は、ルールではなく server の設定から来る Admission Policy の入力(設計文書
// 7a.5、7a.10 節)。今は接続元 IP ごとの同時フロー数の上限だけを持つ。どの項目もゼロ値なら
// 既定値を使う(WithDefaults)。ゼロ値を「上限なし」にすると、設定層を通らずに組み立てた値で
// 守りが黙って外れるためである。上限を外すときは PerSourceOff を入れる。
//
// プロセス全体のフロー予算は Resource Guard に属し、internal/resource の Limits が持つ。
type AdmissionLimits struct {
	UDPPerSource int
	TCPPerSource int
}

// WithDefaults はゼロ値の項目を既定値で埋める。
func (l AdmissionLimits) WithDefaults() AdmissionLimits {
	if l.UDPPerSource == 0 {
		l.UDPPerSource = UDPPerSource
	}
	if l.TCPPerSource == 0 {
		l.TCPPerSource = TCPPerSource
	}
	return l
}

// UDPPerSourceCap と TCPPerSourceCap は、接続元 IP ごとの上限の実効値。0 は上限なし
// (PerSourceFlowCaps の約束に合わせる)。
func (l AdmissionLimits) UDPPerSourceCap() int { return max(l.WithDefaults().UDPPerSource, 0) }
func (l AdmissionLimits) TCPPerSourceCap() int { return max(l.WithDefaults().TCPPerSource, 0) }
