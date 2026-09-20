// Package resource は Resource Guard(設計文書 7a.5、7a.10 節)。wgft 自身が保持するフローの
// プロセス全体の予算と、その予算から導くルールごとの隔離とメモリのソフト上限を持つ。
// エージェントの中継(relay)と vpsd のプロキシモードの中継(proxyrelay)が共有する。
// プロセス全体の数とルールごとの数は、Pool が 1 つの排他の中で数える。
//
// 利用者が設定する通信方針(送信元ごとの同時フロー数の上限)は Admission Policy に属し、
// internal/policy の AdmissionLimits が持つ(設計文書 7a.10 節の型の分割)。
package resource

// 仕様 7 節の値。プロセス全体の上限(WGFT_MAX_UDP_FLOWS、WGFT_MAX_TCP_FLOWS)が設定項目で、
// ここはその既定値。ルールごとの上限は設定項目ではなく、プロセス全体の上限から導く
// (Limits.UDPPerRuleCap、TCPPerRuleCap)。
const (
	UDPTotal = 8192
	TCPTotal = 2048

	// ルールごとの上限の下限。設定項目にする前の固定値で、全体の上限を下げた構成で
	// ルール 1 本の上限が以前より下がらないようにする(Limits.UDPPerRuleCap)
	UDPPerRuleFloor = 4096
	TCPPerRuleFloor = 1024

	// プロセス全体の上限に設定できる範囲
	TotalMin = 16
	TotalMax = 65535
)

// Limits はプロセス全体のフロー予算(設定値)。どの項目もゼロ値なら既定値を使う(WithDefaults)。
// ゼロ値を「上限なし」にすると、設定層を通らずに組み立てた Limits で守りが黙って外れるためである。
type Limits struct {
	UDPTotal int
	TCPTotal int
}

// WithDefaults はゼロ値の項目を既定値で埋める。
func (l Limits) WithDefaults() Limits {
	if l.UDPTotal <= 0 {
		l.UDPTotal = UDPTotal
	}
	if l.TCPTotal <= 0 {
		l.TCPTotal = TCPTotal
	}
	return l
}

// UDPPerRuleCap と TCPPerRuleCap は、ルールごとの同時フロー数の上限をプロセス全体の上限から
// 導く(仕様 7 節)。全体の半分とするが、以前の固定値と全体の上限の小さいほうを下回らない。
// 全体を上げれば一緒に上がり、既定や全体を下げた構成では以前と同じ値になる。
func (l Limits) UDPPerRuleCap() int { return perRuleCap(l.WithDefaults().UDPTotal, UDPPerRuleFloor) }
func (l Limits) TCPPerRuleCap() int { return perRuleCap(l.WithDefaults().TCPTotal, TCPPerRuleFloor) }

func perRuleCap(total, floor int) int { return max(total/2, min(floor, total), 1) }

// MemoryLimit は、この上限で動くプロセスに設定するメモリのソフト上限(バイト)。
// 係数はラボの実測からの定数で、ホストのメモリの量は見ない(仕様 7 節)。
func (l Limits) MemoryLimit() int64 {
	l = l.WithDefaults()
	return 32<<20 + int64(l.UDPTotal)*(12<<10) + int64(l.TCPTotal)*(44<<10)
}
