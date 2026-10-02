// Package kernelmode はエージェントのカーネルモードの dataplane を持つ(設計文書 7a.7 節)。
// internal/dataplane/linuxkernel の部品で、カーネルの WireGuard インタフェースと table inet wgft_agent を
// 宣言へ収束させ、internal/agent/agentdp の Dataplane を満たす。停止中の agent doctor が読むカーネルの
// 読み取り ReadKernel も持ち、稼働中のエージェントも同じ読み方を使う。internal/agent の下では agentdp、
// allowtargets、credentials、controlapi だけを import する。カーネルモードは Linux だけにある。
//
// 本番のコードが package の外から使ってよい名前は New、Built、Prerequisites、ProcessNetAdmin、ReadKernel
// である。実行時の状態は New の結果を agentdp.Dataplane として持ち、型 Dataplane を名指さず、そのメソッドも
// 直接は呼ばない。ほかの公開した名前は internal/agent のテストのための口であり、型 Dataplane、その
// フィールド Ops、Priv、WG、Pub、ObserveErr とメソッド LinkConfig、関数 NewWithOps、型 Ops と DoctorOps と
// それぞれのフィールド、変数 DoctorKernelOps、定数 MaxUnconverged が当たる。
// internal/dataplane/deps_test.go の TestAgentModeTestSeamsStayInTests がこれを検査する。
package kernelmode
