<!-- docs-status: historical -->

# 2026-09-19: architecture

- userspace の dataplane を `Backend` の後ろへ移す(2026-09-19、7a.8 節の Phase 2):`internal/vpsd` のユーザー空間モードの転送面を、トンネル(`utun`)、評価器(`srcpolicy`)と合わせて `internal/dataplane/userspace` へ移した。
  agent と共有する中継(`relay`)も、`internal/agent` の下から同じ場所へ移した。
  `dataplane/userspace` が `internal/agent` を import しないようにするためである(7a.7 節)。
  userspace の `Backend` は、収束先を `Plan` だけから組み立てる。
  中継の待ち受けは `Plan` の Transparent のポートから、評価器は `Plan.Admission` のルールから、接続元 IP ごとの同時フロー数の上限は `Plan.Admission.PerSourceFlowCaps` から作る。
  プロセス全体の予算(Resource Guard)だけは起動時に受け取る。
  評価器の入力が `Plan` の転送するルール(有効で、エージェントが登録済みのもの)だけになったため、無効にしたルールと、登録を取り消したエージェントのルールの評価器の状態(バケットと送信元表)は、以前のように残らず捨てられ、再び転送するときに作り直される。
  7a.4 節をこれに合わせて改めた。
  kernel はテーブルを差し替えるたびに同じ状態を作り直しており、7a.4 節の許容差の範囲に収まる。
  これ以外の転送の挙動は変えていない。
  他テーブルの検査や `ip_forward` のような、ユーザー空間モードでは何もしないホスト側の検査は、Phase 3 で `platform/linux` の前段検査に移すまで `internal/vpsd` に残した

- VPS の kernel backend を `internal/dataplane/linuxkernel` へ移した(2026-09-19、7a.8 節 Phase 3):WireGuard(`wg`)、nftables(`nft`)、conntrack 収束(`conntrack`)、所有判定を `internal/vpsd` から `internal/dataplane/linuxkernel` の下へ移し、host 側の前段検査(他テーブルの forward/input/DNAT の検査、bind 中のポート、`ip_forward`、conntrack テーブルの大きさ、conntrack の UDP タイムアウトの読み取り)を `internal/vpsd/check` から `internal/platform/linux` へ移した。
  前項で予告したとおり、`nft.Apply`/`emit` はルール集合・エージェントのアドレス表・接続元ごとの上限の解決済みの値の代わりに `Plan` と Relay の待ち受け集合だけを受け取るようになり、行と set の連番の並びが `Plan.Ports` の順(Proto、ListenPort.Lo、RuleID)に変わった(`internal/dataplane/linuxkernel/nft/testdata/basic.nft` を更新)。
  conntrack の収束も `Backend.Converge` が `Plan` の Transparent なポートから判定材料を作る(`conntrack.RulesFromPlan`)形にし、呼び出し側(`vpsd`)はもうルール集合を組み立て直さない。
  `internal/dataplane/linuxkernel.Backend` は `dataplane.Backend` を実装し、`internal/vpsd` を import しないことを `internal/dataplane/deps_test.go` の依存方向の検査で確かめている(agent の kernel backend、Phase 7 が共通の部品を再利用できる)。
  `vpsd` 側の `kernelDataplane` は、`Backend` を包んで host 側検査を添えるだけの薄い層になった。
  Relay の宣言を組み立てる `vpsd` の `relayRules` が Phase 2 から実際に使われている経路そのものになったため、比較用に残していた `internal/vpsd/proxyrelay.FromRules` を削除し、対応する等価性テストは `Plan` からの固定の期待値と比べる形に改めた。
  停止時に wg0 とテーブルを残し起動時に収束する挙動、撤去が wgft の物だけを消す挙動は変えていない。
  ラボ(Incus VM)で、両モードの e2e、両モードの lifecycle の全確認、connlimit、kernel モードの split-merge と import-export を通し、`wgft server nft` の出力が新しい順序(TCP のポートが先に来て、set の連番は Transparent なルールだけで数える)になることを確かめた
