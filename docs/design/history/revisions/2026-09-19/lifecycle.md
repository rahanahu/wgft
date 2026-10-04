<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 64, 67, 69 です。

# 2026-09-19: lifecycle

- Runtime として frontend と dataplane の participant を束ねる(2026-09-19、レビュー反映):7a.2、7a.3、7a.7 を改めた。
  `Backend`(kernel/userspace の dataplane)と、Observe/Prepare/Commit/Rollback を持つ transaction の participant は別の概念であり、`Relay` の listener 集合のような frontend 側の資源も participant になりうる。
  `Reconciler` は `Backend` を直接動かさず、frontend と dataplane の participant を固定順序(frontend の `Prepare` → dataplane の `Commit` → frontend の `Commit`、失敗時は逆順の `Rollback`)で束ねた `Runtime` を動かす形に改めた。
  今の `internal/vpsd/proxyrelay` の `Prepare`/`Commit`/`Rollback` と `apply.go` の呼び出し順(`proxyrelay.Prepare` → `dp.ApplyNFT` → `proxyrelay.Commit`/`Rollback`)がその実例である。
  `Commit` の定義も「nftables の 1 トランザクション」から「dataplane と frontend の participant が用意した状態を公開し `Active` を更新すること(kernel backend ではその中核が nftables の 1 トランザクション)」という backend 非依存の言い方に改めた。
  `internal/reconcile` は participant の interface だけを知り、`frontend`/`dataplane` の具体的な実装には依存しないという依存規則を 7a.7 節に追加した。
  `Relay` のルールを fail-closed にする操作を `StopAccepting`(待ち受けだけを閉じる)と `Retire`(安全でなくなった接続だけを閉じ、残りは自然に終わるまで待つ)に分け、ルールのこの 2 つは fail-closed のときにだけ使い、ルールの削除と無効化は今と同じく成立済みの接続も切る(kernel の conntrack 収束と同じ)。
  fail-closed にしたルールについては、conntrack の収束も直前の `Active` の値で判定し、安全な成立済みフローを消さないことにした。
  wire protocol は、`server_protocol_version` が server の実装する最新版ではなく、その接続で agent と server が互いに支える最大の版であることを明記し、agent 側も現在と直前の版の server を扱えるという対称な rolling upgrade の条件を加えた

- Backend と Runtime の interface を追加(2026-09-19、7a.8 節の Phase 2):`internal/dataplane` に `Backend` と dataplane の participant を、`internal/reconcile` に frontend の participant と `Runtime` を置いた。
  `Backend` の `Prepare` は、`Plan` と frontend の `Prepare` の結果(待ち受けているポートの集合)だけを受け取る。
  このため 7a.7 節の依存の規則に、`dataplane/*` が `planner` を import できることを明記した。
  Phase 2 の `Runtime` は、渡された `Plan` の全体について 7a.2 節の固定順序で Prepare と Commit を行うだけである。
  Observe、`Active` との差分、世代、ルール単位の結果は、Phase 4 の Reconciler で加える。
  WireGuard のピアの収束、Commit の後の収束(conntrack とセッション)、drop カウンタの読み出しは、Phase 4 まで `Runtime` の外の個別の呼び出しとして残す

- ルールの適用を `Runtime` 経由にする(2026-09-19、7a.8 節の Phase 2):`vpsd` の `applyNFT` は、保存済みのルール集合から `Plan` を組み立て、プロキシモードの中継(`internal/vpsd/proxyrelay`)を frontend の participant、各モードの dataplane を dataplane の participant とする `Runtime` で適用する。
  frontend の `Prepare` → dataplane の `Prepare` と `Commit` → frontend の `Commit`、失敗時は逆順の `Rollback` という順序は、以前の `proxyrelay.Prepare` → `dp.ApplyNFT` → `proxyrelay.Commit`/`Rollback` と同じである。
  中継の宣言は `Plan` の Relay のポートから作る。
  kernel の dataplane は、Phase 3 で `internal/dataplane/linuxkernel` へ移して `Plan` から組み立てる形にするまで、適用のたびにその回のルール集合を持つ participant を作る。
  `Plan` の Transparent のポートは保存順ではなく決まった順に並ぶため、`Plan` から nftables を組み立てると、行と set の番号の並びが変わり、`wgft server nft` の表示も変わる。
  この変更は、kernel の dataplane を移す Phase 3 で扱う。
  挙動は変えていない。
  ラボの結合テスト(e2e と lifecycle を両モードで、rate をユーザー空間モードで)を通した
