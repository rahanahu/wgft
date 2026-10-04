<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 186 です。

# 2026-09-22: web-ui

- Web UI のルールの読み込みの確認を、予約ポートまで実際の `Batch` に合わせた(2026-09-22):`--dry-run` の改訂が「本改訂の対象に含めておらず、直していない」と書き残した欠陥を塞ぐ。
  `internal/vpsd/admin/webui_import.go` の `importIssues` は `proto.ValidateUpsert` の第 3 引数 `reserved` に `nil` を渡しており、WireGuard・管理用 API・エージェント用 API のポートに重なる読み込みを「受理される」と画面に出したうえで、直後の `Daemon.Batch` が拒んでいた。
  予約ポートの検査は行ごとの `skipValidate` の外にあって全行に掛かるので、この食い違いは読み込む行の内容によらず起きる。
  CLI の `--dry-run` より一度に多くの行を扱う経路であり、同じ種類の偽の受理としては影響が大きい。
  Web UI は `s.backend.ServerInfo()` を同じプロセスの中で呼べるので、CLI のように `GET /api/v1/server` を経由する必要はない。
  CLI が持っていた予約ポートの組み立ての規則(WireGuard のポートは常に予約する、`admin_addr` は `host:port` として構文解析できたときだけ予約し Unix ソケットは予約しない、`agent_api_port` は `ServerInfo` が既に `net.SplitHostPort` 済みで返す文字列を使う)を `internal/vpsd/admin` の `ReservedFromServerInfo` に移し、CLI の `cmd/wgft/rule.go` はこれを呼ぶだけにした。
  規則を 2 か所に持つと片方だけがずれるためである。
  `cmd/wgft` はもともとこの package に依存しているので、依存の向きは変わらない。
  `internal/vpsd/vpsd.go` が `Options` から `Daemon.reserved` を組む実装は、入力が `admin.ServerInfo` ではないので統合していない。
  `ServerInfo()` の読み取りが失敗した場合は、予約ポートを `nil` として続行せず、他の読み取りの失敗と同じく確認の画面そのものを止める。
  続行すると同じ欠陥が戻るためで、CLI の `--dry-run` が同じ場合に終了コード 2 で止めるのと同じ判断である。
  ホストの単体テストで、3 つの予約ポートのそれぞれに重なる読み込みが確認の画面で受理されないことと、同じ fixture に対する保存の経路(`internal/vpsd/store` の `ApplyBatch`。
  `Daemon.Batch` がこれを呼ぶ)も同じ読み込みを拒むことを確かめた。
  テストが呼ぶのは `Daemon.Batch` そのものではない。
  `Daemon` はカーネルへの適用を伴い、ホストの単体テストからは組み立てられないためである。
  検査の核となる `proto.ValidateUpsert` の呼び出しは両者で同じものであり、確認と保存が同じ入力に対して同じ判定に至ることを確かめている。
  あわせて、`Daemon.reserved` を組む `internal/vpsd/vpsd.go` の規則そのものにも表のテストを置いた。
  この規則にはこれまでテストが無く、管理用 API のポートの予約を外しても全体のテストが通る状態だった。
  確認の画面と CLI の `--dry-run` は、どちらもこの規則に合わせることを約束しているので、正本の側が動いたことを検出できなければ、一致の約束は根を持たない。
  他テーブルの DNAT との衝突と bind 中のポートの検査(`internal/vpsd/apply.go` の `checkRule`)は、root と nft を必要とし `internal/vpsd/admin` からは呼べないため、確認の画面も確かめない。
  これは `--dry-run` について既に明記した制約と同じもので、今回広がってはいない。
  画面の文言とテンプレートは変えていないので、スクリーンショットは撮り直していない。
  未確認:ラボと実機での確認
