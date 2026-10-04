<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 182, 184 です。

# 2026-09-22: review

- `rule add` と `rule set` に `--dry-run` を追加(2026-09-22、所有者の設計。
  同日の独立レビューで欠陥が見つかり、同じ改訂の中で直した。
  2 巡目の独立レビューでさらに欠陥が見つかり、これも同じ改訂の中で直した):保存の前に明らかな誤りに気付けるようにした。
  行の形の検査(`proto.Rule.Validate`)は `rule add` と `rule set` のどちらも `--dry-run` の有無に関わらず先に行っており、落ちればその時点で終了コード 1 になるため、`--dry-run` の実装自身はこれを検査し直さない。
  `--dry-run` が行うのは、`GET /api/v1/agents` が返す名前の集合による upsert する行の `--agent` の登録の検査と、現在のルール集合にこの upsert を当てはめた後の集合への `proto.ValidateUpsert` による ID の重複・予約ポート・listen_port の重なりの検査である。
  これは `internal/vpsd/admin_backend.go` の `Daemon.Batch` が実際に検査する範囲(`req.Upsert` の行だけの登録確認、集合全体への `ValidateUpsert`)と一致させるためである。
  `Batch` は呼ばない。
  誤りが無ければ終了コードは 0 とし、何も保存していないことを出力に明記する。
  誤りがあれば終了コードは 1 とする。
  11a 節を改訂した。
  ルールを編集する既存の CLI コマンドは group と note だけを変える `rule set` であり、`rule edit` という名前のコマンドは無いため、対象は `rule add` と `rule set` である。
  独立レビューは、この一致が `ValidateUpsert` の第 3 引数 `reserved` で崩れていることを見つけた。
  実装は当初これに `nil` を渡していたが、実際の経路(`internal/vpsd/admin_backend.go` の `Batch` から `internal/vpsd/store/rules.go` の `ApplyBatch` を経て呼ぶ `ValidateUpsert`)は `Daemon.reserved`(WireGuard・管理用 API・エージェント用 API の 3 つのポート、`internal/vpsd/vpsd.go` が起動時に組む)を渡す。
  予約ポートの検査は行ごとの `skipValidate` の外にあり全行に掛かるため、これらのポートに重なる `rule add --dry-run` は終了コード 0 で accepted と言い、直後の実 `Batch` が拒否していた。
  `--dry-run` の存在理由そのものが破れる欠陥であり、次のとおり直した。
  管理用 API に節点 `GET /api/v1/server` を新設し、`admin.ServerInfo`(`wg_port`・`agent_api_port`・`admin_addr`)を返すようにした(7a.11 節の一覧に加算)。
  CLI はこれを読み、`internal/vpsd/vpsd.go` が `Daemon.reserved` を組む規則と同じ規則(WireGuard のポートは常に予約する、`admin_addr` は `host:port` として構文解析できたときだけ予約し Unix ソケットは予約しない、`agent_api_port` は `ServerInfo` が既に `net.SplitHostPort` 済みで返す文字列を使う)で `proto.Reserved` を組み、`ValidateUpsert` に渡す(`cmd/wgft/rule.go` の `reservedFromServerInfo`)。
  `GET /api/v1/server` が失敗した場合(旧い版の server で 404 になる場合を含む)、予約ポートを `nil` として続行しない。
  続行すると同じ欠陥が戻るためで、`server doctor` と同じ終了コード 2(`unavailable`)で止め、この変更が受理されるかどうかを判定できなかったことを示す。
  同じ理由で、`--dry-run` が読む `GET /api/v1/rules`・`GET /api/v1/agents` の失敗も終了コード 2 とした。
  以前はこれらの失敗がそのまま返って終了コード 1 になっており、監視が「サーバが落ちている」を「ルールが拒否される」と読みかねなかった。
  `rule add`・`rule set` の通常の実行はこの節点を読まないため影響を受けない。
  本節の主な約束を、Web UI の読み込みの確認と同じ順序で行うことから、管理用 API から観測できる範囲で実際の `Batch` が保存前に行う admission の判定と一致させることに改めた。
  Web UI と 3 つの判定を共有していることは一致の手段として残るが、基準にはしない。
  Web UI を基準にしたことがこの欠陥を見落とす一因であった。
  レビューはほかに 3 点を見つけ、同じ改訂の中で直した。
  1 つ目は、`ruleDryRunIssues` の中の `r.Validate()` の分岐がどちらの呼び出し元からも到達しないことである。
  `rule add`・`rule set` の RunE が `runRuleDryRun` を呼ぶ前に同じ行へ `r.Validate()` を掛けて早期に返すため、この分岐は常に成立しない誤りしか見ない。
  分岐を削り、`ruleDryRunIssues` の役目を上記のとおり書き直した。
  `TestRuleAddDryRunShapeError` は名前に反して `--dry-run` の経路を検査しておらず、`--group "bad group"` が前段の共有の検査で落ちることを確かめているだけだったので、`TestRuleAddDryRunShapeErrorNeverReachesAdminAPI` に改名し、コメントを実際の経路に合わせて書き直した。
  2 つ目は、誤りの行が実行のたびに作り直される ULID を運用者に示していたことである。
  `rule add --dry-run` が upsert する行の ID はその場限りの新規発行であり、実際に保存するときの `rule add` が発行する ID とは別物になる。
  現在のルール集合に無い行は ID を出さず、新しいルールの内容(プロトコル・listen_port・エージェント・ターゲット)で示す形に改めた(`dryRunRuleLabel`)。
  3 つ目は、`rule set` のヘルプが存在しない `--agent` フラグを指していたことである。
  `rule set` に `--agent` は無く、検査しているのはルールに保存済みのエージェントであるため、ヘルプと本節の文言をそちらに合わせた。
  2 巡目の独立レビューはさらに 2 点を見つけ、同じ改訂の中で直した。
  1 つ目は、`rule set --dry-run` が管理用 API に届かない場合の終了コードが安定しないことである。
  `rule set` の `RunE` は `--dry-run` の分岐より前で `findRule`(`GET /api/v1/rules` を読む、`rule rm`・`enable`・`disable`・`set` が共有するヘルパー)を呼んでおり、この呼び出しは `unavailable` に包んでいなかった。
  このため終了コードは、`findRule` の `GET /api/v1/rules` が先に落ちれば 1、`findRule` を通過したうえで `runRuleDryRun` 内の読み取りが落ちれば 2 と、どちらの読み取りが先に失敗するかで割れていた。
  `findRule` を呼ぶ `rule rm`・`enable`・`disable` と、`--dry-run` を付けない `rule set` は終了コード 1 のままとする共有の挙動を保ち、`rule set --dry-run` に限り、`findRule` の読み取りの失敗を `unavailable` として終了コード 2 にした。
  2 つ目は、使い捨ての ULID を運用者に示さない前回の修正が「エージェント未登録」の判定にしか及んでいなかったことである。
  予約ポートの衝突・ID の重複・listen_port の重なりの誤りメッセージは `proto.ValidateUpsert` が返す文字列をそのまま使っており、`rule add --dry-run` が発行した使い捨ての ID がこれらの誤りにも出ていた。
  `proto.ValidateUpsert` の誤りの文字列の中の ID を `dryRunRuleLabel` と同じ規則で置き換える形にして直した(`redactThrowawayRuleIDs`)。
  他テーブルの DNAT との衝突(`internal/vpsd/apply.go` の `DNATConflicts`。
  `--force` でも上書きできない)は、`--dry-run` も確かめない。
  この検査には root と nft が要り、admin API 越しの CLI からは判定できないためで、確かめない範囲としてヘルプと本節に明記した。
  ホストの単体テストで、WireGuard のポート・エージェント用 API のポート・管理用 API のポートのそれぞれと重なる `rule add --dry-run` が終了コード 1 になることと、同じ fixture への実 `Batch` も同じ変更を拒むことを確かめた。
  `GET /api/v1/server` を持たない(旧い版を模した)server に対する `--dry-run` が終了コード 2 になることも確かめた。
  2 巡目のレビューを受けて、`GET /api/v1/rules`・`GET /api/v1/agents` の失敗がそれぞれ終了コード 2 になること、`rule set --dry-run` が管理用 API に届かない場合に終了コード 2 になること、`rule rm`・`enable`・`disable` と `--dry-run` を付けない `rule set` はその場合も終了コード 1 のままであること、予約ポートの衝突と listen_port の重なりの誤りに使い捨ての ID が出ないことをホストの単体テストで確かめた。
  未確認:実機とラボでの確認。
  Web UI の読み込みの確認(`internal/vpsd/admin/webui_import.go` の `importIssues`)も同じ `ValidateUpsert` に `nil` を渡しており、同じ種類の見落としを持つが、本改訂の対象に含めておらず、直していない

- 「契約」の語をより自然な日本語に置き換えた(2026-09-22、所有者の決定。
  語の言い換えであり、仕様の変更ではない):設計文書とコードのコメントが使っていた「契約」は英語 contract の直訳で、単独で使うと日本語の実務文書として硬く不自然だった。
  保つ範囲・保たない範囲・機械可読な対象の切り分けは、本節を含め 1 つも変えていない。
  複合語の「外部契約」は「維持する外部仕様」に、「互換性契約」は「互換性の保証」に、それぞれ機械的に統一した。
  単独の「契約」は 1 か所ずつ文脈を読み、外から見える形そのものを指す場合は「仕様」に、崩れないことを指す場合は「保証」に、保つという意思や取り決めを指す場合は「約束」に寄せた。
  そのまま置き換えると不自然になる箇所(「この値は固定の契約にしない」など)は文を書き直した。
  7a.6 節の見出しを「維持する外部仕様と互換性」に、7a.11 節の見出しを「v1.0 の互換性の保証(サーフェスごとの一覧)」に改めた。
  docs/development/architecture.md・docs/development/testing.md と、cmd/wgft・internal/model・internal/policy・internal/vpsd・internal/agent のコメントにある同じ語も揃えた。
  README.ja.md の開発状況の節にも同じ「互換性契約」があり、同じ方針で「互換性の保証」に直した。
  英語の README.md は変えていない。
  英語の contract は英語として自然な語であり、日本語の言い回しを直す今回の変更の対象ではない。
