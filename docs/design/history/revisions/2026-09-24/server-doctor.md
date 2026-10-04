<!-- docs-status: historical -->

# 2026-09-24: server-doctor

- 無効なエージェントを `server doctor` と `status` で扱うようにした(2026-09-24):10.2a 節と 10.2b 節の定めのとおりに実装した。
  `server doctor` は、ルールが有効で持ち主のエージェントが無効なら、`agent.enabled` を SKIPPED `agent_disabled` にし、下流の検査も同じ理由の SKIPPED にする。
  ルールの `status` は skipped、最上位の `status` は ok、終了コードは 0 になり、`rule.public_port` は FAILED `not_published` にならない。
  `agent.enabled` は `rule.enabled` の直後に置き、群は Server とした。
  無効の印は server が持つ宣言だからである。
  有効なエージェントと登録の無いエージェントでは OK になり、既定の表示では隠す。
  1 本の報告の結論の行は、ルール自身の無効とエージェントの無効を書き分ける。
  一覧の Agents の行は、エージェントを名指すルールの検査から 1 つを選ぶときに `agent_disabled` を `rule_disabled` より先に採るので、無効なエージェントの行は灰色の SKIPPED になる。
  `rule.public_port` の次の一手は、理由が `agent "<名前>" is disabled` なら、エージェントが今有効化されたかもしれないので実行し直すよう示す。
  この分岐に来るのは、ルールの読み取りとエージェントの読み取りの間にエージェントが有効化された場合だけであり、そのときエージェントは既に有効である。
  `status` は `agents.disabled` と `rules.agent_disabled` を常に出す。
  10.2b 節の機械向けの出力の例は、実際に動かした出力で書き直した。
  Web UI の診断の画面は、`agent.enabled` を経路の図の `public port` の節点に入れる。
  無効なエージェントのルールは、無効なルールと同じくすべての節点を「届いていない」で描き、札を `agent enabled / agent_disabled` にする。
  管理用 API が疎通の確認を拒むので、ボタンを出さずに理由を示す。
  `public port` の節点の見出しの一覧が変わるので、1 本のルールの診断の画面のスクリーンショットを撮り直した。
  ラボでは両方のモードで次を確かめた。
  無効なエージェントのルールについて、`server doctor` の 1 本の報告、一覧、`--json`、`status`、`status --json` が上の結果になり、どれも終了コード 0 で終わる。
  削除したエージェントに残ったルールは、`agent.enabled` の OK が加わるだけで、`rule.public_port` の FAILED `not_published`、`agent.connection` の FAILED `agent_not_registered`、終了コード 1、`status` の degraded の数え方が変わらない。
  `lab/lifecycle.sh` の確認 11 にこれらの確認を加えた。
  未確認:次の一手が名指す `wgft agent enable` は、この改訂の時点では CLI に無い(7a.11 節の加算として別の変更で加わる)。
  `disabled` を返さない旧い版の server に新しい CLI を向ける組み合わせは、単体テストだけで確かめ、ラボでは確かめていない。
