<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 209 です。

# 2026-09-23: architecture

- 診断のロジックを姉妹 package へ切り出し、証拠の型の所有を決めた(2026-09-23):10.2d 節は診断のロジックの置き場所だけを固定し、証拠の型をどこが所有するかを実装に委ねていた。
  骨組みではなく本物の切り出しで依存を確かめ、次のように決めた。
  姉妹 package の名前は `internal/vpsd/doctor` である。
  `server doctor` と `agent doctor` という利用者に見える呼び名と識別子を対応させた。
  証拠の型は `internal/vpsd/adminapi` へ移し、`internal/vpsd/admin` がそこへの別名を同じ名前で持つ形にした。
  移したのは `BatchResponse`、`AgentInfo`、`ConnCheck` と、それらが参照する `RuleApply`、`Drift`、`DriftResource`、`FlowBudget`、`AgentRuleStatus`、`TunnelStatus`、`Warning` と適用状態の 3 つの定数である。
  型を写した別の組を診断の側に持つ案は採らなかった。
  写しを作ると、報告を持たない Backend を表す nil の有無まで含めて 2 か所を揃え続ける必要があり、切り出しが挙動を変えないという条件を確かめにくくなるためである。
  別名にしたので `admin.AgentInfo` と `adminapi.AgentInfo` は同じ型であり、`internal/vpsd`、`cmd/wgft`、`tools/uidemo` の呼び出しも JSON の形も変わらない。
  節が挙げた 3 つの制約には次のように当たった。
  姉妹 package から `internal/vpsd/admin` への import は、別名の元をこの新しい package に置いたことで要らなくなった。
  `internal/vpsd` への import は元から無い。
  build tag は付けていない。
  ただし、この切り出しで新しく引いた依存の辺が 1 つある。
  `internal/vpsd/doctor` が `internal/agent/allowtargets` を import する。
  `rule.target` の理由の符号と次の一手が、エージェント側で宛先を拒む環境変数の名前を出すためである。
  切り出しの前はこの辺が `cmd/wgft` にあり、`internal/vpsd` の下には無かった。
  つまり server 側の package から agent 側の package への依存を、この版で初めて作った。
  7a.7 節が向きを定めるのは、データプレーンと制御プレーンの間と、`internal/vpsd` とその下の package の間であり、この辺を禁じる規範は無い。
  `internal/dataplane/deps_test.go` の検査も、この辺を対象にしていない。
  定数を中立な位置へ移す案は採らない。
  環境変数の名前 1 つのために package を増やす利得が無いためである。
  切り出しが挙動を変えていないことは、2 とおりの方法で確かめた。
  判定を固定していた既存の一連の試験を、別名だけを足して本文を変えずに動かした。
  加えて、15 とおりの証拠に対する人向けの出力(1 本の報告と一覧、それぞれ `--verbose` の有無)と `--json` と終了コードの文言を切り出しの前後で書き出し、1 バイトも違わないことを確かめた。
  切り出しの過程で分かったこともある。
  `wgft agent doctor` が試していない範囲の一覧を位置指定の複合リテラルで組み立てているため、その型を姉妹 package へ移すと `go vet` の composites の検査に当たる。
  この型だけは `cmd/wgft` に残し、判定が返す一覧をそこへ写す形にした。
  `wgft status` と `rule ls` が使っていた鮮度の判定、世代の食い違いの文、ID の短縮、拒否の総数、フロー予算の要約も姉妹 package が持ち、呼び出し側は同じ名前でそこを呼ぶ。
  CLI と Web UI は、証拠を読む経路も共有する。
  `server doctor` の RunE は `doctor.Read` と `Input.AddProbe` を呼び、`*admin.Client` をそのまま `doctor.Evidence` として渡す。
  Web UI は同じ 3 つを同じプロセスの中で答える adapter を渡す。
  切り出した直後は RunE が 管理用 API の呼び出しを自分で並べており、型の適合だけを共有して実行の経路が分かれていた。
  この形では、読み取りを 1 つ足したときに Web UI にだけ効く。
  揃えた前後で、偽の管理用 API に対する 14 とおりの呼び出しの出力と終了コードが変わらないことを確かめた
