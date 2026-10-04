<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 81, 101, 102, 105, 107, 109 です。

# 2026-09-20: resource-guard

- Resource Guard の再設計を定める(2026-09-20、7a.8 節の Phase 6):7a.10 節を新設した。
  `flowcap.Limits` を、送信元ごとの上限を持つ `policy.AdmissionLimits` と、プロセス全体の予算とメモリのソフト上限を持つ `resource.Limits` に分け、`internal/flowcap` を `internal/resource` に改める。
  ルールごとの隔離は、プロトコルごとの `resource.Pool` で、プロセス全体の予算を共有プールとし、受け付け中のルールに隔離予約 `floor((T - C) / (N - 1))` を持たせる形にした。
  予約は admission の判定にだけ使い、既存のフローを追い出さない。
  Resource Guard の拒否は Admission Policy の drop に数えず、理由(`budget`、`reserve`)ごとの数をメモリに持ち、ログの文言で理由を分ける。
  メモリのソフト上限の式と `GOMEMLIMIT` の扱いは変えない。
  kernel 側は conntrack の表の上限と件数を読んで提示するだけで、値を変えず、新しい強制も加えない。
  実際の VPS(メモリ 462 MB)では `nf_conntrack_max` が 4096 で、`server check` がこれを上げる提示を出した。
  agent は同じ `Pool` を使い、予約の計算に全体状態も join protocol も使わない。
  コードを読んで、今の実装の 3 つの食い違いを見つけ、移行の手順に修正を入れた。
  `relay.Manager` はルールごとの数の確認とプロセス全体の枠の取得を 1 つの排他の中で行わず、範囲のルールでルールごとの上限をわずかに超えうる(`Pool` で直す)。
  `proxyrelay` は拒む接続を通常の `Close` で閉じ、6.3 節の RST と食い違う。
  7 節の「256 MiB の VPS の目安でも 1024 UDP・512 TCP を 1 ルールが保持できる」は、今の式(2048 と 1024)と食い違う。
  所有者の決定は次のとおりである。
  隔離予約は上記の式とする。
  ルールが 2 本以上あるときのルール 1 本の上限は、どの予算でも `C = ceil(T/2)` とし、残りの `floor(T/2)` を他のルールの予約に回す。
  ルールが 1 本なら予算のすべてを使える。
  従来の固定値(UDP 4096、TCP 1024)は式に使わない。
  1 つの式で表し、以前の実装から引き継いだ定数のところで上限が段差を持たないようにするためである。
  既定の予算はちょうど固定値の 2 倍なので既定の構成の上限は変わらず、上限が下がるのは予算を既定より小さくした複数ルールの構成(UDP 6000 なら 4096 が 3000)だけで、所有者はその範囲でより強い隔離を選んだ。
  admin API に `flow_budget` と `resource_refusals` を加え、Web UI は Phase 6 では変えない。
  agent の拒否の数はハートビートで送らず、ログにだけ出す。
  `nf_conntrack_max` が小さいときの警告を、`ip_forward` と同じく起動時にも出す。
  提示する値は、ラボでエントリ 1 件の費用を測ったうえで 65536 以上とし、費用を添え、ホストのメモリの量からは計算しない。
  kernel モードに wgft のポート全体の `ct count` の上限は加えない。
  未確認:conntrack のエントリ 1 件のカーネルのメモリ、kernel モードの `Relay` の接続が使う conntrack のエントリの数、netstack の握手途中の TCP の数の上限

- Resource Guard の型を分ける(2026-09-20、7a.10 節の Phase 6 移行手順 1):`internal/flowcap` を `internal/resource` に改め、送信元ごとの上限を `internal/policy` の `AdmissionLimits` へ、上限で拒んだログを間引く門を `internal/lograte` の `Gate` へ移した。
  `resource.Limits` はプロセス全体の予算(`UDPTotal`、`TCPTotal`)と、そこから導くルールごとの上限とメモリのソフト上限だけを持つ。
  `vpsd.Options` は 2 つの型を別の項目(`Limits` と `AdmissionLimits`)で受け取り、agent は `resource.Limits` だけを受け取る。
  `planner.Input.Limits` と `policy.Build` の引数は `policy.AdmissionLimits` になった。
  `internal/policy` は `internal/flowcap` への依存が無くなり、純粋な Go の型だけを import する。
  判定の式は変えていないので、挙動は変わらない。
  単体テストで、メモリのソフト上限の値(既定で 216 MiB、2048 と 1024 で 100 MiB)、ルールごとの上限の値、設定層の検査とエラーの文言が変わらないことを確かめた。
  7a.2 節の対応表、7a.5 節、7a.7 節の package 配置と改称の段落、docs/development/testing.md の `admission` と `resource` の契機の対象パスを、移動に合わせて書き直した

- Resource Guard の判定を `resource.Pool` に集める(2026-09-20、7a.10 節の Phase 6 移行手順 2):プロトコルごとの `resource.Pool` を置き、プロセス全体の予算とルールごとの上限を 1 つの排他の中で判定するようにした。
  `relay.Manager` の `ruleFlows` による判定と `Counter`、`proxyrelay` の待ち受けごとの `ConnsMax` の判定を置き換えた。
  フローは待ち受けに付けて数え、待ち受けから所属ルールへの対応を `Pool` が持つので、分割と統合で所属ルールが変わった待ち受けの既存のフローは移動先のルールで数える。
  `Retiring` の待ち受けのフローは、プロセス全体の数に残り、ルールごとの数からは外れる。
  置き換え前の `ruleFlows` が Retiring の待ち受けを見なかったのと同じ扱いで、ルール単位の fail-closed はそのルールの待ち受けをすべて Retiring にするため、ルールごとの上限の判定に差は出ない。
  判定の値は今のままで、ルール 1 本の上限は `resource.Limits` の `UDPPerRuleCap`/`TCPPerRuleCap` である。
  隔離予約の式への切り替えは手順 4 に残した。
  拒否の理由ごとの数をルールごとにメモリに持ち、ログの文言を理由で分けた。
  理由は今のところ `budget` と `rule_cap` の 2 つで、`reserve` は式を切り替える手順 4 で加わる。
  ログの行は "udp/2456: flow budget full (8192 of 8192 in use in this process); dropping new flows" の形になり、以前の "session limit reached" と "connection limit reached" を置き換えた。
  ルールごとの数の確認とプロセス全体の枠の取得が 1 つの排他になったので、範囲のルールの複数の待ち受けが同時に受け付けたときのわずかな超過が無くなった。
  単体テストは、置き換え前の判定を写した模型と、取得・返却・付け替え・Retiring・閉鎖を混ぜた 4000 手の列を突き合わせ、通すフローと拒むフローが一致することを確かめる。
  理由ごとの拒否の数、ログの文言、返却で数が負にならないこと、並行した取得と返却(`-race`)もホストの単体テストで確かめた。
  admin API への `flow_budget` と `resource_refusals` の追加は手順 5 に残る。
  未確認:超過が無くなったことは単体テストの模型で確かめただけで、ラボの実負荷では観測していない

- ルールごとの隔離を共有プールと隔離予約に切り替える(2026-09-20、7a.10 節の Phase 6 移行手順 4):`resource.Pool` の判定を、ルールごとの固定の上限から隔離予約の式に切り替えた。
  ルール 1 本の上限はどの予算でも `C = ceil(T/2)` で、新しいフローを受け付けているルールが 1 本のときは効かないので、そのルールは予算 `T` のすべてを保持できる。
  ルールが 2 本以上あるときは、各ルールが予約 `q = floor(floor(T/2) / (N - 1))` を持ち、自分の予約の内側にいるルールは他のルールがフラッドを受けている最中も予約まで新しいフローを通せる。
  置き換える前の式(`max(floor(T/2), min(F, T))`)と、その固定値の定数(`UDPPerRuleFloor`、`TCPPerRuleFloor`)は削除した。
  この 2 つに対応する `WGFT_*` の設定項目は無いので、設定層と互換の扱いは変えていない。
  拒否の理由に `reserve` を加え、ログの文言を 3 つの理由で分けた。
  判定を 1 回あたり一定の手間にするため、ルールごとのフロー数と予約の未使用分の合計を足し引きで保ち、ルールの本数に比例する計算は待ち受けの集合が変わるときだけ行う。
  bind に失敗した待ち受けは、受け付けているルールの集合から外す。
  ホストの単体テストで、式を素直に書き下した模型と 6000 手の混ぜた列(取得、返却、付け替え、Retiring、閉鎖、待ち受けの追加)を突き合わせ、通す・拒むと理由が一致すること、`TotalMin` から `TotalMax` までのすべての予算で `C = ceil(T/2)` と `N × q <= T` が成り立つこと、ルールが 2 本以上あるときの 1 本の最大がちょうど `C` になること、予約の内側のルールがフラッドの最中も予約まで通せること、統合で予約を超えたルールが既存のフローを追い出されずに新しいフローだけを拒まれること、並行した取得と返却(`-race`)を確かめた。
  足し引きで保つ値は、待ち受けの一覧から作り直して突き合わせる検算を毎手で通した。
  式と数の判定を 13 通りに壊す実験を行い、どれも単体テストが落ちることを確かめた。
  7 節の表と説明、6.2 節と 6.3 節の関連する記述、7a.5 節の暫定の式の記述、`docs/manual/setup.md` と `docs/manual/setup.ja.md` のルールごとの上限の説明を改めた。
  `lab/lifecycle.sh` の check 5 は、1 本のルールが予算をすべて埋めてそれを超えるフラッドを重ねる形に改めた。
  1 つの client の名前空間から出せるフラッドで予算を埋めるため、この check の server と agent は予算を UDP 4096、TCP 1024 に下げて動かし、ソフト上限の行も 124 MiB で照合する。
  `lab/connlimit.sh` の「agent のルールごとの上限は `WGFT_MAX_TCP_FLOWS` の半分」という説明も改めた。
  未確認:既定の予算で 1 本のルールが予算をすべて埋めたときの RSS、ルールが 2 本と 3 本のときの隔離の実負荷での確認(どちらも L8 の拡張に残る)

- admin API に Resource Guard の状態を加える(2026-09-20、7a.10 節の Phase 6 移行手順 5、完了):`GET /api/v1/rules` と `POST /api/v1/rules/batch` の応答(`admin.BatchResponse`)に、プロトコルごとの `in_use` と `limit` を持つ `flow_budget` と、ルール ID から理由ごとの拒否の数への表 `resource_refusals` を加えた。
  どちらも、`ApplyStatusBackend` と同じ形の別の interface(`ResourceStatusBackend`)を Backend が実装するときだけ足す加算的なフィールドで、実装しない Backend(fakeBackend、tools/uidemo)は今までどおりの応答を返す。
  `internal/vpsd.Daemon` の実装は、TCP を `proxyrelay.Manager` の Pool(kernel モードでは自分専用、userspace モードでは中継と共有する同じ Pool)から、UDP を userspace モードの dataplane だけが実装する内部の interface `udpPooler` から集める。
  kernel モードは UDP を conntrack で数え Go 側に Pool を持たないため、`flow_budget` に `udp` は現れず、Go が判定しない `Transparent` のルールは `resource_refusals` にも現れない。
  CLI は `rule ls` に REFUSED 列(そのルールの理由を問わない拒否の合計)と、`generation` の行に続く `flow budget: tcp 3/2048` の形の要約行を加えた。
  `rule ls --json` は応答をそのまま出すので同じキーが増える。
  Web UI は 7a.10 節の決定のとおり変えていない(テンプレートとサンプルデータに変更が無いので `scripts/screenshot-ui.sh` の撮り直しも行っていない)。
  単体テストで、report を持たない Backend が両フィールドを付けないこと、kernel モードの形(`flow_budget` に udp が無い、拒否が無いときの `resource_refusals` は省かれる)、複数の理由を持つルールの合計、CLI の human 出力と `--json` の両方を確かめた。
  判断:`ResourceStatusBackend` は `ApplyStatusBackend` と違い bool を返さない 1 メソッドの interface にした。
  Resource Guard の Pool は Daemon の構築時から常に存在し、`ApplyStatus` の「まだ最初のトランザクションを終えていない」に当たる状態を持たないためである。
  `flow_budget` の値は 7a.10 節が明記する `in_use` と `limit` だけとし、ルールごとの上限 `C`、予約 `q`、受け付けているルールの数 `N` は加えていない(7a.10 節の「拒否の報告」はこの 2 つの値だけを定めている)。
  REFUSED 列と flow budget の行は、7a.10 節が `rule ls --json` の項目追加としか書いていない部分を、既存の DROPPED 列と同じ書式で人間向けの出力にも補った判断である。
  未確認:実機や実負荷での `flow_budget`/`resource_refusals` の値の見え方(ホストの単体テストと CLI テストだけで確かめた)

- Resource Guard の隔離と既定の予算の RSS をラボで確かめる(2026-09-20、7a.10 節、ラボの L8 と L3 の拡張):手順 4 の記録で未確認として残した 2 点を、`lab/lifecycle.sh` の check 5b から 5e で確かめた。
  既定の予算(UDP 8192、TCP 2048)で 1 本のルールが予算をすべて埋めたときの RSS は、216 MiB のソフト上限の余裕の内に収まった(check 5b。
  送信元ごとの上限があるので、フラッドの送信元を check 5 の 2 倍にした)。
  ルールが 2 本と 3 本のとき、1 本を天井までフラッドしても、他のルールは予約の分の新しい接続を開け、フラッドされたルールの保持中の接続は切れなかった(check 5c と 5d は userspace の server、check 5e は小さい予算 1024 と 1500 の agent)。
  ルールが 2 本のときは天井と予約が同じ値になり、判定は予算を先に見るので、後から埋まる側のルールの拒否の理由は `rule_cap` ではなく `budget` になる。
  ルールが 3 本の場面では `rule_cap`、`reserve`、`budget` の 3 つの理由がすべて実際の接続で現れた。
  レートの判定(7a.9 節)も `lab/rates.sh` が合否で示すようにした。
  各レートが自分の対象だけを抑えること、拒否した段より後の段のトークンを使わないこと、TCP のルールの `packet_rate` が効かないこと、`Relay` のルールが `Transparent` と同じ判定を受けることを、両モードで確かめた。
  合否の境界は設定したレートとバーストから導き、モードに依らない式にしたので、両モードの合格が一致の根拠になる。
  未確認:3 本を超えるルールでの隔離、kernel モードの server での `Relay` のルールどうしの隔離の実負荷での確認
