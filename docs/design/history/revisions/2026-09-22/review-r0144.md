<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 148, 149, 151-181 です。

# 2026-09-22: review

- 接続中に観測したハンドシェイクで待ちを打ち切らないよう直す(2026-09-22、所有者のレビュー、5.2 節):直前の改訂で入れた打ち切りは、溜まっていた観測を捨てる位置が接続の試みの前にあった。
  長く続いた接続の最中にハンドシェイクを観測すると、その接続が切れた直後の待ちを、古い観測が打ち切ってしまう。
  意図は、接続の試みが終わった後に観測したものだけを根拠にすることであった。
  捨てる位置を接続の試みが戻った直後へ移した。
  余計な再接続が 1 回増えるだけの誤りであるが、この改訂は再接続の間隔そのものを定める改訂であるため直した。
  単体テストを 1 本足し、接続の最中に観測したハンドシェイクが次の待ちを打ち切らないことを確かめた。
  位置を戻すとこのテストは落ちる

- 版の範囲と選んだ版を利用者向けに表示する(2026-09-22、所有者の依頼):2026-09-19 の改訂で管理用 API のエージェント一覧に加算していた `protocol_version`/`agent_protocol_legacy`(7a.6・7a.11 節)を、`wgft version` と `wgft agent ls` の人間向けの出力に載せた。
  7a.6 節に、対応する版の範囲(静的、`wgft version` が出す)と、接続で選んだ版(動的、`wgft agent ls` が出す)は性質の異なる値であり、表示でも語を揃えないことを追記した。
  `wgft version` はバージョンの行の次に `protocol range: vMIN-vMAX` の行を出す。
  `wgft agent ls` は RULES と WARN の列の間に PROTO 列を加え、接続中は選んだ版(`legacy` または `vN`)、切断中は `-` を出す。
  切断中に `-` とするのは、選んだ版が接続ごとに決まる値であり、5.2 節が stream の切断後もエージェントの最後の報告を今の状態として描くことを禁じているのと同じ理由で、切れた接続の版を今の値として出さないためである。
  接続中でも、相手が `protocol_version`/`agent_protocol_legacy` を返さない旧い server であれば、両方が Go のゼロ値になり `Connected=true`、`ProtocolVersion=0`、`AgentProtocolLegacy=false` という組が生じる。
  番号の付いた版は 1 から始まるため `v0` は存在しない表現であり、この組も legacy でも番号の付いた版でもないので、`-` を出す。
  レビューで、この組が実装の default 節に落ちて `v0` と誤って出ていたことの指摘を受け、`ProtocolVersion` が 1 以上の場合だけを番号の付いた版として出す形に直した。
  ホストの単体テストで、切断したエージェントの PROTO が過去に選んだ版を保っていても `-` になること、接続中のエージェントが `v1` または `legacy` を出すこと、接続中で `ProtocolVersion` が 0 かつ legacy でないエージェントも `-` を出すこと、`wgft version` の 2 行目が対応する範囲を出すことを確かめた。
  判定の仕組み(版の不一致の検出、警告の発生)は加えていない。
  既存の `agent_protocol_*` フィールドを表に出しただけであり、管理用 API の応答の形は変えていない。
  未確認:PROTO の 3 つの値はいずれも、合成した fixture でしか確かめていない。
  旧い server が版を返さない場合を実際の旧いバイナリに対して確かめておらず、`legacy` の表示も実際の legacy v0 の agent に対しては確かめていない。
  この改訂ではラボを流していない

- 状態の要約コマンド `wgft status` を加える(2026-09-22、所有者の設計):配置全体が健全かどうかを 1 画面で示す要約コマンドを加えた。
  10.2b 節を新設し、読む節点を `GET /api/v1/rules`、`GET /api/v1/agents`、`GET /api/v1/warnings` の 3 つに絞り、Server・Agents・Rules・Warnings の 4 行の意味と終了コードを定めた。
  10.2a 節の終了コードの節が予告していた「`wgft status` は配置全体の運用の状態が健全かどうかに答える」という役割を、この節で実装として引き継ぐ。
  実装は `cmd/wgft/status.go` に置き、`server` の一群(Linux 限定の build tag)には入れない。
  管理用 API を読むだけで VPS 上のカーネル機能に触れないためである。
  Rules 行は有効なルールだけを総数に数え、無効なルールは除く。
  無効は宣言どおりの状態であり故障ではないという `rule.enabled`(10.2a 節)と同じ判断による。

レビューで 2 つの決定を直した。
1 つ目は状態の語彙である。
最初の実装は、Server 行と Rules 行のいずれも、故障を示す証拠が無い場合は健全側に倒していた。
desired_generation と active_generation と apply_error がどれも無い server を healthy と数え、rule_states にその行が無いルールを active と数えており、`server doctor`(10.2a 節)が「確認できていないことを正常と言わない」とした原則と逆だった。
2026-09-19 の改訂で加えたフィールドを旧い版の server が返さない場合、新しい CLI を旧い server に当てると、フィールドがまだ返らないだけで Server healthy と Rules 8 active を報告してしまう。
unknown という 1 つの状態を足し、証拠の無い項目は healthy でも degraded でもなく unknown にするよう改めた。
Server は Status という文字列の項目(healthy・degraded・unknown)に、Rules は Active・Degraded・Unknown の 3 つの数え分けに直した。
`--json` の server.healthy という真偽値は 3 つの状態を表せないので、server.status という文字列の項目に変えた。
unknown は degraded として数えない。
2 つ目は終了コードである。
最初の実装は、要約の中身がどうであれ判定を持たせず、終了コードを常に 0 にしていた。
所有者の決定により、degraded な項目が 1 つでもあれば終了コード 1 で終わるように改めた。
unknown だけでは 0 のままとし、`server doctor` の UNKNOWN が 0 のままである規則(10.2a 節)と揃えた。
旧い版の server との rolling upgrade の最中、まだ返らないフィールドだけで監視を鳴らし続けることを避けるためである。
10.2a 節は、制御の経路が切れていても最終ハンドシェイクが新しい場合、`server doctor` の判定をあえて終了コード 0 に留める規則を定めており、この異常を拾う役目を `wgft status` に割り当てていた。
この改訂はその割り当てを実装として満たす。
`server doctor` の終了コード 1 は対象のルールの転送の経路が壊れていることに答え、`status` の終了コード 1 は配置全体に運用上の劣化があることに答える。
両者は問うている範囲が違うという規則を 10.2b 節に明記した。
管理用 API に届かない場合と、引数・フラグの誤りは、これまでどおり `server doctor` と同じ終了コード 2 のままである。
ホストの単体テストで、4 行すべてが健全な合成応答と、ルールの適用失敗とエージェントの切断と警告が 1 件ずつある合成応答の 2 つについて、`writeStatusReport` の 4 行の文字列と `json.Marshal` の形の両方を確かめた。
世代のフィールドを返さず rule_states も空の合成応答(Server が unknown、Rules が unknown を含む形になり、終了コードは 0)は、`writeStatusReport` の出力と `statusExit` を確かめたが、`json.Marshal` の形は確かめていない。
実機での確認は、下の「`server doctor` と `wgft status` を実機で確かめた」の項にある。
未確認:ラボでの確認

独立レビューが 4 つの欠陥を見つけ、同じ改訂で直した。
1 つ目は `--json` の経路である。
`RunE` が `enc.Encode` の戻り値をそのまま返しており、degraded な報告でも `statusExit` まで届かず終了コードが 0 のままだった。
`server doctor` の `RunE` が `switch` を抜けたあとで必ず `doctorExit` を呼ぶ形に揃え、`enc.Encode` の失敗も `unavailable` で包んで終了コード 2 にした。
`RunE` 自身を通す試験が 1 本も無かったことがこの欠陥を見逃した原因なので、`cmd.Execute` を text と `--json` の両方で呼ぶ試験を足し、同じ degraded な入力でどちらも終了コード 1 になることを確かめた。
2 つ目は `rulesStatusOf` の既定の分岐である。
`apply_state` が `active` 以外ならすべて degraded に数えており、7a.11 節の「列挙値を持つフィールドは開いた集合であり、知らない値を失敗にしてはならない」約束に反していた。
新しい版の server がこの版の知らない値(例えば `retiring`)を足した場合、rolling upgrade の最中に degraded と誤報する。
既知の値である `admin.ApplyPending` と `admin.ApplyNotActive` だけを degraded に数え、それ以外(空文字とこの版の知らない値)は unknown に数えるよう改めた。
単体テストで、知らない値を持つルールが unknown に数えられ、終了コードが 0 のままであることを確かめた。
3 つ目は終了コードの試験の立て方である。
健全でない行を 3 つ同時に立てる合成応答だけでは、`statusExit` の 4 つの節のうち 1 つを削っても、残り 2 つが終了コードを非 0 に保つため検出できない。
原因ごとに 1 つずつ壊す試験を 4 本(server の degraded、rules の degraded、agent の切断、warning)足し、それぞれ単独でも終了コード 1 になることを確かめた。
レビューが指摘した 6 種の変異(`statusExit` の 4 つの節それぞれの削除、`rulesValue` の "known" を "active" に変える変更、unknown の detail の文言の変更)を実装へ 1 つずつ入れて `go test ./cmd/wgft/...` を流し、いずれも新設した試験のどれかが落ちることを確かめたうえで元に戻した。
4 つ目は、Server の判定が `server doctor` の `server.dataplane` と食い違う一点(世代の遅れが無く `apply_error` だけが残る場合、`server.dataplane` は unknown にとどめるが `status` は degraded にする)を、コメントにも本節にも書いていなかったことである。
両者が問うている範囲の違いを本節と `serverStatusOf` のコメントに明記した。
あわせて、本節の「`apply_state` が active でない行は degraded に数える」という記述が 7a.11 節の約束と矛盾していたので、既知の値だけを degraded に数える記述に直し、Agents 行と Warnings 行が healthy・degraded・unknown の語彙を持たないことと、それでも終了コードの根拠になることも書き加えた

もう 1 巡、独立レビューの指摘と所有者の決定により、Rules 行の出どころを見直した(2026-09-22)。
それまでの `rulesStatusOf` は `rule_states[].apply_state` だけを読んでおり、server がルールを 8 本ともきれいに公開できていても、エージェント自身がその target を拒んでいれば(`WGFT_AGENT_ALLOW_TARGETS` など)1 バイトも転送されない状態を `8 active` と報告し、終了コード 0 で終わっていた。
同じ入力に対し `server doctor` は `8 of 8 rules not carrying traffic` と答えており、2 つのコマンドが同じ配置について逆の答えを返していた。
新しい節点は足さず、`GET /api/v1/rules` が既に返す `agent_rule_states`(この応答にはこの改訂の前から載っている)を読むだけに直した。
`apply_state` が `active` の行はさらに、そのルールの持ち主のエージェントの鮮度のある報告(接続中、`state` が空でない、`targetReportStale` より新しい)を見て、`error` なら degraded、`ok` なら active、報告が無いか古ければ unknown とする。
鮮度の規則は `server doctor` の `freshAgentRuleReport` が実装していたものと同じなので、判定そのものを `freshAgentRuleStatus`(`doctor.go`)という小さな関数に切り出し、`doctor` と `status` の両方から呼ぶ形にした。
切り出しの前後で `doctor` の単体テストがすべて通ることを確かめており、`doctor` の挙動は変えていない。
5.2 節が、切断中のエージェントの最後の報告を今の状態として描くことを禁じているので、stream が切れている間の古い報告や 90 秒を越えて古い報告は、degraded にも active にも数えず unknown に落とす。
ホストの単体テストで、独立レビューが指摘した場合(server は 8 本とも active、agent_rule_states は 8 本とも `error`)を再現し、`status` が `8 active` ではなく全 8 本を degraded と数え、終了コード 1 で終わることを確かめた。
同じ試験で、stream 切断中の古い報告と 90 秒を越えて古い報告のどちらも、degraded にも active にもならず unknown に落ちることも確かめた。

同じ改訂で、Warnings が終了コードを動かす理由と `server doctor` の判定が逆になる理由を、所有者の整理のまま 10.2b 節に明記した。
`server doctor` はそのルールの転送の経路が今止まっているかに答えるので、一度立って以後は運用者の操作を待つだけの警告を経路の外に置き終了コードを動かさない。
`status` はこの配置に運用者の対応が必要な状態が残っているかに答えるので、dismiss していない警告はまさにその対象であり、終了コードを動かす。
同じ証拠を違う問いに使い分けているだけで、矛盾ではない。
あわせて、`warningsStatusOf` が `Warning.At` を読めるときは経過時間を添えるようにした。
開いている警告が種類とエージェントしか出ておらず、30 秒前のものか 3 か月前のものか運用者に分からなかったためである。
管理用 API の型は変えていない。

`rulesValue` の混在時の表示も直した。
unknown が 1 つでもあると、値の列が `Active + Degraded` / Total の 1 つの数(「known」)に畳まれており、5 active・2 degraded・1 unknown のような入力が `7 / 8 known` となって、壊れている 2 本が active 側に隠れて読めなくなっていた(レビューの指摘)。
degraded と unknown のどちらかが 1 つでもあれば、3 つの数をそれぞれ Total と並べて示す形に直した。
10.2b 節の 3 つの例(0 件、全部 unknown、混在)は、実際に合成した応答に対して `wgft status` を動かして得た出力をそのまま貼った。

7a.11 節も、`server doctor --json`(既にマージ済み)と `status --json` がどちらも管理用 API の型を経由しない CLI 専用の模型を持つという実態に合わせて書き直した。
CLI のコマンド一覧に `status` を、`--json` を持つコマンドの一覧に `status`・`server doctor` を加え、機械可読な保証の段落を、`rule ls`・`agent ls` のように管理用 API の型をそのまま返すものと、`status`・`server doctor` のように CLI 専用の型を持ち保証をそれぞれの節が個別に定めるものとに書き分けた。

細かい誤りも直した。
10.2b 節の例のルール ID(`r_01M32SD123`)は 12 文字ちょうどで、`short()`(`cmd/wgft/rule.go`)が詰める閾値(12 文字)をまたいでいなかった。
実際の ID は `r_` + 26 文字の ULID なので必ず `…` が付く。
実際に `newRuleID` と同じ形の ID(`r_01M335HMABBS0HAXB58DE7QSTR`)に差し替え、`status_test.go` の合成データも同じ長さの ID に直したうえで、`…` を経由する表示を確かめる形にした。
証拠の無い server の例に添えていた「`withApply` は 3 つのフィールドをまとめて設定するかまとめて省くかのどちらかなので、7 / 8 known のように一部だけ known にはならない」という記述は、server 側の private な関数の名前を CLI の挙動の根拠にしており、かつ `rule_states` 自体は返るが個々の行の `apply_state` が未知の値であるとき、または agent_rule_states の鮮度が無いときには普通に一部だけ unknown になるので、言い過ぎだった。
この例は `rule_states` 自体が丸ごと無い場合に限った話だと書き直し、混在する場合の例を別に添えた。
`status_test.go` のコメントにあった「買収前はこの経路を試すテストが 1 つも無かった」は「以前は」の誤りだったので直した。

以下を、変異を実装へ 1 つずつ入れて `go test ./cmd/wgft/...` を流し、新設した試験のいずれかが落ちることを確かめたうえで元に戻した。
`rulesStatusOf` の `case` から `admin.ApplyPending` を落とす変異、`c.Rules()`・`c.Agents()`・`c.Warnings()`・`enc.Encode` の失敗を包む `unavailable(err)` をそれぞれ `err` に変える変異、鮮度のある `error` を active に数える変異、鮮度の判定から `Connected` の確認を落とす変異、鮮度の判定から古さの確認を落とす変異である。
最後の 2 つは、`doctor.go` の既存の試験(`TestResolveWithoutEvidenceIsNotTested` など)だけでは検出できず、この改訂で足した `status` 側の試験がなければ見逃していた。
実機での確認は、下の「`server doctor` と `wgft status` を実機で確かめた」の項にある。
未確認:ラボでの確認

3 巡目の独立レビューと所有者の決定により、Agents 行の判定を見直した(2026-09-22)。
それまでの `agentsStatusOf` は `Connected` だけを見ており、制御ストリームは繋がっているがトンネルが死んでいる配置(WireGuard のハンドシェイクが一度も観測されていない、またはエージェントがトンネルを `error` と報告している)を healthy 側に数えていた。
`server doctor` は同じ入力に対して `tunnel.handshake` が FAILED になり終了コード 1 で終わるのに、`status` は「1 / 1 online」と報告して終了コード 0 のままだった。
所有者の決定により、Agents 行は制御ストリームとトンネルの両方を評価する形に改めた。
制御ストリームが切れている場合、またはトンネルが failed・error か鮮度の条件(`handshakeStale`、3 分)を外れている場合は degraded、トンネルの状態や報告がこの版の知らない値の場合は unknown とする。
判定は doctor.go の `handshakeCheck`(`tunnel.handshake`)から `tunnelHealth` という関数を切り出して共有し、doctor 自身の挙動は変えていない(切り出しの前後で `server doctor` の単体テストがすべて通ることを確かめた)。
`agentsStatus` の `--json` は Online と Total だけの形から、Rules 行と同じ online・degraded・unknown・total の数え分けに変え、人向けの表示も `rulesValue` と同じ形(`agentsValue`)にした。

同じ巡で、`rule.target`(`targetCheck`)が `freshAgentRuleStatus` を呼ばず、同じ鮮度の判定を別のインラインのコードとして持ち続けていたことも直した(独立レビューの指摘)。
10.2b 節は以前から「`server doctor` の `rule.target`・`freshAgentRuleStatus` と同じ鮮度の規則」と述べていたが、`targetCheck` は実際にはこの関数を呼んでおらず、判定が今は一致していても、`freshAgentRuleStatus` を直した人が `targetCheck` も追随すると誤認しうる状態だった。
`targetCheck` の `StatusOK`・`StatusError` それぞれの分岐にある古さの確認(`!ageOK || reportAge > targetReportStale`)を `freshAgentRuleStatus` の呼び出し(`!fresh`)に置き換え、本節の記述を実装として満たした。
文言を出し分けるための `state`・`Connected`・報告の有無の場合分けは、`targetCheck` にそのまま残した。

7a.11 節の一文も直した。
同節は `status --json` の `rules.detail`・`agents.detail`・`warnings.detail` を「表に現れない項目」の一覧に挙げ、10.2b 節が定める「`detail` は保証の対象ではない」という決定と逆のことを述べていた。
しかも `server.detail` が列挙から漏れており、4 つのうち 3 つという数え方になっていた。
`writeStatusReport` は `detail` を 4 行の表の右側にそのまま印字するので、表に現れない項目ではない。
この一文を、`status --json` の `server.detail`・`rules.detail`・`agents.detail`・`warnings.detail` は表にそのまま印字される文字列であり保証の対象ではない、という記述に直し、`cmd/wgft/status.go` のコメントの参照先も 10.2b 節に揃えた。

10.2a 節の終了コードの表にはあった終了コード 3(設定の誤り、11a 節)が、10.2b 節の表と `cmd/wgft/helptext.go` の `status` の説明の両方から漏れていたことも直した。
`wgft status --config` に構文の誤った dotenv を渡すと終了コード 3 で終わることを実際に確かめ、両方に表と説明を足した。

日本語の文言の誤りもいくつか直した。
`cmd/wgft/status.go` のコメント「壊れている 2 本が active 側に隠れて読めていた」は意味が逆で「読めなくなっていた」の誤りだったので直した(本節の同じ経緯の記述は元から正しかった)。
`cmd/wgft/doctor.go` の `freshAgentRuleStatus` のコメントにあった「rule_states にその行が無い呼び出し元」は「agent_rule_states」の誤りだったので直した。
`cmd/wgft/status.go` の「declared な状態」は「宣言どおりの状態」に、「嘘の健全を報告してしまう」は「フィールドがまだ返らないだけで健全だと報告してしまう」に書き直した。
`statusExit` の `"%d rule(s) not active"` のような `(s)` の複数形と、`rulesStatusOf` の `rule%s` という複数形が同じ出力の中に混在していたので、`pluralS` という 1 つの関数にまとめた。
`apply_state` がこの版の知らない値であるルールの `detail` が「apply state is unavailable」になっており、値は実際に届いているので unavailable ではなかった。
`rule_states` 自体が丸ごと無い場合(本当に unavailable)と、値が届いたが未知である場合とで文言を書き分けた。
本節にあった「Rules の 3 つの数はいつも一部だけ known にはならないと決めつけることはできない」という文は、廃した `known` という語を含むうえ意味が読み取れなかったので、直後に続く具体的な記述だけを残す形に書き直した。

同じ巡で、レビューが変異を 27 個入れ、次の 2 つが生き残った。
`rulesStatusOf` の `case fresh && ars.State == proto.StatusOK:` を `case fresh:` に変える変異(エージェント側の `state` がこの版の知らない値でも fresh なら active に数えてしまう。
7a.11 節は `agent_rule_states` の `state` も `apply_state` と同列の開いた集合と定めており、エージェント側だけがこの約束を守らないままだった)と、`targetReportStale` の境界を `age > targetReportStale` から `age >= targetReportStale` に変える変異(既存の試験が 5 秒と 2 分しか使っておらず、90 秒ちょうどを踏む例が無かった)である。
それぞれを固定する試験を足し(`TestRulesStatusOfFreshUnknownAgentStateIsUnknownNotActive`、`TestFreshAgentRuleStatusBoundary`)、変異を入れて落ちることと、元に戻すと通ることを確かめた。
Agents 行のトンネルの判定にも同様に変異を入れ(ハンドシェイクの鮮度の確認を落とす、`ai.Tunnel.State == proto.StatusError` の確認を落とす、知らないトンネルの状態を degraded に倒す)、新設した試験がそれぞれ落ちることを確かめたうえで元に戻した。
実機での確認は、下の「`server doctor` と `wgft status` を実機で確かめた」の項にある。
未確認:ラボでの確認

所有者の決定により、`online` の意味が制御ストリームの生存からトンネルも含めた健全性へ狭まった結果、トンネルだけ `error` のエージェントについて `agent ls` は接続元アドレスを示すのに `status` は `online` を 0 と数え 2 つのコマンドが逆の印象を与えていたので、Agents 行の `online` を、Rules 行の `active` と対称な `healthy` に改名した(2026-09-22)。
