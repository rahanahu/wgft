<a id="102b-状態の要約wgft-status"></a>
### 状態の要約(`wgft status`)

`wgft status` は配置全体の運用の状態を見る。
1 画面の 4 行の要約であり、`server doctor`([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor))が転送の経路を公開側から自宅側へたどってどこで止まったかを答えるのに対し、`status` はどこで止まったかを探しません。
判定と次に見る場所の提示は `server doctor` の役目のままとします。
[10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor)の終了コードの節で予告した「`wgft status` は配置全体の運用の状態が健全かどうかに答える」という役割を、この節で実装として定める。
Agents 行は、制御の接続とトンネルの健全さの両方を評価する(2026-09-22、所有者の決定)。

#### 読む節点

読む節点は次の 3 つに絞る。
増やさない。
`admin.BatchRequest` にも項目を足さない。

| 行 | 出どころ |
|---|---|
| Server | `GET /api/v1/rules` の `desired_generation`、`active_generation`、`agent_state_pending`、`apply_error`、`ip_forward` |
| Agents | `GET /api/v1/agents` の `Connected`・`Tunnel`・`LastHandshake`・`Disabled` |
| Rules | `GET /api/v1/rules` の `rule_states[].apply_state` と `agent_rule_states`、`GET /api/v1/agents` の `Disabled` |
| Warnings | `GET /api/v1/warnings` |

Rules 行は `rule_states[].apply_state` に加えて `agent_rule_states` も読む(2026-09-22、所有者の決定)。
どちらも `GET /api/v1/rules` の同じ 1 回の応答に既にある既存のフィールドなので、読む節点の数は 3 つのままです。
ルールの持ち主が無効かは、Agents 行が読む `GET /api/v1/agents` の同じ応答から引くので、節点は増えない(2026-09-24、所有者の決定)。
Agents 行も、`Connected` に加えて `Tunnel`・`LastHandshake` を読む(2026-09-22、所有者の決定)。
どちらも `GET /api/v1/agents` の同じ応答に既にある既存のフィールドであり、`server doctor` の `tunnel.handshake`([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor))が読むものと同じなので、節点は増えません。

警告の件数は `GET /api/v1/warnings` から数えます。
`AgentInfo.Warnings` は使いません。
`AgentInfo.Warnings` はエージェント個別の窃取検知の警告であり、配置全体の件数を数えるための節点ではないためです。

<a id="4-行の意味"></a>
#### 4 行の意味

状態の語彙は healthy・degraded・unknown の 3 つです。
証拠が無い項目は、健全でも故障でもなく unknown とします。
証拠が無いことを健全と数えると、2026-09-19 の改訂で加えたフィールドをまだ返さない旧い版の server にこの版の CLI を向けたとき、フィールドが返らないだけで「Server healthy」「Rules 8 active」と報告してしまう。
unknown は、故障を観測していないことを示す状態であり、故障を観測した degraded とは別です。

- Server:server 側のデータプレーンへの適用が宣言に追いついているかどうかです。
  判定は `server doctor` の `server.dataplane`([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor))と同じ優先順位を使い、世代の遅れ、`ip_forward` による転送停止、`agent_state_pending`、`apply_error` の順に見る。
  `desired_generation` と `active_generation` のどちらか一方でも欠けていれば世代の遅れを計算できないので unknown とします。
  `apply_error` は世代とは別の証拠なので、世代が欠けていても `apply_error` が有れば degraded とします。
  カーネルモードの server が `ip_forward` を 1 でない値と報告し、カーネルで転送する公開中のルールがある場合は、`server.dataplane` と同じ判定と同じ文で degraded とする(2026-09-25)。
  世代の遅れの次に見る。
  `agent_state_pending` が真なら、保存済みの全体 State が未公開なので degraded とします。
  転送停止と同時なら転送停止を先に示し、未公開の事実も所見に添える。
  世代が揃っていて遅れが無く、`apply_error` も無く、`ip_forward` がルールを止めず、`agent_state_pending` が真でない場合だけ healthy とします。
  優先順位は `server.dataplane` と同じでも、判定そのものは食い違う一点があります。
  世代の遅れが無く `apply_error` だけが残る場合、`server.dataplane` はこれを unknown(reason `repair_failed`)にとどめて `server doctor` の終了コードを 0 のままにするが、`status` はここを degraded として終了コードを 1 にします。
  問うている範囲が違うので、これは矛盾ではありません。
  `server doctor` はそのルールの転送が今も通っているかどうかに答えるので、公開された値が現行の generation のままである限り unknown で足りる。
  `status` は配置全体の運用の状態に答えるので、戻れない地点の後の修復が失敗したままという事実そのものを運用上の劣化として degraded に数えます
- Agents:有効なエージェントを healthy・degraded・unknown の 3 つに数え分ける(2026-09-22、所有者の決定。
  有効なものに限るのは 2026-09-24 の所有者の決定)。
  healthy は、制御ストリーム(`Connected`)とトンネルの両方が健全なときだけです。
  degraded は、制御ストリームが切れているとき、またはトンネルが failed・error であるか最終ハンドシェイクが健全の条件(3 分、下記)を外れているときです。
  unknown は、トンネルの状態や報告がこの版の知らない値であるときです。
  トンネルの判定は `server doctor` の `tunnel.handshake`([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor))と同じ判定・同じ鮮度の規則(`handshakeStale`、3 分)を共有し、doctor.go の `tunnelHealth` という関数を両方から呼ぶ。
  制御ストリームが切れている間は、エージェント自身のトンネルの報告がハートビート由来で古くなるため、`tunnelHealth` はこれを故障と決めつけず、直近のハンドシェイク(server が WireGuard から直接読む値)だけで判定するが、Agents 行にとっては制御ストリームが切れていること自体が既に運用上の劣化なので、その場合は `tunnelHealth` の判定を待たずに degraded とします。
  行の値は、healthy な場合だけ「N / M healthy」で示し、degraded か unknown が 1 つでもあれば、Rules 行と同じく、healthy の数と 0 でない degraded・unknown の数をそれぞれ総数と並べて示します。
  以前は `Connected` だけを見ており、制御ストリームは繋がっていてもトンネルが死んでいる配置(WireGuard のハンドシェイクが一度も無い、またはエージェントがトンネルを error と報告している)を healthy 側に数えていました。
  `server doctor` は同じ入力に対して `tunnel.handshake` が FAILED になり終了コード 1 で終わるのに、`status` は「1 / 1 healthy」と報告して終了コード 0 のままだった(レビューの指摘)。
  無効なエージェント([5.1 節](control/registration.md#51-登録))は、healthy・degraded・unknown のどれにも数えず、`disabled` に数える(2026-09-24、所有者の決定)。
  `disabled` は常に持ち、無効なエージェントが無ければ 0 とします。
  総数は登録済みのエージェントのすべてのままであり、healthy・degraded・unknown・disabled の和が総数に等しい。
  人向けの行は、無効なエージェントを healthy の比から外し、「2 / 2 healthy, 1 disabled」のように無効の数を添える。
  無効は宣言どおりの状態なので、終了コードを動かさない
- Rules:有効なルールを active・degraded・unknown・agent_disabled の 4 つに数え分ける。
  無効なルールは総数に数えません。
  無効は宣言どおりの状態であり、故障ではないという `rule.enabled`([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor))と同じ判断による。
  総数は `Rule.Enabled` が真のルールの数という意味を変えない(2026-09-24、所有者の決定)。
  エージェントの無効化はルール自身の `enabled` を変えないので、無効なエージェントのルールを総数から外すと、既存のフィールドの意味を狭めることになるためです。
  持ち主のエージェントが無効([5.1 節](control/registration.md#51-登録))なルールは agent_disabled に数え、active・degraded・unknown には数えません。
  宣言どおりの状態であり、故障ではないので、終了コードを動かさない。
  4 つの和は総数に等しい。
  持ち主のエージェントが登録されていないルールは、今までどおり `apply_state` の `not_active` として degraded に数えます。
  Web UI はこれらを故障に数えないが、`status` は次のメジャー版まで今の数え方を保つ。
  この違いは [7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の互換性の保証による意図したものである([5.1 節](control/registration.md#51-登録))。
  Rules が数える active は、有効なルールのうち、VPS 側の適用と、鮮度のあるエージェント側の報告の両方で、転送の準備が整っているものである(2026-09-22、所有者の決定)。
  `apply_state` の既知の値は `admin.ApplyActive`・`admin.ApplyPending`・`admin.ApplyNotActive` の 3 つで、このうち `pending` と `not_active` は、server 側の適用そのものが失敗している証拠として、この時点で degraded に数えます。
  `apply_state` が `active` であることは、server がそのルールを公開できたという証拠でしかなく、エージェントが実際に target へ届いているという証拠ではありません。
  例えば VPS 側が有効なルールをすべて公開できていても、エージェント自身がその target への到達を拒んでいれば(`WGFT_AGENT_ALLOW_TARGETS` など)、1 バイトも転送されない。
  この場合は、そのルールの持ち主のエージェントが直近に報告した `agent_rule_states` を、`server doctor` の `rule.target`([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor)、`freshAgentRuleStatus`)と同じ鮮度の規則(接続中であること、`state` が空でないこと、報告が `targetReportStale`(90 秒)より新しいこと)で読み、鮮度のある報告が `error` なら degraded、`ok` なら active とします。
  報告が無い場合、または鮮度が無い場合(一度も報告していない、stream が切れている間の古い報告、90 秒より古い報告のいずれか)は、故障を観測してはいないので unknown に数えます。
  [5.2 節](control/connection.md#52-全体状態の配信とハートビート)が、切断中のエージェントの最後の報告を今の状態として描くことを禁じているので、古い報告を degraded にも active にも数えません。
  `rule_states` にその行が無い場合、server がそもそも `rule_states` を返さない場合、または `apply_state` がこの版の知らない値である場合も、同じ理由で unknown に数えます。
  `apply_state` は増えうる開いた集合であり([7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧))、この版が知らない値を故障と決めつけて degraded に数えてはなりません
- Warnings:開いている窃取検知の警告の件数です。
  行の値は件数そのもの(0 件なら none)であり、healthy・degraded・unknown の語は持ちません。
  1 件でもあれば、後述の終了コードの根拠になります

healthy な行は通常その数だけを示し、内部の値(`apply_state` の文字列、待ち受けのエンドポイントなど)を出さない。
Server 行の世代だけは、`active_generation` と `agent_state_generation` が異なる場合、または `agent_state_pending` が真の場合に限り、両方を名前付きで添える。
degraded と unknown の行には、何が見つかったかを 1 行だけ添える。
添える内容は、エージェントなら最後に見えた時刻、ルールなら該当のルールの短い ID とその理由(server 側の適用の失敗、エージェント側の報告の失敗、鮮度のある報告が無い旨のいずれか)、警告なら種類・対象のエージェント・`Warning.At` が読めれば発生からの経過です。
エージェント側の報告の失敗には、どのエージェントの報告かを `agent <名前>:` の形で添える(2026-09-25)。
報告の理由はそのエージェントのホストについて述べるので、VPS の上で読むと VPS のことに読めるためです。
Rules の値の列は、degraded、unknown、agent_disabled がどれも 0 のときだけ「N active」と言い切る。
1 つでも 0 でなければ、active の数と、0 でない degraded・unknown・agent_disabled の数をそれぞれ別に示し、総数と並べる(例:`Rules  5 active, 3 agent disabled / 8`)。
無効なエージェントのルールを「N active」の陰に隠さないためである(2026-09-24、所有者の決定)。
かつては degraded と unknown をまとめて「Active + Degraded」/ Total という 1 つの数(「known」、証拠のある数の意)に畳んでおり、5 active・2 degraded・1 unknown のような組み合わせが「7 / 8 known」となって、壊れている 2 本が active 側に隠れて読めなくなっていた(レビューの指摘)。
今の形は、健全でない項目を 1 つも隠さないことを優先し、値の桁が伸びることを厭わない。

以下は、実際に合成した応答に対して `wgft status` を動かして得た出力です。
健全でない行が 3 つある場合(ルールが 1 本 degraded、エージェントが 1 台切断、警告が 1 件)は次のとおりです。

```
Server        healthy
Agents        1 healthy, 1 degraded / 2   home2 last seen 4m12s ago
Rules         7 active, 1 degraded / 8   r_01M335HMAB… bind failed: address already in use
Warnings      1              ip-flapping on home, 1m0s ago
```

トンネルが死んでいて制御ストリームだけ生きている配置(WireGuard のハンドシェイクが一度も観測されていない)は、次のとおりです。
Agents 行が degraded になり、Rules 行が 8 本とも active のままでも終了コードは 1 になります。

```
Server        healthy
Agents        0 healthy, 1 degraded / 1   home tunnel: no WireGuard handshake with this agent has ever been observed
Rules         8 active
Warnings      none
```

有効なルールが 1 本も無い場合は、次のとおりです。

```
Server        healthy
Agents        1 / 1 healthy
Rules         0 active
Warnings      none
```

証拠の無い server に対する表示は次のとおりです。
この例は、世代のフィールドも `rule_states` も一切返さない server([7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の `ApplyStatusBackend` を実装しない Backend)を再現したもので、Server が unknown になるとともに、Rules は根拠がまったく無いので 8 本すべてが unknown になります。

```
Server        unknown        this server does not report apply generations
Agents        1 / 1 healthy
Rules         0 active, 8 unknown / 8   apply state is unavailable for 8 rules
Warnings      none
```

上の例は `rule_states` 自体が丸ごと無い場合に限った話です。
`rule_states` はあるが個々の行の `apply_state` がこの版の知らない値であるとき、または VPS 側は active と報告しているのにエージェント側の鮮度のある報告がまだ無いときは、一部の行だけが unknown になります。
3 つの状態が混在する例を次に示します。
8 本のうち 5 本が active(VPS 側の適用とエージェント側の報告のどちらも整っている)、2 本が degraded(1 本は VPS 側の適用の失敗、もう 1 本はエージェント側の報告が `error`)、1 本が unknown(VPS 側は active と報告しているが、エージェント側の鮮度のある報告がまだ無い)です。

```
Server        healthy
Agents        1 / 1 healthy
Rules         5 active, 2 degraded, 1 unknown / 8   r_06MIXED000… bind failed: address already in use, r_07MIXED000… agent home: target not allowed, r_08MIXED000… the agent has not confirmed it is forwarding this rule
Warnings      none
```

#### 終了コード

終了コードは次のとおりです。

| コード | 意味 |
|---|---|
| 0 | 健全、または unknown があるだけ |
| 1 | degraded な項目が 1 つ以上ある |
| 2 | 要約を作れなかったか、診断に必要な証拠に権限で到達できず完全な判断ができなかった。管理用 API に届かない場合、引数の数が誤っている場合、知らないフラグを渡した場合が当たる(2026-09-23、所有者の決定) |
| 3 | 設定の誤り([11a 節](security/configuration.md#11a-設定の渡し方)) |

終了コード 2 の意味は `agent doctor`([10.2c 節](diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor))と揃えて広げたが、`status` も管理用 API への呼び出しが成功するか失敗するかの二値でしか証拠を読まず、権限によって証拠に部分的にしか届かない場合を今は持ちません。
したがって、この改訂で挙動は変わりません。

Warnings は healthy・degraded・unknown の語を持たないが、終了コード 1 の根拠になります。
開いている警告が 1 件でもあれば、コード 1 になります。
Agents は Rules と同じく 3 つの語を持ち、degraded なエージェントが 1 台でもあればコード 1 になります。
unknown なエージェント(トンネルの状態がこの版の知らない値)は、Rules の unknown と同じ理由でコードを動かさない。

unknown だけでは終了コードを上げない。
`server doctor` の UNKNOWN が終了コード 0 のままである規則([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor))と揃えています。
旧い版の server との rolling upgrade の最中、まだ返らないフィールドだけで監視を鳴らし続けることを避けるためです。
新旧の版が混在しながら互換を保って正常に更新を進めている間は、監視だけが騒ぐ状態を防ぐ。
この規則は終了コード 2 にも及ぶ。
unknown がいくつ並んでも終了コードは 0 のままであり、終了コード 2 は証拠そのものに権限で到達できなかった実行に限る。

> `status` の終了コード 1 は「転送断」を意味しません。
配置全体に運用上の手当てが必要な degraded state があることを意味します。

この規則を置く背景を述べる。
[10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor)は、制御の経路が切れていても最終ハンドシェイクが新しい場合、`server doctor` の判定をあえて終了コード 0 に留める規則を定めた。
この状態では転送が続いている可能性があり、制御の経路の故障だけでそのルールの転送が止まったと報告すると、疎通確認が実際に target まで届いた場合でも自己矛盾した報告になるためです。
[10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor)はこの異常を拾う役目を `wgft status` に割り当てており、この節が実装するのはその割り当てです。
`server doctor` の終了コード 1 は、対象のルールの転送の経路が壊れていることに答える。
`status` の終了コード 1 は、配置全体に運用上の劣化があることに答える。
両者は問うている範囲が違う。

Warnings が終了コードを動かすことも、同じ問いの違いから来る(2026-09-22、所有者の決定)。
`server doctor` は「このルールの転送の経路が今止まっているか」に答えるので、一度立って以後は運用者の操作を待つだけの累積した所見(Resource Guard の拒否や窃取検知の警告)を経路の外に置き、`rule.credentials`([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor))を unknown にとどめて総合判定にも終了コードにも入れません。
`wgft status` が答える問いはこれとは違う。
「この配置に運用者の対応が必要な状態が残っているか」であり、dismiss していない窃取検知の警告は、まさにその対象です。
この警告は単なる履歴ではありません。
運用者が `wgft agent dismiss-warning` で確認して消すまで `GET /api/v1/warnings` に開いたまま残り続ける所見です。
したがって「3 か月前に一度起きた出来事だから、いつまでも異常だと言われる」のではなく、「3 か月前に発生し、まだ運用者が処理済みにしていない警告が今も 1 件ある」と読みます。
`wgft agent dismiss-warning` は、その未処理から確認済みへの遷移そのものです。
同じ証拠(`GET /api/v1/warnings`)を、`server doctor` は経路の外の所見として終了コードから外し、`status` は配置全体の未処理な項目として終了コードに数えます。
問うている範囲が違うだけで、これも矛盾ではありません。

#### 機械向けの出力

`--json` はこの版から持ちます。
出力は `server doctor` の JSON とは別の、このコマンド専用の模型です。
3 つの状態は、Server では `status` という文字列の項目で、Agents と Rules ではそれぞれ healthy・degraded・unknown、active・degraded・unknown の 3 つの数え分けで区別できます。

```json
{"server":{"status":"healthy"},
 "agents":{"healthy":2,"degraded":0,"unknown":0,"disabled":0,"total":2},
 "rules":{"active":8,"degraded":0,"unknown":0,"agent_disabled":0,"total":8},
 "warnings":{"count":0}}
```

degraded な行は `detail` を持ちます。
実際に動かして得た出力を示す(健全でない行が 3 つある場合、上の人向けの出力の例と同じ入力)。

```json
{"server":{"status":"healthy"},
 "agents":{"healthy":1,"degraded":1,"unknown":0,"disabled":0,"total":2,"detail":"home2 last seen 4m12s ago"},
 "rules":{"active":7,"degraded":1,"unknown":0,"agent_disabled":0,"total":8,"detail":"r_01M335HMAB… bind failed: address already in use"},
 "warnings":{"count":1,"detail":"ip-flapping on home, 1m0s ago"}}
```

unknown な行も `detail` を持ちます。

```json
{"server":{"status":"unknown","detail":"this server does not report apply generations"},
 "agents":{"healthy":1,"degraded":0,"unknown":0,"disabled":0,"total":1},
 "rules":{"active":0,"degraded":0,"unknown":8,"agent_disabled":0,"total":8,"detail":"apply state is unavailable for 8 rules"},
 "warnings":{"count":0}}
```

active・degraded・unknown が混在する行も、それぞれの数を `rules` の 3 つのフィールドにそのまま持ちます。
人向けの出力の混在の例(前節)と同じ入力を動かした出力を示します。

```json
{"server":{"status":"healthy"},
 "agents":{"healthy":1,"degraded":0,"unknown":0,"disabled":0,"total":1},
 "rules":{"active":5,"degraded":2,"unknown":1,"agent_disabled":0,"total":8,
  "detail":"r_06MIXED000… bind failed: address already in use, r_07MIXED000… agent home: target not allowed, r_08MIXED000… the agent has not confirmed it is forwarding this rule"},
 "warnings":{"count":0}}
```

トンネルが死んでいて制御ストリームだけ生きている場合、`agents` は healthy が 0 に、degraded が 1 になります。
人向けの出力の同じ例(前節)と同じ入力を動かした出力を示します。

```json
{"server":{"status":"healthy"},
 "agents":{"healthy":0,"degraded":1,"unknown":0,"disabled":0,"total":1,"detail":"home tunnel: no WireGuard handshake with this agent has ever been observed"},
 "rules":{"active":8,"degraded":0,"unknown":0,"agent_disabled":0,"total":8},
 "warnings":{"count":0}}
```

`agents` は `disabled` も、`rules` は `agent_disabled` も持つ(本節の Agents と Rules の項)。
どちらも常に持ち、該当が無ければ 0 とします。
上の例はどれも無効なエージェントを含まないので、どちらも 0 です。

無効なエージェントを含む場合を示します。
第 1 の例の配置に、無効なエージェント `off` を 1 台加えた。
`off` は有効なルールを 3 本と、自分で無効なルールを 1 本持ちます。
無効なルールは今までどおり総数に数えません。
実際に動かして得た出力であり、終了コードは 0 です。

```
Server        healthy
Agents        2 / 2 healthy, 1 disabled
Rules         8 active, 3 agent disabled / 11
Warnings      none
```

```json
{"server":{"status":"healthy"},
 "agents":{"healthy":2,"degraded":0,"unknown":0,"disabled":1,"total":3},
 "rules":{"active":8,"degraded":0,"unknown":0,"agent_disabled":3,"total":11},
 "warnings":{"count":0}}
```

最上位はオブジェクトとし、[7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の規則どおり項目は増やせるが、既存の項目の名前と意味は変えません。
`detail` は人向けの文であり、保証の対象ではありません。
`server.status` の値は開いた集合として扱い、読み手は知らない値を unknown として扱う。

#### 置き場所

`status` は最上位のコマンドとし、`server` の一群には入れません。
`server` は Linux 限定の build tag を持ち、Linux 以外のビルドでは `cmd/wgft/server_other.go` が拒否する代替に置き換わる([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor))。
`status` は管理用 API を読むだけで VPS 上のカーネル機能に触れないため、この制約を受け継ぐ理由がありません。
実装は `cmd/wgft/status.go` に置き、build tag を持ちません。
