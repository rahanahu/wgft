<a id="7a11-v10-の互換性の保証サーフェスごとの一覧"></a>
### v1.0 の互換性の保証(サーフェスごとの一覧)

v1.0 以降は公開サーフェスごとの互換性を保証します。
内部の型とパッケージ、Web UI の HTML と URL、ログの書式は同じ保証には含めません。


[7a.6 節](architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性)は維持する外部仕様の一覧を示した。v1.0 のリリース後は、そこに挙げた境界の外側にあるすべての変更が互換性の判断の対象になる。この節は、公開しているサーフェスごとに、v1.0 が保つ約束、保たない約束、そのうち機械可読な安定した保証はどこまでか、そして自由に変えてよい人間向けの表示はどこかを分けて示す。目的はすべてを固定することではなく、どこを固定しどこを固定しないかを名指しすることにある(2026-09-21、所有者の決定)。

この節が拘束するのは、Linux で動く server と Linux で動く agent と、Windows で動く agent のうち Windows 11 の実機で確認した範囲です。
Windows の agent の保証の範囲は、登録、TCP と UDP の転送、stream の再接続、スリープからの復帰、ネットワークアダプタを無効にして有効に戻した後の復帰、`agent doctor`、鍵の操作(`agent pubkey` と `agent rotate-key`)である(2026-09-27、所有者の決定)。
この範囲は、agent を Windows 11 の実機で管理者でない利用者として動かし、有線の接続で、カーネルモードの server に対して確かめた。
Windows の agent の保証の範囲の外の挙動と、macOS の agent は暫定とし、v1.0 の保証には含めません。
暫定とすることは、現在配っているバイナリの配布を取りやめる決定ではありません。
保証の対象に含めないのは実機で確認していない挙動を保証しないという意味であり、配布や支援を打ち切る意味ではありません。
したがって暫定である間も、既知の挙動をわざと壊すことはしません。
実機での確認が取れた範囲を保証に格上げし、保証の範囲を現行仕様に反映して、何を確認したかを PR に記載します。

サーフェスを横断する規則は次のとおりです。

- 加算(新しいフィールド、新しいルート、新しい列)は、既存の利用者がそれを無視できるサーフェスでは互換です。
  既存の名前の変更・削除・意味の変更は互換でない
- 機械可読な値について保証するのは、各節が定めたその値の意味です。
  実装が返していた値が、変更の前から各節の本文が定めていた意味と明らかに食い違う場合に限り、その定めに合わせて分類を正すことを不具合の修正として扱い、意味の変更には当たらないとします。
  同じ変更の中で定めそのものを書き換える場合は、この扱いに当たらない。
  正したことで変わる値は、リリースノートに記す
- 既存のフィールドの新しい列挙値と値域の拡大は、加算と同じには扱わない。
  未知のフィールドは読み飛ばせるが、既知のフィールドの未知の値は読み飛ばせないためです。
  互換とするのは、そのサーフェスが未知の値を許容すると明記している場合だけで、扱いは各サーフェスの項で定める
- 人間が読むための表示(CLI の表形式の出力、ログの行、Web UI の HTML と文言)は、それ自体では保証の対象でない。
  自動化が読んでよいのは、各節が明示した機械可読な形だけです
- 「互換」とは、rolling upgrade([5.2 節](control/connection.md#52-全体状態の配信とハートビート)、[7a.6 節](architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性))の間、新旧のプロセスが同時に存在する期間をどちらの順で越えても、古い側が新しい側の追加を読み飛ばして動作を続けられることを指す。
  両側が永久にすべての版を読めることではありません
- 終了コードの意味は、コマンドの種類によって定める節が分かれる。
  常駐するプロセス(`server run`、`agent run`)の起動の失敗は [11b 節](security/startup.md#11b-起動の失敗の意味論)が定める。
  常駐しない一発実行のコマンドは、成功が 0、失敗が 0 以外であることを共通の保証とし、0 以外のどの値になるかは各節が個別に定める。
  個別に定めているのは、`server doctor` が [10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor)、`status` が [10.2b 節](status.md#102b-状態の要約wgft-status)、`agent doctor` が [10.2c 節](diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor)、`rule add` と `rule set` の `--dry-run` が [11a 節](security/configuration.md#11a-設定の渡し方)です。
  どの節にも定めが無いコマンドは、共通の保証だけを持ちます

一発実行のコマンドの終了コードを v1.0 の保証に入れる理由を述べる(2026-09-23、所有者の決定)。
v1.0 以降、CLI の機械向けの挙動を保証するなら、一発実行のコマンドだけが保証の外にある状態は不自然です。
ただし、これまで意味を定義していないコマンドまで今から値を固定する必要はありません。
成功が 0、失敗が 0 以外までを共通の保証とし、細かい意味を持つコマンドだけが各節で追加の保証をします。
`rule ls`、`agent ls`、`server check` のように、[10.5 節](operations/output.md#105-読み取り失敗の見せ方)の「管理用 API の 5xx は 0 以外の終了コードで止まる」という規則しか持たないコマンドは、この共通の保証だけを持ちます。

共通の保証が言う成功は、要求された操作を完了できたことを指す。
その結果が肯定であるかどうかは含めない(2026-09-23、所有者の決定)。
診断の結果そのものを終了コードに載せるのは、各節が名指しするコマンドに限る。
`server doctor`、`status`、`rule add` と `rule set` の `--dry-run` は、検査に失敗があること、配置に劣化があること、その変更が受理されない見込みであることを、答えそのものとして 0 以外で表します。
各節がそう定めているためであり、共通の保証に反しません。

成功をここまでに狭める理由は、共通の保証を広げすぎないことにあります。
処理は正常に完了したが、内容として警告や否定的な所見を含むコマンドまで終了コードに意味を持たせると、既存の挙動と衝突します。
`wgft server check` がその例です。
`internal/vpsd/servercheck` の `Check` は、所見を印字しても、nft の検査を実行できなくても、サーバのデータベースを開けなくても `nil` を返し、終了コードは 0 のままです。
`server check` の所見と部分的な読み取りの失敗は出力で伝え、終了コードには反映しません。
この挙動は変えません。
共通の保証は要求された操作を完了できたかまでにとどめ、診断の結果そのものを終了コードに載せるコマンドだけを各節で明示するほうが一貫します。
サーバのデータベースが新しい版の書いたスキーマで開けない場合(`store.ErrSchemaNewer`)だけは、他の所見と紛れないよう専用の見落としにくい行で示します。
運用者は、入れ替えの巻き戻しの最中に旧い版の `server check` でこれに気付く必要があり、終了コードでは気付けないためである([以前の検証](https://github.com/rahanahu/wgft/blob/c5a6dc454468733e9ff4b2a4eb2b5a17ed4bdf4e/docs/design.md#L1634))。

以下、サーフェスごとに保つものと保たないものを示します。

**管理用 API(`/api/v1/...`)。**
保証の対象は `/api/v1/` 配下の JSON ルートだけであり、`/`・`/ui/...`・`/static/...`(Web UI)は含めない(後述)。

| メソッドとパス | 用途 |
|---|---|
| `GET /api/v1/rules` | ルール一覧と適用状態 |
| `POST /api/v1/rules/batch` | ルールの追加・変更・削除([5.4 節](control/batches.md#54-ルールのバッチ操作)) |
| `GET /api/v1/agents` | エージェント一覧 |
| `POST /api/v1/agents/join-string` | 接続文字列の発行 |
| `DELETE /api/v1/agents/{name}` | エージェントの削除 |
| `POST /api/v1/agents/{name}/disable` | エージェントの無効化([5.1 節](control/registration.md#51-登録)) |
| `POST /api/v1/agents/{name}/enable` | エージェントの有効化([5.1 節](control/registration.md#51-登録)) |
| `GET /api/v1/warnings` | 窃取検知の警告一覧 |
| `POST /api/v1/agents/{name}/dismiss-warning` | 警告を消す。`ip-mismatch` では確認済みの組を記録する([5.2 節](control/connection.md#52-全体状態の配信とハートビート)) |
| `GET /api/v1/agents/{name}/state` | 1 エージェントの状態 |
| `POST /api/v1/rules/{id}/check` | TCP 疎通確認 |
| `GET /api/v1/nft` | 適用中の `table inet wgft` を表示 |
| `GET /api/v1/server` | vpsd/VPS の構成と環境(`admin.ServerInfo`)。`rule add`/`rule set --dry-run` が予約ポートの組み立てに使う([11a 節](security/configuration.md#11a-設定の渡し方)) |

保つものは、各ルートの意味と、リクエスト・レスポンスの型にある既存フィールドの名前と意味、既存の HTTP ステータスコードの使い分けです。
ここで固定するのは、JSON として実際に公開したフィールドの名前と意味であって、対応する Go の型の内部の作りではありません。
フィールドの追加は加算であり互換です。
`GET /api/v1/server` が返す `admin.ServerInfo` も同じ扱いとします。
`--dry-run` が読むのは `wg_port`、`agent_api_port`、`admin_addr` の 3 つだが、公開した以上は他のフィールドの名前と意味も同じ規則で保つ。

| コード | 契機 |
|---|---|
| 200 | 通常の成功 |
| 204 | `DELETE /api/v1/agents/{name}`、`POST .../dismiss-warning` の成功 |
| 400 | リクエスト本文の構文誤り・必須項目の欠落 |
| 403 | Host・Origin の検査による拒否([11 節](security/admin-transport.md#11-セキュリティ)) |
| 404 | `GET /api/v1/agents/{name}/state`、`POST /api/v1/agents/{name}/disable`、`POST /api/v1/agents/{name}/enable` での不明なエージェント名 |
| 409 | `POST /api/v1/rules/batch` が `ErrBatchConflict`([5.4 節](control/batches.md#54-ルールのバッチ操作))のとき |
| 422 | バッチ・検証のその他の失敗。エージェントの無効化では、保存は済んだが公開に失敗したとき。エージェントの有効化では、それに加えて、書き込みの時の検査が拒んで何も保存しなかったとき([5.1 節](control/registration.md#51-登録)) |
| 500 | バックエンドの読み取り・書き込みの失敗 |

管理用 API には独自の認証が無いため 401 は使いません。
エージェント用 API の登録(`POST /api/v1/agents/register`)と stream は別の仕様で、無効なトークンを 401、二重登録を 409、送信元ごとのレート制限と、エージェントごとの確立の前の stream の数の上限([11 節](security/admin-transport.md#11-セキュリティ))を 429、backend 自体の失敗(SQLite の一時的な失敗など)を 500 で区別します。
日常的な認証拒否と backend 自体の失敗を同じコードにしないことが約束であり、これを取り違えると削除されていない agent が誤って復帰経路([5.1 節](control/registration.md#51-登録))に入ります。

`BatchResponse` の `desired_generation`・`active_generation`・`rule_states`・`drift`・`apply_error`・`flow_budget`・`resource_refusals`・`agent_rule_states`・`udp_replies` は、それぞれ `ApplyStatusBackend`・`ResourceStatusBackend`・`AgentRuleStatusBackend`・`UDPReplyBackend` を実装する Backend のときだけ加わる加算的なフィールドで、実装しない Backend(`fakeBackend`、`tools/uidemo`)には現れない。
「実装すれば増える、しなければ元の応答のまま」という形自体が約束であり、今後の加算もこの形を保つ。
`rule ls` の REFUSED 列と `resource_refusals` は Resource Guard によるフロー予算の拒否だけを数え、意味を変えません。
フロー予算の判定がルールのフローを受け付けたときのルールの登録で数え、退役した登録のフローを帰属の規則で移すこと([7a.10 節](resource/admission.md#7a10-resource-guard-の再設計))は、この意味の変更に当たらない(2026-09-29、所有者の決定)。
`flow_budget` の `in_use` と `limit` はプロセス全体のフローの数と上限のまま、`resource_refusals` はルール ID と理由ごとのフロー予算の拒否の数のままであり、変わるのは拒否が起きる時点と理由の内訳です。
`rule_cap` は改訂の前と同じく、ルールの listener が運ぶフローの数で判定します。
改訂の前も管理用 API はルールごとのフローの数を返していなかったので、数え方の変更で値の意味が変わる既存のフィールドはありません。
`resource_refusals` の理由のキーへの `floor` と `spare` の追加は、開いた集合への値の加算です。
最低分、予備、登録ごとのフローの数は管理用 API に加えず、拒否のログの文言でだけ示す(2026-09-30、所有者の決定)。
ユーザー空間モードの TCP の `flow_budget.in_use` は、[末尾を届けている途中](userspace/tcp-retention.md#中継が終わった後の末尾の配送)のフローも数えます。
`in_use` は上限の判定に使う数なので、上限の対象を示すという意味は変わりませんが、中継中の接続数として読んでいた利用者には大きく見える場合があります。
`rule ls` とエージェントの `agent doctor` の予算も同じ値です。
ユーザー空間モードの `vpsd` の接続元 IP ごとの同時フロー数も配送中のフローを数えます。
この数は管理用 API に出さず、`src_flow` の拒否が起きる時点が変わります。
カーネルモードの `vpsd` の数え方は変わりません。
`WGFT_AGENT_ALLOW_TARGETS`([7 節](agent-dataplane.md#7-データプレーン自宅側)、[11a 節](security/configuration.md#11a-設定の渡し方))によるエージェント側の宛先拒否、リスナーの開放失敗、TCP の接続確認の失敗は、`agent_rule_states`(rule_id をキーに、そのルールの持ち主のエージェントが直近のハートビートで報告した `state`・`reason`、報告したエージェント名、報告日時、そのエージェントが今も接続しているかを持つ)として加えた(2026-09-21、所有者の決定)。
値は必ずそのルールの今の持ち主(`Rule.Agent`)のハートビートから引き、他のエージェントの古いハートビートが同じルール ID を載せていても混ざらない。
持ち主でないエージェントの古い報告を拾うと、ルールが別のエージェントへ移った直後や、削除された後もその旧い持ち主が未接続のままの間、無関係な(あるいは既に存在しない)エージェントの古い状態が正しい状態を上書きし得ます。
`agent_rule_states[].state`・`agent_rule_states[].reason` と、`agent ls --json`(`[]admin.AgentInfo`)の `tunnel.state`・`tunnel.reason`・`tunnel.endpoint`・`rules[].id`・`rules[].state`・`rules[].reason` は、いずれもエージェントのハートビートに乗って届く値なので、`vpsd` の受け口([5.2 節](control/connection.md#52-全体状態の配信とハートビート))が長さを切り詰め、表示できない文字を読める形に置き換えた後の値である(2026-09-25、所有者の決定)。
この切り詰めと置き換えは、値の意味(`ok`/`error` の語彙、拒否・失敗の理由の文言であること)を変えない範囲の加工として扱い、[7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の意味の変更の禁止には当たらない。
正当なエージェントが送る値の長さと文字種はこの加工の範囲に収まるので、影響を受けるのはハートビートの文字列に表示できない文字や [5.2 節](control/connection.md#52-全体状態の配信とハートビート)の上限を超える長さを混ぜて送る場合だけです。

今あるルールは、`Rule.Agent` が登録済みかどうかや報告の有無に関わらず、必ず `agent_rule_states` に 1 件の項目を持つ(2026-09-21、所有者の決定)。
存在しないルール ID がキーに現れないことは変わらない(削除したルールは、その持ち主が未接続のままでも、上の理由で拾われない)。
項目は 3 通りに読みます。

- `state` があり `connected` が true:そのルールの持ち主が今接続していて、直近のハートビートで報告した内容(`ok` か、`error` と `reason`)です
- `state` があり `connected` が false:持ち主の接続が切れる前の最後の報告であり、[5.2 節](control/connection.md#52-全体状態の配信とハートビート)のとおり現在の値として扱ってはなりません
- `state` が無い:持ち主がこのルールをまだ 1 度も報告していません。
  `connected` が true ならその持ち主は接続中でこれから報告しうる状態、false なら接続していない(一度も接続したことが無い、エージェントが削除された、など)ため当面報告は来ない

`state` が無いことは、値を持たないフィールドの一般の規則(観測していない値は省く。
上記の `tunnel.last_handshake` と同じ)に従っただけであり、`state` に `"unknown"` や `"pending"` のような server 発の値を新設したのではありません。
`state` はエージェント自身の語彙(`ok`/`error`)だけを持つ場所であり、そこに server が作った値を混ぜると、どちらが言った状態かが読み手にわかりにくくなる。
`reason`・`at` も `state` と一緒に省く。
`agent`・`connected` は常にあります。
`Rule.Agent` が指す名前が今は登録されていない(エージェントの削除。
[11 節](security/admin-transport.md#11-セキュリティ))場合も、その名前で hub を引くだけなので同じ形で `connected: false` の項目になります。
これで `rule ls --json` だけを読む自動化も、`agent ls` を突き合わせずにルールごとの拒否・失敗の理由と、まだ報告が無いことをすべて追える。
`agent ls` の RULES 列と Web UI は、同じ元データ(そのエージェントの直近のハートビート)から変わらず同じ情報を出す。

管理用 API のタイムスタンプ(`created_at`・`last_heartbeat`・`generation_behind_since`・`disabled_at`・`tunnel.last_handshake`・警告の `at` など)は、観測していない値をフィールドごと省き、観測した値を秒精度の RFC3339 の文字列で表す、という 1 つの規則に揃える。
`tunnel.last_handshake` はこれまでこの規則に従っておらず、agent -> server のハートビートに乗る wire の型(`proto.TunnelStatus`、[5.2 節](control/connection.md#52-全体状態の配信とハートビート))の `time.Time` をそのまま返していたため、一度もハンドシェイクしていないトンネルで Go の `time.Time` の既定の JSON 表現(`\"0001-01-01T00:00:00Z\"`、しかも他のタイムスタンプと違い RFC3339Nano)を返す不具合があった(2026-09-21 修正)。
`TunnelStatus` は agent の新旧の実装が読み書きし続ける wire の型なので変えず、管理用 API だけがこの規則に沿う別の型(`internal/vpsd/admin/tunnelview.go` の同名の `TunnelStatus`。
admin パッケージの中でだけ使う見せ方で、新しい層ではない)を経由して返します。

`RuleApply.ActiveGeneration`(`rule_states[id].active_generation`)は、世代 0 を「一度も公開していない」の代わりに使っていました。
世代はルールが 1 つも無ければ 0 なので([9 節](state.md#9-状態の保存と再起動))、0 は無効な値ではなく、公開済みの世代 0 と未公開が JSON 上で見分けられなかった。
`BatchResponse` の `desired_generation`・`active_generation` と同じ `*uint64` に変え、一度も公開していないルールはキーの値自体を省く(2026-09-21、所有者の決定)。

エージェントの無効化([5.1 節](control/registration.md#51-登録))は、管理用 API に次のものを加える(2026-09-24、所有者の決定)。
どれも加算です。

- `POST /api/v1/agents/{name}/disable` と `POST /api/v1/agents/{name}/enable`:リクエストの本文を持ちません。
  成功の応答は 200 で、`name`、`disabled`(操作の後の状態)、`changed`(状態が変わったか)、`generation`(操作の後の世代)を持ちます。
  状態が変わらない操作も 200 とし、`changed` を false にします。
  `changed` が false であることは、その状態が公開済みであることを意味しません。
  公開済みかどうかは `rule ls` と `server doctor` で確かめる。
  422 の応答の本文は、何も保存しなかったのか、保存は済んだが公開していないのかを、誤りの文言に頼らず機械が区別できる形で持ちます。
  この区別は保証の対象です。
  区別は本文の `saved` で表します。
  `saved` は真偽値で、この 2 つのルートの失敗の応答(404、422、500)が必ず持ちます。
  true は保存は済んだが公開していないことを、false は何も保存していないことを表します。
  true になるのは 422 だけです。
  有効化の検査が拒んだ 422 は false です。
  他のルートの失敗の応答は `saved` を持ちません
- `GET /api/v1/agents/{name}/state`:このルートが返すのは、エージェントに配る写しです。
  無効なエージェントでは、ルールの `enabled` は保存値ではなく `false` になります。
  全体状態に加算する無効を示すフィールド([5.1 節](control/registration.md#51-登録))も、このルートの応答に加わる。
  フィールドの名前は `agent_disabled` で、真偽値です。
  無効なエージェントでは true になり、有効なエージェントでは省く
- エージェント一覧(`GET /api/v1/agents`、`agent ls --json`)の `disabled` と `disabled_at`:`disabled` は真偽値で、常に持ちます。
  `disabled_at` は無効にした時刻で、上のタイムスタンプの規則に従い、有効なエージェントでは省く。
  旧い版の server は `disabled` を返さないので、読み手は不在を false と読みます。
  旧い版の server は無効化を持たないので、その読みは正しい

UDP の応答の観測([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor))は、管理用 API に `udp_replies` を加える(2026-09-24、所有者の決定)。
加算です。
`GET /api/v1/rules` と `POST /api/v1/rules/batch` の応答に、rule_id をキーにした項目として載る。
キーは、server が今公開している有効な UDP のルールだけです。
項目は次の 3 つを持ちます。

- `since`:途切れずに観測している始まりの時刻です。
  `not_observed` があるときは省く
- `last_reply_at`:`since` 以降に見た最後の応答の時刻です。
  見ていなければ省く
- `not_observed`:観測できない理由です。
  応答が無いこととは別の意味を持ちます

観測を報告しない Backend(`fakeBackend`、`tools/uidemo`)と旧い版の server は、フィールドごと省く。
時刻は上のタイムスタンプの規則に従います。

保たないものは、このバージョン(v1)にまだ無いフィールドの追加そのものを制限しないことです。
`GET /api/v1/nft` は他の `/api/v1/*` と違って `text/plain` を返すが、これは意図した例外です。
返しているのは `nft list table inet wgft` の出力そのもの、つまり本来テキストの資料であり、JSON に包んでも構造化した情報は増えない(2026-09-21、所有者の決定)。

機械が読める保証の対象は上表のルートと各レスポンス型の既存フィールドです。
人間向け(自由に変更してよいもの)は `ErrorBody` の `message` の具体的な言い回しです。

**Web UI(`/`、`/ui/...`、`/static/...`)。**
保つものはありません。
ダッシュボードの URL 構成、`/ui/rules/{id}` のようなパス、フォームのフィールド名、`?lang=` と言語 cookie、HTML の構造は、テンプレートの都合で理由なく変わってよい。
`GET /ui/rules/export` だけは JSON を返すが、これは CLI の `rule import` と同じ配列を人が手元で編集して読み込むための書き出しであり、`proto.Rule` の JSON 形(ルールのスキーマ、[5.3 節](control/rules.md#53-ルールのスキーマ))を経由した保証であって `/ui/` 自体の保証ではありません。
Web UI を自動化の対象にする場合は `/api/v1/...` を直接呼ぶべきで、`/ui/...` の HTML を解析すべきでない。

## 関連する仕様

- [サーフェスごとの互換性](compatibility/README.md)
