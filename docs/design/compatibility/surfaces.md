# CLI、設定、wire、配布物の互換性

CLI と設定、wire、データの更新経路、配布物には、それぞれ維持する名前と意味があります。


**CLI のコマンドとフラグ。**
保つものは、コマンド名とサブコマンドの構成(`server`・`agent`・`rule`・`status`・`version` とその下位)、フラグの名前と意味、`--json` を持つコマンド(`rule ls`・`agent ls`・`status`・`server doctor`・`agent doctor`)がその出力を持ち続けることです。

保たないものは、表形式の人間向け出力(列の並びと幅、`last:` のような接頭辞、REFUSED や DROPPED の見せ方)と、`--help`・`docs/cli.md` の文面です。

機械が読める保証の対象は `--json` の出力です。
ただし、出力の形には 2 通りあります。
`rule ls --json` は `admin.BatchResponse` を、`agent ls --json` は `[]admin.AgentInfo` を、CLI 側で別の型に写さずそのまま出力します。
この 2 つは管理用 API の応答をそのまま出しているだけなので、保証は上記の管理用 API の保証そのものであり、二重に管理しません。
`status --json`([10.2b 節](../status.md#102b-状態の要約wgft-status))と `server doctor --json`([10.2a 節](../diagnosis/server-observations.md#102a-転送の診断-server-doctor))はこれとは違う。
どちらも管理用 API の応答だけを読んで組み立てるが、出力は `statusReport` と診断の報告の型という、admin パッケージのどの型とも一致しない模型です。
`statusReport` は CLI だけが持ちます。
診断の報告の型は、[10.2d 節](../web-doctor.md#102d-web-ui-の診断の画面)のとおり Web UI と共有する姉妹 package へ移るので、CLI 専用ではありません。
保証するのは `server doctor --json` が出力する JSON の形であって、その型をどの package が持つかではありません。
`agent doctor --json`([10.2c 節](../diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor))も CLI が組み立てる模型だが、管理用 API を読まない。
エージェントのホストの認証情報ファイル、OS、稼働中のエージェントの制御ソケットから組み立て、CLI だけが持ちます。
この 3 つの保証は、それぞれの節(10.2b・10.2a・10.2c)が個別に定め、フィールドの追加も、既知の値の集合の開き方も、各節の記述に従います。
管理用 API の型をそのまま返すコマンドと、CLI が組み立てる模型を持つコマンドは、この節では別の扱いとして書き分ける。
いずれの場合も、ここから導かれる規則は次のとおりです。

- フィールドは v1 の中で追加されるだけで、名前が変わったり削除されたりしません
- 消費者は知らないフィールドを無視しなければならない(`encoding/json` の既定の振る舞いに合わせる)
- 列挙値を持つフィールド(`rule_states` の `apply_state`、`tunnel` と `rules` の `state`、`agent_rule_states` の `state`、`resource_refusals` の理由のキー、警告の `kind`、`status --json` の `server.status`、`server doctor --json` の `checks[].id`・`checks[].status`・`checks[].reason`、`agent doctor --json` の `status`・`checks[].id`・`checks[].status`・`checks[].reason`)は、v1 の中で値が増えうる開いた集合です。
  消費者は知らない値を「不明」として扱い、失敗にしてはなりません。
  この条件のもとで、値の追加は互換です。
  既存の値の意味は変えません。
  リクエストに書く側の列挙値(ルールの `proto`、`vps_mode`)は閉じた集合で、値の追加は新しい機能の追加として扱う
- 人間向けの表(`rule ls`・`agent ls` の素の出力、`status`・`server doctor`・`agent doctor` の表形式の出力)は自動化が読んではならない情報であり、どの列が何を意味するかは `--help` の文面と同じ扱いで自由に変わる
- `--json` の出力のうち表に現れない項目(`rule ls --json` の `rule_states`・`drift`・`desired_generation`・`active_generation`、`agent ls --json` の `public_key`・`registered_from`・`created_at`・`agent_protocol_min`・`agent_protocol_max`・`generation_behind_since`・`warnings` の詳細)も同じ保証の対象であり、情報量が多い分だけ自動化に向く。
  `status --json` の `server.detail`・`rules.detail`・`agents.detail`・`warnings.detail` はこれとは逆です。
  どれも表にそのまま印字される文字列であり、表に現れない項目ではないため、保証の対象ではない([10.2b 節](../status.md#102b-状態の要約wgft-status))
- 一発実行のコマンドの終了コードも、`--json` の出力と並ぶ機械が読める保証の対象です。
  成功が 0、失敗が 0 以外であり、0 以外のどの値になるかを定めるのは各節です。
  定めが無いコマンドはこの共通の保証だけを持つ(本節冒頭の横断する規則)

エージェントの無効化([5.1 節](../control/registration.md#51-登録))は、CLI に次のものを加える(2026-09-24、所有者の決定)。
どれも上の規則の加算に当たる。
無効なエージェントは新しい状態であり、既存の利用者の手元には現れないので、既存の値の意味は変わりません。

- `agent disable` と `agent enable`:コマンドの加算です。
  `--json` を持たず、終了コードは共通の保証だけを持ちます。
  無効かどうかは `agent ls --json` の `disabled` で読む(管理用 API の項)
- `server doctor --json`:`checks[].id` に `agent.enabled` を、`checks[].reason` に `agent_disabled` を加える([10.2a 節](../diagnosis/server-observations.md#102a-転送の診断-server-doctor))。
  どちらも開いた集合への値の加算です
- `agent doctor --json`:`checks[].reason` に `agent_disabled` を加える([10.2c 節](../diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor))。
  開いた集合への値の加算です
- `status --json`:`agents` に `disabled` を加える([10.2b 節](../status.md#102b-状態の要約wgft-status))。
  `agents.total` は登録済みのエージェントの総数という意味を変えません。
  `healthy`、`degraded`、`unknown` は有効なエージェントだけを数え分け、`healthy` + `degraded` + `unknown` + `disabled` = `total` が成り立つ。
  無効なエージェントが無い配置では、どの値も変わりません
- `status --json` の `rules`:`agent_disabled` を加える([10.2b 節](../status.md#102b-状態の要約wgft-status))。
  常に持ち、該当が無ければ 0 とします。
  `rules.total` は `Rule.Enabled` が真のルールの数という意味を変えず、`active` + `degraded` + `unknown` + `agent_disabled` = `total` が成り立つ
- 持ち主が登録されていないルール:`status --json` と `server doctor --json` の結果は変えない([5.1 節](../control/registration.md#51-登録))。
  `agent.enabled` はこれらのルールで OK になり、既存の検査の結果、ルールの `status`、最上位の `status`、終了コードのどれも動かさない

UDP の応答の観測([10.2a 節](../diagnosis/server-observations.md#102a-転送の診断-server-doctor))は、`server doctor --json` の `rule.target` の検査に任意の項目 `last_reply_at`・`reply_since`・`reply_not_observed` を加える(2026-09-24、所有者の決定)。
加算であり、`checks[].id`・`checks[].status`・`checks[].reason` は変えません。
値は管理用 API の `udp_replies` の写しで、UDP のルールの `rule.target` にだけ付き、観測を報告しない server では省く。

**設定(`WGFT_*`)。**
[11a 節](../security/configuration.md#11a-設定の渡し方)が定める名前と意味を維持します。
同じ名前をフラグとファイル(dotenv)の両方から渡せることと、優先順位(フラグ、環境変数、ファイル、既定の順)も保証に含む。
`--force`・`--purge`・`--adopt-existing`・`--yes`・`--dry-run` の 5 つは 1 回限りの操作なので、これらに対応する `WGFT_*` を新設しないことも保証に含む([11a 節](../security/configuration.md#11a-設定の渡し方))。

保たないものは、値の構文検査の追加・強化です。
検査を新設・強化して今まで通っていた誤った値を拒むようにすることは、[11a 節](../security/configuration.md#11a-設定の渡し方)の「設定起因の失敗は終了コード 3」の原則に沿う限り互換の維持とみなす。
値そのものの意味を変えることは互換でない。

**ログ出力。**
保証はありません。
秘密(登録トークン、恒久トークン、秘密鍵、`Authorization`、接続文字列全体)をログに出さないことは [10.4 節](../operations/output.md#104-ログ)の約束だが、これは互換性の保証ではなく安全側の性質です。
行の書式、語順、`journalctl` で拾える語彙は、いつでも変えてよい。
`scripts/check-log-tokens.sh` は CI の内部検査であり、トークンらしき文字列がログに紛れていないかを人が確認した一覧と照合するだけで、ログの形式を外部に約束するものではありません。
`journalctl -u wgft | grep 'rules: '`(docs/manual/setup.md)のような固定の接頭辞に頼る運用があっても、それは wgft の保証ではなく運用側の前提です。

**agent-server の wire protocol と capability。**
[7a.6 節](../architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性)が定めるとおり、`pubkey`(agent → server)と `state`(server → agent)の既存フィールドの意味は変えません。
版の交渉の仕組み(`protocol_min`/`protocol_max`/`capabilities`、`server_protocol_version`/`server_capabilities`、legacy v0)そのものが約束であり、これによって将来の版で全体状態の形を変えても、直前の版までの実装と rolling upgrade できます。
保つものは、`pubkey`/`state` の JSON フィールド名と型、legacy v0 の判定規則(両方のフィールドが無ければ legacy)、malformed な advertisement と共通部分が無い場合を別の WebSocket close コード(`4003`/`4004`、`proto/stream.go`)で区別することです。
保たないものは capability 文字列の語彙(まだ何も定義されていない)と、エージェント用 API のエラー文言です。
既存のフィールドに新しい値を足すことは、wire の上では加算として扱わない。
受け取る側の旧い実装がその値を許容すると確かめられていなければ、capability で交渉する変更として扱う([7a.6 節](../architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性)。
旧い側が表せないルールは理由付きの `not_active` にする)。

現在の値は `proto.SupportedProtocol = {Min: 1, Max: 1}` であり、番号の付いた版は v1 の 1 つしか存在しません。
`capabilities`/`server_capabilities` の語彙も `proto.SupportedCapabilities` が空配列で、まだ 1 つも定義されていません。
したがって「現在の版と直前の版の 2 つを必ず支える」という [7a.6 節](../architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性)の約束は、今のところ実地で確かめようがありません。
v2 が実際に生まれ、それに対する v1 との rolling upgrade をラボで確かめるまで、この約束は設計上の意図であって検証済みの事実ではない(下記「保つのが難しい約束」)。

**サーバのデータベースとエージェントの認証情報ファイル。**
保つものは、更新の経路(SQLite の migration が自動で吸収します。
`internal/vpsd/store` は `PRAGMA user_version` で管理し、今のバイナリが対応する版より新しい DB を開こうとした場合は原因を示して起動を拒む)と、データの置き場所(`WGFT_DATA_DIR`、[11a 節](../security/configuration.md#11a-設定の渡し方))およびファイル名(`agent.json`、サーバのデータベースファイル)です。

保たないものは、旧版への戻し([7a.6 節](../architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性)で既に保証から除外済み)と、DB のテーブル定義や `agent.json` の JSON の内部の形です。
エージェントの認証情報ファイルは知らないフィールドを保存し直さない。
読み書きのたびに `Credentials` 構造体に無いキーは消えるため、手で編集したファイルや将来の版が足したフィールドを今の版が読み書きすると失われうる。
認証情報ファイルを人が編集する運用は元から想定していないので、これは許容します。

**ファイルの権限と所有者。**
方針が 2 つに分かれていることをここに明記します。
サーバのデータベースファイルと WAL の補助ファイルは、起動のたびに group・other の権限を積極的に締め直す([9 節](../state.md#9-状態の保存と再起動))。
エージェントの認証情報ファイルは Unix では締め直さない(管理者が絞った権限を緩めないため)一方、Windows では DACL を起動のたびに締め直す([11a 節](../security/configuration.md#11a-設定の渡し方))。
`server.env`(0644 推奨)・`agent.env`(0640 推奨)はどちらも chmod で強制せず、`agent.env` が秘密(`WGFT_JOIN`)を含みかつ other から読める場合にだけ 1 行警告します。
つまりこれらの推奨パーミッションは保証ではなく推奨であり、警告を出すかどうかの規則だけが保証です。

**`deploy/` の同梱物。**
保つものは、systemd の unit ファイル名(`server.service`・`agent.service`。
それぞれの中身にある `ExecStart`・`RestartPreventExitStatus=3`)、エージェントのカーネルモードの drop-in のファイル名(`agent.kernel.conf`。
利用者が手順の中でパスで参照するため)、compose ファイルが使う環境変数名とボリュームパス、macOS の plist の `Label`(`io.github.rahanahu.wgft.agent`)です。
保たないものは、サンドボックス化の詳細(`ProtectSystem=strict` などの個々の設定)で、守りを強める変更は互換の維持とみなす。

**リリース成果物とコンテナイメージ。**
保つものは、バイナリ名の形式 `wgft-{os}-{arch}`(Windows だけ `.exe` が付く)と、対応する `.sha256`・`.spdx.json` が付くこと、コンテナイメージ名 `ghcr.io/rahanahu/wgft-server`・`ghcr.io/rahanahu/wgft-agent` とその版タグ(`vX.Y.Z`)と、リリースのバイナリの `wgft version` の 1 行目がそのリリースのタグ(`vX.Y.Z`)そのものであることです。
docs/manual/setup.md の手順は、この行で systemd の unit のファイルをバイナリと同じタグから取得します。
保たないものは、`:latest` タグの中身(常に最新の版を指すので固定した参照ではない)と、対応する OS・アーキテクチャの組み合わせ([11a 節](../security/configuration.md#11a-設定の渡し方)が明記するとおり、実機で検証できた組み合わせだけを増減する)です。
この項は配布物の名前と付随物の形の約束であり、本節冒頭の暫定の扱いはこの項に影響しません。
agent の保証の範囲の外の挙動を暫定とすること自体は、現在配っているバイナリの配布を取りやめる決定ではありません。
配布する成果物については、この項の名前と付随物の形式を保つ。

**Go モジュールとパッケージ(`proto/`、`cmd/`)。**
`proto/` は `internal/` の外にあるため Go のコードとして外部から import できるが、README(英日とも)はこれをライブラリとして使えるとは謳っておらず、CLI とコンテナイメージだけを配布物として説明しています。
この文書は `proto/` の Go の型・関数を外部向けの API とは約束しません。
約束しているのは `proto` パッケージが生成する JSON の形(ルールのスキーマ、wire protocol のメッセージ)であり、それは上記の各節で個別に保証しています。
Go のシグネチャの変更(フィールドの型、メソッドの追加)はこの節の対象外です。

[互換性](README.md)
