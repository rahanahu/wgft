<a id="7a6-維持する外部仕様と互換性"></a>
### 維持する外部仕様と互換性

公開した wire の既存フィールドの意味を維持し、版と capability を交渉します。
未知の加算フィールドは読み飛ばせる形式で扱います。


内部の package、型、interface、DB のスキーマは互換を求めません。
次の境界は外部仕様として維持します。

| 維持する外部仕様 | 維持の方法 |
|---|---|
| CLI のコマンドとフラグの意味 | 変えない。`cmd/wgft` は `admin.Client` と Options を介するだけなので、内部の再構成の影響を受けない |
| 文書化した `WGFT_*` | 変えない。`WGFT_MODE` は `DataplaneMode` の外部名として残す |
| 機械向けの CLI 出力 | 変えない |
| ルールの書き出しと読み込みの形式 | 変えない。`vps_mode`/`proxy_protocol` の値は、normalize 時に `Forwarding`/`SourceMetadata` へ写すアダプタを通すだけで、JSON の形は変わらない |
| admin API v1 | 既存のリクエストとレスポンスの意味は変えない。ルールごとの適用状態のような新しい情報は加算的にだけ追加する([7a.3 節](lifecycle.md#7a3-状態遷移と失敗の意味論)) |
| join string と agent/server の通信 | 既存のメッセージの意味は変えず、版と機能の交渉を加算的なフィールドとして追加する(下記) |
| 既存のデータの置き場からの更新 | SQLite と状態ファイルは自動の migration で吸収する。旧版への戻しは保証に含めない(下記) |

wire protocol の版と機能の交渉は、既存のメッセージへ次のフィールドを追加するだけで足りる。

- agent が送る最初のメッセージ(`pubkey`)に、対応する版の範囲 `protocol_min` と `protocol_max`(整数)と、`capabilities`(文字列の配列)を追加します
- server が送る全体状態(`state`)に、その接続で選んだ版 `server_protocol_version`(整数)と `server_capabilities`(文字列の配列)を追加します

版の番号は 1 から始める。
server は自分が対応する版の範囲と agent の範囲の共通部分を取り、その最大の版をその stream 接続の版として選ぶ(例:agent が 2 から 3、server が 1 から 2 なら 2、agent が 2 から 3、server が 2 から 3 なら 3)。
共通部分が無ければ、server は双方の範囲を示すエラーで stream を断り、agent はそれをログに出す。
`protocol_min`/`protocol_max` の片方だけがある宣言、または `protocol_min` が 1 未満か `protocol_max` を超える宣言(番号の付いた版は 1 から始まるため、どちらも版の範囲として意味を持たない)は、共通部分が無い場合とは別に malformed な advertisement として扱い、何が壊れているかを示すエラーで stream を断る。
前者(共通部分が無い)は版を上げれば直る正常な状態、後者(malformed)は相手の実装の不具合という違いがあるため、agent が原因を区別できるよう、送る理由は別にします。
agent は、返ってきた `server_protocol_version` が 1 以上の番号の付いた版であり、かつ自分の範囲に入っていることを確かめる。
`server_protocol_version` は server が実装する最新の版ではなく、その接続で選んだ版です。
全体状態は選んだ版のスキーマと意味だけで組み立てるため、1 通の `state` がどの版に属するかは曖昧になりません。
同じルール集合でも stream 接続ごとに形を作り分けられるため、全体状態の形そのものを変える機能追加でも、旧い実装との互換を保ったまま進められる。
`capabilities`/`server_capabilities` が空の配列なら「版はあるが追加の機能は無い」を表します。

版のフィールドを持たない実装(今の実装)は、legacy v0 として別に扱う。
agent の `pubkey` に `protocol_min`/`protocol_max` が無ければ、その agent は legacy v0 にしか対応しないとみなし、server は今の形の全体状態を送る。
server の `state` に `server_protocol_version` が無ければ、agent はその server を legacy v0 とみなし、今の機能だけを使います。
Go の `encoding/json` は構造体に無いフィールドを無視するので、旧い側は新しいフィールドを読み飛ばすだけで済み、専用のネゴシエーションのラウンドトリップは要りません。

どこまで旧い実装を支えるかは、製品の版ではなく版の番号で決める。
server と agent は、番号の付いた版のうち現在の版と直前の版の 2 つを必ず支える。
これにより、通常の rolling upgrade(server と agent のどちらを先に上げても)が通る。
legacy v0 はこの版の履歴に含めない特例で、server と agent の双方が v1.0.x の間は必ず支え、v1.1 以降は落としてよい。
capability を追加しただけでは版を上げない。
既存の版で意味を後方互換に表せなくなったときだけ上げる。
旧い実装が新しい機能を表せない場合は、黙って旧い挙動へ downgrade せず、そのルールを理由付きの `not_active`(例:`agent does not support capability X`)にします。
通信方針はどの agent の版でも同じ意味を持つべきだからである([7a.1 節](model.md#7a1-原則と優先順位)の原則 1)。

`capabilities`/`server_capabilities` の語彙(将来の差分配信、複数エージェントへの振り分けなど、どの機能をどの文字列で表すか)は、その機能を追加する時点で個別に定める。

対応する版の範囲と、接続の版は、性質の異なる値です。
利用者向けの出力ではこの 2 つを区別します。
`wgft version` は、実行したバイナリに組み込まれた、対応する版の範囲(`proto.SupportedProtocol` の Min と Max)を出す。
この範囲が指すのは番号の付いた版だけであり、版のフィールドを持たない legacy v0 の相手は含まない。
server は legacy v0 の agent を v1.0.x の間はこの範囲に関わらず別に受け入れるため(上記)、範囲の外だからといって legacy v0 の相手と繋がらないとは限らない。
値はディスク上のそのバイナリに組み込まれた静的な値であり、動いている server のプロセスの範囲を読み取るものではありません。
VPS で実行した場合でも、バイナリを置き換えてから server のプロセスを再起動するまでの間は、動いている server の範囲と一致しないことがあります。
rolling upgrade はまさにこの不一致が生じる区間であり、両者の違いが意味を持つ場面でもあります。

`wgft agent ls` は、そのエージェントとの接続の版を出す。
値は 3 通りに分かれる。
`protocol_min`/`protocol_max` に共通部分があり `SelectProtocolVersion` が版を選んだ接続は、選んだ版(`vN`)を出す。
agent が legacy v0 として扱われた接続(`SelectProtocolVersion` を呼ばずに決まる。
上記)は `legacy` を出す。
どちらでもない場合、つまりエージェントが切断している間と、接続中でも相手が `protocol_version`/`agent_protocol_legacy` を返さない旧い server である場合は、`-` を出す。
切断している間に最後に選んだ版を今の値として出さないのは、[5.2 節](../control/connection.md#52-全体状態の配信とハートビート)が stream の切断後もエージェントの最後の報告を残しつつ、それを今の状態として描くことを禁じているのと同じ理由による。
`wgft version` が出す範囲と、`wgft agent ls` が出す 3 つの値では、表示の文言を揃えない。
範囲か、選んだ版か、legacy か、不明かのどれであるかが分かる語を使います。
番号の付いた版は 1 から始まり legacy v0 とは別の値なので、旧い server との接続を `v0` とは表さない。

更新の経路は保証します。
旧版への戻しは互換性の保証に含めず、各版で観測した挙動だけを記録します。
戻す必要があるときは、更新の前に取ったデータの置き場のバックアップから戻します。
戻しを約束すると、SQLite のスキーマ、migration、知らないフィールドの保存、状態ファイル、wire protocol の変更を、旧い版が読める形に永久に縛ることになるためです。
wire protocol の直前の版との互換は、上記の rolling upgrade のために別に支えるもので、データの置き場を旧い版へ戻せることは意味しません。

外部の表現が新しいモデルと根本から矛盾する例は、今のところ見つかっていません。
`vps_mode`、`proxy_protocol` を含め、既存の外部表現はすべて内部モデルへ写せています。
今後そのような矛盾が見つかった場合は、旧い形式を読めるアダプタを用意したうえで新しい形式を正とする、という規則を適用します。

[内部構造](README.md)
