# stream の接続と寿命

stream は agent から server への WebSocket で、agent ごとに 1 本です。
agent は公開鍵とハートビートを送り、server は全体状態を送ります。
メッセージの形は [messages.md](messages.md) にあり、ここでは接続の手順、上限、閉じ方、再接続を定めます。
理由と運用の扱いは[全体状態の配信とハートビート](../control/connection.md#52-全体状態の配信とハートビート)、[stream の生死と再接続](../control/liveness.md)、[版の交渉](../architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性)にあります。

## 接続の要求

agent は次の要求で WebSocket を開きます。

- URL:`wss://<endpoint>/api/v1/agents/stream` です。
  `endpoint` は `agent.json` の `endpoint` です
- TLS:[join.md](join.md#tls-と証明書のピン) のピンの規則に従います。
  ピンは `agent.json` の `cert_sha256` です
- 認証:`Authorization: Bearer <permanent_token>` の header を付けます。
  server は `Bearer ` の 7 文字を大文字と小文字を区別して照合し、残りを恒久トークンとして読みます
- 拡張と subprotocol:permessage-deflate と subprotocol を求めません。
  server は permessage-deflate を受けません
- `Origin`:付けません。
  Go の性質として、server の WebSocket のライブラリ (`coder/websocket`) は、`Origin` があって `Host` と違う要求を拒みます
- 期限:WebSocket の確立までを 30 秒で打ち切ります

確立の前に server が返す状態は次のとおりです。
本文は Go の `http.Error` の形で、文言の後に改行が付きます。

| 状態 | 本文 | 条件 | agent の扱い |
| --- | --- | --- | --- |
| 401 | `unauthorized` | header が無い、形が違う、恒久トークンが無効 | [登録のし直し](#登録のし直し)に進みます |
| 429 | `too many attempts` | 送信元の IP アドレスの頻度の上限を超えた、またはその agent の確立の前の stream が既に 2 本ある | 通常の再接続です |
| 500 | `internal error` | 認証の読み取りの失敗 | 通常の再接続です |

送信元の頻度の上限は登録と同じ枠です ([join.md](join.md#応答))。

## メッセージの運び方

- フレーム:1 つのメッセージは 1 つの WebSocket のテキストのメッセージで、中身は 1 つの JSON のオブジェクトです。
  v1 の両側はテキストで送ります。
  Go の性質として、両側はバイナリのメッセージも同じように読みますが、これは保証の外です
- 書きの期限:両側とも 1 つのメッセージの書き込みを 10 秒で打ち切ります

読む量の上限は次のとおりです。
上限を超えるメッセージを受けた側は、WebSocket の close の符号 1009 で閉じます。

| 読む側 | 対象 | 上限 |
| --- | --- | --- |
| server | 最初のメッセージ | 4096 byte |
| server | 2 通目以降 | 1 MiB (1048576 byte) |
| agent | すべて | 4 MiB (4194304 byte) |

全体状態が 4 MiB に、ハートビートが 1 MiB に収まることは、agent あたりのルールの上限 512 本と、ID、`target`、理由の長さの上限から決まります ([ルールのスキーマ](../control/rules.md#53-ルールのスキーマ))。

## 接続の手順

1. agent は確立の直後に `pubkey` を 1 通送ります。
   中身は自分の WireGuard の公開鍵と、対応する版の範囲と機能です ([messages.md](messages.md#pubkey))
2. server は確立から 10 秒以内に届いた最初のメッセージだけを受けます。
   10 秒以内に届かない、JSON として読めない、`type` が `pubkey` でない場合は、符号 1008 と理由 `first message must be pubkey` で閉じます
3. server は公開鍵を確かめ、だめなら 1008 で閉じます。
   理由は `invalid public key`、`public key equals server key`、`public key belongs to another agent` のどれかです。
   他の agent の鍵を確かめる読み取りに失敗したら、1011 と `internal error` で閉じます
4. server は版を交渉し、だめなら 4004 か 4003 で閉じます ([版の交渉](#版の交渉))
5. server は公開鍵を保存し、WireGuard のピアを置き換えます。
   鍵の変更の頻度の上限に当たれば 1008 と理由 `public key changes are limited; retry later` で閉じます ([鍵の変更の頻度の上限](#鍵の変更の頻度の上限))。
   それ以外の失敗は 1011 と `peer setup failed` で閉じます
6. server は配る全体状態を選びます。
   選べなければ close のフレームを送らずに TCP を閉じます
7. 同じ agent の古い接続があれば、server はそれを 4000 と `superseded` で閉じます
8. server は全体状態 (`state`) を 1 通送ります
9. 以後、server は配る内容が変わるたびに全体状態を送り、agent はハートビートを送ります

鍵の検証と版の交渉に失敗した接続は、古い接続に影響しません。
同じ agent の接続の処理は server の中で 1 本ずつ進みます。

### 接続の後の server の扱い

- 期限:server は、データのメッセージを 90 秒受けなければ 4002 と `heartbeat timeout` で閉じます。
  期限は、JSON として読めたメッセージを受けるたびに戻ります。
  `type` が `heartbeat` でないメッセージも期限を戻します。
  WebSocket の ping と pong は期限を戻しません
- 読めないメッセージ:2 通目以降のメッセージを JSON として読めなければ、server は close のフレームを送らずに接続を捨てます
- 知らない `type`:`heartbeat` 以外のメッセージは期限を戻すだけで、中身を使いません
- 取り消し:管理者が agent を削除すると、server は接続を 4001 と `revoked` で閉じます
- 配る鍵の変化:配っている全体状態の鍵か登録が接続のものと違うものに変わると、server は close のフレームを送らずに接続を閉じます
- ping:server は ping を送りません。
  agent の ping には pong を返します

### 全体状態を受けた agent の扱い

- 最初の全体状態:接続ごとの最初の `state` は、世代に関わらず適用します。
  適用の前に `server_protocol_version` を確かめます ([版の交渉](#版の交渉))
- 古い世代:2 通目以降で、世代が最後に適用した世代より小さい `state` は捨てます
- 同じ内容:2 通目以降で、最後に適用して保存した全体状態と世代も中身も同じ `state` は適用し直しません
- 読めないメッセージ:JSON として読めないメッセージは、ログに 1 行出して捨て、接続を続けます
- 他の `type`:`type` が `state` でないメッセージと、`state` が無いか `null` のメッセージは捨てます
- 適用の後:適用のたびにハートビートを 1 通送ります ([ハートビートの送り方](#ハートビートの送り方))

世代の比べ方は接続の中に限ります。
server の世代が戻った場合も、接続し直せば最初の全体状態として適用します。

## close の符号と理由

| 符号 | 閉じる側 | 理由の文字列 | 意味 |
| --- | --- | --- | --- |
| 1008 | server | `first message must be pubkey` | 最初のメッセージの期限切れ、読めない、`type` の違い |
| 1008 | server | `invalid public key` | 公開鍵を 32 byte の base64 として読めない |
| 1008 | server | `public key equals server key` | server の公開鍵と同じ |
| 1008 | server | `public key belongs to another agent` | 他の agent の保存した鍵と同じ |
| 1008 | server | `public key changes are limited; retry later` | 鍵の変更の頻度の上限 |
| 1009 | 読む側 | ライブラリの文言 | 読む量の上限を超えた |
| 1011 | server | `internal error` または `peer setup failed` | server の内部の誤り |
| 4000 | server | `superseded` | 同じ agent の新しい接続に置き換わった |
| 4001 | server | `revoked` | 恒久トークンを取り消した |
| 4002 | server | `heartbeat timeout` | 90 秒メッセージが届かない |
| 4003 | server | `no overlapping protocol version: server supports [<min>,<max>], agent supports [<min>,<max>]` | 版の範囲に共通部分が無い |
| 4004 | server | `malformed protocol advertisement: ...` | 版の宣言の形の誤り ([版の交渉](#版の交渉)) |

- 1008 の見分け:server は 1008 を公開鍵の拒否にだけ使います。
  agent は再接続の待ちを 1008 の符号だけで判断し、理由の文字列を見ません。
  鍵の変更の頻度の上限かどうかだけは、理由の文字列が `public key changes are limited; retry later` と一致するかで見分け、`agent doctor` に示します
- 1009 の文言:ライブラリの文言で、保証の外です
- close のフレームの無い終わり:上の手順 6、読めないメッセージ、配る鍵の変化で、server は close のフレームを送らずに閉じます。
  agent は通常の切断として扱います
- agent の側の閉じ方:agent は close のフレームを送らずに閉じます。
  停止、ping の期限切れ、server の選んだ版の拒否が当たります。
  これは保証の外で、server は通常の切断として扱います

fixture の `testdata/spec/wire/close.json` が、符号と理由の文字列を持ちます。

## 版の交渉

v1 の両側が対応する番号の付いた版は 1 だけで、機能 (capability) の語彙は空です。

agent の宣言:

- agent は `pubkey` に `protocol_min: 1`、`protocol_max: 1`、`capabilities: []` を載せます。
  `capabilities` は空でも省きません。
  空の配列は「版はあるが追加の機能は無い」を表し、フィールドの不在は legacy v0 を表すためです

server の判定は、`protocol_min` と `protocol_max` の有無で 4 通りに分かれます。

| 宣言 | server の扱い |
| --- | --- |
| 両方とも無い | legacy v0 の agent とみなし、交渉しません。全体状態に `server_protocol_version` と `server_capabilities` を載せません |
| 片方だけある | 4004 で閉じます。理由は `malformed protocol advertisement: <ある方> is present but <無い方> is missing` です |
| 両方あるが `protocol_min` が 1 未満か `protocol_max` より大きい | 4004 で閉じます。理由は `malformed protocol advertisement: invalid range [<min>,<max>]; protocol_min must be at least 1 and at most protocol_max` です |
| 両方あり範囲が正しい | server の範囲 `[1,1]` との共通部分の最大を選びます。共通部分が無ければ 4003 で閉じます |

- `null` の扱い:`protocol_min: null` は不在と同じです ([encoding.md](encoding.md#読む側の規則))
- 選んだ版:server は選んだ版を全体状態の `server_protocol_version` に、自分の機能を `server_capabilities` に載せます。
  v1 の server の `server_capabilities` は `[]` です
- agent の確かめ:agent は接続の最初の `state` で `server_protocol_version` を確かめます。
  フィールドが無ければ legacy v0 の server とみなし、確かめません。
  値が 1 未満か、agent の範囲 `[1,1]` の外なら、接続を閉じて通常の再接続に入ります
- ログ:両側とも選んだ版を接続ごとに 1 回ログに出します。
  agent の行は `stream: server selected protocol v1` か `stream: server selected protocol legacy v0` です

legacy v0 は v1.0.x の間は必ず支え、v1.1 以降は支えなくて構わないと決めてあります ([版の交渉](../architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性))。
v1 の Go の server は今も legacy v0 の agent を受けます。
Rust の agent は legacy v0 の宣言を送りません。

## ハートビートの送り方

- 周期:接続している間、30 秒ごとに送ります
- 適用の直後:全体状態を適用するたびに 1 通送ります。
  接続の直後の最初の適用も含みます。
  送っていない通知が溜まっていれば 1 通にまとめます
- ハンドシェイク待ちの追送り:適用の直後のハートビートのトンネルの理由が `handshake not established` なら、1 秒ごとに最長 10 秒まで送り直します。
  理由が変わったら送り直しをやめます。
  30 秒ごとの送信では送り直しません
- stream の外の変化:保留した適用の再試行が成功したときと、カーネルモードの観測で状態が変わったときも、1 通送ります
- 書く順:JSON のメッセージを書くのは接続ごとに 1 つの処理だけで、メッセージが混ざりません

中身と理由の切り詰めは [messages.md](messages.md#heartbeat) にあります。

## ping と接続の生死

- ping:agent は接続している間、30 秒ごとに WebSocket の ping を送ります
- 期限:20 秒以内に pong が届かなければ、接続を閉じて再接続します
- 適用の間:全体状態を適用している間は ping を送りません。
  ping を送ってから pong を待つ間に適用が挟まった場合も、期限切れで閉じません。
  適用の間は agent が読みを止めるので、pong を処理できないためです
- ping の中身:v1 の agent は 1 から数える 10 進の数字を送ります。
  中身は保証の外です

## 再接続

agent は stream が終わるたびに待ってから接続し直します。
規則は次のとおりです。

- 待ちの伸び方:最初は 1 秒で、待つたびに倍にし、5 分で止めます
- 待ちを戻す条件:接続が 1 分を超えて続いた後の切断では、次の待ちを 1 秒に戻します
- 新しいハンドシェイク:待っている間に WireGuard の新しいハンドシェイクを観測したら、残りの待ちを打ち切って直ちに接続し、待ちを 1 秒に戻します。
  観測はトンネルの点検が 30 秒ごとに読む最終ハンドシェイクの値です。
  接続していた間に観測したハンドシェイクは使いません
- トンネルが新しい間の上限:最終ハンドシェイクが新しい間は、待ちの上限を 10 秒にします。
  新しいとは、最終ハンドシェイクの値を観測した時刻からも、値そのものの時刻からも 180 秒未満であることです。
  観測した時刻からの経過は単調な時計で測ります
- 上限を当てない切断:恒久トークンの拒否、4000、4001、4003、1008、証明書のピンの不一致、server の選んだ版の拒否では、トンネルが新しくても待ちの上限を 10 秒にしません
- ログ:待ちに入るたびに 1 行出します。
  前と同じ文面の行は 1 分に 1 行までにし、出さなかった行の数を次の行に添えます

### 登録のし直し

- 恒久トークンの拒否:確立の前の 401 では、`WGFT_JOIN` で登録し直します。
  `WGFT_JOIN` が無い、読めない、使用済みのどれかなら、終了コード 3 の拒否で止まります。
  登録し直しに失敗したら、`agent.json` を残して誤りで止まります
- 証明書のピンの不一致:`WGFT_JOIN` があり、使用済みでなく、そのピンが `cert_sha256` と違うときだけ、その接続文字列で登録し直します。
  条件に合わなければ止まらずに再接続を続け、新しい接続文字列が要ることをログで示します
- 登録し直しの成功:待ちを 1 秒に戻して接続します

登録し直しの手順と `agent.json` への記録は [join.md](join.md#登録の結果の記録) と同じです。
登録し直しだけが `tunnel_address` の記録を置き換えます。

## 鍵の変更の頻度の上限

server は、保存している公開鍵を別の鍵に変える宣言を、登録ごとに続けて 3 回までと、その後は 10 分に 1 回までに限ります。
数え方は 10 分ごとに 1 回分が戻り、3 回分まで溜まるトークンバケットです。

- 数える宣言:保存している鍵を変える宣言だけを数えます。
  初回の宣言、保存している鍵と同じ鍵での再接続、新しい鍵の適用が失敗している間の最後に成功した鍵での再接続は数えません
- 上限を超えた宣言:鍵を保存せず、ピアも変えず、1008 と `public key changes are limited; retry later` で閉じます
- 状態の置き場所:上限の状態は server のプロセスのメモリにあり、server の再起動で戻ります
- agent の扱い:通常の再接続を続けます。
  wgft の agent は運用者の `agent rotate-key` のときだけ鍵を変えます

[agent と server の境目の仕様](README.md)
