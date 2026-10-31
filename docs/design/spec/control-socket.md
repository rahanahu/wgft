# 制御ソケットと agent doctor --json

稼働中の agent は、`agent.json` の隣の AF_UNIX のソケットで、同じホストの CLI からの指示を受けます。
指示は `rotate-key` と `doctor` で、どちらも 1 行の要求に 1 行の応答を返します。
`wgft agent doctor --json` は、この応答と `agent.json` とホストの OS から組み立てた報告です。
理由と運用の扱いは[エージェント側の診断](../diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor)と[制御ソケットの拡張](../diagnosis/agent-control.md)にあります。

## ソケット

- パス:`<データディレクトリ>/agent.json.sock` です。
  Windows でも AF_UNIX です
- パスの長さ:sockaddr_un の `sun_path` に収まる長さで、どの OS でも収まるのは 103 byte までです。
  長すぎて開けなければ、その旨をログに出して制御ソケットを使わずに動きます
- 開き方:agent は起動のたびに同じパスの古いファイルを消してから待ち受けます。
  権限は [credentials.md](credentials.md#windows-の-dacl) のとおりです
- 閉じ方:停止のときにソケットを閉じ、ファイルを消します
- 開けない場合:agent は止まらずに動き続けます。
  その間、稼働中の `rotate-key` と `agent doctor` の稼働中の証拠は使えません

## 要求と応答

1 つの接続で 1 つの要求を扱います。

- 要求:改行 (`\n`) で終わる 1 行です。
  agent は前後の空白を除いてから照合します
- 期限:agent は接続ごとに読みと書きの全体を 30 秒で打ち切ります
- 応答:改行で終わる 1 行を書いて接続を閉じます

| 要求 | 応答 |
| --- | --- |
| `rotate-key` | 成功なら `ok <新しい公開鍵>`、失敗なら `error: <文言>` |
| `doctor` | 下の `DoctorResponse` の JSON の 1 行 |
| それ以外 | `error: unknown command` |

- `rotate-key` の扱い:agent は WireGuard の鍵対を作り直して `agent.json` に保存し、トンネルを作り直します。
  新しい鍵は次の stream の接続で `pubkey` として server に届きます
- 未知の要求:新しい CLI と古い agent を組ませた場合の扱いです。
  CLI は `error: unknown command` を「稼働中の診断を取れない」として扱います

CLI の側の上限は次のとおりです。

| 読み手 | 接続の期限 | 全体の期限 | 応答の上限 |
| --- | --- | --- | --- |
| `agent rotate-key` | 5 秒 | 30 秒 | 64 KiB |
| `agent doctor` | 設計の 10.2c 節のとおり | 設計の 10.2c 節のとおり | 4 MiB |

応答が上限に届いても改行が来なければ、CLI は上限を名指す誤りにします。
CLI は応答の文字列をすべて、表示できない文字を escape してから表示します ([messages.md](messages.md#理由の切り詰め) の 2 の変換)。
稼働中の agent も信頼の境界の外にあるためです。

## DoctorResponse

`doctor` の応答は、稼働中のプロセスしか持たない証拠だけを載せます。
`agent.json`、OS、名前解決のような停止中にも読める事実は CLI が自分で読み、応答には入れません。
キーの順は表の順です。

| キー | 型 | 省略 | 意味 |
| --- | --- | --- | --- |
| `error` | 文字列 | 空なら省きます | 応答を組む処理の失敗。値があれば他のキーはありません |
| `allow_targets` | オブジェクト | 無ければ省きます | 宛先の許可一覧 |
| `stream` | オブジェクト | 無ければ省きます | 制御の stream の観測 |
| `process` | オブジェクト | 無ければ省きます | agent のプロセスの実行主体 |
| `runtime_state` | オブジェクト | 無ければ省きます | 実行時の排他の下で 1 回に読んだ状態 |
| `runtime_state_timeout` | 整数 (ナノ秒) | 0 なら省きます | 実行時の排他を期限内に取れなかったときの待った長さ。v1 は 2 秒です |

- `allow_targets`:`set` (真偽)、`list` (正規化した一覧、空なら省く)、`env` (`WGFT_AGENT_ALLOW_TARGETS`) です
- `stream`:`connected`、`disconnected_at`、`disconnect_reason`、`pin_mismatch`、`key_change_limited`、`backoff` (ナノ秒)、`retry_at`、`last_ping_at`、`last_pong_at`、`awaiting_pong` です。
  時刻のキーは値が無くても零の時刻で書きます
- `process`:`uid` (Windows では -1)、`user`、`cap_net_admin` (Linux の外では省く) です
- `runtime_state`:`mode`、`generation`、`tunnel`、`rules`、`budgets`、`refusals_since`、`agent_disabled`、`kernel`、`publish_error`、`check_error` です。
  `tunnel` の `state` と `reason` はハートビートと同じ値です
- 文字列の上限:応答の中の 1 つの文字列は 512 byte で切ります
- 時間の値:`time.Duration` のキーはナノ秒の整数です。
  Go の性質として、Go の `time.Duration` を JSON にするとナノ秒の整数になります

各キーの細部と、`kernel` の中身の形は `internal/agent/controlapi` の型が正本です。
fixture の `testdata/spec/control/doctor-reply.json` (ユーザー空間モード) と `doctor-reply-kernel.json` (カーネルモード) は、ラボで稼働中の agent から読んだ応答です。
`internal/agent/controlapi` の `spec_test.go` が、Go の v1 の型が知らないキー無しで読み、同じ 1 行に書き戻すことを確かめます。
fixture が契約にするのは形で、値はラボで観測したものです。
`socket_buffers` の値は Linux のカーネルが `SO_RCVBUF` を倍にして返す値とラボの `net.core.rmem_max` で決まり、転送量やポートの値も実行ごとに変わります。

この応答は CLI の材料で、運用者向けの保証は次の `agent doctor --json` にあります。
Rust の agent と Go の v1 の CLI を組ませる場合は、この応答の形も合わせなければなりません。

## agent doctor --json

`wgft agent doctor --json` は、標準出力に 2 つの空白で字下げした JSON を 1 つ書き、改行で終えます。
最上位はオブジェクトで、キーの順は表の順です。

| キー | 型 | 意味 |
| --- | --- | --- |
| `status` | 文字列 | 総合判定。`ok`、`failed`、`unknown` のどれか |
| `checked_at` | 文字列 | 診断した時刻。RFC 3339 の UTC で、秒の小数部を持ちません |
| `data_dir` | 文字列 | 報告が答えるデータディレクトリ |
| `checks` | 配列 | 検査の一覧。並びは設計の検査の表の順です |
| `history` | オブジェクト | `available` (真偽) と `detail` (文字列)。v1 は履歴を持たず `available` は偽です |
| `not_tested` | 配列 | 試していない範囲。各要素は `id` と `detail` です |

`checks` の各要素は次のとおりです。

| キー | 型 | 省略 | 保証 |
| --- | --- | --- | --- |
| `id` | 文字列 | 省きません | 保証します |
| `status` | 文字列 | 省きません | 保証します。`ok`、`failed`、`unknown`、`skipped`、`not_tested` のどれか |
| `reason` | 文字列 | `ok` では省きます | 保証します。理由の符号 |
| `evidence_unreachable` | 真偽 | 偽なら省きます | 保証します。終了コード 2 に倒した検査だけが真 |
| `group` | 文字列 | 省きません | 人向けで保証の外 |
| `label` | 文字列 | 省きません | 人向けで保証の外 |
| `detail` | 文字列 | 省きません | 人向けで保証の外 |
| `next` | 文字列 | 空なら省きます | 人向けで保証の外 |

- 検査の `id` と理由の符号:一覧と意味は[検査の一覧と証拠の出どころ](../diagnosis/agent-evidence.md#検査の一覧と証拠の出どころ)と[総合判定を動かす検査](../diagnosis/agent-judgment.md)が正本です
- 終了コード:総合判定の `ok`、`failed`、`unknown` がそれぞれ 0、1、2 です。
  `failed` のとき、標準エラーに `Error: ` で始まる 1 行が出ます
- 加算の規則:キーと値は v1 の中で加えるだけで、名前と意味を変えません ([互換性](../compatibility/surfaces.md))

fixture の `testdata/spec/control/agent-doctor.json` は稼働中の agent に、`agent-doctor-stopped.json` は止めた agent に対して実行した出力です。
どちらもラボのユーザー空間モードの agent で、root で実行したので `host.privileges` は `unknown` の `running_as_root` です。
証明書とトークンのハッシュの先頭は fixture の値に置き換えてあります。
`cmd/wgft` の `spec_test.go` が、Go の v1 の型が知らないキー無しで読み、同じ byte 列に書き戻すことを確かめます。

[agent と server の境目の仕様](README.md)
