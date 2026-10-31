# agent と server の境目の仕様 (wire の版 1)

この文書群は、Go で書いた wgft v1 が今実装している agent と server の境目を、言語に依らない形で書いたものです。
対象は wire の版 1 と、その前の legacy v0 の扱いです。
Rust の実装はこの文書群を契約として従います。
最初に Rust の agent を変更していない Go の v1 の server と組ませ、後で Rust の server を同じ契約で作ります。

## 位置付けと読み方

この文書群は今の振る舞いを写したもので、振る舞いを変えません。
振る舞いを決める理由は既存の設計の各節にあり、この文書群はその節へ案内します。
この文書群と Go の v1 の振る舞いが食い違う場合は、Go の v1 の振る舞いが正です。
その場合はこの文書群と fixture を直します。

文の扱いは次のとおりです。

- 要件:断りの無い文は、v1 の実装が満たす要件です。
  Rust の実装も同じ要件を満たします
- Go の性質:見出しか箇条書きのラベルに「Go の性質」とある項目は、Go の標準ライブラリか依存のライブラリの性質だけで決まる挙動です。
  Go 以外の実装が同じ結果を出すために要ることを、同じ項目に書きます
- 観測:「保証の外」とある項目は、v1 で観測できるが相手が頼ってはならない挙動です
- 未確認:確かめていない点は「未確認」と書きます

## 文書の一覧

| 面 | 文書 | 中身 |
| --- | --- | --- |
| JSON の共通規則 | [JSON の符号化と Go に由来する細部](encoding.md) | キーの大文字と小文字、重複したキー、知らないキー、時刻、配列の不在と空、HTML の書き換え |
| 登録 | [接続文字列、登録、証明書のピン](join.md) | `wgft://` の形、`POST /api/v1/agents/register`、TLS の検証 |
| stream | [stream の接続と寿命](stream.md) | 認証、最初のメッセージ、読む量の上限、close の符号、版の交渉、再接続、鍵の変更の頻度、ping |
| stream のメッセージ | [pubkey、state、heartbeat](messages.md) | メッセージの形、`WGConfig`、`AgentRule`、`agent_disabled`、理由の切り詰め |
| 認証情報 | [agent.json と .lock と .sock](credentials.md) | 置き場所、キーと型と省略、書き方、ロック、Windows の DACL |
| 制御ソケット | [制御ソケットと agent doctor --json](control-socket.md) | 要求の行、応答の JSON、上限、`agent doctor --json` の形 |
| CLI と設定 | [agent の CLI と設定](cli-config.md) | コマンドとフラグ、`WGFT_*`、優先順位、dotenv、終了コード、起動ログ、秘密を伏せる規則 |
| トンネルの中 | [トンネルの中の約束](tunnel.md) | アドレス、MTU、keepalive の ping、ハンドシェイクの監視、疎通確認、ルールのポート、中継、UDP の timeout、IPv4 の断片 |

server の側だけの面、つまり管理用 API、サーバのデータベース、Admission Policy の IR、nftables の出力は、Rust の server に着手する前に別に書きます。

## fixture と照合の試験

fixture はリポジトリの直下の `testdata/spec/` に置き、Go と Rust の両方が読みます。
fixture は Go の v1 が実際に出すか受ける値です。
メッセージの fixture は、送る byte 列の後に改行を 1 つ付けたファイルです。
読む側は末尾の改行を 1 つだけ除いて比べます。
HTTP の本文の fixture は本文そのもので、Go の v1 の本文は改行で終わります。
`agent.json` の fixture はファイルの中身そのもので、末尾に改行を持ちません。
Go の試験は、Go の実装が fixture と同じ値を出すことと、fixture を受けて同じ意味に読むことを確かめます。
仕様と Go の v1 が黙って離れないようにするためです。

| fixture | 中身 | 照らす Go の試験 |
| --- | --- | --- |
| `testdata/spec/wire/` | `pubkey`、`state`、`heartbeat` のメッセージ、close の理由、版の交渉 | `proto`、`internal/agent`、`internal/vpsd/stream` の `spec_test.go` |
| `testdata/spec/join/` | 接続文字列の正と誤り、登録の要求と応答 | `internal/agent/enroll`、`internal/vpsd/agentapi` の `spec_test.go` |
| `testdata/spec/credentials/` | v1 の `agent.json` の写し (秘密は置き換え済み) | `internal/agent/credentials` の `spec_test.go` |
| `testdata/spec/control/` | 制御ソケットの `doctor` の応答と `agent doctor --json` | `internal/agent/controlapi` の `spec_test.go`、`cmd/wgft` の `spec_doctor_test.go` |
| `testdata/spec/config/` | dotenv の正と誤り、設定の値の検査、宛先の許可一覧、拒否の文言、起動ログの有効な設定の行 | `cmd/wgft` の `spec_config_test.go` |
| `testdata/spec/tunnel/` | 全体状態からのトンネルの設定、endpoint の解決、UAPI のピア、ルールから待ち受けへの写し、中継の時間 | `internal/agent/usermode`、`internal/dataplane/userspace/tunnel`、`internal/dataplane/userspace/relay` の `spec_test.go` |

fixture を書き換えるのは、Go の v1 の振る舞いを意図して変えたときだけです。
その場合は同じコミットでこの文書群も直します。

[設計仕様](../README.ja.md)
