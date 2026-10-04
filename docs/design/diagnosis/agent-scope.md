#### 範囲外

agent doctor は手元の診断です。
遠隔の診断、--report、エージェント側から VPS の公開ポートを能動的に試す機能は未実装です。


遠隔の診断は含めません。
server がエージェントに診断を要求し、その結果を併せて示す形であり、必要かどうかの判断を `agent doctor` ができてからにすることは [10.2a 節](server-observations.md#102a-転送の診断-server-doctor)が既に定めています。
手元で見えるものが分かって初めて、server 側から要求すべき情報が決まるという理由も変わりません。

Web UI からの呼び出しと `--report` も含めません。
[10.2a 節](server-observations.md#102a-転送の診断-server-doctor)が定めた順序は `agent doctor`、Web UI、`--report`、遠隔の診断です。

エージェントの回線から VPS の WireGuard の UDP ポートとエージェント用 API のポートへ届くかどうかを、エージェント側から能動的に確かめる機能も含めません。
[10.2a 節](server-observations.md#102a-転送の診断-server-doctor)が「切り分けられない所見」として残した穴、つまり最終ハンドシェイクが無い原因を VPS の側からは 1 つに決められないという穴を埋める候補ではあります。
`--probe` に当たるものをエージェント側に置くかどうかは、`agent doctor` を実際に使ってから決める。

`agent doctor` は、エージェントの設定の全体を出所付きで印字する機能を持ちません。
`wgft server check` に当たるものをエージェント側に置くかどうかは、この節では決めない。
起動ログの先頭が有効な設定を出所付きで印字することは [11a 節](../security/configuration.md#11a-設定の渡し方)のとおりであり、そちらで足りるかどうかは実際に使ってから判断します。

#### 置き場所

`agent doctor` は `agent` の一群の下に置く。
`server doctor` が `server` の下にあるのと対称になり、[7a.11 節](../compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)が保つコマンドの構成 (`server`、`agent`、`rule`、`status`、`version` とその下位) にもそのまま収まる。
`agent` の一群は build tag を持たず (`cmd/wgft/agent.go`)、Windows と macOS のバイナリにも入ります。
実装は `cmd/wgft` の専用のファイルに置き、build tag を持たせない。

ただし [7a.11 節](../compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)のとおり、macOS のエージェントは暫定であり、v1.0 の保証に含まれない。
この節の記述のうち、macOS での挙動は設計の意図であって、実機で確かめた事実ではありません。
Windows の `agent doctor` は、稼働中と停止中の実行と `--json` を Windows 11 の実機で確かめ、[7a.11 節](../compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の保証に含めた(改訂の記録 2026-09-27)。
管理者の権限での実行は期待する結果を定めておらず、`control socket` が OK、終了コードが 0 になったことを観察しただけです。

`server doctor` の自宅側の確認が要る所見は、`wgft agent doctor` を案内します。

<a id="102d-web-ui-の診断の画面"></a>
### Web UI の診断の画面

[本文](../web-doctor.md#102d-web-ui-の診断の画面)

[診断](README.md)
