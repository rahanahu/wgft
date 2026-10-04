<!-- docs-status: deprecated -->

# server doctor

server doctor は、server から見た転送の経路の失敗を診断します。
制御の劣化だけでは転送の故障と数えません。

現行の各仕様は[server doctorの索引](diagnosis/README.md)から参照できます。

<details>
<summary>旧見出しの参照先</summary>

- <a id="102a-転送の診断-server-doctor"></a> [102a-転送の診断-server-doctor](diagnosis/server-observations.md#102a-転送の診断-server-doctor)
- <a id="名前と置き場所"></a> [名前と置き場所](diagnosis/server-observations.md#名前と置き場所)
- <a id="両側の診断とこの版の範囲"></a> [両側の診断とこの版の範囲](diagnosis/server-observations.md#server-と手元の診断の責務)
- <a id="5-つの状態"></a> [5-つの状態](diagnosis/server-observations.md#5-つの状態)
- <a id="観測の古さ"></a> [観測の古さ](diagnosis/server-observations.md#観測の古さ)
- <a id="ルール集合の世代の遅れ"></a> [ルール集合の世代の遅れ](diagnosis/server-observations.md#ルール集合の世代の遅れ)
- <a id="udp-の応答の観測"></a> [udp-の応答の観測](diagnosis/server-observations.md#udp-の応答の観測)
- <a id="この-vps-の-ip_forward"></a> [この-vps-の-ip_forward](diagnosis/server-observations.md#この-vps-の-ip_forward)
- <a id="検査の一覧と証拠の出どころ"></a> [検査の一覧と証拠の出どころ](diagnosis/server-evidence.md#検査の一覧と証拠の出どころ)
- <a id="2-つの粒度"></a> [2-つの粒度](diagnosis/server-evidence.md#2-つの粒度)
- <a id="能動的に試す範囲"></a> [能動的に試す範囲](diagnosis/server-evidence.md#能動的に試す範囲)
- <a id="経路の上の検査と経路の外の検査"></a> [経路の上の検査と経路の外の検査](diagnosis/server-evidence.md#経路の上の検査と経路の外の検査)
- <a id="agentconnection-が測るもの"></a> [agentconnection-が測るもの](diagnosis/server-failures.md#agentconnection-が測るもの)
- <a id="degraded-の意味"></a> [degraded-の意味](diagnosis/server-failures.md#degraded-の意味)
- <a id="検査どうしの優先順位"></a> [検査どうしの優先順位](diagnosis/server-failures.md#検査どうしの優先順位)
- <a id="切り分けられない所見"></a> [切り分けられない所見](diagnosis/server-failures.md#切り分けられない所見)
- <a id="試していない範囲"></a> [試していない範囲](diagnosis/server-failures.md#試していない範囲)
- <a id="履歴"></a> [履歴](diagnosis/server-output.md#履歴)
- <a id="機械向けの出力"></a> [機械向けの出力](diagnosis/server-output.md#機械向けの出力)
- <a id="終了コード"></a> [終了コード](diagnosis/server-output.md#終了コード)
- <a id="--report-の設計上の約束"></a> [--report-の設計上の約束](proposals/diagnostic-report.md#--report-の設計上の約束)

</details>
