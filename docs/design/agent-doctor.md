<!-- docs-status: deprecated -->

# agent doctor

agent doctor は、エージェントのホストで、停止中も読める状態と稼働中の制御ソケットの証拠を診断します。
server 無しでも、読めた範囲で判定します。

現行の各仕様は[agent doctorの索引](diagnosis/README.md)から参照できます。

<details>
<summary>旧見出しの参照先</summary>

- <a id="エージェント側の診断"></a> [エージェント側の診断](diagnosis/agent-evidence.md#エージェント側の診断)
- <a id="102c-エージェント側の診断-wgft-agent-doctor"></a> [102c-エージェント側の診断-wgft-agent-doctor](diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor)
- <a id="この節が固定する範囲"></a> [この節が固定する範囲](diagnosis/agent-evidence.md#この節が固定する範囲)
- <a id="2-つのコマンドの境目"></a> [2-つのコマンドの境目](diagnosis/agent-evidence.md#2-つのコマンドの境目)
- <a id="2-つの証拠の出どころ"></a> [2-つの証拠の出どころ](diagnosis/agent-evidence.md#2-つの証拠の出どころ)
- <a id="証拠の鮮度の違い"></a> [証拠の鮮度の違い](diagnosis/agent-evidence.md#証拠の鮮度の違い)
- <a id="検査の一覧と証拠の出どころ"></a> [検査の一覧と証拠の出どころ](diagnosis/agent-evidence.md#検査の一覧と証拠の出どころ)
- <a id="示す値の定め方"></a> [示す値の定め方](diagnosis/agent-evidence.md#示す値の定め方)
- <a id="判定できない場合と手前の失敗で試せない場合"></a> [判定できない場合と手前の失敗で試せない場合](diagnosis/agent-evidence.md#判定できない場合と手前の失敗で試せない場合)
- <a id="宛先の許可一覧の扱い"></a> [宛先の許可一覧の扱い](diagnosis/agent-evidence.md#宛先の許可一覧の扱い)
- <a id="能動的に試す範囲"></a> [能動的に試す範囲](diagnosis/agent-evidence.md#能動的に試す範囲)
- <a id="総合判定を動かす検査"></a> [総合判定を動かす検査](diagnosis/agent-judgment.md#総合判定を動かす検査)
- <a id="relaylisteners-の粒度"></a> [relaylisteners-の粒度](diagnosis/agent-judgment.md#relaylisteners-の粒度)
- <a id="tunnellocal-の判定"></a> [tunnellocal-の判定](diagnosis/agent-judgment.md#tunnellocal-の判定)
- <a id="個別の理由で動かさない検査"></a> [個別の理由で動かさない検査](diagnosis/agent-judgment.md#個別の理由で動かさない検査)
- <a id="出力の形"></a> [出力の形](diagnosis/agent-output.md#出力の形)
- <a id="機械向けの出力"></a> [機械向けの出力](diagnosis/agent-output.md#機械向けの出力)
- <a id="終了コード"></a> [終了コード](diagnosis/agent-output.md#終了コード)
- <a id="制御ソケットの拡張"></a> [制御ソケットの拡張](diagnosis/agent-control.md#制御ソケットの拡張)
- <a id="制御ソケットから実行時の状態を取れない場合"></a> [制御ソケットから実行時の状態を取れない場合](diagnosis/agent-control.md#制御ソケットから実行時の状態を取れない場合)
- <a id="カーネルモードのエージェント"></a> [カーネルモードのエージェント](diagnosis/agent-kernel.md#カーネルモードのエージェント)
- <a id="カーネルモードの総合判定"></a> [カーネルモードの総合判定](diagnosis/agent-kernel.md#カーネルモードの総合判定)
- <a id="カーネルモードの証拠の読み方"></a> [カーネルモードの証拠の読み方](diagnosis/agent-kernel.md#カーネルモードの証拠の読み方)
- <a id="dataplaneinterface-の判定"></a> [dataplaneinterface-の判定](diagnosis/agent-kernel.md#dataplaneinterface-の判定)
- <a id="dataplanetable-の判定"></a> [dataplanetable-の判定](diagnosis/agent-kernel-table.md#dataplanetable-の判定)
- <a id="hostforwarding-の判定"></a> [hostforwarding-の判定](diagnosis/agent-kernel-host.md#hostforwarding-の判定)
- <a id="カーネルモードの-hostprivileges-と-root-の実行"></a> [カーネルモードの-hostprivileges-と-root-の実行](diagnosis/agent-kernel-host.md#カーネルモードの-hostprivileges-と-root-の実行)
- <a id="カーネルモードの制御ソケットの応答"></a> [カーネルモードの制御ソケットの応答](diagnosis/agent-kernel-host.md#カーネルモードの制御ソケットの応答)
- <a id="範囲外"></a> [範囲外](diagnosis/agent-scope.md#範囲外)
- <a id="置き場所"></a> [置き場所](diagnosis/agent-scope.md#置き場所)
- <a id="102d-web-ui-の診断の画面"></a> [102d-web-ui-の診断の画面](diagnosis/agent-scope.md#102d-web-ui-の診断の画面)

</details>
