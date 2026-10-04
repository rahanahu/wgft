<!-- docs-status: deprecated -->

# テストの分類と実行の契機

[現在の文書](development/testing.md)

<details>
<summary>旧見出しへのリンク / Links to previous headings</summary>

- <a id="テストの分類と実行の契機"></a> [テストの分類と実行の契機](development/testing.md#テストの分類と実行の契機)
- <a id="類の定義"></a> [類の定義](development/testing.md#類の定義)
- <a id="壁時計で測る区間を使うテストの規範"></a> [壁時計で測る区間を使うテストの規範](development/testing.md#壁時計で測る区間を使うテストの規範)
- <a id="マージの前に流すテスト"></a> [マージの前に流すテスト](development/testing.md#マージの前に流すテスト)
- <a id="変更の契機と対象のパス"></a> [変更の契機と対象のパス](development/testing.md#変更の契機と対象のパス)
- <a id="ci-とラボの関係"></a> [CI とラボの関係](development/testing.md#ci-とラボの関係)
- <a id="ラボの一式を隔てる単位"></a> [ラボの一式を隔てる単位](development/testing.md#ラボの一式を隔てる単位)
- <a id="テストの一覧"></a> [テストの一覧](development/testing.md#テストの一覧)
- <a id="a-類-すべての-pr"></a> [A 類 (すべての PR)](development/testing.md#a-類-すべての-pr)
- <a id="ラボの一式の内訳"></a> [ラボの一式の内訳](development/testing.md#ラボの一式の内訳)
- <a id="b-類-関係する変更の関門"></a> [B 類 (関係する変更の関門)](development/testing.md#b-類-関係する変更の関門)
- <a id="c-類-段階の完了の関門"></a> [C 類 (段階の完了の関門)](development/testing.md#c-類-段階の完了の関門)
- <a id="d-類-リリース候補の関門"></a> [D 類 (リリース候補の関門)](development/testing.md#d-類-リリース候補の関門)
- <a id="e-類-手作業と実機の関門"></a> [E 類 (手作業と実機の関門)](development/testing.md#e-類-手作業と実機の関門)
- <a id="f-類-調査だけの実験"></a> [F 類 (調査だけの実験)](development/testing.md#f-類-調査だけの実験)
- <a id="v1-の項目と繰り返しの頻度"></a> [v1 の項目と繰り返しの頻度](development/testing.md#v1-の項目と繰り返しの頻度)
- <a id="更新と戻しの約束"></a> [更新と戻しの約束](development/testing.md#更新と戻しの約束)
- <a id="新設と自動化が未了の項目"></a> [新設と自動化が未了の項目](development/testing.md#新設と自動化が未了の項目)
- <a id="b7-の-not_active-の確認"></a> [B7 の not_active の確認](development/testing.md#b7-の-not_active-の確認)
- <a id="c1-悪い条件のネットワーク"></a> [C1 悪い条件のネットワーク](development/testing.md#c1-悪い条件のネットワーク)
- <a id="c2-クラッシュと強制停止からの収束"></a> [C2 クラッシュと強制停止からの収束](development/testing.md#c2-クラッシュと強制停止からの収束)
- <a id="c3-規模の試験"></a> [C3 規模の試験](development/testing.md#c3-規模の試験)
- <a id="c4-ラボの一式を別のディストリビューションで"></a> [C4 ラボの一式を別のディストリビューションで](development/testing.md#c4-ラボの一式を別のディストリビューションで)
- <a id="c5-長時間の-tcp-と-udp"></a> [C5 長時間の TCP と UDP](development/testing.md#c5-長時間の-tcp-と-udp)
- <a id="c6-小さいメモリの環境"></a> [C6 小さいメモリの環境](development/testing.md#c6-小さいメモリの環境)
- <a id="d1-と-d2windows-と-macos-のエージェントの-smoke"></a> [D1 と D2:Windows と macOS のエージェントの smoke](development/testing.md#d1-と-d2windows-と-macos-のエージェントの-smoke)
- <a id="d4-の残りの項目-実装済み"></a> [D4 の残りの項目 (実装済み)](development/testing.md#d4-の残りの項目-実装済み)
- <a id="f1-conntrack-のメモリの費用の実測"></a> [F1 conntrack のメモリの費用の実測](development/testing.md#f1-conntrack-のメモリの費用の実測)
- <a id="e-類の手作業の確認"></a> [E 類の手作業の確認](development/testing.md#e-類の手作業の確認)
- <a id="windows-と-macos-のエージェント"></a> [Windows と macOS のエージェント](development/testing.md#windows-と-macos-のエージェント)
- <a id="windows-のエージェントの-smoke-の内容"></a> [Windows のエージェントの smoke の内容](development/testing.md#windows-のエージェントの-smoke-の内容)
- <a id="macos-のエージェントの-smoke-の内容"></a> [macOS のエージェントの smoke の内容](development/testing.md#macos-のエージェントの-smoke-の内容)
- <a id="実機の確認を小さな回帰テストに置き換えた範囲"></a> [実機の確認を小さな回帰テストに置き換えた範囲](development/testing.md#実機の確認を小さな回帰テストに置き換えた範囲)
- <a id="高価な実験を小さな回帰テストへ置き換える規則"></a> [高価な実験を小さな回帰テストへ置き換える規則](development/testing.md#高価な実験を小さな回帰テストへ置き換える規則)

</details>
