<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 299-300 です。

# early-review: server-doctor

- `agent.rules_received` の世代番号の一致を、適用済み State の内容の一致と読めないようにした。
  wire と認証情報の保存形式は変えず、内容は常に UNKNOWN と明記する。
  既存の検査 ID と判定、世代の遅れに関する理由、ルールの総合判定は維持する。
  CLI と Web UI のルール別診断では検査の所見に、一覧では試していない範囲にこの限界を示す。
  `agent ls` の GEN も報告された番号と説明する。
  単体テストでは、番号が一致したときの所見、遅れたときの判定、一覧の制約の表示を確かめた。
  ラボのカーネルモードでは、実際に接続したエージェントの番号が一致しても `server doctor --json` の所見が内容を UNKNOWN と示すことを確かめた。
  未確認:エージェントの適用済み State の内容。
  現在の通信には内容を照合する証拠が無い。
