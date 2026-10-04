<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 13 です。

# 2026-09-16: control-plane

- 設定の語彙と登録の名前(2026-09-16):データの置き場を `WGFT_DATA_DIR` / `--data-dir` と呼ぶ(旧 `WGFT_STATE_DIR`。
  利用者向けの呼び名を「認証情報」にしたため)。
  5.1 節の登録で名前を任意にし、登録の応答に確定した名前を含めてエージェントが状態ファイルに保存する形に変更。
  9 節のエージェントの状態ファイルの項目に `name` を追記。
  10.3 節を追随
