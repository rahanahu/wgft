<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 87 です。

# 2026-09-20: compatibility

- 旧版への戻しを互換性の保証から外す(2026-09-20、7a.6 節):維持する外部仕様の表の「既存のデータの置き場からの更新」に、更新の経路は保証し、旧版への戻しは保証に含めないことを明記した。
  戻しは各版で観測した挙動だけを記録し、戻す必要があるときは更新の前に取ったデータの置き場のバックアップから戻す。
  戻しを約束すると、SQLite のスキーマ、migration、知らないフィールドの保存、状態ファイル、wire protocol の変更が旧い版の読み方に永久に縛られるためである。
  リリース候補の試験(docs/development/testing.md の D4)も、更新だけを確かめ、戻しは挙動の記録にとどめる
