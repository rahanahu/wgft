<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 28 です。

# 2026-09-18: compatibility

- エージェントと CLI を Windows と macOS でビルドできるようにした(2026-09-18):11a 節に OS ごとの既定の置き場所、Linux 以外では `server` を持たないこと、排他ロックの OS ごとの実装、実機では未確認であることを追記。
  版数の埋め込み先を `internal/vpsd` から OS に依存しない `internal/buildinfo` に移した
