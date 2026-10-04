<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 342-343 です。

# 2026-10-01: operations

- `server check` を `internal/vpsd/servercheck` に移した(2026-10-01、7a.7 節。
  挙動は変えていない):`server check` の実装は `internal/vpsd` の `servercheck.go` にあり、`Daemon` に依存していなかった。
  共有していたのは、起動の設定 `Options`、meta 表のキー、起動時の同じ検査が使う自分の待ち受けポートの一覧だけであった。
  キーは `internal/vpsd/store` の定数になっている。
  実装を下位の package `internal/vpsd/servercheck` に移し、読む設定だけを持つ `servercheck.Options` を設けた。
  `cmd/wgft` が server の設定からこれを組む。
  自分の待ち受けポートの一覧は `servercheck.OwnPortTargets` として公開し、`internal/vpsd` の `Run` も起動時の検査に使う。
  7a.7 節の配置の木にこの package を加え、`internal/vpsd` の根に置くものと下位の package に置くものの分け方を書いた。
  `TestVpsdServerCheckImportsOnlyTheStore` が、この package が `internal/vpsd` の下位の package のうち `store` だけを import することを検査する。
  `server check` の出力と終了コード、起動時のログの文言は変えていない。
