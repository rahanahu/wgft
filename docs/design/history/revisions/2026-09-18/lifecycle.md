<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 26 です。

# 2026-09-18: lifecycle

- conntrack の表の上限を `server check` で表示(2026-09-18):6.1 節に、`nf_conntrack_max` は `vpsd` が変えないこと、`server check` が件数と上限を表示して 65536 未満なら警告すること、レート制限で落としたフローは表を消費しないことを追記
