<!-- docs-status: historical -->

# 2026-09-18: lifecycle

- conntrack の表の上限を `server check` で表示(2026-09-18):6.1 節に、`nf_conntrack_max` は `vpsd` が変えないこと、`server check` が件数と上限を表示して 65536 未満なら警告すること、レート制限で落としたフローは表を消費しないことを追記
