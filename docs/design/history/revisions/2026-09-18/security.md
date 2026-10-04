<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 23 です。

# 2026-09-18: security

- サーバ証明書が変わったエージェントの復帰経路(2026-09-18、公開前レビューの指摘):`teardown --purge` のあとに立て直した `vpsd` に対し、エージェントはピンの不一致で再接続を続けるだけで、新しい `WGFT_JOIN` を与えても登録済みとして無視していた。
  5.1 節に、ピンの不一致を区別し、未使用でピンの違う `WGFT_JOIN` があるときだけ再登録する経路を追加。
  条件を満たさなければ停止せずに再接続を続ける
