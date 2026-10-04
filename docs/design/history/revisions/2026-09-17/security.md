<!-- docs-status: historical -->

# 2026-09-17: security

- forward チェーンの取りこぼしを塞ぐ(2026-09-17、公開前レビューの指摘):6.1 節の forward に、DNAT 済みの accept の後で `iifname "wg0" drop` と `oifname "wg0" drop` を追加。
  それまでは wg0 から VPS の他のインタフェースへ出る新規フローが既存ファイアウォールの forward の policy 任せで、accept の VPS では盗んだ認証情報で VPS の内側へ片方向のパケットを送れた。
  5.1 節の「到達できる先がない」の根拠を追随

- 起動時の衝突検査と撤去の所有判定の穴を塞ぐ(2026-09-17、公開前レビューの指摘):9 節に、WireGuard 以外のプロセスが `--wg-port` を bind している場合の中止(インタフェースを作る前に検出)と、作った直後の失敗でインタフェースを消す扱いを追記。
  10.3 節の撤去に、空鍵は所有とみなさないこと、`--adopt-existing` でも WireGuard 以外のリンクは消さないことを追記
