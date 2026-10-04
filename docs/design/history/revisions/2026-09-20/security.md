<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 85, 96, 97, 98 です。

# 2026-09-20: security

- `proxyrelay` の拒否を RST で閉じる(2026-09-20、7a.10 節の Phase 6 移行手順 3):`internal/vpsd/proxyrelay` は、接続元制限と同時フロー数の上限による拒否を通常の `Close` で閉じており、6.3 節の「実ソケットでも拒否は `SetLinger(0)` の RST で閉じ」という記述と食い違っていた(改訂の記録 2026-09-20「Resource Guard の再設計を定める」で見つけた食い違いの 1 つ)。
  `internal/dataplane/userspace/relay` の `abortRefused`(実ソケットでは `SetLinger(0)` の後に `Close`)と同じ考え方を `proxyrelay` にも実装した。
  `relay` パッケージは並行する別の変更の対象だったため、依存を増やさずコードを写す形にした。
  ホストの単体テストで、拒んだ接続(接続元制限、同時フロー数の上限)がループバックで `ECONNRESET` を返すことと、成立して通常に終わる中継は変わらず `io.EOF` で終わることを確かめた。
  6.2 節に、この 2 つの拒否がどちらも accept の直後に `SetLinger(0)` の RST で閉じることを追記した。

- エージェント用 API の同時接続数に上限を設ける(2026-09-20、11 節、セキュリティ点検の指摘):登録と stream の待ち受けに ReadHeaderTimeout などの期限はあったが、同時に張れる接続の数には上限が無く、正常に見える接続を大量に張るだけの単純な DoS で塞ぎ得た。
  `golang.org/x/net/netutil.LimitListener`(既存の直接の依存。
  `internal/dataplane/userspace/tunnel` が icmp/ipv4 で使っている)で同時接続数を 4096 に抑えた。
  上限は数百台のエージェントの stream に十分な余裕を持たせた固定値で、11a 節の設定項目にはしない。
  単体テストで、上限ちょうどまでは接続が処理されること、上限を超えた接続は拒否や切断ではなく accept を待つだけで応答が来ないこと、待っている間も上限内の接続(stream に見立てた)は切れないこと、1 本閉じて枠が空けば待っていた接続がそのまま処理されることを確かめた

- TCP で開いた管理用 API に http.Server の期限を付ける(2026-09-20、11 節、セキュリティ点検の指摘):Unix ソケットと TCP のどちらの待ち受けも `(&http.Server{Handler: h}).Serve(ln)` で、期限が一切無かった。
  ヘッダや本文を送り終えない接続、応答を受け取らない keep-alive 接続が、ループバックの `--admin` や `--admin-tailscale` を塞ぎ得た。
  ln が Unix ソケットか TCP かで分け、TCP のときだけ ReadHeaderTimeout(10 秒)・ReadTimeout(30 秒)・WriteTimeout(30 秒)・IdleTimeout(120 秒)を付けた。
  管理用 API の応答はどれも束縛されている(バッチの本文、ルール一覧の書き出し、読み込みの確認)ため、WriteTimeout を付けても正常な応答を中断しない。
  単体テストで、TCP の待ち受けには 4 つの期限がすべて付き、Unix ソケットには付かないこと、ヘッダの途中で止まる接続が ReadHeaderTimeout で切れること、何もしない keep-alive 接続が IdleTimeout で切れることを確かめた

- CLI の管理用 API クライアントにタイムアウトを付ける(2026-09-20、10.2 節、セキュリティ点検の指摘):`admin.Client` は `http.DefaultClient` かソケット直結の `http.Client{}` を使い、どちらもタイムアウトが無かった。
  サーバが応答せずに止まると、`wgft rule ls` のようなコマンドが診断も出さずに永久に待ち続けた。
  既定のクライアントに 30 秒のタイムアウトを付け、`net.Error` かつ `Timeout()` なエラーは、アドレスと待った時間を添えた文言に置き換えた。
  CLI からの呼び出しはどれも束縛された応答(バッチの本文、ルール一覧、5 秒の dial 期限を持つ疎通確認)を待つだけなので、30 秒はどの正当な呼び出しも壊さない。
  テストで、既定のクライアント(TCP と Unix ソケットの両方)にタイムアウトが付くこと、`HTTP` を注入した呼び出し元はその設定のまま使われること、応答しないサーバに対して打ち切りのエラーが "did not respond" を含むことを確かめた
