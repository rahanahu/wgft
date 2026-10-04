<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 75, 99 です。

# 2026-09-20: web-ui

- 適用状態を admin API と Web UI に出す(2026-09-20、7a.3 節の実装):`GET /api/v1/rules` と `POST /api/v1/rules/batch` の応答に、`desired_generation`、`active_generation`、ルールごとの `rule_states`、`drift`(`active_only`/`retiring`)、`apply_error` を加算的に加えた。
  既存のフィールドは変えず、報告を持たない Backend では新しいキーを出さない。
  Web UI のルール一覧と詳細は、server で公開できていないルールを「サーバーで未適用」「サーバーで反映待ち」として理由付きで示す。
  単体テストで、応答のフィールドと状態の欄の表示を確かめた。
  未確認:ラボで bind の失敗と nftables のトランザクションの失敗を起こしたときの応答と画面、CLI の表示(`rule ls` の表は変えていない)

- Web UI と管理用 API に防御的な応答ヘッダを付ける(2026-09-20、11 節、セキュリティ点検の指摘):応答には Host・Origin の検査だけがあり、`X-Content-Type-Options`、`X-Frame-Options`、`Referrer-Policy`、`Content-Security-Policy`、`Cache-Control` のいずれも付いていなかった。
  テンプレートを読み、`<script>`・`<style>` のインラインは無く、`style` 属性のインラインだけがあることを確かめたうえで、`ServeHTTP` の先頭で全応答に 4 つのヘッダを付け、`/static/` 以外には `Cache-Control: no-store` も付けるようにした。
  単体テストで、Web UI と JSON のどちらの応答にも 4 つのヘッダが付くこと、`/static/` は `no-store` を強制されないことを確かめた。
  `scripts/screenshot-ui.sh` で撮り直し、`docs/images/dashboard.png` の差分は表示中の経過時間の秒数だけで、ヘッダによる見た目の変化は無いことを確認した(コミットはしていない)
