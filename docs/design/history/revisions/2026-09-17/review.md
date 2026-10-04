<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 18 です。

# 2026-09-17: review

- `--admin-tailscale` の検出を tailscaled 優先に変更(2026-09-17):`100.64.0.0/10` は Tailscale 専用の帯ではなく、一部の VPS 事業者が内部網に使うため、アドレスだけで検出すると事業者の内部網に管理用 API が開き得る公開レビューの指摘を受けた。
  `tailscale status --json` の `Self` を第 1 の情報源にし、コマンドがない・失敗するときだけ、名前が `tailscale` で始まるインタフェースにフォールバックする。
  検出した MagicDNS 名を `Host` の許可リストへ自動で加え、`--admin-host` は追加の名前専用に改める。
  11 節を改訂
