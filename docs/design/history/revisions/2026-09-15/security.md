<!-- docs-status: historical -->

# 2026-09-15: security

- 管理 API の認証の見直し(2026-09-15):管理者パスワード(Basic 認証)を廃止し、管理用 API の既定を Unix ソケット(root 所有 0600)に変更。
  Tailscale の待ち受けを `--admin-tailscale` に、ループバック TCP は任意に。
  ブラウザ経路の守りを `Host` の検査と他オリジン発の変更の拒否に置き換え。
  理由と経緯は 11 節。
  3・4・5・5.3・10.3・11 節を改訂
