<!-- docs-status: historical -->

# 2026-09-19: admission-policy

- バッチの防御的コピーが空の接続元制限を nil に取り違える不具合を修正(2026-09-19、`ExpectedDigest` のラボ検証中に発見):`store.ApplyBatch` が mutate に渡す前のコピー(`cloneRules`)は、`append([]netip.Prefix(nil), p...)` の形で `SourceAllow`/`SourceDeny` を複製していたため、空だが nil でないリスト(`rule add` や Web UI が明示的に設定する)を nil に変えてしまうことが分かった。
  これにより、無関係なフィールドだけを変える他のバッチを経由するだけで保存内容が `"source_allow":[]` から `"source_allow":null` に静かに変わり、`proto.RulesDigest` がこれをハッシュに含むため、`ExpectedDigest` の照合(前項)が実際には変わっていないルールを食い違いと誤判定しうることをラボ(`lab/import-export.sh`)の CLI 往復で確認した。
  nil と空の区別を保つ複製に改めた。
  この項目自体は設計文書の決定事項の変更を伴わない実装の修正である
