<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 205 です。

# 2026-09-23: security

- テストの listen_port の読み返しに production 側の公開メソッドを追加した(2026-09-23、テストのフレークという実害を受けた見直し):2026-09-21 の改訂の記録は、`Tunnel` に読み返しの手段が無いことを理由に、テストファイルを package utun の内側に置いて非公開の `dev` フィールドへ直接アクセスする形を採り、production 側の interface は変えないと決めていた。
  その後、固定範囲を順に走査して空きポートを選ぶテストヘルパーが、複数のテストプロセスを並行して走らせる場面で範囲の衝突によって実際に失敗する事例が見つかり、この判断を覆した。
  読み返しの手段を production 側に持たない限りテストは同じ走査に頼らざるを得ず、範囲を広げても衝突の芽は残るためである。
  `internal/dataplane/userspace/utun` の `Tunnel` に公開メソッド `ListenPort()` を追加し、`IpcGet` の出力から `listen_port` の行を読んで返す形にした。
  `Config.ListenPort` に 0 を渡して bind すると OS が実際の空きポートを選ぶので、テストはこの形で bind してから `ListenPort()` で実際の値を読み返す形に統一した。
