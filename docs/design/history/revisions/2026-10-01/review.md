<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 326-327, 340-341, 344-345, 346-347 です。

# 2026-10-01: review

- 独立レビューを受け、前項の文書の言い回しを改めた(2026-10-01、5.2・7・11 節、所有者の決定。
  コードは変えていない):置き換えられて閉じる途中の stream が持つメモリは、TLS を使わない `httptest` の上の使い捨てのテストで測り、1 本あたり約 1.1 MiB を約 5 秒(close のフレームの書き込みが詰まれば最長約 10 秒)保持することを確かめた。
  これはそのエージェントの恒久トークンの持ち主だけが引き起こせる保持点であり、件数の構造の上限(3072 本分、約 3.4 GiB)を持つが、直さずに 7 節の「上界の式に入れない」一覧へ所有者の決定として加え、後で直すことにした。
  1 つの IPv4 のアドレスの上限は 16 のまま変えないことにし、CGNAT の後ろの正規のエージェントを巻き込むという同じ理由を 11 節に 1 文加えた。
  11 節の「stream は恒久トークンの確認を通った時点でどの数からも外れる」は、確認の後もエージェントごとの確立前の数に入ることと合わなかったため、確立前の数に入ったところで未認証の数から外れると書き直し、この数に入れられなかった 3 本目が未認証の数に残ったまま閉じることを加えた。
  11 節の「認証を通っていない接続が枠を持つのは最長 15 秒である」は読みの期限の和であり、ハンドラの処理と応答後の `closeWriteAndWait` の最長 500 ミリ秒の待ちを含まないことを書き足した。
  7 節の「既定の上限はメモリが 6 GiB のホストに収まる」は、表の式で計算し直すと約 5.9 GiB で余裕がほとんど無いため、6 GiB という言い方をやめた。
  5.2 節の「今の `pubkey`」は「現在の `pubkey`」に直した。


- サーバのデータベースの meta 表のキーを `internal/vpsd/store` の定数にまとめた(2026-10-01、7a.2 節。
  挙動は変えていない):meta 表のキーは、`internal/vpsd` の `mode.go`、`teardown.go`、`vpsd.go` と、`internal/vpsd/agentapi`、`internal/vpsd/store` のそれぞれが非公開の定数として持っていた。
  同じ表を読み書きする `server check` と `server teardown` は、`internal/vpsd` の中にあることでこの定数を共有していた。
  キーと、`mode` のキーに記録する転送方式の値 `ModeKernel`/`ModeUserspace` を `internal/vpsd/store` の `meta.go` に移し、7a.2 節が述べる転送方式の語彙の置き場所を直した。
  キーの文字列は変えていないので、既存のデータベースの記録はそのまま読める。
  単体テスト `TestMetaKeysKeepTheirStoredNames` が各キーの文字列を固定する。


- `server teardown` を `internal/vpsd/teardown` に移した(2026-10-01、7a.7 節。
  挙動は変えていない):`server teardown` の実装は `internal/vpsd` の `teardown.go` にあり、`Daemon` に依存していなかった。
  起動時に撤去の手掛かりを記録する関数だけを `internal/vpsd` の `Run` が呼んでいた。
  meta 表のキーは `internal/vpsd/store` の定数になっている。
  実装と手掛かりの記録を下位の package `internal/vpsd/teardown` に移し、記録の関数は `teardown.RecordHints` として公開した。
  `Run` は記録を同じ時点で呼ぶ。
  build tag `lab` の撤去のテストも同じ package に移したので、`docs/development/testing.md` の B2 の対象と `kernel` の契機のパスを新しい package に合わせた。
  7a.7 節の配置の木にこの package を加えた。
  `TestVpsdTeardownImportsOnlyTheStore` が、この package が `internal/vpsd` の下位の package のうち `store` だけを import することを検査する。
  `server teardown` の出力と、起動時のログの文言は変えていない。


- `--admin-tailscale` の待ち受けを `internal/vpsd/tailnet` に移した(2026-10-01、7a.7 節。
  挙動は変えていない):tailnet のアドレスの検出、待ち受けのインタフェースへの縛り、接続元の検査、作り直しの見張りは、`internal/vpsd` の `vpsd.go` と `tailnet.go` にあり、`Daemon` に依存していなかった。
  これを下位の package `internal/vpsd/tailnet` に移し、`Daemon` は管理用 API の応答と Host の許可の更新を関数の値として渡す。
  7a.7 節の配置の木にこの package を加えた。
  `TestVpsdTailnetImportsNoServerPackage` が、この package が `internal/vpsd` のどの package も import しないことを検査する。
  ログの文言と、待ち受けを開く順序は変えていない。
