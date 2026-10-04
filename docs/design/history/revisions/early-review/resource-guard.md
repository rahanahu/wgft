<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 295-296 です。

# early-review: resource-guard

- プロキシ中継の予算取得前の処理を、公開ポートごとの accept ループで同期して行うようにした。
  接続ごとの goroutine は Admission Policy と Resource Guard を通過した後にだけ作る。
  停止時は判定中のソケットを閉じ、全対象へ停止を要求してから古いループの終了を待つ。
  同じポートの停止と再作成を繰り返しても予算取得前の処理が積み重ならないようにした。
  公開の接続数上限と拒否の判定順は変えない。
