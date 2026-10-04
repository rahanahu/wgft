<!-- docs-status: historical -->

# early-review: resource-guard

- プロキシ中継の予算取得前の処理を、公開ポートごとの accept ループで同期して行うようにした。
  接続ごとの goroutine は Admission Policy と Resource Guard を通過した後にだけ作る。
  停止時は判定中のソケットを閉じ、全対象へ停止を要求してから古いループの終了を待つ。
  同じポートの停止と再作成を繰り返しても予算取得前の処理が積み重ならないようにした。
  公開の接続数上限と拒否の判定順は変えない。
