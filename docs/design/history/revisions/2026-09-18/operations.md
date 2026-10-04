<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 27, 29, 36 です。

# 2026-09-18: operations

- systemd の unit を非 root とサンドボックスに変更(2026-09-18):10.3 節に、`DynamicUser=yes` と 2 つの capability で動かすこと、`ProtectKernelTunables` を付けない理由、旧い root の unit からの更新でデータが引き継がれることを追記し、11 節と 10.3 節のソケットの所有者の記述を追随させた。
  ラボの VM で実際の unit として起動し、カーネルモードの転送、プロキシ、旧い unit からの更新、撤去がサンドボックスの下でも動くことを確認した。
  compose には `cap_drop: [ALL]`、`no-new-privileges`、`read_only` を追加し、Docker でも登録と転送を確認した

- カーネルの WireGuard モジュールが無い環境での起動(2026-09-18):9 節に、`wireguard-tools` は要らないこと、モジュールが無ければ終了コード 3 で止まりユーザー空間モードへ案内することを追記。
  それまでは `operation not supported` とだけ出て終了コード 1 になり、unit が再起動を繰り返していた。
  ラボでモジュールをロード不可にして文言と終了コードを、`wg` コマンドを隠してカーネルモードの結合シナリオが通ることを確認

- 設定起因の起動失敗を終了コード 3 に統一(2026-09-18):設定ファイルの構文と値の誤り、必須の値の欠落、モードとアドレス帯の食い違いが再起動では回復しないことを確認し、systemd がこれらを再起動しない設計にした。
  SQLite やデータの置き場など実行時の障害は、従来どおり終了コード 1 とする。
  あわせて 11a 節の `WGFT_MODE` の記述を実装に合わせ、初回の起動だけ必須とした
