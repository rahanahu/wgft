<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 19, 22 です。

# 2026-09-17: userspace

- ユーザー空間モードの仕様(2026-09-17):6.3 節を新設し、13 節の予定から外した。
  サーバ側トンネル(wireguard-go と netstack、`IpcSet` / `IpcGet`)、中継の向きの反転、Go でのレート制限、性質の違いを記述。
  プロセス内の 3 つの netstack を実 UDP で繋ぐ実験で、ピアの動的な足し引き、netstack 越しの dial の送信元が `10.200.0.1` の一時ポートになること、3,000 バイトの UDP の往復を確認した。
  ピア追加前の握手は捨てられ再送が 5 秒後になることも同じ実験で分かり、5.2 節の順で吸収する

- ユーザー空間モードの実装に伴う追随(2026-09-17):5.3 節の `vps_mode` の意味、9 節の停止時の扱い、10.3 節の入れ方(systemd ならカーネル、Docker ならユーザー空間)、11 節の公開面を 6.3 節に合わせた
