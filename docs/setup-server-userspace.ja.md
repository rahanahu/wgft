# VPS をユーザー空間モードで動かす

root やカーネル WireGuard が使えない VPS では、ユーザー空間モードを使います。
転送は `wgft server` が行うため、プロセスが止まると転送も止まります。
VPS の firewall では、WireGuard の UDP 51820、agent API の TCP 8443 と、すべての転送ポートを許可してください。

既定のフロー数で攻撃時の最悪値に耐えるには、agent が 1 つ、TCP の転送ポートが 1 つでも約 7.1 GiB のホストメモリが必要です。
フロー数の上限を下げても約 4.1 GiB 未満にはなりません。
通常時の使用量ではなく、資源が同時に最大まで使われる場合の上界です。
内訳は[設計文書](design.md)にあります。
Linux の[ソケットのバッファ](socket-buffers.ja.md)も確認してください。

## systemd で常駐させる

[基本の VPS 手順](setup.ja.md#2-vps-の-server-を-systemd-で常駐させる)を使い、`/etc/wgft/server.env` のモードだけ `WGFT_MODE=userspace` にします。
付属の `server.service` は両モードで共通です。
VM または専用ホストでは、この unit が与える `CAP_NET_ADMIN` により WireGuard のソケットのバッファを確保できます。
LXC ベースの VPS ではホストの sysctl に依存し、条件を満たせるかは未確認です。
server のログに警告がないか確認してください。

## root 権限なしで起動する

[バイナリを取得して検証](setup.ja.md#1-バイナリをインストールする)し、設定とデータをホームディレクトリに置きます。
arm64 では、以下のファイル名も `amd64` から `arm64` に置き換えます。
`vps.example.com` を VPS の公開名または IP アドレスに置き換えてください。

```sh
mkdir -p ~/.local/bin
install -m 0755 wgft-linux-amd64 ~/.local/bin/wgft
install -d -m 0700 ~/wgft
printf 'WGFT_MODE=userspace\nWGFT_WG_ENDPOINT=vps.example.com:51820\nWGFT_DATA_DIR=%s/wgft\nWGFT_ADMIN=unix://%s/wgft/admin.sock\n' "$HOME" "$HOME" > ~/wgft/server.env
chmod 0600 ~/wgft/server.env
~/.local/bin/wgft server run --config ~/wgft/server.env
```

通常ユーザーでは 1024 未満のポートを直接待ち受けられません。
以降の CLI は `sudo` の代わりに `--config ~/wgft/server.env` を指定します。
ホストのソケットのバッファの上限が不足する場合、変更にはホストの root 権限が必要です。

接続文字列の発行は、VPS で `~/.local/bin/wgft agent join-string --name home --config ~/wgft/server.env` を実行します。
エージェントは[基本手順の続き](setup.ja.md#3-linux-のエージェントを-systemd-で常駐させる)で登録します。
登録できたら、VPS で次のコマンドを実行して[転送ルール](setup.ja.md#4-転送ルールを追加する)を追加します。

```sh
~/.local/bin/wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game --config ~/wgft/server.env
```

VPS の firewall でも UDP 2456 と 2457 を許可してください。
