# VPS をユーザー空間モードで動かす

root やカーネル WireGuard が使えない VPS では、推奨のカーネルモードの代わりにユーザー空間モードを使います。
転送は `wgft server` が行うため、プロセスが止まると転送も止まります。
VPS の firewall では、WireGuard の UDP 51820、agent API の TCP 8443 と、すべての転送ポートを許可してください。

フロー数の上限が既定値のとき、agent が 1 つで TCP の転送ポートが 1 つでも、約 12.7 GiB のホストメモリが必要です。
この値は設計文書に記載した最悪値の見積もりです。
この見積もりは、計算に数えたフローの状態やバッファなどが、攻撃によってそれぞれの上限まで同時に埋まった場合を想定しています。
この値は通常時の使用量の予想ではありません。
フロー数の上限を下げても、必要なメモリは約 3.2 GiB より小さくなりません。
内訳は[設計文書](../design/agent-dataplane.md)にあります。

ユーザー空間モードは、メモリの使用量が最悪値の見積もりを超えないことを保証しません。
netstack の TCP の接続のうち ACK を待つデータの多い接続に、相手がデータを含まない ACK を送り続けると、メモリが見積もりを超えて増えることがあります。
この[既知の制限](../design/userspace/memory-limits.md#中身の無い-segment-の処理待ち)は設計文書にあります。
ユーザー空間モードの server では、公開側の利用者はホストのソケットに接続し、netstack と通信するのは agent だけです。
このため、増加を起こすには agent の WireGuard の鍵が要ります。
agent を信頼できない場合は、server をカーネルモードで動かしてください。

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

接続文字列は、VPS で `~/.local/bin/wgft agent join-string --name home --config ~/wgft/server.env` を実行して発行します。
エージェントは[基本手順の続き](setup.ja.md#3-linux-のエージェントを-systemd-で常駐させる)で登録します。
登録できたら、VPS で次のコマンドを実行して[転送ルール](setup.ja.md#4-転送ルールを追加する)を追加します。

```sh
~/.local/bin/wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game --config ~/wgft/server.env
```

VPS の firewall でも UDP 2456 と 2457 を許可してください。

[English](setup-server-userspace.md)
