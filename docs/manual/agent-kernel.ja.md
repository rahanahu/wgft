# Linux エージェントのカーネルモード

Linux の agent をカーネルモードにすると、ホストの WireGuard と nftables が転送します。
agent のプロセスを再起動している間も、既に設定した転送は続きます。
Linux のカーネル WireGuard と `CAP_NET_ADMIN` が必要です。
Docker で動かす手順はありません。

エージェントが転送先へ接続してよい範囲は、ユーザー空間モードと同じく `WGFT_AGENT_ALLOW_TARGETS` で制限できます。
転送先には IPv4 の LAN アドレスを指定してください。
`127.0.0.1` のようなループバックアドレスは使えません。
エージェントのホスト自身にある UDP サービスは、そのホストの LAN アドレスで待ち受ける必要があります。
すべてのアドレスで待ち受ける UDP サービスでは、応答が転送したフローと一致せず、クライアントに届きません。

## systemd の設定

[Linux agent の基本手順](setup.ja.md#3-linux-のエージェントを-systemd-で常駐させる)の unit を使います。
付属の drop-in で agent に `CAP_NET_ADMIN` を加え、`agent.env` にモードを設定します。

```sh
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/agent.kernel.conf"
sudo install -D -m 0644 agent.kernel.conf /etc/systemd/system/wgft-agent.service.d/kernel.conf
printf 'WGFT_MODE=kernel\n' | sudo tee -a /etc/wgft/agent.env >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart wgft-agent
```

新規導入では、基本手順の `systemctl enable --now wgft-agent` より前に、上の restart 以外を実行します。
unit に `ProtectKernelTunables=` を追加しないでください。
agent が必要に応じて `net.ipv4.ip_forward` を 1 に変更できなくなります。

起動中の agent は、その利用者で診断します。

```sh
sudo runuser -u wgft -- wgft agent doctor
```

停止中も転送は続きますが、ルールの変更や外部の変更による nftables の欠落は修復されません。
停止中の状態を調べるときは `sudo wgft agent doctor` を実行します。
`nftables.conf` の `flush ruleset` は agent のテーブルを削除するため、agent の停止中に nftables を reload しないでください。

## ユーザー空間モードへ戻す

agent を止め、残っている WireGuard インタフェースと nftables のテーブルを削除してからモードを切り替えます。

```sh
sudo systemctl stop wgft-agent
sudo wgft agent teardown --dry-run
sudo wgft agent teardown
sudo sed -i '/^WGFT_MODE=/d' /etc/wgft/agent.env
sudo rm /etc/systemd/system/wgft-agent.service.d/kernel.conf
sudo systemctl daemon-reload
sudo systemctl start wgft-agent
```

`agent teardown` は登録情報と鍵を残します。
`ip_forward` は自動で元に戻しません。
変更が必要な場合は teardown の出力にコマンドが表示されます。
v1.1.x へ戻すときも、v1.2 以降のバイナリで teardown を済ませてから旧版を起動してください。

動作と未確認の環境の詳細は[設計文書の 7b 節](../design/agent-kernel.md)にあります。
