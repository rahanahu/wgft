# Linux エージェントのカーネルモード

Linux の agent には、カーネルモードを推奨します。
agent の既定はユーザー空間モードなので、以下の手順でカーネルモードを明示して選びます。
Linux の agent をカーネルモードにすると、ホストの WireGuard と nftables が転送します。
agent のプロセスを再起動している間も、既に設定した転送は続きます。
Linux のカーネル WireGuard と `CAP_NET_ADMIN` が必要です。
Docker で動かす手順はありません。

エージェントが転送先へ接続してよい範囲は、ユーザー空間モードと同じく `WGFT_AGENT_ALLOW_TARGETS` で制限できます。
転送先には IPv4 のアドレスを指定してください。

エージェントのホストで `127.0.0.1` だけで待ち受けるサービスも、`127.0.0.1:25565` のような転送先にできます。
カーネルモードがループバックの転送先へ転送するのは、エージェントのホストの `WGFT_AGENT_ALLOW_TARGETS` が `127.0.0.0/8` の中の項目でその転送先を名指すときだけです。
たとえば `WGFT_AGENT_ALLOW_TARGETS=127.0.0.1:25565` と書きます。
この一覧はほかの転送先も制限するので、ルールが使う LAN の転送先も一覧に加えてください。
ループバックのサービスは、アドレスとポートで 1 つずつ名指してください。
`127.0.0.0/8` のような項目では、乗っ取られた VPS がルールの転送先を、このホストのループバックで待ち受けるどのサービスにも向けられます。
ループバックの転送先へ転送するルールがある間、エージェントは `net.ipv4.conf.wgft0.route_localnet` を 1 にします。
ほかのインタフェースの値は変えず、この値は `wgft0` と一緒に消えます。
サービスから見た接続元は `127.0.0.1` ではなく、`10.200.0.1` のような VPS のトンネルアドレスです。

エージェントのホスト自身にある UDP サービスは、ルールの転送先のアドレスで待ち受ける必要があります。
転送先のアドレスは `127.0.0.1` か、そのホストの LAN アドレスです。
すべてのアドレスで待ち受ける UDP サービスでは、応答が転送したフローと一致せず、クライアントに届きません。

カーネルモードの agent は、カーネルモードの VPS の後ろのユーザー空間モードの agent が持つ既知の制限を受けません。
ユーザー空間モードでは、送り残しの多い TCP の接続に TCP のルールの公開側の利用者が中身の無い ACK を送り続けると、agent のメモリが増え続けることがあります。
詳細は[設計文書](../design/userspace/memory-limits.md#中身の無い-segment-の処理待ち)を参照してください。

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

[English](agent-kernel.md)
