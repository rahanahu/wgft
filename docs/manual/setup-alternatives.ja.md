# 環境別の導入

VPS と自宅側の agent で、それぞれ使う環境の手順を選びます。
VPS と Linux の agent には、カーネルモードを推奨します。
ユーザー空間モードは、カーネルモードを使えない環境のためのモードです。
転送の保証はカーネルモードより弱く、wgft のプロセスが止まると転送も止まります。
ユーザー空間モードの制約は[ユーザー空間の設計](../design/userspace/README.md)にあります。
どの組み合わせでも、最後に[転送ルールを追加](setup.ja.md#4-転送ルールを追加する)します。

| 使う場所 | 環境 | モード | 手順 |
|---|---|---|---|
| VPS | Linux、root 権限あり | カーネル: 推奨 | [systemd の基本手順](setup.ja.md#2-vps-の-server-を-systemd-で常駐させる) |
| VPS | root 権限なし、またはカーネル WireGuard なし | ユーザー空間 | [ユーザー空間モード](setup-server-userspace.ja.md) |
| VPS | Docker | ユーザー空間 | [Docker の server](setup-docker.ja.md#vps-の-server) |
| 自宅側 | Linux、systemd | カーネル: 推奨 | [systemd の基本手順](setup.ja.md#3-linux-のエージェントを-systemd-で常駐させる)。サービスを有効にする前に[カーネルモードの agent](agent-kernel.ja.md)の設定を加えます |
| 自宅側 | Linux、systemd | ユーザー空間 | [systemd の基本手順](setup.ja.md#3-linux-のエージェントを-systemd-で常駐させる) |
| 自宅側 | Windows または macOS | ユーザー空間 | [デスクトップの agent](setup-desktop.ja.md) |
| 自宅側 | Docker | ユーザー空間 | [Docker の agent](setup-docker.ja.md#自宅側の-agent) |

## 接続文字列の発行

- systemd の VPS: [Web UI または CLI](setup.ja.md#接続文字列を発行する)
- root 権限のない VPS: [ユーザー空間モードの CLI](setup-server-userspace.ja.md#root-権限なしで起動する)
- Docker の VPS: [コンテナ内の CLI](setup-docker.ja.md#vps-の-server)

<a id="linux-の-agent-を前面で試す"></a>
## Linux の agent をフォアグラウンドで試す

[バイナリをダウンロード](setup.ja.md#1-バイナリをインストールする)し、次のコマンドを実行します。
arm64 では、以下のファイル名も `amd64` から `arm64` に置き換えてください。

```sh
chmod +x wgft-linux-amd64
mkdir -p ~/.local/bin ~/.wgft
mv wgft-linux-amd64 ~/.local/bin/wgft
WGFT_JOIN='<join string>' ~/.local/bin/wgft agent run --data-dir ~/.wgft
```

`<join string>` は発行した接続文字列に置き換えます。
初回登録後は `wgft agent run --data-dir ~/.wgft` で起動できます。

[English](setup-alternatives.md)
