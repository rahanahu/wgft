# 環境別の導入

VPS と自宅側の agent で、それぞれ使う環境の手順を選びます。
どの組み合わせでも、最後に[転送ルールを追加](setup.ja.md#4-転送ルールを追加する)します。

| 使う場所 | 環境 | 手順 |
|---|---|---|
| VPS | Linux、root 権限あり | [systemd の基本手順](setup.ja.md#2-vps-の-server-を-systemd-で常駐させる) |
| VPS | root 権限なし、またはカーネル WireGuard なし | [ユーザー空間モード](setup-server-userspace.ja.md) |
| VPS | Docker | [Docker の server](setup-docker.ja.md#vps-の-server) |
| 自宅側 | Linux、systemd | [systemd の基本手順](setup.ja.md#3-linux-のエージェントを-systemd-で常駐させる) |
| 自宅側 | Linux、カーネルモード | [カーネルモードの agent](agent-kernel.ja.md) |
| 自宅側 | Windows または macOS | [デスクトップの agent](setup-desktop.ja.md) |
| 自宅側 | Docker | [Docker の agent](setup-docker.ja.md#自宅側の-agent) |

## 接続文字列の発行

- systemd の VPS: [Web UI または CLI](setup.ja.md#接続文字列を発行する)
- root 権限のない VPS: [ユーザー空間モードの CLI](setup-server-userspace.ja.md#root-権限なしで起動する)
- Docker の VPS: [コンテナ内の CLI](setup-docker.ja.md#vps-の-server)

## Linux の agent を前面で試す

[バイナリをダウンロード](setup.ja.md#1-バイナリをインストールする)して次を実行します。
arm64 では、以下のファイル名も `amd64` から `arm64` に置き換えてください。

```sh
chmod +x wgft-linux-amd64
mkdir -p ~/.local/bin ~/.wgft
mv wgft-linux-amd64 ~/.local/bin/wgft
WGFT_JOIN='<join string>' ~/.local/bin/wgft agent run --data-dir ~/.wgft
```

発行した接続文字列を `<join string>` に入れます。
初回登録後は `wgft agent run --data-dir ~/.wgft` で起動できます。
