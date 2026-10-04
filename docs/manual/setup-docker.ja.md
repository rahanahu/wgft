# Docker で動かす

付属の compose ファイルは server と agent の両方をユーザー空間モードで動かします。
コンテナのホストで[ソケットのバッファ](socket-buffers.ja.md)を設定してください。
server には[最悪時のメモリ要件](setup-server-userspace.ja.md)もあります。

## VPS の server

リポジトリを取得し、[deploy/server.compose.yaml](../../deploy/server.compose.yaml) の `WGFT_WG_ENDPOINT` と公開するポートの `ports:` を編集します。

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
docker compose -f deploy/server.compose.yaml up -d
```

CLI は `docker compose -f deploy/server.compose.yaml exec wgft-server wgft ...` の形で実行します。
接続文字列は `docker compose -f deploy/server.compose.yaml exec wgft-server wgft agent join-string --name home` で発行します。
`network_mode: host` を使えば `ports:` の列挙は不要ですが、非特権コンテナでは 1024 未満のポートを待ち受けられません。

## 自宅側の agent

[deploy/agent.compose.yaml](../../deploy/agent.compose.yaml) の `WGFT_JOIN` に、VPS で発行した接続文字列を設定します。

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
docker compose -f deploy/agent.compose.yaml up -d
docker compose -f deploy/agent.compose.yaml exec wgft-agent wgft agent doctor
```

転送先の LAN アドレスへ届かない場合は、compose の `network_mode: host` を有効にします。
agent が接続したら、[転送ルールを追加](setup.ja.md#4-転送ルールを追加する)してください。
VPS で実行するコマンドは次のとおりです。

```sh
docker compose -f deploy/server.compose.yaml exec wgft-server wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game
```

VPS の firewall でも UDP 2456 と 2457 を許可してください。
別の公開ポートを使う場合は、VPS の compose ファイルの `ports:` も変更します。

[English](setup-docker.md)
