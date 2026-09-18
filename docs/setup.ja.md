# セットアップ

この文書には、README から分離した詳細なインストール・運用手順をまとめています。

## 動作環境

VPS 側は Linux で動作します。自宅側の agent は Windows amd64 でも動作し、Windows 11 で実機確認済みです。macOS はまだ対応していません。実機での確認がまだ済んでいないためです。wgft は現在 IPv4 のみに対応しています。

自宅側のエージェントには root 権限も TUN デバイスも不要です。VPS 側の要件は動作モードで変わります。

| | カーネルモード `kernel` | ユーザー空間モード `userspace` |
|---|---|---|
| VPS の root 権限 | 必要 | 不要 |
| カーネル / nftables | Linux 6.1 以上、nftables 1.0.6 以上 | 不要 |
| 転送経路 | カーネル WireGuard + nftables DNAT | wireguard-go + ユーザー空間 netstack |
| wgft プロセス停止・クラッシュ時 | 設定済みの転送は継続 | 転送も停止 |
| レート制限の判定場所 | カーネル | wgft プロセス |
| `wgft server` のメモリ | 通常の DNAT ルールはほぼ一定。proxy モードの TCP は接続数に応じて増える | フロー数に応じて増え、同時フロー数の上限で抑える |

カーネルモードでは、wgft が WireGuard / nftables の実行時状態を作った後は、wgft プロセスがクラッシュまたは再起動しても、その状態がカーネルに残るため転送は継続します。一方、VPS 自体を再起動すると実行時状態は失われるため、wgft service が再び起動して状態を作り直す必要があります。通常運用では付属の systemd unit を有効にしておいてください。

VPS で root が使えるならカーネルモードを推奨します。ユーザー空間モードは、root が使えない環境、カーネルに WireGuard がない環境、コンテナだけで完結させたい場合向けです。

wgft がユーザー空間で中継するフローには同時数の上限があります。`vpsd` ではルールごと、接続元アドレスごと、プロセス全体の 3 段、agent では接続元アドレスを区別できないためルールごととプロセス全体の 2 段です。上限に達すると新しいフローだけを拒否し、既存のフローは切りません。通常のカーネル DNAT は `wgft server` のフロー上限を消費しませんが、自宅側 agent は中継を行うため上限の対象です。

プロセス全体の上限は `WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS` で設定し、既定値はそれぞれ 8192 と 2048 です。server と agent は別プロセスなので、必要ならそれぞれに設定してください。wgft はこの 2 つの値から Go ランタイムのメモリのソフト上限を計算し、起動時に表示します。開発用ラボでは、ユーザー空間モードの server で既定値の上限を埋め、さらに大量の通信を送ったときの最大 RSS は 208 MiB でした。`WGFT_MAX_UDP_FLOWS=2048` と `WGFT_MAX_TCP_FLOWS=1024` では同じ負荷を 150 MiB の cgroup 制限内で動かせました。実際の 256 MiB VPS ではまだ確認していません。systemd では、必要なら付属 unit のコメント例を使って `MemoryMax=` を起動時に表示されるソフト上限より大きい値に設定できます。

## 1. バイナリをインストールする

同じバイナリに server、agent、CLI が含まれています。

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64.sha256
sha256sum -c wgft-linux-amd64.sha256
```

arm64 環境では `amd64` を `arm64` に置き換えてください。

Go 1.26 以上があれば次でもインストールできます。

```sh
go install github.com/rahanahu/wgft/cmd/wgft@latest
```

## 2. VPS を設定する

wgft は `WGFT_*` 環境変数で設定します。systemd 構成では `/etc/wgft/server.env` を読み込みます。全設定項目は [deploy/server.env.example](../deploy/server.env.example) にあります。

### カーネルモード

バイナリを配置し、最小限の設定を作ります。

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
sudo mkdir -p /etc/wgft
printf 'WGFT_MODE=kernel\nWGFT_WG_ENDPOINT=vps.example.com:51820\n' | sudo tee /etc/wgft/server.env
sudo chmod 0644 /etc/wgft/server.env
```

初回起動前に設定を確認します。

```sh
sudo wgft server check
```

`check` は、有効な設定、同じ server key を持つ WireGuard インタフェースの残骸、既存 firewall に必要な forwarding 許可を表示します。

wgft は既存の firewall 設定を変更しません。カーネルモードでは IPv4 forwarding が必要なため、必要に応じて `net.ipv4.ip_forward=1` を有効にします。`wgft server teardown` は、元に戻す必要がある設定も表示します。

WireGuard 用の UDP 51820 と agent API 用の TCP 8443 を開けます。ufw の例:

```sh
sudo ufw allow 51820/udp
sudo ufw allow 8443/tcp
```

firewalld の例:

```sh
sudo firewall-cmd --permanent --add-port=51820/udp --add-port=8443/tcp
sudo firewall-cmd --reload
```

付属の systemd unit を使う場合:

```sh
sudo install -m 0644 deploy/server.service /etc/systemd/system/wgft.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgft
```

`/etc/wgft/server.env` は秘密情報を含まず、付属の service は非特権の動的ユーザーで動作するため、意図的に 0644 にします。旧版のセットアップ手順でインストールした環境では 0600 のままになっている場合があるため、service の起動・再起動前に `sudo chmod 0644 /etc/wgft/server.env` を実行してください。root で動作する旧 unit から移行する場合も同様です。

手動で試す場合:

```sh
sudo wgft server run
```

### systemd でユーザー空間モードを使う

カーネルモードと同じ unit を使い、モードだけ変更します。

```sh
printf 'WGFT_MODE=userspace\nWGFT_WG_ENDPOINT=vps.example.com:51820\n' | sudo tee /etc/wgft/server.env
```

UDP 51820、TCP 8443、および転送する各ポートを VPS の firewall で開けてください。ユーザー空間モードでは `wgft server` が停止すると転送も停止します。

### root なしでユーザー空間モードを使う

設定とデータをホームディレクトリに置きます。

```sh
install -d -m 0700 ~/wgft
printf 'WGFT_MODE=userspace\nWGFT_WG_ENDPOINT=vps.example.com:51820\nWGFT_DATA_DIR=%s/wgft\nWGFT_ADMIN=unix://%s/wgft/admin.sock\n' "$HOME" "$HOME" > ~/wgft/server.env
chmod 0600 ~/wgft/server.env
wgft server run --config ~/wgft/server.env
```

通常ユーザーでは 1024 未満のポートを直接 bind できません。この構成では、以降の `sudo` の代わりに `--config ~/wgft/server.env` を付けて CLI を実行します。

### Docker でユーザー空間モードを使う

server コンテナはユーザー空間モードで動きます。リポジトリを clone し、[deploy/server.compose.yaml](../deploy/server.compose.yaml) の `WGFT_WG_ENDPOINT` を設定して起動します。

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
# deploy/server.compose.yaml の WGFT_WG_ENDPOINT を編集
docker compose -f deploy/server.compose.yaml up -d
```

転送するポートは compose の `ports:` に列挙する必要があります。`network_mode: host` を使えば列挙は不要ですが、非特権コンテナでは 1024 未満のポートを bind できません。

コンテナ利用時の CLI は次の形で実行します。

```sh
docker compose -f deploy/server.compose.yaml exec wgft-server wgft ...
```

## 3. 自宅側エージェントを登録する

VPS で一度だけ使える join string を発行します。

```sh
sudo wgft agent join-string --name home
```

join string は 1 回だけ使用でき、1 時間で期限切れになります。`#` を含むため shell から渡す場合は引用符で囲んでください。

### バイナリとして起動する

```sh
chmod +x wgft-linux-amd64
mkdir -p ~/.local/bin ~/.wgft
mv wgft-linux-amd64 ~/.local/bin/wgft
WGFT_JOIN='<join string>' ~/.local/bin/wgft agent run --data-dir ~/.wgft
```

初回登録に成功すると `~/.wgft/agent.json` が作成されます。2 回目以降は次だけで起動できます。

```sh
wgft agent run --data-dir ~/.wgft
```

### Windows で agent を実行する

[Releases ページ](https://github.com/rahanahu/wgft/releases) から `wgft-windows-amd64.exe` を取得します。ファイルを保存したフォルダで PowerShell を開きます。例えば Downloads フォルダです。次を実行します。

```powershell
Rename-Item wgft-windows-amd64.exe wgft.exe
$env:WGFT_JOIN = '<join string>'
.\wgft.exe agent run
```

join string は `#` を含むため、PowerShell では単一引用符で囲みます。初回登録に成功すると `%ProgramData%\wgft\agent.json` が作成されます。既定のこの場所は管理者権限を必要としません。2 回目以降は次だけで起動できます。

```powershell
.\wgft.exe agent run
```

wireguard-go が UDP をすべてのインタフェースで待ち受けるため、初回起動時に Windows Defender Firewall が `wgft.exe` の受信を許可するかどうかのダイアログを出すことがあります。Windows 11 の実機で、このダイアログを許可してもキャンセルしても、WireGuard の鍵の再交換をまたいでトンネルと中継が動作し続けることを確認しました。agent は外向きの接続だけを使うためです。停止は Ctrl+C を押すか、コンソールのウィンドウを閉じます。次の起動では保存済みの認証情報を使って復帰します。

wgft は Windows のサービスもタスクスケジューラも通知領域への常駐も持ちません。`agent run` は起動した利用者の権限で動作し、ゲーミング PC の多くのゲームサーバーと同じ動き方です。ログオンのたびに自動で起動させるかどうかは利用者に任されています。スタートアップフォルダへの登録はその一例ですが、未確認です。

### systemd で起動する

付属の unit は非特権の `wgft` ユーザーで動きます。

```sh
sudo install -m 0755 ~/.local/bin/wgft /usr/local/bin/wgft
sudo useradd --system --home-dir /var/lib/wgft --shell /usr/sbin/nologin wgft
sudo mkdir -p /etc/wgft
printf 'WGFT_JOIN=<join string>\n' | sudo tee /etc/wgft/agent.env >/dev/null
sudo chown root:wgft /etc/wgft/agent.env
sudo chmod 0640 /etc/wgft/agent.env
sudo install -m 0644 deploy/agent.service /etc/systemd/system/wgft-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgft-agent
```

認証情報は `/var/lib/wgft/agent.json` に保存されます。

### Docker で起動する

[deploy/agent.compose.yaml](../deploy/agent.compose.yaml) の `WGFT_JOIN` を設定して起動します。

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
# deploy/agent.compose.yaml の WGFT_JOIN を編集
docker compose -f deploy/agent.compose.yaml up -d
```

コンテナから LAN 側の転送先に到達できない場合は、compose の `network_mode: host` を有効にしてください。

## 4. 転送ルールを追加する

まずエージェントの接続を確認します。

```sh
sudo wgft agent ls
```

UDP のゲームサーバを公開する例:

```sh
sudo wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game
```

ポート範囲を指定した場合、`--to` は転送先の先頭ポートを示します。この例では VPS の UDP 2456 は `192.168.1.20:2456` へ、UDP 2457 は `192.168.1.20:2457` へ転送されます。

TCP で実クライアント IP を PROXY protocol v2 として渡す例:

```sh
sudo wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol
```

転送対象のポートは VPS の firewall 側でも開けてください。

ルールを追加・変更しても、無関係な既存セッションは切断されません。接続元 allow/deny やレート制限は CLI から設定できます。詳しくは [cli.md](cli.md) を参照してください。

## Web UI

管理 API は既定で `/run/wgft/admin.sock` だけで待ち受け、VPS のネットワークには公開されません。SSH でローカルポートへ転送します。

```sh
ssh -L 8686:/run/wgft/admin.sock root@vps
```

SSH 接続中に `http://localhost:8686` を開いてください。

root で SSH ログインできない場合は、次を設定します。

```text
WGFT_ADMIN=127.0.0.1:8686
```

その場合は VPS の loopback listener へ転送します。

```sh
ssh -L 8686:127.0.0.1:8686 vps
```

Tailscale 経由で管理画面にアクセスする場合は `WGFT_ADMIN_TAILSCALE=true` を設定します。追加の Host 名は `WGFT_ADMIN_HOST` で指定できます。

## HTTPS を公開する

wgft 自身は TLS を終端しません。VPS の 443 と 80 を自宅のリバースプロキシへ転送し、証明書と認証はリバースプロキシ側で管理します。

Caddy では 443 に PROXY protocol を使うことで、アクセスログに実クライアント IP を残せます。

```sh
sudo wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol
sudo wgft rule add --agent home --tcp 80  --to 192.168.1.30:80
```

以下の listener wrapper を使うには Caddy 2.11 以上が必要です。

```text
{
    servers 192.168.1.30:443 {
        listener_wrappers {
            proxy_protocol {
                allow 192.168.1.30/32
            }
            tls
        }
    }
}

example.com {
    reverse_proxy 192.168.1.40:8080
}
```

`allow` には wgft agent が動いているホストのアドレスを指定します。Caddy から見た TCP peer はそのホストになるためです。

## 削除する

サービスを停止し、まず削除内容を確認します。

```sh
sudo systemctl disable --now wgft
sudo wgft server teardown --dry-run
```

wgft が管理する状態を削除する場合:

```sh
sudo wgft server teardown --purge --yes
```

`--purge` を付けなければ key と証明書は残るため、再起動後も同じ server identity を使えます。`--purge` を付けると server key、ルール、agent 登録も削除されるため、agent の再登録が必要です。

Docker の agent を認証情報ごと削除する場合:

```sh
docker compose -f deploy/agent.compose.yaml down -v
```

## コマンドリファレンス

`wgft <command> --help` には各コマンドの例があります。生成済みの完全な一覧は [cli.md](cli.md) にあります。