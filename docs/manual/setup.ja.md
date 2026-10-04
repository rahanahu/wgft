# セットアップ

Linux の VPS と自宅側の Linux マシンに wgft をインストールし、systemd で常駐させます。
VPS はカーネルモード、agent は既定のユーザー空間モードを使います。
自宅ルータのポート開放は不要です。

Windows、macOS、Docker などを使う場合は、先に[環境別の導入](setup-alternatives.ja.md)から手順を選んでください。

## 動作環境

- VPS: Linux 6.1 以上、nftables 1.0.6 以上、root 権限。カーネルの WireGuard が必要です。
- エージェント: Linux。既定のユーザー空間モードでは root 権限と TUN デバイスは不要です。
- 通信: IPv4 のみ。VPS の firewall で UDP 51820、TCP 8443 と公開する転送ポートを許可します。

Linux の agent でソケットのバッファについて警告が出た場合は、[ホスト側の設定](socket-buffers.ja.md)を確認してください。

## 1. バイナリをインストールする

VPS と自宅側の Linux マシンで実行します。
最小構成の OS に `curl` がない場合は、先にインストールしてください。

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64.sha256
sha256sum -c wgft-linux-amd64.sha256
```

arm64 では、ダウンロードから以下のインストールまで、ファイル名の `amd64` を `arm64` に置き換えます。
VPS ではバイナリを配置します。

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
```

## 2. VPS の server を systemd で常駐させる

`vps.example.com` を VPS の公開名または IP アドレスに置き換えます。

```sh
sudo mkdir -p /etc/wgft
printf 'WGFT_MODE=kernel\nWGFT_WG_ENDPOINT=vps.example.com:51820\n' | sudo tee /etc/wgft/server.env
sudo chmod 0644 /etc/wgft/server.env
sudo wgft server check
```

`server check` は設定と firewall の不足を表示しますが、firewall は変更しません。
VPS の firewall で UDP 51820 と TCP 8443 を許可します。
ufw を使う場合の例です。

```sh
sudo ufw allow 51820/udp
sudo ufw allow 8443/tcp
```

systemd の unit は、インストールしたバイナリと同じリリースから取得します。

```sh
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/server.service"
sudo install -m 0644 server.service /etc/systemd/system/wgft.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgft
```

起動状態は `sudo systemctl status wgft` で確かめます。
firewalld の場合は `sudo firewall-cmd --permanent --add-port=51820/udp --add-port=8443/tcp` と `sudo firewall-cmd --reload` を実行します。

## 3. Linux のエージェントを systemd で常駐させる

### 接続文字列を発行する

手元のマシンから VPS へ SSH 転送を開きます。

```sh
ssh -L 8686:/run/wgft/admin.sock root@vps
```

`vps` を VPS の接続先に置き換え、ブラウザで `http://localhost:8686` を開きます。
「+ エージェントを追加」で `home` を指定し、「接続文字列を生成」を押します。
表示された接続文字列を控えます。
root で SSH ログインできない場合は[Web UI の接続方法](operations.ja.md#web-ui)を参照してください。

CLI なら VPS で `sudo wgft agent join-string --name home` を実行します。
接続文字列は秘密の値で、1 回だけ使用でき、1 時間で期限切れになります。

### agent の service を登録する

自宅側の Linux マシンで実行します。
`<join string>` は発行した接続文字列に置き換えてください。

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/agent.service"
sudo useradd --system --home-dir /var/lib/wgft --shell /usr/sbin/nologin wgft
sudo mkdir -p /etc/wgft
printf 'WGFT_JOIN=<join string>\n' | sudo tee /etc/wgft/agent.env >/dev/null
sudo chown root:wgft /etc/wgft/agent.env
sudo chmod 0640 /etc/wgft/agent.env
sudo install -m 0644 agent.service /etc/systemd/system/wgft-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgft-agent
```

登録後の認証情報は `/var/lib/wgft/agent.json` に保存されます。
Web UI のエージェント一覧か、VPS の `sudo wgft agent ls` で接続を確認します。

Linux のエージェントをカーネルモードで使う場合は、[カーネルモードのエージェント](agent-kernel.ja.md)を参照してください。

## 4. 転送ルールを追加する

接続文字列を発行した Web UI で「+ ルールを追加」を選びます。
エージェントに `home`、プロトコルに `UDP`、公開ポートに `2456-2457`、転送先に `192.168.1.20:2456` を指定します。
VPS の UDP 2456 と 2457 が、自宅の `192.168.1.20` の同じポートへ転送されます。

CLI なら VPS で次を実行します。

```sh
sudo wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game
sudo wgft rule ls
```

VPS の firewall でも UDP 2456 と 2457 を許可し、Web UI のルール一覧で状態を確認してください。
通信が届かない場合は `sudo wgft server doctor` を実行し、[ログと診断](operations.ja.md#ログと診断)を参照してください。
TCP、HTTPS、削除の手順は[運用ガイド](operations.ja.md)に、別の OS とモードの手順は[環境別の導入](setup-alternatives.ja.md)にあります。

[English](setup.md)
