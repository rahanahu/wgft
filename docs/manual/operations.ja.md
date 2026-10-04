# 転送と運用

最初の転送は[セットアップ](setup.ja.md)で追加できます。
通信が届かない場合は[診断手順](troubleshooting.ja.md)、導入済みの wgft を更新する場合は[更新手順](upgrade.ja.md)に従います。

## Web UI

管理 API は既定で VPS 内の `/run/wgft/admin.sock` だけで待ち受けます。
手元のマシンで SSH 転送を開き、`http://localhost:8686` を表示します。

```sh
ssh -L 8686:/run/wgft/admin.sock root@vps
```

root で SSH ログインできない場合は、VPS の `server.env` に `WGFT_ADMIN=127.0.0.1:8686` を設定し、server を再起動します。
その後は次の転送を使います。

```sh
ssh -L 8686:127.0.0.1:8686 vps
```

Tailscale 経由で管理する場合は `WGFT_ADMIN_TAILSCALE=true` を設定します。
server が Tailscale より先に起動して tailnet のアドレスがない場合は、server を再起動してください。

## TCP と HTTPS の転送

TCP で実際のクライアント IP を転送先へ渡すには、PROXY protocol v2 を使います。
転送先も PROXY protocol v2 に対応する必要があります。

```sh
sudo wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol
```

wgft は TLS を終端しません。
HTTPS の証明書と認証は、自宅側のリバースプロキシで管理します。
HTTP も転送する場合:

```sh
sudo wgft rule add --agent home --tcp 80 --to 192.168.1.30:80
```

Caddy 2.11 以上で 443 の実クライアント IP を受け取る場合は、次の listener wrapper を設定します。

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

`allow` には agent が動くホストの LAN アドレスを指定します。
Caddy から見た TCP peer は、そのホストになるためです。

VPS の firewall で公開するポートを許可してください。
Web UI の「+ ルールを追加」からも同じルールを作れます。
接続元の allow/deny とレート制限の設定は [CLI リファレンス](../cli.md)にあります。

## エージェントの転送先を制限する

server が配る任意の LAN 宛先へ接続させたくない場合は、agent の `WGFT_AGENT_ALLOW_TARGETS` を設定します。
systemd の場合は `/etc/wgft/agent.env` に、例えば次を追加します。

```text
WGFT_AGENT_ALLOW_TARGETS=192.168.1.20:25565,192.168.1.21:2456-2458
```

項目はコンマ区切りで、`CIDR`、`CIDR:ポート`、`CIDR:下限-上限` を指定できます。
IPv6 のアドレスにポートを付ける項目は `[2001:db8::/32]:8080` の形で囲みますが、転送自体は現在 IPv4 のみです。
設定を省くと宛先を制限しません。
許可されない転送先のルールは待ち受けを開かず、`wgft agent ls` と Web UI に理由が出ます。
この設定の有無にかかわらず、agent はどちらのモードでもブロードキャストとマルチキャストの転送先を拒みます。
対象は `255.255.255.255`、マルチキャストのアドレス、agent のホストのネットワークのブロードキャストのアドレスです。
たとえば `192.168.1.0/24` のネットワークでは `192.168.1.255` が当たります。
ブロードキャストのアドレスは agent のホストのインタフェースのネットワークから求めます。
末尾が `.255` であることだけでは判定しません。
`/31` のネットワークの両端のアドレスは通常のホストとして扱います。
ブロードキャストかマルチキャストの転送先を持つルールは転送せず、`wgft agent ls` に理由が出ます。
ルールを通してブロードキャストのアドレスへ Wake-on-LAN のパケットを送る使い方はサポートしません。
ユーザー空間モードでは、この拒否を入れる前はそのようなパケットが LAN に届いていた可能性があります。
今は届きません。
agent を Docker のブリッジネットワークのコンテナで動かす場合 (`deploy/agent.compose.yaml` の既定)、agent のホストのネットワークはコンテナ自身のネットワークです。
そのため、コンテナの中の agent は、自宅の LAN のブロードキャストのアドレスをブロードキャストのアドレスとしては拒みません。
設定を変更した後は `sudo systemctl restart wgft-agent` を実行します。

## ログと診断

付属の systemd unit はログを journald に保存します。

```sh
sudo journalctl -u wgft -b
sudo journalctl -u wgft-agent -f
sudo wgft server doctor
sudo runuser -u wgft -- wgft agent doctor
```

[診断手順](troubleshooting.ja.md)で、ルールごとの確認、結果と終了コードの意味、`startup hold`、ポートの競合、`ip-flapping` を確認します。
診断は外部からの接続や UDP の応答をすべて検査するものではないため、実際のサービスのクライアントでの確認も必要です。

## 削除

server を止め、削除する内容を先に確認します。

```sh
sudo systemctl disable --now wgft
sudo wgft server teardown --dry-run
```

`sudo wgft server teardown --purge --yes` は server の鍵、ルール、agent の登録も削除します。
これらを残す場合は `--purge` を付けません。
カーネルモードの agent は停止後もインタフェースと nftables のテーブルを残すため、認証情報を削除する前に[agent teardown](agent-kernel.ja.md#ユーザー空間モードへ戻す)を実行します。
Docker の agent を認証情報ごと削除する場合は `docker compose -f deploy/agent.compose.yaml down -v` を使います。
