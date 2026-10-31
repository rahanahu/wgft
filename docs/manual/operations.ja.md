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
[カーネルモード](agent-kernel.ja.md)では、`127.0.0.1:25565` のようなループバックの転送先には、それを名指す `127.0.0.0/8` の中の項目が要ります。
`0.0.0.0/0` のような項目は名指しに数えません。
`127.0.0.0/8` の項目では乗っ取られた VPS がどのループバックのサービスにも届くので、`127.0.0.1:ポート` の項目を使ってください。
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

## 実験的な netstack を試す

ユーザー空間モードの agent は、トンネルから届く TCP と UDP をプロセスの中の netstack で終端します。
既定は gVisor の netstack です。
`WGFT_AGENT_NETSTACK=wgstack` を設定すると、代わりに wgft が持つ TCP/IP の実装の wgstack を使います。

```text
WGFT_AGENT_NETSTACK=wgstack
```

wgstack は実験的な選択肢です。
転送の品質と資源の挙動は互換性の保証に含まれず、wgstack で起動すると agent は警告の行を 1 つ出します。
省略と空の値は `gvisor` で、それ以外の値では agent は終了コード 3 で止まります。
カーネルモードは netstack を使わないので、設定を使わない旨を出して起動します。
設定を変えた後は `sudo systemctl restart wgft-agent` を実行します。

wgstack は CPU を減らすために、パケットをまとめて WireGuard に渡します。
`WGFT_AGENT_BATCH_MIB` は、まとめたパケットが暗号化と送信を待つ間に持てるメモリの上限で、単位は MiB です。

```text
WGFT_AGENT_BATCH_MIB=32
```

省略と空の値では `WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS` から導き、既定の上限の Linux と macOS では 54 MiB です。
バッファの小さい Windows では後述の上限の値で、CPU が 8 個なら約 73 MiB です。
`0` はまとめを使いません。
この値が抑えるのは、まとめた分だけです。
WireGuard の 1 件ずつのパケットのキューは値によらず別に持ち、CPU が 8 個の Linux で約 73 MiB です。
ホストの CPU の数で決まる上限を超える値は上限に丸め、agent は起動時に使う値をログに出します。
まとめを使うには、CPU の数の 4 倍に 20 を足した個数以上のバッファに当たる値が要ります。
Linux と macOS のバッファは 64 KiB なので、CPU が 2 個なら 1.75 MiB、8 個なら 3.25 MiB です。
この下限より小さい値では wgstack はパケットを 1 つずつ渡し、起動時のログにまとめを使わないことと理由を出します。
既定のフロー数の上限では、既定の値が下限より小さくなるのは CPU が約 210 個より多いホストだけです。
Windows では、トンネルの MTU が 1953 より大きい場合もまとめを使わず、agent はトンネルを立てる時にその旨をログに出します。
0 以上の整数でない値では、agent は終了コード 3 で止まります。
gVisor とカーネルモードでは設定を使わず、使わない旨を出して起動します。

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

[English](operations.md)
