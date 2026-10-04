# Linux のソケットのバッファ

Linux のユーザー空間モードでは、WireGuard の UDP ソケットに受信と送信でそれぞれ 7 MiB のバッファが必要です。
対象は Linux の agent と、ユーザー空間モードの server です。
カーネルモードにはこの条件はありません。

Linux は権限のないプロセスが要求するサイズを `net.core.rmem_max` と `net.core.wmem_max` で制限します。
ホスト上で両方を 7340032 以上に設定します。

```sh
printf 'net.core.rmem_max = 7340032\nnet.core.wmem_max = 7340032\n' | sudo tee /etc/sysctl.d/90-wgft.conf
sudo sysctl --system
```

設定後に agent または server を再起動してください。
ソケットのサイズは開いた時点で決まります。
wgft は Linux が報告する値を確かめるため、受信と送信の両方が 14680064 バイト以上なら条件を満たします。

systemd の agent は、agent と同じ利用者で診断します。

```sh
sudo runuser -u wgft -- wgft agent doctor
```

`Tunnel` の `socket buffers` が `OK` なら設定は完了です。
`FAILED` でも agent は転送を続けますが、ログに `warning: the WireGuard UDP sockets` が出ます。
Windows と macOS ではバッファを測らず、`agent doctor` は `NOT TESTED` と表示します。

## コンテナで使う場合

Docker、LXC、Incus の非特権コンテナでは、**コンテナのホスト**で sysctl を設定します。
コンテナ内の root や `docker run --sysctl` では、この値を変更できません。
ホストの設定後、Docker の agent コンテナは再起動し、次で確認します。

```sh
docker compose -f deploy/agent.compose.yaml exec wgft-agent wgft agent doctor
```

LXC または Incus の agent は、コンテナ内で `systemctl restart wgft-agent` を実行してから、上記の `agent doctor` を実行します。
コンテナ内の `sysctl` の表示はカーネルによって異なるため、ソケットの実測値で判断してください。
server コンテナでは `docker compose -f deploy/server.compose.yaml logs` を読み、警告が消えたことを確かめます。

## server の注意点

付属の systemd unit で VM または専用ホスト上の server を動かす場合は、`CAP_NET_ADMIN` によって WireGuard のバッファを sysctl の上限を超えて確保できます。
コンテナ内と LXC ベースの VPS では、その権限だけではホストの上限を超えられません。
LXC ベースの VPS の server が条件を満たせるかどうかは未確認です。
server 自身が記録する警告を確認してください。

ユーザー空間モードの server は、公開する UDP ポートにも別の送信バッファを要求します。
`warning: the public UDP socket` が出る場合も、ホストの `net.core.wmem_max` を上げます。
このソケットでは `CAP_NET_ADMIN` だけでは警告を防げません。

検証した環境と仕組みは[設計文書](../design/agent-dataplane.md)にあります。
