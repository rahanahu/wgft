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

## 条件を満たさないときの転送の遅れ

条件を満たさないと、トンネルの通信が集中したときに WireGuard のソケットの受信のバッファが溢れ、Linux は入りきらないパケットを捨てます。
Linux はこの欠落を、同じ network namespace の他の UDP のソケットの欠落と合わせて `UdpRcvbufErrors` に数えます。
`nstat -az UdpRcvbufErrors` は、実行した network namespace の値を表示します。
この手順は、Linux のホストと、ラボの VM とその network namespace で確かめました。
自分の network namespace を持つコンテナでは、`sudo nsenter -t <pid> -n nstat -az UdpRcvbufErrors` がその namespace の値を読みます。
`<pid>` は、ホストから見た agent または server のプロセスの PID で、たとえば `docker inspect -f '{{.State.Pid}}' <container>` で得られます。
コンテナでのこの手順は未確認です。
この欠落でパケットを失った TCP の接続は、ユーザー空間モードが使う gVisor の TCP の回復の状態に入り、再送のタイマーが切れるたびに数個の segment しか送らなくなることがあります。
ラボでは、この状態で 1 MiB の HTTP のダウンロードに最長で約 1 分かかり、32 MiB の転送は 100 Mbit/s を超える速さではなく数 Mbit/s になりました。
この遅れは gVisor の TCP の送り手の制限であり、wgft はこれにパッチを当てません。
両方の sysctl を 7340032 にすると、ラボの通常の通信の確認では server でこの欠落が起きなくなり、遅い転送もまれになりました。
ラボの 40 回のうち 1 回では、server でこの欠落が無いまま遅い転送が起きました。
この 1 回の原因は未確認です。
設計の推論では、条件を満たすソケットでも、持続する過負荷では受信のバッファが溢れることがあります。
この溢れはラボでは観測していません。
この場合は[フロー数とメモリの設計](../design/userspace/flow-limits.md)で説明します。
回復の状態は[ユーザー空間モードの設計](../design/vps/userspace.md#63-ユーザー空間モード)に書いてあります。

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

[English](socket-buffers.md)
