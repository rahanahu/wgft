# セットアップ

この文書には、README から分離した詳細なインストール・運用手順をまとめています。

## 動作環境

VPS 側は Linux で動作します。自宅側の agent は Windows amd64 でも動作し、Windows 11 で実機確認済みです。Apple シリコンの macOS でも動作し、macOS 27 で実機確認済みです。Intel Mac には対応していません。wgft は現在 IPv4 のみに対応しています。

既定のユーザー空間モードでは、自宅側のエージェントには root 権限も TUN デバイスも不要です。ただし Linux では、ホストのソケットのバッファの上限を 2 つ上げる必要があります。詳しくは[ユーザー空間モードのソケットのバッファ](#ユーザー空間モードのソケットのバッファ)を参照してください。Linux のエージェントはカーネルモードでも動作し、カーネルモードには `CAP_NET_ADMIN` が必要です。詳しくは[カーネルモードで起動する](#カーネルモードで起動する)を参照してください。VPS 側の要件は動作モードで変わります。

| | カーネルモード `kernel` | ユーザー空間モード `userspace` |
|---|---|---|
| VPS の root 権限 | 必要 | 不要 |
| カーネル / nftables | Linux 6.1 以上、nftables 1.0.6 以上 | 不要 |
| ホストのソケットのバッファの上限 | 条件なし | `net.core.rmem_max` と `net.core.wmem_max` が 7340032 以上。VM か専用のホストで server が `CAP_NET_ADMIN` を持つ場合を除く。[ユーザー空間モードのソケットのバッファ](#ユーザー空間モードのソケットのバッファ)を参照 |
| 転送経路 | カーネル WireGuard + nftables DNAT | wireguard-go + ユーザー空間 netstack |
| wgft プロセス停止・クラッシュ時 | 設定済みの転送は継続 | 転送も停止 |
| レート制限の判定場所 | カーネル | wgft プロセス |
| `wgft server` のメモリ | 通常の DNAT ルールはほぼ一定。proxy モードの TCP は接続数に応じて増える | フロー数に応じて増える。同時フロー数の上限はフローの数を抑える |

カーネルモードでは、wgft が WireGuard / nftables の実行時状態を作った後は、wgft プロセスがクラッシュまたは再起動しても、その状態がカーネルに残るため転送は継続します。一方、VPS 自体を再起動すると実行時状態は失われるため、wgft service が再び起動して状態を作り直す必要があります。通常運用では付属の systemd unit を有効にしておいてください。

VPS で root が使えるならカーネルモードを推奨します。ユーザー空間モードは、root が使えない環境、カーネルに WireGuard がない環境、コンテナだけで完結させたい場合向けです。ただし、ユーザー空間モードに要るソケットのバッファの上限を上げるには、ホストかコンテナのホストで一度だけ root の権限が要ります。

ユーザー空間モードでは、`wgft server` 自身がルールの listen port で待ち受けます。この listen port がホストのエフェメラルポートの範囲(Linux の既定は 32768-60999、`net.ipv4.ip_local_port_range`)に入っていると、VPS 上のどのプロセスの外向きの接続でも、その番号を送信元ポートとして使っているあいだや、切断後 60 秒の TIME_WAIT のあいだは、server の bind と衝突します。衝突すると bind は失敗し、ルールは宣言に残ったまま not active として報告されます。理由は `bind failed: listen tcp4 :<port>: bind: address already in use` で、server のログには `rule <id>: not active: bind failed: ...` の行が出て、Web UI のルールの状態にも同じ理由が表示されます。`wgft rule ls --json` の `rule_states` にも同じ理由が入ります。`wgft server` は 30 秒ごとに適用をやり直すため、ポートが空けば自然に回復します。`SO_REUSEADDR` はこの衝突を防ぎません。カーネルモードでは VPS 上で公開ポートを待ち受けるプロセスが無いため、この問題は起きません。衝突を避けるには、listen port をエフェメラルポートの範囲外から選ぶか、`sysctl net.ipv4.ip_local_reserved_ports=<ports>` で予約してください。

カーネルモードでは、ルール集合をカーネルへ 1 つの nftables バッチとして適用します。wgft はこのバッチに合わせて netlink ソケットのバッファの大きさを調整します([design.md](design.md) の 6.1 節)。付属の systemd unit でカーネルモードを動かしたラボでは、1 回の `rule import` によるバッチでも 1 本ずつの `rule add` による追加でも、2000 本までのルール集合を適用できました。2000 本を超える規模は確かめていません。文書にあるカーネルモードの配置には、`net.core.rmem_max` と `net.core.wmem_max` で制限されるものがありません。付属の systemd unit は、この 2 つの sysctl の値を超えてバッファを要求するための権限を wgft に与えます。Docker の配置はユーザー空間モードだけを対象にしており、カーネルモードを対象にしていません。ユーザー空間モードには、WireGuard のソケットのために、同じ 2 つの sysctl についての別の条件があります。[ユーザー空間モードのソケットのバッファ](#ユーザー空間モードのソケットのバッファ)を参照してください。

カーネルモードは、ホストの conntrack の表にも依存します。`wgft server check` と起動時のログは、`nf_conntrack_max` が wgft の推奨する下限 65536 を下回っている場合に警告し、上げるための `sysctl -w net.netfilter.nf_conntrack_max=65536` を提示します。

フローには、ルールごと、接続元アドレスごと、プロセス全体の 3 段の同時数の上限があります。agent は接続元アドレスを区別できないため、ルールごととプロセス全体の 2 段だけを適用します。`wgft server` は、ユーザー空間モードでは 3 段とも Go で適用します。カーネルモードでは、DNAT ルールの通信は nftables が転送し、`wgft server` を経由しません。そのため、DNAT ルールには接続元アドレスごとの上限だけを nftables の `ct count` で適用します。proxy モードのルールの TCP 接続は、カーネルモードでも `wgft server` が終端します。そのため、proxy モードのルールにはユーザー空間モードと同じく 3 段とも適用します。上限に達すると新しいフローだけを拒否し、既存のフローは切りません。server がカーネルモードでも、ユーザー空間モードの agent は中継を行うため、agent の上限の対象です。カーネルモードの agent は中継を行わず、そのフローは自宅のホストの conntrack の表が保持します。

プロセス全体の上限は `WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS` で設定し、既定値はそれぞれ 8192 と 2048 です。server と agent は別プロセスなので、必要ならそれぞれに設定してください。wgft はこの 2 つの値から Go ランタイムのメモリのソフト上限を計算し、起動時に表示します。ソフト上限は Go のガベージコレクションの目標であり、プロセスのメモリの上限ではありません。開発用ラボでは、ユーザー空間モードの server で既定値の上限を埋め、さらに大量の通信を送ったときの最大 RSS は 208 MiB でした。`WGFT_MAX_UDP_FLOWS=2048` と `WGFT_MAX_TCP_FLOWS=1024` では同じ負荷を 150 MiB の cgroup 制限内で動かせました。208 MiB と 150 MiB は、上限を埋めて大量の通信を送った試験の負荷での値です。ユーザー空間モードで、攻撃ですべてのフローとバッファが同時に埋まった最悪の場合には、メモリの量は 208 MiB よりはるかに大きくなります。既定の上限では、agent が 1 つ、転送する TCP のポートが 1 つの server に、約 7.1 GiB のメモリを持つホストが要ります。上限を下げても、要るメモリは約 4.1 GiB より小さくなりません。内訳と、小さいホストに向けて上限を下げたときの表は、[design.md](design.md) の 7 節にあります。systemd では、必要なら付属 unit のコメント例を使って `MemoryMax=` を起動時に表示されるソフト上限より大きい値に設定できます。ソフト上限はメモリの上限ではないので、この設定だけで OOM を避けられるとは限りません。

1 つのルールが全体の容量を独占しないよう、wgft は内部で予算をルールに分けます。この分け方は設定項目ではありません。新しいフローを受け付けているルールが 1 本だけなら、そのルールはプロセス全体の上限から 4 本を除いた数まで保持できます。この 4 本は予備で、後から加わるルールがすぐに最初のフローを通せるように空けておくものです。2 本以上あるときは、ルールごとに最低分を保証し、1 本のルールはプロセス全体の上限の半分(切り上げ)を超えられません。最低分は、上限から予備の 4 本を除いた数の半分を他のルールの数で割った値で、4 を下回りません。既定の TCP の上限でルールが 2 本なら 1022 です。どのルールの最低分にも届かない分と予備を残した残りは先着順に共有するので、1 本のルールへのフラッドの最中も、他のルールは最低分まで新しいフローを通せます。接続元アドレスごとの上限は `wgft server` だけの設定項目で、`WGFT_MAX_UDP_FLOWS_PER_SOURCE`(既定 256)と `WGFT_MAX_TCP_FLOWS_PER_SOURCE`(既定 128)を全ルールの合計に対して適用し、1 つの接続元アドレスがルールの上限を埋めて他の利用者を締め出すことを防ぎます。プロセス全体の上限と連動しないため、メモリに余裕がありプロセス全体の上限を上げた運用者も、この設定を明示して上げない限り接続元ごとの上限は既定値のままです。0 にするとそのプロトコルの上限を無効にできます。agent にはこの設定項目がありません。agent から見た相手は server だけなので、どのフローも同じアドレスから来ているように見えるためです。

### ユーザー空間モードのソケットのバッファ

ユーザー空間モードは、WireGuard の UDP ソケットが 7 MiB の受信バッファと 7 MiB の送信バッファを得ることを動作条件とします。wireguard-go はソケットを開くときにこの大きさを要求します。条件は Linux のエージェントとユーザー空間モードの server に当てはまり、カーネルモードにはありません。Linux は、ホスト自身の user namespace で `CAP_NET_ADMIN` を持たないプロセスの要求を、`net.core.rmem_max` と `net.core.wmem_max` の値で切り詰めます。非特権のコンテナの中と LXC ベースの VPS のプロセスは、そこでどの権限を持っていても、この権限を持ちません。開発用ラボの Debian 12 のカーネルでは 2 つとも 212992、Fedora 44 では 4194304 で、どちらも条件に届きません。wgft はこの sysctl を書き換えません。

ホストで 2 つとも 7340032 以上に設定します。起動のたびに適用されるように、`/etc/sysctl.d` のファイルに書きます。

```sh
printf 'net.core.rmem_max = 7340032\nnet.core.wmem_max = 7340032\n' | sudo tee /etc/sysctl.d/90-wgft.conf
sudo sysctl --system
```

ソケットのバッファは開いたときに決まるので、設定の後にエージェントか server を再起動します。Linux は要求の 2 倍の値を報告するので、sysctl が 7340032 のとき、ソケットは 14680064 を報告します。wgft が確かめるのはこの報告の値です。実際の WireGuard のソケットの受信と送信がどちらも 14680064 バイト以上なら、条件を満たします。

エージェントとユーザー空間モードの server は、トンネルを立てるたびに自分の WireGuard のソケットを測ります。条件に届かなければ、`warning: the WireGuard UDP sockets` で始まる行をログに出します。エージェントのホストでは、稼働中のエージェントが測った値を `agent doctor` で確かめます。エージェントと同じ利用者で実行し、付属の unit では次のコマンドになります。

```sh
sudo runuser -u wgft -- wgft agent doctor
```

Tunnel の群の `socket buffers` の項目は、OK か、測った値と設定する値を添えた FAILED を示します。条件に届かないエージェントも転送は続けるので、この項目は終了コードを変えません。

VPS では、ユーザー空間モードの `sudo wgft server check` が、2 つの sysctl の値、`CAP_NET_ADMIN` を持たないソケットが得る値、条件の値を示します。`server check` は server の判定をしません。VM か専用のホストでは、付属の systemd の unit で起動した server は `CAP_NET_ADMIN` を持ち、sysctl の値を超えるバッファを得られるためです。コンテナの中と LXC ベースの VPS では、unit が与える権限はコンテナの中に限られ、上限を超えさせないので、条件はコンテナのホストの sysctl で決まります。LXC のコンテナの中と LXC ベースの VPS の server が条件を満たせるかどうかは未確認です。判定の決め手は server 自身のログで、server はソケットが条件に届かないときだけ前述の警告を出します。

コンテナでは、2 つの sysctl をコンテナのホストで設定します。コンテナの中からは変えられず、`docker run --sysctl` による設定も失敗します。LXC や Incus のコンテナでは、コンテナの root が中から書き込んでも、ホストの値は変わりません。カーネルによっては、コンテナの中の `sysctl -w` はエラーを表示しても終了コード 0 で終わります。前述のファイルと `sysctl --system` をコンテナの中で実行しても変わらず、カーネル 6.1 と 6.8 では、この 2 つの設定を何も表示せずに読み飛ばしました。付属の compose ファイルは非特権のまま使い、ホストの設定だけで条件を満たします。前述の手順でコンテナのホストに設定し、コンテナを再起動してから、コンテナの中のソケットが得た値を確かめます。

```sh
docker compose -f deploy/agent.compose.yaml exec wgft-agent wgft agent doctor
```

server のコンテナでは、`docker compose -f deploy/server.compose.yaml logs` でログを確かめます。

LXC や Incus のコンテナのエージェントでは、前述の手順でコンテナのホストに 2 つの sysctl を設定します。その後、コンテナの中で `systemctl restart wgft-agent` によってエージェントを再起動し、前述のとおり `agent doctor` を実行します。コンテナ自体の再起動は要りません。

コンテナの中から 2 つの sysctl が見えるかどうかは、カーネルによって違います。ラボでは、2 つの sysctl はカーネル 6.1 と 6.8 ではコンテナの中に存在せず、カーネル 6.17 では読み取り専用で、ホストの値を示しました。Fedora 44 のホストのカーネル 7.2 でも、分けた network namespace の中で読み取り専用でした。このため、コンテナの中の `server check` は、2 つの sysctl を見えないものとして示すことがあります。その場合も、`CAP_NET_ADMIN` を持たないソケットが得る値は示します。

この手順は、開発用ラボの Debian 12(カーネル 6.1)で確かめました。既定の値では、`agent doctor` がこの項目を FAILED とし、終了コードは 0 で、エージェントは警告を出しました。前述の 2 つのコマンドと再起動の後は、この項目が OK になりました。Docker でも、付属の compose ファイルで動かしたエージェントと server で同じ結果になり、server は設定の前だけ警告を出しました。同じ VM で既定の値のまま、`CAP_NET_ADMIN` だけを持つ server のプロセスは条件を満たすバッファを得て、警告を出しませんでした。付属の unit そのものでは確かめていません。非特権の Incus のコンテナのエージェントでも同じ結果になりました。このコンテナは Incus の既定のままで、security の設定も nesting もありません。エージェントは付属の unit で専用の利用者として動き、capability を持ちません。設定の前は `agent doctor` がこの項目を FAILED とし、終了コードは 0 で、エージェントは警告を出しました。コンテナのホストで前述のファイルを適用し、エージェントを再起動した後は、この項目が OK になり、警告は出なくなりました。`wgft agent rotate-key` の後もこの項目は OK のままでした。確かめたカーネルは、Debian 12 のカーネル 6.1、Ubuntu 24.04 のカーネル 6.8、Ubuntu のカーネル 6.17 です。6.17 では、ファイルを置いたままコンテナのホストを再起動し、再起動の後もこの項目が OK になることも確かめました。Proxmox VE のコンテナ、nesting を有効にしたコンテナ、非特権の LXC や Incus のコンテナの中のユーザー空間モードの server、rootless のコンテナ、LXC や Incus のコンテナのエージェントでのカーネル 7.x、他のディストリビューションは未確認です。Windows と macOS のエージェントはソケットを測らず、`agent doctor` はこの項目を NOT TESTED として示します。この 2 つの OS で得られるバッファの大きさと、設定が要るかどうかは未確認です。

ユーザー空間モードの server は、前述の WireGuard のソケットの要求とは別に UDP のルールごとの公開側の UDP ソケットにも固定 2 MiB の送信バッファを要求します。この要求は server の UDP のルールだけに当てはまり agent には当てはまりません。カーネルが要求より小さい値を割り当てると、server は `warning: the public UDP socket on port <port> got a send buffer of <bytes> bytes` で始まる行を 1 分に 1 回まで出します。送信バッファが小さいと、そのルールの応答の burst は届かず捨てられやすくなります。前述の `net.core.wmem_max` を 7340032 以上にする対処はこの小さい要求の切り詰めも防ぎます。`CAP_NET_ADMIN` は WireGuard のソケットの場合と違って効きません。この要求は FORCE を使わないため、この capability を持つ server でも、WireGuard のソケットが条件を満たしたままこの警告だけ出ることがあります。

## 1. バイナリをインストールする

同じバイナリに server、agent、CLI が含まれています。VPS のイメージや Proxmox の LXC テンプレートのような最小構成のイメージは、curl を含まないことがあります。あらかじめ `sudo apt install curl` のように導入してください。

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64.sha256
sha256sum -c wgft-linux-amd64.sha256
```

arm64 環境では `amd64` を `arm64` に置き換えてください。Windows と macOS での手順は、[Windows で agent を実行する](#windows-で-agent-を実行する)と[macOS で agent を実行する](#macos-で-agent-を実行する)で説明します。

Go 1.27 以上があれば次でもインストールできます。

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

`check` は、有効な設定、同じ server key を持つ WireGuard インタフェースの残骸、既存 firewall に必要な forwarding 許可を表示します。加えて、host 自身の input firewall が wgft 自身のポート(WireGuard と agent API)や、wgft が host 上で受けるルールの listen port(カーネルモードはプロキシモードのルール、ユーザー空間モードは全ルール)を塞いでいないかも検査し、追加する行を提示します。firewall 自体は変更しません。

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

付属の systemd unit を使う場合は、次のように導入します。unit のファイルはリリースの配布物に含まれないため、バイナリと同じリリースのタグから取得します。リリースのバイナリの `wgft version` は、1 行目にそのタグを出力します。

```sh
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/server.service"
sudo install -m 0644 server.service /etc/systemd/system/wgft.service
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

UDP 51820、TCP 8443、および転送する各ポートを VPS の firewall で開けてください。ユーザー空間モードでは `wgft server` が停止すると転送も停止します。付属の unit は `CAP_NET_ADMIN` を与えます。VM か専用のホストでは、この権限により、server の WireGuard のソケットは sysctl を上げなくても[ソケットのバッファの条件](#ユーザー空間モードのソケットのバッファ)を満たします。LXC ベースの VPS では、この権限は上限を超えさせないので、条件はコンテナのホストの sysctl で決まります。LXC ベースの VPS の server が条件を満たせるかどうかは未確認です。どの場合も、ソケットが条件に届かなければ server のログに警告が出ます。

### root なしでユーザー空間モードを使う

設定とデータをホームディレクトリに置きます。

```sh
install -d -m 0700 ~/wgft
printf 'WGFT_MODE=userspace\nWGFT_WG_ENDPOINT=vps.example.com:51820\nWGFT_DATA_DIR=%s/wgft\nWGFT_ADMIN=unix://%s/wgft/admin.sock\n' "$HOME" "$HOME" > ~/wgft/server.env
chmod 0600 ~/wgft/server.env
wgft server run --config ~/wgft/server.env
```

通常ユーザーでは 1024 未満のポートを直接 bind できません。この構成では、以降の `sudo` の代わりに `--config ~/wgft/server.env` を付けて CLI を実行します。

この構成の server は `CAP_NET_ADMIN` を持たないので、[ソケットのバッファの条件](#ユーザー空間モードのソケットのバッファ)を満たすかどうかはホストの sysctl で決まります。sysctl の設定にはホストの root の権限が要ります。設定できない場合、条件を満たせるのは既に十分な値を持つホストだけで、それ以外のホストでは server が起動時に警告を出します。

### Docker でユーザー空間モードを使う

server コンテナはユーザー空間モードで動きます。リポジトリを clone し、[deploy/server.compose.yaml](../deploy/server.compose.yaml) の `WGFT_WG_ENDPOINT` を設定して起動します。

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
# deploy/server.compose.yaml の WGFT_WG_ENDPOINT を編集
docker compose -f deploy/server.compose.yaml up -d
```

転送するポートは compose の `ports:` に列挙する必要があります。`network_mode: host` を使えば列挙は不要ですが、非特権コンテナでは 1024 未満のポートを bind できません。

コンテナは `CAP_NET_ADMIN` を持たないので、Docker のホストの sysctl で[ソケットのバッファの条件](#ユーザー空間モードのソケットのバッファ)を満たす必要があります。

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

join string は秘密の値です。持っている人は誰でもこのエージェントとして登録できます。以下の例は `WGFT_JOIN` を環境変数か dotenv ファイルに設定する形を使い、コマンドラインのフラグには渡しません。フラグの値は `ps` から他の利用者にも見え、shell の履歴にも残るためです。

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

[Releases ページ](https://github.com/rahanahu/wgft/releases) から `wgft-windows-amd64.exe` と `wgft-windows-amd64.exe.sha256` を取得します。ファイルを保存したフォルダで PowerShell を開きます。例えば Downloads フォルダです。次のコマンドでダウンロードを検証します。

```powershell
if ((Get-FileHash -Algorithm SHA256 .\wgft-windows-amd64.exe).Hash -ne (Get-Content .\wgft-windows-amd64.exe.sha256).Split(' ')[0]) {
    throw "SHA256 mismatch"
}
```

一致すれば何も表示されず、そのまま次に進めます。一致しなければ例外を投げてスクリプトを止めるため、ハッシュが合わないバイナリをそのまま実行することを防げます。`Get-FileHash` はハッシュを大文字で返し、公開されている `.sha256` ファイルは小文字であるため、PowerShell の `-ne` が大文字と小文字を区別せずに比較する点が重要です。続けて次を実行します。

```powershell
Rename-Item wgft-windows-amd64.exe wgft.exe
$env:WGFT_JOIN = '<join string>'
.\wgft.exe agent run
```

Explorer で .exe をダブルクリックすると、PowerShell から実行するよう促す文章を表示し、Return キーを押すまでウィンドウを閉じずに待ちます。

join string は `#` を含むため、PowerShell では単一引用符で囲みます。初回登録に成功すると `%ProgramData%\wgft\agent.json` が作成されます。既定のこの場所は管理者権限を必要としません。2 回目以降は次だけで起動できます。

```powershell
.\wgft.exe agent run
```

wireguard-go が UDP をすべてのインタフェースで待ち受けるため、初回起動時に Windows Defender Firewall が `wgft.exe` の受信を許可するかどうかのダイアログを出すことがあります。Windows 11 の実機で、このダイアログを許可してもキャンセルしても、WireGuard の鍵の再交換をまたいでトンネルと中継が動作し続けることを確認しました。agent は外向きの接続だけを使うためです。停止は Ctrl+C を押すか、コンソールのウィンドウを閉じます。次の起動では保存済みの認証情報を使って復帰します。

配布するバイナリはコード署名をしていません。確認に使用した Windows 11 環境では、Web ブラウザで取得したファイルを Explorer からダブルクリックで起動すると、Microsoft Defender SmartScreen の「Windows によって PC が保護されました」という警告が表示され、詳細情報を選んで実行を選ぶまでプログラムは起動しませんでした。Windows または組織のポリシーによっては、この警告を回避できない場合があります。同じ環境で、一度実行を選んだ同じファイルでは、この警告は再表示されませんでした。また、本書のとおり PowerShell から起動した場合、この警告は表示されませんでした。

wgft は Windows のサービスもタスクスケジューラも通知領域への常駐も持ちません。`agent run` は起動した利用者の権限で動作し、ゲーミング PC の多くのゲームサーバーと同じ動き方です。ログオンのたびに自動で起動させるかどうかは利用者に任されています。スタートアップフォルダへの登録はその一例ですが、未確認です。

### macOS で agent を実行する

macOS 版は Apple シリコン (arm64) 向けで、macOS 27 で実機確認済みです。Intel Mac には対応していません。ターミナルで `curl` を使って取得します。

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64.sha256
shasum -a 256 -c wgft-darwin-arm64.sha256
sudo mkdir -p /usr/local/bin
sudo install -m 0755 wgft-darwin-arm64 /usr/local/bin/wgft
```

`curl` で取得したファイルには quarantine 属性が付きません。Web ブラウザで取得するとこの属性が付き、Gatekeeper は、この属性が付いていて Apple の公証 (notarization) を受けていないバイナリの起動を止めます。wgft は公証を受けていません。Apple シリコンの Mac には `/usr/local/bin` が無い場合があるため、`mkdir -p` で作成します。

ターミナルから 1 回だけ登録します。

```sh
WGFT_JOIN='<join string>' /usr/local/bin/wgft agent run
```

初回登録に成功すると、`registered as agent <name>` が表示され、`~/Library/Application Support/wgft/agent.json` が作成されます。ディレクトリの権限は 0700、ファイルの権限は 0600 です。下の LaunchDaemon を登録する前に、Ctrl+C でこの agent を止めます。認証情報は `agent.json` に残ります。LaunchDaemon とターミナルの agent は同時に動かせません。後から起動した側が `credentials file is in use by another process` を表示して起動を止めるためです。

agent を常駐させる場合は、[deploy/io.github.rahanahu.wgft.agent.plist](../deploy/io.github.rahanahu.wgft.agent.plist) を LaunchDaemon として登録します。この LaunchDaemon は `UserName` により root ではなく利用者の権限で `wgft agent run` を実行し、`WGFT_DATA_DIR` で同じ `~/Library/Application Support/wgft` を指します。plist のファイルはリリースの配布物に含まれないため、バイナリと同じリリースのタグから取得します。リリースのバイナリの `wgft version` は、1 行目にそのタグを出力します。プレースホルダ `YOUR_USER` を利用者名とホームディレクトリに置き換えてから、インストールして読み込みます。

```sh
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/io.github.rahanahu.wgft.agent.plist"
sed -e "s|/Users/YOUR_USER|$HOME|g" -e "s|YOUR_USER|$(id -un)|g" io.github.rahanahu.wgft.agent.plist > wgft-agent.plist
plutil -lint wgft-agent.plist
sudo install -m 0644 -o root -g wheel wgft-agent.plist /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
```

plist はすべての利用者が読めるため、join string を書きません。このため、初回登録は上のとおりターミナルから行います。LaunchDaemon の動作とログは次で確認します。

```sh
sudo launchctl print system/io.github.rahanahu.wgft.agent | grep -E 'state|pid'
tail -f ~/Library/Logs/wgft-agent.log
```

トンネルが確立すると、VPS 側の `sudo wgft agent ls` の `TUNNEL` 列が `ok` になります。agent がエラーで終了した場合や強制終了された場合、launchd は agent を再起動します。再起動の間隔は最短で 10 秒 (`ThrottleInterval`) です。launchd には systemd の unit の `RestartPreventExitStatus=3` に当たる設定が無く、終了コード 3 で終わる設定の誤りでも同じ間隔で再起動を繰り返します。macOS 27 で確認しました。設定の誤りが残っている間、agent は 10 秒ごとに起動と失敗を繰り返し、`launchctl print` は `last exit code = 3` と `state = spawn scheduled` を示します。これ以外にデーモンの異常を示すものはありません。再起動を繰り返す場合はログを確認します。

LaunchDaemon は次で止めます。

```sh
sudo launchctl bootout system/io.github.rahanahu.wgft.agent
```

plist は `/Library/LaunchDaemons` に残るため、次の起動時に LaunchDaemon は再び起動します。登録を解除するには、続けて `sudo rm /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist` を実行します。

更新するには、上と同じ手順で新しい `wgft-darwin-arm64` を取得してから、次を実行します。

```sh
sudo launchctl bootout system/io.github.rahanahu.wgft.agent
sudo install -m 0755 wgft-darwin-arm64 /usr/local/bin/wgft
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
```

wgft は更新の経路を保証しますが、更新後に旧版へ戻すことは保証しません。戻す場合に備え、更新前に `~/Library/Application Support/wgft` のバックアップを取ってください。

この構成は、macOS の次の 2 つの挙動に合わせたものです。

- ローカルネットワークのプライバシー保護: `~/Library/LaunchAgents` の LaunchAgent として起動した agent は、デフォルトゲートウェイには接続できましたが、LAN 内の他のホストへの接続は `connect: no route to host` で失敗し、許可を求めるダイアログも表示されませんでした。同じバイナリをターミナルから起動した場合と、`UserName` に同じ利用者を指定した LaunchDaemon として起動した場合は、どちらも UDP と TCP でそのホストに接続できました。ターミナルから起動したプロセスは、ターミナル自身の許可を引き継ぎます。失敗の原因をローカルネットワークのプライバシー保護とする判断は症状からの推測で、裏付けるシステムログは見つかっていません。`brew services` も LaunchAgent を使うため同じ問題が起きる可能性がありますが、未確認です。macOS 27 では、インストール直後のバイナリが LAN 内の他のホストへ行う最初の接続だけが同じ `connect: no route to host` で失敗し、その後の接続はすべて成功しました。1 回だけ失敗した理由は分かっていません。
- FileVault: FileVault を有効にした Mac では、再起動後、LaunchDaemon は起動時ではなく利用者が最初にログインした時点で起動しました。その後、その Mac 自身のネットワークが使えるようになるまで `network is unreachable` を記録し、その後は自動で接続しました。この待ち時間は、ある Mac では約 15 秒、Wi-Fi の接続もログイン後に始まる Mac では約 60 秒でした。FileVault を無効にした Mac でログインせずに起動時から動くかどうかと、ログアウト後も動き続けるかどうかは未確認です。

### systemd で起動する

付属の unit は非特権の `wgft` ユーザーで動きます。server と同じく、unit のファイルはバイナリと同じリリースのタグから取得します。

```sh
sudo install -m 0755 ~/.local/bin/wgft /usr/local/bin/wgft
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

認証情報は `/var/lib/wgft/agent.json` に保存されます。

### カーネルモードで起動する

カーネルモード (`WGFT_MODE=kernel`) の Linux のエージェントは、ホストにカーネルの WireGuard インタフェースと `table inet wgft_agent` を作り、カーネルが DNAT で LAN の転送先へ転送します。インタフェースの名前は `WGFT_WG_INTERFACE` で変えない限り `wgft0` です。エージェントのプロセスは通信を中継しないため、エージェントの停止中や再起動中も転送は続きます。ただし停止中は、ルールの変更への追従、転送先の名前の引き直し、外からの変更で崩れたテーブルの修復が止まります。詳しくは [design.md](design.md) の 7b 節にあります。

カーネルモードとユーザー空間モードの違いは次のとおりです。

- 権限:エージェントには `CAP_NET_ADMIN` が必要で、ホストにはカーネルの WireGuard のモジュールが必要です。権限が無い場合、エージェントは起動時に終了コード 3 で止まり、ログに `CAP_NET_ADMIN` を示します。この停止は接続文字列の使用と `agent.json` へのモードの記録より前に起きるので、`WGFT_MODE=kernel` を外して `sudo systemctl restart wgft-agent` で起動し直せば、エージェントはユーザー空間モードで起動します。unit の `RestartPreventExitStatus=3` によって unit は failed のまま残るので、行を外すだけではエージェントは起動しません。WireGuard に対応しないカーネルでも、エージェントは同じ時点で止まります
- 転送先:IPv4 の転送先だけを転送し、`127.0.0.1` のようなループバックの転送先は拒否します。エージェントのホスト自身のサービスへ転送する場合は、そのホストの LAN のアドレスを転送先に指定します。このサービスから見た送信元は server のトンネルアドレスで、既定では `10.200.0.1` です。LAN の別のホストのサービスから見た送信元は、エージェントのホストの LAN のアドレスです。エージェントのホスト自身の UDP のサービスは、そのホストの LAN のアドレスで待ち受けるように設定します。`0.0.0.0` のようにすべてのアドレスに bind した通常のソケットは、エージェントのトンネルアドレスを送信元として応答します。この応答は転送したフローと一致しないため、client に届きません。応答の送信元のアドレスをサービス自身が選ぶ場合に影響があるかは未確認です。ルールの listen port を転送先のポートと同じにしても解消しません。TCP のサービス、LAN の別のホストのサービス、ユーザー空間モードでは、この問題は起きません。`wgft server doctor` は UDP の転送先を試さないため、このルールを失敗と示しません。原因は [design.md](design.md) の 7b.2 節にあります
- ホストの転送:エージェントは起動時に `net.ipv4.ip_forward` が 0 なら 1 に書き換え、書き換えたことを `agent.json` に記録します。ホストは wgft 以外の通信もインタフェースの間で転送するようになり、wgft のテーブルが制限するのは `wgft0` が関わる転送だけです。エージェントが `ip_forward` を 0 に戻すことはありません
- 同時フロー数の上限:`WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS` は使いません。フローはホストの conntrack の表が保持します

`WGFT_AGENT_ALLOW_TARGETS` の意味はカーネルモードでも変わらず、一覧の外の転送先には DNAT を作りません。

カーネルモードの手順は、前節の systemd の構成を前提にします。付属の `agent.service` は権限を持たないままとし、drop-in の [deploy/agent.kernel.conf](../deploy/agent.kernel.conf) が `CAP_NET_ADMIN` だけを加えます。エージェントは引き続き `wgft` ユーザーで動作し、unit の他のサンドボックスの設定も変わりません。drop-in を unit の隣に置き、`agent.env` に `WGFT_MODE=kernel` を加えます。

```sh
curl -fLO "https://raw.githubusercontent.com/rahanahu/wgft/$(wgft version | head -n 1)/deploy/agent.kernel.conf"
sudo install -D -m 0644 agent.kernel.conf /etc/systemd/system/wgft-agent.service.d/kernel.conf
printf 'WGFT_MODE=kernel\n' | sudo tee -a /etc/wgft/agent.env >/dev/null
sudo systemctl daemon-reload
sudo systemctl restart wgft-agent
```

新しいホストでは、systemd の構成の `systemctl enable --now wgft-agent` の前に、上のコマンドのうち restart 以外を実行します。エージェントは登録を済ませ、カーネルモードで起動します。ユーザー空間モードで動いているエージェントは、最後の restart でカーネルモードに切り替わります。`ProtectKernelTunables=` は `/proc/sys` を読み取り専用にし、エージェントによる `ip_forward` の書き換えを止めるため、drop-in に加えないでください。

結果は `agent doctor` で確かめます。エージェントの稼働中は、エージェントの利用者として実行します。Dataplane の群の項目は、エージェント自身が報告する `wgft0`、テーブル、転送の設定を示し、終了コード 0 はこのホストが転送できることを意味します。

```sh
sudo runuser -u wgft -- wgft agent doctor
```

エージェントの停止中は、カーネルの状態を root だけが読めるため、`sudo wgft agent doctor` を実行します。process の項目は FAILED になりますが、カーネルが転送を続けるので、`wgft0`、テーブル、`ip_forward` がそろっていれば終了コードは 0 です。停止中のエージェントを `wgft` ユーザーとして診断すると、Dataplane の群の項目は `needs_cap_net_admin` の UNKNOWN になり、終了コードは 2 になります。

エージェントの停止中は、テーブルを戻すものがありません。`nftables.conf` が `flush ruleset` で始まるホストで `systemctl reload nftables` を実行すると、`table inet wgft_agent` だけが消え、`wgft0` と 1 の `ip_forward` は残ります。このため、エージェントが起動してテーブルを公開し直すまで、VPS のピアからこのホストと LAN への通信を止めるものが無くなります。この間、`sudo wgft agent doctor` はテーブルを FAILED と示します。

ユーザー空間モードへ戻すには、エージェントを止め、カーネルモードが残したものを `wgft agent teardown` で削除してから、`WGFT_MODE=kernel` と drop-in を取り除きます。

```sh
sudo systemctl stop wgft-agent
sudo wgft agent teardown --dry-run
sudo wgft agent teardown
sudo sed -i '/^WGFT_MODE=/d' /etc/wgft/agent.env
sudo rm /etc/systemd/system/wgft-agent.service.d/kernel.conf
sudo systemctl daemon-reload
sudo systemctl start wgft-agent
```

`wgft agent teardown` は、`wgft0`、エージェントが転送したフローの conntrack のエントリ、`table inet wgft_agent`、`agent.json` のカーネルモードの記録を削除します。登録の情報と鍵は残るため、エージェントは同じエージェントとして接続し直します。エージェントの稼働中は何も削除せずに拒否します。`ip_forward` は元に戻しません。エージェントが 0 から書き換えた場合は、元に戻すコマンドを出力に示します。teardown の前にユーザー空間モードで起動したエージェントは、カーネルモードの記録が残っている間は起動を拒否し、`wgft agent teardown` の実行を案内します。

以上の手順は、開発環境の Debian 12 の VM で、server をカーネルモードにして確認済みです。確認した内容は、エージェントのホスト自身のアドレスへの TCP の転送、そのアドレスで待ち受ける UDP のサービスへの転送、別のホストへの TCP の転送、VM の再起動、エージェントの停止中の転送、稼働中と停止中の `agent doctor`、drop-in が無い場合の終了コード 3、teardown、2 つのモードの間の切り替えです。試験用の実機では、Proxmox VE の非特権の LXC コンテナ (Debian 13) で drop-in を確認済みです。このコンテナは nesting を有効にし、AppArmor のプロファイルを unconfined にしています。確認した内容は、`systemctl restart wgft-agent` の後とコンテナ自体の再起動の後に転送が戻ること、エージェントを約 40 秒止めている間も転送が続くこと、エージェントの稼働中と停止中の `wgft agent rotate-key` です。Ubuntu や Fedora のような他のディストリビューション、SELinux や AppArmor を有効にしたディストリビューション、nesting を無効にした Proxmox VE のコンテナ、AppArmor のプロファイルが制限をかける Proxmox VE のコンテナ、Incus のコンテナ、Docker では未確認です。Docker でカーネルモードを使う手順は、このガイドに記載していません。

v1.1.x のエージェントはカーネルモードを持ちません。カーネルモードのエージェントを v1.1.x へ戻すには、v1.2 のバイナリで、ユーザー空間モードへ戻す手順を最後の `systemctl start` の前まで実行し、v1.1.x のバイナリをインストールしてから起動します。試験用の実機では、この順で戻した v1.1.3 がユーザー空間モードで TCP、UDP、PROXY protocol v2 を正常に転送しました。teardown を省いても v1.1.3 は起動しますが、`wgft0` と `table inet wgft_agent` はカーネルに残り、v1.1.3 は `agent.json` をカーネルモードの記録を除いて書き直します。残った `wgft0` はエージェントの鍵を持ったままです。`wgft0` とテーブルが転送に与える影響は未確認です。その後でも、v1.2 の `wgft agent teardown` は `wgft0` とテーブルを削除します。ただし、v1.1.x が必要な記録を除いているため、teardown は conntrack のエントリを削除できず、`ip_forward` を元に戻すコマンドも表示しません。

### Docker で起動する

[deploy/agent.compose.yaml](../deploy/agent.compose.yaml) の `WGFT_JOIN` を設定して起動します。

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
# deploy/agent.compose.yaml の WGFT_JOIN を編集
docker compose -f deploy/agent.compose.yaml up -d
```

コンテナから LAN 側の転送先に到達できない場合は、compose の `network_mode: host` を有効にしてください。

Docker のホストは[ソケットのバッファの条件](#ユーザー空間モードのソケットのバッファ)を満たす必要があります。コンテナは 2 つの sysctl を自分では設定できません。条件を満たしたかどうかは `docker compose -f deploy/agent.compose.yaml exec wgft-agent wgft agent doctor` で確かめます。

### 転送先のアドレスを必要な範囲に絞る

エージェントは server が配る転送先へそのまま接続します。VPS を奪った攻撃者は、転送先を LAN の任意のアドレスに書き換えられます。`WGFT_AGENT_ALLOW_TARGETS` は、エージェントが接続してよいアドレスの一覧です。

```sh
WGFT_AGENT_ALLOW_TARGETS=192.168.1.20:25565,192.168.1.21:2456-2458 wgft agent run --data-dir ~/.wgft
```

systemd では `/etc/wgft/agent.env` の `WGFT_JOIN` と並べて書きます。

```sh
printf 'WGFT_AGENT_ALLOW_TARGETS=192.168.1.20:25565,192.168.1.21:2456-2458\n' | sudo tee -a /etc/wgft/agent.env >/dev/null
```

項目はコンマ区切りで、各項目は `CIDR`、`CIDR:ポート`、`CIDR:下限-上限` のいずれかです。アドレスだけの項目は 1 台のホストを指し、ポートを書かない項目はそのアドレスの全ポートを許します。IPv6 のアドレスにポートを付ける項目は `[2001:db8::/32]:8080` のように角括弧で囲みます。判定は接続する直前のアドレスに対して行うので、ホスト名の転送先は名前解決の後に判定され、新しい接続と UDP のセッションごとに判定されます。転送先が IP アドレスで一覧の外にあるルールは待ち受けを開かず、理由付きの error として `wgft agent ls` と Web UI に出ます。ポートの範囲を持つルールでは、一覧の外のポートだけが閉じたままになります。設定を省略した場合は制限しません。値の構文が誤っている場合は、終了コード 3 で起動を止めます。コンマだけのように、値はあるのに項目が 1 つも無い場合も同じく起動を止めます。守りの設定が黙って無効になることを防ぐためです。

### ローミングと ip-flapping の警告

エージェントを動かすホストがネットワークを移動し、直近 10 分以内に使ったネットワークへ戻ると `ip-flapping` の警告が出ます。stream 側と WireGuard のエンドポイント側でそれぞれ 1 件です。自宅の Wi-Fi と携帯回線のテザリングの間を移動するノート PC や、2 つの事業所の間を移動する運用では、認証情報が 1 部のままでもこれが日常的に起こります。この場合の警告は、窃取の兆候ではありません。`wgft agent warnings` は次の形で表示します。

```
AGENT   KIND         DETAIL                                                         AT
laptop  ip-flapping  stream source alternated between 198.51.100.7 and 203.0.113.9  2026-01-01T09:00:00+09:00
laptop  ip-flapping  wg endpoint alternated between 198.51.100.7 and 203.0.113.9    2026-01-01T09:00:05+09:00
```

ローミングすると分かっているエージェントでは、警告を削除します。詳細の引数を付けなければ、そのエージェントの `ip-flapping` の警告をすべて削除します。

```sh
sudo wgft agent dismiss-warning laptop ip-flapping
```

移動しないエージェントに `ip-flapping` が出た場合は、鍵か恒久トークンの複製を疑います。対応は `wgft agent warnings --help` にあります。

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

エージェントは、新しいルールのために TCP の待ち受けを開くとき、転送先へ 1 回だけ試し接続してすぐ閉じます。接続を拒む転送先を、通信が来る前に報告するためです。転送先からは、データを運ばない接続 1 本に見えます。転送先が待ち受けていない間、`wgft agent ls` はそのルールを `RULES` 列に `cannot connect to target` として示します。この状態は、転送先が起動してから 30 秒以内、エージェントの次の報告で消えます。UDP のルールにこの確認はありません。データグラムは、送っても届いたかどうかが分からないためです。

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

Tailscale 経由で管理画面にアクセスする場合は `WGFT_ADMIN_TAILSCALE=true` を設定します。追加の Host 名は `WGFT_ADMIN_HOST` で指定できます。server はこの待ち受けで、Tailscale のインタフェースから届き、送信元が tailnet のアドレスである接続だけを受け付けます。このため、LAN のアドレスを SNAT せずに転送するサブネットルータからは届きません。Tailscale の再起動でインタフェースが作り直されたときと、tailnet のアドレスが変わったときは、server が待ち受けを閉じて数秒のうちに開き直し、それぞれをログに 1 行ずつ書きます。server が Tailscale より先に起動して tailnet のアドレスが無かった場合は、wgft を再起動するまでこの待ち受けを開きません。

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

## ログを見る

server とエージェントは、ログを標準エラー出力に書き、独自のログファイルを持ちません。同梱の systemd の unit では、journald がログを保存します。

```sh
sudo journalctl -u wgft -b            # server、直近の起動以降
sudo journalctl -u wgft-agent -f      # エージェント、新しい行を追う
sudo journalctl -u wgft --since "1 hour ago"
```

Docker では `docker compose -f deploy/server.compose.yaml logs` か、コンテナに対する `docker logs` を使います。

server は、データプレーンの適用が済み、管理用 API とエージェント用 API の待ち受けを開けた時点で、版、モード、世代、ルールとエージェントの件数を `server started` の 1 行に出します。この行が無ければ起動は終わっていません。止まった箇所は、直前の行に出ます。ただし、起動を終わらせない失敗が 1 つあります。保存済みのルールがまったく適用できない場合、server は `startup hold` の 1 行を出し、管理用 API だけを待ち受けたまま 30 秒ごとに適用をやり直します。保留の間も `wgft rule rm` と `wgft rule disable` は届くので、適用できない宣言を小さくして直せます。適用が成功するまで、server は新しい宣言を反映済みとは扱いません。`server started` の行も適用の成功の後に出ます。保留が止めるのは公開であり、転送ではありません。初回の起動や VPS 自体の再起動の直後は、カーネルに何も残っていないため転送されません。プロセスだけの再起動をまたぐときは、前のプロセスがカーネルに残したものがそのまま残ります。どちらの宣言を転送しているかは適用がどこで失敗したかで変わり、ログからは分かりません。カーネルが差し替えを行わないまま失敗した場合は、テーブルは実際に旧いままなので、前回の宣言のまま転送を続けます。宣言の送信自体が失敗した場合と、カーネルがバッチを拒んだ場合が該当します。カーネルが差し替えを終えたのに vpsd が応答を受け取れなかった場合は、テーブルは既に差し替わっており、vpsd が失敗として報告した新しい宣言のほうを転送しています。プロキシモードの待ち受けは、いずれの場合もプロセスと一緒に消えます。実際のカーネルの内容は `wgft server nft` で読めます。ルールの変更が成功するたびに、`cli rule add` や `ui import` のような操作の出所、対象のルールの ID、結果の世代を 1 行に出します。ルールの変更だけを一覧にするコマンドは次のとおりです。

```sh
sudo journalctl -u wgft | grep 'rules: '
```

wgft は個々のパケットや成功したフローをログに出しません。接続文字列、トークン、秘密鍵もログに出しません。

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

カーネルモードのエージェントは、停止した後もインタフェースと nftables のテーブルをカーネルに残します。認証情報を削除する前にエージェントを止め、`sudo wgft agent teardown` を実行してください。詳しくは[カーネルモードで起動する](#カーネルモードで起動する)を参照してください。

Docker の agent を認証情報ごと削除する場合:

```sh
docker compose -f deploy/agent.compose.yaml down -v
```

## コマンドリファレンス

`wgft <command> --help` には各コマンドの例があります。生成済みの完全な一覧は [cli.md](cli.md) にあります。