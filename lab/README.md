# lab:wgft の開発用ラボ

VPS 側のカーネル機能(nftables、WireGuard、conntrack)を、ホストを汚さずに試すための環境。

## 開発環境の方針

| やること | 場所 |
|---|---|
| コードを書く、`go test`、エージェント・制御プレーン・CLI を動かす | ホスト |
| nftables、wg0、conntrack が絡む実験と、端から端までの結合テスト | Incus の VM(`wgft-lab`)の中の netns |

- ホストや Docker でカーネル機能を試すと、ホストのカーネルのバージョン、読み込まれるモジュール、Docker が有効にする `br_netfilter` 経由のホストのルールと conntrack が結果に混ざる。VM に閉じ込めて切り分ける
- Docker は開発環境には使わない。使うのはエージェントの配布用イメージを確かめるときだけ
- VM は 1 台。トポロジは VM 内の netns で組むので、同じ `netns.sh` を CI でも使える
- ホストのリポジトリを VM の `/wgft` に**読み取り専用**で共有する。ホストでビルドし、VM で実行する

## 前提

- Incus が入っていて、自分が `incus-admin` グループにいる(ログインし直す前でも `lab` は `sg` で動く)
- Go(ホストでのビルド用)

## 使い方

```sh
lab/lab up                      # 初回:VM 作成、パッケージ導入、スナップショット、トポロジ(2 回目以降は起動とトポロジだけ)
lab/lab status                  # 状態確認
lab/lab exec client ping 198.51.100.1
lab/lab build                   # ホストで ./cmd/... ./tools/... を bin/ にビルドし、VM の /usr/local/bin に install
lab/lab test internal/vpsd/nft  # build tag lab 付きのテストを VM の vps ns で実行(root と nft が要るゴールデンテストなど)
lab/lab exec vps wgft server run ...  # VM では /usr/local/bin の名前で実行する(/wgft/bin を直接 exec しない。下の注意)
lab/lab shell home              # home ns で bash
lab/lab exec vm bash /wgft/lab/e2e.sh kernel     # 端から端までのシナリオ(登録、TCP/UDP、PROXY protocol、deny の即時反映、撤去)を PASS/FAIL で
lab/lab exec vm bash /wgft/lab/e2e.sh userspace  # 同じシナリオをユーザー空間モード(非 root の wgftlab ユーザー)で
lab/lab exec vm bash /wgft/lab/rates.sh kernel   # レート制限の実負荷(packet、per-source、new-flow)。userspace も同じ
lab/lab exec vm bash /wgft/lab/connlimit.sh      # カーネルモードの接続元 IP ごとの同時フロー数の上限(ct count)。userspace には無い機能なので kernel だけ
lab/lab exec vm bash /wgft/lab/split-merge.sh kernel   # Web UI の分割・統合。流れている UDP セッションが切れないことを確認。userspace も同じ
lab/lab exec vm bash /wgft/lab/import-export.sh kernel # Web UI の書き出しと読み込み。確認画面の差分、確認後の変更による適用の拒否を確認。userspace も同じ
lab/lab exec vm bash /wgft/lab/lifecycle.sh kernel     # server の再起動、ルールの増減、撤去、プロキシの bind 失敗、既定の上限下でのメモリを確認。userspace も同じ
lab/lab reset                   # 実験で壊したらスナップショットに戻す
lab/lab destroy                 # VM ごと消す
```

VM の中で一式を動かす例(`lab/lab shell vm` で入ってから):

```sh
# 設定は WGFT_* かフラグで渡す。ラボでは管理用 API を Unix ソケットの代わりにループバック TCP で開くと楽(--admin)
ip netns exec vps wgft server run --mode kernel --data-dir /tmp/wgft --wg-endpoint 203.0.113.1:51820 --admin 127.0.0.1:8686 &
JOIN=$(ip netns exec vps wgft agent join-string --name home)
ip netns exec home env WGFT_JOIN="$JOIN" WGFT_NAME=home wgft agent run --data-dir /var/lib/wgft-agent &
ip netns exec vps wgft rule add --agent home --udp 2456-2457 --to 192.168.50.2:3000   # stream で即配信される
ip netns exec vps wgft agent ls                                                      # 接続・ハートビート・ハンドシェイク
ip netns exec home echo -bind 192.168.50.2 -udp 3000,3001 -tcp 25565 &
ip netns exec client sh -c 'echo hi | socat -t2 - UDP:198.51.100.1:2456'
```

VM 名やイメージは環境変数で変えられる(`WGFT_LAB_VM`、`WGFT_LAB_IMAGE`、`WGFT_LAB_CPU`、`WGFT_LAB_MEM`)。

## 対応する VPS の環境

wgft が対応するのは **カーネル 6.1 以上、nftables 1.0.6 以上**(Debian 12、Ubuntu 24.04、Fedora 44 以降)。
既定の VM イメージ `images:debian/12` はこの下限そのもので、ここで通ったものは新しい環境でも通る見込み。
別のディストリで確かめたいときは 2 台目を立てる。

```sh
WGFT_LAB_IMAGE=images:ubuntu/24.04 WGFT_LAB_VM=wgft-lab-ubuntu lab/lab up
```

## トポロジ

```
client ── vps ── homerouter(NAT) ─┬─ home(エージェント)
                                  └─ lan(自宅 LAN 上の別ホスト)
```

home と lan は homerouter の中のブリッジ(br0)にぶら下がる、同じ自宅 LAN セグメントの 2 台。
実際の自宅と同じく、lan のデフォルトゲートウェイはエージェントの host(home)ではなく homerouter。

| ns | IF | アドレス | 役割 |
|---|---|---|---|
| client | eth0 | 198.51.100.2/24 | インターネット上の利用者 |
| vps | pub0 | 198.51.100.1/24 | 公開 IF(client 側) |
| vps | pub1 | 203.0.113.1/24 | 公開 IF(自宅側。WireGuard とエージェント API の宛先) |
| homerouter | wan0 | 203.0.113.2/24 | 自宅ルータの WAN。home と lan の通信はこのアドレスに masquerade される |
| homerouter | br0 | 192.168.50.1/24 | 自宅 LAN のブリッジ(lan0 = home 側、lan1 = lan 側) |
| home | eth0 | 192.168.50.2/24 | エージェント |
| lan | eth0 | 192.168.50.3/24 | LAN 上の別ホスト(ゲームサーバ役。ゲートウェイは homerouter) |

- `vps` の `ip_forward` は設定しない。`vpsd` が起動時に設定する(仕様 6.1 節)
- netns はメモリ上にしかないので、VM を再起動すると消える。`lab up` か `lab net up` で立て直す
- `netns.sh` は Incus に依存しない。CI では root で `lab/netns.sh up` を直接実行する

## 既知の問題:VM が IPv4 で外に出られない

Fedora のホストで firewalld と Docker が動いていると、VM は IPv6 では外に出られるが、DHCPv4、DNS、IPv4 の転送が落ちる(開発時の実験で確認)。

- `lab up` は、DNS が引けなければ VM の DNS を IPv6 のサーバに切り替えてパッケージを入れるので、そのままでも動く。設定は `/etc/systemd/resolved.conf.d/wgft-lab-ipv6-dns.conf` に書くので、再起動や `lab reset` の後も残る(`/etc/resolv.conf` は `/run` へのシンボリックリンクなので直接書かない)
- 恒久的に直すなら `lab/lab host-fix`(sudo。内容は実行前に表示される)

## 共有ディレクトリの注意

- ホストに virtiofsd がないので 9p で共有する。9p はホットプラグできないため、デバイスは VM の作成時(起動前)に追加している
- VM 側からは書き込めない。ビルド成果物はホストで `bin/` に作る
- **`/wgft/bin` のバイナリを VM で直接 exec しない。** そのバイナリを実行中のプロセスがいる間にホストで上書きすると(`go build` は同じ inode に書く)、VM のページキャッシュに固定された古いページと新しいページが混ざり、Go ランタイムの初期化で SIGSEGV になる。`lab build` が `install`(unlink してからコピー)で `/usr/local/bin` に置くので、VM ではその名前で実行する

## 確認済み:管理用 API のアクセス経路(2026-09-15)

ラボ VM で `wgft server run`(既定の `--admin unix:///run/wgft/admin.sock`)を起動して確かめた結果:

- ソケットは `srw------- root root`(0600)、親 `/run/wgft` は `drwx------`(0700)。ソケットは
  ファイルシステム上にあるので netns には縛られず、VM のどの ns からでも同じパスで届く
- root の `wgft rule ls` は env の編集も再起動もなしに応答する。非 root ユーザーは
  `dial unix /run/wgft/admin.sock: connect: permission denied` になり、CLI が
  「sudo で実行してください」と案内する。⇒ **SSH で入るのが root なら素通り。非 root ユーザーで
  `LocalForward` するなら `wgft` グループ+0660 の逃げ道が要る**(`sshd` は VM 未導入なので
  転送そのものは実機で最終確認する)
- `--admin-tailscale` は `100.64.0.0/10` のアドレスを持つ iface を検出して、その IP に限定して
  待ち受ける(ダミー iface `100.64.0.5/10` で確認)。アドレスが無ければ警告して unix ソケットで継続
- ブラウザ経路:Firefox 155 は同一オリジンのネイティブ form POST に `Sec-Fetch-Site: same-origin` と
  `Origin` の両方を付けるので通る。`Host: evil.example` や `Sec-Fetch-Site: cross-site` の POST は 403
- ループバック以外の TCP(`--admin 0.0.0.0:8686`)に向けると警告を出すが起動は続ける

## 確認済み:実 Caddy での HTTPS 経路

home ns で実際に Caddy を動かして PROXY protocol、80 の素通し、TLS の終端、拒否の即時反映を確かめた記録は [lab/caddy/README.md](caddy/README.md) を参照。
