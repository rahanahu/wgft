# lab:wgft の開発用ラボ

VPS 側のカーネル機能(nftables、WireGuard、conntrack)を、ホストを汚さずに試すための環境。

## 開発環境の方針

| やること | 場所 |
|---|---|
| コードを書く、`go test`、エージェント・制御プレーン・CLI を動かす | ホスト |
| nftables、wg0、conntrack が絡む実験と、端から端までの結合テスト | Incus の VM(`wgft-lab`)の中の netns |

- ホストや Docker でカーネル機能を試すと、ホストのカーネルのバージョン、読み込まれるモジュール、Docker が有効にする `br_netfilter` 経由のホストのルールと conntrack が結果に混ざる。VM に閉じ込めて切り分ける
- Docker は開発環境には使わない。使うのは server とエージェントの配布用イメージを確かめるときだけ(`scripts/docker-smoke.sh`)
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
lab/lab exec vm bash /wgft/lab/rates.sh kernel   # 3 つのレートと Relay ルールのレートの実際の通過数、拒否の順序、TCP への packet_rate 無効を PASS/FAIL で。userspace も同じ
lab/lab exec vm bash /wgft/lab/connlimit.sh      # カーネルモードの接続元 IP ごとの同時フロー数の上限(ct count)。userspace には無い機能なので kernel だけ
lab/lab exec vm bash /wgft/lab/split-merge.sh kernel   # Web UI の分割・統合。流れている UDP セッションが切れないことを確認。userspace も同じ
lab/lab exec vm bash /wgft/lab/import-export.sh kernel # Web UI の書き出しと読み込み。確認画面の差分、確認後の変更による適用の拒否を確認。userspace も同じ
lab/lab exec vm bash /wgft/lab/lifecycle.sh kernel     # server の再起動、ルールの増減、撤去、プロキシの bind 失敗、既定と半分の予算下でのメモリ、Resource Guard のルール間の隔離、ルール単位/backend 全体の適用失敗と再試行を確認。userspace も同じ
lab/lab exec vm bash /wgft/lab/lifecycle.sh kernel 3 3b  # 確認の番号(1 2 3 3b 4 5 5b 5c 5d 5e 6 7 8 9)を並べると、その確認だけを流す
lab/lab exec vm bash /wgft/lab/ipv6.sh kernel    # IPv6 の送信元が判定するポートに届かず、集約のレートのトークンも使わないことを確認。userspace も同じ
lab/lab exec vm bash /wgft/lab/version-skew.sh         # 版の組み合わせ(新旧の server・agent、legacy v0)。旧いバイナリは GitHub の Releases から取得しキャッシュする(スクリプト冒頭のコメント参照)
lab/lab exec vm bash /wgft/lab/upgrade.sh kernel       # 旧版からの更新(D4)。既定は直前のリリース(v0.5.0)のデータに現在のビルドを重ね、ルール・鍵・認証情報が保たれ、転送が戻ることを確認。WGFT_UPGRADE_OLD_VERSION=0.4.0 を付けると、release notes が更新を約束するもう一方の版でも同じ確認を流せる。userspace も同じ
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
| client | eth0 | 198.51.100.2/24、2001:db8::2/64 | インターネット上の利用者 |
| vps | pub0 | 198.51.100.1/24、2001:db8::1/64 | 公開 IF(client 側) |
| vps | pub1 | 203.0.113.1/24 | 公開 IF(自宅側。WireGuard とエージェント API の宛先) |
| homerouter | wan0 | 203.0.113.2/24 | 自宅ルータの WAN。home と lan の通信はこのアドレスに masquerade される |
| homerouter | br0 | 192.168.50.1/24 | 自宅 LAN のブリッジ(lan0 = home 側、lan1 = lan 側) |
| home | eth0 | 192.168.50.2/24 | エージェント |
| lan | eth0 | 192.168.50.3/24 | LAN 上の別ホスト(ゲームサーバ役。ゲートウェイは homerouter) |

client と vps だけが IPv6(ドキュメント用のプレフィクス `2001:db8::/32`)も持つ。homerouter より
先には IPv6 の経路も宛先も無い。wgft は v1 では IPv4 だけを扱い、IPv6 の送信元を拒む(設計文書
7a.9 節)。この IPv6 アドレスは、その守りを `lab/ipv6.sh` で実際のパケットで確かめるためにある。

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

## Sandbox: 1 台の VM の中で並べる隔離の単位

確認を隔てる単位は Sandbox です。VM は OS とカーネルを与える Lab Host で、その中に使い捨ての
Sandbox を並べます。

```
Lab Host VM
|- Sandbox A: wgft-<id>-client, -vps, -router, -home, -lan, -runner, 作業ディレクトリ、自分のプロセス
|- Sandbox B: ...
```

network namespace がすでに隔てているものは、Sandbox ごとに分けません。インタフェース名
(`wgft0`)、アドレス、待ち受けポート、`127.0.0.1:8686`、WireGuard のポート、`table inet wgft`、
conntrack のテーブルは、Sandbox ごとに同じ値を同時に使えます。分けるのは、network namespace が
隔てないものだけです。データディレクトリ、ログ、scratch ファイルの置き場 (`/tmp/wgft-lab/<id>/`)
と、プロセスの所有です。

Sandbox の発行、トポロジの構築、プロセスの所有、後片付け、並列実行、結果の集約は
[tools/labhost](../tools/labhost) が担います。ホストで `lab/lab build` がビルドして VM の
`/usr/local/bin` に入れるので、VM の中では名前だけで実行します。

### 確認の流し方

```sh
lab/lab exec vm labhost run "e2e.sh kernel"                                 # 1 つの確認
lab/lab exec vm labhost run -parallel 4 "e2e.sh kernel" "ipv6.sh kernel"    # いくつかの確認を並列に
lab/lab exec vm labhost run -parallel 4 -repeat 20 "e2e.sh kernel"          # 同じ確認を 20 回
lab/lab exec vm labhost run -parallel 8 all                                 # 一式 (lab/suite.txt)
lab/lab exec vm labhost list                                                # 今ある Sandbox
lab/lab exec vm labhost create                                              # 手作業用に 1 つ作る
lab/lab exec vm labhost gc                                                  # 死んだ実行の残骸の片付け
lab/lab exec vm labhost run -wait 10m -parallel 8 all                       # 他の run が終わるまで待つ
```

`run` と `gc` は、Lab Host VM ごとに 1 つのロック (`/run/wgft-labhost.lock`) を取ります。2 つ目の
`run` は既定では待たずに断り、ロックファイルの場所と持ち主の PID を示します。`-wait <期間>` を付けた
ときだけ、その期間まで順番を待ちます。単独で流す分類が約束するのは「Lab Host VM の中で単独」なので、
2 つの `run` が同時に走ると、一方の単独の仕事が他方のどの仕事とでも重なります。ロックの実体は
カーネルの flock で、持ち主が SIGKILL で死んでも残りません。`create` と `destroy` は名指しした
Sandbox 1 つだけを扱う手作業の道具なので、ロックを取りません。`run` が持っている Sandbox を
名指ししない限り、いつでも使えます。

`run all` は [lab/suite.txt](suite.txt) を読みます。`parallel` に分類された確認を大きさ
`-parallel` のプールで流し、そのあと `exclusive-*` に分類された確認を 1 つずつ流します。`run all` が流すのは `suite.txt` の `default` の列が yes の確認だけです。
`version-skew.sh` は Lab Host VM からリリースのバイナリを取得できる場合に限る確認なので、
`default` は no とし、名指ししたときだけ流れます。

終了コードが 0 になるのは、すべての仕事が成功し、中断されず、後片付けの漏れが無かったときだけです。
確認がすべて PASS でも、netns、プロセス、作業ディレクトリ、root netns のリンクのどれかが残っていれば
非 0 で終わり、`LEFTOVER FAILURE` の行が何が残ったかを挙げます。片付けの正しさは harness 自身の
責任なので、シナリオの失敗と同じ扱いにしています。`-keep-failed` で意図して残した作業ディレクトリは
漏れに数えません。

出力の最後に、確認ごとの PASS、FAIL、SKIP の行数が並びます。従来の 1 確認 1 VM の流し方と
同じ確認が流れたことは、この行数の一致で確かめられます。

### 確認の分類

[lab/suite.txt](suite.txt) が確認ごとに持つ分類は 4 つです。

| 分類 | 意味 | 対象 |
|---|---|---|
| `parallel` | 他の Sandbox と同時に流せます。触るものが自分の namespace と自分の作業ディレクトリの中に閉じます | `e2e.sh`、`ipv6.sh`、`split-merge.sh`、`import-export.sh`、`connlimit.sh`、`version-skew.sh`、`lifecycle.sh` の check 1 2 3 3b 4 5c 5d 6 7 8 9 |
| `exclusive-heavy` | Lab Host VM の中で単独で流します。主張の根拠になる値そのものが、メモリか到達頻度の測定値です | `lifecycle.sh` の check 5、5b、5e、`rates.sh` |
| `exclusive-timing` | Lab Host VM の中で単独で流します。壁時計の窓の中で何が起きないかを主張するので、その窓が始まる前に収束を確認できないと、同じ VM を分け合ったときに失敗します | 該当する確認は今はありません |
| `exclusive-global` | Lab Host VM の中で単独で流します。network namespace が隔てない値を変えます | 該当する確認は今はありません |

`lifecycle.sh` の check 5c と check 5d は、主張の根拠が到達頻度でもメモリでもなく、ルールごとの受け付けの判定です。8 つの Sandbox のプールの中で、しかも 5c と 5d が同時に流れる状態で、20 回ずつ流して 160 件のすべてが成功し、保持数も毎回同じでした。この測定により、分類は `parallel` です。

`rates.sh` と `lifecycle.sh` の check 5 を単独で流す理由は、隣の Sandbox が結果を壊すからではなく、読む値が測定値そのものだからです。ラボでの実測では、両方とも隣に 4 つと 8 つの Sandbox がある状態でも同じ判定を出しました。check 5 の RSS は 85 MiB から 110 MiB の幅に収まり、上限の 224 MiB に対して半分以上の余裕がありました。`rates.sh` の上限なしの到達数は 500 回中 405 回から 500 回の幅で動きますが、隣の Sandbox の数とは相関しませんでした。`connlimit.sh` は 9 回の実行で 1 つの値も動かなかったので、`parallel` に分類しています。

`nf_conntrack_max` と conntrack のハッシュの大きさは VM 全体で 1 つの値です。network namespace の
中からの書き込みはカーネルが拒みます。この値を変える確認を新たに作るときは `exclusive-global` に
入れます。`nf_conntrack_acct` は namespace ごとの値なので、`lifecycle.sh` の check 6 の扱いは
`parallel` のままです。

`lifecycle.sh` の check 8 と check 9 は、server の 30 秒の再試行に合わせた 45 秒の壁時計の
budget を持ちます。実際の待ちは、単独で流したときも、8 並列のプールの中で流したときも、
`exclusive-heavy` の確認を隣で流したときも 24 秒から 25 秒で、並列で延びませんでした。
余裕は約 20 秒あるので、check 8 の分類は `parallel` です。

check 9 はかつて `exclusive-timing` でした。check 9c は、何も変えていない 35 秒の窓の間に適用が
1 度も記録されないことを主張しますが、窓に入る前には前段の flush と delete への応答で forwarding が
戻ったことしか確認しておらず、それぞれの応答が残す "applied"/drift のログ行そのものは確認していませんでした。
隣の Sandbox の負荷でそのログ行の書き込みが遅れると、窓の中に紛れ込み、無関係な apply に見えました
(実測は単独で 20 回中 20 回成功、8 並列のプールで 20 回中 17 回成功、一式の中で 20 回中 18 回成功で、
失敗はいつも `no apply was logged in the window`)。[docs/testing.md](../docs/testing.md) の規範に
従い、窓の基準値を取る前に、直前の 2 つの応答それぞれの "applied"/drift のログ行を実際に確認するよう
直しました。直した後の実測は、単独で 20 回中 20 回成功、8 並列のプール (この 8 並列は本節の表にある
`parallel` の確認一式を隣に置いた状態) で 20 回中 20 回成功だったので、分類を `parallel` に移しました。

check 6h は、squat したポートを解放した直後、その解放を確かめずに 45 秒の再試行の budget に入って
いました。次に確かめる条件 (rule の apply_state) は解放したポートそのものを見ないため、隣の
Sandbox の負荷で解放が遅れると、再試行が 1 回分の無駄な試みで終わり、45 秒の budget を超えることが
ありました (100 回のうち 1 回、単独では 40 回中 40 回成功)。ポートが実際に解放されたことを、
budget に入る前に確かめる形に直しました。直した後の実測は、8 並列のプールで check 6 (check 6h を
含む) を 100 回流してすべて成功したので、分類は `parallel` のままです。

### 失敗した Sandbox の調べ方

```sh
lab/lab exec vm labhost run -keep-failed -parallel 4 all
```

`-keep-failed` は、失敗した Sandbox の作業ディレクトリを残します。実行ごとの置き場
`/tmp/wgft-lab/run-<日時>/` には、確認ごとのログ (`logs/`)、1 秒ごとのメモリと load average の
記録 (`metrics.csv`)、結果の一覧 (`summary.json`) が残ります。network namespace とプロセスは、
成功しても失敗しても片付けます。残った作業ディレクトリは `labhost gc` が消します。

### 後片付け

- **`pkill -x wgft` のような VM 全体への kill は使いません。** Sandbox は自分の namespace の
  中のプロセスだけを止めます。`ip netns pids <ns>` が `setsid nohup` で切り離された孫まで
  数え上げるので、cgroup も PID の記録も要りません
- 確認の shell 自身は、トポロジに加わらない 6 つ目の namespace (`-runner`) の中で動きます。
  harness が SIGKILL で死んで shell が孤児として残っても、`gc` がその孤児を見つけられます
- 止める順序はプロセス、network namespace、作業ディレクトリの順です。namespace を先に消すと、
  プロセスは名前の無い namespace に残って動き続けます
- `gc` は `wgft-<id>-` の名前の namespace と作業ディレクトリを探し、持ち主のいない Sandbox を
  片付けます。持ち主の有無は作業ディレクトリのロックで判別するので、流れている Sandbox には
  触りません
- SIGINT で harness を止めると、harness 自身が自分の Sandbox を片付けます。SIGKILL で止めると
  harness は片付けられないので、namespace、プロセス、作業ディレクトリが残ります。`run` は
  流し始めに毎回 `gc` を呼ぶので、前回 SIGKILL で終わった残骸は次の `run` の前に消えます。
  すぐに残骸を消したいときは `labhost gc` を単独で呼びます。`gc` も Lab Host のロックを取るので、
  流れている `run` があるときは断ります

### シナリオ側の約束

確認は shell のまま動かします。Sandbox の値は環境変数で渡し、[lab/sandbox.sh](sandbox.sh) が
受け取ります。

| 環境変数 | 内容 | 既定 |
|---|---|---|
| `WGFT_LAB_CLIENT_NS` | client の network namespace の名前 | `client` |
| `WGFT_LAB_VPS_NS` | vps の network namespace の名前 | `vps` |
| `WGFT_LAB_ROUTER_NS` | homerouter の network namespace の名前 | `homerouter` |
| `WGFT_LAB_HOME_NS` | home の network namespace の名前 | `home` |
| `WGFT_LAB_LAN_NS` | lan の network namespace の名前 | `lan` |
| `WGFT_LAB_WORKDIR` | データディレクトリ、ログ、scratch ファイルの置き場 | `/tmp` |
| `WGFT_LAB_SANDBOX` | Sandbox の ID。設定されているときだけ後片付けが Sandbox の範囲に閉じます | 空 |

これらの変数が未設定のときの既定は、従来の共有トポロジと `/tmp` なので、
`lab/lab exec vm bash /wgft/lab/e2e.sh kernel` の流し方は変わりません。従来の 1 確認 1 VM の
流し方も、そのまま残っています。

新しい確認を Sandbox で流せるようにする手順は 3 つです。

1. `. "$(dirname "$0")/sandbox.sh"` を読み込みます
2. 固定の `/tmp/...` の道を `$W/...` に変えます。データディレクトリ、ログ、scratch ファイル、
   fifo、鍵のファイルのすべてが対象です
3. network namespace の名前を `$VPS_NS` などの変数から取り、プロセスの停止を
   `sandbox_kill_named`、`sandbox_pids_named`、`sandbox_any_named`、`sandbox_kill_cmdline` に
   置き換えます。`pkill`、`pgrep`、`pidof` は VM 全体を見るので使いません

`lab/netns.sh` は同じ 5 つの変数を読み、名前を変えたトポロジを何組でも組めます。veth は
`ip link add ... netns X peer name ... netns Y` で両端を目的の namespace に直接作るので、
並行して組んでも root namespace で名前が衝突する瞬間がありません。

`version-skew.sh` の取得キャッシュ (`/tmp/wgft-version-skew-cache`) は、Lab Host VM で 1 つだけ
持つ共有の置き場のままです。同じ版を同時に取りに行っても壊れないよう、書き手ごとに別の一時
ファイルを同じディレクトリに作り、`mv` で置き換えます。

### Lab Host VM の大きさ

Sandbox が 1 つ増えるごとにメモリはおよそ 47 MiB 増えます。ラボでの実測では、2 vCPU / 2 GiB の
Lab Host VM のまま Sandbox を 32 個まで並列に流せ、そのときのピークのメモリは 1828 MiB 中
1808 MiB でした。メモリの上限に近づくのはこの並列数からで、それ以上に増やすには
`WGFT_LAB_MEM` を大きくする必要があります。

一式を並列数 8 で流すだけなら、`lab/lab up` が既定で作る 2 vCPU / 2 GiB の VM で足ります。
10 回の実測 (check 9 がまだ `exclusive-timing` だった時点) は 337.5 秒から 338.3 秒、ピークの
メモリは 808 MiB から 836 MiB、CPU は 33 秒でした。8 vCPU / 8 GiB の VM で同じ一式を流しても
速くはなりませんでした。制約はメモリで、CPU ではありません。

check 9 を `parallel` に移した前後を 1 回ずつ実測すると、移す前が 339.3 秒、移した後が 313.7 秒
でした。単独で流していた check 9 kernel (約 37 秒) と check 9 userspace (対象外で即 SKIP) の分だけ
縮んだ差で、10 回の実測ではなく前後 1 回ずつの比較です。

一式の所要時間のうち約 240 秒は、単独で流す確認を 1 つずつ流す時間です (check 9 を移した後は単独の
確認が 10 個から 8 個に減っています)。Lab Host VM を 2 台にして、1 台に並列のプール、もう 1 台に
単独の待ち行列を割り当てると、一式は約 240 秒に縮む見込みです (未確認)。

CPU は、この実測の範囲では制約になっていません。2 vCPU のまま並列数を 1 から 32 まで上げても、
1 つあたりの確認の壁時計の時間はほぼ変わらず (約 39 秒から 42 秒)、並列数に応じて全体の時間が
ほぼ線形に縮みました。Lab Host VM の大きさを決める要因はメモリであり、CPU ではありません。

`incus config set <vm> limits.cpu` と `limits.memory` による実行中の Incus VM への設定変更は、
Incus 側では受け付けられても、ゲスト側の `nproc` と `MemTotal` には反映されないことをラボで
確かめました。Lab Host VM を大きくするときは、`WGFT_LAB_CPU` と `WGFT_LAB_MEM` を設定してから
`lab/lab up` を実行し、VM を新しく作り直します。
