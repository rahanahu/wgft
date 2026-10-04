# lab:wgft の開発用ラボ

Incus の VM で nftables、WireGuard、conntrack の実験と結合テストを実行します。
実行の契機と必須条件は[テストの規範](../docs/development/testing.md)に従います。

## 開発環境の方針

コードの編集と `go test` はホストで行い、カーネル機能の実験と結合テストは VM の network namespace で行います。
ホストのカーネルや Docker の `br_netfilter` による結果の混入を避けるため、Docker は開発用ラボに使いません。
配布用イメージの確認は `scripts/docker-smoke.sh` が担当します。
ホストのリポジトリは VM の `/wgft` に読み取り専用で共有します。

## 前提

- Incus:開発者が `incus-admin` グループに属している必要があります。ログインし直す前でも `lab` は `sg` で実行します。
- Go:ホストでビルドに使います。

## 使い方

```sh
lab/lab up
lab/lab status
lab/lab build
lab/lab exec vm labhost run -parallel 8 all
```

初回の `up` は VM の作成、パッケージの導入、スナップショット、トポロジの構築を行います。
2 回目以降は起動とトポロジの構築を行います。
`build` はホストでビルドし、VM の `/usr/local/bin` にインストールします。
`run all` の対象は [lab/suite.txt](suite.txt) の `default=yes` の確認で、両モードを含みます。
結果は PR の本文に記録します。

```sh
lab/lab test internal/dataplane/linuxkernel/nft
lab/lab exec client ping 198.51.100.1
lab/lab shell home
lab/lab exec vps wgft server run --help
```

`test` は `lab` の build tag を付けたテストを VM の vps namespace で実行します。
VM の中ではインストールされた名前を使い、`/wgft/bin` のバイナリを直接実行しません。

`lab/lab reset` は VM をスナップショットに戻し、`lab/lab destroy` は VM を削除します。
共有中の VM では、実行中の作業と所有者を確認してから行います。

## 対応する VPS の環境

カーネルと nftables の対応範囲は[セットアップの前提](../docs/manual/setup.md)に従います。
既定の VM は `images:debian/12` です。
別のディストリビューションの VM は、イメージと名前を指定して作成します。

```sh
WGFT_LAB_IMAGE=images:ubuntu/24.04 WGFT_LAB_VM=wgft-lab-ubuntu lab/lab up
WGFT_LAB_IMAGE=images:fedora/44 WGFT_LAB_VM=wgft-lab-fedora lab/lab up
```

`lab/lab` は `/etc/os-release` の `ID` で apt と dnf を選びます。
過去の確認条件と未確認の範囲は[追加テストの台帳の C4](../docs/development/testing-catalog.md#c4-ラボの一式を別のディストリビューションで)にあります。

## トポロジ

```text
client -- vps -- homerouter(NAT) --+-- home(agent)
                                 +-- lan
```

home と lan は homerouter の br0 に接続し、同じ自宅 LAN セグメントを使います。
lan の既定のゲートウェイは homerouter です。

| namespace | インタフェース | アドレス | 役割 |
|---|---|---|---|
| client | eth0 | 198.51.100.2/24、2001:db8::2/64 | 公開側の利用者です |
| vps | pub0 | 198.51.100.1/24、2001:db8::1/64 | client 側です |
| vps | pub1 | 203.0.113.1/24 | WireGuard とエージェント API の側です |
| homerouter | wan0 | 203.0.113.2/24 | home と lan を masquerade します |
| homerouter | br0 | 192.168.50.1/24 | 自宅 LAN のブリッジです |
| home | eth0 | 192.168.50.2/24 | エージェントです |
| lan | eth0 | 192.168.50.3/24 | 自宅 LAN の別ホストです |

client と vps の IPv6 は `lab/ipv6.sh` の拒否の確認に使います。
homerouter の先には IPv6 の経路を作りません。
vps の `ip_forward` は server が起動時に設定します。
VM を再起動すると namespace が消えるため、`lab/lab up` か `lab/lab net up` で構築し直します。

## 既知の問題:VM が IPv4 で外に出られない

Fedora のホストで firewalld と Docker が動いている条件では、VM の IPv4 の転送が失敗した記録があります。
`lab/lab up` は DNS が引けなければ IPv6 の DNS を設定して導入を続けます。
`lab/lab host-fix` はホストの設定を変更するため、表示される変更内容を確認し、ホストの変更を許可された場合に実行します。

## 共有ディレクトリの注意

共有は 9p で行い、デバイスは VM の作成時に追加します。
VM から共有先には書き込めません。
実行中の共有バイナリをホストで上書きすると、古いページと新しいページが混ざる場合があります。
`lab/lab build` は `install` で `/usr/local/bin` に置くため、VM ではその名前で実行します。

## Sandbox: 1 台の VM の中で並べる隔離の単位

[tools/labhost](../tools/labhost) は、確認ごとに network namespace、作業ディレクトリ、プロセスを持つ Sandbox を発行します。
分類と隔離の規範は[テストの規範](../docs/development/testing.md#ラボの一式を隔てる単位)に従います。

### 確認の流し方

```sh
lab/lab exec vm labhost run "e2e.sh kernel"
lab/lab exec vm labhost run -parallel 4 "e2e.sh kernel" "ipv6.sh kernel"
lab/lab exec vm labhost run -parallel 4 -repeat 20 "e2e.sh kernel"
lab/lab exec vm labhost run -parallel 8 all
lab/lab exec vm labhost run -wait 10m -parallel 8 all
lab/lab exec vm labhost list
lab/lab exec vm labhost create
```

`run` と `gc` は VM ごとの `/run/wgft-labhost.lock` を取得します。
2 つ目の `run` は既定では待たず、持ち主の PID を示して終了します。
`-wait` を指定した場合だけ順番を待ちます。
`create` と `destroy` は手作業の Sandbox を名指しして扱い、`run` が所有する Sandbox を操作しません。

`version-skew.sh` は旧版を取得する条件が必要なため、`run all` に含めません。
B7、B11、B12、C3、D4 など一式の外の試験は、契機に従って追加します。
旧版の取得と上書き変数は各スクリプトの冒頭にあります。

```sh
lab/lab exec vm labhost run version-skew.sh
lab/lab exec vm bash /wgft/lab/rcvwin.sh
lab/lab test internal/nettun vps -test.run=^TestRelayHoldOutOfOrderKernelData$
lab/lab exec vm bash /wgft/lab/scale.sh kernel
lab/lab exec vm bash /wgft/lab/scale.sh userspace
lab/lab exec vm bash /wgft/lab/upgrade.sh kernel
lab/lab exec vm bash /wgft/lab/upgrade.sh userspace
```

これらの直接実行は共有トポロジを使うため、同じ VM の他の実行が終了してから行います。
D4 の旧版の選択と確認範囲は[追加テストの台帳](../docs/development/testing-catalog.md#d4-旧版からの更新)に従います。

### 確認の分類

現在の分類は [lab/suite.txt](suite.txt) を参照します。
`parallel` の後に `exclusive-heavy`、`exclusive-timing`、`exclusive-global` の確認を 1 つずつ実行します。
分類を決める規範は[テストの規範](../docs/development/testing.md#ラボの一式を隔てる単位)に従います。

### 失敗した Sandbox の調べ方

```sh
lab/lab exec vm labhost run -keep-failed -parallel 4 all
```

実行の置き場 `/tmp/wgft-lab/run-<日時>/` に、`logs/`、`metrics.csv`、`summary.json` が残ります。
`-keep-failed` は失敗した作業ディレクトリを残しますが、namespace とプロセスは片付けます。
すべての確認が PASS でも後片付けが漏れた場合は非 0 で終わり、`LEFTOVER FAILURE` に対象を表示します。
意図して残したディレクトリは漏れに数えません。

### 後片付け

```sh
lab/lab exec vm labhost gc
```

`gc` は作業ディレクトリのロックで所有者を確認し、持ち主のいない Sandbox だけを片付けます。
実行中の `run` がある場合は、VM のロックを取得できず終了します。
`run` も開始時に `gc` を呼びます。
SIGINT は自分の Sandbox を片付けますが、SIGKILL は残骸を残します。

Sandbox の停止は自分の namespace のプロセス、namespace、作業ディレクトリの順です。
namespace を先に削除すると、名前の無い namespace にプロセスが残ります。
`pkill -x wgft` のような VM 全体の停止は使いません。
確認の shell は 6 つ目の runner namespace に置き、孤児も `gc` で検出します。

### シナリオ側の約束

[lab/sandbox.sh](sandbox.sh) は Sandbox の値を環境変数で受け取ります。

| 環境変数 | 内容 | 未設定時の値 |
|---|---|---|
| `WGFT_LAB_CLIENT_NS` | client namespace です | `client` |
| `WGFT_LAB_VPS_NS` | vps namespace です | `vps` |
| `WGFT_LAB_ROUTER_NS` | router namespace です | `homerouter` |
| `WGFT_LAB_HOME_NS` | home namespace です | `home` |
| `WGFT_LAB_LAN_NS` | lan namespace です | `lan` |
| `WGFT_LAB_WORKDIR` | データ、ログ、scratch ファイルの置き場です | `/tmp` |
| `WGFT_LAB_SANDBOX` | 後片付けの範囲を限定する ID です | 空です |

新しいシナリオは `sandbox.sh` を読み込み、ファイルを `$W/` の下に置き、namespace を `$VPS_NS` などの変数から取得します。
プロセスの操作は `sandbox_kill_named`、`sandbox_pids_named`、`sandbox_any_named`、`sandbox_kill_cmdline` を使います。
VM 全体を見る `pkill`、`pgrep`、`pidof` は使いません。
`version-skew.sh` のキャッシュは VM で共有し、別の一時ファイルから `mv` で置き換えます。

### Lab Host VM の大きさ

既定の 2 vCPU / 2 GiB で一式を並列数 8 で実行した記録があります。
現在の一式の費用は実行時の `metrics.csv` で確認します。
VM を大きくする場合は `WGFT_LAB_CPU` と `WGFT_LAB_MEM` を指定して新しく作成します。
実行中の `incus config set` の変更がゲストの `nproc` と `MemTotal` に反映されなかった記録があります。

<a id="確認済み管理用-api-のアクセス経路2026-09-15"></a>
## 管理用 API の確認記録

[当時の確認条件](https://github.com/rahanahu/wgft/blob/c5a6dc454468733e9ff4b2a4eb2b5a17ed4bdf4e/lab/README.md#確認済み管理用-api-のアクセス経路2026-09-15)は旧版の文書を参照します。
現在の経路と制約は[管理の接続経路](../docs/design/security/admin-transport.md)に従います。

<a id="確認済み実-caddy-での-https-経路"></a>
## Caddy の確認記録

[lab/caddy/README.md](caddy/README.md)に確認手順と記録があります。
