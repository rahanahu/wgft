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

初回の `up` は VM の作成、パッケージとカーネルの導入、スナップショット、トポロジの構築を行います。
2 回目以降は起動とトポロジの構築を行います。
トポロジの構築では、VM の `net.core.rmem_max` と `net.core.wmem_max` を[ソケットのバッファの手順](../docs/manual/socket-buffers.ja.md)の 7340032 に設定します。
ラボは server と agent を権限のない利用者でも動かすため、ユーザー空間モードの動作条件を満たした状態で確認を流します。
この 2 つの値を下げる確認は `lifecycle.sh` の check 12 だけで、単独で流れ、終了時に値を戻します。
`labhost run` は、プールの前と単独の確認の前にこの 2 つの値が 7340032 を下回る場合に警告し、`summary.json` の `warnings` にも記録します。
警告が出た VM では `lab/lab net up` を実行し直します。
`build` はホストでビルドし、VM の `/usr/local/bin` にインストールします。
`run all` の対象は [lab/suite.txt](suite.txt) の `default=yes` の確認で、両モードを含みます。
結果は PR の本文に記録します。

ユーザー空間モードのエージェントを wgstack で動かすときは、ホストで `WGFT_LAB_AGENT_NETSTACK=wgstack` を付けて実行します。
`lab/lab` はこの値を VM の中のコマンドに `WGFT_AGENT_NETSTACK` として渡し、確認が起動するエージェントがそれを継ぎます。
カーネルモードのエージェントは、値を使わない旨を出して起動します。
wgstack の選択で一式を流して確かめたのは、ユーザー空間モードのエージェントを使う行です。
カーネルモードのエージェントを使う `agentkernel.sh` の行は、2 行だけをこの選択で試しました。
未設定なら何も渡さず、既定の gvisor で動きます。

```sh
WGFT_LAB_AGENT_NETSTACK=wgstack lab/lab exec vm labhost run -parallel 8 all
```

ユーザー空間モードのエージェントを Rust の agent に替えるときは、ホストで `WGFT_LAB_AGENT_IMPL=rust` を付けます。
扱いは[Rust の agent で流す](#rust-の-agent-で流す)にあります。

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

## 一式を複数の VM に分けて流す

`lab/lab suite` は一時的な VM を作り、`run all` の仕事を shard に分けて同時に流します。
各 shard の結果は 1 つの判定にまとめ、最後に VM を消します。
VM の台数は `--vms` で指定し、既定は 3 台です。
各 VM はテンプレートと同じ大きさで、`lab/lab up` の既定では 2 vCPU と 2 GiB のメモリを使います。
`--vms 2` にすると VM 1 台分のメモリが空きますが、測った 1 回では統合までが 490 秒で、3 台の 329 秒より長くかかりました。
レートの時間窓に最も近かった別の VM の守る確認との間隔も、測った 1 回ずつでは 2 台が 19 秒、3 台が 69 秒でした。
1 台で流すより周期が短くなる代わりに、単独で流す確認の約束が VM の間で弱くなります。
1 台の VM で流す `labhost run -parallel 8 all` が厳密な形です。

```sh
lab/lab suite
lab/lab suite --vms 2
lab/lab suite --vms 2 --netstack both
lab/lab suite --vms 3 --netstack wgstack --durations earlier/summary.json
lab/lab suite --vms 2 --agent-impl rust
lab/lab suite --vms 2 --netstack both --agent-impl both
```

`--agent-impl` はユーザー空間モードのエージェントの実装を `go`、`rust`、`both` から選び、既定は `go` です。
一式は組 (エージェントの実装と netstack) ごとに流します。
Rust の agent は netstack を 1 つしか持たないので、`rust` の組は `--netstack` によらず 1 回だけ流します。
`--netstack both --agent-impl both` の組は、`go` と既定の netstack、`go` と `wgstack`、`rust` の 3 つです。

### 単独の確認の扱い

VM の中では、`exclusive-*` の確認は 1 台で流す場合と同じく単独で流れます。
VM の間ではホストの CPU、メモリ、ネットワークを分け合うので、単独の確認も別の VM の確認と同時に流れます。
守るのはレートを測る時間窓だけです。
時間窓は、[suite.txt](suite.txt) で `rate=measure` を持つ `rates.sh` の確認が走る間です。
`rate=group` を持つ `lifecycle.sh` の単独の確認は、時間窓と同じ VM に置き、`rates.sh` の後に流します。

別の VM で時間窓から離しておく確認は 2 種類です。
1 つは `rate=overlap` を持たない単独の確認で、その VM の単独の段の中の自分の順番の時間で見ます。
もう 1 つは `rate=flood` を持つ `parallel` の確認で、フラッドや大量の転送を流します。
`connlimit.sh`、`lifecycle.sh userspace` の 5c と 5d、`usage.sh` がこれに当たり、選んだ理由は suite.txt にあります。
プールのどこで走るかは決まらないので、プールの始まりから終わりの見積もりまでの全体をその時間とみなします。
どちらも、見積もりの時間が時間窓の前後 30 秒の中に入らないように割り当てます。
この秒数は `labhost run` の `-rate-margin` です。
入りそうな確認は、入らない VM のうち全体が最も早く終わる VM へ移します。
時間窓の VM はいつも移し先の候補で、その VM ではプールが時間窓の前に終わり、単独の確認は 1 つずつ流れます。
移すので、VM を増やしても時間窓の VM より短い周期にはなりません。
例外は `rate=overlap` を持つ `exhaustion.sh userspace postclose` で、時間窓と重なることがあります。
`rate=flood` を持たない `parallel` の確認は、別の VM で時間窓の間も流れます。
守れない割り当てになった場合は、守りを外さずに `labhost run` が警告を出し、`summary.json` の `warnings` に記録します。

割り当ては見積もりに基づくので、実際の所要時間が見積もりと違えば、時間窓と重なることがあります。
`labhost merge` は各確認の実際の開始の時刻と所要時間から重なりを調べ、統合した結果の `rate_window` に書きます。
重なった場合は、その確認の名前と重なった秒数を `warnings` に記録します。
重ならなかった場合は、時間窓に最も近かった確認とその間隔を書きます。
`--netstack both` では 2 つの netstack の割り当てが同じになり、shard が同時に始まるので、2 つの `rates.sh` の時間窓が互いに重なります。
時間窓はそれぞれの netstack の shard の間でだけ守ります。

### 一時的な VM

一時的な VM は `WGFT_LAB_TEMPLATE` のスナップショット `clean` の複製で、`WGFT_LAB_TEMPLATE` の既定は `WGFT_LAB_VM` です。
`lab/lab up` で作った VM があれば足ります。
複製は CPU とメモリの上限をスナップショットから継ぎ、リポジトリの共有はこの作業ツリーを指します。
CPU の固定は[VM の CPU の固定](#vm-の-cpu-の固定)に従います。
スナップショットが無い場合は `lab/lab up` と同じ手順で VM を新規に作るので、遅くなります。
ビルドはホストで 1 回行い、各 VM にインストールします。
各 VM の用意がそろってから、すべての shard が同時に `labhost run` を始めます。
用意に 900 秒を超える VM があれば、その VM を待たずに始めます。
`--netstack both` は既定の netstack と `wgstack` を同時に流すので、VM の台数は `--vms` の 2 倍です。
VM の台数は一般に `--vms` と組の数の積です。
ホストの空きに合わせて、同時に立てる VM は 4 台までを目安にし、`--netstack both` には `--vms 2` を付けます。

### VM の CPU の固定

`WGFT_LAB_CPUS` にホストの CPU の集合を `0-7` や `0-3,8` の形で指定すると、`lab/lab` が作る VM の vCPU を集合の中の CPU に 1 対 1 で固定します。
ホストの残りの CPU を計測などの別の仕事に空けておく場合に使います。
対象は `lab/lab up` が新しく作る VM と、`lab suite` の一時的な VM です。
既にある VM の固定は変えません。
Incus は動いている VM の固定を変えられないので、固定を変える場合は VM を作り直します。
vCPU の数は固定しない場合と同じです。
`lab/lab up` は `WGFT_LAB_CPU` の数の CPU を集合の先頭から取ります。
`lab suite` は複製のもとのスナップショットの vCPU の数を変えず、各 VM に集合の CPU を先頭から順に重ならないように割り当てます。
集合の CPU が足りない場合は、VM を作る前に止まります。
割り当てが分けるのは 1 回の `lab suite` の VM の間だけです。
ほかの固定した VM、`wgft-lab` 自体、同じ集合を指定して同時に流す別の `lab suite` は考慮しないので、重ならない集合を指定します。
2 vCPU の VM では、`--vms 2 --netstack both` の 4 台が 8 個の CPU を使い、`0-7` に収まります。
`--vms 3 --netstack both` は 12 個の CPU を使うので、`0-7` では止まります。
未設定なら固定せず、`limits.cpu` に vCPU の数だけを指定して作ります。
固定した VM を `WGFT_LAB_CPUS` を指定せずに複製すると、すべての一時的な VM が同じ CPU に固定されるので、`lab suite` はその旨を出します。
固定されるのは vCPU のスレッドだけで、qemu のほかのスレッドはホストのすべての CPU で動きます。
計測の隔離にはなりません。
固定した一式を流しながら残りの CPU で計った byte あたりの CPU の値は、一式を流さない場合と比べて 5% 以上高くなり、固定しない場合より揺れが減ることは確かめられませんでした。

```sh
WGFT_LAB_CPUS=0-7 lab/lab suite --vms 2 --netstack both
```

### 割り当て

shard の割り当ては `labhost run -shard K/N all` が決めます。
重い仕事から順に、見積もりが最も小さい VM へ置きます。
見積もりは `--durations` に渡した以前の `summary.json` の所要時間で、無い仕事は [suite.txt](suite.txt) の `weight=`、それも無い仕事は 10 秒です。
割り当ては入力が同じなら同じです。
最も長い仕事より短い周期にはならないので、台数を増やしても周期はそこで止まります。
台数が多すぎて仕事の無い shard ができると、その shard は失敗します。

### 結果と終了コード

各 shard の結果は `--out` の下の `<エージェントの実装>/<netstack>/shard-K/` に残り、`summary.json`、`logs/`、`shard.log`、VM のカーネルの版を書いた `kernel` があります。
組ごとの見出しは `==== lab suite: agent=<実装>, netstack=<netstack>, N VMs` です。
統合の前の shard ごとの行にも、カーネルの版が出ます。
`--out` の既定は `/tmp/wgft-lab-suite-<日時>` です。
統合した判定は `<エージェントの実装>/<netstack>/summary.json` です。
各 shard の `summary.json` は、割り当ての要約の `plan_digest` と、確認が使った `netstack` と `agent_impl` を記録します。
統合は、どの shard でも流れなかった仕事、2 つの shard で流れた仕事、足りない shard、`plan_digest` の違い、`netstack` の混在、`agent_impl` の混在を失敗にします。
これらは `MERGE FAILURE` として、仕事の名前とともに出ます。
`rust` の組の統合は、`agent=go` の仕事の結果を最初の `go` の組の統合から取り、`from go:` の行で示します。
この行は `rust` の組の件数と終了コードに入りません。
`go` の組を流さなかった場合は、その旨を出します。
`go` の組の `summary.json` が読めない場合は警告にし、`rust` の組の統合はそのまま書きます。
1 つの shard の `labhost run` は `--shard-timeout` の秒数で止め、その shard は `summary.json` の無い失敗になります。
`summary.json` の無い shard があっても、ある分を統合し、どの shard でも流れなかった仕事を名前で出します。
秒数の既定は 3600 で、環境変数 `WGFT_LAB_SHARD_TIMEOUT` でも指定できます。
結果の回収は 1 回 300 秒で打ち切ります。
終了コードは、組ごとの結果を合わせたものです。
組の結果は、どれかの shard の失敗、VM の中の後片付けの漏れ、中断、統合の不整合で失敗になります。
`go` の組も流したときも、`rust` の組の失敗を終了コードに入れます (`lab/lab` の `SUITE_RUST_GATES`)。
「UDP の中継」の段までは報告だけでした。
`rust` の組だけを流したときは、その結果が終了コードです。
VM の削除の失敗は、終了コードに入れません。
最後に統合までの所要時間を出し、VM を消した後に削除までを含めた所要時間を出します。

INT や TERM による中断と失敗でも VM を消します。
SIGKILL で残った VM は、作った `lab/lab` のプロセスがもう無ければ、次の `lab suite` の開始時か `lab/lab suite-gc` が消します。
生死は `/proc` で見るので、同じホストの他の利用者が実行中の `lab suite` の VM も消しません。
`--keep` を付けると VM を残します。

1 台の VM で 1 つの shard を流すことと、shard の統合は、次のように直接も行えます。

```sh
lab/lab exec vm labhost run -shard 1/3 -durations /tmp/earlier.json -parallel 8 all
labhost merge -out merged shard-1/summary.json shard-2/summary.json shard-3/summary.json
```

## Rust の agent で流す

ホストの変数 `WGFT_LAB_AGENT_IMPL` は、ラボの確認が起動するユーザー空間モードのエージェントの実装を選びます。
値は `go` と `rust` で、未設定は `go` です。
`lab/lab` はこの値を VM の中のすべての実行にそのまま渡します。
`lab suite` の `--agent-impl` は、組ごとにこの値を決めます。
完成の条件と確認の分け方は[Rust の agent の置き換えの設計](../docs/design/v2/agent-parity.md#ラボの切り替え)にあります。

```sh
WGFT_LAB_AGENT_IMPL=rust lab/lab build
WGFT_LAB_AGENT_IMPL=rust lab/lab exec vm labhost run -parallel 8 all
WGFT_LAB_AGENT_IMPL=rust lab/lab exec vm bash /wgft/lab/e2e.sh kernel
```

`rust` のとき、`lab/lab build` は Go のバイナリに加えて Rust の `wgft` を `cargo zigbuild --release --locked --target x86_64-unknown-linux-musl -p wgft` で musl の静的バイナリにし、`bin/rust/wgft` に置きます。
ホストに cargo-zigbuild と zig が要ります。
VM の中では `/usr/local/lib/wgft-rust/wgft` に置きます。
ファイル名を `wgft` に保つのは、確認がプロセスを comm の `wgft` と cmdline の ` agent run` で探すためです。
`lab-eph.sh` で流す場合も、同じ値を環境に付けます。

確認の台本は、ユーザー空間モードのエージェントの `agent run` と、それに向けた `agent doctor`、`agent rotate-key`、`agent pubkey` を `"$AGENT_WGFT"` で呼びます。
[lab/sandbox.sh](sandbox.sh) が `AGENT_WGFT` を決め、`rust` なら `/usr/local/lib/wgft-rust/wgft`、それ以外は `wgft` です。
カーネルモードのエージェントの起動と、それに向けた `agent doctor`、`agent rotate-key`、`agent teardown` は Go の `wgft` のままで、行末に `# lab: go agent` を付けます。
server と VPS の側のコマンドも `wgft` のままです。
`tools/labhost` の試験 `TestScenariosCallTheAgentThroughAgentWgft` は、`lab/*.sh` の中で agent のホストのコマンドを `wgft` の名前のまま呼び、印の無い行を見つけます。
変数を通した呼び出しは、この試験には見えません。

[suite.txt](suite.txt) の `agent=go` の確認は、どの組でも Go の agent を動かします。
`agentkernel.sh`、`agentdoctor.sh` のカーネルモードの節、`exhaustion.sh userspace mss`、`exhaustion.sh kernel postclose` です。
`rust` の組の `labhost run all` はこれらを流さず、`lab suite` が `go` の組の結果を示します。

Go の実行環境に依る読み取りは、Rust の agent では次のように読み替えます。

- `lifecycle.sh` の check 5 と 5b:エージェントの `memory soft limit:` の行の代わりに `memory bound:` の行を読み、RSS がその値と 32 MiB の和を超えないことを確かめます。
  あわせて、洪水の前 (トンネルと待ち受けを開いた後) に RSS を測り、洪水の間の育ちが `memory bound terms:` の行のうち洪水が満たせる項 (`core fixed`、`tables`、`driver`、`device`、`tcp relay`、`udp relay` と、洪水が使った接続の枠の配列) の和に 32 MiB を足した値を超えないことを確かめます。
  洪水が使った接続の枠の配列は、エージェントの最後の `connection slots used so far` の行の KiB です。
  洪水はデータを運ばないので、`tcp bulk` と `core flows` は入れません。
  項の分け方は [agent-parity.md](../docs/design/v2/agent-parity.md#メモリの上界の行) にあります
- `exhaustion.sh` の acceptq と ackflood:エージェントの GC の記録が無いので、ヒープの値を示さず RSS だけを示します
- `agentmem.sh`:Go の agent のメモリの probe に依るので、`SKIP` を 1 行出して何もしません
- `agentdoctor.sh` の userspace の節:`AGENTDOCTOR_BASELINE` の既定を Go の `wgft` にし、Go の CLI が Rust の agent の制御ソケットから読む ID と状態と理由が、Rust の CLI と同じことを確かめます

`lab/agent-handover.sh` は、Go の agent と Rust の agent が互いの `agent.json` を引き継ぐことを、変更していない Go の v1 の server に対して確かめます。
Rust の agent が自分で登録した `agent.json` から Go の agent が動くことと、その逆を、TCP の転送の SHA-256 の比較まで確かめます。
両方のバイナリが要るので、suite.txt では `default=no` です。

```sh
WGFT_LAB_AGENT_IMPL=rust lab/lab build
lab/lab exec vm bash /wgft/lab/agent-handover.sh kernel
lab/lab exec vm bash /wgft/lab/agent-handover.sh userspace
```

今の Rust の agent は Rust の wgstack の上で動き、root も TUN も要りません。
`rust` の組の扱いは [テストの規範](../docs/development/testing.md#マージの前に流すテスト) にあります。

## byte あたりの CPU を組にして比べる

`lab/lab paired` は、2 つの腕のエージェントの byte あたりの CPU を、一時的な VM 2 台で同時に測って比べます。
変更の前後と、2 つの netstack や実装の比べに使います。
測り方の理由と参照の値は[CPU の比べ方](../docs/design/userspace/wgstack-performance.md#cpu-の比べ方)にあります。

```sh
WGFT_LAB_PAIR_CPUS="16-23 8-15" lab/lab paired fast wgstack gvisor
WGFT_LAB_PAIR_CPUS="16-23 8-15" lab/lab paired --direction up rate rust wgstack
WGFT_LAB_PAIR_CPUS="16-23 8-15" lab/lab paired --base origin/main fast wgstack base:wgstack
WGFT_LAB_PAIR_CPUS="16-23 8-15" lab/lab paired --tool iperf3 --streams 4 fast rust kernel
WGFT_LAB_PAIR_CPUS="16-23 8-15" lab/lab paired --tool iperf3 --udp-ping --direction up fast rust gvisor
```

経路は `lab/tcpquality-cpu.sh` の `fast` か `rate` で、`--direction up` でエージェントが受ける向きにします。
腕は `lab/tcpquality.sh` のユーザー空間モードの `gvisor`、`wgstack`、`rust` です。
`gvisor` と `wgstack` は Go の agent をその netstack で動かし、`rust` は Rust の agent を動かします。
`kernel` はカーネルの WireGuard とカーネルの TCP で、WireGuard と TCP の仕事がエージェントのプロセスの外にあります。
エージェントの byte あたりの CPU がほぼ 0 になるので、`kernel` の腕は VM 全体の byte あたりの CPU だけで比べ、`--tool iperf3` を要します。
`userspace` は `gvisor` と同じなので、腕にできません。
`--tool iperf3` は転送を iperf3 にし、1 回の実行を 10 秒の転送にします。
`--streams N` は iperf3 の並行の TCP 接続の数です。
iperf3 は送り手と受け手の byte あたりの CPU が `tcpquality.py` より小さいので、カーネルの速さの腕でも測る道具の CPU が値を占めません。
`--udp-ping` は、`--tool iperf3` の実行ごとに、同じエージェントの UDP の規則を通る 100 byte の datagram の往復の時間を、何もしていない時と TCP の転送の間に測ります。
解析の `LAT` の行が腕ごとの p50、p99、最大、jitter と失った数を、`LATRATIO` の行が p99 と jitter の比を出します。
`--bulk-mbit N` は iperf3 の stream ごとの速さを N Mbit/s で頭打ちにし、2 つの腕に同じ負荷を掛けます。
`--agent-gso on` は、`fast` の経路で、エージェントの `eth0` の UDP の segmentation offload を切らずに測ります。
解析の `MBITRATIO` の行は、組にした速さの比です。
`base:<モード>` は、`--base` の commit の build で同じモードを動かします。
`--base` は commit をホストの `~/.cache/wgft-lab/` の一時的な worktree に取り出し、`wgft` を `bin/base/` に作ります。
腕に `rust` があれば、Rust の `wgft` も作ります。
`--base-rust-target` は base の Rust の `wgft` の target を変えます (既定は `x86_64-unknown-linux-musl`)。
`--base HEAD --base-rust-target x86_64-unknown-linux-gnu.2.41` と腕 `rust base:rust` で、同じ commit の musl と glibc の build を比べます。
比は 1 つ目の腕 x の値を 2 つ目の腕 y の値で割ったものです。

手順は次のとおりです。

- 用意:ビルドはホストで 1 回行い、2 台の VM にインストールします。
  VM は `lab suite` と同じく `WGFT_LAB_TEMPLATE` のスナップショット `clean` の複製で、5 秒ずらして起動します。
  2 台を同時に起動すると片方が上がらないことがあったためで、上がらない VM は 1 回だけ作り直します
- 固定:`WGFT_LAB_PAIR_CPUS` に VM a と VM b の CPU の集合を空白で区切って指定すると、各 VM の vCPU を集合の先頭の `--vcpus` 個 (既定 4) に固定します。
  2 つの集合が重なれば止まります。
  ハイブリッドの CPU では、2 つの集合を同じ種類のコアにします。
  未設定なら固定しません
- round:各 round で 2 台が同時に `tcpquality-cpu.sh <経路> <モード>` を `SYNC=1` で流します。
  奇数の round は x が VM a、偶数の round は x が VM b です。
  `--rounds` (既定 4) は偶数で、round ごとにエージェントを起動し直して `--runs` (既定 3) 回流します
- 始まりの同期:`tcpquality.sh` は実行ごとに `SYNC ready` を出して待ちます。
  ホストは 2 台がそろうと、1 秒先の時刻をそれぞれの VM の時計に直して書き、2 台はその時刻に client を繋ぎます。
  VM の時計はホストの時計と 1 秒ほどずれることがあり、2 台の間でも違ったので、ホストは round の始めに `incus exec` の往復の中点で各 VM の時計の差を測ります。
  時計の差が round の間に 50 ms を超えて動いた場合と、始まりの時刻が過ぎてから届いた実行は、警告を出します。
  片方の VM の `tcpquality-cpu.sh` が途中で終了した場合は、残りの VM だけを進め、その実行は組になりません
- 解析:`tcpquality.py cpupaired` が、同じ round と実行の番号の 2 つの実行を組にし、x の値を y の値で割ります。
  x が VM a の組の比の中央値と、x が VM b の組の比の中央値の幾何平均を比として出し、組を引き直す bootstrap の 95% の区間を付けます。
  2 台の CPU の差は `vm_a_over_b` に出ます。
  失敗した実行、始まりの同期を待ちきれなかった実行、送り手が 1 つの CPU の 0.7 以上を使った実行を含む組は除き、予定の組の数に対する理由ごとの数を出します。
  iperf3 の送り手の値は、stream ごとに 1 つのスレッドを使うので stream の数で割ります。
  どちらかの側で予定の組の半分より少なくしか残らなければ、比を出さずに失敗します。
  round ごとの比の中央値と、組の 2 つの実行が重なった割合も出し、重なりが 0.9 より小さければ警告します。
  VM 全体の byte あたりの CPU (`/proc/stat` の user、nice、system、irq、softirq の和) も同じ形で比べ、行の名前の頭に `VM` を付けて (`VMRATIO` など) 出します。
  `kernel` の腕を含む比べには `RATIO` の行が無く、そのことを示す 1 行が出ます

結果は `--out` (既定は `/tmp/wgft-lab-paired-<日時>`) の `result.txt`、組の行の `paired.log`、round と VM ごとのログです。
`FAIL` の行があるか組が足りない場合は、終了コードが 0 以外になります。
VM は終わると消し、`--keep` を付けると残します。
残った VM は `lab/lab suite-gc` が消します。

## 対応する VPS の環境

カーネルと nftables の対応範囲は[セットアップの前提](../docs/manual/setup.md)に従います。
既定の VM は `images:debian/13` です。
Debian 13 の VM には、`lab/lab` の `LAB_KERNEL_ABI` と `LAB_KERNEL_VERSION` が固定する trixie-backports のカーネルを入れ、そのカーネルで起動し直してからスナップショットを取ります。
trixie-backports は新しい版が出ると古い版を消すので、package は snapshot.debian.org の `LAB_KERNEL_SNAPSHOT` の時刻の trixie-backports から取ります。
起動し直した後に別のカーネルで動いていれば、`up` は止まります。
固定を上げた後に、前の版で作った VM で `up` が止まった場合は、`lab/lab destroy` と `lab/lab up` で作り直します。
このカーネルは wgstack の適合の試験の参照の Linux で、版の記録は[参照の Linux の設定](../docs/design/userspace/wgstack-verification.md#参照の-linux-の設定)にあります。
Debian 13 は `/tmp` を tmpfs にしますが、ラボの VM では Debian 12 と同じくディスクに置きます。
ラボの VM では、パッケージの一覧の更新などの定時の仕事と、tty1 の getty と polkit を止め、journal を 32 MiB までにします。
定時の仕事が確認の最中に走って CPU とメモリを使わないようにするためです。
別のディストリビューションの VM は、イメージと名前を指定して作成します。
Debian 13 以外のイメージには固定したカーネルを入れず、イメージのカーネルのまま動かします。

```sh
WGFT_LAB_IMAGE=images:debian/12 WGFT_LAB_VM=wgft-lab-debian12 lab/lab up
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
lab/lab test internal/nettun vps -test.run='^(TestRelayHold|TestSetupFailure)OutOfOrderKernelData$'
lab/lab test internal/tcpharness/linuxdut
lab/lab exec vm bash /wgft/lab/tcpquality.sh
lab/lab exec vm bash /wgft/lab/tcpquality-cpu.sh fast
lab/lab exec vm bash /wgft/lab/scale.sh kernel
lab/lab exec vm bash /wgft/lab/scale.sh userspace
lab/lab exec vm bash /wgft/lab/upgrade.sh kernel
lab/lab exec vm bash /wgft/lab/upgrade.sh userspace
```

これらの直接実行は共有トポロジを使うため、同じ VM の他の実行が終了してから行います。
`tcpquality.sh` のモードと変数 (`TOOL=iperf3`、`STREAMS`、`IPERF_S`、`CPU=1` の値) はスクリプトの冒頭にあります。
`tcpquality.sh` は、エージェントの namespace の `eth0` の UDP の segmentation offload を切ってから測り、終了時に元の状態に戻します。
wireguard-go の Linux のバインドは同じ大きさの datagram の列を 1 つの UDP の GSO の packet で送り、veth はこの packet を分けずにルータへ渡します。
ルータの netem はこの packet を 1 つとして待ち行列に数え、損失も packet ごとに決めるので、実際の回線の待ち行列には無いまとまった遅れと損失が生じます。
理由は[ラボの経路の UDP の GSO](../docs/design/userspace/wgstack-performance.md#ラボの経路の-udp-の-gso)を参照してください。
`lab/lab test` はテストのバイナリをその場で作ります。
ほかの行は VM にインストールしたバイナリを使うので、先に `lab/lab build` を実行します。
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
| `WGFT_LAB_AGENT_IMPL` | ユーザー空間モードのエージェントの実装です。`AGENT_WGFT` を決めます | `go` です |

新しいシナリオは `sandbox.sh` を読み込み、ファイルを `$W/` の下に置き、namespace を `$VPS_NS` などの変数から取得します。
ユーザー空間モードのエージェントは `"$AGENT_WGFT"` で起動し、Go の agent を意図して呼ぶ行には行末に `# lab: go agent` を付けます。
プロセスの操作は `sandbox_kill_named`、`sandbox_pids_named`、`sandbox_any_named`、`sandbox_kill_cmdline` を使います。
VM 全体を見る `pkill`、`pgrep`、`pidof` は使いません。
`version-skew.sh` のキャッシュは VM で共有し、別の一時ファイルから `mv` で置き換えます。

### Lab Host VM の大きさ

既定の 2 vCPU / 2 GiB で一式を並列数 8 で実行した記録があります。
現在の一式の費用は実行時の `metrics.csv` で確認します。
VM を大きくする場合は `WGFT_LAB_CPU` と `WGFT_LAB_MEM` を指定して新しく作成します。
vCPU を特定の CPU に固定する場合は、同時に `WGFT_LAB_CPUS` を指定します([VM の CPU の固定](#vm-の-cpu-の固定))。
実行中の `incus config set` の変更がゲストの `nproc` と `MemTotal` に反映されなかった記録があります。

<a id="確認済み管理用-api-のアクセス経路2026-09-15"></a>
## 管理用 API の確認記録

[当時の確認条件](https://github.com/rahanahu/wgft/blob/c5a6dc454468733e9ff4b2a4eb2b5a17ed4bdf4e/lab/README.md#確認済み管理用-api-のアクセス経路2026-09-15)は旧版の文書を参照します。
現在の経路と制約は[管理の接続経路](../docs/design/security/admin-transport.md)に従います。

<a id="確認済み実-caddy-での-https-経路"></a>
## Caddy の確認記録

[lab/caddy/README.md](caddy/README.md)に確認手順と記録があります。
