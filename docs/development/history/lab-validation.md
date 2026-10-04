# ラボの確認と測定の記録

<!-- docs-status: historical -->

コミット `8875f37e` の `lab/README.md` から、確認と測定の記録を保存しています。
測定時の一式と現在の一式は異なる場合があり、時間や PASS の行数を現在の期待値に使いません。
現在の分類は[lab/suite.txt](../../../lab/suite.txt)、実行手順は[lab/README.md](../../../lab/README.md)に従います。

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

home ns で実際に Caddy を動かして PROXY protocol、80 の素通し、TLS の終端、拒否の即時反映を確かめた記録は [lab/caddy/README.md](../../../lab/caddy/README.md) を参照。


## Sandbox の分類の測定


[lab/suite.txt](../../../lab/suite.txt) が確認ごとに持つ分類は 4 つです。

| 分類 | 意味 | 対象 |
|---|---|---|
| `parallel` | 他の Sandbox と同時に流せます。触るものが自分の namespace と自分の作業ディレクトリの中に閉じます | `e2e.sh`、`ipv6.sh`、`split-merge.sh`、`import-export.sh`、`connlimit.sh`、`version-skew.sh`、`agentkernel.sh`、`agentdoctor.sh`、`lifecycle.sh` の check 1 2 3 3b 4 5c 5d 6 7 8 9 10 11 |
| `exclusive-heavy` | Lab Host VM の中で単独で流します。主張の根拠になる値そのものが、メモリか到達頻度の測定値です | `lifecycle.sh` の check 5、5b、5e、`rates.sh` |
| `exclusive-timing` | Lab Host VM の中で単独で流します。壁時計で測る区間の中で何が起きないかを主張するので、その区間が始まる前に収束を確認できないと、同じ VM を分け合ったときに失敗します | 該当する確認は今はありません |
| `exclusive-global` | Lab Host VM の中で単独で流します。network namespace が隔てない値を変えます | `lifecycle.sh` の check 12 |

`lifecycle.sh` の check 5c と check 5d は、主張の根拠が到達頻度でもメモリでもなく、ルールごとの受け付けの判定です。8 つの Sandbox のプールの中で、しかも 5c と 5d が同時に流れる状態で、20 回ずつ流して 160 件のすべてが成功し、保持数も毎回同じでした。この測定により、分類は `parallel` です。

`rates.sh` と `lifecycle.sh` の check 5 を単独で流す理由は、隣の Sandbox が結果を壊すからではなく、読む値が測定値そのものだからです。ラボでの実測では、両方とも隣に 4 つと 8 つの Sandbox がある状態でも同じ判定を出しました。check 5 の RSS は 85 MiB から 110 MiB の幅に収まり、判定の閾値 (ソフト上限と上乗せ分の和) の 224 MiB に対して半分以上の余裕がありました。`rates.sh` の上限なしの到達数は 500 回中 405 回から 500 回の幅で動きますが、隣の Sandbox の数とは相関しませんでした。`connlimit.sh` は 9 回の実行で 1 つの値も動かなかったので、`parallel` に分類しています。

`nf_conntrack_max` と conntrack のハッシュの大きさは VM 全体で 1 つの値です。network namespace の
中からの書き込みはカーネルが拒みます。この値を変える確認を新たに作るときは `exclusive-global` に
入れます。`nf_conntrack_acct` は namespace ごとの値なので、`lifecycle.sh` の check 6 の扱いは
`parallel` のままです。

`net.core.rmem_max` と `net.core.wmem_max` も VM 全体で 1 つの値です。Debian 12 のカーネルでは、
分けた network namespace の中にこの 2 つのファイルが現れません。この 2 つを変える `lifecycle.sh`
の check 12 は、Sandbox の runner の namespace から `nsenter -t 1 -n` で初期の namespace に入って
書き、終わりに元の値へ戻します。分類は `exclusive-global` です。

`lifecycle.sh` の check 8 と check 9 は、server の 30 秒の再試行に合わせた 45 秒の壁時計の
budget を持ちます。実際の待ちは、単独で流したときも、8 並列のプールの中で流したときも、
`exclusive-heavy` の確認を隣で流したときも 24 秒から 25 秒で、並列で延びませんでした。
余裕は約 20 秒あるので、check 8 の分類は `parallel` です。

check 9 はかつて `exclusive-timing` でした。check 9c は、何も変えていない 35 秒の区間の間に適用が
1 度も記録されないことを主張しますが、区間に入る前には前段の flush と delete への応答で forwarding が
戻ったことしか確認しておらず、それぞれの応答が残す "applied"/drift のログ行そのものは確認していませんでした。
隣の Sandbox の負荷でそのログ行の書き込みが遅れると、区間の中に紛れ込み、無関係な apply に見えました
(実測は単独で 20 回中 20 回成功、8 並列のプールで 20 回中 17 回成功、一式の中で 20 回中 18 回成功で、
失敗はいつも `no apply was logged in the window`)。[docs/development/testing.md](../../development/testing.md) の規範に
従い、区間の基準値を取る前に、直前の 2 つの応答それぞれの "applied"/drift のログ行を実際に確認するよう
直しました。直した後の実測は、単独で 20 回中 20 回成功、8 並列のプール (この 8 並列は本節の表にある
`parallel` の確認一式を隣に置いた状態) で 20 回中 20 回成功だったので、分類を `parallel` に移しました。

check 6h は、squat したポートを解放した直後、その解放を確かめずに 45 秒の再試行の budget に入って
いました。次に確かめる条件 (rule の apply_state) は解放したポートそのものを見ないため、隣の
Sandbox の負荷で解放が遅れると、再試行が 1 回分の無駄な試みで終わり、45 秒の budget を超えることが
ありました (100 回のうち 1 回、単独では 40 回中 40 回成功)。ポートが実際に解放されたことを、
budget に入る前に確かめる形に直しました。直した後の実測は、8 並列のプールで check 6 (check 6h を
含む) を 100 回流してすべて成功したので、分類は `parallel` のままです。


## Lab Host VM の大きさの測定


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
縮んだ差で、10 回の実測ではなく前後 1 回ずつの比較です。単独で流す確認は、check 9 を移した時点では
8 個で、一式の所要時間のうち約 240 秒がそれを 1 つずつ流す時間でした。その後 `exclusive-global`
の check 12 が加わっており、この時間は測り直していません。今の一式全体の所要時間は
[docs/development/testing.md](../../development/testing.md) の「マージの前に流すテスト」にあります。

CPU は、この実測の範囲では制約になっていません。2 vCPU のまま並列数を 1 から 32 まで上げても、
1 つあたりの確認の壁時計の時間はほぼ変わらず (約 39 秒から 42 秒)、並列数に応じて全体の時間が
ほぼ線形に縮みました。Lab Host VM の大きさを決める要因はメモリであり、CPU ではありません。

`incus config set <vm> limits.cpu` と `limits.memory` による実行中の Incus VM への設定変更は、
Incus 側では受け付けられても、ゲスト側の `nproc` と `MemTotal` には反映されないことをラボで
確かめました。Lab Host VM を大きくするときは、`WGFT_LAB_CPU` と `WGFT_LAB_MEM` を設定してから
`lab/lab up` を実行し、VM を新しく作り直します。
