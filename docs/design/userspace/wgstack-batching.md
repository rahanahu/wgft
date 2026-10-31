# wgstack のバッチと segment のまとめ

この文書は、[wgstack](wgstack.md) が wireguard-go と packet をまとめて受け渡す方法(バッチ)と、1 本の接続の連続した segment をまとめて処理する方法(受信の連なりと送信のまとめ作り)を定めます。
どちらも未実装です。
[性能の段階](wgstack-performance.md)の[CPU の仕事](wgstack-performance.md#cpu-の仕事)の一部で、上界と不変条件は[上界の式](wgstack.md#上界の式)と[不変条件](wgstack.md#不変条件)に従います。
構造と規則の骨格をここで決め、測ってから決める値と細部は[未確認の点と未決の点](#未確認の点と未決の点)に残します。

## 目的と範囲

CPU の目標は、エージェントの byte あたりの CPU を両方の向きで gVisor の 0.6 倍以下にすることです([目標と制約](wgstack-performance.md#目標と制約))。
バッチと segment のまとめは、この目標の必須の項目です。
判定は[判定の行列](wgstack-performance.md#判定の行列)の CPU の測り方(`lab/tcpquality-cpu.sh` と `tcpquality.py cpuratio`)で行います。
完成の段の測定では、速さを制限しない経路の比が送る向きで約 0.79、受ける向きで約 0.84 で、目標まで送る向きで約 24%、受ける向きで約 29% を減らす必要があります。

値は wireguard-go の暗号と UDP の処理を含み、2 つの netstack はその部分に同じコードを使います。
このため、wgstack の内側の手間だけを減らしても、比は wireguard-go の手間の分より下がりません。
バッチは、wgstack の内側の手間に加えて、packet ごとに払っている wireguard-go の手間(system call、キューの受け渡し、ピアのタイマーの更新)を減らせる点で、この目標に要ります。

範囲は次のとおりです。

- 対象:wgstack を使うエージェントのトンネルだけです。
  gVisor を使うエージェントと `vpsd` のユーザー空間モード(`internal/dataplane/userspace/utun`)は、今の 1 件ずつの経路のままにします
- 境目:wgstack は自分で `tun.Device` を満たし、カーネルの TUN ではありません。
  wireguard-go の Linux の TUN の offload(virtio-net の header、TUN の GSO と GRO)は `tun_linux.go` の中だけの処理で、device の層は 1 つの buffer を 1 つの IP の packet として暗号にします。
  このため wgstack は MTU を超える packet と offload の header を作りません。
  まとめた segment は wgstack の中だけの単位で、wireguard-go へは MTU 以下の packet の列として渡します
- 対象外:WireGuard の暗号そのものの速さと、wireguard-go の改造です([依存へのパッチを避ける方針](netstack-dependency.ja.md))

## wireguard-go との境目

### 依存の版の挙動

次の挙動は、`go.mod` の `golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446` のソースから読みました(MIT)。
依存を更新するときは、この節の挙動が変わっていないことを後述の試験と読み直しで確かめます。

- device の 1 回の件数:`device.BatchSize()` はバインドの `BatchSize()` と TUN の `BatchSize()` の大きい方です。
  device は作るときにこの値を読み、buffer の pool の入れ物の容量と、TUN の読み取りの goroutine の buffer の数に使います。
  `tun.Device` の約束では、`BatchSize` は Device の寿命の間変わりません
- `Read`:TUN の読み取りの goroutine(`RoutineReadFromTUN`)は、`device.BatchSize()` 個の buffer と、offset に `MessageTransportHeaderSize`(16)を渡します。
  buffer はそれぞれ pool の `MaxMessageSize` の配列の全体です。
  1 回の `Read` の結果はピアごとに 1 つの入れ物になり、入れ物はピアの staged のキュー(128 個、満杯なら先頭の古いものから捨てます)、暗号のキュー、ピアの送信のキュー(1024 個)を通り、入れ物 1 つにつき 1 回のバインドの `Send` で送られます
- staged のキューから取り出す処理:`SendStagedPackets` は staged のキューの先頭から入れ物を 1 つずつ取り出し、nonce を付けてピアの送信のキューと暗号のキューに入れます。
  取り出してから送信のキューに入れるまで、呼び出し 1 つが持つ入れ物は 1 つです。
  この処理を同じピアについて同時に動かしうる goroutine は、TUN の読み取り、ピアの受信の goroutine、ハンドシェイクの処理の goroutine(device を作る時の `runtime.NumCPU()` の数)、ピアのタイマーの 2 つ(keepalive と persistent keepalive)、`ipcMutex` を持つ設定の処理(`IpcSet` か `Up`)、`SendKeepalivesToPeersWithCurrentKeypair` の呼び出し側です。
  タイマー 1 つが同時に持つのは 1 つの呼び出しだけです。
  wireguard-go のタイマーは callback を `runningLock` で直列にし、2 つ目の callback はキューに触れる前に待つためです。
  wgft は `SendKeepalivesToPeersWithCurrentKeypair` を呼びませんが、上界には数えます。
  合わせて C = `runtime.NumCPU()` + 6 個で、C は device を作る時の値に固定します。
  ハンドシェイクの再送、新しいハンドシェイク、鍵の破棄、`StagePackets`、`FlushStagedPackets` は、staged のキューから取り出さないか、捨てるためだけに取り出します
- 暗号:`Seal` は header(`elem.buffer[:16]`)に暗号文を足すので、`Send` が受ける message の slice は、`Read` が書いた buffer と同じ配列の先頭から始まり、容量はその配列の末尾までです。
  詰め物と暗号は配列の [0, 32 + 詰めた packet の長さ) だけに書きます。
  Linux の IPv6 の宛先では、`Send` の中の GSO のまとめ(`coalesceMessages`)が、まとまりの最初の buffer に後の datagram を 65,527 byte まで足すので、その buffer の末尾の 16 byte に書くことがあります。
  IPv4 の宛先は 65,507 byte で止まるので、末尾に届きません
- `Write`:ピアの受信の goroutine(`RoutineSequentialReceiver`)は、受信の入れ物 1 つにつき 1 回 `Write` を呼びます。
  入れ物はバインドの 1 回の受信の結果のうち、そのピアの packet です。
  したがって `Write` の 1 回の件数を決めるのは TUN の `BatchSize` ではなく、バインドの 1 回の受信の件数です。
  `Write` に渡る slice は受信の buffer の先頭から始まり、容量はその配列の末尾までです。
  offset は `MessageTransportOffsetContent`(16)で、`Write` が戻った後に buffer は再利用されます
- バインドの受信の件数:受信の goroutine(`RoutineReceiveIncoming`)の buffer の数は、device の値ではなくバインドの `BatchSize()` です。
  受信の goroutine はどの OS でも IPv4 と IPv6 の 2 つです
- 標準のバインド:`conn.StdNetBind` の `BatchSize()` は Linux で 128、それ以外の OS で 1 です。
  Linux の `Send` は、同じ大きさの datagram が続く間 UDP の GSO で 1 つの message にまとめ(1 つの message に 64 個と 65,507 byte まで、短い datagram はその message に含めてから次の message に移ります)、`sendmmsg` で送ります。
  Linux の受信は `recvmmsg` と UDP の GRO で読み、GRO でまとまった datagram を分けて渡します。
  ほかの OS の `Send` は、datagram ごとに `WriteMsgUDP` を呼び、最初の誤りで残りを送らずに戻ります
- `Send` の上限:`Send` が使う message の配列は `conn.IdealBatchSize`(128)個です。
  128 個を超える buffer を 1 回の `Send` に渡すと配列の外を指すので、TUN の `BatchSize` は 128 以下にします
- buffer の大きさ:入れ物の packet は 1 つずつ `MaxMessageSize` の buffer を持ちます。
  Linux と macOS では 65,535 byte(ヒープの区分で 64 KiB)、Windows では 2,016 byte(2 KiB)です。
  pool は数の上限を持たない(`PreallocatedBuffersPerPool` が 0)ので、保持の上限はキューの長さと 1 回の件数だけで決まります

今の wgft では、wgstack と `internal/nettun` の `BatchSize` が 1 で、バインドは[1 回の受信で 1 件だけを渡す包み](tunnel-recovery.md#wireguard-の受信の-1-回の件数)(`BatchOne`)なので、device の値は 1 です。
このため packet 1 つごとに、入れ物 1 つ、キューの受け渡し、ピアのタイマーの更新、`Send` の system call 1 回がかかります。
Linux の受信は、包みの内側で既に `recvmmsg` と GRO を使っているので、system call の数はまとまっています。

### Device の約束

wgstack の Device は、バッチを使うときに次の約束を守ります。

- `BatchSize`:作成の時に決めた定数 k_tx を返します。
  k_tx は 1 以上 128 以下です
- `Read`:1 個以上、min(`len(bufs)`, `len(sizes)`, k_eff) 個以下の packet を `bufs[i][offset:]` に作り、`sizes[i]` に長さを書き、個数を返します。
  k_eff は後述の[送信の向きの予算](#送信の向きの予算)が決める k_tx 以下の値です。
  `len(bufs)` は device の値なので、バインドの件数が k_tx より大きければ k_tx より長くなりえます。
  送るものが 1 つも無ければ、今と同じく次に送るものができるまで待ちます。
  1 つ作った後は待たず、次の packet を作れなくなった時点で戻ります。
  したがってバッチは、件数をそろえるための待ちを足しません。
  入れ物の中の暗号は 1 つの goroutine が順に行うので、入れ物の最初の packet が出るまでの時間は件数とともに延びます([危険](#危険))。
  誤りを返すのは今と同じく `Close` の後の `os.ErrClosed` だけで、そのときの個数は 0 です
- 印:`Read` は packet を書いた buffer の末尾の 16 byte に、後述の送った番号の印を書きます
- `Write`:何個の packet でも受け取り、順に処理します。
  1 件ごとの検査、捨て方、返す値と誤りは[今の境目](wgstack.md#今の境目)と同じです。
  packet は呼び出しの間だけ使い、保持しません
- 並行性:`Read` を呼ぶのは 1 つの goroutine だけです。
  `Write` はピアごとの goroutine から呼ばれるので、今と同じく並行の呼び出しに耐えます
- packet の形:どの packet も MTU 以下の IPv4 の packet です

wgft のバインドの層は、受信の件数を決める包みと、`Send` を見る層を分けます。

- 受信の包み:wgstack を使うトンネルの受信の件数 k_rx を決めます(後述の[受信の向きの件数](#受信の向きの件数))。
  内側のバインドの件数が 1 の OS では包みません
- `Send` を見る層:wgstack を使うトンネルでは、どの OS でも `Send` を見る層を置き、送信の向きの予算に送った番号を知らせます。
  `Send` はそのまま内側に渡します。
  今の handshake の送信元の包み(`wgbind.NewDevice` の `sourceGate`)と同じく、OS によらず置きます

gVisor を使うトンネルと `vpsd` のトンネルは `BatchOne` のままで、`Send` を見る層を置きません。
バインドの選び方はトンネルの package が実装の選択と同じ所で決めます。
`internal/dataplane/userspace/wgbind` と `internal/wgstack` は互いを import せず、トンネルの package が両方を関数の値でつなぎます。
`internal/wgstack` は今と同じく標準ライブラリと `tun` の型だけを import します。

## wireguard-go の滞留の上界

### 入れ物の数

1 回の件数を k にすると、wireguard-go のキューに滞留する packet の上界が k 倍になります。
キューは packet ではなく入れ物を数え、入れ物の packet はそれぞれ `MaxMessageSize` の buffer を持つためです([フロー数とメモリのソフト上限](flow-limits.md))。
この上界は wgstack の `Bound` の外の、エージェントの上界の式の wireguard-go の項([エージェントとホストのメモリの条件](memory-agent-host.md#wgstack-を使うエージェントの上界))に入ります。
ピアは 1 つで、buffer 1 つの大きさを S と書きます。

- 送信の向きの入れ物の数 N_tx:送信のキューの 1024 個、staged のキューの 128 個、送信の goroutine が持つ 1 個、`SendStagedPackets` の呼び出し C 個が 1 つずつ持つ分の和で、N_tx = 1153 + C です。
  CPU が 8 個なら C は 14 で、N_tx は 1167 です
- 受信の向きの入れ物の数 N_rx:受信のキューの 1024 個、`Write` に渡している 1 個、キューの空きを待つ 2 つの受信の goroutine の 2 個の和で、N_rx = 1027 です

今の[フロー数とメモリのソフト上限](flow-limits.md)の 1026 件は、C 個の呼び出しのうち TUN の読み取りの 1 個だけを数え、ほかの呼び出しが持つ C - 1 個(CPU が 8 個なら 13 個、Linux で約 0.81 MiB)を数えていません。
この数え落としは件数が 1 の今の経路にもあるので、1 の段の PR で N_tx の形に直します。

### 件数を固定する場合

件数を固定する場合(案 A)の Linux の値は、CPU が 8 個のとき次のとおりです。

| 1 回の件数 | 送信の向き:N_tx × k × S | 受信の向き:N_rx × k × S |
|---|---|---|
| 1(今) | 72.9 MiB | 64.2 MiB |
| 4 | 291.8 MiB | 256.8 MiB |
| 8 | 583.5 MiB | 513.5 MiB |
| 16 | 1,167.0 MiB | 1,027.0 MiB |
| 32 | 2,334.0 MiB | 2,054.0 MiB |

macOS の値も同じで、Windows の値はこの表の 32 分の 1 です。
ほかに、TUN の読み取りの goroutine が device の値の個数の buffer を、2 つの受信の goroutine がバインドの件数の個数の buffer を固定で持ちます。
k が 8 なら合わせて約 1.5 MiB です。
今の wgstack を使うエージェントの生きているヒープの上界は約 1,923 MiB です。
両方の向きを 8 にすると生きているヒープの上界が約 960 MiB 増え、[ランタイムの係数](memory-agent-host.md#wgstack-を使うエージェントの上界)(生きているヒープの約 2 倍)を掛けたプロセスの上界は約 2 GiB 増えます。

Linux と macOS の送信の向きでは、効果の出る件数でこの増加を払えないので、次節の予算で抑えます(案 B)。
Windows では buffer が 2 KiB なので、k_tx が 32 でも送信の向きは約 72.9 MiB(今より約 70.7 MiB の増加)で、案 A で払えます。

| OS | 送信の向き | 受信の向き |
|---|---|---|
| Linux | 案 B(予算と同期) | 連なりの段の測定まで k_rx = 1。代わりの案は案 A の k_rx = 4 |
| macOS | 案 B(予算と同期) | k_rx = 1(標準のバインドが 1) |
| Windows | 案 A(k_tx を固定) | k_rx = 1(標準のバインドが 1) |

Windows の案 A は、後述の P_max を上限の値に置いた案 B と同じ動きなので、実装は 1 つです。

## 送信の向きの予算

### 予算の門

送信の向きの予算は、2 個以上の packet を持つ入れ物の buffer の数を P_max 以下に抑えます。
1 個の入れ物は N_tx 個以下なので、送信の向きの滞留は次の式で抑えられます。

```
W_tx(P_max) = (N_tx + P_max) × S
```

- 送った番号:`Read` は呼び出しごとに 1 ずつ増える 64 bit の番号 s を付け、作ったすべての buffer の末尾の 16 byte に、s と、Device ごとの送信の向きの秘密の鍵で s から作った 8 byte の確認の値を書きます。
  1 個だけの `Read` にも書きます。
  Device は最後に出した番号を atomic の値で持ち、`Read` が戻る前に更新します
- 印を書ける条件:offset + packet の長さ + 詰め物 + 認証の tag の 16 byte が、buffer の容量から 16 を引いた値以下のときだけ印を書けます。
  Windows の 2,016 byte の buffer では 32 + MTU + 15 ≤ 2000 で、MTU が 1,953 以下なら成り立ちます。
  成り立たない MTU の Device はバッチを使いません
- 台帳:2 個以上を返した `Read` ごとに、番号と個数の行を台帳の固定の輪に足します。
  行は `Read` が戻る前に足します。
  台帳に残る行の個数の和を L と書きます
- 送った印:`Send` を見る層は、内側の `Send` を呼ぶ前に、型が transport(4)で長さが keepalive の 32 byte より長い message ごとに、slice を容量まで広げた末尾の 16 byte を読みます。
  内側の IPv6 の GSO のまとめが末尾を書く前に読むためです。
  確認の値が合い、番号が Device の最後に出した番号以下の値だけを使います
- 1 回遅れの知らせ:`Send` を見る層は、data の message を持つ `Send` の呼び出しで読んだ最大の番号を手元に置き、次に data の message を持つ `Send` の呼び出しの初めに Device に知らせます。
  data の message の `Send` はピアの送信の goroutine 1 つだけが呼び、その goroutine は前の入れ物の buffer を `Send` から戻った後に返してから次の入れ物を取ります。
  したがって知らせた番号の入れ物は、知らせた時点で buffer を返し終えています。
  Device は知らされた番号の最大 W を持ち、W 以下の番号の行を台帳から外します
- 余裕:R = (C - 1) × k_eff を、送ったと分かった番号より前に残りうる入れ物の分として、常に予算から引いておきます
- 門:`Read` は台帳から W 以下の行を外した後、L + R + n ≤ P_max を満たす n の最大と k_eff の小さい方まで packet を作ります。
  その値が 2 より小さければ 1 個だけ作ります。
  予算は送ることを止めず、件数だけを絞ります

### 同期が上界を崩さないこと

上界の主張は、2 個以上の入れ物が持つ buffer が常に L + R 以下であることです。
門が L + R + n ≤ P_max を守って行を足し、L は行を外すときだけ減るので、主張から P_max 以下が従います。

- W より後の番号の入れ物:台帳の行が残っているので、L に数えられています
- W 以下の番号の入れ物:番号 W の入れ物は staged のキューから取り出されて送られました。
  staged のキューは先頭から取り出し、捨てるのも先頭なので、W より前の入れ物は、番号 W の入れ物より前に取り出されたか捨てられています。
  捨てた入れ物は buffer を返しています。
  取り出した入れ物は、番号 W の入れ物より前に送信のキューに入ったか、番号 W の入れ物が送信のキューに入った時点で、別の `SendStagedPackets` の呼び出しが持っていたかのどちらかです。
  前者は送信のキューの順(送信の goroutine は 1 つ)で番号 W の入れ物より前に送られています。
  後者は、呼び出し 1 つが持つ入れ物が 1 つなので、番号 W の入れ物を入れた呼び出しを除く C - 1 個以下で、それぞれ k_eff 個以下の packet を持ちます。
  番号 W の入れ物そのものは、1 回遅れの知らせにより、W を知らせた時点で buffer を返しています。
  W が大きくなると、W 以下でまだ返していない入れ物は、新しい W の入れ物が入った時点の後者に限られるので、いつも R 以下です
- 入れ直し:`SendStagedPackets` は nonce を使い切った packet を staged のキューの末尾に入れ直しますが、使い切るには 1 つの鍵で約 2^64 個の message を送る必要があります。
  鍵は 180 秒(`RejectAfterTime`)で使えなくなるので、この入れ直しは起きません
- 古い印:data の message の buffer は、どれもその送信の前に `Read` が書いたものなので、末尾の印は必ずその `Read` の番号です。
  `Read` が受ける buffer は送信の途中に無いものだけで、pool から再利用した buffer の古い印は、次の `Read` が上書きします。
  古い印が残っても番号は小さい側にしかずれず、最大の値の更新では使われません。
  keepalive は長さで、ハンドシェイクと cookie の message は型で除き、確認の値が合わない値と、最後に出した番号より大きい値は使いません。
  pool は device ごとで、トンネルを作り直すと鍵も変わります
- 漏れの回復:staged のキューの溢れ、ハンドシェイクを諦めた時の staged のキューの破棄(`FlushStagedPackets`)、鍵の破棄(`ZeroAndFlushAll`)、ピアの停止、endpoint の無い送信で捨てた入れ物は、どれも後の `Read` の入れ物より古いので、後の `Read` の packet が 1 つ送られた時点で W が追い越し、台帳から外れます。
  1 個だけの `Read` にも印を付けるので、門が閉じて 1 個ずつ送っている間も同期は進みます。
  長い途絶の後も、送り始めれば件数は戻ります

この主張は、staged のキューと送信のキューの順、呼び出し 1 つが持つ入れ物の数、C の数え方、`Seal` が同じ配列に書くこと、内側の `Send` より前には配列の末尾に触れないこと、data の message の `Send` を呼ぶ goroutine が 1 つであること、ピアが 1 つであることに頼ります。
どれも依存のコードから読んだ挙動なので、後述の前提の試験と、依存を更新するたびの読み直しで確かめます。

### 数えの規則

- 持ち主:台帳と L は `Read` の goroutine だけが触れ、今の `readMu` の中で扱います。
  足す処理と確かめる処理の間に別の書き手はいないので、門の判定は錠の中の 1 回の比較です。
  L は錠の中でだけ増減し、外す行は足した行だけなので、負になりません
- W:`Send` を見る層が 1 回遅れで、CAS の繰り返しで最大の値に更新する atomic の 64 bit の値で、`Read` が読みます。
  `Send` を呼ぶ goroutine が複数でも、W は減りません
- 手元の番号:1 回遅れの知らせのために `Send` を見る層が手元に置く番号は、data の message の `Send` を呼ぶ 1 つの goroutine だけが触れます
- 番号:64 bit の符号なしの値で、1 秒に 10^9 回の `Read` でも一周に約 584 年かかるので、一周を扱いません
- 台帳の輪の大きさ:行は 2 個以上の packet を持つので、行の数は ⌊P_max / 2⌋ 以下です。
  輪は作成の時にこの大きさで確保します

### P_max の決め方

P_max の既定の値は、`cmd/wgft/limits.go` がフロー数の上限からメモリのソフト上限を導くのと同じ所と形で、フロー数の上限から導きます。

```
M_soft = 32 MiB + U × 12 KiB + K × 44 KiB     (resource.Limits.MemoryLimit)
P_max  = min(⌊β × M_soft / S⌋, P_upper)
P_upper = N_tx × k_tx
k_eff  = min(k_tx, ⌊P_max / (2 × (C - 1))⌋)
```

- S:Linux と macOS は 64 KiB、Windows は 2 KiB です
- M_soft:フロー数の上限から導く値で、運用者が `GOMEMLIMIT` を設定してランタイムのソフト上限を変えた場合も、この式の値を使います。
  P_max を変えるには後述の設定を使います
- β:メモリのソフト上限のうち送信の向きの予算に当てる割合で、骨格の段では未決です。
  たとえば β が 1/4 なら、既定の U と K(8192 と 2048)で M_soft は 216 MiB で、Linux の P_max は 864 です。
  β は 1 の段の P_max を変えた測定で、byte あたりの CPU が予算の無い場合との差を定めた割合以内に収まる最小の P_max を求め、その P_max の増分 W_tx(P_max) - W_tx(0) が既定の上限でのプロセスの上界の定めた割合以下になるように選びます。
  2 つの割合は測定の後に所有者が決めます
- P_upper:すべての入れ物が k_tx 個を持っても門が閉じない値で、これ以上の P_max は案 A と同じです。
  k_tx は 128 以下なので、P_upper は 128 × N_tx 以下です。
  Windows の既定の P_max は P_upper です
- k_eff:余裕 R を予算の半分以下に保つための件数の上限です。
  CPU の多いホストでは C が大きく、k_eff が下がります
- 下限:P_max が 0 か、k_eff が 2 より小さいときは、`Read` は 1 個ずつ返します。
  これは今の経路と同じで、正しいままです

設定は `WGFT_AGENT_BATCH_MIB` で受け取り、フラグ `--agent-batch-mib` はその別名です([設定の渡し方](../security/configuration.md#11a-設定の渡し方))。

- 値:送信の向きの予算の MiB で、P_max = ⌊値 × 1 MiB / S⌋ です。
  省略と空の値は既定の式です。
  値が抑えるのは 2 個以上の packet の入れ物の分だけで、1 個の入れ物の分の N_tx × S(Linux で CPU が 8 個なら約 73 MiB)は値によらず残ります。
  使い方の文書とヘルプにもこの点を書きます
- 0:バッチを使いません
- 上限:P_upper を超える値は P_upper に丸め、起動ログの有効な設定に丸めた値と出所を出します。
  P_upper は CPU の数で決まるので、同じ設定をどのホストでも受け付けるためです。
  範囲の外の値を設定の誤りにする[設定の渡し方](../security/configuration.md#11a-設定の渡し方)の扱いに対する、意図した例外です
- 誤り:整数でない値と負の値は設定の誤りとして終了コード 3 で止めます
- 使う場所:エージェントが wgstack を使うときだけ使います。
  gVisor とカーネルモードでは、値が設定されていれば使わない旨を英語の 1 行で出して起動を続けます(`WGFT_AGENT_NETSTACK` と同じ扱い)
- 公開のサーフェス:名前と意味は、このブランチが main に入る時に公開のサーフェスになります

送信の向きの予算の項は、エージェントの上界の式で W_tx(P_max) と書き、定数にしません。

### 予算と速さ

P_max を小さくすると、k_eff と、同時に流せる 2 個以上の入れ物の数(⌊(P_max - R) / k_eff⌋)が減ります。
件数だけの試作では、送る向きの byte あたりの CPU は件数を 1 から 32 まで上げる間減り続けたので、P_max を減らすと CPU は単調に今の値へ近づくと見込みます。
下限では今の値と同じです。
速さが落ち始める P_max は、送信の経路が同時に持つ入れ物の深さで決まり、測っていません([未確認の点と未決の点](#未確認の点と未決の点))。

## 受信の向きの件数

wgstack の `Write` が 1 回に受ける件数は、包みが 1 回に渡す件数 k_rx で決まります。
Linux の包みは、今と同じく内側の標準のバインドを 128 件分の自前の buffer で読み、wireguard-go の呼び出しごとに k_rx 件まで写して渡します。
写す回数と system call の数は今と同じで、変わるのは入れ物の数です。
Windows と macOS の標準のバインドは 1 回に 1 件なので、包みを使わず、`Write` は今と同じく 1 件ずつ受けます。

件数だけの試作では、受ける向きの効果は小さく、効果は連なりの処理に頼ります。
そこで k_rx は連なりの段を測るまで 1 のままにします。
連なりの段では、案 A の k_rx = 4(受信の向きの増加は約 192.6 MiB、プロセスの上界で約 0.39 GiB)で測り、その値を持って所有者に次の 3 つから選んでもらいます。

- k_rx = 1 のまま
- 案 A の小さな固定の k_rx
- 後述の同期を持つ受信の向きの予算(案 B)

### 受信の向きの予算の候補

受信の向きの予算は、送信の向きと同じ印の形で、偽の datagram が同期を止められない形にできます。
骨格は次のとおりです。

- 印:包みは受信の関数(IPv4 と IPv6)ごとに 1 ずつ増える番号を持ち、wireguard-go の受信の buffer に datagram を写した後、buffer の末尾の 16 byte に関数の印、番号、確認の値を書きます。
  写すすべての datagram に書きます。
  送信と受信は同じ buffer の pool を使うので、確認の値は送信の向きと別の鍵で作ります。
  容量から 16 を引いた長さより大きな datagram は、ほかの datagram と分けて 1 件だけで渡し、台帳に数えません
- 台帳:包みは 2 件以上を渡した呼び出しの行を、関数ごとの台帳に足します。
  台帳は関数の goroutine だけが触れ、予算は 2 つの関数に半分ずつ分けます
- 同期:wgstack の `Write` は受けた packet の slice を容量まで広げて印を読み、関数ごとの最大の番号を手元に置きます。
  次の `Write` の呼び出しの初めに、手元の番号で関数ごとの W_f を atomic に更新します(1 回遅れの知らせ)。
  `Write` はピアの受信の goroutine 1 つだけが呼び、その goroutine は `Write` から戻った後に前の入れ物の buffer を返してから次の入れ物を取るので、知らせた番号の入れ物は buffer を返し終えています
- 健全さ:関数 1 つの受信は 1 つの goroutine が行い、その関数の入れ物はピアの受信のキューに渡した順に `Write` に届きます。
  したがって W_f を知らせた時点で、その関数の W_f 以下の入れ物は buffer を返し終えたか捨てられており、送信の向きの余裕に当たる分はありません。
  包みが最後に出した番号より大きい値は使いません。
  上界は (N_rx + P_max_rx) × S です
- 偽の datagram:受信者の番号の合わない偽の transport の message、期限の切れた鍵の message、長さの合わない message は、入れ物ができる前に捨てられるので buffer を持ちません。
  受信者の番号は本物の packet に平文で載るので、経路の上の相手は正しい番号の偽の message を送れます(経路の外の相手は 32 bit を当てる必要があります)。
  この message はキューに入り、復号に失敗するまで buffer を持ち、`Write` に届かないので、同じ関数の本物の packet が後で `Write` に届くまで台帳の行に残ります。
  その buffer は数えた行の中にあるので、上界は保たれます。
  偽の datagram が門を閉じておけるのは洪水を続ける間だけで、その間の datagram ごとの手間は予算によらず払っています。
  一方の関数が偽の datagram だけを受ける場合はその関数の予算の半分が埋まったままになりますが、その関数は本物の packet を運んでいないので害はありません

## 受信の向き:連なりの処理

### 連なりの定義

連なりは、1 回の `Write` の中で続く、同じ 4 つ組の確立した接続に当たる TCP の segment の列です。
長さの上限は G_rx で、k_rx 以下です。
次のどれかで連なりを終えます。

- 次の packet が TCP でないか、断片か、別の 4 つ組です
- segment が SYN、RST、FIN のどれかを持ちます。
  この segment は今の経路で処理し、そこで連なりを終えます
- segment の処理の後に接続の状態がデータの転送の状態(ESTABLISHED、CLOSE_WAIT、FIN_WAIT_1、FIN_WAIT_2)でなくなったか、枠が返されました
- TIME_WAIT の接続が新しい SYN を受けて処理し直す場合(RFC 6191)です
- 長さが G_rx に達しました

### 連なりで 1 回にすること

連なりの segment は、1 つずつ今の規則で処理します。
PAWS、受け入れの判定、ACK の受け入れの範囲、TS.Recent の更新、ACK の処理、データの受け入れは segment ごとに行い、まとめません。
1 回にするのは、規則の結果を変えない次の手間だけです。

- 表の検索と接続の錠:連なりの最初で 1 回引き、連なりの間は錠を持ち続けます。
  錠を持つ時間は G_rx 個の segment の処理で抑えられます
- 時刻:連なりの最初に 1 回読みます。
  連なりの segment は同じバインドの受信で届いたので、届いた時刻の差は userspace から見えません。
  RTT の標本と RACK の時刻の誤差は、連なりの処理の時間以下です
- 入力の後の処理:送るものの確認と出力の list への追加、窓の probe の開始、TIME_WAIT への移り、読み手と書き手への知らせ、出力の goroutine への知らせを、連なりの最後に 1 回行います
- `Stats` の数:連なりの中では手元で数え、最後に 1 回 atomic に足します

checksum の確認と header の読み取りは segment ごとに行います。
WireGuard の認証は VPS とエージェントの間の区間だけを守り、利用者から VPS までの区間で壊れた segment もトンネルに入るためです。

### ACK の決め方

受け手の ACK の規則(遅延 ACK、推定した相手の MSS を超えた確認での ACK、quickack、順序外と重複の segment への即座の ACK、D-SACK)は segment ごとに今と同じ判定をします([受け手の ACK と D-SACK](wgstack-performance.md#受け手の-ack-と-d-sack))。
今の wgstack は ACK を `Read` の時に作り、送ると決めた ACK は接続に 1 つの印で表します。
`Read` が `Write` に追いつかない間は、後の segment で決めた ACK が前の ACK に合わさり、1 つの ACK が多くの segment を確認します。
連なりは錠を持ち続けるので、何もしなければ連なり 1 つの ACK が 1 つに合わさります。
これは RFC 5681 4.2 の「少なくとも 2 つ目の full-sized の segment ごとに ACK を返す」(SHOULD)から外れ、RFC 5681 3.1 のように ACK ごとに min(N, SMSS) だけ窓を増やす送り手の slow start を遅らせます。

そこで、ACK の控えを持ちます。

- 控え:送ると決めた ACK がまだ作られていないうちに次の ACK を送ると決めたら、前の ACK を控えに写します。
  控えは ACK の番号、TSecr、SACK の block(D-SACK を含みます)を持ちます。
  写した時点で、ACK を送った後の状態の更新(確認を待つ byte の数の 0、遅延 ACK のタイマーの解除、quickack の数の減算、最後に送った ACK の番号、D-SACK の印の解除)を行います
- TSecr:最後に送った ACK の番号を控えの番号にするので、RFC 7323 4.3 の TS.Recent の規則(最後に送った ACK 以下から始まる segment だけが TS.Recent を更新します)が控えごとに働きます。
  控えの TSecr は、その ACK を segment ごとに送っていた場合と同じ値です
- 送る順:控えは、ACK の欄を持つほかのどの segment よりも先に、古い順に中身の無い ACK として作ります。
  確立した接続の segment はどれも ACK の欄を持つので、接続が `Read` で作る最初の segment から控えを出し切り、その後に後述の優先の順の出力を作ります。
  新しい ACK の番号を持つ data の segment が古い控えを追い越すと、相手は SND.UNA より小さい ACK を無視し、控えは ACK の数を保たないまま CPU だけを使うためです
- 窓の欄:控えの窓の欄は、作る時の広告した右端 R_adv から (R_adv - 控えの番号) >> scale を求め、65535 を超えれば 65535 にします。
  丸めると相手から見える右端は R_adv より手前になります。
  控えは古い順に、ほかの segment より先に出るので、それまでに送った ACK の番号はどれも控えの番号以下です。
  送った右端はどれも、その ACK の番号に 65535 << scale を足した値以下なので、丸めた右端は送った右端より手前になりません(RFC 9293 の窓の縮小に当たりません)
- 数の上限:控えは接続ごとに A 個までの固定の配列に置きます。
  A は OS と k_rx によらない定数です。
  控えは連なりの外でも、`Read` が遅れる間の ACK の合わさりを減らすためです。
  満杯のときは控えに写さず、今と同じく次の ACK に合わせます。
  したがって ACK の数は今より減らず、最悪でも今の合わさり方になります
- 閉じる時:接続が CLOSED になるか枠を返すときに、控えを捨てます。
  今の、作る前の ACK の印を捨てる扱いと同じです

控えは受信の向きの ACK の数を今より増やし、ACK の暗号と送信の CPU を増やします。
増えた ACK は同じ大きさの packet として 1 回の `Read` に並ぶので、Linux では UDP の GSO で 1 つの system call にまとまります。
ACK の数を減らす案(連なり 1 つに 1 つの ACK)は、[未確認の点と未決の点](#未確認の点と未決の点)に残します。

### SACK、RACK、PAWS との関係

- SACK と D-SACK:順序外の segment と重複の segment は、今と同じく即座の ACK を決めます。
  控えはその時の SACK の block を写すので、segment ごとに送っていた場合と同じく、最も新しい segment を含む block を先頭にした ACK が segment ごとに出ます(RFC 2018)。
  D-SACK の block は 1 つの ACK だけに載ります(RFC 2883)
- quickack:quickack の数は控えに写すたびに減ります。
  接続の始めと長く黙った後に遅らせずに返す ACK の数は、今と同じです
- RACK と RTT:wgstack が送り手の連なり(中身の無い ACK の列)でも、ACK は 1 つずつ処理します。
  重複した ACK の数、SACK の scoreboard、RACK の時刻、輻輳の窓の増え方は ACK ごとの規則なので、合わせません(RFC 5681、RFC 6675、RFC 8985)
- PAWS:segment ごとに今と同じく比べます

### 順序どおりの segment の合体

GRO に当たる合体は、連なりの後の段で、プロファイルで要ると分かった場合だけ加えます。
骨格は次のとおりです。

- 合体の条件:受信のバッファに順序外の区間が無く、segment が順序どおりに続き、flag が ACK と PSH だけで、ACK の番号と窓の欄が前の segment と同じで、option が timestamp だけで、TSval が減らない場合です
- まとめる処理:ACK の欄が同じなので、ACK の処理を最初の segment だけで行います。
  受け入れの判定(RCV.WND の内側か)と PAWS は segment ごとに行います。
  順序どおりでも窓の内側とは限らないためです。
  データの受け入れ、推定した MSS の更新、ACK の規則の判定も segment ごとに行います
- 外れたとき:条件を満たさない segment と、受け入れられない segment で合体を終えます。
  受け入れられない segment は今の経路で処理し、受け入れられない segment への ACK を送ると決めます

## 送信の向き:1 回の Read で複数の segment を作る

### 組の選び方

`Read` は、packet を 1 つずつ作る今の処理を、件数の上限か作るものが尽きるまで繰り返します。
4 つの組の間の deficit round robin は、作った packet の byte をそのまま数えます。
接続の組は 1 回の選択で後述の G_tx 個まで作るので、deficit が負のまま次の回に quantum を足しても正にならない組は、その回を飛ばします。
今の実装は quantum を足した後の deficit が 0 以下でも組を選ぶので、この点を直します。
これで、組の間の byte の配分は今と同じになります。

### 接続ごとのまとめ作り

接続の組から取り出した接続は、錠を 1 回取り、次の順で G_tx 個まで segment を作ります。
G_tx は k_eff 以下です。

1. ACK の控え(古い順)
2. 今の優先の順の出力:高速の再送、窓の probe、TLP の probe、規則 1 の再送、新しいデータと FIN、規則 3 の再送、ACK

segment ごとの状態の更新(送信の記録、送った時刻の順の list、SND.NXT、RTO と TLP の期限、輻輳の窓の検証、PRR)は今と同じく segment ごとに行います。
記録は今と同じく segment 1 つに 1 件で、複数の segment を 1 件にまとめません。
SACK と RACK の損失の単位を segment のまま保つためです。

まとめ作りで 1 回にするのは次の手間です。

- 錠と時刻:接続の錠と時刻の読み取りを 1 回にします
- option:timestamp の値と SACK の block はまとめの間で同じなので、最初の segment で作った option を写します。
  D-SACK の block は最初の segment にだけ載るので、D-SACK を載せた segment の後は option を作り直します
- header:最初の segment の header を型にして、番号、IP の ID、長さ、checksum だけを書き直します。
  IP の ID は G_tx 個をまとめて取ります
- list の入れ直し:出力の list へは、まとめの最後に 1 回だけ入れ直します

送った時刻は segment ごとに別の値にし、作った順に増やします。
まとめの i 番目の segment の送った時刻は、読んだ時刻と、その接続が前に記録した送った時刻に 1 ns を足した値の大きい方に、i ns を足した値です。
RFC 8985 は送った時刻が同じ segment を終わりの番号の順に並べるので、時刻を共有すると、新しいデータの後に作った番号の小さい規則 3 の再送が先に送ったものとみなされ、新しいデータの SACK で再送を誤って失ったと判断しうるためです。
時刻の差は ns の単位なので、RTT の標本と RACK の並べ替えの窓への影響は測定の誤差より小さくなります。

checksum は segment ごとに中身から計算します。
wireguard-go は平文の packet を暗号にするので、checksum を後の層に任せられません。
中身の写しと checksum を 1 回の走査で行う形は、プロファイルで要ると分かった場合に加えます。

### 接続の間の公平さ

G_tx 個のまとめは、通信量の少ない stream が大きな転送の後ろで待つ時間を、大きな転送 1 本あたり最大で G_tx - 1 個の segment の分だけ延ばします。
組の間の deficit round robin は byte で数えるので、UDP の組と制御の組の取り分は変わりません。
G_tx の値は、[遅れの p99](wgstack-performance.md#判定の行列)を退行させない範囲で測って決めます。

### UDP の GSO との関係

Linux の標準のバインドは、同じ大きさの datagram が続く間だけ GSO でまとめます。
full-sized の segment は WireGuard の詰め物の後に同じ大きさになるので、まとめ作りの segment は続けてまとまります。
中身の無い ACK や短い segment が入ると、そこで GSO の message が終わります。
1 回の `Read` の中で大きな packet を先に並べるかどうかは、測ってから決めます。

## 上界の式への項

wgstack の `Bound` に加える項は次のとおりです。

| 構造 | 大きさ | 入る項 |
|---|---|---|
| ACK の控え | 接続の枠ごとに A 個 × 控え 1 個(48 byte 以下の見込み)。A が 8 なら、K が 2048 で N_c = K + Q = 2560 のとき 2560 × 384 byte で約 0.94 MiB | 新しい項 a_ack。N_c × (c_conn + f_s + f_r + r_f + h_f + a_ack) |
| 送信の向きの台帳と W | ⌊P_max / 2⌋ 行 × 16 byte と固定の値。Linux で P_max が 864 なら約 6.8 KiB | M_fix。P_max の関数です |
| `Read` と `Write` の作業の値 | 件数によらない固定の大きさ。連なりは packet を写さず、wireguard-go の buffer の上で処理します | M_fix |

wgstack の外の項は、エージェントの上界の式の wireguard-go の項です。
送信の向きは W_tx(P_max) = (N_tx + P_max) × S、受信の向きは N_rx × k_rx × S(案 A)か (N_rx + P_max_rx) × S(案 B)にし、TUN の読み取りの goroutine と受信の goroutine の固定の buffer を足します。
実装の段では、[フロー数とメモリのソフト上限](flow-limits.md)、[トンネルの回復と作り直し](tunnel-recovery.md)の 1 回の件数の 2 項、[エージェントとホストのメモリの条件](memory-agent-host.md#wgstack-を使うエージェントの上界)の表を、wgstack を使う場合の値で同じ変更の中で直します。

敵対的な入力がバッチで保持を増やせないことは、次の構造で決まります。

- 連なりは `Write` の中で同期して処理し、`Write` が戻った後に packet も連なりの状態も残しません
- 控えは接続ごとの固定の配列で、満杯なら合わせるだけです
- 送信の向きの予算は、相手の入力によらず W_tx(P_max) で抑えられ、漏れは後の送信で回復します
- 受信の向きは、案 B を選ぶまで件数を固定します

不変条件との対応は次のとおりです。

- I1 有限、I2 保持の前の予約:新しい構造は控えの固定の配列、台帳の固定の輪、固定の作業の値だけで、作成の時に確保します
- I4 TCP の正しさ:segment ごとの規則と記録は変えず、控えは ACK を捨てずに遅らせるだけです
- I5 自己増殖の禁止:バッチ、控え、台帳は入力と `Read` と `Send` の中でだけ動き、タイマーを足しません
- I7 隔離:変更は wgstack とトンネルの wgstack の経路だけで、カーネルモードの経路に入りません

## OS ごとの挙動と代わりの経路

| OS | `Write` の件数 | `Read` の件数 | `Send` の system call | `MaxMessageSize` |
|---|---|---|---|---|
| Linux | k_rx まで(包み) | k_eff まで(案 B) | `sendmmsg` と UDP の GSO で入れ物ごとに 1 回程度 | 64 KiB |
| Windows | 1(標準のバインドが 1) | k_tx まで(案 A) | datagram ごとに 1 回 | 2 KiB |
| macOS | 1(標準のバインドが 1) | k_eff まで(案 B) | datagram ごとに 1 回 | 64 KiB |

OS によらない部分は、wgstack の `Read` と `Write`、印と台帳、連なり、控え、まとめ作り、`Send` を見る層です。
Linux だけの部分は、受信の包みの件数と、wireguard-go の中の `recvmmsg`、`sendmmsg`、UDP の GSO と GRO です。
Windows と macOS では受信の連なりの長さが 1 になり、今の 1 件ずつの経路と同じ処理になります。
送信のまとめ作りと `Read` のバッチは、Windows と macOS でも wireguard-go の入れ物ごとの手間を減らしますが、system call の数は減りません。

能力が無い場合の代わりの経路は、wgstack の側で分岐を持たない形にします。

- `Write` はどの件数でも同じ処理で、件数が 1 なら今の処理と同じです
- 受信の包みは、内側のバインドの件数が 1 なら包まずに内側を返します(今の `BatchOne` と同じ判定)
- 予算の下限では `Read` が 1 個ずつ返し、今の経路と同じです
- 印を書く余地の無い buffer(MTU と header と詰め物と認証の tag と印の 16 byte が buffer に収まらない場合)では、バッチを使いません
- UDP の GSO をカーネルが拒めば、wireguard-go がその場で GSO を止めて送り直します。
  wgstack はこれに関わりません

試験は CI の Linux、Windows、macOS のすべてで流す OS によらない試験と、OS ごとの前提の試験に分けます。

- OS によらない試験:手で進める時計の Device で、k_eff 個までの `Read`、門と台帳と W の同期、連なりを含む `Write`、控えの ACK の列(番号、TSecr、SACK の block、D-SACK、窓の欄の丸め、data より先に出ること)、まとめ作りの送った時刻、組の間の byte の配分を確かめます
- wireguard-go との結合の試験:試験用のバインドの上で wgstack を wireguard-go の device に組み込み、次を確かめます。
  device の値と `Read` の件数、`Read` の入れ物 1 つに `Send` 1 回、受信の入れ物 1 つに `Write` 1 回、`Send` が受ける message の slice の配列の末尾に `Read` の印が残ること、受信の印が `Write` まで残ること、staged のキューの溢れとピアの停止の後に W が追い越して件数が戻ること
- 依存の前提の試験:標準のバインドの `BatchSize` が Linux で 128、ほかで 1 であること、`conn.IdealBatchSize` が k_tx 以上であること、`device.QueueStagedSize`、`QueueOutboundSize`、`QueueInboundSize`、`MaxMessageSize` が上界の表の値であること、受信の包みが内側の件数 1 で包まないことを、build の OS ごとに確かめます。
  依存の更新でこの前提が変わると失敗します
- 読み直しの項目:C の呼び出しの数、staged のキューと送信のキューの順、呼び出し 1 つが持つ入れ物の数は試験で固定できないので、依存を更新するたびの読み直しの項目にします

Windows と macOS の CPU の効果は、[実機の OS との相互運用](wgstack-verification.md#実機の-os-との相互運用)の機会に測るまで未確認です。

## 確保しない計画

packet ごとの確保を 0 にし、`testing.AllocsPerRun` で確かめます。

- `Read`:packet は wireguard-go の buffer に直接作り、印もその buffer に書きます。
  件数ごとの作業の配列と台帳は Device が作成の時に持ちます
- `Write`:連なりは header を読んだ値を stack の上の固定の大きさの値で持ち、packet を写しません
- 控え:接続の枠の固定の配列に置きます
- `Send` を見る層:message を読むだけで、W は atomic の値です
- 受信の包み:wireguard-go の buffer に写すだけです

試験は、確立した接続への k_rx 個の順序どおりの segment の `Write`、順序外の segment を含む `Write`、k_tx 個の data の segment を作る `Read`、控えを含む `Read`、`Send` を見る層のそれぞれで、確保が 0 であることを確かめます。
受信の包みの試験は、試験用の内側のバインドで流します。
標準のバインドの受信は message ごとに endpoint を確保し、その確保は wireguard-go の分です。

## 危険

- 滞留のメモリ:件数を上げると wireguard-go の滞留の上界が増えます。
  案 A では件数に比例し、案 B では予算の同期の前提が崩れると上界が崩れます。
  前提は前述の試験と読み直しで確かめます
- 暗号の粒度:wireguard-go は入れ物の中の packet を 1 つの worker で順に暗号にし、復号も同じです。
  件数を上げると並列の単位が粗くなり、入れ物の最初の packet が出るまでに k - 1 個分の暗号の時間がかかります。
  UDP の遅れの p99 と、CPU の少ないホストの速さを測って確かめます
- 送信の途中の誤り:Linux 以外の `Send` は、最初の `WriteMsgUDP` の誤りで入れ物の残りを送りません。
  件数を上げると、macOS の ENOBUFS のような一時の誤りで失う packet がまとまります。
  macOS と Windows での頻度は未確認です
- ACK の数の変化:控えは `Read` が遅れる間の ACK を今より増やし、受信の向きの CPU を増やします。
  減らす向きに変えると相手の slow start を遅らせます
- 錠の保持:連なりとまとめ作りは接続の錠を長く持ち、`Read` と `Write` とアプリケーションの操作が待ちます。
  保持の長さは G_rx と G_tx で抑えます
- 公平さと遅れ:まとめ作りは通信量の少ない stream の遅れを延ばします
- 依存の挙動:`device.BatchSize()` の決め方、入れ物の数え方、`Send` の配列の長さ、`Seal` が同じ配列に書くこと、配列の末尾に触れないことは依存のコードから読んだ挙動で、公開の約束ではありません
- 時刻の共有:連なりの時刻の共有は、処理の時間の分だけ RTT の標本をずらします

## 実装の順序

各段は 1 つの PR で、[段階の順序](wgstack-performance.md#段階の順序)の確かめ(適合の試験、stream の一致、上界、競合、日常の行列)に加えて、両方の向きの `lab/tcpquality-cpu.sh fast` と `rate` を流し、前の段からの byte あたりの CPU の変化を PR に書きます。

1. `Read` のバッチと送信の向きの予算:`BatchSize` を k_tx にし、`Read` が packet を 1 つずつ作る今の処理を k_eff まで繰り返します。
   印、台帳、門、`Send` を見る層、`WGFT_AGENT_BATCH_MIB`、wireguard-go の滞留の項の直し(N_tx の形を含みます)を含みます。
   P_max を変えた測定で、速さが落ち始める値と β を決めます
2. ACK の控え:受信の規則の判定は変えず、控えの配列と `Read` の作り方を加えます。
   適合の試験の台本に、ACK の列の番号と TSecr を Linux と比べる場面を試験の書き手が加えます
3. 連なりの処理:表の検索、錠、時刻、入力の後の処理を連なりごとに 1 回にします。
   試験の設定で案 A の k_rx = 4 にした測定を加え、受信の向きの件数の選び方を所有者に戻します
4. 受信の向きの件数:所有者の選んだ形で、wgstack のトンネルの受信の件数と受信の向きの滞留の項を直します
5. 接続ごとのまとめ作り:錠、option、header の型、list の入れ直しを G_tx 個ごとに 1 回にし、送った時刻を segment ごとに増やします。
   組の間の deficit round robin の直しを含みます
6. 必要なら加える変更:順序どおりの segment の合体、8 byte ずつの checksum、写しと checksum の 1 回の走査です。
   5 の段の後のプロファイルで目立つものだけを加えます

2 の段は 3 と 4 の段より前に置きます。
受信の件数を上げると `Write` の繰り返しが速くなり、ACK の合わさりが増えるので、先に ACK の数を保つ仕組みを入れます。

## 最初に測ること

件数だけの試作(連なり、控え、まとめ作り、予算を含まないもの)を 1 回だけ目安として流した結果では、送る向きの byte あたりの CPU は件数を 32 まで上げる間減り続け、受ける向きは件数だけではほとんど減りませんでした。
値は PR #565 にあります。
次に、エージェントの CPU のプロファイルを fast の経路で取り、wireguard-go の暗号、system call、キューの受け渡し、wgstack の入力と出力の割合を求めます。
この割合で、3 から 6 の段の効果の上限を見積もります。

## 未確認の点と未決の点

- 件数の値:k_tx、G_rx、G_tx、A の値は、測って決めます
- β と P_max:β の値と、速さが落ち始める P_max(送信の経路が同時に持つ入れ物の深さ)は、1 の段の P_max を変えた測定で決めます
- 受信の向きの件数:k_rx = 1、案 A の小さな固定の k_rx、受信の向きの予算のどれを採るかは、連なりの段の測定の後に所有者が決めます
- C の大きさ:C はハンドシェイクの処理の goroutine の数(device を作る時の `runtime.NumCPU()`)を含みます。
  実際に同じピアの `SendStagedPackets` を同時に動かすのは多くて数個と読めますが、上界には呼び出しうる数を使います
- ACK の数を減らす案:連なり 1 つに 1 つの ACK にすると受信の向きの CPU は減りますが、RFC 5681 4.2 の SHOULD から外れ、相手の slow start を遅らせえます。
  参照の Linux の受け手の ACK の列を、試験の書き手がラボで外から観測してから判断します
- 控えの大きさ:控え 1 個の大きさ(48 byte 以下の見込み)は実装で測ります
- 連なりの範囲:隣り合わない同じ接続の packet を 1 つの連なりに集めるかは、1 回の `Write` の中の flow の混ざり方を測ってから決めます
- UDP の連なり:同じ endpoint への UDP の datagram の連なりで予算の錠をまとめるかは、UDP の転送の CPU を測ってから決めます
- `Read` の中の並べ方:大きな packet を先に並べて GSO のまとまりを長くするかは、測ってから決めます
- 錠の分け方:連なりの間、`Read` が同じ接続の錠を待つ時間を mutex のプロファイルで確かめます
- Windows と macOS の効果:system call が減らない OS での効果と、送信の途中の誤りの頻度は未測定です
- wgstack 以外の手間:wireguard-go の暗号の CPU が目標の 0.6 倍にどこまで届かせるかは、プロファイルまで分かりません
- 依存の更新:wireguard-go が TUN の件数、入れ物の数え方、buffer の扱いを変えた場合の扱いは、更新の時に決めます

[ユーザー空間の仕様](README.md)
