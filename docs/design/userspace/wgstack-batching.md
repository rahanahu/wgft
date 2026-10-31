# wgstack のバッチと segment のまとめ

この文書は、[wgstack](wgstack.md) が wireguard-go と packet をまとめて受け渡す方法(バッチ)と、1 本の接続の連続した segment をまとめて処理する方法(受信の連なりと送信のまとめ作り)を定めます。
どちらも未実装です。
[性能の段階](wgstack-performance.md)の[CPU の仕事](wgstack-performance.md#cpu-の仕事)の一部で、上界と不変条件は[上界の式](wgstack.md#上界の式)と[不変条件](wgstack.md#不変条件)に従います。
構造と規則の骨格をここで決め、測ってから決める値と細部は[未確認の点と未決の点](#未確認の点と未決の点)に残します。

## 目的と範囲

所有者の新しい性能の目標は、エージェントの byte あたりの CPU を両方の向きで gVisor の 0.6 倍以下にすることです。
バッチと segment のまとめは、この目標の必須の項目です。
判定は[判定の行列](wgstack-performance.md#判定の行列)の CPU の測り方(`lab/tcpquality-cpu.sh` と `tcpquality.py cpuratio`)で行います。

今の値は、経路の速さを制限しない場合(fast)の中央値で次のとおりです(ラボの測定の車線での 9 回ずつ)。

| 向き | gVisor(CPU 秒 / GB) | wgstack(CPU 秒 / GB) | 比 | 0.6 倍に要る wgstack の値 |
|---|---|---|---|---|
| エージェントが送る | 12.78 | 10.05 | 0.786 | 7.67 以下(今より 24% 減) |
| エージェントが受ける | 5.02 | 4.23 | 0.842 | 3.01 以下(今より 29% 減) |

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
依存を更新するときは、この節の挙動が変わっていないことを後述の試験で確かめます。

- device の 1 回の件数:`device.BatchSize()` はバインドの `BatchSize()` と TUN の `BatchSize()` の大きい方です。
  device は作るときにこの値を読み、buffer の pool の入れ物の容量と、TUN の読み取りの goroutine の buffer の数に使います。
  `tun.Device` の約束では、`BatchSize` は Device の寿命の間変わりません
- `Read`:TUN の読み取りの goroutine(`RoutineReadFromTUN`)は、`device.BatchSize()` 個の buffer と、offset に `MessageTransportHeaderSize`(16)を渡します。
  1 回の `Read` の結果はピアごとに 1 つの入れ物になり、入れ物はピアの staged のキュー(128 個、満杯なら古いものから捨てます)、暗号のキュー、ピアの送信のキュー(1024 個)を通り、入れ物 1 つにつき 1 回のバインドの `Send` で送られます
- `Write`:ピアの受信の goroutine(`RoutineSequentialReceiver`)は、受信の入れ物 1 つにつき 1 回 `Write` を呼びます。
  入れ物はバインドの 1 回の受信の結果のうち、そのピアの packet です。
  したがって `Write` の 1 回の件数を決めるのは TUN の `BatchSize` ではなく、バインドの 1 回の受信の件数です。
  offset は `MessageTransportOffsetContent`(16)で、`Write` が戻った後に buffer は再利用されます
- バインドの受信の件数:受信の goroutine(`RoutineReceiveIncoming`)の buffer の数は、device の値ではなくバインドの `BatchSize()` です
- 標準のバインド:`conn.StdNetBind` の `BatchSize()` は Linux で 128、それ以外の OS で 1 です。
  Linux の `Send` は、同じ大きさの datagram が続く間 UDP の GSO で 1 つの message にまとめ(1 つの message に 64 個と 65,507 byte まで、短い datagram が来たらその後は次の message)、`sendmmsg` で送ります。
  Linux の受信は `recvmmsg` と UDP の GRO で読み、GRO でまとまった datagram を分けて渡します。
  ほかの OS の `Send` は、datagram ごとに `WriteMsgUDP` を呼びます
- `Send` の上限:`Send` が使う message の配列は `conn.IdealBatchSize`(128)個です。
  128 個を超える buffer を 1 回の `Send` に渡すと配列の外を指すので、TUN の `BatchSize` は 128 以下にします
- buffer の大きさ:入れ物の packet は 1 つずつ `MaxMessageSize` の buffer を持ちます。
  Linux と macOS では 65,535 byte(ヒープの区分で 64 KiB)、Windows では 2,016 byte(2 KiB)です

今の wgft では、wgstack と `internal/nettun` の `BatchSize` が 1 で、バインドは[1 回の受信で 1 件だけを渡す包み](tunnel-recovery.md#wireguard-の受信の-1-回の件数)(`BatchOne`)なので、device の値は 1 です。
このため packet 1 つごとに、入れ物 1 つ、キューの受け渡し、ピアのタイマーの更新、`Send` の system call 1 回がかかります。
Linux の受信は、包みの内側で既に `recvmmsg` と GRO を使っているので、system call の数はまとまっています。

### Device の約束

wgstack の Device は、バッチを使うときに次の約束を守ります。

- `BatchSize`:作成の時に決めた定数 k_tx を返します。
  k_tx は 1 以上 128 以下です
- `Read`:1 個以上、min(`len(bufs)`, `len(sizes)`, k_tx) 個以下の packet を `bufs[i][offset:]` に作り、`sizes[i]` に長さを書き、個数を返します。
  `len(bufs)` は device の値なので、バインドの件数が k_tx より大きければ k_tx より長くなりえます。
  送るものが 1 つも無ければ、今と同じく次に送るものができるまで待ちます。
  1 つ作った後は待たず、次の packet を作れなくなった時点で戻ります。
  したがってバッチは遅れを足しません。
  誤りを返すのは今と同じく `Close` の後の `os.ErrClosed` だけで、そのときの個数は 0 です
- `Write`:何個の packet でも受け取り、順に処理します。
  1 件ごとの検査、捨て方、返す値と誤りは[今の境目](wgstack.md#今の境目)と同じです。
  packet は呼び出しの間だけ使い、保持しません
- 並行性:`Read` を呼ぶのは 1 つの goroutine だけです。
  `Write` はピアごとの goroutine から呼ばれるので、今と同じく並行の呼び出しに耐えます
- packet の形:どの packet も MTU 以下の IPv4 の packet です

wgstack を使うトンネルのバインドは、`BatchOne` の代わりに、1 回の受信で k_rx 件まで渡す包みにします(後述の[受信の向きの件数](#受信の向きの件数))。
gVisor を使うトンネルと `vpsd` のトンネルは `BatchOne` のままです。
バインドの選び方はトンネルの package が実装の選択と同じ所で決め、`internal/wgstack` はバインドを知りません。

## wireguard-go の滞留の上界

1 回の件数を k にすると、wireguard-go のキューに滞留する packet の上界が k 倍になります。
キューは packet ではなく入れ物を数え、入れ物の packet はそれぞれ `MaxMessageSize` の buffer を持つためです([フロー数とメモリのソフト上限](flow-limits.md))。
この上界は wgstack の `Bound` の外の、エージェントの上界の式の wireguard-go の項([エージェントとホストのメモリの条件](memory-agent-host.md#wgstack-を使うエージェントの上界))に入ります。

ピアは 1 つなので、Linux の値は次のとおりです。

| 1 回の件数 | 送信の向き:(1026 + 128) 個の入れ物 × k × 64 KiB | 受信の向き:1027 個の入れ物 × k × 64 KiB |
|---|---|---|
| 1(今) | 72.1 MiB | 64.2 MiB |
| 4 | 288.5 MiB | 256.8 MiB |
| 8 | 577.0 MiB | 513.5 MiB |
| 16 | 1,154.0 MiB | 1,027.0 MiB |
| 32 | 2,308.0 MiB | 2,054.0 MiB |

1026 と 1027 の内訳は[フロー数とメモリのソフト上限](flow-limits.md)のとおりで、128 は staged のキューです。
Windows では buffer が 2 KiB なので、値はこの表の 32 分の 1 です。
ほかに、TUN の読み取りの goroutine が device の値の個数の buffer を、受信の goroutine(Linux では 2 つ)がバインドの件数の個数の buffer を固定で持ちます。
k が 8 なら合わせて約 1.5 MiB です。
今の wgstack を使うエージェントの生きているヒープの上界は約 1,923 MiB なので、両方の向きを 8 にするだけで約 954 MiB 増えます。

この増加を抑えるため、次の 2 つの案を比べ、所有者が決めます。

- 案 A(固定の件数):k_tx と k_rx を小さな定数にし、表の値をそのまま上界に足します。
  構造は単純ですが、件数の効果と上界の増加が比例します
- 案 B(件数の予算):複数の packet の入れ物を作ってよい量を、wgft の側の数えで抑えます。
  件数を予算で抑えるだけで、送ることは止めません。
  予算を超えている間は、今と同じく 1 回に 1 件を渡します

案 B の送信の向きの数え方は次のとおりです。

- 数える値:wgstack の `Read` が渡した packet の数から、バインドの `Send` が受けた data の message の数を引いた値 P_tx です。
  `Send` を包む wgft のバインドの層が数え、トンネルの package が同じ数えを Device に渡します。
  data の message は、型が transport(4)で長さが keepalive の 32 byte より長いものです。
  ハンドシェイクと cookie の message と keepalive は、`Read` の packet ではないので数えません
- 門:`Read` は、P_tx に今回の件数を足して上限 P_max 以下のときだけ、2 個以上の packet を返します。
  超えるときは 1 個だけ返します
- 上界:2 個以上の入れ物の packet は P_max 以下で、1 個の入れ物は入れ物の数の 1154 以下なので、滞留は (1154 + P_max) 個の buffer 以下です。
  P_max が 1024 なら Linux で約 136.1 MiB で、今より約 64 MiB 増えます
- 数えの漏れ:wireguard-go が `Send` の前に捨てた packet(staged のキューの溢れ、ピアの停止、宛先のピアの無い packet、nonce の使い切り)は引かれず、P_tx に残ります。
  漏れは P_tx を実際より大きくするだけなので、上界は崩れません。
  漏れが積もると件数が 1 に戻り、性能が今の値に戻ります。
  P_tx はトンネルの作り直しで 0 に戻ります。
  門で 1 件に絞った回数を `Stats` に数えます

案 B の受信の向きは、包みが渡した transport の message(keepalive を除く)の数から、wgstack の `Write` が受けた packet の数を引いた値 P_rx で同じ門を作ります。
包みは、P_rx に件数を足して上限以下のときだけ 2 件以上を渡します。
上界は (1027 + P_max) 個の buffer 以下です。
受信の漏れは、復号の失敗、replay、受信者の番号の合わない message、送信元の許可の外の packet です。
WireGuard の UDP のポートに偽の transport の message を送れる相手は漏れを積ませ、受信の件数を 1 に戻せます。
戻るのは性能だけで、メモリの上界と転送は崩れません。
この扱いを受け入れるか、受信の向きだけ案 A にするかも、所有者が決めます。

案 B は wgft のバインドの層と Device を数え 1 つでつなぎます。
数えは標準ライブラリの atomic の値 1 つで、トンネルの package が作って両方に渡します。
`internal/dataplane/userspace/wgbind` と `internal/wgstack` は互いを import せず、`internal/wgstack` は今と同じく標準ライブラリと `tun` の型だけを import します。

## 受信の向きの件数

wgstack の `Write` が 1 回に受ける件数は、包みが 1 回に渡す件数 k_rx で決まります。
Linux の包みは、今と同じく内側の標準のバインドを 128 件分の自前の buffer で読み、wireguard-go の呼び出しごとに k_rx 件まで写して渡します。
写す回数と system call の数は今と同じで、変わるのは入れ物の数です。
Windows と macOS の標準のバインドは 1 回に 1 件なので、包みを使わず、`Write` は今と同じく 1 件ずつ受けます。

## 受信の向き:連なりの処理

### 連なりの定義

連なりは、1 回の `Write` の中で続く、同じ 4 つ組の確立した接続に当たる TCP の segment の列です。
長さの上限は G_rx で、k_rx と同じ値にします。
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
- 送り方:`Read` は接続の出力のうち、控えを古い順に中身の無い ACK として先に作り、その後に今の規則の出力を作ります。
  窓の欄は作る時の広告した右端から求めます。
  右端は後ろへ戻らないので、古い番号の控えも、受信のバッファを超える右端を知らせません
- 数の上限:控えは接続ごとに A 個までの固定の配列に置き、A は G_rx と同じ値にします。
  満杯のときは控えに写さず、今と同じく次の ACK に合わせます。
  したがって ACK の数は今より減らず、最悪でも今の合わさり方になります
- 閉じる時:接続が CLOSED になるか枠を返すときに、控えを捨てます。
  今の、作る前の ACK の印を捨てる扱いと同じです

控えは連なりの外でも働き、`Read` が遅れる間の ACK の合わさりも減らします。
このため、控えは受信の向きの ACK の数を今より増やし、ACK の暗号と送信の CPU を増やします。
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
  受け入れの判定と PAWS は、TSval が減らないことと順序どおりであることで最初の segment の判定から決まります。
  データの受け入れ、推定した MSS の更新、ACK の規則の判定は segment ごとに行います
- 外れたとき:条件を満たさない segment で合体を終え、連なりの処理に戻ります

## 送信の向き:1 回の Read で複数の segment を作る

### 組の選び方

`Read` は、packet を 1 つずつ作る今の処理を、件数の上限か作るものが尽きるまで繰り返します。
4 つの組の間の deficit round robin は、作った packet の byte をそのまま数えます。
接続の組は 1 回の選択で後述の G_tx 個まで作るので、deficit が負のまま次の回に quantum を足しても正にならない組は、その回を飛ばします。
今の実装は quantum を足した後の deficit が 0 以下でも組を選ぶので、この点を直します。
これで、組の間の byte の配分は今と同じになります。

### 接続ごとのまとめ作り

接続の組から取り出した接続は、錠を 1 回取り、今の優先の順(高速の再送、窓の probe、TLP の probe、規則 1 の再送、新しいデータと FIN、規則 3 の再送、ACK の控えと ACK)で G_tx 個まで segment を作ります。
G_tx は k_tx 以下です。
segment ごとの状態の更新(送信の記録、送った時刻の順の list、SND.NXT、RTO と TLP の期限、輻輳の窓の検証、PRR)は今と同じく segment ごとに行います。
記録は今と同じく segment 1 つに 1 件で、複数の segment を 1 件にまとめません。
SACK と RACK の損失の単位を segment のまま保つためです。

まとめ作りで 1 回にするのは次の手間です。

- 錠と時刻:接続の錠と時刻を 1 回にします。
  まとめた segment の送った時刻は同じになります。
  RFC 8985 は送った時刻が同じ segment を終わりの番号で順に並べるので、RACK の判定は変わりません
- option:timestamp の値と SACK の block はまとめの間で同じなので、最初の segment で作った option を写します。
  D-SACK の block は最初の segment にだけ載るので、D-SACK を載せた segment の後は option を作り直します
- header:最初の segment の header を型にして、番号、IP の ID、長さ、checksum だけを書き直します。
  IP の ID は G_tx 個をまとめて取ります
- list の入れ直し:出力の list へは、まとめの最後に 1 回だけ入れ直します

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
中身の無い ACK や短い最後の segment が間に入ると、そこで GSO の message が分かれます。
1 回の `Read` の中で大きな packet を先に並べるかどうかは、測ってから決めます。

## 上界の式への項

wgstack の `Bound` に加える項は次のとおりです。

| 構造 | 大きさ | 入る項 |
|---|---|---|
| ACK の控え | 接続の枠ごとに A 個 × 控え 1 個(48 byte 以下の見込み)。A が 8 で K が 2048 なら N_c × 384 byte で約 0.94 MiB | 新しい項 a_ack。N_c × (c_conn + f_s + f_r + r_f + h_f + a_ack) |
| 送信の向きの数え | Device の固定の値 | M_fix |
| `Read` と `Write` の作業の値 | 件数によらない固定の大きさ。連なりは packet を写さず、wireguard-go の buffer の上で処理します | M_fix |

wgstack の外の項は、エージェントの上界の式の wireguard-go の項で、前述の[wireguard-go の滞留の上界](#wireguard-go-の滞留の上界)の値に置き換えます。
実装の段では、[フロー数とメモリのソフト上限](flow-limits.md)、[トンネルの回復と作り直し](tunnel-recovery.md)の 1 回の件数の 2 項、[エージェントとホストのメモリの条件](memory-agent-host.md#wgstack-を使うエージェントの上界)の表を、wgstack を使う場合の値で同じ変更の中で直します。

敵対的な入力がバッチで保持を増やせないことは、次の構造で決まります。

- 連なりは `Write` の中で同期して処理し、`Write` が戻った後に packet も連なりの状態も残しません
- 控えは接続ごとの固定の配列で、満杯なら合わせるだけです
- 件数の数えの漏れは件数を 1 に戻すだけで、保持を増やしません

不変条件との対応は次のとおりです。

- I1 有限、I2 保持の前の予約:新しい構造は控えの固定の配列と固定の作業の値だけで、作成の時に確保します
- I4 TCP の正しさ:segment ごとの規則と記録は変えず、控えは ACK を捨てずに遅らせるだけです
- I5 自己増殖の禁止:バッチと控えは入力と `Read` の中でだけ動き、タイマーを足しません
- I7 隔離:変更は wgstack とトンネルの wgstack の経路だけで、カーネルモードの経路に入りません

## OS ごとの挙動と代わりの経路

| OS | `Write` の件数 | `Read` の件数 | `Send` の system call | `MaxMessageSize` |
|---|---|---|---|---|
| Linux | k_rx まで(包み) | k_tx まで | `sendmmsg` と UDP の GSO で入れ物ごとに 1 回程度 | 64 KiB |
| Windows | 1(標準のバインドが 1) | k_tx まで | datagram ごとに 1 回 | 2 KiB |
| macOS | 1(標準のバインドが 1) | k_tx まで | datagram ごとに 1 回 | 64 KiB |

OS によらない部分は、wgstack の `Read` と `Write`、連なり、控え、まとめ作りです。
Linux だけの部分は、包みの受信の件数と、wireguard-go の中の `recvmmsg`、`sendmmsg`、UDP の GSO と GRO です。
Windows と macOS では受信の連なりの長さが 1 になり、今の 1 件ずつの経路と同じ処理になります。
送信のまとめ作りと `Read` のバッチは、Windows と macOS でも wireguard-go の入れ物ごとの手間を減らしますが、system call の数は減りません。

能力が無い場合の代わりの経路は、wgstack の側で分岐を持たない形にします。

- `Write` はどの件数でも同じ処理で、件数が 1 なら今の処理と同じです
- 包みは、内側のバインドの件数が 1 なら包まずに内側を返します(今の `BatchOne` と同じ判定)
- UDP の GSO をカーネルが拒めば、wireguard-go がその場で GSO を止めて送り直します。
  wgstack はこれに関わりません

試験は CI の Linux、Windows、macOS のすべてで流す OS によらない試験と、OS ごとの前提の試験に分けます。

- OS によらない試験:手で進める時計の Device で、k_tx 個までの `Read`、連なりを含む `Write`、控えの ACK の列(番号、TSecr、SACK の block、D-SACK)、組の間の byte の配分を確かめます
- wireguard-go との結合の試験:`conn/bindtest` のような試験用のバインドの上で wgstack を wireguard-go の device に組み込み、device の値、`Read` の件数、packet の順を確かめます
- 依存の前提の試験:標準のバインドの `BatchSize` が Linux で 128、ほかで 1 であること、`conn.IdealBatchSize` が k_tx 以上であること、包みが内側の件数 1 で包まないことを、build の OS ごとに確かめます。
  依存の更新でこの前提が変わると失敗します

Windows と macOS の CPU の効果は、[実機の OS との相互運用](wgstack-verification.md#実機の-os-との相互運用)の機会に測るまで未確認です。

## 確保しない計画

packet ごとの確保を 0 にし、`testing.AllocsPerRun` で確かめます。

- `Read`:packet は wireguard-go の buffer に直接作り、件数ごとの作業の配列は Device が作成の時に持ちます
- `Write`:連なりは header を読んだ値を stack の上の固定の大きさの値で持ち、packet を写しません
- 控え:接続の枠の固定の配列に置きます
- 数え:Device の atomic の値です
- 包み:wireguard-go の buffer に写すだけです

試験は、確立した接続への k_rx 個の順序どおりの segment の `Write`、順序外の segment を含む `Write`、k_tx 個の data の segment を作る `Read`、控えを含む `Read` のそれぞれで、確保が 0 であることを確かめます。
包みの受信の関数も同じく確かめます。

## 危険

- 滞留のメモリ:件数を上げると wireguard-go の滞留の上界が増えます。
  案 A では件数に比例し、案 B では数えの誤りが上界を崩します。
  数えは、数える message の型と大きさの判定を試験で固定します
- ACK の数の変化:控えは `Read` が遅れる間の ACK を今より増やし、受信の向きの CPU を増やします。
  減らす向きに変えると相手の slow start を遅らせます
- 錠の保持:連なりとまとめ作りは接続の錠を長く持ち、`Read` と `Write` とアプリケーションの操作が待ちます。
  保持の長さは G_rx と G_tx で抑えます
- 公平さと遅れ:まとめ作りは通信量の少ない stream の遅れを延ばします
- 依存の挙動:`device.BatchSize()` の決め方、入れ物の数え方、`Send` の配列の長さは依存のコードから読んだ挙動で、公開の約束ではありません。
  依存の更新のたびに前提の試験で確かめます
- 時刻の共有:連なりとまとめ作りの時刻の共有は、処理の時間の分だけ RTT の標本をずらします

## 実装の順序

各段は 1 つの PR で、[段階の順序](wgstack-performance.md#段階の順序)の確かめ(適合の試験、stream の一致、上界、競合、日常の行列)に加えて、両方の向きの `lab/tcpquality-cpu.sh fast` と `rate` を流し、前の段からの byte あたりの CPU の変化を PR に書きます。

1. `Read` のバッチ:`BatchSize` を k_tx にし、`Read` が packet を 1 つずつ作る今の処理を繰り返します。
   wireguard-go の滞留の項の変更(案 A か案 B の送信の向き)と、その文書の直しを含みます
2. ACK の控え:受信の規則の判定は変えず、控えの配列と `Read` の作り方を加えます。
   適合の試験の台本に、ACK の列の番号と TSecr を Linux と比べる場面を試験の書き手が加えます
3. 受信の向きの件数:wgstack のトンネルのバインドを k_rx 件の包みにし、受信の向きの滞留の項を直します
4. 連なりの処理:表の検索、錠、時刻、入力の後の処理を連なりごとに 1 回にします
5. 接続ごとのまとめ作り:錠、option、header の型、list の入れ直しを G_tx 個ごとに 1 回にします。
   組の間の deficit round robin の直しを含みます
6. 必要なら加える変更:順序どおりの segment の合体、8 byte ずつの checksum、写しと checksum の 1 回の走査です。
   5 の段の後のプロファイルで目立つものだけを加えます

2 の段は 3 と 4 の段より前に置きます。
受信の件数を上げると `Write` の繰り返しが速くなり、ACK の合わさりが増えるので、先に ACK の数を保つ仕組みを入れます。

## 最初に測ること

最初に、1 の段と 3 の段に当たる最小の試作で、件数だけの効果を測ります。
試作は `Read` が packet を作れる間だけ繰り返し、包みが k_rx 件まで渡すもので、連なり、控え、まとめ作りを含みません。
効果が 1 の段の主な見込みである wireguard-go の入れ物ごとの手間と system call から来るなら、送る向きの値は件数とともに下がります。

2026-10-31 に、使い捨てのラボの VM で普通の仕事として 1 回だけ試しました(fast の経路、512 MiB、組ごとに 2 回を 2 巡、gVisor と同じ時間帯)。
測定の車線ではないので、値は目安で、判定には使いません。
同じ VM の今の wgstack の比は、送る向きで 0.64、受ける向きで 0.75 で、車線の値(0.786 と 0.842)より低く出ました。

| 向き | 試作の件数 | wgstack の CPU 秒 / GB | gVisor との比 |
|---|---|---|---|
| 送る | 1(今) | 4.28 | 0.64 |
| 送る | k_tx = 8 | 3.14 | 0.38 |
| 送る | k_tx = 32 | 2.19 | 0.27 |
| 受ける | 1(今) | 2.23 | 0.75 |
| 受ける | k_tx = 8 | 2.11 | 0.74 |
| 受ける | k_tx = 8、k_rx = 8 | 2.01 | 0.72 |
| 受ける | k_tx = 32、k_rx = 32 | 2.02 | 0.72 |

送る向きは件数だけで今より 27%(8)と 49%(32)減り、スループットも上がりました。
送る向きの主な効果は、見込みのとおり wireguard-go の入れ物ごとの手間と system call から来ると考えます。
8 から 32 でも減り続けるので、件数と滞留の上界の取り合いが大きく、案 B を選ぶ理由になります。
受ける向きは 10% ほどしか減りませんでした。
試作の `Read` は接続ごとに ACK を 1 つしか作れず、`Write` は packet ごとに錠を取るので、受ける向きの効果には連なり、控え、プロファイルによる手間の特定が要ります。
試作は ACK の数を数えていないので、k_rx を上げた時に ACK が合わさって減った分が値に含まれるかは未確認です。

その次に、エージェントの CPU のプロファイルを fast の経路で取り、wireguard-go の暗号、system call、キューの受け渡し、wgstack の入力と出力の割合を求めます。
この割合で、4 から 6 の段の効果の上限を見積もります。

## 未確認の点と未決の点

- 件数の値:k_tx、k_rx、G_rx、G_tx、A の値は、測って決めます
- 滞留の上界の案:案 A と案 B のどちらを採るか、案 B の P_max の値、受信の向きの漏れを受け入れるかは、所有者が決めます
- ACK の数を減らす案:連なり 1 つに 1 つの ACK にすると受信の向きの CPU は減りますが、RFC 5681 4.2 の SHOULD から外れ、相手の slow start を遅らせえます。
  参照の Linux の受け手の ACK の列を、試験の書き手がラボで外から観測してから判断します
- 控えの大きさ:控え 1 個の大きさ(48 byte 以下の見込み)は実装で測ります
- 連なりの範囲:隣り合わない同じ接続の packet を 1 つの連なりに集めるかは、1 回の `Write` の中の flow の混ざり方を測ってから決めます
- UDP の連なり:同じ endpoint への UDP の datagram の連なりで予算の錠をまとめるかは、UDP の転送の CPU を測ってから決めます
- `Read` の中の並べ方:大きな packet を先に並べて GSO のまとまりを長くするかは、測ってから決めます
- 錠の分け方:連なりの間、`Read` が同じ接続の錠を待つ時間を mutex のプロファイルで確かめます
- Windows と macOS の効果:system call が減らない OS での効果は未測定です
- wgstack 以外の手間:wireguard-go の暗号の CPU が目標の 0.6 倍にどこまで届かせるかは、プロファイルまで分かりません
- 依存の更新:wireguard-go が TUN の件数と入れ物の数え方を変えた場合の扱いは、更新の時に決めます

[ユーザー空間の仕様](README.md)
