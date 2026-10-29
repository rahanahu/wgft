# wgstack の検証

[エージェントの wgft の netstack](wgstack.md)(wgstack)の完成は、Linux との適合、損なわれた経路での転送、fuzzing、敵対的な保持の試験、退行の確認で判定します。
適合の試験は一部の台本が動き、損なわれた経路での試験は計測の骨組みが動きます。
ほかの試験は未実装です。
試験の形と判定の規則をここで決め、個々の試験の内容は実装の時に決めます。

## 検証の原則

- 参照の実装:正しさの基準は Linux の TCP/IP です。
  gVisor は今の既定の実装として同じ試験に流し、差を記録しますが、基準にはしません
- 書き手の分離:試験を書く人と wgstack を実装する人を分けます。
  試験の書き手は規格と Linux の挙動から試験を書き、wgstack のコードを読みません。
  wgstack の[期待した差の一覧](#期待した差の一覧)に行を足せるのは、試験の書き手と所有者だけです
- Linux で先に通すこと:新しい試験は、ラボの Linux で通ってから試験の一式に入ります。
  Linux で通らない試験は、試験の誤りとして直します
- 決定的な実行:wgstack に対する試験は、手で進める時計と固定の乱数の種で核を直接進め、壁時計の待ちを使いません。
  Linux と gVisor に対する試験は壁時計で動くので、[壁時計で測る区間を使うテストの規範](../../development/testing.md#壁時計で測る区間を使うテストの規範)に従います

## 適合の試験

適合の試験は、トンネルの側から IPv4 の packet を入れ、出てきた packet とアプリケーションの側の出来事を確かめる、packet の水準の台本です。
台本の 1 行は、packet を入れる、packet を期待する、時刻を進める、アプリケーションの操作(`Accept`、読み取り、書き込み、`CloseWrite`、`Close`、`Abort`)を行う、のどれかです。
同じ台本を 3 つの実装に流します。

- wgstack:ホストの `go test` で流します。
  核を直接進める実行と、手で進める時計を渡した Device の `tun.Device` の境目に流す実行の 2 つを持ちます。
  後者は、核と Device の間の錠、通知、出力の選び方の誤りを捉えます
- gVisor:ホストの `go test` で、`internal/nettun` の Device の `tun.Device` の境目に流します
- Linux:ラボの VM の network namespace の中の TUN に流し、namespace の sysctl を後述の固定の値にしてから始めます。
  TUN の offload は切り、segment の大きさを TCP の処理だけが決めるようにします。
  root と TUN を要するので、ホストでは流しません

ISN、timestamp の値、IP の ID のように実装ごとに決まる値は、台本で変数に束縛し、後の行では関係(前の値より大きい、前の値と同じ)で比べます。
窓の大きさと時刻は、値そのものではなく台本が定める範囲で比べます。
時刻の範囲は RTO の回数のように規格の単位で書きます。

台本が扱う分野は次のとおりです。
各分野の網羅の度合いは、実装の時に試験の書き手が決めます。

- 握手:option の交渉、MSS の下限、握手の途中の表と accept の待ち行列の満杯、SYN に載ったデータ
- データ:順序どおりの転送、順序外の到着と区間の表、窓の外のデータ、送り手と受け手の SWS の回避、遅延 ACK
- 窓:0 の窓、persist の probe、窓の更新、窓の scale
- 再送:RTO とその倍化、NewReno の高速の再送と回復、再送の打ち切り
- RFC 7323 と RFC 5961:PAWS、challenge ACK、窓の外の RST と SYN
- 終わり方:ハーフクローズ、同時の close、未読のデータを持った `Close`、`Abort`、TIME_WAIT と RFC 6191 の再利用、FIN_WAIT_2 へのデータ
- ICMP:誤りの送信元の確認、Fragmentation Needed と MTU の下限、Port Unreachable、echo
- UDP と断片:受信の予算、送信時の断片化、再組み立ての表の満杯と期限

### 参照の Linux の設定

Linux の既定は、完成に含めない回復の仕組みを有効にしています。
既定のままでは、損失の回復の台本は Linux の上で常に wgstack と違う結果になるか、違いを吸収するまで条件を緩めて正誤を見分けられなくなります。
このため、参照の Linux の namespace では、完成の機能に合わせて次の値に固定します。

- 輻輳の制御:`net.ipv4.tcp_congestion_control=reno`
- RACK と TLP:`net.ipv4.tcp_recovery=0`、`net.ipv4.tcp_early_retrans=0`
- F-RTO:`net.ipv4.tcp_frto=0`
- ECN、TFO、SYN cookie:`net.ipv4.tcp_ecn=0`、`net.ipv4.tcp_fastopen=0`、`net.ipv4.tcp_syncookies=0`
- D-SACK:`net.ipv4.tcp_dsack=0`
- 測定値の持ち越し:`net.ipv4.tcp_no_metrics_save=1`。
  前の台本の RTT と輻輳の窓が次の台本に残らないようにします
- 受信のバッファ:`net.ipv4.tcp_moderate_rcvbuf=0` とし、台本の側のソケットに floor と同じ大きさを与えます
- 小さな書き込みのまとめ:`net.ipv4.tcp_autocorking=0`

損失の回復を確かめる台本は、相手の SYN で SACK を許さず、両者を NewReno の動作にします。
SACK を交渉する台本は、受け手として返す SACK の block の内容と順を確かめます。
値の一覧は、試験の書き手が台本を足すときに増やします。

設定で外せない Linux の挙動は、期待した差として扱います。

- 回復の間の送る量:Linux は回復の間の送る量を PRR(RFC 6937)で決め、RFC 6582 の窓の膨らませ方を使いません。
  回復の台本は、再送する範囲と順、回復の終わる位置、byte の列の一致を確かめ、回復の間の輻輳の窓の値は比べません
- quickack:Linux は接続の始めと黙った後に、遅延なしで ACK を返す期間を持ちます
- 黙った後の窓:Linux の `tcp_slow_start_after_idle` は RFC 5681 の 4.1 節と異なる計算で窓を戻します
- 閉じた後の打ち切り:Linux は閉じた接続の再送と probe を `tcp_orphan_retries` で打ち切ります。
  wgstack の扱いは未決です([未確認の点と未決の点](wgstack.md#未確認の点と未決の点))
- RTO の計算:最小の RTO と RTTVAR の扱いの細部が違うので、時刻は RTO の回数の範囲で比べます
- 送る量が足りない間の窓:Linux は、アプリケーションが送る量の足りない間に輻輳の窓を広げない独自の検証を持ちます

### 期待した差の一覧

Linux との差は、実装ごとに 1 つの一覧で管理します。
一覧の 1 行は、台本、行、差の内容、差を受け入れる理由を持ちます。
一覧に無い差が出たら試験は落ち、一覧にあるのに差が出なくなった行も、一覧を直すまで試験を落とします。
wgstack の一覧に行を足せるのは、試験の書き手と所有者だけです。
実装する人は、差を見つけたら一覧を変えずに知らせ、書き手か所有者が受け入れるかを決めます。
実装する人が一覧を変えられると、落ちた試験を一覧で黙らせられるためです。

wgstack の一覧に最初から入る差は、[wgstack の設計](wgstack.md#tcp-の機能)が選んだ次の点です。

- MSS が 536 より小さい SYN を捨てること([MSS の下限](packet-validation.md#tcp-の-mss-の下限))
- next-hop MTU が 552 より小さい Fragmentation Needed を捨てること([Fragmentation Needed の MTU の下限](packet-validation.md#fragmentation-needed-の-mtu-の下限))
- SYN cookie を持たないこと(参照の Linux の設定でも切ります)
- ECN を交渉しないこと
- 緊急のデータを通常のデータとして渡すこと
- D-SACK を返さないこと(参照の Linux の設定でも切ります)
- 前節の設定で外せない Linux の挙動

gVisor の一覧は、今の `internal/nettun` の試験が固定している gVisor との差(例えば[断片に対する ICMP](packet-validation.md#断片に対する-icmp)の 3 つの差)とは別のものです。
gVisor の一覧は、gVisor を基準でなく比較の対象として扱うために持ちます。

試験の仕組みは、一覧を次の規則で照合します。

- 鍵:一覧の行は台本の名前と確かめの名前を鍵にし、観測した差と受け入れる理由を持ちます。
  観測した差は、確かめが落ちたときに実装が代わりにしたことを、実行ごとに変わる番号を含めずに書いたものです
- 照合:確かめが落ち、その観測が行の観測と一致すれば、差として受け入れます。
  一致しなければ、差の形が変わったとして試験を落とします
- 古い行:行にある確かめが通ったら試験を落とします。
  すべての台本を流した実行で、どの確かめも行の鍵に当たらなかった場合も、鍵の誤りか不要な行として試験を落とします。
  `-run` で台本を絞った実行では、当たらなかった行をログに出すだけにします

### 試験の置き場所と DUT

適合の試験の台本は `internal/tcpharness` に置きます。
この package は、試験の側の IPv4 と TCP の組み立てと解釈、台本、期待した差の照合を持ち、モジュールの中の何も import しません。
台本が実装のコードに頼れないようにするためです。
実装ごとの DUT は別の package に置き、その package は核と自分が作る実装だけを import します。
`internal/tcpharness/gvisordut` は `internal/nettun` の公開の面だけで Device を作り、wgft の SACK の設定、バッファの範囲、入口の検査、中身の無い ACK の予算をそのまま試験に含めます。
`internal/tcpharness/linuxdut` は、ラボの VM の network namespace の中の TUN と Linux のソケットを使います。
新しい network namespace の `net.ipv4.tcp_*` の値は、多くがカーネルに組み込まれた既定の値になり、一部が最初の namespace の値の写しになります。
ラボの VM の 6.1 のカーネルでは、`tcp_congestion_control`、`tcp_rmem`、`tcp_wmem` が写しになり、`tcp_frto`、`tcp_sack`、`tcp_recovery`、`tcp_autocorking` は既定の値になりました。
どの値が写しになるかはカーネルの版で変わりうるので、`linuxdut` は[参照の Linux の設定](#参照の-linux-の設定)の値をすべて書き込み、読み戻して確かめます。
待ち受けのソケットには floor と同じ 256 KiB を送信と受信のバッファとして与えます。
`internal/tcpharness/wgstackdut` は、手で進める時計(`ManualClock`)と台本の種から作った乱数の源を渡して wgstack の Device を作ります。
この Device は goroutine を作らず、DUT は `Write`、`Poll`、`Tick` で Device を進める `ClockedDUT` です。
wgstack の台本の実行は、実装する人が直している確かめが残る間、環境変数 `WGFT_TEST_WGSTACK_CONFORMANCE=1` を与えたときだけ流します。
本番の package はどれも `internal/tcpharness` とその下を import しません。
`internal/dataplane/deps_test.go` がこれらの規則を検査します。

DUT は次の操作を持ちます。

- packet:`Inject` がトンネルから届いた IPv4 の packet を 1 つ渡し、`Emitted` が実装の送った packet を順に返します。
  MTU を超える packet が出たら試験を落とします
- アプリケーション:`Listen` と `Accept` が受動の open を行い、接続は `net.Conn` に加えて `CloseWrite` と `Abort` を持ちます。
  中継が型アサーションで探す `Delivered`、`CloseForDelivery`、`OnBoost` は、実装が持つ場合だけ台本が確かめます
- 手で進める時計:時計を渡せる実装は `ClockedDUT` として `Now`、`Advance`、`Poll` を持ちます。
  台本は `Poll` で packet を引き取り、何もなければ時計を 1 ms ずつ進めるので、壁時計を待ちません。
  実装は `Inject` と `Advance` の中で処理を終え、送る packet を `Poll` が引き取るまで自分の中に持ちます。
  実装が容量の決まった channel へ送らないので、台本が読む前に多くの segment を入れても、台本の goroutine は `Inject` の中で止まりません

台本の側の乱数は、試験の側のポート、ISN、timestamp の起点に使います。
乱数は実行ごとの種と台本の名前から決め、種をログに出します。
環境変数 `WGFT_TEST_TCPHARNESS_SEED` で同じ種を与えると、台本は同じ値を使います。
DUT を作る関数も同じ種を受け取るので、wgstack の DUT はこの種を ISN の鍵と表の hash の種に使えます。
Linux と gVisor の ISN と timestamp の起点は、それぞれの実装が持つ乱数の源から決まるので、種では固定できません。

規格が直ちに返すとする segment について、台本は、壁時計では 100 ms 以内に、手で進める時計では時計を進める前に出ることを確かめます。
順序外の segment への重複した ACK、穴を埋めた segment への ACK(窓の scale の台本で順序外の区間の後に穴を埋めたときを含みます)、3 つ目の重複した ACK による再送、PAWS で捨てた segment への重複した ACK、TIME-WAIT で再送された FIN への ACK がこれに当たります。
相手の data と FIN への ACK は遅らせてよいので、RFC 1122 の遅延 ACK の上限の 500 ms で確かめます。
Linux はこの ACK を遅延 ACK のタイマーで約 40 ms 遅らせます。
100 ms は遅延 ACK と RTO の下限の 200 ms より短いので、遅延した応答はこの範囲に入りません。

台本の確かめの有効さは、故障を入れた実装に台本を流して調べます。
ホストの `go test` は、gVisor を包んで故障を 1 つずつ入れ、その故障を捉えるはずの確かめが落ちることを求めます。
中身の無い ACK を 300 ms 遅らせる故障では、順序外の台本の重複した ACK の確かめが落ちます。
MSS が 536 の SYN の checksum を壊す故障では、どの実装も答えるはずの MSS 536 の確かめが落ちます。
RCV.NXT から 64 KiB より先の data を捨てる故障では、窓の scale の台本で順序外の区間を保持する確かめが落ちます。

## 損なわれた経路での試験

ラボで、トンネルの外側の経路に netem で損失、並べ替え、重複、遅延、1 秒から数秒の途絶を入れ、転送した byte の列の hash が一致することを確かめます。
完成の判定で求めるのは、byte の列の一致と、接続が誤りなく終わることです。
回復の時間、スループット、遅れの p99、CPU は同じ構成で Linux と gVisor と並べて記録し、性能の段階の目標と比べます。
記録の方法と回数は性能の段階で決めます。

ラボの `lab/tcpquality.sh` が、この試験の骨組みです。
LAN のホストが同じ大きさの byte の列を送り、client が規則を通して受け取ります。
エージェントはカーネルモード(TCP の終点は LAN のホストの Linux)とユーザー空間モード(TCP の終点はエージェントの netstack)の両方で流します。
VPS と自宅の間の経路には netem の遅延と損失を入れます。
受け手が決まった量を読んだ時点で経路を途絶させ、途絶の前か後に読み取りが無い実行は判定不能とします。
1 回の実行ごとに、hash の一致、スループット、途絶の終わりから最初の byte までの時間、途絶をはさむ読み取りの間隔、途絶の外で最も長い読み取りの間隔を出し、複数の実行の中央値を出します。
ラボの VM の tc とカーネルは netem の乱数の種を受け付けないので、損失の位置は実行ごとに変わります。

## fuzzing

Go の fuzzing で 2 種類の対象を持ちます。

- packet の解釈:IPv4、TCP、UDP、ICMP のヘッダーと option の解釈が、どの byte の列でも panic せず、範囲の外を読まないこと
- 核の packet の列:手で進める時計の下で、任意の packet と時刻の進みとアプリケーションの操作の列を核に与えます。
  各段の後に、予約の合計が上界の式の値以下であること、表の数と予約が一致すること、Device の `Close` の後に予約が 0 に戻ることを確かめます

fuzzing で見つけた入力は、回帰の試験の入力として残します。

## 敵対的な保持の試験

次の入力のそれぞれで、wgstack の会計が数える保持が上界の式の値で止まり、入力が止まった後に元の値へ戻ることを確かめます。

| 入力 | 確かめること |
|---|---|
| 中身の無い segment の洪水(重複した ACK、SACK block を持つ ACK、累積の確認を 1 byte ずつ進める ACK) | 処理待ちが生まれず、送り残しの多い接続でも保持が増えません |
| 順序外の洪水(多数の穴を作る小さな segment) | 順序外の保持が受信の予約の内側に留まり、区間の数が H を超えません |
| 読まない相手 | 送信の保持が送信の予約で止まり、窓の probe が続く間も増えません |
| 偽の送信元からの SYN の洪水 | 握手の途中の表が N_syn で止まり、接続の枠とバッファを使いません |
| 短い接続の入れ替わり | TIME_WAIT の表が M で止まり、追い出した数が数えられます |
| 断片の洪水 | 再組み立ての表が今の上限で止まります |
| 読まない UDP の endpoint への洪水 | endpoint の上限と Device の予算で止まります |
| 握手を終えたまま `Accept` されない接続 | accept の待ち行列が Q と待ち受けごとの上限で止まり、超えた最後の ACK を捨てます |
| どの接続にも当たらない segment の洪水 | 制御の輪だけが埋まり、SYN-ACK、TCP の data、UDP の出力が組の配分の分だけ進み続けます |
| 需要の無いまま boost の枠を持つ接続 | 別の接続の取得の要求で枠が 1 秒の後に返り、黙った相手が古い窓へ送ったデータは捨てられて再送されます |
| 遅い読み手への小さな書き込み(`TCP_NODELAY`) | 送信の記録の輪が容量で止まり、送信の輪の byte が予約を超えません |
| floor に戻った保有者への送信の再開と、その後の読み手の停止(Windows の再送の回数を超える長さ) | 古い窓の先のデータを捨てるたびに重複した ACK を返し、相手が接続を諦める前に回復するか、諦めるまでの時間を記録します |
| 出力の詰まり(wireguard-go が `Read` を呼ばない間) | 出力の保持が増えず、詰まりが解けた後に送り直しで回復します |

会計の値は構造の上限を確かめるのに使います。
生きているヒープも、GC を強制した後に `runtime/metrics` で測り、会計の値と M_fix の和からの差を記録します。
この差の上限は Go のランタイムの費用として式の外にあり([上界の式](wgstack.md#上界の式))、記録は保証ではありません。
ホストで流せる試験はホストの `go test` に置き、実際のトンネルを要する試験はラボに置きます。

## 競合の試験

`-race` を付けた `go test` で、多数の接続への同時の読み書き、`Close`、`Abort`、待ち受けの `Close`、Device の `Close`、boost の取得と回収、TIME_WAIT の表の追い出しを、入力と出力と並べて動かす負荷の試験を持ちます。
確かめるのは、データの競合が無いこと、錠の待ちが止まらないこと、Device の `Close` の後に goroutine と予約が残らないことです。

## 実機の OS との相互運用

Windows、macOS、スマートフォン、ゲーム機の TCP を相手に、本番と同じ VPS を通した経路で wgstack を確かめます。
所有者の実機を要するので、[テストの規範](../../development/testing.md)の E 類に置きます。
未実装です。

## 退行の確認

- 既定の経路:既定は gVisor のままなので、ラボの一式(A9)を今までどおり両モードで流します
- wgstack の経路:ユーザー空間モードのエージェントを wgstack で動かすラボの一式の実行を加えます。
  ラボにこの選択を渡す仕組みは未実装で、実装の時に足します
- 中継の試験:`internal/dataplane/userspace/relay` と `internal/netpipe` の試験のうち netstack の接続を使うものを、両方の実装に流します。
  今の試験の一部は `nettun.Create` を直接呼ぶので、実装を選んで Device を作る試験用の関数を足します。
  `tcp_reset_before_accept_test` は、accept の待ち行列で RST を受けた接続を gVisor が `Accept` で返す挙動を確かめているので、wgstack では待ち行列から外す挙動を確かめる形に分けます
- 公開のサーフェス:CLI のヘルプ、管理用 API、終了コード、`agent doctor` の JSON が、実装の選択によって変わらないことを確かめます

新しい試験は[テストの規範](../../development/testing.md)の「新設」として[追加テストの台帳](../../development/testing-catalog.md)に記録し、実装された時点で類と契機を決めます。
既定を gVisor から替える前に、ステージングの環境で長く動かして確かめます。
期間と判定の基準は、その判断の時に所有者が決めます。

[ユーザー空間の仕様](README.md)
