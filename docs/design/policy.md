<a id="7a9-admission-policy-のコンパイラ"></a>
### Admission Policy のコンパイラ

Admission Policy は、1 つの IR を nftables と Go の評価器へコンパイルします。
送信元の許可と拒否、送信元ごとの同時フロー数、レートの順序は両方で同じ意味を持ちます。


`internal/policy` の IR は、kernel 用の nftables の行の列と、userspace 用の Go の評価器へコンパイルします。
共有 fixture を使うホストの単体テストで、両者の判定を許容差の範囲内で確かめます。

`Forwarding` は通信を届ける方法を選び、Admission Policy は入口で通信を通すかどうかを決める。
両者は別の軸であり、`Forwarding` の値によって Admission Policy の意味は変わりません。
`Relay` のルールも `Transparent` のルールと同じ Admission Policy のすべての段を持ちます。

#### IR の形

`policy.Policy` は、ルールごとの `RulePolicy` と、プロトコルごとの `PerSourceFlowCaps` を持ちます。
`RulePolicy` はルール ID、プロトコル、`source_allow`、`source_deny` と 3 つのレートを持ち、次の評価の定数と順序を使います。

- 評価の定数:トークンバケットの burst(5)、送信元ごとの表の期限(1 分)と大きさ(65535)、同時フロー数の set の大きさ(65535)を、`internal/policy` の定数として 1 か所に持ちます。
  以前は `nft` と `srcpolicy`(Phase 5 の移行の手順 5 で削除)が同じ値をそれぞれ書いていました
- 段と drop の種類の対応:`Order` の各段は、drop カウンタの種類(`deny`、`allow`、`per_source`、`src_flow`、`new_flow`、`packet`)を 1 つずつ持ちます。
  この文字列は SQLite に累積する drop の種類なので、今の値を変えません
- 段の適用範囲:`deny` と `allow` は、外から入るフローのすべてのパケットに効く。
  `per_source_rate`、送信元ごとの同時フロー数の上限、`new_flow_rate` は、TCP と UDP の新しいフローに効く。
  `packet_rate` は UDP のデータグラムだけに効く(後述)
- CIDR の正規化:`policy.Build` が `source_allow` と `source_deny` の CIDR をマスクし、重なりと隣接を併合して昇順に並べる。
  今は nftables の set を作るときだけ併合しており(`intervalElements`)、Go の評価器は併合前の一覧を走査しています。
  deny と allow の両方に含まれる送信元は、deny が先に評価されるので拒まれる
- 送信元のアドレス:v1 は IPv4 だけを扱い、IPv4 でない送信元を拒む(後述)

評価順は、deny、allow、送信元ごとの新規フローレート、送信元ごとの同時フロー数の上限、集約の新規フローレート、パケットレートの順です。
この順序は IR の `Order` だけが持ち、両方のコンパイラは `Order` を順に回して、段の順序を自分では持ちません。
ある段がフローかパケットを拒んだとき、それより後の段の状態は消費されない。
deny と allow で拒んだ送信元はレートのトークンを使わず、同時フロー数の上限で拒んだフローは `new_flow_rate` のトークンを使いません。
IR に無いルール ID のフローは拒む(fail-closed)。

IR が表せないものは、ポートと宛先(DNAT と listener。
`Plan` が持つ)、送信元ごとのパケットレート、バイト単位のレート、TCP のパケットレート、IPv6 の送信元、ルールごとの同時フロー数とプロセス全体の予算(Resource Guard。
[7a.5 節](architecture/admission-resources.md#7a5-resource-guard))、時間帯や送信元の地域による条件です。
これらを加えるときは、IR の段、両方のコンパイラ、fixture を同じ変更で直す。

状態を持つ段(送信元ごとの新規フローレート、同時フロー数の上限、集約の新規フローレート、パケットレート)は、1 つのフローにつき 1 か所だけで評価します。
評価する場所は `DataplaneMode` で決まり、`Forwarding` では決まらない。
kernel モードでは、`Transparent` のポートと、待ち受けを開けている `Relay` のポートの両方を nftables が判定します。
userspace モードでは、両方を Go の評価器が判定します。
kernel モードの `Relay` の中継は状態を持つ段を評価せず、`RulePolicy.SourceAllowed` による状態を持たない確認だけを残し、drop カウンタには数えません。

#### TCP の packet_rate

`packet_rate` は UDP のデータグラムだけに効く。
TCP のパケットの数は ACK と再送も含み、MSS やオフロードによってアプリケーションのバイト数とも対応しません。
落としても TCP が再送するだけで、流量の制限としての意味を持ちません。
そのため kernel のコンパイラも、TCP のルールには `packet` の行を作りません。

TCP のルールの `packet_rate` は、ルールの書き出しと読み込みの互換のため、今までどおり受け付けて保存し、新しく設定する操作も拒まない。
CLI は、TCP のルールに `packet_rate` があるとき、`packet_rate is stored but has no effect on TCP rules` の旨を示す(`rule rate packet`、`rule import`、`rule ls`)。
`rule add` は `packet_rate` を設定するフラグを持たないので、旨を示す対象に含まない。
Web UI も同じ旨を、TCP のルールに `packet_rate` が保存されているときだけ、レート区画に添える。
入力欄は無効にしません。
無効にすると、ブラウザがその欄を送らず、他の欄の保存が誤りになるか、保存済みの値を静かに消しかねないためです。

#### IPv4 だけを扱う v1 の守り

v1 は IPv4 だけを扱い([4 節](network.md#4-ネットワーク))、IPv4 でない送信元を拒む(fail-closed)。
userspace では 2 重に守る。
1 つ目の守りとして、userspace と `Relay` の listener を IPv4 だけで開く(`tcp4`、`udp4`)。
移行の手順 3 より前の listener は IPv6 でも待ち受けており(`net.Listen("tcp", ":port")` など)、VPS が IPv6 を持つと、IPv6 の送信元は IPv4 の CIDR だけを並べた deny に一致せずに通った。
2 つ目の守りとして、Go の評価器自身が、IPv4 射影のアドレスを IPv4 に戻した後、IPv4 でない送信元を拒みます。
評価器は listener の開き方に頼らない。
kernel では、IPv6 のパケットは DNAT されないが、移行の手順 3 より前の行のうち IPv4 に限っていたのは送信元を読む行(deny、allow、送信元ごとの新規フローレート、送信元ごとの同時フロー数の上限)だけだった。
送信元を読まない集約のレートの行(`new_flow_rate`、`packet_rate`)は `inet` のテーブルで IPv6 のパケットにも一致したので、判定するポートへの IPv6 のフラッドが集約のトークンを使い、IPv4 の正規の通信の新規フローとパケットを落とせた。
このため、kernel の Admission Policy のすべての行に `meta nfproto ipv4` を付け、送信元の set を使わない集約のレートの行も IPv4 のパケットだけに一致させる。
IPv6 への対応は、同じ IR と両方のコンパイラに IPv6 の set を加える形で行う([13 節](roadmap.md#制限と未実装の提案))。

#### nftables へのコンパイルの約束

`internal/policy/nftables` は、IR と、判定を付けるポートの集合(`Plan` の `Transparent` のポートと、frontend が待ち受けを開けている `Relay` のポート)を受け取り、行の列を返します。
行は、一致条件(プロトコル、ポート範囲、`ct state new` の有無、送信元の set)、文(set の照合、送信元ごとの `limit`、`ct count`、集約の `limit`)、カウンタのコメント(`wgft:<ルール ID>:<種類>`)、判定(drop)を持つ Go のデータで、google/nftables を import しません。
`internal/dataplane/linuxkernel/nft` は、この行の列を nftables の式へ写し、DNAT、input、forward、postrouting の行を加えます。

- 行の順序:ポートは `Plan` の順、段は `Order` の順に並べる
- 行を作らない条件:allow が空なら set も行も作りません。
  レートが未設定なら行を作りません。
  同時フロー数の上限が 0 のプロトコルには set も行も作らない([6.1 節](vps/kernel.md#61-カーネルモード)のまま)。
  TCP のルールには `packet` の行を作りません
- set の名前:`deny_N`、`allow_N`、`meter_N`、`flows_udp`、`flows_tcp` の名前と連番の振り方を変えません。
  `packet_rate` を持つ TCP のルールが無く、`Transparent` だけの設定では、生成するテーブルが今の `testdata/basic.nft` と一致します
- `Relay` のポート:`Transparent` と同じ段の行を、同じ順で付ける。
  `Relay` のルールも set の連番を進めるので、`Relay` のルールを含む設定では `wgft server nft` の表示の番号が、段の行を付ける前と変わる

#### Go の評価器へのコンパイルの約束

`internal/policy/goengine` は、IR から評価器を作る。
nftables の評価順を手で模していた旧い `internal/dataplane/userspace/srcpolicy` は Phase 5 で削除した(移行の手順 3 と 5)。
評価器の判定は `Decision` の値(考え方としては `Decision{Allow bool; Kind DropKind}`)を返し、拒んだときは拒んだ段の drop の種類を `Kind` に持ちます。
drop カウンタも評価器が数え、呼び出し側(中継)は drop の種類を決めない。

- `AdmitFlow`:新しいフロー(TCP の accept、UDP の新しいセッションの最初のデータグラム)を `Order` の全段で判定します。
  送信元ごとの同時フロー数の段を通ったときは枠を取り、フローの終わりに枠を返すための手形を返します。
  後の段か Resource Guard が拒んだときは、その場で枠を返します
- `AdmitPacket`:成立済みの UDP セッションのデータグラムを `packet_rate` の段で判定します。
  `Retiring` の UDP の待ち受け([7a.3 節](architecture/lifecycle.md#7a3-状態遷移と失敗の意味論))のセッションには呼びません。
  そのルールは公開した方針に無く、IR に無いルール ID として拒まれるためです。
  kernel モードでも、fail-closed にしたルールの成立済みのフローは、そのルールの行が無いテーブルを通るので、`packet_rate` を受けない
- `SourceAllowed`:成立済みのフローを残すかを deny と allow だけで判定する([7a.3 節](architecture/lifecycle.md#7a3-状態遷移と失敗の意味論)の `Retiring`、ルール変更の後にセッションを閉じる判定)
- `Update`:状態を引き継ぐ規則は [7a.4 節](architecture/admission-resources.md#7a4-admission-policy-と入口の分岐)のままです。
  直前の宣言にあって新しい宣言に無いルール(削除、無効化、分割と統合で消えた ID、fail-closed にしたルール)は、次の `Update` まで旧い方針のまま判定を続ける(退いたルール)。
  評価器の更新と中継の待ち受けの更新(所属ルール ID の付け替え、待ち受けの閉鎖、`Retiring` への移行)は不可分ではなく、userspace モードの `Relay` の待ち受けは dataplane の `Commit` の後の frontend の `Commit` で付け替わる。
  この間に旧い ID で届く新しいフローを、IR に無いルール ID として拒まないためです。
  分割と統合は既存のセッションを切らない([7 節](agent-dataplane.md#7-データプレーン自宅側))だけでなく、新しいフローも拒まない。
  待ち受けの更新は同じトランザクションの中で終わり、旧い ID で受け付ける待ち受けは残らないので、次の `Update` で退いたルールを捨てます。
  退いたルールの状態は引き継がず、同じ ID が宣言に戻れば新しく作る
- `Drops`:段ごとの drop を返して 0 に戻す(旧い `srcpolicy.Drops` と同じ経路)
- IR に無いルール ID と IPv4 でない送信元:拒み、drop には数えません。
  退いたルール(`Update`)は IR に無いルール ID に含めません。
  移行の手順 3 より前の `srcpolicy` は未知のルール ID を通していました。
  listener は、そのルールの IR を公開した後にだけ中継を始める([7a.3 節](architecture/lifecycle.md#7a3-状態遷移と失敗の意味論))ので、正しい実装では起きない。
  起きたときに通さないためです

Go の評価器と nftables のコンパイラは、次の判定の順序を持ちます。

- UDP のパケットレート:新しいセッションの最初のデータグラムは `AdmitFlow` の全段を通り、deny と allow で拒んだ送信元は packet のトークンを使いません。
  成立済みセッションのデータグラムは `AdmitPacket` で判定します。
- 送信元ごとの同時フロー数:集約の `new_flow_rate` より前に判定し、拒否は `src_flow` の drop に数えます。
- Relay の受け付け:Transparent と同じ Admission Policy の全段を持ち、レートと送信元ごとの同時フロー数を判定します。

#### 許容差の扱い

避けられない差は、名前付きの許容差として定める。
fixture は、[7a.4 節](architecture/admission-resources.md#7a4-admission-policy-と入口の分岐)と本節に挙げた名前でしか差を許さない。
等価性が対象とするのは、判定(通すか落とすか)、落とした理由(drop の種類)、drop カウンタ、レートと同時フロー数の状態です。
拒否がネットワーク上でどう見えるかは対象としません。
[7a.4 節](architecture/admission-resources.md#7a4-admission-policy-と入口の分岐)の 4 つに次を加えます。

- 拒否の見え方:kernel モードは nftables でパケットを捨てるので、クライアントには時間切れとして見える。
  userspace モードの TCP は accept の後に閉じる([7a.5 節](architecture/admission-resources.md#7a5-resource-guard))ので、クライアントには RST か EOF として見える。
  `Relay` のルールにも同じ差があります。
  fixture はネットワーク上の見え方を比べない
- 新しいフローの数え方:kernel は `ct state new` のパケットを数えます。
  応答が返る前の同じ UDP フローの 2 つ目以降のパケットと、TCP の SYN の再送も、新しいフローとして送信元ごとと集約の新規フローレートのトークンを使い、drop にも数えられます。
  Go はセッションか接続 1 つを 1 回と数えます。
  userspace の TCP はホストのカーネルが握手を終えた後に判定するので、握手を終えない SYN は評価器に届かない
- drop カウンタの単位:kernel は L3 のパケット数とバイト数を数えます。
  Go は、UDP のデータグラム 1 つ(バイト数は中身の長さ)と TCP の接続 1 つ(バイト数は 0)を 1 パケットと数えます。
  fixture はパケット数だけを比べ、バイト数は比べない
- 送信元ごとの表の期限と溢れ:kernel の meter の要素は、`add` で作った時点から 1 分で消える(`add` が期限を延ばさないことは未確認)。
  Go は最後に触れてから 1 分で消す。
  表が 65535 件で埋まると、kernel は新しい送信元の `add` が失敗して送信元ごとの新規フローレートの制限が外れ([6.1 節](vps/kernel.md#61-カーネルモード))、Go は最も長く触れていない送信元を捨てて制限を続けます。
  Go の挙動は許可を広げない側にあるので、kernel に揃えない
- 補充の境界:両者は同じトークンバケット(容量 5、満杯から始まり、count/unit の速さで補充する)を持ちます。
  ただし、トークンがちょうど補充される時刻での判定は、kernel の時計の粒度に依存する(未確認)。
  fixture の出来事は、補充の時刻から補充間隔の 10% 以上離して置く

#### fixture の形式と等価性の検査

fixture は `internal/policy/testdata/admission/*.json` に置き、1 ファイルが 1 つの場面を表します。

- `comment`:場面の説明
- `policy`:ルールの一覧(`id`、`proto`、`forwarding`、`source_allow`、`source_deny`、`per_source_rate`、`new_flow_rate`、`packet_rate`。
  `forwarding` は `transparent` か `relay` で、ほかの値の書き方は [5.3 節](control/rules.md#53-ルールのスキーマ)と同じ)と、`per_source_flow_caps`(`udp`、`tcp`。
  省いた項目は既定値、0 は上限なし)。
  ポートと宛先は IR の外にあるので書きません。
  検査の側がルールごとに 1 つのポートを振り、本番と同じ `Planner` で `Plan` を組み立てる
- `events`:時刻順の出来事の列。
  各出来事は、`at_ms`(仮想の時計の時刻)、`op`(`flow` は新しいフローの最初のパケット、`packet` は成立済みのフローのパケット、`end` はフローの終わり)、`rule`、`src`、`flow`(フローの名前)、`want`(`admit`、`drop:<種類>`、または `drop`)を持ちます。
  `drop` は drop カウンタに数えない拒否で、IR に無いルール ID に使います。
  `end` は `want` を持ちません
- `want_drops`:最後に読む drop カウンタ(ルール ID と種類からパケット数への表)
- `tolerances`:その場面が避けた許容差の名前の一覧。
  fixture は許容差の及ぶ出来事を書かない(補充の境界なら、出来事を補充の時刻から離して置く)ので、この一覧があっても判定と drop カウンタの完全な一致を求めます。
  名前は、[7a.4 節](architecture/admission-resources.md#7a4-admission-policy-と入口の分岐)の 4 つを順に `udp_flow_counting`、`timeout_asymmetry`、`token_bucket_granularity`、`table_replacement_reset`、本節の 5 つを順に `rejection_visibility`、`new_flow_counting`、`drop_counter_units`、`per_source_table_expiry`、`refill_boundary` と書きます

等価性の検査は `go test ./internal/policy/...` の単体テストで、root もネットワーク名前空間も要らず、CI でも走る。
検査は、各 fixture について次の手順を踏む。

1. `goengine` で評価器を作り、仮想の時計で出来事を順に流す。
   出来事は本番の中継と同じ呼び出しに写す。
   `flow` は `AdmitFlow`、`packet` は `AdmitPacket`、`end` は手形の返却です。
   各出来事の `Decision` を `want` に、評価器の drop カウンタを `want_drops` に照らす
2. `policy/nftables` で行の列を作り、テスト専用の解釈器で同じ出来事を流す。
   解釈器は、interval の set の照合、動的 set への `add` と要素ごとの `limit`、`ct count`(フローの `end` で数から抜ける)、集約の `limit`、`ct state new`(フローの最初のパケットだけが一致する)、カウンタを模し、どの行(段とカウンタの種類)がパケットを落としたかを `want` に、行のカウンタを `want_drops` に照らす。
   解釈器は IR を読まずに行の列だけを入力にするので、コンパイラの誤り(行の順序、行の抜け、`ct state new` の付け忘れ、コメントの誤り)を拾える。
   後の行や `ct count` の行が落とした新しいフローは conntrack に確定しないので、解釈器はそのフローをその場で `ct count` の数から抜く。
   カーネルでは、この要素は次の gc で抜ける。
   IR に無いルール ID の出来事は、どの行にも一致せず、DNAT も待ち受けも無いポートへ送るので、検査の側が `drop` と判定します。
   IPv4 でない送信元の出来事も、どの行にも一致せず、`dnat ip to` に写されず、IPv4 だけで開く待ち受けにも届かないので、検査の側が `drop` と判定します。
   どちらも、行が落としたら誤りとして報告します
3. 2 つの結果を互いにも照らす

fixture の読み込みと検査の手順は `internal/policy/admissiontest` に、解釈器は `internal/policy/nftables/interp` に置く。
どちらも本番のコードからは import しません。
評価器は `admissiontest.Engine` を実装して差し込み、`goengine` も同じ fixture を同じ手順で流す。

fixture は次の場面を対象とします。
deny と allow の一覧、CIDR の重なりと隣接、deny と allow の両方に含まれる送信元、空の allow、各レートの burst と補充、送信元ごとの表による送信元の分離、同時フロー数の上限のルール間での合算とフローの終わりによる解放、段の順序(deny の送信元がレートのトークンを使わないこと、同時フロー数の上限で拒んだフローが `new_flow_rate` のトークンを使わないこと)、`Relay` のルール、TCP のルールの `packet_rate` が効かないこと、各段の drop カウンタ、IPv4 射影のアドレス、IR に無いルール ID です。
IPv6 の送信元は kernel の行に一致しないので、評価器の単体テストで拒むことを確かめる。

解釈器は kernel の挙動の模型なので、kernel との一致はホストでは確かめられない。
次のことはラボでだけ確かめる。

- 行の列から作った式の `nft list` が、同じ内容を `nft -f` で流したものと一致すること(今の `lab_test.go` のゴールデンテスト)
- 実際のパケットでの通過数と drop 数。
  `lab/rates.sh` と `lab/connlimit.sh` を両モードで流す。
  `lab/rates.sh` には `Relay` のルールの 2 つのレートを確かめる場面があります
- 許容差に挙げた未確認の点(meter の期限、補充の境界、応答前の UDP のパケットの数え方)

#### Resource Guard との境界

Admission Policy が扱うのは IR の 6 つの段です。
Resource Guard は、Admission Policy がフローを通した後にだけ判定します。
資源の拒否は Admission Policy の drop の種類にも fixture にも含めません。
kernel の conntrack の表が溢れる場合も、prerouting の判定の後にフローが落ちるので、両モードで順序を維持します。

## 関連する仕様

- [Resource Guard](resource/README.md)

<details>
<summary>旧見出しの参照先</summary>

- <a id="phase-5-の移行の手順"></a> [phase-5-の移行の手順](history/admission-policy-migration.md#phase-5-の移行の手順) <!-- docs-history -->
- <a id="利用者から見て変わらないものと変わるもの"></a> [利用者から見て変わらないものと変わるもの](history/admission-policy-migration.md#利用者から見て変わらないものと変わるもの) <!-- docs-history -->

</details>
