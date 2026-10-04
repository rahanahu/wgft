### 7a.9 Admission Policy のコンパイラ

Phase 5 では、`internal/policy` の IR を 2 つの対象へコンパイルする。kernel の対象は nftables の行の列、userspace の対象は Go の評価器である。両者が同じ判定をすることは、ホストの単体テストで動く共有 fixture で確かめる。

`Forwarding` は通信を届ける方法を選び、Admission Policy は入口で通信を通すかどうかを決める。両者は別の軸であり、`Forwarding` の値によって Admission Policy の意味は変わらない。`Relay` のルールも `Transparent` のルールと同じ Admission Policy のすべての段を持つ。

#### IR の形

`policy.Policy` は、ルールごとの `RulePolicy`(ルール ID、プロトコル、`source_allow`、`source_deny`、3 つのレート)と、プロトコルごとの `PerSourceFlowCaps` を持つ。この形は Phase 1 のままで、Phase 5 では次を IR に加える。

- 評価の定数:トークンバケットの burst(5)、送信元ごとの表の期限(1 分)と大きさ(65535)、同時フロー数の set の大きさ(65535)を、`internal/policy` の定数として 1 か所に持つ。以前は `nft` と `srcpolicy`(Phase 5 の移行の手順 5 で削除)が同じ値をそれぞれ書いていた
- 段と drop の種類の対応:`Order` の各段は、drop カウンタの種類(`deny`、`allow`、`per_source`、`src_flow`、`new_flow`、`packet`)を 1 つずつ持つ。この文字列は SQLite に累積する drop の種類なので、今の値を変えない
- 段の適用範囲:`deny` と `allow` は、外から入るフローのすべてのパケットに効く。`per_source_rate`、送信元ごとの同時フロー数の上限、`new_flow_rate` は、TCP と UDP の新しいフローに効く。`packet_rate` は UDP のデータグラムだけに効く(後述)
- CIDR の正規化:`policy.Build` が `source_allow` と `source_deny` の CIDR をマスクし、重なりと隣接を併合して昇順に並べる。今は nftables の set を作るときだけ併合しており(`intervalElements`)、Go の評価器は併合前の一覧を走査している。deny と allow の両方に含まれる送信元は、deny が先に評価されるので拒まれる
- 送信元のアドレス:v1 は IPv4 だけを扱い、IPv4 でない送信元を拒む(後述)

評価順は、deny、allow、送信元ごとの新規フローレート、送信元ごとの同時フロー数の上限、集約の新規フローレート、パケットレートの順である。この順序は IR の `Order` だけが持ち、両方のコンパイラは `Order` を順に回して、段の順序を自分では持たない。ある段がフローかパケットを拒んだとき、それより後の段の状態は消費されない。deny と allow で拒んだ送信元はレートのトークンを使わず、同時フロー数の上限で拒んだフローは `new_flow_rate` のトークンを使わない。IR に無いルール ID のフローは拒む(fail-closed)。

IR が表せないものは、ポートと宛先(DNAT と listener。`Plan` が持つ)、送信元ごとのパケットレート、バイト単位のレート、TCP のパケットレート、IPv6 の送信元、ルールごとの同時フロー数とプロセス全体の予算(Resource Guard。7a.5 節)、時間帯や送信元の地域による条件である。これらを加えるときは、IR の段、両方のコンパイラ、fixture を同じ変更で直す。

状態を持つ段(送信元ごとの新規フローレート、同時フロー数の上限、集約の新規フローレート、パケットレート)は、1 つのフローにつき 1 か所だけで評価する。評価する場所は `DataplaneMode` で決まり、`Forwarding` では決まらない。kernel モードでは、`Transparent` のポートと、待ち受けを開けている `Relay` のポートの両方を nftables が判定する。userspace モードでは、両方を Go の評価器が判定する。kernel モードの `Relay` の中継は状態を持つ段を評価せず、`RulePolicy.SourceAllowed` による状態を持たない確認だけを残し、drop カウンタには数えない。

#### TCP の packet_rate

`packet_rate` は UDP のデータグラムだけに効く。TCP のパケットの数は ACK と再送も含み、MSS やオフロードによってアプリケーションのバイト数とも対応しない。落としても TCP が再送するだけで、流量の制限としての意味を持たない。そのため kernel のコンパイラも、TCP のルールには `packet` の行を作らない。

TCP のルールの `packet_rate` は、ルールの書き出しと読み込みの互換のため、今までどおり受け付けて保存し、新しく設定する操作も拒まない。CLI は、TCP のルールに `packet_rate` があるとき、`packet_rate is stored but has no effect on TCP rules` の旨を示す(`rule rate packet`、`rule import`、`rule ls`)。`rule add` は `packet_rate` を設定するフラグを持たないので、旨を示す対象に含まない。Web UI も同じ旨を、TCP のルールに `packet_rate` が保存されているときだけ、レート区画に添える。入力欄は無効にしない。無効にすると、ブラウザがその欄を送らず、他の欄の保存が誤りになるか、保存済みの値を静かに消しかねないためである。

#### IPv4 だけを扱う v1 の守り

v1 は IPv4 だけを扱い(4 節)、IPv4 でない送信元を拒む(fail-closed)。userspace では 2 重に守る。1 つ目の守りとして、userspace と `Relay` の listener を IPv4 だけで開く(`tcp4`、`udp4`)。移行の手順 3 より前の listener は IPv6 でも待ち受けており(`net.Listen("tcp", ":port")` など)、VPS が IPv6 を持つと、IPv6 の送信元は IPv4 の CIDR だけを並べた deny に一致せずに通った。2 つ目の守りとして、Go の評価器自身が、IPv4 射影のアドレスを IPv4 に戻した後、IPv4 でない送信元を拒む。評価器は listener の開き方に頼らない。kernel では、IPv6 のパケットは DNAT されないが、移行の手順 3 より前の行のうち IPv4 に限っていたのは送信元を読む行(deny、allow、送信元ごとの新規フローレート、送信元ごとの同時フロー数の上限)だけだった。送信元を読まない集約のレートの行(`new_flow_rate`、`packet_rate`)は `inet` のテーブルで IPv6 のパケットにも一致したので、判定するポートへの IPv6 のフラッドが集約のトークンを使い、IPv4 の正規の通信の新規フローとパケットを落とせた。このため、kernel の Admission Policy のすべての行に `meta nfproto ipv4` を付け、送信元の set を使わない集約のレートの行も IPv4 のパケットだけに一致させる。IPv6 への対応は、同じ IR と両方のコンパイラに IPv6 の set を加える形で行う(13 節)。

#### nftables へのコンパイルの約束

`internal/policy/nftables` は、IR と、判定を付けるポートの集合(`Plan` の `Transparent` のポートと、frontend が待ち受けを開けている `Relay` のポート)を受け取り、行の列を返す。行は、一致条件(プロトコル、ポート範囲、`ct state new` の有無、送信元の set)、文(set の照合、送信元ごとの `limit`、`ct count`、集約の `limit`)、カウンタのコメント(`wgft:<ルール ID>:<種類>`)、判定(drop)を持つ Go のデータで、google/nftables を import しない。`internal/dataplane/linuxkernel/nft` は、この行の列を nftables の式へ写し、DNAT、input、forward、postrouting の行を加える。

- 行の順序:ポートは `Plan` の順、段は `Order` の順に並べる
- 行を作らない条件:allow が空なら set も行も作らない。レートが未設定なら行を作らない。同時フロー数の上限が 0 のプロトコルには set も行も作らない(6.1 節のまま)。TCP のルールには `packet` の行を作らない
- set の名前:`deny_N`、`allow_N`、`meter_N`、`flows_udp`、`flows_tcp` の名前と連番の振り方を変えない。`packet_rate` を持つ TCP のルールが無く、`Transparent` だけの設定では、生成するテーブルが今の `testdata/basic.nft` と一致する
- `Relay` のポート:`Transparent` と同じ段の行を、同じ順で付ける。`Relay` のルールも set の連番を進めるので、`Relay` のルールを含む設定では `wgft server nft` の表示の番号が、段の行を付ける前と変わる

#### Go の評価器へのコンパイルの約束

`internal/policy/goengine` は、IR から評価器を作る。nftables の評価順を手で模していた旧い `internal/dataplane/userspace/srcpolicy` は Phase 5 で削除した(移行の手順 3 と 5)。評価器の判定は `Decision` の値(考え方としては `Decision{Allow bool; Kind DropKind}`)を返し、拒んだときは拒んだ段の drop の種類を `Kind` に持つ。drop カウンタも評価器が数え、呼び出し側(中継)は drop の種類を決めない。

- `AdmitFlow`:新しいフロー(TCP の accept、UDP の新しいセッションの最初のデータグラム)を `Order` の全段で判定する。送信元ごとの同時フロー数の段を通ったときは枠を取り、フローの終わりに枠を返すための手形を返す。後の段か Resource Guard が拒んだときは、その場で枠を返す
- `AdmitPacket`:成立済みの UDP セッションのデータグラムを `packet_rate` の段で判定する。`Retiring` の UDP の待ち受け(7a.3 節)のセッションには呼ばない。そのルールは公開した方針に無く、IR に無いルール ID として拒まれるためである。kernel モードでも、fail-closed にしたルールの成立済みのフローは、そのルールの行が無いテーブルを通るので、`packet_rate` を受けない
- `SourceAllowed`:成立済みのフローを残すかを deny と allow だけで判定する(7a.3 節の `Retiring`、ルール変更の後にセッションを閉じる判定)
- `Update`:状態を引き継ぐ規則は 7a.4 節のままである。直前の宣言にあって新しい宣言に無いルール(削除、無効化、分割と統合で消えた ID、fail-closed にしたルール)は、次の `Update` まで旧い方針のまま判定を続ける(退いたルール)。評価器の更新と中継の待ち受けの更新(所属ルール ID の付け替え、待ち受けの閉鎖、`Retiring` への移行)は不可分ではなく、userspace モードの `Relay` の待ち受けは dataplane の `Commit` の後の frontend の `Commit` で付け替わる。この間に旧い ID で届く新しいフローを、IR に無いルール ID として拒まないためである。分割と統合は既存のセッションを切らない(7 節)だけでなく、新しいフローも拒まない。待ち受けの更新は同じトランザクションの中で終わり、旧い ID で受け付ける待ち受けは残らないので、次の `Update` で退いたルールを捨てる。退いたルールの状態は引き継がず、同じ ID が宣言に戻れば新しく作る
- `Drops`:段ごとの drop を返して 0 に戻す(旧い `srcpolicy.Drops` と同じ経路)
- IR に無いルール ID と IPv4 でない送信元:拒み、drop には数えない。退いたルール(`Update`)は IR に無いルール ID に含めない。移行の手順 3 より前の `srcpolicy` は未知のルール ID を通していた。listener は、そのルールの IR を公開した後にだけ中継を始める(7a.3 節)ので、正しい実装では起きない。起きたときに通さないためである

Phase 5 の前の userspace の実装は、次の 3 点で IR の意味と食い違っていた。最初の 2 つは移行の手順 3、3 つ目は手順 4 で直した。

- `packet_rate` の位置:UDP の中継は、セッションの有無を見る前に、すべてのデータグラムを `packet_rate` で判定している(`relay/udp.go`)。deny の送信元のデータグラムも `packet` のトークンを使うため、deny の送信元からのフラッドが、正規の成立済みセッションのデータグラムを落としうる。nftables では deny の行が先に落とすので、この問題は起きない
- 送信元ごとの同時フロー数の上限の位置:今は `AdmitFlow` の後に `flowcap.Counter.Acquire` で判定しており、`new_flow_rate` より後になる。上限で拒んだフローも `new_flow_rate` のトークンを使い、drop カウンタにも数えない
- `Relay` の受け付け:userspace モードの `proxyrelay` は deny と allow だけを判定し、レートを評価していなかった。kernel モードも `src_flow` の行しか付けていなかったので、`Relay` のルールのレートは両モードで効いていなかった

#### 許容差の扱い

避けられない差は、名前付きの許容差として定める。fixture は、7a.4 節と本節に挙げた名前でしか差を許さない。等価性が対象とするのは、判定(通すか落とすか)、落とした理由(drop の種類)、drop カウンタ、レートと同時フロー数の状態である。拒否がネットワーク上でどう見えるかは対象としない。7a.4 節の 4 つに次を加える。

- 拒否の見え方:kernel モードは nftables でパケットを捨てるので、クライアントには時間切れとして見える。userspace モードの TCP は accept の後に閉じる(7a.5 節)ので、クライアントには RST か EOF として見える。`Relay` のルールにも同じ差がある。fixture はネットワーク上の見え方を比べない
- 新しいフローの数え方:kernel は `ct state new` のパケットを数える。応答が返る前の同じ UDP フローの 2 つ目以降のパケットと、TCP の SYN の再送も、新しいフローとして送信元ごとと集約の新規フローレートのトークンを使い、drop にも数えられる。Go はセッションか接続 1 つを 1 回と数える。userspace の TCP はホストのカーネルが握手を終えた後に判定するので、握手を終えない SYN は評価器に届かない
- drop カウンタの単位:kernel は L3 のパケット数とバイト数を数える。Go は、UDP のデータグラム 1 つ(バイト数は中身の長さ)と TCP の接続 1 つ(バイト数は 0)を 1 パケットと数える。fixture はパケット数だけを比べ、バイト数は比べない
- 送信元ごとの表の期限と溢れ:kernel の meter の要素は、`add` で作った時点から 1 分で消える(`add` が期限を延ばさないことは未確認)。Go は最後に触れてから 1 分で消す。表が 65535 件で埋まると、kernel は新しい送信元の `add` が失敗して送信元ごとの新規フローレートの制限が外れ(6.1 節)、Go は最も長く触れていない送信元を捨てて制限を続ける。Go の挙動は許可を広げない側にあるので、kernel に揃えない
- 補充の境界:両者は同じトークンバケット(容量 5、満杯から始まり、count/unit の速さで補充する)を持つ。ただし、トークンがちょうど補充される時刻での判定は、kernel の時計の粒度に依存する(未確認)。fixture の出来事は、補充の時刻から補充間隔の 10% 以上離して置く

#### fixture の形式と等価性の検査

fixture は `internal/policy/testdata/admission/*.json` に置き、1 ファイルが 1 つの場面を表す。

- `comment`:場面の説明
- `policy`:ルールの一覧(`id`、`proto`、`forwarding`、`source_allow`、`source_deny`、`per_source_rate`、`new_flow_rate`、`packet_rate`。`forwarding` は `transparent` か `relay` で、ほかの値の書き方は 5.3 節と同じ)と、`per_source_flow_caps`(`udp`、`tcp`。省いた項目は既定値、0 は上限なし)。ポートと宛先は IR の外にあるので書かない。検査の側がルールごとに 1 つのポートを振り、本番と同じ `Planner` で `Plan` を組み立てる
- `events`:時刻順の出来事の列。各出来事は、`at_ms`(仮想の時計の時刻)、`op`(`flow` は新しいフローの最初のパケット、`packet` は成立済みのフローのパケット、`end` はフローの終わり)、`rule`、`src`、`flow`(フローの名前)、`want`(`admit`、`drop:<種類>`、または `drop`)を持つ。`drop` は drop カウンタに数えない拒否で、IR に無いルール ID に使う。`end` は `want` を持たない
- `want_drops`:最後に読む drop カウンタ(ルール ID と種類からパケット数への表)
- `tolerances`:その場面が避けた許容差の名前の一覧。fixture は許容差の及ぶ出来事を書かない(補充の境界なら、出来事を補充の時刻から離して置く)ので、この一覧があっても判定と drop カウンタの完全な一致を求める。名前は、7a.4 節の 4 つを順に `udp_flow_counting`、`timeout_asymmetry`、`token_bucket_granularity`、`table_replacement_reset`、本節の 5 つを順に `rejection_visibility`、`new_flow_counting`、`drop_counter_units`、`per_source_table_expiry`、`refill_boundary` と書く

等価性の検査は `go test ./internal/policy/...` の単体テストで、root もネットワーク名前空間も要らず、CI でも走る。検査は、各 fixture について次の手順を踏む。

1. `goengine` で評価器を作り、仮想の時計で出来事を順に流す。出来事は本番の中継と同じ呼び出しに写す。`flow` は `AdmitFlow`、`packet` は `AdmitPacket`、`end` は手形の返却である。各出来事の `Decision` を `want` に、評価器の drop カウンタを `want_drops` に照らす
2. `policy/nftables` で行の列を作り、テスト専用の解釈器で同じ出来事を流す。解釈器は、interval の set の照合、動的 set への `add` と要素ごとの `limit`、`ct count`(フローの `end` で数から抜ける)、集約の `limit`、`ct state new`(フローの最初のパケットだけが一致する)、カウンタを模し、どの行(段とカウンタの種類)がパケットを落としたかを `want` に、行のカウンタを `want_drops` に照らす。解釈器は IR を読まずに行の列だけを入力にするので、コンパイラの誤り(行の順序、行の抜け、`ct state new` の付け忘れ、コメントの誤り)を拾える。後の行や `ct count` の行が落とした新しいフローは conntrack に確定しないので、解釈器はそのフローをその場で `ct count` の数から抜く。カーネルでは、この要素は次の gc で抜ける。IR に無いルール ID の出来事は、どの行にも一致せず、DNAT も待ち受けも無いポートへ送るので、検査の側が `drop` と判定する。IPv4 でない送信元の出来事も、どの行にも一致せず、`dnat ip to` に写されず、IPv4 だけで開く待ち受けにも届かないので、検査の側が `drop` と判定する。どちらも、行が落としたら誤りとして報告する
3. 2 つの結果を互いにも照らす

fixture の読み込みと検査の手順は `internal/policy/admissiontest` に、解釈器は `internal/policy/nftables/interp` に置く。どちらも本番のコードからは import しない。評価器は `admissiontest.Engine` を実装して差し込み、`goengine` も同じ fixture を同じ手順で流す。

fixture は次の場面を対象とする。deny と allow の一覧、CIDR の重なりと隣接、deny と allow の両方に含まれる送信元、空の allow、各レートの burst と補充、送信元ごとの表による送信元の分離、同時フロー数の上限のルール間での合算とフローの終わりによる解放、段の順序(deny の送信元がレートのトークンを使わないこと、同時フロー数の上限で拒んだフローが `new_flow_rate` のトークンを使わないこと)、`Relay` のルール、TCP のルールの `packet_rate` が効かないこと、各段の drop カウンタ、IPv4 射影のアドレス、IR に無いルール ID である。IPv6 の送信元は kernel の行に一致しないので、評価器の単体テストで拒むことを確かめる。

解釈器は kernel の挙動の模型なので、kernel との一致はホストでは確かめられない。次のことはラボでだけ確かめる。

- 行の列から作った式の `nft list` が、同じ内容を `nft -f` で流したものと一致すること(今の `lab_test.go` のゴールデンテスト)
- 実際のパケットでの通過数と drop 数。`lab/rates.sh` と `lab/connlimit.sh` を両モードで流す。`lab/rates.sh` には `Relay` のルールの 2 つのレートを確かめる場面がある
- 許容差に挙げた未確認の点(meter の期限、補充の境界、応答前の UDP のパケットの数え方)

#### Phase 5 の移行の手順

各段は、7a.8 節の共通の完了条件を満たしてから次へ進む。6.1、6.2、6.3 節と 5.3 節の記述は、挙動を変える段のコミットで合わせて改める。

1. `internal/policy` に評価の定数、段と drop の種類の対応、CIDR の正規化を置く。`conntrack` と `proxyrelay` の `sourceAllowed` を `RulePolicy.SourceAllowed` に置き換える。挙動は変えない
2. `internal/policy/nftables` と解釈器と fixture を置き、`internal/dataplane/linuxkernel/nft` の `emit` の送信元制限とレートの部分を置き換える。完了条件は、`testdata/basic.nft` とゴールデンテストが変わらず、今の kernel の挙動を書いた fixture がすべて通ることである。この段では kernel の挙動を変えないので、`Relay` のポートは `src_flow` の行だけを持ち、TCP のルールも `packet` の行を持つ。この 2 点の fixture は `interim_until_step` を付けた暫定のもので、手順 4 と 5 で書き直す(`Relay` の分は手順 4 で書き直した)
3. `internal/policy/goengine` を置き、`srcpolicy` と中継の中の判定の呼び出しを置き換える。前項の userspace の食い違いのうち最初の 2 つを直し、同じ fixture を通す。送信元ごとの同時フロー数は評価器が数え、`flowcap.Counter` はプロセス全体の数だけを数える。評価器は IPv4 でない送信元を拒み、userspace と `Relay` の listener を IPv4 だけで開く。`Relay` の listener は両モードで同じ `proxyrelay` の待ち受けなので、kernel モードの `Relay` の listener もこの段で IPv4 だけになる。kernel の Admission Policy のすべての行に `meta nfproto ipv4` を付ける(送信元の set を使わない集約のレートの行を含む)。nftables の出力が変わるので、`testdata/basic.nft` とゴールデンテストを同じコミットで改め、解釈器にも `meta nfproto` の照合を加える
4. `Relay` に Admission Policy のすべての段を適用する。kernel モードでは待ち受けを開けている `Relay` のポートに全段の行を付け、`Relay` のポートも set の連番を進める。userspace モードでは `proxyrelay` の受け付けで `AdmitFlow` を呼び、手順 3 の入口(`AdmitSourceFlow`)を取り除く。kernel モードの `proxyrelay` に残るのは deny と allow の状態を持たない確認だけで、その拒否は drop に数えない
5. TCP のルールの `packet_rate` の扱いを仕上げる。kernel の nftables コンパイラから TCP のルールの `packet` の行をやめ、`srcpolicy` を削除する。CLI(`rule rate packet`、`rule import`、`rule ls`)と Web UI(ルール詳細ページのレート区画)に、TCP のルールでは `packet_rate` を保存しても効かない旨を示す。`rule add` は `packet_rate` を設定するフラグを持たないので対象に含まない。入力欄は無効にせず、他の欄の保存で既存の値を消さない。この段で Phase 5 のすべての手順が終わる

#### 利用者から見て変わらないものと変わるもの

CLI のコマンドとフラグ、`WGFT_*`、機械向けの CLI 出力、ルールの書き出しと読み込みの形式、admin API v1、join string と agent/server の通信は変わらない(7a.6 節)。Admission Policy は server の中だけで評価し、エージェントには配らない(5.3 節)ので、全体状態も変わらない。drop の種類の文字列、SQLite への累積、`Transparent` の UDP のルールの nftables の行も変わらない。

次の挙動は、IR の意味に揃える修正として変わる。

- userspace モードの UDP で、deny と allow で拒む送信元のデータグラムが、`packet_rate` のトークンを使わなくなる
- userspace モードで、送信元ごとの同時フロー数の上限が `new_flow_rate` より先に判定され、`src_flow` の drop として数えられる
- userspace モードで、`Relay` のルールの接続を送信元ごとの同時フロー数の上限で拒んだとき、`src_flow` の drop として数えられる(手順 3。kernel モードは既に数えている)
- `Relay` のルールに `per_source_rate` と `new_flow_rate` が効き、deny と allow を含めて drop カウンタに数えられる(手順 4)。既にレートを書いた `Relay` のルールでは、更新の後に初めて制限が効き始める
- kernel モードの `Relay` のルールでレートと送信元ごとの同時フロー数が拒む接続は、accept の後に閉じられる代わりに、nftables で黙って捨てられる(手順 4)
- `Relay` のルールを含む設定では、kernel モードの set の連番が `Relay` のポートでも進むので、`wgft server nft` が示す set の番号が変わる(手順 4)
- kernel モードで、TCP のルールの `packet_rate` が効かなくなる(手順 5)
- CLI(`rule rate packet`、`rule import`、`rule ls`)と Web UI が、TCP のルールに `packet_rate` が保存されているとき、効かない旨を新しく示す(手順 5)
- userspace と `Relay` の listener が IPv6 で待ち受けなくなり、IPv6 の送信元は届かなくなる

#### Phase 6 との境界

Phase 5 が扱うのは、IR の 6 つの段だけである。Resource Guard(プロセス全体の予算、ルールごとの隔離、メモリのソフト上限、kernel の conntrack の保護)は、Admission Policy がフローを通した後にだけ判定する。その拒否は Admission Policy の drop の種類に数えず、fixture にも含めない。kernel でも、conntrack の表が溢れてフローが落ちるのは prerouting の判定の後なので、この順序は両モードで同じである。Phase 5 は、送信元ごとの同時フロー数を数える場所を `flowcap.Counter` から評価器へ移すだけで、`flowcap.Limits` の型の分割、`internal/flowcap` の改称、ルールごとの隔離の方式は Phase 6 に残す。

`frontend` の package の分け方(7a.7 節)は、分けないことで決着した。詳細は 7a.7 節を見よ。
