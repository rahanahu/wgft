## 7a. 内部アーキテクチャ

6 節と 7 節が定める外部から見た挙動(送信元制限、レート制限、2 つのデータプレーン)は変えない。対象は内部の package・型・interface・DB スキーマで、互換は求めない。v1.0 の前に適用する再設計である。

### 7a.1 原則と優先順位

内部アーキテクチャは、次の 3 つの原則に従う。

1. 通信方針はグローバルである。送信元の許可と拒否、送信元ごとの新規フローのレート、ルール全体の新規フローレートとパケットレート、送信元ごとの同時フロー数の上限は、kernel dataplane、userspace dataplane、proxy frontend のどれで実装しても同じ意味を持つ
2. 資源の保護はローカルである。Go のヒープと gVisor の状態量の上限、userspace の TCP・UDP フロー予算、ルール間の資源隔離、カーネルの conntrack 資源の保護は、backend ごとに異なる実装で構わない
3. 状態の変更はトランザクショナルである。SQLite に保存しただけのルールを、nftables や listener へ無条件に active として公開しない

判断に迷う場面の優先順位は次のとおりで、上位が下位に優先する。

1. 誤った通信を許可・遮断しない
2. 既存の通信を不用意に切らない
3. 部分的な失敗から安全に回復できる
4. 再起動やクラッシュのあと、宣言した状態へ収束できる
5. 通信方針の意味が backend に依存しない
6. backend 固有の資源保護を適切に行う
7. コード量
8. 内部 API との互換性

### 7a.2 層と責務

ドメインモデルは backend の実装詳細を持たない。`Rule` は ID、プロトコル、待ち受けポート、宛先、所属エージェントだけを持ち、転送方式は別の型で表す。

- `Forwarding`:転送の意味を選ぶ。`Transparent`(素通し。今の `vps_mode=kernel`)と `Relay`(`vpsd` 自身が TCP を終端して中継する。今の `vps_mode=proxy`)の 2 値を持つ。server・agent 全体の転送方式(今の `WGFT_MODE`。`internal/vpsd/store` が持つ `ModeKernel`/`ModeUserspace` の文字列の語彙であり、この層の型ではない)ともう一方の軸であり、これと紛れる「kernel」という語を、ルール単位の選択には使わない
- `SourceMetadata`:送信元の情報を付けるかどうかを選ぶ。`None`(付けない)と `ProxyV2`(PROXY protocol v2 ヘッダを付ける。今の `proxy_protocol=true`)の 2 値を持つ。`Transparent` と組み合わせられるのは `None` だけで、`Transparent` + `ProxyV2` は無効な組み合わせである(今の `proxy_protocol` が `vps_mode=proxy` でしか立てられない制約のまま)。`vps_mode=proxy` と `proxy_protocol` は別の軸なので、`Forwarding` と `SourceMetadata` も別の型にする

外部の表現(rule import/export の JSON、CLI のフラグ、admin API のリクエスト)は変えない。`vps_mode` フィールドの値 `kernel`/`proxy` は、normalize 時に `Forwarding` の `Transparent`/`Relay` へ写す。`proxy_protocol` フィールドは `SourceMetadata` の `None`/`ProxyV2` へ写す。書き出し時はどちらも元のフィールドへ戻す。この写像は、維持する外部仕様である `proto.Rule` と内部モデルの `Rule` の間のアダプタが持つ。

normalize/validate は、外部の `Rule` を受け取り、構造的な検査(ポート範囲の重なり、予約ポート、`proxy_protocol` は `Forwarding=Relay` でしか立てられない、など)をしたうえで内部モデルへ写す。今の `proto.ValidateRules`/`ValidateUpsert`/`UnchangedIDs` が持つ「変更のない行を検査し直さない」規則は、この層に引き継ぐ。

`AdmissionPolicy` は、送信元の許可拒否、送信元ごとの新規フローレート、ルール全体の新規フローレートとパケットレート、送信元ごとの同時フロー数の上限をまとめた中間表現である。kernel の nftables 式、userspace の Go の評価器は、どちらもこの IR から作る。評価順(拒否、許可、送信元ごとの上限、送信元ごとの同時フロー数の上限、集約の新規フローレート、集約のパケットレート。今の 6.1 節の順序をそのまま踏襲する)は、IR の一部として 1 か所にだけ書く。

`Planner` は、normalize したルール集合と `AdmissionPolicy` から `Plan` を組み立てる。OS、nftables、gVisor の実装詳細を知らない。`Plan` は、宣言した世代番号、送信元制限を含む ingress の計画、宛先までの経路の集合、WireGuard のピア集合を持つ、backend に依存しないデータである。

`Backend`(kernel/userspace の dataplane)と、Observe/Prepare/Commit/Rollback を持つ transaction の参加者(participant)は別の概念である。`Backend` はその 1 つの participant だが、`Relay` の listener 集合のような frontend 側の資源も、同じ Observe/Prepare/Commit/Rollback を持つ participant になりうる。`internal/vpsd/proxyrelay` の `Prepare`/`Commit`/`Rollback` が、この形の実例として既にある。

`Runtime` は、participant を固定の順序で束ねた実行単位である。server の `Runtime` は frontend の資源(`Relay` の listener)と dataplane の `Backend` から組み立て、agent の `Runtime` も同じ 2 種類の participant から組み立てる(agent の frontend は空、または userspace の `Relay` の listener になる)。ただし agent を `Runtime` へ移すのは後の段階であり、それまでの agent は `internal/agent` の中に切った dataplane の境目を使う(7a.7 節)。

`Reconciler` は `Backend` を直接動かさず、`Runtime` を動かす。手順は次の固定順序である。

1. frontend を `Prepare` する(新しい listener を開く、など)。`Prepare` に失敗したルールは、dataplane へ渡す `Plan` から外す(7a.3 節の fail-closed)
2. frontend の `Prepare` の結果(待ち受けているポートの集合)を、dataplane の `Prepare` への入力にする
3. dataplane を `Commit` する(公開する。kernel backend ではこれが nftables の 1 トランザクションである)
4. frontend を `Commit` する(中継を始める、消えた listener を閉じる)
5. 失敗すれば、`Prepare` した participant を逆順に `Rollback` する

この手順には、戻せる地点と戻せない地点がある。失敗しうる処理(bind、名前解決、資源の確保、検査)はすべて `Prepare` に置く。dataplane の `Commit` は不可分の公開であり、失敗すれば何も公開されず、frontend の `Prepare` を `Rollback` できる。kernel backend には例外が 2 つある。commit の後の応答の受信に失敗した場合(6.1 節の受信側の壁)と、差し替えの後に読み直した送信元の一覧の set が送った要素を持たない場合(6.1 節)は、テーブルが差し替わった後で誤りが返る。dataplane の `Commit` が成功した時点が戻れない地点で、それ以降は `Rollback` しない。そのため frontend の `Commit` は失敗してはならず、何度呼んでも同じ結果になるものにする。中身は、`Prepare` で確保済みの資源を使い始めることと、消えたものを閉じることだけに限る。戻れない地点の直後にプロセスが落ちた場合は、`Rollback` ではなく、再起動時の `Observe` が `Desired` との差分を見つけて収束させる(7a.3 節の適用途中のクラッシュ)。

WireGuard のピアの変更、drop カウンタの読み出し、公開の後の収束も、同じトランザクションに含める。dataplane の `Prepare` は、新しく宣言されたピアを追加し(旧いピアはまだ残す)、kernel backend ではテーブルの差し替えを組み立てるところまでを行う。dataplane の `Commit` は、差し替える前のテーブルの drop カウンタを読み、差し替えを公開し、宣言から消えたピアを削除し、conntrack(userspace backend ではセッション)を収束させる。drop カウンタは公開が成功したときだけ制御プレーンへ渡す。差し替えが失敗した場合は旧いテーブルがカウンタを持ち続け、次の成功した差し替えで 1 回だけ読まれるので、同じカウンタを二重に累積しない。ピアの削除と収束は戻れない地点の後の処理なので、失敗しても `Commit` を失敗させず、ログに残し、7a.3 節の「戻れない地点の後の修復」で試し直す。`Rollback` は、追加したピアを取り除き、元の集合に戻す。起動時は、最初のトランザクションの前にインタフェースだけを立ち上げる(鍵、待ち受けポート、アドレス、MTU。所有判定による中止もここで行う)。ピアは最初のトランザクションで収束させる。

参加する participant の種類と順序は固定であり、汎用の 2 相コミットではない。Phase 2 より前の `internal/vpsd/apply.go` の `applyNFT`(`proxyrelay.Prepare` → `dp.ApplyNFT` → `proxyrelay.Commit`/`Rollback`)が、この順序の実例であり、Phase 2 からは同じ順序を `internal/reconcile` の `Runtime` が実行する。`Runtime` の合成は `internal/reconcile` の participant interface として持ち、実際の組み立ては `vpsd` が起動時に `frontend` と `dataplane` の実装から行う(7a.7 節)。Observe → diff → Prepare → Commit の骨格そのものは共有 package `internal/reconcile` に置く。今この骨格を使うのは server であり、agent は `Runtime` へ移った後に同じ骨格を使う(7a.7 節)。`Backend` は kernel と userspace の 2 つを持ち、それぞれが OS、nftables、netstack などの実装詳細を隠す。

`Resource Guard` は、`AdmissionPolicy` と分けて持つ、wgft 自身と OS の資源を守るための予算である(7a.5 節)。

`Forwarding` の実装は `Transparent` と `Relay` の待ち受けと中継を持つ。userspace backend では両者は同じ中継コードを使う(6.3 節のとおり)。kernel backend では `Transparent` は nftables の DNAT で完結し、`Relay` は `vpsd` 自身の TCP リスナーを要する。`SourceMetadata=ProxyV2` は `Relay` の中継が接続先へ送るヘッダの有無を選ぶだけで、待ち受けの構造そのものは変えない。

現在の実装から新しい層への対応は次のとおりである。

| 現在の実装 | 新しい層 | 備考 |
|---|---|---|
| `proto.Rule` の `VPSMode`/`ProxyProtocol` | `Rule` + `Forwarding` + `SourceMetadata` | 外部 JSON の `vps_mode`/`proxy_protocol` は変えず、アダプタで写す |
| `proto.ValidateRules`/`ValidateUpsert`/`UnchangedIDs` | normalize/validate | 変更のない行を検査し直さない規則を引き継ぐ |
| `internal/dataplane/linuxkernel/nft` の評価順ロジック(deny・allow・per_source・flow-cap・new_flow・packet。Phase 3 で `internal/vpsd/nft` から移した) | `AdmissionPolicy` の nftables コンパイラ | IR からnftables 式を生成する部分だけを残す |
| `internal/dataplane/userspace/srcpolicy`(Phase 2 で `internal/vpsd/srcpolicy` から移した) | `AdmissionPolicy` の Go 評価器 | nftables の評価順を手で模す実装をやめ、IR 由来の 1 実装に統合する。Phase 5 の移行の手順 3 で `internal/policy/goengine` に置き換わり、手順 5 で package ごと削除した |
| `internal/dataplane/linuxkernel/conntrack`(Phase 3 で `internal/vpsd/conntrack` から移した)の `allowed()` | 同上を呼び出す側 | 許可判定の再実装をやめ、共通の評価器を呼ぶ |
| `internal/vpsd/proxyrelay` の `sourceAllowed()` | 同上を呼び出す側 | 同上 |
| `internal/vpsd/proxyrelay` の `Prepare`/`Commit`/`Rollback` | frontend の最初の transaction participant | `Relay` の listener 集合を、`Runtime` の frontend participant として一般化する |
| `internal/vpsd/apply.go` の `applyNFT`/`converge` | `Planner`(Plan 生成) + `internal/reconcile` が動かす `Runtime`(適用) | 1 関数に融合していた計画と適用を分ける。`proxyrelay.Prepare` → `dp.ApplyNFT` → `proxyrelay.Commit`/`Rollback` という呼び出し順が `Runtime` の participant の順序の実例。Phase 2 で、`applyNFT` は `Plan` を組み立てて `Runtime` で適用する形になった。Phase 4 で、`internal/reconcile` の `Reconciler` が `Runtime` を動かし、`Active` と世代を持つ形になった |
| `internal/vpsd/dataplane.go` の `serverDataplane` interface | kernel `Backend` | Phase 2 で、`ApplyNFT` の直接呼び出しを `Runtime` の dataplane の participant(Prepare/Commit/Rollback)に置き換えた。Phase 3 で kernel の実装を `internal/dataplane/linuxkernel.Backend` へ移し、`Plan` と Relay の待ち受け集合だけから組み立てる形にした(`nft.Apply` はルール集合と接続元ごとの上限の解決済みの値をもう受け取らない)。`internal/vpsd/dataplane.go` の `kernelDataplane` は、`Backend` を包んで host 側検査(`internal/platform/linux`)を添えるだけの薄い層として残る |
| `internal/dataplane/userspace`(Phase 2 で `internal/vpsd/dataplane_userspace.go` から移した) | userspace `Backend` | `Plan` だけから組み立てる。`internal/vpsd/dataplane_userspace.go` には、ユーザー空間モードで何もしないホスト側の検査だけが残る |
| `internal/dataplane/linuxkernel/wg`(Phase 3 で `internal/vpsd/wg` から移した。`Ensure` の差分適用) | kernel `Backend` の WireGuard 収束 | 現在の値と宣言を突き合わせて差分だけ変える実装なので、ほぼそのまま引き継いだ。インタフェース名と `--adopt-existing` は `Backend` の構築時の値になり、`dataplane.WGConfig`(宣言)には含めない |
| `internal/dataplane/linuxkernel/conntrack`(Phase 3 で `internal/vpsd/conntrack` から移した) | kernel `Backend` の conntrack 収束 | `Backend.Converge` が `RulesFromPlan` で `Plan` の Transparent なポートから収束の判定材料を作る。呼び出し側(`vpsd`)はもうルール集合を組み立て直さない |
| `internal/platform/linux`(Phase 3 で `internal/vpsd/check` から移した) | host 側の前段検査 | kernel `Backend` に同梱しない。agent の kernel backend(Phase 7)からも同じ検査を呼ぶため。`ip_forward` の確認・書き込み、conntrack テーブルの大きさ、conntrack の UDP タイムアウトの読み取り(旧 `internal/vpsd/wg` の一部)もここに合わせて移した |
| `internal/resource`(Phase 6 の移行の手順 1 で `internal/flowcap` から改めた) | `Resource Guard` | `Limits` はプロセス全体の予算だけを持つ。接続元ごとの上限は `internal/policy` の `AdmissionLimits` へ、ログを間引く門は `internal/lograte` へ移した(7a.5、7a.10 節) |
| `internal/dataplane/userspace/relay`(Phase 2 で `internal/agent/relay` から移した)の `plan`/`Action` | `internal/reconcile` の骨格のひな型 | この型を `internal/reconcile` に一般化する。agent が `Runtime` へ移った後は、server と agent で共有する |
| `internal/dataplane/userspace/tunnel`(`internal/agent/tunnel` から移した)、`internal/dataplane/userspace/utun`(Phase 2 で `internal/vpsd/utun` から移した)、`internal/nettun` | userspace `Backend` の下位実装 | プラットフォーム配線そのままである |
| `internal/vpsd/agentapi`、`internal/vpsd/stream`、`internal/vpsd/store`、`internal/vpsd/admin` | `vpsd` の制御プレーン | 変更なし(登録、配信、永続化、admin API) |
| `internal/agent/credentials` | `agent` の制御プレーン | 変更なし |

### 7a.3 状態遷移と失敗の意味論

ルール 1 本、あるいは WireGuard のピア 1 つは、次の 5 つの状態を遷移する。

- `Desired`:管理用 API のバッチ操作で SQLite に保存された状態。世代を 1 つ進める(5.4 節)
- `Validated`:normalize/validate を通り、内部モデルに写った状態
- `Prepared`:元に戻せる資源を確保した状態。listener の bind、名前解決がこれに当たる
- `Active`:nftables または userspace の dataplane へ公開され、実際に転送している状態
- `Retiring`:宣言から消えたが、既存の conntrack エントリやセッションがまだ残っている状態

`Prepare` は元に戻せる資源だけを取る。listener の bind、ホスト名の名前解決がこれに当たり、失敗すればそのルールだけが `Active` にならず、他のルールの `Prepare`・`Commit` を妨げない。`Commit` は、dataplane と frontend の participant(7a.2 節の `Runtime`)が準備した状態を公開し、`Active` の値を更新することを指す。kernel backend では、公開の中核は nftables の 1 トランザクションである。WireGuard のピアは、公開の前に足し、公開をやめた後に消す順序で扱う。参加する participant の種類と順序は固定で、汎用の 2 相コミットは持たない。

この区別の具体例は、proxy frontend の listener 管理に既にある(6.1 節)。ルール変更を適用するとき、新しく追加されたポートの listener だけを先に開き(`Prepare`)、既存の listener はそのまま残す。新しく開いた listener はこの時点では中継を始めない。nftables へ渡す計画は、開き終えた後の listener 集合(残るもの + 新しく開いたもの。削除されるポートは除く)から組み立てる。dataplane への適用が失敗すれば、新しく開いた listener を閉じて(`Rollback`)、旧い listener と旧い nftables テーブルの組み合わせのまま保つ。成功すれば、新しい listener で中継を始め、削除対象の listener を閉じ、残る listener の制限を更新する(`Commit`)。

6.1 節が述べるとおり、この手順でも SQLite には新しい宣言(`Desired`)が既に保存されているのに、nftables への適用(`Commit`)だけが失敗する瞬間が生じる。今の実装は、この失敗を `log.Printf` で記録し、その場の管理用 API 呼び出しへのエラー応答として返すだけである(`internal/vpsd/apply.go` の `applyNFT`、`admin_backend.go` の `Batch`)。呼び出し元がその応答を見送れば、SQLite に保存された宣言と実際に転送しているルールとの食い違いは、どこにも残らない。これが埋めるべき隙間である。

新しいアーキテクチャでは、制御プレーンが `Desired` と `Active` の両方を持つ。admin API・CLI・Web UI はルール集合を `Desired` の値で示しつつ、ルールごとに `apply_state`(`active`、`pending`、`not_active`)、理由付きの `reason`、そのルールが最後に反映された `active_generation`、今の `desired_generation` を添えて返す。これは admin API v1 への加算的な変更であり、既存のフィールドは変えない(例:bind 失敗の理由は `bind failed: address in use`)。今はこの理由がログにしか残らない。

`Desired` のルール一覧だけでは、削除済みなのに backend 全体の失敗で残ったままのルールのように、`Active` にはあるが `Desired` には無い資源を見せられない。このため admin API は、ルール一覧とは別に、`Desired` に無いのに `Active` または `Retiring` のまま残っている資源(`active_only`/`retiring`)を観測できる経路を持つ。

dataplane への適用は、その時点の宣言を normalize/validate した結果から組み立てた `Plan` を渡し、再起動時の収束も `Desired` との差分で行う(9 節の突き合わせと同じ)。`Active` は「直近の `Commit` が成功して実際に転送している値」を指す、読み取り専用の派生値である。

失敗の意味論は、失敗の及ぶ範囲によって次の 2 つに分かれる。

- ルール単位で閉じる失敗(1 つの listener の bind、1 つの target の名前解決):既存のルールを置き換える `Prepare` が失敗した場合、そのルールは新しい `Active` の値にならない。旧い `Active` の値は他のルールの `Commit` までは残ってよいが、他のルールの `Commit` が成功した時点で、このルールは新規のフローを拒む(fail-closed)。宣言と食い違ったまま旧い設定で新規の通信を許可・拒否し続けることは、7a.1 節の優先順位 1 に反するためである。既に成立しているフローは、安全であれば(新しい `source_deny` などに反しない限り)`Retiring` として残す。ただし、成立済みのフローを残せるのは、エージェントに配る宣言(`listen_port`、`target`、5.3 節)が変わらない置き換えに限る。エージェントは VPS と同じポートで待ち受け(6.1 節)、`listen_port` か `target` が変わるとリスナーを閉じ直す(7 節の実効宛先)ので、server 側の `Prepare` が失敗しても、旧いポートと旧い宛先の成立済みの接続はエージェント側で切れる。フローが残るのは、同じポートと宛先のまま `vps_mode` を切り替えた場合や、送信元の一覧だけを変えた場合である。`Desired` は新しい値のままとし、状態は理由付きの `not_active` として報告する。他のルールの `Prepare`・`Commit` は妨げず、`Active` 世代は進む。nftables は全体を毎回組み立てて 1 トランザクションで差し替える(6.1 節)ため、この fail-closed は次の全体差し替えにこのルールの新しい dispatch を含めない、というだけで実現できる。差し替え中のルールだけを部分的に書き換える仕組みは要らない
- backend 全体に及ぶ失敗(共有の `flows_tcp`/`flows_udp` の set が作れない、WireGuard インタフェースを変えられない、nftables のトランザクション誤りなど):`Commit` 全体を中止し、`Active` 世代を進めない。nftables の 1 トランザクションはカーネル側で原子的なので、カーネルがバッチを拒んだ場合と、送信が拒まれた場合は、テーブル全体が旧のまま残る。例外は、commit の後の応答の受信に失敗した場合(6.1 節の受信側の壁)と、差し替えの後に読み直した送信元の一覧の set が送った要素を持たない場合(6.1 節)である。どちらの場合もテーブルが差し替わった後で誤りが返るので、`Active` 世代とテーブルが食い違う。この食い違いは drift として検出し、`Active` 世代の再公開で収束させる(7a.3 節)。新しく開いた listener があれば `Rollback` する
- 適用途中のクラッシュ:再起動時に `Observe`(9 節の突き合わせ)を行い、`Desired` との差分だけを `Prepare`・`Commit` し直す。kernel dataplane は停止していた間も wg0 とテーブルを残すため(9 節)、収束は差分だけで済む
- 通常のシャットダウンと明示的な撤去(`teardown`)は別の操作である。通常のシャットダウンは制御プレーンだけを止め、kernel dataplane は残す。撤去は wgft が作った資源だけを消す(10.3 節)。この区別は今の server の kernel モードが既に満たしているので、崩さずに引き継ぐ
- conntrack を伴う更新:ルールの変更後、既存のフローで新しい宣言に合わないものを `Retiring` として消す(6.1 節の conntrack 収束)。この判定は失敗時の意味論ではなく、`Active` 化の直後に必ず行う収束である。置き換えの `Prepare` に失敗して fail-closed にしたルールについては、収束は直前の `Active` の値でフローを判定し、安全な成立済みのフローを `Retiring` として残す。新しい宣言だけで判定すると、fail-closed のルールの成立済みフローまで消えてしまうためである。収束は kernel backend の責務で、server だけの機能にしない。agent の kernel dataplane を手で組んだ試作では、この収束が無いと、宛先を変えたルールの既存フローが旧い宛先へ流れ続け、消したルールのフローの conntrack が残った(TCP は最長 5 日)

`Relay` の listener を `Retiring` にする操作は 2 つに分ける。`StopAccepting` は待ち受けソケットだけを閉じ、既に成立している TCP 接続には触れない。触れなかった接続は `Retiring` になり、自然に終わるまで残る。`Retire`(drain)は、新しい方針の下で安全でなくなった接続(新しい `source_deny` に一致するようになった接続など)だけを閉じ、それ以外は自然に終わるまで待つ。今の `internal/vpsd/proxyrelay` の `listener.close()` は待ち受けソケットと進行中の接続をまとめて閉じており、ルールの削除や無効化のたびに成立済みの接続も切れる。`StopAccepting` と `Retire` は、置き換えの `Prepare` に失敗したルールを fail-closed にするときにだけ使う。ルールの削除と無効化は、今と同じく成立済みの接続も切る。kernel backend でも、削除したルールの DNAT に合うフローは conntrack の収束(6.1 節)が消し、この挙動はラボの lifecycle テストで固定している。削除は利用者がその通信を止める宣言であり、宣言を反映できないときの fail-closed とは意味が違う。

Phase 4 の実装で、7a.3 節の意味論の細部を次のとおり定めた。

- 適用状態の値:`apply_state` は `active`、`pending`、`not_active` の 3 値である。`active` は、そのルールの `Desired` の値が転送中の値と一致する状態である。`pending` は、直前のトランザクションが backend 全体の失敗で中止され、`Desired` の値がまだ公開されていない状態で、`reason` はその失敗である。無効化のように転送をやめる宣言が公開されていない場合も `pending` とする。`not_active` は、そのルールが転送されない状態で、`reason` は `Prepare` の失敗(fail-closed)、`disabled`、エージェントの未登録、SQLite の行が内部モデルへ写せないこと、のいずれかである
- admin API の加算:`GET /api/v1/rules` と `POST /api/v1/rules/batch` の応答に、`desired_generation`、`active_generation`、`rule_states`(ルール ID から `apply_state`、`reason`、`active_generation` への表)、`drift`(`active_only` と `retiring` の 2 つの一覧)、`apply_error`(直前のトランザクションの backend 全体の失敗か、公開の後の修復の失敗。後述の「戻れない地点の後の修復」)を加える。既存のフィールドは変えない。配信用の全体状態については別に `agent_state_generation`(最後に全体の適用に成功した世代)と `agent_state_pending`(保存済みの全体宣言に対応する適用がまだ成功していないか)を加える。報告する server は `agent_state_pending` の偽も明示し、報告しない旧版では両フィールドを省く。無効化だけを先に重ねたときの送信上の世代は `agent_state_generation` より進みうる。`rule ls --json` は応答をそのまま出力するので、同じキーが増える。Web UI は、ルール一覧と詳細の状態の欄に、server で公開できていないルールを理由付きで示す
- 世代:`desired_generation` は、最後に適用を試みた宣言の世代(SQLite の世代。5.4 節)である。`active_generation` は、最後に成功したトランザクションの世代である。ルールごとの `active_generation` は、そのルールの転送中の値が公開された世代で、値が変わらない限り進まない。エージェントの登録のように世代を進めない変更でもトランザクションは走り、その場合の `active_generation` は同じ番号のままである

転送面が NoOp と判定して `active_generation` が進んでも、配信用の全体状態が異なれば明示的な適用を 1 回試す。その適用が失敗した場合、転送面の `active_generation` を配信用の全体状態が公開された世代とは呼ばない。`agent_state_pending` は真で、`agent_state_generation` は前の成功値のままである。診断はこのとき配信用の全体状態まで完了したとは報告しない。

これらの値を報告する server は、正常時にも管理用 API の `active_generation`、`agent_state_generation`、`agent_state_pending` を返す。`status` と `server doctor` の通常の人向け表示では、2 つの世代が異なるとき、または `agent_state_pending` が真のときだけ、両方の世代を名前付きで示す。数値が等しくても pending が真なら未公開の所見を残し、両方を示す。この表示条件で一方の数値が欠けていれば、その値を未報告と示す。世代の数値が異なることだけでは判定を変えない。正常で両世代が等しく pending が偽なら、通常の出力に世代を加えない。
- 差分と公開の範囲:トランザクションは毎回 `Plan` の全体を公開する(nftables は全体の差し替え。6.1 節)。`Active` との差分は、ルールごとの状態の報告と、fail-closed にしたルールの `Retiring` の値の決定に使い、公開する範囲の絞り込みには使わない
- `Retiring` の期間:fail-closed にしたルールは、最後に `Active` だった値を `Retiring` として持つ。失敗が続くあいだも、`Retiring` の値は公開されなかった新しい値ではなく、最後に `Active` だった値のままである。ルールが新しい値で `Active` になったとき、削除・無効化されたとき、エージェントの登録が取り消されたときに `Retiring` は終わり、残っていた成立済みのフローも閉じる。新しい値で `Active` になったときに閉じるのは、新しい値に合わない成立済みのフローを削除する kernel backend の conntrack の収束と、同じ扱いにするためである
- 安全の判定:`Retiring` のフローを残す条件は、直前の `Active` の値と新しい宣言の両方の送信元の許可拒否に合うことである。kernel backend の conntrack の収束は、直前の `Active` の値の宛先(ポートとエージェントのアドレス)でフローを照合し、この条件で判定する
- userspace backend の `Retiring`:TCP の listener は、`Relay` の `StopAccepting` と同じく待ち受けソケットだけを閉じ、成立済みの接続を残す。UDP の listener はセッションの応答を同じソケットから返すので、ソケットを閉じずに、新しい送信元のデータグラムを捨てる。受け付けを止めたかどうかは、データグラムを読んだ時点に加えて、Admission Policy の判定の後とセッションの登録の時点でも確かめる。このため、読んだ後の判定や宛先への dial の途中で `Retiring` になった新しい送信元のセッションも作られない。同じポートが宣言に戻れば、UDP は保持していたソケットで受け付けを再開する
- `Observe`:`Reconciler` は、最初のトランザクションの前に dataplane の `Observe` を呼び、デバイスが今持つ WireGuard のピアの集合を読む。kernel backend では、前のプロセスが残したピアである。ルールの `Active` の値はプロセスの中だけに持つので、再起動後の最初のトランザクションは、すべてのルールを新しい値として公開する。nftables は全体の差し替えなので、これが再起動時の収束(9 節の突き合わせ)になる。最初の `Commit` の後の `Observe` は、実際の状態が直前の `Commit` の残した状態と一致するかも返す(後述の「実際の状態への収束」)
- 再試行:`Desired` がすべて `Active` になっていないあいだ、`vpsd` は 30 秒ごとに宣言を適用し直す。対象は、ルールの `Prepare` の失敗(bind、名前解決)と backend 全体の失敗の両方で、1 つの再試行の仕組みで扱う。起動時の最初の適用の失敗も、同じ間隔で試し直す(11b 節の起動の保留)。どちらも、解消したことを知らせる通知が無いためである。ポートが空いても nftables の変更の通知は届かない。`table inet wgft` を保持していた他のプロセスが終わってテーブルが消えても、通知は届かない(後述の「実際の状態への収束」)。間隔はエージェントの待ち受けの再試行(5.2 節)と同じである。無効化、エージェントの未登録、写せない行は、意図して転送しないルールなので再試行の理由にしない。再試行が前回の公開と同じもの(世代を除いた `Plan`、待ち受けているポートの集合、失敗したルールの集合が同じで、ピアの変更が無い)を公開するだけなら、何も commit せずに `Prepare` を戻す。nftables のテーブルを差し替えると meter と `ct count` の状態がリセットされる(7a.4 節)ため、変化の無い再試行ではテーブルを差し替えない。管理者の操作による適用は、従来どおり毎回公開する。ルール単位の失敗は、始まったときと理由が変わったときに 1 行、回復したときに 1 行だけログに出し、再試行のたびには出さない。今の理由は admin API と Web UI の状態で見える。backend 全体の失敗は、試し直しで同じ失敗が続くあいだ 1 行だけ出す。backend 全体の失敗の後は、変更の通知による適用し直しの間隔を空ける。失敗した公開もテーブルを差し替えることがあり(6.1 節の受信側の壁と、送った要素を持たない set)、その差し替えが生む通知で適用し直すと、失敗が 1 秒に数回の間隔で繰り返され、そのたびに meter と `ct count` の状態がリセットされるためである。通知による適用し直しは、失敗の後 1 秒から始まり、失敗が続くたびに倍になって 30 秒で頭打ちになる間隔が過ぎるまで行わない。成功すると間隔は 1 秒に戻る。`Observe` が新しく見つけた食い違いは、この間隔を待たずに適用し直す。この食い違いには、wgft の外からの変更のほかに、失敗した公開が差し替えたテーブルも含まれる。公開し直しの途中でなかった公開が差し替えの後に失敗すると、比べる基準は直前の成功のままなので、次の `Observe` は wgft 自身の差し替えを新しい食い違いとして報告するためである。したがって、失敗の続く期間はどれも、間隔を待たない適用し直しを 1 回だけ含んで始まる。その後は公開し直しの途中の状態が続くので、同じ食い違いは新しいものとして報告されず、間隔が効く。30 秒ごとの再試行は、この間隔に関係なく走る。ルールの変更、エージェントの登録と鍵の宣言、`vpsd` の再起動でも、そのときのトランザクションが `Prepare` し直す。userspace モードで同じポートの `Transparent` と `Relay` を切り替えると、最初のトランザクションでは旧い側がポートを持っているので bind に失敗する。旧い側は `Retiring` として待ち受けソケットを閉じるので、次のトランザクション(再試行を含む)で新しい側が `Active` になる
- ピアを変える操作:エージェントの登録、公開鍵の変更、登録の取り消しは、ピアをトランザクションの中で変えるので、テーブルの差し替えを伴う。公開鍵の変更はエージェントの恒久トークンの持ち主が起こせるので、回数を 5.2 節の鍵の変更の頻度の上限で抑える。ピアだけを変えるトランザクションでテーブルを差し替えない形は 13 節に残す
- エージェントの無効化(5.1 節):無効なエージェントのルールは、本節ではルールの無効化と同じに扱う。宣言から外れて `Retiring` を終え、成立済みのフローを閉じ、再試行の理由にせず、評価器の状態も作り直す(7a.4 節)。`apply_state` は `not_active` とし、`reason` はエージェントが無効であることを示す。ピアは変えない

実際の状態への収束:`vpsd` は、宣言が変わったときにだけ適用する方式ではなく、`Desired` と実際の状態が食い違えばいつでも収束させる方式を取る。kernel dataplane の `table inet wgft` と wg インタフェースは、wgft の外からも変えられるためである。多くの VPS の `/etc/nftables.conf` は `flush ruleset` で始まるので、`systemctl reload nftables` の実行だけでテーブルが消え、転送が止まる。収束の契機はカーネルの変更の通知であり、定期的な突き合わせは通知の取りこぼしに備える安全網である。

- 変更の通知:kernel backend は、nftables の変更の通知(`NETLINK_NETFILTER` の `NFNLGRP_NFTABLES`。`nft monitor` が読む通知と同じもの)と、リンクと IPv4 アドレスの変更の通知(`RTNLGRP_LINK`、`RTNLGRP_IPV4_IFADDR`)を購読する。購読は Go から netlink で直接行い、`nft monitor` のプロセスは起動しない。この購読のソケットも、6.1 節の応答側の壁と同じ理由で受信バッファを既定より大きい値(8 MiB)まで要求する。大きな Admission Policy の送信元一覧(7a.4 節。数千要素の set)を差し替えると、その通知が既定の受信バッファ(`net.core.rmem_default`)を超えて `ENOBUFS` になりうるためである。要求は `SO_RCVBUFFORCE` で行い、権限が足りなければ `SO_RCVBUF` に落ちる。init の user namespace での `CAP_NET_ADMIN` が無い配置(user namespace を分けた非特権の LXC など)では `SO_RCVBUFFORCE` が拒まれ、`SO_RCVBUF` は `net.core.rmem_max` の 2 倍で頭打ちになるので、要求した 8 MiB に届かないことがある。この配置でも `ENOBUFS` は起こりうるが、下の「安全網」の購読の張り直しが同じように拾う。通知は `Reconciler` を起こすきっかけにすぎず、`vpsd` は通知の内容を読まない。どのテーブルのどの変更の通知でも、最初の通知から 250 ミリ秒待って続く通知をまとめ、`Observe` で実際の状態を読み、直前の `Commit` の残した状態と比べる。一致すれば何もしない。`vpsd` 自身の `Commit` も通知を生むが、扱いは同じで、`Observe` が一致を確かめて終わる。この 1 つの仕組みが、ルール、set、チェーンの編集、テーブルの削除、`flush ruleset` を扱う。持ち主の印(`owner` フラグ)を付けて `table inet wgft` を保持するプロセスがあると、テーブルの差し替えは backend 全体の失敗になる。そのプロセスが終わるとカーネルはテーブルを消すが、この削除は通知を生まない(Linux 6.1 のラボで `nft monitor` でも確かめた)。このため、保持の解放は 30 秒ごとの再試行が拾い、`pending` のままだった世代が、管理者の操作を待たずに公開される。backend 全体の失敗で公開できなかった世代はエージェントにも配られていないので、試し直しがその世代を公開したときにエージェントへ配る(5.2 節)
- 安全網:通知が無くても 5 分ごとに `Observe` する。受信バッファの溢れ(`ENOBUFS`)で通知を失った場合と、購読が切れた場合は、何かが変わったものとして `Observe` し、1 秒から 1 分まで間隔を倍にしながら購読を張り直す。購読の失敗は、失敗が続くあいだ 1 行だけログに出す。WireGuard には設定の変更の通知が無い。`wg set` でピアや待ち受けポートを変えても、netlink の通知は届かない(ラボで確かめた)。この変更は安全網が 5 分以内に拾う
- 比較する状態:kernel backend は、`Commit` の直後に次の 2 つを読んで持ち、`Observe` で読み直して比べる。1 つ目は `table inet wgft` の指紋である。指紋は、各チェーンの名前、種類、フック、優先度と、各行のハンドル、コメント、式の並びと、wgft が要素を書く set(`deny_N`、`allow_N`)の要素から計算する SHA-256 である。式のうち `counter` の値は 0 に置き換える。meter と `flows_udp`/`flows_tcp` のように、パケットが要素を加える set(`flags dynamic`)は要素を含めない。どちらも転送のたびに変わるが、変わっても宣言は崩れていないためである。行の削除と追加、置き換えはハンドルか式の並びを変えるので、指紋も変わる。読み取りはテーブル、チェーン、各チェーンの行、set、各 set の要素の netlink のダンプで、`nft list` の出力の比較はしない。指紋を基準として持つのは `Commit` が成功したときだけである。送信元の一覧の set の検査(6.1 節)に失敗した差し替えのテーブルは、基準にしない。2 つ目は wg インタフェースで、WireGuard の種別であること、秘密鍵、待ち受けポート、アドレス、up の状態、ピアの集合(公開鍵と AllowedIPs)を、直前の `Commit` の宣言と比べる
- 食い違ったときの公開:何が食い違ったかを 1 行のログに出し、`Plan` の全体を 1 回だけ公開し直す。このトランザクションはテーブルを差し替え、wg インタフェースを鍵、ポート、アドレス、MTU、ピアまで収束させ、インタフェースが無ければ作る。公開し直すと meter と `ct count` の set はリセットされ、消えたテーブルの drop カウンタは累積されない。どちらもテーブルが消えた時点で既に失われた状態なので、許容する。食い違いの無い `Observe` は何も `Prepare` せず、テーブルを差し替えないので、meter と `ct count` の状態は保たれる。公開し直しが失敗しているあいだは、`Plan` のすべてのルールを `pending` として報告する。転送が止まっているかもしれず、`active` とは言えないためである
- 所有:wg インタフェースの名前を、wgft の鍵と一致しない WireGuard デバイスか WireGuard 以外のリンクが持っていれば、他人の資源とみなして触らない(9 節の所有判定)。起動時の `--adopt-existing` も稼働中の引き継ぎには使わない。この状態は backend 全体の失敗として `apply_error` とログに出し、名前が空けば次の `Observe` がインタフェースの消失として扱って作り直す
- userspace モード:カーネルに残る状態が無く、トンネルと待ち受けはプロセスの中にあるので、通知を購読しない。`Observe` は食い違いを報告しないので、5 分ごとの安全網は何も公開し直さない。失敗の試し直しは kernel モードと同じ 30 秒ごとの再試行が行う
- 比べない状態:他のテーブル(`flush ruleset` の後に読み込まれる forward の `policy drop` など)は wgft の資源ではないので比べない。起動時と `rule add` の検査(6.1 節)がこれを提示する。`net.ipv4.ip_forward` と conntrack のエントリも比べない。`ip_forward` は比べず戻しもしないが、管理用 API が今の値を返し、診断が示す(6.1 節)

戻れない地点の後の修復:dataplane の `Commit` は、公開(kernel backend では nftables の差し替え)の後の手順が失敗しても `Commit` を失敗させない(7a.2 節)。この手順のうち、試し直せば直るものを修復と呼ぶ。修復は、宣言から消えた WireGuard のピアの削除(kernel と userspace の両方)、conntrack の収束、公開したテーブルの指紋の読み直しの 3 つである。conntrack は `Observe` が比べない(前項)ので、収束の失敗を記録しなければ、削除や無効化をしたルールの成立済みのフローが、無関係な次の変更まで旧い DNAT のまま流れ続ける。これは「削除と無効化は成立済みのフローも切る」という意味論(本節の前半)に反する。

- 修復が残っている状態:`Reconciler` は、公開は済んだが修復が残っている状態を持つ。このあいだ `NeedsRetry` を立て、admin API の `apply_error` に `published generation N, but a repair after the publication failed: ...` の形で失敗を示す。ルールの `apply_state` は `active` のままにする。新しいフローは公開した宣言どおりに扱われており、残っているのは、閉じるべき成立済みのフローと消すべきピアだからである。修復が済むと `apply_error` は空に戻る
- 修復の再試行:30 秒ごとの再試行と、変更の通知の後の `Observe` が修復を試し直す。修復の再試行は、公開が前回と同じでも、修復の手順(ピアの削除と conntrack の収束)だけを dataplane の `Repair` で走らせる。nftables のテーブルは差し替えないので、meter と `ct count` の状態は保たれる。修復が残っていない再試行は、従来どおり公開が同じなら何も commit しない。管理者の変更や食い違いの後の公開で `Commit` が走ると、その `Commit` が修復の手順を含むので、残っていた修復も済む。消し損ねたピアがあれば、ピアの集合が変わらなくても、公開の後で WireGuard を宣言に収束させる。公開の前には触らないので、ピアの削除の失敗が次の公開を妨げない。ピアの削除が修復として残っているあいだ、`Observe` はピアの集合の違いを食い違いとして報告しない。修復がピアを宣言の全体へ収束させるので、他のプロセスが変えたピアもそこで直る。食い違いとして扱うと、削除が失敗し続けるあいだ再試行のたびにテーブルが差し替えられ、meter と `ct count` の状態が失われるためである。テーブル、リンクの種別、鍵、待ち受けポート、アドレス、up の状態の違いは、このあいだも食い違いとして報告する
- 指紋の読み直しの失敗:比べる基準が分からない状態になる。この状態の `Observe` は、テーブルがあっても一致とはみなさず、食い違いとして報告し、`Plan` の全体を公開し直して指紋を読み直す。修復の再試行も、まず `Observe` で食い違いを確かめる。指紋の読み直しだけを試し直さないのは、公開から読み直しまでのあいだに wgft の外で変えられたテーブルを、基準として受け入れてしまうためである。このため、この失敗に限り、修復で meter と `ct count` の状態がリセットされる
- drop カウンタの読み出しの失敗:修復にしない。差し替えの後では差し替えられたテーブルのカウンタは無く、試し直しても読めないためである。失敗はログにだけ残し、そのぶんの drop 数は累積されない

### 7a.4 Admission Policy と入口の分岐

kernel dataplane では、`Transparent` と `Relay` への分岐より前に、共通の ingress 層を置く。対象は、wgft が実際に待ち受けを開けている、または DNAT を持つポートだけである。この層は、送信元の許可拒否、送信元ごとの同時フロー数の上限、集約のレートを、`Transparent` と `Relay` のルールに同じ意味で適用する。この考え方は、送信元 IP ごとの同時フロー数の上限をプロキシモードのルールにも同じ `flows_tcp` の set で数える今の実装に、既に部分的に表れている(6.1 節)。bind に失敗したポートには行を付けない規則も、そのまま引き継ぐ。

同じ意味を持つはずの `AdmissionPolicy` でも、kernel の nftables コンパイラと userspace の Go 評価器のあいだには、実装の単位から来る許容差がある。これらは意味の違いではなく実装の単位の違いとして文書化し、共有 fixture で確かめる(7a.9 節)。次の 4 つのほかに、7a.9 節が許容差を加える。

- UDP の 1 フローの数え方:kernel は conntrack のエントリ数を `ct count` で数える。userspace は `relay.Manager` が持つセッション数を数える。両者は「今生きているフロー数」の近似として一致するが、テーブル差し替え直後の扱いは次の項で述べるとおり異なる
- タイムアウトの非対称:VPS の conntrack の `udp_timeout`(既定 30 秒)と、agent 側のセッションタイムアウト(全体状態の `udp_timeout_stream`)は非対称である(4 節、7 節)。この非対称は既に文書化された許容差として扱う
- トークンバケットの粒度:nftables の `limit rate over` は burst 5 で動く。userspace の評価器はこれを模した固定 burst 5 のトークンバケットを持ち、ラボでカーネルモードと通過数・drop 数の累計が一致することを確かめている(2026-09-17)。IR はこの burst 値を仕様の一部として持ち、実装ごとに変えない
- テーブル差し替えによる ct count/meter のリセット:kernel は nftables のテーブル差し替えのたびに `flows_udp`/`flows_tcp` の set を作り直すため、差し替え前からのフローは新しい set の数に入らない(6.1 節)。userspace の評価器(`goengine.Engine.Update`)は、送信元ごとの同時フロー数を作り直さずに引き継ぎ、ルール ID が転送するルール(有効で、エージェントが登録済みのもの)として引き続き存在し、かつそのレートの値が変わっていない限り、バケットと送信元表を引き継ぐ。ルール ID が変わる操作(分割・統合)、レートの値そのものを変える操作、ルールの無効化、エージェントの登録の取り消しでは、そのルールの状態だけを作り直す(転送しなくなったルールの状態は捨て、再び転送するときに新しく作る)。適用のたびに評価器全体を作り直すわけではないため、無関係な他ルールの状態はリセットされない。kernel の差し替えは、管理者の操作、server の起動、wgft の外の変更の公開し直しのほかに、エージェントの公開鍵の変更でも起き、鍵の変更は恒久トークンの持ち主が起こせる(6.1 節)。その回数を 5.2 節の鍵の変更の頻度の上限で抑えるので、この差は許容する

### 7a.5 Resource Guard

`AdmissionPolicy` と `Resource Guard` は別の subsystem である。前者は利用者が設定するルールの意味を表し、後者は wgft 自身と OS の資源を守る。送信元 IP ごとの同時フロー数の上限(`WGFT_MAX_*_FLOWS_PER_SOURCE`)は前者に属する。1 つの送信元が wgft の公開しているサービスを独占しないための、利用者向けの通信方針だからである。

```
AdmissionPolicy
  送信元ごとの同時フロー数の上限(WGFT_MAX_*_FLOWS_PER_SOURCE)
    kernel: flows_tcp/flows_udp の set + ct count
    userspace: Go の評価器(internal/policy/goengine)

Resource Guard
  プロセス全体のフロー予算(WGFT_MAX_*_FLOWS)
  メモリのソフト上限(GC の目標。GOMEMLIMIT が優先)
  ルールごとの隔離
  kernel の conntrack・システムの予算
```

以前の `flowcap.Limits` は、送信元ごとの上限(Admission Policy)とプロセス全体の予算(Resource Guard)という別の関心事を 1 つの型に混ぜていた。Phase 6 の移行の手順 1 で、`policy.AdmissionLimits`(送信元ごとの上限)と `resource.Limits`(プロセス全体の予算、ルールごとの隔離)に分けた。

userspace 側の Resource Guard の予算は次のとおりである。

- プロセス全体の TCP/UDP 予算:`WGFT_MAX_UDP_FLOWS`/`WGFT_MAX_TCP_FLOWS`(7 節)
- ルールごとの隔離:設定項目にはせず、プロセス全体の予算から導く内部の値とする。Phase 6 の移行の手順 4 で、1 本のルールなら空いている予算を使い切れ、複数のルールが競合するときだけ他ルールの最低限を守る、共有プールと隔離予約の方式に置き換えた(式と既定値は 7a.10 節)。以前の「プロセス全体の半分、ただし従来の固定値(UDP 4096、TCP 1024)を下回らない」という計算式と、その固定値の定数は削除した。隔離予約は、ルール 1 本の上限を残したまま、予算から予備を除いた値から求め直し、ルールの登録ごとの最低分と、次に加わる 1 つの登録のための予備の形に改めた(2026-09-29 と 2026-09-30 の所有者の決定。移行の手順 6)。最低分と予備は admission 時の請求であって保証ではない。既存のフローを公平化のために強制的に追い出すことはしない。新しいルールの最低分が既存のフローで既に埋まっている場合、その最低分は既存のフローが終わるまで満たされない
- メモリのソフト上限:予算から導く値をランタイムに設定する(`resource.Limits.MemoryLimit`)。GC の目標であり、メモリの使用量の上限ではない(7 節)
- 拒否した TCP の即時終了:accept 直後に RST で終える(`internal/nettun.TCPConn.Abort`)。通常の `Close` は gVisor の TIME_WAIT にエンドポイントを残し、上限を超えたフラッドの間ヒープが増え続けることを、生きているヒープの直接計測で確認している(ラボでの計測、2026-09-19)
- UDP の無通信タイムアウト:全体状態の `udp_timeout_stream` に従う(7 節)
- netstack の出力のキュー:gVisor と wireguard-go の間の深さ 1024 の FIFO 1 つで、満杯なら新しいパケットを捨て、送り出す側を待たせない(7 節)。設定項目にはしない。ルールごとの隔離はこのキューに及ばない
- IPv4 の断片の再組み立ての表:TUN の入口に置く固定の大きさの表で、満杯なら最も古い未完成の datagram を追い出す(7 節)。設定項目にはしない。ルールごとの隔離はこの表に及ばない
- UDP の受信の会計:Device の全ての UDP の endpoint の受信のキューを 1 つの予算で数え、endpoint 1 つにはその 1/4 の上限を置く。予約できない datagram は捨てる(7 節)。設定項目にはしない。ルールごとの隔離はこの予算に及ばない
- UDP の応答のバッファの枠:宛先からの応答を読むバッファをプロセス全体で同時に 64 個までしか貸さず、枠が無いセッションは空くまで待つ。`vpsd` の公開側のソケットの送信バッファが満杯の応答は待たずに捨てる(7 節)。設定項目にはしない。ルールごとの隔離はこの枠に及ばない

kernel 側の Resource Guard は、userspace の計算式を再利用しない。conntrack の表の大きさ、nftables の set の大きさ、カーネルのメモリ圧を基準にする。userspace の「プロセス全体の予算」や「ルールごとの隔離」に当たる概念を kernel は持たない。

Resource Guard に kernel と userspace で共通の Go interface は持たせない。kernel の資源保護は conntrack の表の大きさという OS 側の限界であり、Go の `Acquire`/`Release` に相当する呼び出し点を持たないためである。

### 7a.6 維持する外部仕様と互換性

内部の package、型、interface、DB のスキーマは互換を求めない。次の境界は外部仕様として維持する。

| 維持する外部仕様 | 維持の方法 |
|---|---|
| CLI のコマンドとフラグの意味 | 変えない。`cmd/wgft` は `admin.Client` と Options を介するだけなので、内部の再構成の影響を受けない |
| 文書化した `WGFT_*` | 変えない。`WGFT_MODE` は `DataplaneMode` の外部名として残す |
| 機械向けの CLI 出力 | 変えない |
| ルールの書き出しと読み込みの形式 | 変えない。`vps_mode`/`proxy_protocol` の値は、normalize 時に `Forwarding`/`SourceMetadata` へ写すアダプタを通すだけで、JSON の形は変わらない |
| admin API v1 | 既存のリクエストとレスポンスの意味は変えない。ルールごとの適用状態のような新しい情報は加算的にだけ追加する(7a.3 節) |
| join string と agent/server の通信 | 既存のメッセージの意味は変えず、版と機能の交渉を加算的なフィールドとして追加する(下記) |
| 既存のデータの置き場からの更新 | SQLite と状態ファイルは自動の migration で吸収する。旧版への戻しは保証に含めない(下記) |

wire protocol の版と機能の交渉は、既存のメッセージへ次のフィールドを追加するだけで足りる。

- agent が送る最初のメッセージ(`pubkey`)に、対応する版の範囲 `protocol_min` と `protocol_max`(整数)と、`capabilities`(文字列の配列)を追加する
- server が送る全体状態(`state`)に、その接続で選んだ版 `server_protocol_version`(整数)と `server_capabilities`(文字列の配列)を追加する

版の番号は 1 から始める。server は自分が対応する版の範囲と agent の範囲の共通部分を取り、その最大の版をその stream 接続の版として選ぶ(例:agent が 2 から 3、server が 1 から 2 なら 2、agent が 2 から 3、server が 2 から 3 なら 3)。共通部分が無ければ、server は双方の範囲を示すエラーで stream を断り、agent はそれをログに出す。`protocol_min`/`protocol_max` の片方だけがある宣言、または `protocol_min` が 1 未満か `protocol_max` を超える宣言(番号の付いた版は 1 から始まるため、どちらも版の範囲として意味を持たない)は、共通部分が無い場合とは別に malformed な advertisement として扱い、何が壊れているかを示すエラーで stream を断る。前者(共通部分が無い)は版を上げれば直る正常な状態、後者(malformed)は相手の実装の不具合という違いがあるため、agent が原因を区別できるよう、送る理由は別にする。agent は、返ってきた `server_protocol_version` が 1 以上の番号の付いた版であり、かつ自分の範囲に入っていることを確かめる。`server_protocol_version` は server が実装する最新の版ではなく、その接続で選んだ版である。全体状態は選んだ版のスキーマと意味だけで組み立てるため、1 通の `state` がどの版に属するかは曖昧にならない。同じルール集合でも stream 接続ごとに形を作り分けられるため、全体状態の形そのものを変える機能追加でも、旧い実装との互換を保ったまま進められる。`capabilities`/`server_capabilities` が空の配列なら「版はあるが追加の機能は無い」を表す。

版のフィールドを持たない実装(今の実装)は、legacy v0 として別に扱う。agent の `pubkey` に `protocol_min`/`protocol_max` が無ければ、その agent は legacy v0 にしか対応しないとみなし、server は今の形の全体状態を送る。server の `state` に `server_protocol_version` が無ければ、agent はその server を legacy v0 とみなし、今の機能だけを使う。Go の `encoding/json` は構造体に無いフィールドを無視するので、旧い側は新しいフィールドを読み飛ばすだけで済み、専用のネゴシエーションのラウンドトリップは要らない。

どこまで旧い実装を支えるかは、製品の版ではなく版の番号で決める。server と agent は、番号の付いた版のうち現在の版と直前の版の 2 つを必ず支える。これにより、通常の rolling upgrade(server と agent のどちらを先に上げても)が通る。legacy v0 はこの版の履歴に含めない特例で、server と agent の双方が v1.0.x の間は必ず支え、v1.1 以降は落としてよい。capability を追加しただけでは版を上げない。既存の版で意味を後方互換に表せなくなったときだけ上げる。旧い実装が新しい機能を表せない場合は、黙って旧い挙動へ downgrade せず、そのルールを理由付きの `not_active`(例:`agent does not support capability X`)にする。通信方針はどの agent の版でも同じ意味を持つべきだからである(7a.1 節の原則 1)。

`capabilities`/`server_capabilities` の語彙(将来の差分配信、複数エージェントへの振り分けなど、どの機能をどの文字列で表すか)は、その機能を追加する時点で個別に定める。

対応する版の範囲と、接続の版は、性質の異なる値である。利用者向けの出力ではこの 2 つを区別する。`wgft version` は、実行したバイナリに組み込まれた、対応する版の範囲(`proto.SupportedProtocol` の Min と Max)を出す。この範囲が指すのは番号の付いた版だけであり、版のフィールドを持たない legacy v0 の相手は含まない。server は legacy v0 の agent を v1.0.x の間はこの範囲に関わらず別に受け入れるため(上記)、範囲の外だからといって legacy v0 の相手と繋がらないとは限らない。値はディスク上のそのバイナリに組み込まれた静的な値であり、動いている server のプロセスの範囲を読み取るものではない。VPS で実行した場合でも、バイナリを置き換えてから server のプロセスを再起動するまでの間は、動いている server の範囲と一致しないことがある。rolling upgrade はまさにこの不一致が生じる区間であり、両者の違いが意味を持つ場面でもある。

`wgft agent ls` は、そのエージェントとの接続の版を出す。値は 3 通りに分かれる。`protocol_min`/`protocol_max` に共通部分があり `SelectProtocolVersion` が版を選んだ接続は、選んだ版(`vN`)を出す。agent が legacy v0 として扱われた接続(`SelectProtocolVersion` を呼ばずに決まる。上記)は `legacy` を出す。どちらでもない場合、つまりエージェントが切断している間と、接続中でも相手が `protocol_version`/`agent_protocol_legacy` を返さない旧い server である場合は、`-` を出す。切断している間に最後に選んだ版を今の値として出さないのは、5.2 節が stream の切断後もエージェントの最後の報告を残しつつ、それを今の状態として描くことを禁じているのと同じ理由による。`wgft version` が出す範囲と、`wgft agent ls` が出す 3 つの値では、表示の文言を揃えない。範囲か、選んだ版か、legacy か、不明かのどれであるかが分かる語を使う。番号の付いた版は 1 から始まり legacy v0 とは別の値なので、旧い server との接続を `v0` とは表さない。

更新の経路は保証する。旧版への戻しは互換性の保証に含めず、各版で観測した挙動だけを記録する。戻す必要があるときは、更新の前に取ったデータの置き場のバックアップから戻す。戻しを約束すると、SQLite のスキーマ、migration、知らないフィールドの保存、状態ファイル、wire protocol の変更を、旧い版が読める形に永久に縛ることになるためである。wire protocol の直前の版との互換は、上記の rolling upgrade のために別に支えるもので、データの置き場を旧い版へ戻せることは意味しない。

外部の表現が新しいモデルと根本から矛盾する例は、今のところ見つかっていない。`vps_mode`、`proxy_protocol` を含め、既存の外部表現はすべて内部モデルへ写せている。今後そのような矛盾が見つかった場合は、旧い形式を読めるアダプタを用意したうえで新しい形式を正とする、という規則を適用する。

### 7a.7 package 配置

目標とする配置は次のとおりである。

```
internal/
  model/                 Rule、Forwarding、SourceMetadata、proto.Rule との写像(FromProto/ToProto)
  policy/                AdmissionPolicy(IR)
  policy/nftables/       IR から nftables の行の列へのコンパイラ(google/nftables を import しない。7a.9 節)
  policy/goengine/       IR から Go の評価器へのコンパイラ
  planner/               Planner、Plan
  resource/              Resource Guard(予算、カウンタ)
  lograte/               同じ理由で繰り返すログを間引く門(7a.10 節)と、名前の解決の誤りの文面をそろえる関数(5.2 節)
  startup/               起動の拒否の型と種別(11b 節)
  textsafe/              信頼できない文字列を端末向けに無害化する関数(11 節)
  reasontext/            ルールの理由の文言のうち、理由を書く側と server doctor が共有する断片(10.2a 節)
  reconcile/             Observe -> diff -> Prepare -> Commit の骨格(今は server が使う。agent は変更の通知の購読の張り直しと公開し直しの間隔だけを使い、移行は後の段階)
  dataplane/             Backend interface(Observe、Prepare、Commit、Rollback)
  dataplane/userspace/   wireguard-go + netstack + 中継
  dataplane/linuxkernel/ カーネルの WireGuard、nftables、conntrack、所有判定
  platform/linux/        sysctl、capability、他ファイアウォールとの衝突の検査
  vpsd/                  制御プレーン(登録、stream、SQLite、admin API)。proxyrelay が frontend の participant を実装する(下記)
  vpsd/servercheck/      `wgft server check`。internal/vpsd の下位の package のうち store だけを import する(下記)
  vpsd/teardown/         `wgft server teardown`。internal/vpsd の下位の package のうち store だけを import する(下記)
  vpsd/tailnet/          --admin-tailscale の待ち受け(11 節)。internal/vpsd のどの package も import しない(下記)
  agent/                 制御プレーン(認証情報、stream クライアント、rotate-key)と、2 つのモードの選択(下記)
  agent/credentials/     認証情報ファイル(agent.json)、そのロック、停止中に CLI が認証情報ファイルを書くための排他(9 節)
  agent/allowtargets/    エージェントが接続してよい宛先の一覧(7 節)
  agent/teardown/        wgft agent teardown の判定と順序、撤去のカーネル操作(10.3 節)。実行時の状態に依存しない
  agent/controlapi/      制御ソケットの wire の型と定数(proto と resource だけを import する葉。下記)
  agent/control/         制御ソケットのサーバと、エージェントのホストで動く CLI の側(rotate-key、agent pubkey)。実行時の状態は Backend の後ろに置き、internal/agent の下では controlapi と credentials だけを import する(下記)
  agent/agentdp/         エージェントの dataplane の境目(Dataplane と任意の interface、1 回の読み取りの型、起動の失敗の型)。internal/agent の下では controlapi だけを import する(下記)
  agent/usermode/        ユーザー空間モードの dataplane。wireguard-go と netstack のトンネルと中継を包む。internal/agent の下では agentdp と allowtargets だけを import する(下記)
  agent/kernelmode/      カーネルモードの dataplane と、停止中の agent doctor が使うカーネルの読み取り。internal/agent の下では agentdp、allowtargets、credentials、controlapi だけを import し、usermode を import しない(下記)
  agent/enroll/          登録のクライアントの側(接続文字列の解釈、ピン留めした登録 API の呼び出し、登録の結果の認証情報への記録)
proto/                   維持する外部仕様としての wire スキーマ(既存フィールドの意味は変えず、加算のみ許す)
```

`platform/windows/`、`platform/darwin/` は、Windows・macOS の agent(13 節)に着手するときに設ける。今は `platform/linux/` だけがあり、目標の木には含めない。

依存の向きは一方向である。`model`、`policy`、`planner`、`resource` は OS、nftables、gVisor を知らない純粋な Go の型と関数だけを持ち、`dataplane/*`、`platform/*` を一切 import しない。`reconcile` は `planner` の `Plan` と、`Runtime` を組み立てる participant の interface(dataplane の `Backend`、frontend の `Frontend`/`FrontendPrepared`)だけを持ち、`dataplane/userspace`・`dataplane/linuxkernel` にも、frontend の実装にも依存しない。`dataplane/*` は `model`、`policy`、`planner`、`resource`、`platform/*` を import できるが、互いには依存しない。`planner` を含めるのは、`Backend` が収束先を `Plan` と実行時の入力(frontend が待ち受けているポートの集合など)だけから受け取り、設定やルール集合を別の経路から読まないためである。`Relay` の listener 集合という frontend 側の資源には独立した package を置かない。server では `internal/vpsd/proxyrelay` が `Prepare`/`Commit`/`Rollback` を持ち、`internal/vpsd` がそれを `reconcile.Frontend`/`FrontendPrepared` へ橋渡しする(7a.2 節)。`vpsd` と `agent` は上記すべてを import できる唯一の層である。`vpsd` は起動時に dataplane と frontend の実装から `Runtime` を組み立て、`reconcile` に渡す。この向きにより `internal/dataplane/linuxkernel` が `internal/vpsd` に依存しない構造になり、agent のカーネルモード(7b 節)が server の kernel backend の共通の部品(WireGuard、host 側の検査、nftables と conntrack の基本操作)を再利用できる。VPS 用の table(公開ポートから agent への DNAT)とその収束は server に固有で、agent には LAN の宛先への DNAT、MASQUERADE、agent 側の conntrack 収束という別の経路を同じ package に足す。

`internal/vpsd` の根には、実行時の状態を持つ `Daemon` と、下位の package が定める `Backend` の実装と、起動の配線を置く。`Daemon` に依存しない機能は下位の package に置く。`internal/vpsd/servercheck` は `wgft server check`(6.1・10.3・11a 節)を持つ。このコマンドは server を起動せずにサーバのデータベースを読むだけなので、`internal/vpsd` の下位の package のうち `store` だけを import する。`internal/dataplane/deps_test.go` の `TestVpsdServerCheckImportsOnlyTheStore` がこれを検査する。`internal/vpsd/teardown` は `wgft server teardown`(10.3 節)と、その手掛かりを起動時に記録する関数を持つ。撤去は停止した server の後片付けとしてサーバのデータベースを読むので、`internal/vpsd` の下位の package のうち `store` だけを import する。`internal/dataplane/deps_test.go` の `TestVpsdTeardownImportsOnlyTheStore` がこれを検査する。`internal/vpsd/tailnet` は `--admin-tailscale` の待ち受け(11 節)を持つ。この package は管理用 API の応答と、Host の検査で許す名前の更新を関数の値として受け取るので、`internal/vpsd` のどの package も import しない。`internal/dataplane/deps_test.go` の `TestVpsdTailnetImportsNoServerPackage` がこれを検査する。

agent は `reconcile.Runtime`、`dataplane.Backend`、`planner.Plan` をまだ使わない。`internal/agent` は userspace のトンネル(`internal/dataplane/userspace/tunnel`)と中継(`internal/dataplane/userspace/relay`)を直接駆動し、全体状態(`proto.AgentRule` を含む)を自分で収束させる。v1.2 はこの形を保ったまま、`internal/agent` の中に狭い dataplane の境目を切り、その後ろにユーザー空間モードとカーネルモードの 2 つの実装を置く(2026-09-24、所有者の決定)。ユーザー空間モードの実装は今のトンネルと中継をそのまま包み、カーネルモードの実装は `internal/dataplane/linuxkernel` の部品から組み立てる。agent 全体を `Runtime` へ移してからカーネルモードを足す案は採らなかった。移行はトンネルの作り直し(7 節)、全体状態の適用の試し直し、`agent doctor`(10.2c 節)の経路を巻き込み、カーネルモードを加えるという目的より大きいためである。agent を `Runtime` へ移すのは後の段階とする。

この境目は依存の向きの規則を変えない。カーネルモードのために加える部品は `internal/dataplane/linuxkernel` の下に置き、`internal/agent` を import しない。`internal/dataplane/deps_test.go` の `TestDependencyDirection`、`TestPureLayersStayPure`、`TestVpsdSubpackagesDoNotImportVpsd`、`TestPolicyNftablesDoesNotImportGoogleNftables` は変えずに、この配置を検査する。

境目は `internal/agent/agentdp` の interface `Dataplane` である。ユーザー空間モードの実装は `internal/agent/usermode` の `Dataplane` であり、カーネルモードの実装は `internal/agent/kernelmode` の `Dataplane` である。境目の後ろの実装が持つのは、トンネルを立てることと閉じること、ルールの宣言への収束、30 秒ごとの見直し、watchdog が読む最終ハンドシェイク、ハートビートと `agent doctor` が共有する 1 回の読み取りである。処理済み世代と `last_state` の記録、トンネルの作成の試し直しの予定、トンネルを作り直すかどうかの判定は、境目の手前の実行時の状態に残す。ルールの収束は、宣言をまとめて公開できなかった backend 全体の失敗(7b.3 節の 3 つ目の種類)を誤りとして返し、このとき処理済み世代は進まない。ルール単位の失敗は誤りにせず、ルールごとの状態として読み取りに載せる。

カーネルモードの実装だけが持つ処理は、`internal/agent/agentdp` の任意の interface に置く。全体状態の適用の前の名前の解決、wg 設定の検証、30 秒ごとの見直し、変更の通知の購読、起動時の所有の判定、`agent doctor` のためのカーネルの読み取りである。実行時の状態は任意の interface を型アサーションで探し、満たさない実装ではその処理を飛ばす。メソッドの形がずれても黙って飛ばされないよう、カーネルモードの実装がそれぞれの interface を満たすことをコンパイル時に検査する。`agentdp` は実行時の状態と 2 つのモードの実装の両方から import されるので、それらより下に置く。モジュールの中から直接 import するのは、`proto`、`internal/resource`、`internal/dataplane`、読み取りの型が載せる中継とソケットのバッファの型の package(`internal/dataplane/userspace/relay`、`internal/dataplane/userspace/sockbuf`)、カーネルの読み取りの型を持つ `internal/agent/controlapi` だけである。`internal/agent` とその他の下位の package、`internal/dataplane/linuxkernel` には推移的にも依存しない。`internal/dataplane/deps_test.go` の `TestAgentDataplaneBoundaryImports` がこの規則を検査する。

`internal/agent/usermode` はユーザー空間モードの実装を持ち、wireguard-go と netstack のトンネル(`internal/dataplane/userspace/tunnel`)と、その上の中継(`internal/dataplane/userspace/relay`)を包む。`internal/agent` の下で import するのは `agentdp` と `allowtargets` だけである。`internal/agent` 自身、`internal/agent/kernelmode`、`internal/dataplane/linuxkernel` には推移的にも依存しない。

`internal/agent/kernelmode` はカーネルモードの実装を持ち、`internal/dataplane/linuxkernel` の部品でカーネルの WireGuard インタフェースと `table inet wgft_agent` を宣言へ収束させる。停止中の `agent doctor` が読むカーネルの読み取り(`ReadKernel`)も同じ package にあり、稼働中のエージェントの読み取りと同じ関数を使う。`internal/agent` の下で import するのは `agentdp`、`allowtargets`、`credentials`、`controlapi` だけである。`internal/agent` 自身、`internal/agent/usermode`、`internal/vpsd` とその下位の package には推移的にも依存しない。`internal/dataplane/userspace` とその下位の package は直接 import しない。読み取りの型が載せる中継とソケットのバッファの型の package には、`agentdp` を通して推移的に依存する。`internal/agent` 自身は `internal/dataplane/linuxkernel` とその下位の package を直接 import しない。この 2 つの規則の検査は直接の import だけを見る。ほかの package を通した推移的な依存は検査の外である。例えば、カーネルの層を import する `internal/agent/teardown` を `internal/agent` の本番のファイルが import しても、この検査は落ちない。

この節の 2 つのモードの規則は本番のファイルに当てはめ、テストのファイルには当てはめない。カーネルモードのテストは、エージェントが書く理由の文言を server doctor に読ませて確かめるために、`internal/vpsd/doctor` などを import する。`internal/dataplane/deps_test.go` の `TestAgentModesStayApart` が、2 つのモードの package と `internal/agent` 自身の import をテスト以外のファイルから読み、これらの規則を検査する。

Go には、package をまたいでテストにだけ名前を見せる仕組みが無い。`internal/agent` のテストがユーザー空間モードの実装の中身を読み書きできるよう、`usermode` はトンネルと中継のフィールド、宛先の許可一覧とフロー予算のフィールド、トンネルの作成と状態の読み取りの差し替え口、ルールごとの状態の合成、中継の調整値の組み立てを公開する。これらはテストのための口であり、本番のコードが `usermode` の外から使ってよいのは作成の関数 `New` だけである。`kernelmode` も同じ理由で、dataplane の型とそのフィールドの一部、wgft0 の宣言を返すメソッド、カーネルと名前解決への操作の差し替え口とその型、カーネルの読み取りの操作の差し替え口とその型、収束が済んでいない前の公開を残す数の上限を公開する。本番のコードが `kernelmode` の外から使ってよいのは、作成の関数 `New`、このビルドがカーネルモードを持つかどうか(`Built`)、ホストの前提の検査(`Prerequisites`)、このプロセスが `CAP_NET_ADMIN` を持つかどうかの読み取り(`ProcessNetAdmin`)、カーネルの読み取り(`ReadKernel`)だけである。`internal/agent/control`(下記)も同じ理由で、接続を 1 つ処理する関数 `ServeConn` を `internal/agent` のテストのために公開する。本番のコードが `control` の外から使ってよいのは、制御ソケットを開いて指示を受ける関数 `Serve`、実行時の状態の interface `Backend`、CLI の側の `RotateKey` と `PublicKey` だけである。本番のコードが使ってよい名前とテストのための口は、`internal/dataplane/deps_test.go` の `modeSeams` と `modeTestSeams` に、モードの package と `control` の package ごとに列挙する。これらの package が公開する名前は、`agentdp` の interface を満たすメソッドを除いて、どちらか一方だけに載せる。公開した interface の型のメソッド(`Backend` のメソッド)は、どちらの一覧にも載せない。`Backend` を満たすメソッドは実装の側の型が持つためである。本番のコードが package の外から interface の型を通じてそのメソッドを使うことは許さず、同じ検査が、テストのための口とは別の文言で落ちる。同じファイルの `TestAgentModeTestSeamsStayInTests` が、これらの package を import するモジュールの中の package の本番のファイルを型検査し、この規則を検査する。

`internal/agent` の下位の package は `internal/agent` を import しない。実行時の状態を持つ `internal/agent` が下位の package を使う向きだけを許し、`wgft agent teardown` のような 1 回限りのコマンドを実行時の状態から切り離すためである。`internal/vpsd` の下位の package と同じ規則であり、`internal/dataplane/deps_test.go` の `TestAgentSubpackagesDoNotImportAgent` が検査する。

制御ソケット(9 節、10.2c 節)の wire の型と定数は `internal/agent/controlapi` に置く。`doctor` の要求と応答の型、応答に載せる 1 つの文字列の長さの上限、応答が載せるカーネルモードの読み取りの型と列挙の値、ソケットのパスの規則と長さの上限、応答の 1 行の読み取りとその大きさの上限、読み手が照らし合わせるトンネルの理由の文字列が含まれる。応答を組み立てる処理は `internal/agent` に残り、制御ソケットのサーバと、エージェントのホストで動く CLI の側(`rotate-key` と `agent pubkey`)は `internal/agent/control` に置く。サーバは実行時の状態を `control.Backend` を通じて呼び、`internal/agent` がそれを実装する。`cmd/wgft` の `agent doctor` は、稼働中のエージェントの実装に依存せずに応答の形を読む。server の `internal/vpsd/adminapi`(管理用 API の読み取りの型。10.2d 節)と同じ位置づけの葉である。モジュールの中から、`adminapi` は `proto` だけを、`controlapi` は `proto` と `internal/resource` だけを import する。`controlapi` が `internal/resource` を import するのは、フロー予算の拒否の理由が `resource.Reason` の型を持つためである。`internal/resource` 自身はモジュールの中を何も import しない。`internal/dataplane/deps_test.go` の `TestWireShapesStayLeaf` がこの規則を検査する。

`internal/agent/control` が `internal/agent` の下で import するのは `controlapi` と `credentials` だけである。`internal/agent` 自身、`internal/agent/agentdp`、`internal/agent/usermode`、`internal/agent/kernelmode`、`internal/dataplane` とその下位の package には推移的にも依存しない。この規則も本番のファイルだけに当てはめる。`internal/dataplane/deps_test.go` の `TestAgentControlImportsNoRuntimeOrMode` が、`control` の import をテスト以外のファイルから読み、この規則を検査する。

`internal/agent/enroll` は登録のクライアントの側を持ち、`internal/agent` の初回の登録と登録のし直しの両方が使う。`cmd/wgft` も、`agent run` の起動時に接続文字列の形を確かめて警告するために `internal/agent/enroll` を直接使う。

`internal/startup` は、この向きの例外ではなく葉である。モジュールの中の何も import せず、`cmd/wgft` から `internal/dataplane/linuxkernel/wg` までのどの層も import できる。起動の拒否は、値を受け取る入口と、カーネルに書き込む層の両方が作るので、どちらからも見える場所に置く必要がある。`internal/resource` と `internal/lograte` と同じ扱いであり、`internal/dataplane/deps_test.go` がモジュールの中を import しないことを検査する。`internal/textsafe`(信頼できない文字列の無害化。11 節)も同じ理由で葉に置く。`cmd/wgft`、`internal/agent`、`internal/vpsd/stream` のように、エージェントが選ぶ文字列を端末へ出す層すべてから見える必要があるためである(2026-09-25、所有者の決定)。

`internal/reasontext` も葉である。ルールの理由の文言のうち、理由を書く側と、それを部分一致で読む `server doctor`(10.2a 節)の両方が使う断片を持つ。書く側は、エージェント(`internal/agent`、`internal/dataplane/linuxkernel/nft`、`internal/dataplane/userspace/relay`)と、ルールを公開しなかった server(`internal/vpsd`、`internal/vpsd/proxyrelay`、中継の `Prepare`)である。dataplane の実装と 2 つの制御プレーンのどこからも見える必要があるので、葉に置く。エージェントの宛先の許可一覧の設定の名前も拒否の理由に入るので、この package に置き、`internal/agent/allowtargets` はその値を使う。`internal/dataplane/deps_test.go` の `TestPureLayersStayPure` が、この package がモジュールの中を import しないことを検査する。

2 つの制御プレーンは互いを import しない。`internal/vpsd` の下のどの package も `internal/agent` の下の package に依存せず、その逆も無い。両側が共有するものは、`internal/reasontext` のような下の層に置く。`internal/dataplane/deps_test.go` の `TestControlPlanesDoNotImportEachOther` がこれを検査する。

`internal/flowcap` は、Phase 6 の移行の手順 1 で `internal/resource` に改めた。送信元ごとの上限を `internal/policy` の `AdmissionLimits` へ、上限で拒んだログを間引く門を `internal/lograte` へ移し、`internal/resource` には Resource Guard の予算だけを残した(7a.10 節)。

`frontend` の package の分け方(7a.9 節の未決事項だった)は、分けないことで決着した。kernel backend 側の `Transparent` は nftables の DNAT だけで完結して独立したコードを持たず、`Relay` の listener 集合は server に固有で(wg 越しに agent へ dial する)`internal/vpsd/proxyrelay` に残る。agent 側の userspace の中継は `internal/dataplane/userspace/relay` に既にある。独立した `frontend` package を作っても、動かすコードが無い。

### 7a.8 移行の段取り

各段階は、今のラボの結合テスト(`lab/e2e.sh`、rate、connlimit、split-merge、import-export)と、策定中の lifecycle テスト(再起動中の転送継続、無関係なフローを切らないこと、proxy の bind 失敗が nftables に漏れないこと、teardown が wgft の物だけを消すこと、上限到達時の RSS がソフト上限と余裕の和の内側にあること)を、その段階の終わりに通すことを共通の完了条件とする。どのテストをどの変更と時点で流すか(コードを変える PR ではマージの前にラボの一式を流すことを含む)は [docs/testing.md](testing.md) に定める。以下は各段階に固有の完了条件だけを示す。

- **Phase 1(model/policy/plan)**:既存の Rule と State を内部モデルへ normalize し(外部形式からのアダプタを含む)、`AdmissionPolicy` の IR、`Plan`、`Planner` を作る。dataplane の挙動は変えない。完了条件:純粋な単体テストが model/policy/planner を対象とし、生成される nftables の内容と userspace の転送挙動が変更前と一致する
- **wire protocol の版と機能の交渉**:全体状態の形を変える前に入れる。完了条件:旧 agent と新 server、新 agent と旧 server の組み合わせで、通常の rolling upgrade がラボで通る
- **Phase 2(userspace backend 化)**:userspace の中継と proxy を `Backend` の後ろへ移す。完了条件:挙動を変えず、基準のテストを通す
- **Phase 3(VPS kernel backend 化)**:WireGuard、nftables、conntrack、sysctl、所有判定を `internal/vpsd` から `internal/dataplane/linuxkernel` へ切り離す。完了条件:`internal/dataplane/linuxkernel` から `internal/vpsd` への import が無いことをビルドで確かめられ、停止時に残し起動時に収束する今の挙動を保つ
- **Phase 4(トランザクショナルな収束)**:`Desired`/`Prepared`/`Active`/`Retiring`、`Prepare`/`Commit`/`Rollback`(7a.3 節の範囲)、世代、失敗からの回復、再起動時の収束を導入する。ルール単位の fail-closed は、nftables の全体差し替え(6.1 節)にそのルールの新しい dispatch を含めないことで実現し、差し替え中のルールだけを部分的に書き換える仕組みは作らない。完了条件:backend 全体に及ぶ失敗が `Active` 世代を進めないこと、ルール単位の prepare 失敗はそのルールだけを理由付きの `not_active` のまま見えるようにし、他のルールの `Active` 化と世代の前進を妨げないこと、置き換えに失敗したルールが他のルールの commit 後に新規フローを拒むこと(fail-closed)、`Desired` に無いのに残っている資源が `active_only`/`retiring` として見えること、`Relay` のルールを fail-closed にしても安全な成立済みの TCP 接続が残ることを、新設の lifecycle テストで確かめる
- **Phase 5(共通の Admission Policy)**:nftables コンパイラと Go の評価器を 1 つの IR から作る形に統合し、4 か所に分かれていた許可拒否の判定(`internal/dataplane/linuxkernel/nft`、`internal/dataplane/userspace/srcpolicy`、`internal/dataplane/linuxkernel/conntrack` の `sourceAllowed`、`internal/vpsd/proxyrelay` の `sourceAllowed`)を IR と 2 つのコンパイラへ集約する。kernel dataplane では `Transparent` と `Relay` の分岐より前に共通の ingress 層を置く。IR の形、各コンパイラの約束、許容差、fixture、移行の手順は 7a.9 節に定める。完了条件:同じ入力に対して両コンパイラが 7a.4 節と 7a.9 節の許容差の範囲内で一致することを共有 fixture で確かめ、既存の connlimit などのラボテストを保つ
- **Phase 6(Resource Guard の再設計)**:`flowcap.Limits` が混ぜている送信元ごとの上限(Admission Policy)とプロセス全体の予算(Resource Guard)を `AdmissionLimits` と `ResourceLimits` に分ける。ルールごとの隔離を、共有プールと隔離予約の方式に置き換える。隔離予約は admission 時の予約であり、既存のフローを追い出す保証ではない。kernel 側の保護(conntrack の表、set の大きさ)は、userspace の計算式を再利用しない形のまま整理する。型、式、拒否の報告、移行の手順は 7a.10 節に定める。完了条件:1 本のルールなら空いている予算をほぼ使い切れ、複数のルールが競合するときだけ他ルールの最低限を守り、既存のフローを公平化のために切らないことを、ラボで確かめる
- **Phase 7(agent の kernel dataplane、v1.2)**:Linux のエージェントのカーネルモード(7b 節)を、`internal/dataplane/linuxkernel` の共通の部品を再利用し、agent に固有の nftables と conntrack の経路を同じ package に足す形で追加する。agent は `Runtime` へ移さず、`internal/agent` の中に切った dataplane の境目の後ろに置く(7a.7 節)。ラボで手作業で組んだ検証(2026-09-19)から、範囲のルールは無名 map の DNAT で表すこと、`DynamicUser` と `CAP_NET_ADMIN` のサンドボックスで足りること(`ProtectKernelTunables` は `ip_forward` の書き込みを妨げるため付けないこと)、実物の Docker の `DOCKER-USER` への追加行が Docker の再起動をまたいで残ること、複数 LAN セグメントを持つ自宅では `rp_filter` の strict が転送を壊しうること(`conf.all` と個別インタフェースの値は、より厳しい方が勝つ)が分かっている。agent の kernel dataplane をラボで試作した結果(2026-09-19)からは、agent の停止中も既存と新規のフローが続くこと、変更の無い再起動で conntrack が保たれること、マシンの再起動の後に保存した状態から stream に接続する前に組み直せること、LAN の target に設定変更が要らず MASQUERADE が要ることが分かっている。同じ試作で、自宅側に conntrack の収束が要ること(7a.3 節)、agent は `ip_forward` を明示して設定する必要があること、userspace と kernel の切り替えには約 1 から 2 秒の断があることも分かった。v1.2 の設計の前のラボ(2026-09-23)では、範囲のずらしを表す無名の連結 map の DNAT を google/nftables で組めること、非 root で `CAP_NET_ADMIN` だけを持つプロセスが WireGuard、nftables、conntrack、`ip_forward` のすべてを操作できること、非特権の LXC の中でも同じ操作ができることを確かめた(改訂の記録 2026-09-24)。決定と外部から見える面は 7b 節に定め、完了条件の細部は各段の実装がその節に書く
