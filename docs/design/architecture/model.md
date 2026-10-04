<a id="7a-内部アーキテクチャ"></a>
## 内部アーキテクチャ

通信方針は backend 間で同じ意味を持ち、資源の保護は backend ごとに実装します。
SQLite の宣言は、適用に成功するまで転送面の Active 状態として公開しません。


内部の package、型、interface と DB スキーマは、公開サーフェスとは別の実装の境界です。
内部の互換性は保証せず、公開の通信と転送の仕様はサーフェスごとの保証に従います ([7a.11 節](../compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧))。

<a id="7a1-原則と優先順位"></a>
### 原則と優先順位

内部アーキテクチャは、次の 3 つの原則に従います。

1. 通信方針はグローバルです。
   送信元の許可と拒否、送信元ごとの新規フローのレート、ルール全体の新規フローレートとパケットレート、送信元ごとの同時フロー数の上限は、kernel dataplane、userspace dataplane、proxy frontend のどれで実装しても同じ意味を持ちます
2. 資源の保護はローカルです。
   Go のヒープと gVisor の状態量の上限、userspace の TCP・UDP フロー予算、ルール間の資源隔離、カーネルの conntrack 資源の保護は、backend ごとに異なる実装で構わない
3. 状態の変更はトランザクショナルです。
   SQLite に保存しただけのルールを、nftables や listener へ無条件に active として公開しません

判断に迷う場面の優先順位は次のとおりで、上位が下位に優先します。

1. 誤った通信を許可・遮断しません
2. 既存の通信を不用意に切らない
3. 部分的な失敗から安全に回復できます
4. 再起動やクラッシュのあと、宣言した状態へ収束できます
5. 通信方針の意味が backend に依存しません
6. backend 固有の資源保護を適切に行います
7. コード量
8. 内部 API との互換性

<a id="7a2-層と責務"></a>
### 層と責務

ドメインモデルは backend の実装詳細を持ちません。
`Rule` は ID、プロトコル、待ち受けポート、宛先、所属エージェントだけを持ち、転送方式は別の型で表します。

- `Forwarding`:転送の意味を選ぶ。
  `Transparent`(素通し。
  今の `vps_mode=kernel`)と `Relay`(`vpsd` 自身が TCP を終端して中継します。
  今の `vps_mode=proxy`)の 2 値を持ちます。
  server・agent 全体の転送方式(今の `WGFT_MODE`。
  `internal/vpsd/store` が持つ `ModeKernel`/`ModeUserspace` の文字列の語彙であり、この層の型ではない)ともう一方の軸であり、これと紛れる「kernel」という語を、ルール単位の選択には使いません
- `SourceMetadata`:送信元の情報を付けるかどうかを選ぶ。
  `None`(付けない)と `ProxyV2`(PROXY protocol v2 ヘッダを付ける。
  今の `proxy_protocol=true`)の 2 値を持ちます。
  `Transparent` と組み合わせられるのは `None` だけで、`Transparent` + `ProxyV2` は無効な組み合わせである(今の `proxy_protocol` が `vps_mode=proxy` でしか立てられない制約のまま)。
  `vps_mode=proxy` と `proxy_protocol` は別の軸なので、`Forwarding` と `SourceMetadata` も別の型にします

外部の表現(rule import/export の JSON、CLI のフラグ、admin API のリクエスト)は変えません。
`vps_mode` フィールドの値 `kernel`/`proxy` は、normalize 時に `Forwarding` の `Transparent`/`Relay` へ写す。
`proxy_protocol` フィールドは `SourceMetadata` の `None`/`ProxyV2` へ写す。
書き出し時はどちらも元のフィールドへ戻します。
この写像は、維持する外部仕様である `proto.Rule` と内部モデルの `Rule` の間のアダプタが持ちます。

normalize/validate は、外部の `Rule` を受け取り、構造的な検査(ポート範囲の重なり、予約ポート、`proxy_protocol` は `Forwarding=Relay` でしか立てられない、など)をしたうえで内部モデルへ写す。
今の `proto.ValidateRules`/`ValidateUpsert`/`UnchangedIDs` が持つ「変更のない行を検査し直さない」規則は、この層に引き継ぐ。

`AdmissionPolicy` は、送信元の許可拒否、送信元ごとの新規フローレート、ルール全体の新規フローレートとパケットレート、送信元ごとの同時フロー数の上限をまとめた中間表現です。
kernel の nftables 式、userspace の Go の評価器は、どちらもこの IR から作る。
評価順(拒否、許可、送信元ごとの上限、送信元ごとの同時フロー数の上限、集約の新規フローレート、集約のパケットレート。
今の [6.1 節](../vps/kernel.md#61-カーネルモード)の順序をそのまま踏襲する)は、IR の一部として 1 か所にだけ書きます。

`Planner` は、normalize したルール集合と `AdmissionPolicy` から `Plan` を組み立てる。
OS、nftables、gVisor の実装詳細を知らない。
`Plan` は、宣言した世代番号、送信元制限を含む ingress の計画、宛先までの経路の集合、WireGuard のピア集合を持つ、backend に依存しないデータです。

`Backend`(kernel/userspace の dataplane)と、Observe/Prepare/Commit/Rollback を持つ transaction の参加者(participant)は別の概念です。
`Backend` はその 1 つの participant だが、`Relay` の listener 集合のような frontend 側の資源も、同じ Observe/Prepare/Commit/Rollback を持つ participant になりうる。
`internal/vpsd/proxyrelay` の `Prepare`/`Commit`/`Rollback` が、この形の実例として既にあります。

`Runtime` は、participant を固定の順序で束ねた実行単位です。
server の `Runtime` は frontend の資源(`Relay` の listener)と dataplane の `Backend` から組み立て、agent の `Runtime` も同じ 2 種類の participant から組み立てる(agent の frontend は空、または userspace の `Relay` の listener になる)。
ただし agent を `Runtime` へ移すのは後の段階であり、それまでの agent は `internal/agent` の中に切った dataplane の境目を使う([7a.7 節](packages.md#7a7-package-配置))。

`Reconciler` は `Backend` を直接動かさず、`Runtime` を動かす。
手順は次の固定順序です。

1. frontend を `Prepare` する(新しい listener を開く、など)。
   `Prepare` に失敗したルールは、dataplane へ渡す `Plan` から外す([7a.3 節](lifecycle.md#7a3-状態遷移と失敗の意味論)の fail-closed)
2. frontend の `Prepare` の結果(待ち受けているポートの集合)を、dataplane の `Prepare` への入力にします
3. dataplane を `Commit` する(公開します。
   kernel backend ではこれが nftables の 1 トランザクションである)
4. frontend を `Commit` する(中継を始める、消えた listener を閉じる)
5. 失敗すれば、`Prepare` した participant を逆順に `Rollback` します

この手順には、戻せる地点と戻せない地点があります。
失敗しうる処理(bind、名前解決、資源の確保、検査)はすべて `Prepare` に置く。
dataplane の `Commit` は不可分の公開であり、失敗すれば何も公開されず、frontend の `Prepare` を `Rollback` できます。
kernel backend には例外が 2 つあります。
commit の後の応答の受信に失敗した場合([6.1 節](../vps/kernel.md#61-カーネルモード)の受信側の壁)と、差し替えの後に読み直した送信元の一覧の set が送った要素を持たない場合([6.1 節](../vps/kernel.md#61-カーネルモード))は、テーブルが差し替わった後で誤りが返る。
dataplane の `Commit` が成功した時点が戻れない地点で、それ以降は `Rollback` しません。
そのため frontend の `Commit` は失敗してはならず、何度呼んでも同じ結果になるものにします。
中身は、`Prepare` で確保済みの資源を使い始めることと、消えたものを閉じることだけに限る。
戻れない地点の直後にプロセスが落ちた場合は、`Rollback` ではなく、再起動時の `Observe` が `Desired` との差分を見つけて収束させる([7a.3 節](lifecycle.md#7a3-状態遷移と失敗の意味論)の適用途中のクラッシュ)。

WireGuard のピアの変更、drop カウンタの読み出し、公開の後の収束も、同じトランザクションに含めます。
dataplane の `Prepare` は、新しく宣言されたピアを追加し(旧いピアはまだ残す)、kernel backend ではテーブルの差し替えを組み立てるところまでを行います。
dataplane の `Commit` は、差し替える前のテーブルの drop カウンタを読み、差し替えを公開し、宣言から消えたピアを削除し、conntrack(userspace backend ではセッション)を収束させる。
drop カウンタは公開が成功したときだけ制御プレーンへ渡す。
差し替えが失敗した場合は旧いテーブルがカウンタを持ち続け、次の成功した差し替えで 1 回だけ読まれるので、同じカウンタを二重に累積しません。
ピアの削除と収束は戻れない地点の後の処理なので、失敗しても `Commit` を失敗させず、ログに残し、[7a.3 節](lifecycle.md#7a3-状態遷移と失敗の意味論)の「戻れない地点の後の修復」で試し直す。
`Rollback` は、追加したピアを取り除き、元の集合に戻します。
起動時は、最初のトランザクションの前にインタフェースだけを立ち上げる(鍵、待ち受けポート、アドレス、MTU。
所有判定による中止もここで行う)。
ピアは最初のトランザクションで収束させる。

参加する participant の種類と順序は固定であり、汎用の 2 相コミットではありません。
Phase 2 より前の `internal/vpsd/apply.go` の `applyNFT`(`proxyrelay.Prepare` → `dp.ApplyNFT` → `proxyrelay.Commit`/`Rollback`)が、この順序の実例であり、Phase 2 からは同じ順序を `internal/reconcile` の `Runtime` が実行します。
`Runtime` の合成は `internal/reconcile` の participant interface として持ち、実際の組み立ては `vpsd` が起動時に `frontend` と `dataplane` の実装から行う([7a.7 節](packages.md#7a7-package-配置))。
Observe → diff → Prepare → Commit の骨格そのものは共有 package `internal/reconcile` に置く。
この骨格を使うのは server です。
agent は `Runtime` を使いません ([7a.7 節](packages.md#7a7-package-配置))。
agent を移す場合は同じ骨格を共有する案ですが、移行は未実装です。
`Backend` は kernel と userspace の 2 つを持ち、それぞれが OS、nftables、netstack などの実装詳細を隠す。

`Resource Guard` は、`AdmissionPolicy` と分けて持つ、wgft 自身と OS の資源を守るための予算である([7a.5 節](admission-resources.md#7a5-resource-guard))。

`Forwarding` の実装は `Transparent` と `Relay` の待ち受けと中継を持ちます。
userspace backend では両者は同じ中継コードを使う([6.3 節](../vps/userspace.md#63-ユーザー空間モード)のとおり)。
kernel backend では `Transparent` は nftables の DNAT で完結し、`Relay` は `vpsd` 自身の TCP リスナーを要します。
`SourceMetadata=ProxyV2` は `Relay` の中継が接続先へ送るヘッダの有無を選ぶだけで、待ち受けの構造そのものは変えません。

外部形式と旧い部品から、現行の層への対応は次のとおりです。
旧い部品の列には、移行で削除した名前も含みます。
agent が `Runtime` を共有する案は未実装で、現在の境界は[package の配置](packages.md#7a7-package-配置)に定めます。

| 外部形式と旧い部品 | 現行の層または未実装の案 | 対応と現在の状態 |
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
| `internal/resource`(Phase 6 の移行の手順 1 で `internal/flowcap` から改めた) | `Resource Guard` | `Limits` はプロセス全体の予算だけを持つ。接続元ごとの上限は `internal/policy` の `AdmissionLimits` へ、ログを間引く門は `internal/lograte` へ移した([7a.5 節](admission-resources.md#7a5-resource-guard)、[7a.10 節](../resource/admission.md#7a10-resource-guard-の再設計)) |
| `internal/dataplane/userspace/relay`(Phase 2 で `internal/agent/relay` から移した)の `plan`/`Action` | `internal/reconcile` の骨格のひな型 | agent が `Runtime` を使う場合に共有する案で、agent の移行は未実装です |
| `internal/dataplane/userspace/tunnel`(`internal/agent/tunnel` から移した)、`internal/dataplane/userspace/utun`(Phase 2 で `internal/vpsd/utun` から移した)、`internal/nettun` | userspace `Backend` の下位実装 | プラットフォーム配線そのままである |
| `internal/vpsd/agentapi`、`internal/vpsd/stream`、`internal/vpsd/store`、`internal/vpsd/admin` | `vpsd` の制御プレーン | 変更なし(登録、配信、永続化、admin API) |
| `internal/agent/credentials` | `agent` の制御プレーン | 変更なし |

[内部構造](README.md)
