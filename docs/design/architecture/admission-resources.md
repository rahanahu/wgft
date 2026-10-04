<a id="7a4-admission-policy-と入口の分岐"></a>
### Admission Policy と入口の分岐

Admission Policy は通信を許可する条件で、Resource Guard は backend の資源を保護する条件です。
資源の拒否は Admission Policy の drop カウンタには数えません。


kernel dataplane では、`Transparent` と `Relay` への分岐より前に、共通の ingress 層を置く。
対象は、wgft が実際に待ち受けを開けている、または DNAT を持つポートだけです。
この層は、送信元の許可拒否、送信元ごとの同時フロー数の上限、集約のレートを、`Transparent` と `Relay` のルールに同じ意味で適用します。
この考え方は、送信元 IP ごとの同時フロー数の上限をプロキシモードのルールにも同じ `flows_tcp` の set で数える今の実装に、既に部分的に表れている([6.1 節](../vps/kernel.md#61-カーネルモード))。
bind に失敗したポートには行を付けない規則も、そのまま引き継ぐ。

同じ意味を持つはずの `AdmissionPolicy` でも、kernel の nftables コンパイラと userspace の Go 評価器のあいだには、実装の単位から来る許容差があります。
これらは意味の違いではなく実装の単位の違いとして文書化し、共有 fixture で確かめる([7a.9 節](../policy.md#7a9-admission-policy-のコンパイラ))。
次の 4 つのほかに、[7a.9 節](../policy.md#7a9-admission-policy-のコンパイラ)が許容差を加えます。

- UDP の 1 フローの数え方:kernel は conntrack のエントリ数を `ct count` で数えます。
  userspace は `relay.Manager` が持つセッション数を数えます。
  両者は「今生きているフロー数」の近似として一致するが、テーブル差し替え直後の扱いは次の項で述べるとおり異なる
- タイムアウトの非対称:VPS の conntrack の `udp_timeout`(既定 30 秒)と、agent 側のセッションタイムアウト(全体状態の `udp_timeout_stream`)は非対称である([4 節](../network.md#4-ネットワーク)、[7 節](../agent-dataplane.md#7-データプレーン自宅側))。
  この非対称は既に文書化された許容差として扱う
- トークンバケットの粒度:nftables の `limit rate over` は burst 5 で動く。
  userspace の評価器はこれを模した固定 burst 5 のトークンバケットを持ち、ラボでカーネルモードと通過数・drop 数の累計が一致することを確かめている(2026-09-17)。
  IR はこの burst 値を仕様の一部として持ち、実装ごとに変えません
- テーブル差し替えによる ct count/meter のリセット:kernel は nftables のテーブル差し替えのたびに `flows_udp`/`flows_tcp` の set を作り直すため、差し替え前からのフローは新しい set の数に入らない([6.1 節](../vps/kernel.md#61-カーネルモード))。
  userspace の評価器(`goengine.Engine.Update`)は、送信元ごとの同時フロー数を作り直さずに引き継ぎ、ルール ID が転送するルール(有効で、エージェントが登録済みのもの)として引き続き存在し、かつそのレートの値が変わっていない限り、バケットと送信元表を引き継ぐ。
  ルール ID が変わる操作(分割・統合)、レートの値そのものを変える操作、ルールの無効化、エージェントの登録の取り消しでは、そのルールの状態だけを作り直す(転送しなくなったルールの状態は捨て、再び転送するときに新しく作る)。
  適用のたびに評価器全体を作り直すわけではないため、無関係な他ルールの状態はリセットされない。
  kernel の差し替えは、管理者の操作、server の起動、wgft の外の変更の公開し直しのほかに、エージェントの公開鍵の変更でも起き、鍵の変更は恒久トークンの持ち主が起こせる([6.1 節](../vps/kernel.md#61-カーネルモード))。
  その回数を [5.2 節](../control/connection.md#52-全体状態の配信とハートビート)の鍵の変更の頻度の上限で抑えるので、この差は許容します

<a id="7a5-resource-guard"></a>
### Resource Guard

`AdmissionPolicy` と `Resource Guard` は別の subsystem です。
前者は利用者が設定するルールの意味を表し、後者は wgft 自身と OS の資源を守る。
送信元 IP ごとの同時フロー数の上限(`WGFT_MAX_*_FLOWS_PER_SOURCE`)は前者に属します。
1 つの送信元が wgft の公開しているサービスを独占しないための、利用者向けの通信方針だからです。

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

以前の `flowcap.Limits` は、送信元ごとの上限(Admission Policy)とプロセス全体の予算(Resource Guard)という別の関心事を 1 つの型に混ぜていました。
Phase 6 の移行の手順 1 で、`policy.AdmissionLimits`(送信元ごとの上限)と `resource.Limits`(プロセス全体の予算、ルールごとの隔離)に分けた。

userspace 側の Resource Guard の予算は次のとおりです。

- プロセス全体の TCP/UDP 予算:`WGFT_MAX_UDP_FLOWS`/`WGFT_MAX_TCP_FLOWS`([7 節](../agent-dataplane.md#7-データプレーン自宅側))
- ルールごとの隔離:設定項目にはせず、プロセス全体の予算から導く内部の値とします。
  Phase 6 の移行の手順 4 で、1 本のルールなら空いている予算を使い切れ、複数のルールが競合するときだけ他ルールの最低限を守る、共有プールと隔離予約の方式に置き換えた(式と既定値は [7a.10 節](../resource/admission.md#7a10-resource-guard-の再設計))。
  以前の「プロセス全体の半分、ただし従来の固定値(UDP 4096、TCP 1024)を下回らない」という計算式と、その固定値の定数は削除した。
  隔離予約は、ルール 1 本の上限を残したまま、予算から予備を除いた値から求め直し、ルールの登録ごとの最低分と、次に加わる 1 つの登録のための予備の形に改めた(2026-09-29 と 2026-09-30 の所有者の決定。
  移行の手順 6)。
  最低分と予備は admission 時の請求であって保証ではありません。
  既存のフローを公平化のために強制的に追い出すことはしません。
  新しいルールの最低分が既存のフローで既に埋まっている場合、その最低分は既存のフローが終わるまで満たされない
- メモリのソフト上限:予算から導く値をランタイムに設定する(`resource.Limits.MemoryLimit`)。
  GC の目標であり、メモリの使用量の上限ではない([7 節](../agent-dataplane.md#7-データプレーン自宅側))
- 拒否した TCP の即時終了:accept 直後に RST で終える(`internal/nettun.TCPConn.Abort`)。
  通常の `Close` は gVisor の TIME_WAIT にエンドポイントを残し、上限を超えたフラッドの間ヒープが増え続けることを、生きているヒープの直接計測で確認している(ラボでの計測、2026-09-19)
- UDP の無通信タイムアウト:全体状態の `udp_timeout_stream` に従う([7 節](../agent-dataplane.md#7-データプレーン自宅側))
- netstack の出力のキュー:gVisor と wireguard-go の間の深さ 1024 の FIFO 1 つで、満杯なら新しいパケットを捨て、送り出す側を待たせない([7 節](../agent-dataplane.md#7-データプレーン自宅側))。
  設定項目にはしません。
  ルールごとの隔離はこのキューに及ばない
- IPv4 の断片の再組み立ての表:TUN の入口に置く固定の大きさの表で、満杯なら最も古い未完成の datagram を追い出す([7 節](../agent-dataplane.md#7-データプレーン自宅側))。
  設定項目にはしません。
  ルールごとの隔離はこの表に及ばない
- UDP の受信の会計:Device の全ての UDP の endpoint の受信のキューを 1 つの予算で数え、endpoint 1 つにはその 1/4 の上限を置く。
  予約できない datagram は捨てる([7 節](../agent-dataplane.md#7-データプレーン自宅側))。
  設定項目にはしません。
  ルールごとの隔離はこの予算に及ばない
- UDP の応答のバッファの枠:宛先からの応答を読むバッファをプロセス全体で同時に 64 個までしか貸さず、枠が無いセッションは空くまで待つ。
  `vpsd` の公開側のソケットの送信バッファが満杯の応答は待たずに捨てる([7 節](../agent-dataplane.md#7-データプレーン自宅側))。
  設定項目にはしません。
  ルールごとの隔離はこの枠に及ばない

kernel 側の Resource Guard は、userspace の計算式を再利用しません。
conntrack の表の大きさ、nftables の set の大きさ、カーネルのメモリ圧を基準にします。
userspace の「プロセス全体の予算」や「ルールごとの隔離」に当たる概念を kernel は持ちません。

Resource Guard に kernel と userspace で共通の Go interface は持たせない。
kernel の資源保護は conntrack の表の大きさという OS 側の限界であり、Go の `Acquire`/`Release` に相当する呼び出し点を持たないためです。

[内部構造](README.md)
