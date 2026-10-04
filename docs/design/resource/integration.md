#### メモリのソフト上限との関係

メモリのソフト上限と kernel の conntrack の保護は、フローの予算とは別の条件です。
エージェントにも同じ Resource Guard を適用します。


メモリのソフト上限は、`resource.Limits` の `MemoryLimit` だけから導く。
式(`32 MiB + 12 KiB × UDPTotal + 44 KiB × TCPTotal`)、`GOMEMLIMIT` を優先する規則、起動ログと `server check` の `memory soft limit:` の行は変えません。
隔離予約と、それを改める最低分と予備は予算 `T` の内側での配分なので、保持するフローの数の合計の最大もメモリのソフト上限も変わりません。
ルールが 1 本の構成では、1 本のルールへのフラッドで予算 `T` のすべてが埋まりうる。
ラボでは、既定の上限を全部埋めてフラッドを重ねたときの RSS の最大は約 210 MiB だった(改訂の記録 2026-09-18)。
この値はその負荷での測定であり、プロセスのメモリの上界ではない([7 節](../agent-dataplane.md#7-データプレーン自宅側))。

kernel モードの server は Go で UDP のフローを持たないが、ソフト上限の式は UDP の項を含めたままにします。
ソフト上限は GC の回収の目安であって、メモリを確保する値ではないため、実際より大きくても害がありません。
式をモードで変えると、同じ設定で起動ログの値がモードによって変わる。

Resource Guard は、ヒープの量を見て新しいフローを拒む判定を持ちません。
フロー数の予算はフローの数を抑え、ソフト上限は GC の目標です。
最低分と予備の配分は、このメモリのソフト上限の役割を変えません。
どちらもプロセスのメモリの量を抑える上限ではない([7 節](../agent-dataplane.md#7-データプレーン自宅側))。
IPv4 の断片の再組み立ては gVisor に渡さず、TUN の入口の固定の大きさの表で行い([7 節](../agent-dataplane.md#7-データプレーン自宅側))、UDP の endpoint の受信のキューは TUN の入口の会計の予算で数え([7 節](../agent-dataplane.md#7-データプレーン自宅側))、拒んだ TCP の TIME_WAIT は RST で閉じて残さない([7a.5 節](../architecture/admission-resources.md#7a5-resource-guard))。
宛先からの応答を読むバッファは、プロセス全体の枠で数える([7 節](../agent-dataplane.md#7-データプレーン自宅側))。
Resource Guard の最低分と予備の配分は、ユーザー空間のこれらの保持点に新しい上限を加えません。
応答のバッファの枠はソフト上限の式に入れません。
枠の上限は式の値に比べて小さく、ソフト上限は GC の目標であって上限ではないためです。
netstack の出力のキューと wireguard-go の送信のキューに滞留するパケットの上限は、1 回の `Read` の件数を 1 に保つことで決まり、wireguard-go の受信のキューに滞留するパケットの上限は、バインドの 1 回の受信の件数を 1 に保つことで決まる([7 節](../agent-dataplane.md#7-データプレーン自宅側))。
netstack の握手途中の TCP の数に上限が効いているかは未確認です。

#### kernel 側の保護

kernel 側の Resource Guard は、観測して提示するだけで、値を変えず、強制も加えない。
wgft の方針は、環境を見て挙動を推測せず、明示された値に従うか、提示して止まることです。
conntrack の表はホスト全体の資源であり、wgft 以外の通信も同じ表を使うので、wgft が上限を決める立場にない。

kernel 側で Resource Guard が行うことは次のとおりです。

- conntrack の表の上限と件数の読み取り:`internal/platform/linux` の `ReadConntrackUsage` が `nf_conntrack_max` と `nf_conntrack_count` を読みます。
  `server check` は今のとおり件数と上限を表示し、上限が 65536 未満なら、上げる sysctl と `new_flow_rate` の設定を提示します。
  実際の VPS(メモリ 462 MB)では、上限は 4096 で、この提示が出た。
  [6.1 節](../vps/kernel.md#61-カーネルモード)が例に挙げた 16384 より小さい上限の VPS もあります
- 起動時の Finding:以前は `server check` を実行したときにしか出なかった。
  同じ判定は、`ip_forward` と同様に起動時のログにも出します。
  `server check` を実行しない運用者にも気付けるようにするためです。
  conntrack の表の上限についての起動時の Finding はログに出し、管理用 API と Web UI には載せません。
  kernel モードの server の `ip_forward` は別の経路で管理用 API が現在の値と読み取りの誤りを報告し、CLI と Web UI の診断が判定に使います ([server の観測と判定](../diagnosis/server-observations.md#102a-転送の診断-server-doctor))。
- 提示する値:以前の提示は `nf_conntrack_max=262144` だった。
  所有者の決定により、`server check` と起動時の Finding のどちらも、メモリの数値(MiB、エントリ 1 件のバイト数、bucket 数のいずれも)を出さない。
  提示する値は 65536 に改めた。
  判定の閾値も同じ 65536 です

  観測:Debian 12 / Linux 6.1 のラボで約 6 万件を埋めて測ったところ、DNAT を伴う conntrack のエントリは 1 件あたり約 384 バイト(本体 256 バイトと NAT の拡張 128 バイト)、NAT を伴わないエントリは約 256 バイトだった。
  ほかにハッシュ表の費用があります。
  これは kernel の版、設定、エントリの種類で変わるので、wgft の診断の出力にも推奨値の計算にも使いません。
  65536 はメモリの量から出した値ではなく、wgft が運用上の最低の推奨値として定める
- set の大きさ:`meter_N` と `flows_udp`/`flows_tcp` の大きさ(65535)は、Phase 5 から IR の定数である([7a.9 節](../policy.md#7a9-admission-policy-のコンパイラ))。
  埋まったときの劣化(送信元ごとの制限が外れ、集約上限に委ねる)は [6.1 節](../vps/kernel.md#61-カーネルモード)のとおりで、Resource Guard の最低分と予備は、この kernel の扱いを変えません。
  set の要素数は監視しません

kernel 側で Resource Guard が行わないことは次のとおりです。

- `nf_conntrack_max` と `nf_conntrack_buckets` を書き換えない([6.1 節](../vps/kernel.md#61-カーネルモード))
- ホストのメモリの量から提示する値を計算しません。
  提示は判定の閾値(65536)という固定の値だけから作り、メモリの数値(MiB、エントリの費用、bucket 数)は出さない
- wgft のポート全体の同時フロー数を `ct count` で抑える行を加えない。
  この上限は利用者の設定項目にない新しい通信方針になり、`flows_udp`/`flows_tcp` と同じくテーブルの差し替えで数がリセットされる。
  `new_flow_rate` と conntrack の表の上限という既存の手段で足りる
- ルールごとの隔離を持たない([7a.5 節](../architecture/admission-resources.md#7a5-resource-guard))

kernel モードの `Relay` のルールの接続は、`vpsd` のソケットが終端するので、Go の側の Resource Guard(`proxyrelay` の TCP のプール)で数えます。
同じ接続は、公開側と wg0 側で conntrack のエントリを 2 件使う(ラボで確認した)。
`Transparent` なルールの接続は、DNAT だけを経由するので 1 件のエントリを使う(同じラボで確認した)。

#### agent への適用

agent の userspace dataplane は server と同じ `relay.Manager` を使うので、共有プール、ルール 1 本の上限、最低分と予備、拒否の数とログ、メモリのソフト上限をそのまま使います。
agent の `A` は、全体状態のうちその agent のルールで、listener を開けているものです。
最低分と予備の計算は agent が自分の `resource.Limits` と自分のルールの集合だけから行うので、全体状態にも join protocol にも何も加えない。
agent には `AdmissionLimits` がありません。
agent から見た送信元は常に `10.200.0.1` であり([7 節](../agent-dataplane.md#7-データプレーン自宅側))、Admission Policy は server だけで評価するためです。

agent の拒否の数は、ログと手元の制御ソケットの診断で報告します。
`agent doctor` は、制御ソケットの `budgets` と `refusals` を読みます。
ハートビートには加えず、server へは伝えません。
ハートビートに加える場合は、wire protocol と capability の規則に従います ([7a.6 節](../architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性))。

agent の kernel dataplane では、kernel 側の保護を server と同じく `internal/platform/linux` の読み取りと提示で行い、ルールごとの隔離は持ちません。

[Resource Guard](README.md)
