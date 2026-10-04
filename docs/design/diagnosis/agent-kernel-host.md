#### `host.forwarding` の判定

ip_forward、他テーブルの forward、rp_filter、稼働中の実効権限を検査します。
権限が無くても読めた故障の事実は FAILED として報告します。


`host.forwarding` は、ホストの転送の設定を見る。

- FAILED `ip_forward_off`:`net.ipv4.ip_forward` が 1 でない。
  カーネルは wgft0 から入ったパケットを LAN へ転送しません。
  宛先がホスト自身のルールだけは届くが ([7b.2 節](../kernel-agent/targets.md#7b2-宛先の扱い))、転送を担えないと確かに言える事実です
- UNKNOWN `ip_forward_unreadable`:`ip_forward` を読めません
- UNKNOWN `needs_cap_net_admin`:停止中で、呼び出し元が他のテーブルを読めません。
  `ip_forward` が 1 のときだけ当たる
- UNKNOWN `forward_policy_drop`:他のテーブルの forward のチェーンが既定で落とす。
  明示の accept があれば転送は通るので、[6.1 節](../vps/kernel.md#61-カーネルモード)と同じく手掛かりとして示し、FAILED にはしません。
  判定はエージェントが起動時にログへ出すものと同じ関数で行う ([7b.1 節](../kernel-agent/installation.md#7b1-カーネルに置くもの))
- UNKNOWN `rp_filter_strict`:`net.ipv4.conf.all.rp_filter` か `net.ipv4.conf.default.rp_filter` が 1 です。
  経路の組み方によっては転送が通るので、手掛かりとして示します
- それ以外は OK とします

#### カーネルモードの `host.privileges` と root の実行

root の実行の扱いは次のとおりとする (2026-09-24、所有者の決定)。
ファイルの権限の検査は今のまま保ち、root の実行では `host.privileges` を UNKNOWN `running_as_root` とします。
root がファイルのパーミッションを迂回する事情は、カーネルモードでも変わらないためです。
所見には、制御ソケットの答えから、稼働中のエージェントの実 uid と利用者名を添える。
これはモードによらない。
利用者名を引けない uid では、uid だけを示します。

カーネルモードでは、`host.privileges` の対象に、稼働中のエージェントが実効として持つ `CAP_NET_ADMIN` を加え、制御ソケットの答えで判定します。
これは「個別の理由で動かさない検査」の項が退けた、制御ソケットからエージェント自身の権限を取る案を、カーネルモードに限って採るものです。
`runuser` で実行した呼び出し元は ambient の権限を持てないので、呼び出し元の権限を見てもエージェントの `CAP_NET_ADMIN` については何も分からないためです。
エージェントがこの権限を持たなければ `host.privileges` を FAILED とし、理由の符号を `agent_lacks_cap_net_admin` とします。
この判定の結果は、エージェント自身の性質をエージェントが答えたものであり、呼び出し元が証拠に届かなかったことを示さないので、実行を層 2 に入れません。
呼び出し元の権限の不足 (`permission_denied`) と root の実行 (`running_as_root`) は、この判定より先に効く。
同梱の unit はカーネルモードでもエージェントを root で動かさない。
root で動くエージェントは、「2 つの証拠の出どころ」の項の root の実行の扱いをそのまま受ける。

#### カーネルモードの制御ソケットの応答

制御ソケットの `doctor` の応答に、次のものを加えます。
どれも加算であり、古い CLI は読み飛ばす。

- 最上位の `process`:稼働中のエージェントの実 uid、引ければ利用者名、Linux では実効の `CAP_NET_ADMIN` の有無。
  実行時の排他を要らないので、排他を取れなかった応答にも載る
- `runtime_state` の `kernel`:カーネルモードのエージェントだけが持ちます。
  前述の読み方の関数の結果、つまり wgft0、テーブルと記録の比較、ホストの転送の設定です
- `runtime_state` の `publish_error` と `check_error`:公開できずに試し直している全体状態の誤りと、直前の見直しの誤りです。
  見直しは 30 秒ごとの見直しと変更の通知の後の見直し([7b.4 節](../kernel-agent/lifecycle.md#7b4-収束と停止))の両方を指し、どちらも同じテーブルと wgft0 を読むので、誤りを 1 つの控えに持ちます
- ルールごとの `ports` と `dnat_ports`:ルールの宣言のポートの数と、DNAT を置いたポートの数です

`runtime_state` の `mode` が `kernel` なのに `kernel` を持たない応答は、この変更より前のカーネルモードのエージェントの応答です。
この場合、3 つの検査は SKIPPED とし、理由の符号を `doctor_unsupported` とします。

[診断](README.md)
