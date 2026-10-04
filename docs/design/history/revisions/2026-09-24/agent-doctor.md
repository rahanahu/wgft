<!-- docs-status: historical -->

移動元: [docs/design/revisions.md](https://github.com/rahanahu/wgft/blob/8875f37e04e2576fed740c62e6a96a29a51e46b7/docs/design/revisions.md)。
基準コミットは `8875f37e`、元の行範囲は 228, 252, 266 です。

# 2026-09-24: agent-doctor

- `agent doctor` の人向けの出力で、値だけを示す 6 つの検査を「Observed values」節に分けた(2026-09-24、所有者の決定):`stream.backoff`、`stream.liveness`、`tunnel.watchdog`、`tunnel.transfer`、`relay.sessions`、`relay.refusals` は、値を述べるだけで良し悪しを言う閾値を持たず、健全なエージェントでも UNKNOWN にしかならない。
  判定済みの検査と同じ大きな状態語を Connection、Tunnel、Relay の各群に並べると、運用者はその列を故障と読む。
  この 6 つを群から抜き、5 つの群の後に「Observed values」という 1 つの節としてまとめた。
  値を読めた実行(状態が UNKNOWN)は状態語を出さず、ラベルと同じ行から値を示す。
  この行には次に見るもの(`Check:` の行)も出さない。
  健全なエージェントでも 6 つの `Check:` の行が並び、何かを確かめる必要があるように読めるためである。
  値の読み方は `--help` に短く書き、`--json` の `next` はこれまでどおり持つ。
  値に文脈を添えないと読み違えられる場合は、決まった `Check:` の行ではなく、その値に短い注記を付ける。
  値を読めなかった実行は、これまでどおり SKIPPED を状態語と次に見るものごと示す。
  値が無いことを値と取り違えないためである。
  実装を読んで確かめたところ、この 6 つは UNKNOWN と SKIPPED のどちらかにしかならず、OK にも FAILED にもならない。
  内部の判定、`checks[]` の `id`、`status`、`reason`、終了コード、`--json` の出力は変えていない。
  変える前と後で `--json` の出力が一致することを確かめた。
  ラボで稼働中と停止中のエージェントに対して人向けの出力と `--json` を確かめた。
  未確認:実機では確かめていない。

- agent doctor がエージェントの無効を示すようにした(2026-09-24):5.1 節が全体状態に加算すると定めていた `AgentDisabled` を、`internal/agent` が `agent.json` の `LastState`(`proto.State` をまるごと持つので、この加算のフィールドは既に自動で乗っていた)と、稼働中の制御ソケットの `doctor` の応答の `DoctorRuntimeState.AgentDisabled` に載せた。
  新しい検査は作らず、10.2c 節が既に定めていたとおり、稼働中の `relay.listeners` は無効の間 SKIPPED `agent_disabled` とし、所見に「server がこのエージェントを無効にしていること」と「VPS で `wgft agent enable <name>` を実行するまでリスナーを開かないこと」を、そのエージェントの登録名で添える。
  SKIPPED は総合判定と終了コードを動かさない。
  `agent.last_state` は `agent.json` の `LastState` から同じ事実を読むので、稼働中でも停止中でも同じ所見を示し、状態は OK のままとする。
  ただし停止中のこの所見は保存した時点のものであり、既に停止しているエージェントを server が無効にしても、または無効なまま停止しているエージェントを有効に戻しても、agent.json は書き換わらないので所見が現状と食い違いうる(実装時に判明。
  「証拠の鮮度の違い」の項に追記)。
  理由の符号と判定の組み立ては relay.listeners がまず持つ。
  設計文書 10.2c 節の「カーネルモードのエージェント」の項は、カーネルモードの `dataplane.table` も同じ符号を使うと定めているが、その検査はまだ実装していない。
  実装するときにこの判定を共有できるよう、SKIPPED / `agent_disabled` を立てる部分だけを小さな共有の関数に切り出した。
  10.2c 節の検査の一覧の表に、`agent.last_state` が無効かどうかも見ることを追記し、理由の符号の表に `agent_disabled` を加えた。
  旧い server は `agent_disabled` を送らないので、その stream につながるエージェントは常に無効を示さない。
  確かめ方:ホストの単体テストで、稼働中と停止中の `agent doctor` の両方が無効を示すこと、`agent.json` のフィールドが無効化と有効化で立ってから消えること、`agent_disabled` を持たない旧い server の全体状態を模した JSON を読んでも無効を示さないこと、総合判定と終了コードが 0 のままであることを確かめた。
  いくつかの変異(無効かどうかの判定を外す、所見からエージェント名を落とす、理由の符号を入れ替える、`agent.last_state` の所見を消す、その状態を変える)を入れ、対応するテストが落ちることを確かめた。
  ラボの `lab/lifecycle.sh` の check11(エージェントの無効化と有効化)に、home を無効にした状態でその場から `wgft agent doctor` を実行する手順を加え、カーネルモードとユーザー空間モードの両方で、`relay.listeners` が SKIPPED `agent_disabled` になり `agent.last_state` も無効を示すこと、`--json` でも空白を畳んだ人向けの出力でも所見が `wgft agent enable home` を名指すこと、有効化をやり直すと `agent_disabled` が消えて所見も戻ること、終了コードが 0 のままであることを確かめた。
  未確認:無効の間に停止した場合の `agent doctor` は、ホストの単体テストだけで確かめ、ラボでは稼働中の場面と、稼働中に有効化し直した場面だけを確かめた。

- `agent doctor` をカーネルモードのエージェントに対応させた(2026-09-24、所有者の決定):10.2c 節の「カーネルモードのエージェント」の項と、それに続く項に、`dataplane.interface`、`dataplane.table`、`host.forwarding` の判定の順と理由の符号、証拠の読み方、制御ソケットの応答に加えるものを書き、検査の表と理由の符号の表に行を加えた。
  7a.11 節の加算の記述と、「終了コード」の項の層 2 の列挙も合わせた。
  層 2 には `needs_cap_net_admin` を加え、`agent_lacks_cap_net_admin` の `host.privileges` の FAILED は入れない。
  決めたことを挙げる。
  第 1 に、カーネルの状態は、稼働中のエージェントが制御ソケットで返し、停止中だけ呼び出し元が直接読む。
  読む関数は 1 つで、両方の実行が使う。
  第 2 に、`dataplane.table` は、稼働中も停止中も、直近の公開の記録と実際のテーブルを同じ比べ方で比べる。
  欠けると転送が止まる行か DNAT が欠けていれば FAILED `table_rows_missing` とし、欠けても転送が止まらない守りの行だけが欠けていれば UNKNOWN `guard_rows_missing` として終了コードを動かさない(所有者の決定)。
  加わった行だけなら UNKNOWN `table_changed`、公開の失敗は UNKNOWN `publish_failed` とした。
  行の分け方は「その行が欠けたときに転送が止まるか」で決め、10.2c 節に表として置いた。
  通す行は、同じチェーンの drop の行があるときだけ転送の行に数え、`input` と `forward` と `postrouting` の転送の行は、その行を通る宛先のルールがあるときだけ数える。
  分け方は、停止中のエージェントのテーブルから行とチェーンを 1 種類ずつ消し、LAN の宛先とホスト自身の宛先への転送が通るかを見て確かめた。
  `filter_pre` の drop の行を消すと転送は続き、他のテーブルの DNAT が wgft0 から届くようになった。
  見出しの違うチェーンの扱いは確かめていない。
  期待する行が同じチェーンの別の位置にある場合は、欠けに数えず、行が加わった場合と同じく効果の分からない変更として `table_changed` とする(所有者の決定)。
  `filter_pre` と `forward` の drop の行を先頭へ移した表では転送が止まり、この場合を欠けとして数えると守りの行だけが欠けたように見え、転送が続きうると述べることになったためである。
  表に加わった行か位置の違う行があるときは、守りの行の欠けの所見でも転送が続きうるとは言わない。
  守りの行の欠けの所見は、欠けた drop の行の組み合わせで開きうる面を述べる。
  drop の行は層になっていて、`input` の drop の行だけが欠けても、`filter_pre` の drop の行がホストのポートを閉じていることを、ラボで確かめた。
  `filter_pre` の drop の行だけが欠けると他のテーブルの DNAT にだけ届き、`input` の drop の行も欠けるとホストのポートにも届いた。
  1 行だけの欠けで面が開かないときは、残っている行が閉じていることを所見に示す。
  ただし表に加わった行か位置の違う行があれば示さない。
  `input` の drop の行を消して `filter_pre` の先頭に通す行を加えた表では、ホストのポートにも他のテーブルの DNAT にも届いたためである(所有者の決定)。
  `forward` の wgft0 から wgft0 への drop の行と wgft0 へ出るものの drop の行の効果は、ラボで観測できず未確認である。
  位置の違う行は、順に並ぶ行の数が最も多くなる対応で照合し、動いていない行ではなく移した行を名指す。
  ルール単位の失敗は `relay.listeners` と同じ符号 `listener_error` の FAILED とし、所見はルールごとに DNAT を置いたポートの数を示す。
  第 3 に、server のトンネルアドレスへの経路が wgft0 を通らない場合は、`dataplane.interface` の UNKNOWN `route_not_via_interface` とした。
  経路の問い合わせが答えるのはホスト自身が送るパケットの経路であり、転送する応答の経路とは違いうるので、転送を担えないと確かには言えないためである。
  第 4 に、権限なしで読める事実、つまりリンクの有無、種別、up の印と `ip_forward` から FAILED と言える場合は、呼び出し元が `CAP_NET_ADMIN` を持たなくても FAILED を示す。
  第 5 に、root の実行の所見と、カーネルモードの `host.privileges` の判定には、制御ソケットが返す稼働中のエージェントの実 uid、利用者名、実効の `CAP_NET_ADMIN` を使う。
  `server doctor` の `rule.target` は、カーネルモードのループバックの宛先の理由を `target_loopback_unsupported` に分類するようにした。
  設計の前に、使い捨ての骨組みをラボで動かし、何を読むのに `CAP_NET_ADMIN` が要るかを確かめた。
  WireGuard の鍵とピアと nftables の読み出しは、`runuser -u` で切り替えた利用者では権限の誤りで拒まれ、root と ambient の `CAP_NET_ADMIN` を持つ利用者では読めた。
  リンクの属性、経路の問い合わせ、`ip_forward` と `rp_filter` は権限なしで読めた。
  ambient の `CAP_NET_ADMIN` で動くエージェントの `/proc/self/status` の CapEff には、その権限のビットが立っていた。
  実装の後に、`lab/agentdoctor.sh` を server のカーネルモードとユーザー空間モードの両方で流した。
  確かめたのは、稼働中と停止中の判定、停止中も転送が続くときの終了コード 0、DNAT の行を消したときの `table_rows_missing`、`ip_forward` が 0 のときの `ip_forward_off`、forward の既定の落としを持つ表を足したときの `forward_policy_drop`、別の経路表へ送る規則を足したときの `route_not_via_interface`、ループバックの宛先での `listener_error` と `target_loopback_unsupported`、無効化での `agent_disabled`、3 つの実行主体の違いである。
  ユーザー空間モードのエージェントでは、既存の検査の `id`、状態、理由の符号が、この変更の前のバイナリと同じだった。
  未確認:Tailscale そのものを動かしたホストでの経路の所見、systemd の `DynamicUser` で動くエージェントの利用者名の示し方、`publish_failed` と記録の無い場合の判定の実際のカーネルでの再現。
  この 2 つは単体テストだけで確かめた。
