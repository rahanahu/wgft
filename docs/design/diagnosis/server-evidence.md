#### 検査の一覧と証拠の出どころ

通常の診断は保存済みの宣言と直近の観測を読みます。
--probe は指定した TCP ルールの内側の経路だけを試し、外からの到達性は試しません。


検査はすべて既存の管理用 API の応答から組み立てます。
新しい節点を追加せず、[7a.11 節](../compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の保証を変えません。

| 検査の ID | 見出し | 証拠 | 呼び出し |
|---|---|---|---|
| `rule.enabled` | enabled | `Rule.Enabled` | `GET /api/v1/rules` |
| `agent.enabled` | agent enabled | `AgentInfo.Disabled`、`AgentInfo.DisabledAt` | `GET /api/v1/agents` |
| `rule.public_port` | public port | `rule_states[id].apply_state` と `reason`、`drift`、`ip_forward`、`forward_policy` | `GET /api/v1/rules` |
| `rule.source_filter` | source filter | `source_deny`、`source_allow` と `--from` の値 | `GET /api/v1/rules` |
| `server.dataplane` | dataplane | `desired_generation`、`active_generation`、`agent_state_generation`、`agent_state_pending`、`apply_error`、`ip_forward`、`forward_policy` | `GET /api/v1/rules` |
| `tunnel.handshake` | WireGuard | `AgentInfo.LastHandshake`、`AgentInfo.Tunnel` | `GET /api/v1/agents` |
| `agent.connection` | connected | `AgentInfo.Connected`、`LastHeartbeat`、`StreamFrom`、`KeyChangeRefusedAt` | `GET /api/v1/agents` |
| `agent.rules_received` | rule generation | `AgentInfo.Generation`、`AgentInfo.GenerationBehindSince` と応答の `generation` | `GET /api/v1/agents`、`GET /api/v1/rules` |
| `agent.credentials` | credentials | `AgentInfo.Warnings` | `GET /api/v1/agents` |
| `rule.target_resolve` | target resolve | `agent_rule_states[id].reason` の文言 | `GET /api/v1/rules` |
| `rule.target` | target | `agent_rule_states[id]` の `state`、`reason`、`at`、`connected`。UDP のルールの補足の行は `udp_replies[id]` | `GET /api/v1/rules` |
| `rule.flow_budget` | flow budget | `resource_refusals[id]`、`flow_budget` | `GET /api/v1/rules` |
| `rule.probe` | end-to-end probe | 疎通確認の `reach` と `detail` | `POST /api/v1/rules/{id}/check` |

引数を付けない実行は `GET /api/v1/rules` と `GET /api/v1/agents` の 2 回だけを呼び出します。
ルールの本数によらず費用は変わりません。

`rule.target_resolve` だけは、今の観測では単独の検査として成立しません。
エージェントが `target` のホスト名を自分で解決し、server はその結果を直接観測しないためです。
この版は次のとおりに分けて扱います。

- `target` が IP リテラルである: 解決する名前が無いので OK とします
- ホスト名で、接続中のエージェントの新しい報告が、名前解決の失敗と、直前の解決の結果で転送を続けていること([7b.2 節](../kernel-agent/targets.md#7b2-宛先の扱い))の両方を示す文言を持つ: UNKNOWN とし、理由の符号は `target_resolve_failed` のままとします(2026-09-25)。
  解決の失敗は観測していますが、DNAT は直前のアドレスへ向いたまま残っており、転送の停止は観測していません。
  FAILED は転送の停止そのものを観測した検査にだけ使います(本節「検査どうしの優先順位」)。
  直前のアドレスが今も正しい宛先かどうかは server にもエージェントにも分からないので、判定に足りない UNKNOWN とします。
  今この報告を送るのは、カーネルモードのエージェントだけです。
  人向けの出力では `DEGRADED` と表示します(本節「`DEGRADED` の意味」)。
  所見は直前の解決の結果で転送を続けていることを述べ、次に見るものとしてエージェントのホストの名前の解決を示します。
  ルールの結論の行も、止まった位置ではなく、転送を続けていることと名前の解決を直すことを述べます。
  経路の上に他の UNKNOWN もあれば、結論の行は他の証拠が古いか確かめられていないことも併せて述べます
- ホスト名で、接続中のエージェントの新しい報告が名前解決の失敗を示す文言を持ち、前項に当たらない: FAILED とします。
  文言による判定なので確実ではなく、当てはまらない失敗は `rule.target` の誤りとして扱い、決めつけません
- ホスト名で、TCP のルールで、接続中のエージェントの新しい報告が `ok` である: OK とします。
  TCP のルールの `ok` は、エージェントがその `target` への接続を開けたことを意味します ([5.2 節](../control/connection.md#52-全体状態の配信とハートビート))。
  名前への接続は解決を経るので、その報告の時点で解決が成功したことを観測しています。
  仮定ではなく観測であり、OK を実際に検証したものだけに使う規則を満たします。
  観測の時刻はその報告の時刻とし、古さの閾値は `rule.target` と同じ 90 秒とします。
  UDP のルールには同じことが言えません。
  UDP の `ok` はリスナーを開けたことしか意味せず、解決を伴わないためです
- それ以外: NOT TESTED とします。
  UDP のルールでホスト名を使う場合と、TCP のルールで報告が古いか、まだ 1 度も報告が無い場合が当たります。
  証拠がどちらにも無いので、古い証拠を指す UNKNOWN ではなく、そもそも試さない条件として扱います。
  解決を server が観測しないこと自体は出力に示し、試していない範囲の「エージェントのホストの環境」とも対応します

解決を単独の検査にするには前述の遠隔の診断が要ります。

`rule.target` が FAILED になる場合の理由の符号も、`rule.target_resolve` と同じくエージェントの人が読む文言による判定であり、確実ではありません(2026-09-24)。
文言と理由の符号は次のように対応させます。

- 許可一覧の外の宛先を示す文言: `target_not_allowed`
- エージェント自身のリスナーの bind が失敗したと分かる文言: `listener_bind_failed`
- 名前解決の失敗を示す文言: `target_resolve_failed`。
  `rule.target_resolve` と同じ符号を、こちらの検査にも当てます
- 接続を拒まれたことを示す文言: `connection_refused`
- 時間切れを示す文言: `target_timeout`
- 到達できないことを示す文言: `target_unreachable`

カーネルモードのエージェントが、自分のホストの `net.ipv4.ip_forward` が 1 でないために転送できないと報告する文言には `agent_ip_forward_off` を当てます (2026-09-25)。
ループバックの宛先の `target_loopback_unsupported` ([7b.3 節](../kernel-agent/targets.md#7b3-ルールの状態と失敗の種類)) と同じく、直す場所がエージェントのホストだと分かる場合を専用の符号に分けます。
所見は、どのエージェントのホストの値かを示します。
所見は次の一手として、そのホストで `sysctl net.ipv4.ip_forward` で値を確かめ、1 でなければ `sysctl -w net.ipv4.ip_forward=1` にすることと、そのホストの `agent doctor` の `host.forwarding` を示します。
この符号は、値が 0 の場合のほか、エージェントが値を読めず書けもしなかった場合と、0 を読んで書けなかった場合にも付くので、所見は値を 0 と断定しません。
書けない場合は再起動だけでは直らないことと、読み取り専用の `/proc` やコンテナの制限などの原因を除くことを、所見で述べます(2026-10-03)。
旧い版のエージェントの理由にも、この案内は当てはまります。
宛先のサービスを疑わせる既定の案内も、VPS の設定を疑わせる読み方も避けるためです。
この変更の前の版のエージェントは、同じ事実を「this host」と書く文言で報告しますが、同じ符号に分類します。
エージェントがブロードキャストかマルチキャストの宛先を拒んだ文言には `target_not_unicast` を当てます(2026-10-03 節、[7 節](../agent-dataplane.md#7-データプレーン自宅側))。
直す場所はルールの宛先であり、許可一覧に加えても通らないので、`target_not_allowed` と分けます。
UDP のルールの `ok` に当てる `udp_listener_only` は本節前段のとおりです。
どの文言にも当てはまらない場合は `target_error` とします。
`target_error` は原因を判定できなかったことを表す既定の符号であり、宛先のサービス自体に問題があるとは限りません。

直前の解決の結果で転送を続けているという報告では、`rule.target` はその部分を除いた残りの文言で判定します(2026-09-25)。
残りが無ければ、報告が `ok` であった場合と同じに扱い、TCP のルールは OK、UDP のルールは NOT TESTED の `udp_listener_only` とします。
カーネルモードのエージェントは試し接続の誤りを理由の後ろに続ける([7b.2 節](../kernel-agent/targets.md#7b2-宛先の扱い))ので、残りが無い TCP のルールの報告は、直前のアドレスへの試し接続が失敗していないことを示します。
残りがあれば、前段の規則で残りの文言を分類し、FAILED とします。
たとえば直前のアドレスの宛先が接続を拒めば `connection_refused` になり、そのルールは `target` で止まります。

<a id="2-つの粒度"></a>
#### 2 つの粒度

引数を付けない実行は、server、エージェント、全ルールを 1 行ずつで概観します。
ルールを指定した実行は、その 1 本を公開側から宛先まで順に調べ、`Server`、`Tunnel`、`Agent` のまとまりごとに示します。

```
$ wgft server doctor r_01M2R009
r_01M2R009AA…  tcp 2456 to 192.168.1.50:2456

Server
  public port        NOT TESTED
                     serving tcp 2456; reachability from outside was not tested
                     Check: test it from another host: nc -vz <this vps> 2456
  dataplane          OK         the server's forwarding matches the current rules
Tunnel
  WireGuard          OK         handshake 32s ago
Agent "home"
  connected          OK         heartbeat 12s ago
  rule generation    OK         the agent reported generation 12, matching this server's generation;
                                applied State content is UNKNOWN because generations do not verify its contents
  target             FAILED
                     the agent could not use this rule: connection refused, last check 8s ago
                     Check: the tunnel and the agent are healthy up to this point. Check that a
                     service is listening on 192.168.1.50:2456 ...

Result: traffic stops at "target"
```

FAILED の所見には必ず次に見るものを添えます。
エージェントが接続していない場合であれば「最後に観測したのは 12 分前です。
エージェントのホストで `wgft agent doctor` を動かす」に当たる文を出します。

既定の表示には、nftables のチェーン、ソケット、世代、Backend の内部状態を出しません。
これらは `--verbose` が追加します。

#### 能動的に試す範囲

既定は読み取りだけです。
`--probe` を付けたときに限り、server から wg0 経由でエージェントのリスナーへ実際に TCP 接続します ([10.1 節](../interface.md#101-web-ui)の疎通確認)。
宛先の側にはデータを伴わない接続が 1 本届くので、運用者が明示したときだけ行います。
`--probe` は 1 本のルールにしか付けられません。
全ルールに対して能動的な確認を行うと、server 側の確認の時間 (dial の期限 5 秒と様子を見る時間 11 秒で、1 本あたり最長 16 秒) がルールの本数だけ積み上がり、自宅の全サービスに同時に接続することになるためです。
引数を付けない実行で `--probe` を渡した場合は、ルールを指定するよう求めて止めます。

接続できた後は、`internal/vpsd/conncheck` が接続を閉じられずに無言のまま保たれるかを見ます。
閉じられれば、エージェントが target に繋げなかったことを示します (拒む target はこの場合です)。
一方、ユーザー空間モードのエージェントの中継は、接続を受けてから target へ最長 10 秒ダイヤルし、黙って捨てる target ではその間 server からの接続を閉じません。
様子を見る時間がこれより短いと、捨てられている target を到達と報告してしまいます。
そこで既定の様子を見る時間は、中継の期限に 1 秒を足した 11 秒とし、中継の期限と同じ定数から導きます。
無言のまま生きる正常な target (多くのプロトコルが該当します) の確認は、この 11 秒いっぱいかかります。
バナーを返す target や、閉じられる場合は、それより早く結果が出ます。
「接続は開いたが無言」を一律に未確認とする案は採りません。
無言のまま待つプロトコルが多く、確認がほぼ常に未確認になるためです。
カーネルモードのエージェントは中継を持たず、捨てられている target では接続自体が server 側の dial の期限 (5 秒) で失敗し、`none` になると読んでいます (コードの読みによる推定で、ラボでは未確認です)。
カーネルモードで target が接続を拒む場合は、中継が無いので server 自身の dial が target の RST を受け取ります。
結果は `agent` でなく `none` で、詳細は "the agent's listener refused the connection; rule may not be applied" になります。
この詳細はエージェントのリスナーを疑わせますが、実際に拒んだのは target です。
これもコードの読みによる推定で、ラボでは未確認です。
中継の限界もあります。
許可一覧 `WGFT_AGENT_ALLOW_TARGETS` を設定し、target をホスト名で書いたルールでは、中継の名前の解決 (最長 5 秒) が 10 秒のダイヤルの前に入ります。
名前の解決が遅いと、捨てられている target でもダイヤルの途中で 11 秒の観察が終わり、到達と報告することがあります。
この限界は残し、確認の時間は延ばしません。

`--from <アドレス>` を付けると、その接続元がそのルールの拒否リストと許可リストを通るかを判定します。
判定の順序は [5.3 節](../control/rules.md#53-ルールのスキーマ)のとおり拒否が先です。
付けない実行では `rule.source_filter` を NOT TESTED とし、通るとは言いません。

#### 経路の上の検査と経路の外の検査

ルールの総合判定は、転送の経路の上にある検査だけから決めます。
経路の上の検査とは、失敗や証拠の古さがそのまま「今このルールは転送していないかもしれない」を意味する検査です。
`rule.enabled`、`agent.enabled`、`rule.public_port`、`rule.source_filter`、`server.dataplane`、`tunnel.handshake`、`agent.connection`、`agent.rules_received`、`rule.target_resolve`、`rule.target`、`rule.probe` が当たります。

`agent.credentials` と `rule.flow_budget` の 2 つは経路の外にあります。
どちらも server の起動からの累積の事実を述べるだけで、そのルールが今転送しているかどうかを述べません。
Resource Guard の拒否は、深夜に一度フラッドを受ければ、その後は転送が完全に健全でも server を再起動するまで数え続けます。
窃取の警告も、運用者が削除するまで残り続けます。
これらを総合判定に混ぜると、一度の異常のあと要約が永久に下がったままになり、要約が健全なルールと壊れたルールを区別しなくなります。
何も出さない診断と同じく、警告を出し続ける診断も運用者に読まれなくなります。

したがって、この 2 つは所見としては必ず出し、次に何をするかも添えますが、ルールの総合判定と終了コードを動かしません。
経路の外の検査は FAILED を返しません。
転送が止まったという主張をしないためです。
検査そのものの状態の意味は本節の表のままで変わりません。
UNKNOWN は依然として「証拠はあるが判定に足りない」であり、変えたのは判定を積み上げる範囲だけです。

機械向けの出力では、この区別を今のところ項目として持ちません。
`rules[].status` は上の規則で計算した値をそのまま返すので、読み手が自分で積み上げ直す場合にだけ、経路の外の 2 つの `id` を上の一覧から除く必要があります。
後から `id` ごとの項目として加えることはできます。
加算は互換な変更です。

[診断](README.md)
