#### 検査の一覧と証拠の出どころ

通常の診断は保存済みの宣言と直近の観測を読みます。
--probe は指定した TCP ルールの内側の経路だけを試し、外からの到達性は試しません。


検査はすべて既存の管理用 API の応答から組み立てる。
新しい節点を追加しない ([7a.11 節](../compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の保証を変えない)。

| 検査の ID | 見出し | 証拠 | 呼び出し |
|---|---|---|---|
| `rule.enabled` | enabled | `Rule.Enabled` | `GET /api/v1/rules` |
| `agent.enabled` | agent enabled | `AgentInfo.Disabled`、`AgentInfo.DisabledAt` | `GET /api/v1/agents` |
| `rule.public_port` | public port | `rule_states[id].apply_state` と `reason`、`drift`、`ip_forward` | `GET /api/v1/rules` |
| `rule.source_filter` | source filter | `source_deny`、`source_allow` と `--from` の値 | `GET /api/v1/rules` |
| `server.dataplane` | dataplane | `desired_generation`、`active_generation`、`agent_state_generation`、`agent_state_pending`、`apply_error`、`ip_forward` | `GET /api/v1/rules` |
| `tunnel.handshake` | WireGuard | `AgentInfo.LastHandshake`、`AgentInfo.Tunnel` | `GET /api/v1/agents` |
| `agent.connection` | connected | `AgentInfo.Connected`、`LastHeartbeat`、`StreamFrom`、`KeyChangeRefusedAt` | `GET /api/v1/agents` |
| `agent.rules_received` | rule generation | `AgentInfo.Generation`、`AgentInfo.GenerationBehindSince` と応答の `generation` | `GET /api/v1/agents`、`GET /api/v1/rules` |
| `agent.credentials` | credentials | `AgentInfo.Warnings` | `GET /api/v1/agents` |
| `rule.target_resolve` | target resolve | `agent_rule_states[id].reason` の文言 | `GET /api/v1/rules` |
| `rule.target` | target | `agent_rule_states[id]` の `state`・`reason`・`at`・`connected`。UDP のルールの補足の行は `udp_replies[id]` | `GET /api/v1/rules` |
| `rule.flow_budget` | flow budget | `resource_refusals[id]`、`flow_budget` | `GET /api/v1/rules` |
| `rule.probe` | end-to-end probe | 疎通確認の `reach` と `detail` | `POST /api/v1/rules/{id}/check` |

引数を付けない実行は `GET /api/v1/rules` と `GET /api/v1/agents` の 2 回だけを呼び出す。
ルールの本数によらず費用は変わりません。

`rule.target_resolve` だけは、今の観測では単独の検査として成立しません。
エージェントが `target` のホスト名を自分で解決し、server はその結果を直接観測しないためです。
この版は次の 5 つに分けて扱う。

- `target` が IP リテラルである: 解決する名前が無いので OK とします
- ホスト名で、接続中のエージェントの新しい報告が、名前解決の失敗と、直前の解決の結果で転送を続けていること([7b.2 節](../kernel-agent/targets.md#7b2-宛先の扱い))の両方を示す文言を持つ: UNKNOWN とし、理由の符号は `target_resolve_failed` のままとする(2026-09-25)。
  解決の失敗は観測しているが、DNAT は直前のアドレスへ向いたまま残っており、転送の停止は観測していません。
  FAILED は転送の停止そのものを観測した検査にだけ使う(本節「検査どうしの優先順位」)。
  直前のアドレスが今も正しい宛先かどうかは server にもエージェントにも分からないので、判定に足りない UNKNOWN とします。
  今この報告を送るのは、カーネルモードのエージェントだけです。
  人向けの出力では `DEGRADED` と表示する(本節「`DEGRADED` の意味」)。
  所見は直前の解決の結果で転送を続けていることを述べ、次に見るものとしてエージェントのホストの名前の解決を示します。
  ルールの結論の行も、止まった位置ではなく、転送を続けていることと名前の解決を直すことを述べる。
  経路の上に他の UNKNOWN もあれば、結論の行は他の証拠が古いか確かめられていないことも併せて述べる
- ホスト名で、接続中のエージェントの新しい報告が名前解決の失敗を示す文言を持ち、前項に当たらない: FAILED とします。
  文言による判定なので確実ではなく、当てはまらない失敗は `rule.target` の誤りとして扱い、決めつけない
- ホスト名で、TCP のルールで、接続中のエージェントの新しい報告が `ok` である: OK とします。
  TCP のルールの `ok` は、エージェントがその `target` への接続を開けたことを意味する ([5.2 節](../control/connection.md#52-全体状態の配信とハートビート))。
  名前への接続は解決を経るので、その報告の時点で解決が成功したことを観測しています。
  仮定ではなく観測であり、OK を実際に検証したものだけに使う規則を満たす。
  観測の時刻はその報告の時刻とし、古さの閾値は `rule.target` と同じ 90 秒とします。
  UDP のルールには同じことが言えない。
  UDP の `ok` はリスナーを開けたことしか意味せず、解決を伴わないためです
- それ以外: NOT TESTED とします。
  UDP のルールでホスト名を使う場合と、TCP のルールで報告が古いか、まだ 1 度も報告が無い場合が当たる。
  証拠がどちらにも無いのだから、古い証拠を指す UNKNOWN ではなく、そもそも試さない条件として扱う。
  解決を server が観測しないこと自体は出力に示し、試していない範囲の「エージェントのホストの環境」とも対応します

解決を単独の検査にするには前述の遠隔の診断が要る。

`rule.target` が FAILED になる場合の理由の符号も、`rule.target_resolve` と同じくエージェントの人が読む文言による判定であり、確実ではない(2026-09-24)。
許可一覧の外の宛先を示す文言には `target_not_allowed`、エージェント自身のリスナーの bind が失敗したと分かる文言には `listener_bind_failed`、名前解決の失敗を示す文言には `target_resolve_failed`(`rule.target_resolve` と同じ符号を、こちらの検査にも当てる)、接続を拒まれた・時間切れ・到達できないことを示す文言にはそれぞれ `connection_refused`・`target_timeout`・`target_unreachable` を当てる。
カーネルモードのエージェントが、自分のホストの `net.ipv4.ip_forward` が 1 でないために転送できないと報告する文言には `agent_ip_forward_off` を当てる (2026-09-25)。
ループバックの宛先の `target_loopback_unsupported` ([7b.3 節](../kernel-agent/targets.md#7b3-ルールの状態と失敗の種類)) と同じく、直す場所がエージェントのホストだと分かる場合を専用の符号に分ける。
所見は、どのエージェントのホストの値かを名指し、次の一手は、そのホストで `sysctl net.ipv4.ip_forward` で値を確かめ、1 でなければ `sysctl -w net.ipv4.ip_forward=1` にすることと、そのホストの `agent doctor` の `host.forwarding` を示します。
この符号は、値が 0 の場合のほか、エージェントが値を読めず書けもしなかった場合と、0 を読んで書けなかった場合にも付くので、所見は値を 0 と断定せず、書けない場合は再起動だけでは直らないことと、読み取り専用の `/proc` やコンテナの制限などの原因を除くことを述べる(2026-10-03)。
旧い版のエージェントの理由にも、この案内は当てはまる。
宛先のサービスを疑わせる既定の案内も、VPS の設定を疑わせる読み方も避けるためです。
この変更の前の版のエージェントは、同じ事実を「this host」と書く文言で報告するが、同じ符号に分類します。
エージェントがブロードキャストかマルチキャストの宛先を拒んだ文言には `target_not_unicast` を当てる(2026-10-03 節、[7 節](../agent-dataplane.md#7-データプレーン自宅側))。
直す場所はルールの宛先であり、許可一覧に加えても通らないので、`target_not_allowed` と分ける。
UDP のルールの `ok` に当てる `udp_listener_only` は本節前段のとおりです。
どの文言にも当てはまらない場合は `target_error` とします。
`target_error` は原因を判定できなかったことを表す既定の符号であり、宛先のサービス自体に問題があるとは限らない。

直前の解決の結果で転送を続けているという報告では、`rule.target` はその部分を除いた残りの文言で判定する(2026-09-25)。
残りが無ければ、報告が `ok` であった場合と同じに扱い、TCP のルールは OK、UDP のルールは NOT TESTED の `udp_listener_only` とします。
カーネルモードのエージェントは試し接続の誤りを理由の後ろに続ける([7b.2 節](../kernel-agent/targets.md#7b2-宛先の扱い))ので、残りが無い TCP のルールの報告は、直前のアドレスへの試し接続が失敗していないことを示します。
残りがあれば、前段の規則で残りの文言を分類し、FAILED とします。
たとえば直前のアドレスの宛先が接続を拒めば `connection_refused` になり、そのルールは `target` で止まります。

<a id="2-つの粒度"></a>
#### つの粒度

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

FAILED の所見には必ず次に見るものを添える。
エージェントが接続していない場合であれば「最後に観測したのは 12 分前です。
エージェントのホストで `wgft agent doctor` を動かす」に当たる文を出す。

既定の表示には、nftables のチェーン、ソケット、世代、Backend の内部状態を出さない。
これらは `--verbose` が追加します。

#### 能動的に試す範囲

既定は読み取りだけです。
`--probe` を付けたときに限り、server から wg0 経由でエージェントのリスナーへ実際に TCP 接続する ([10.1 節](../interface.md#101-web-ui)の疎通確認)。
宛先の側にはデータを伴わない接続が 1 本届くので、運用者が明示したときだけ行います。
`--probe` は 1 本のルールにしか付けられない。
全ルールに対して能動的な確認を行うと、server 側の dial の期限 (既定 5 秒) がルールの本数だけ積み上がり、自宅の全サービスに同時に接続することになるためです。
引数を付けない実行で `--probe` を渡した場合は、ルールを指定するよう求めて止めます。

`--from <アドレス>` を付けると、その接続元がそのルールの拒否リストと許可リストを通るかを判定します。
判定の順序は [5.3 節](../control/rules.md#53-ルールのスキーマ)のとおり拒否が先です。
付けない実行では `rule.source_filter` を NOT TESTED とし、通るとは言わない。

#### 経路の上の検査と経路の外の検査

ルールの総合判定は、転送の経路の上にある検査だけから決める。
経路の上の検査とは、失敗や証拠の古さがそのまま「今このルールは転送していないかもしれない」を意味する検査です。
`rule.enabled`、`agent.enabled`、`rule.public_port`、`rule.source_filter`、`server.dataplane`、`tunnel.handshake`、`agent.connection`、`agent.rules_received`、`rule.target_resolve`、`rule.target`、`rule.probe` が当たる。

`agent.credentials` と `rule.flow_budget` の 2 つは経路の外にあります。
どちらも server の起動からの累積の事実を述べるだけで、そのルールが今転送しているかどうかを述べない。
Resource Guard の拒否は、深夜に一度フラッドを受ければ、その後は転送が完全に健全でも server を再起動するまで数え続けます。
窃取の警告も、運用者が削除するまで残り続けます。
これらを総合判定に混ぜると、一度の異常のあと要約が永久に下がったままになり、要約が健全なルールと壊れたルールを区別しなくなる。
沈黙する診断と同じく、鳴りやまない診断も運用者から読まれなくなる。

したがって、この 2 つは所見としては必ず出し、次に何をするかも添えるが、ルールの総合判定と終了コードを動かさない。
経路の外の検査は FAILED を返さない。
転送が止まったという主張をしないためです。
検査そのものの状態の意味は本節の表のままで変わりません。
UNKNOWN は依然として「証拠はあるが判定に足りない」であり、変えたのは判定を積み上げる範囲だけです。

機械向けの出力では、この区別を今のところ項目として持ちません。
`rules[].status` は上の規則で計算した値をそのまま返すので、読み手が自分で積み上げ直す場合にだけ、経路の外の 2 つの `id` を上の一覧から除く必要があります。
後から `id` ごとの項目として加えることはできる (加算は互換である)。

[診断](README.md)
