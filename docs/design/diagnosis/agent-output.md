#### 出力の形

--json は検査 ID、状態、理由の符号を持つ機械向けの形式です。
理由は開いた集合として加算でき、既存の値と意味は保証を維持します。


操作体系を `server doctor` ([10.2a 節](server-observations.md#102a-転送の診断-server-doctor)) に揃える。
揃えるのは操作体系であって、検査の中身ではありません。
状態の語彙、`--json`、終了コードの考え方が揃っていれば、運用者は読み方もスクリプトも共通にできます。
見る場所が違うことは、検査の一覧が違うことで表します。
この項が定めるのは次のとおりです。
`--json` と終了コードは、後続の 2 つの項で定める。

- 群分け: 検査を `Host`、`Credentials`、`Connection`、`Tunnel`、`Relay`、`Dataplane` の群に分けて示します。
  `Dataplane` はカーネルモードの検査の群です。
  [10.2a 節](server-observations.md#102a-転送の診断-server-doctor)が `Server`、`Tunnel`、`Agent` に分けるのと同じ形です
- 値だけを示す検査の節: 値だけを示し合否を持たない 6 つの検査 (`stream.backoff`、`stream.liveness`、`tunnel.watchdog`、`tunnel.transfer`、`relay.sessions`、`relay.refusals`) は群から抜き、群の後に「Observed values」という 1 つの節としてまとめて出す (2026-09-24、所有者の決定、改訂の記録に詳細)。
  値を読めた実行 (状態が UNKNOWN) は状態語も次に見るもの (Next) も出さず、ラベルと同じ行から値を示します。
  値の読み方は `--help` と、`--json` の `next` が持ちます。
  値そのものを読めなかった実行は、SKIPPED のまま判定済みの検査と同じく状態語と次に見るものを出す。
  値に文脈を添えないと読み違えられる場合は、決まった `Check:` の行ではなく、その値に短い注記を付ける。
  人向けの出力だけの見せ方であり、内部の模型と `--json` の `checks[]` は変えない ([7a.11 節](../compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧))
- 状態の語彙: [10.2a 節](server-observations.md#102a-転送の診断-server-doctor)の表の OK、FAILED、UNKNOWN、NOT TESTED、SKIPPED をそのまま使います。
  意味も同じとし、新しい語を加えない
- 次に見るもの: FAILED の所見には必ず次に見るものを添える。
  次の行動を伴わない所見は、[10.2a 節](server-observations.md#102a-転送の診断-server-doctor)と同じく機能の失敗として扱う
- 試していない範囲: [10.2a 節](server-observations.md#102a-転送の診断-server-doctor)と同じく、何も壊れていない実行でも試していない範囲を必ず出力する (2026-09-23、所有者の決定)。
  現在の一覧は、server 側の状態、VPS への到達性、LAN の宛先、手元の設定を含みます。
  LAN の宛先への接続はこの診断から試さず、稼働中のエージェントが報告した結果を読みます。
  kernel モードでは、その結果は各 TCP 範囲の先頭のポートを試したものです
- 履歴: [10.2a 節](server-observations.md#102a-転送の診断-server-doctor)と同じく、診断のために保存の仕組みを追加せず、履歴を持ちません。
  [10.2a 節](server-observations.md#102a-転送の診断-server-doctor)が持つ `History` のまとまりは同じ形で出力します。
  一方 `Result:` の行は持ちません。
  転送の経路を順にたどる形を持たないため、「転送はここで止まった」という位置を言えないためです

次の断片は、エージェントが止まっている実行の出力の形を示す例です。
実際に動かして得たものではなく、値も仮のものです。
Tunnel 群は、停止中も成立する `wg endpoint resolve` の行だけを示した。
`tunnel.local` の行は、Connection 群と同じく SKIPPED で並ぶので省いた。
Relay 群は、`relay.allow_targets` が UNKNOWN になるほかは SKIPPED で並ぶので省いた。
Observed values 節は、`reconnect backoff` と `liveness` だけを示した。
`watchdog`、`transfer`、`sessions`、`refusals` の行も同じく SKIPPED で並ぶので省いた。
1 行に収まらない所見は、状態語の次の行に置く。

```
Host
  platform           OK       linux/amd64, wgft vX.Y.Z
  privileges         OK       running as wgft, uid 999; the data directory is readable, new files can be created in it, agent.json is readable
  interfaces         OK       3 interfaces
  endpoint resolve   OK       vps.example.net resolves to 203.0.113.10
Credentials
  credentials        OK       last: registered as "home", pinned to cert sha256:...
  process            FAILED
                     the agent is not running on this host
                     Check: systemctl status wgft-agent, or docker ps for a container
  last state         OK       last: generation N, 3 rules
Connection
  control socket     SKIPPED
                     the agent is not running, so its live state was not read
  control connection SKIPPED
                     the agent is not running, so its live state was not read
Tunnel
  wg endpoint resolve OK       vps.example.net resolves to 203.0.113.10

Observed values
  reconnect backoff  SKIPPED
                     the agent is not running, so its live state was not read
  liveness           SKIPPED
                     the agent is not running, so its live state was not read
```

次の断片は、稼働中のエージェントの出力のうち Observed values 節の先頭の 3 行を示す例です。
ラボで動かして得た出力から取った。
値はラベルと同じ行から始まり、続く行は値の桁で折り返します。
次に見るものの `Check:` の行は出さない。

```
Observed values
  reconnect backoff  no reconnect wait has been recorded on this connection yet; no attempt is
                     waiting now
  liveness           the last ping went out at 2026-09-23T22:44:28Z, 13s ago; the last pong came
                     back at 2026-09-23T22:44:28Z, 13s ago
  watchdog           the tunnel in place was built at 2026-09-23T22:43:58Z, 43s ago; the rebuild
                     interval in force is 5m0s; no rebuild is waiting to be retried
```

#### 機械向けの出力

`--json` は、人向けの表の写しではなく、診断そのものの模型を出す。
最上位はオブジェクトとし、`server doctor --json` とも `status --json` とも別の、このコマンド専用の模型とする (2026-09-23、所有者の決定)。
同じ事実を表すフィールドには `server doctor --json` ([10.2a 節](server-observations.md#102a-転送の診断-server-doctor)) と同じ名前と同じ値の語彙を使う (2026-09-23)。
運用者がスクリプトを共通にできるようにするためです。
形は次のとおりです。
例は、権限で証拠に届かない検査と総合判定を動かす検査の FAILED が同じ実行で成り立ち、終了コード 2 になる実行です。

```json
{"status":"unknown","checked_at":"...","data_dir":"/var/lib/wgft",
 "checks":[{"id":"host.privileges","status":"failed","reason":"permission_denied","evidence_unreachable":true,
            "group":"Host","label":"privileges","detail":"...","next":"..."},
           {"id":"agent.process","status":"failed","reason":"agent_not_running",...}],
 "history":{"available":false,"detail":"..."},"not_tested":[{"id":"...","detail":"..."}]}
```

各フィールドは次のとおりとする (2026-09-23)。

- `status`: 総合判定です。
  値は `ok`、`failed`、`unknown` で、報告を出した実行の終了コードの 0、1、2 に当たる。
  `failed` は総合判定を動かす検査に FAILED が 1 つ以上ある実行であり、`unknown` は終了コード 2 に倒す条件が成り立った実行です。
  両方が成り立つ実行は、終了コードと同じく `unknown` になります。
  `server doctor --json` の `status` と同じ名前にし、診断が成立しなかった実行には [10.2a 節](server-observations.md#102a-転送の診断-server-doctor)の UNKNOWN の語を当てる。
  証拠が判定に足りない状態という定義にそのまま当たるので、新しい語を作りません
- `checked_at`: 診断した時刻で、RFC 3339 の UTC です
- `data_dir`: この報告が答えるデータディレクトリであり、実際に調べたディレクトリの絶対パスを正規化した形で示します。
  同じパスを相対パスや `..` を含む形で指定しても、値は同じになります。
  設定ファイルを読めずに既定値を使った実行でも、実際に見たディレクトリを示します
- `checks[]`: 前掲の表の検査すべてを表の順に持ちます。
  実行の状態によって項目は消えない。
  各項目は `id`、`status`、`reason`、`evidence_unreachable`、`group`、`label`、`detail`、`next` を持ちます。
  `reason` は OK の検査では省く。
  `evidence_unreachable` は終了コード 2 に倒す条件に当たった検査だけが `true` として持ち、他の検査では省く。
  `next` は次に見るものを持たない検査では省く
- `history`: [10.2a 節](server-observations.md#102a-転送の診断-server-doctor)と同じ形で、`available` と `detail` を持ちます。
  `available` はこの版では常に `false` です
- `not_tested[]`: 試していない範囲であり、各項目は `id` と `detail` を持ちます。
  何も壊れていない実行でも必ず持ちます

`server doctor --json` の `probed` と `rules`、および検査ごとの `rule_id`、`agent`、`observed_at`、`causes`、`internal` は持ちません。
このコマンドはルールごとの経路をたどらず、観測の古さで状態を変えることもしないためです。
後から加えることは [7a.11 節](../compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の加算の規則に従います。

機械向けの保証は、最上位の `status`・`checked_at`・`data_dir`、`checks[]` の `id`・`status`・`reason`・`evidence_unreachable`、`history.available` です。
`checks[].id` の値は前掲の表のとおりであり、`checks[].status` の値は [10.2a 節](server-observations.md#102a-転送の診断-server-doctor)の 5 つであり、`checks[].reason` の値は次の表のとおりです。
最上位の `status` と、この 3 つの値は、[7a.11 節](../compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の規則に従う開いた集合として扱う。
値を増やすことだけができ、既存の値の名前の変更も意味の変更も互換ではありません。
読み手は知らない `id` を読み飛ばし、知らない `status` と `reason` を「不明」として扱わなければなりません。
`group`・`label`・`detail`・`next`、`history.detail`、`not_tested[]` の `id` と `detail` は人向けの文であり、保証の対象ではありません。

理由の符号は、1 つの符号が 1 つの事実だけを表す (2026-09-23)。
同じ符号が複数の検査に付くことはあるが、どの検査に付いても同じ事実を指す。
状態とは 1 対 1 ではありません。
`agent.credentials`、`agent.process`、`agent.control` が OK でないために SKIPPED になった検査は、その検査の符号をそのまま持ちます。
`agent.credentials` の失敗で試せなかった検査が `credentials_missing` を持ち、止まっているエージェントの稼働中専用の検査が `agent_not_running` を持つのは、この規則による。
この規則の外にある SKIPPED は、自分の事実の符号を持ちます。
中継が無いために SKIPPED になる `relay.listeners`、`relay.sessions`、`relay.refusals` は、トンネルが無い原因が何であっても `no_relay` を持ち、`tunnel.local` の符号を引き継がありません。
実行時の排他を取れなかった実行の SKIPPED は、`agent.control` が OK なので `runtime_state_busy` を持ちます。

| 理由の符号 | 表す事実 |
|---|---|
| `agent_not_running` | このデータディレクトリのロックを持つプロセスが無い |
| `lock_unreadable` | ロックファイルを読めず、エージェントが稼働中かどうかを判定できない |
| `credentials_missing` | `agent.json` が無い |
| `credentials_unreadable` | `agent.json` はあるが、権限で読めない |
| `data_dir_unreadable` | データディレクトリを権限で辿れず、`agent.json` があるかどうかを判定できない |
| `credentials_malformed` | `agent.json` を認証情報として読めない。無い場合と権限で読めない場合を除き、JSON として解釈できない場合と他の読み取りの誤りが当たる |
| `not_registered` | `agent.json` が恒久トークンを持たず、登録が済んでいない |
| `permission_denied` | エージェント自身が要る権限のどれかを、呼び出し元が持たない |
| `permission_not_determined` | エージェント自身が要る権限のどれかを、副作用なしには判定できない |
| `running_as_root` | root で実行したので、エージェントを動かす利用者が権限で証拠に届くかどうかを答えられない |
| `config_unreadable` | 設定ファイルを権限で読めず、その値に依る予測を示せない |
| `interfaces_unreadable` | このホストのネットワークインタフェースを読めない |
| `resolve_failed` | ホスト名をこのホストで解決できない |
| `no_last_state` | `agent.json` が最後に処理した全体状態を持たない |
| `no_wg_endpoint` | 記録された全体状態が WireGuard のピアの宛先を持たない |
| `control_socket_unreachable` | 稼働中のエージェントの制御ソケットに繋げない。ソケットのパスが長すぎる場合を除く |
| `control_socket_path_too_long` | 稼働中のエージェントの制御ソケットのパスが `sun_path` の上限を超えていて、原理的に繋げない |
| `doctor_unsupported` | 稼働中のエージェントが制御ソケットの `doctor` に対応していない |
| `doctor_failed` | 稼働中のエージェントが、自分の状態を組めなかったと答えた |
| `doctor_reply_unreadable` | 稼働中のエージェントの応答を読めない |
| `runtime_state_busy` | 稼働中のエージェントが、実行時の状態を守る排他を期限内に取れなかった |
| `reconnecting` | 制御ストリームが今つながっていない |
| `server_cert_mismatch` | 制御ストリームが今つながっておらず、直近の試みが server の証明書と登録のときに固定したハッシュとの不一致で終わった |
| `key_change_limited` | 制御ストリームが今つながっておらず、直近の試みが server の鍵の変更の頻度の上限による拒否で終わった |
| `no_threshold` | 値を示すだけで、その良し悪しを言う閾値をこのコマンドが持たない |
| `handshake_pending` | トンネルはあるが、ハンドシェイクがまだ成立していない |
| `full_state_pending` | トンネルが無く、稼働中のエージェントが全体状態をまだ持っていない |
| `tunnel_build_failed` | トンネルが無く、直近のトンネルの構築が失敗している |
| `no_tunnel` | トンネルが今無い。`tunnel.local` では、`full_state_pending` と `tunnel_build_failed` のどちらにも当たらない場合に使う |
| `tunnel_error_no_endpoint` | トンネルが誤りを報告していて、転送に使える解決済みのエンドポイントも持たない |
| `tunnel_error_endpoint_kept` | トンネルが誤りを報告しているが、解決済みのエンドポイントは保っている |
| `listener_error` | ルール 1 本以上の状態が `error` である。カーネルモードでは、直前の解決の結果で転送を続けているだけのルールを除く |
| `agent_disabled` | server がこのエージェントを無効にしている(仕様 [5.1 節](../control/registration.md#51-登録)) |
| `socket_buffer_below_requirement` | WireGuard の UDP ソケットの実効の受信か送信のバッファが、ユーザー空間モードの条件に届かない([7 節](../agent-dataplane.md#7-データプレーン自宅側)) |
| `socket_buffers_unreadable` | 稼働中のエージェントが、自分の WireGuard の UDP ソケットのバッファを測れなかった |
| `socket_buffers_not_reported` | 稼働中のエージェントが、WireGuard の UDP ソケットのバッファを答えない。測る前の版の実行ファイルで動いている |
| `not_measured_on_this_os` | エージェントの OS では WireGuard の UDP ソケットのバッファを測らない。測るのは Linux だけである([7 節](../agent-dataplane.md#7-データプレーン自宅側)) |
| `udp_accounting_stopped` | netstack の UDP の受信の会計が不変条件の違反を検出して、トンネルの UDP を止めた([7 節](../agent-dataplane.md#7-データプレーン自宅側)) |
| `udp_accounting_not_reported` | 稼働中のエージェントが、UDP の受信の会計の状態を答えない。会計を持つ前の版の実行ファイルで動いている |
| `no_relay` | 中継が今無い |
| `kernel_mode` | エージェントがカーネルモードで動き、この検査が見る対象を持たない |
| `userspace_mode` | エージェントがユーザー空間モードで動き、この検査が見る対象を持たない |
| `needs_cap_net_admin` | 呼び出し元が `CAP_NET_ADMIN` を持たず、カーネルの状態を直接読めない |
| `kernel_unreadable` | カーネルの状態を、権限の不足でない理由で読めない |
| `agent_lacks_cap_net_admin` | 稼働中のカーネルモードのエージェントが、実効の `CAP_NET_ADMIN` を持たない |
| `interface_missing` | エージェントの WireGuard インタフェースが無い |
| `interface_not_ours` | 同名のリンクが、今の鍵か 1 つ前の鍵を持つ WireGuard インタフェースでない |
| `interface_down` | エージェントの WireGuard インタフェースが down である |
| `peer_missing` | エージェントの WireGuard インタフェースに、server の公開鍵を持ち server のトンネルアドレスを AllowedIPs に含むピアが無い |
| `interface_differs` | エージェントの WireGuard インタフェースが、鍵、アドレス、MTU、keepalive、ピアの集合のどれかで宣言と違う |
| `route_not_via_interface` | server のトンネルアドレスへの経路が、エージェントの WireGuard インタフェースを通らない |
| `table_missing` | `table inet wgft_agent` が無い |
| `table_rows_missing` | `table inet wgft_agent` に、直近の公開の記録から組む行、チェーン、DNAT のうち、欠けると転送が止まるものが無い |
| `guard_rows_missing` | `table inet wgft_agent` に、直近の公開の記録から組む行とチェーンのうち、欠けても転送が止まらないもの (守りの行) だけが無い |
| `table_changed` | `table inet wgft_agent` に、直近の公開の記録に無い行かチェーンが加わっているか、記録から組む行が同じチェーンの別の位置にある |
| `publish_failed` | 稼働中のエージェントが直近の全体状態を公開できず、旧いテーブルが残っている |
| `ip_forward_off` | `net.ipv4.ip_forward` が 1 でない |
| `ip_forward_unreadable` | `net.ipv4.ip_forward` を読めない |
| `forward_policy_drop` | 他のテーブルの forward のチェーンが、既定でパケットを落とす |
| `rp_filter_strict` | `net.ipv4.conf.all.rp_filter` か `net.ipv4.conf.default.rp_filter` が 1、つまり strict である |

[7a.11 節](../compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の CLI の項は、`--json` を持つコマンドと列挙値を持つフィールドの一覧に `agent doctor` を含める。

#### 終了コード

| コード | 意味 |
|---|---|
| 0 | 総合判定を動かす検査に FAILED が 1 つも無い |
| 1 | 総合判定を動かす検査に FAILED が 1 つ以上ある |
| 2 | 報告を作れなかったか、診断に必要な証拠に権限で到達できず完全な判断ができなかった。引数の数が誤っている、知らないフラグを渡した場合、呼び出し元が権限で証拠に届かない場合が当たる (2026-09-23、所有者の決定) |
| 3 | 設定の誤り ([11a 節](../security/configuration.md#11a-設定の渡し方)) |

検査は、総合判定と終了コードへの効き方によって 3 つの層に分かれる (2026-09-23、所有者の決定)。

1. 総合判定を動かし、終了コード 1 に効く層。
   `agent.credentials`、`agent.process`、`tunnel.local`、`relay.listeners` です。
   カーネルモードでは `agent.credentials`、`tunnel.local`、`dataplane.interface`、`dataplane.table`、`host.forwarding` です。
   どちらのモードでも、直近の試みが鍵の変更の頻度の上限による拒否で終わった場合の `stream.connection` がこの層に入る (2026-10-03)
2. 権限で証拠に届かないときに終了コード 2 に倒す層。
   呼び出し元の権限の不足による `host.privileges` の失敗 (`permission_denied`)、`agent.credentials` が `agent.json` を権限で読めない場合とデータディレクトリを権限で辿れない場合、`agent.process` がロックファイルを権限で開けない場合、稼働中のエージェントの制御ソケットにファイルのパーミッションで繋げない場合、停止中のカーネルモードのエージェントのカーネルの状態を呼び出し元が `CAP_NET_ADMIN` を持たずに読めない場合 (`needs_cap_net_admin`) です。
   設定ファイルを権限で読めない場合は、`host.privileges` の失敗としてこの層に入ります。
   root で実行した場合の `host.privileges` の UNKNOWN と、稼働中のカーネルモードのエージェントが `CAP_NET_ADMIN` を持たない場合の `host.privileges` の FAILED (`agent_lacks_cap_net_admin`) は、この層に入りません。
   後者はエージェント自身が答えた事実であり、呼び出し元が証拠に届かなかったことを示さないためである (「カーネルモードの `host.privileges` と root の実行」の項)
3. どちらにも効かない層。
   残りの検査であり、所見としては必ず出すが、総合判定にも終了コード 2 にも数えません

権限で証拠に届かない場合とは、`agent doctor` をエージェントと同じ実行主体で動かすという前提が崩れている実行を指す。
層 2 の条件はいずれも、失敗の原因が呼び出し元の権限にあるのか、エージェント自身が転送を担えない状態にあるのかを区別できないため、診断できなかった側に倒す。
出力では、エージェントと同じ実行主体で実行し直すことを示す (2026-09-23、所有者の決定)。
root での実行し直しは案内しません。
root はデータディレクトリと `agent.json` をすべて読めるため、root で実行すると `host.privileges` はエージェント自身の権限について答えられず、前提の崩れそのものを検出できなくなる。
root で実行した場合の扱いは、前述の[「2 つの証拠の出どころ」](agent-evidence.md#2-つの証拠の出どころ)の項で定めた。

層 1 の FAILED と層 2 の条件が同じ実行で同時に成り立つ場合、終了コード 2 を優先する (2026-09-23、所有者の決定)。
終了コード 2 は診断の結果を信頼できないことを表します。
層 2 は推測で答えないために置いた層であり、診断が成立していないまま総合判定を終了コード 1 として返すことは、この層の趣旨と矛盾します。

層 2 に当たる実行でも、報告は出す (2026-09-23、所有者の決定)。
どこまで読めてどこから権限で読めなかったかを示すほうが、運用者は直せる。
そのかわり、終了コードの意味を「転送できない」ではなく「診断が成立しない」の側として分ける。
`host.privileges` 自体の状態は FAILED でよい。
状態の語と終了コードは別のものとして扱う。
この検査は層 1 に無いので、状態が FAILED でも終了コードは 1 にならず、呼び出し元の権限の不足による FAILED は層 2 として終了コード 2 になります。

UNKNOWN、NOT TESTED、SKIPPED だけでは 0 のままとします。
[10.2a 節](server-observations.md#102a-転送の診断-server-doctor)が定める同じ趣旨の規則は「UNKNOWN と NOT TESTED だけでは 0 のままとする」であり、SKIPPED を挙げていません。
`agent doctor` は稼働中専用の検査が SKIPPED になりうるため、この節では SKIPPED も 0 を保つ対象に加えます。
この規則は終了コード 2 にも及ぶ。
SKIPPED がいくつ並んでも終了コードは 0 のままであり、終了コード 2 は証拠そのものに権限で到達できなかった実行に限る。

`agent.json` が無いこと、まだ登録していないこと、中身が壊れていて JSON として読めないことは、2 ではなく `agent.credentials` の FAILED として 1 にする (2026-09-23、所有者の決定)。
どれもエージェント自身の状態についての事実であり、診断を始められなかった失敗ではないためです。
一方、`agent.json` があるのに権限で読めないことは 2 にする (2026-09-23、所有者の決定)。
呼び出し元がエージェントと同じ実行主体で動いていないために起きる失敗であり、エージェントが転送を担えるかどうかについては何も述べない。
この切り分けは、読み取りの誤りから `errors.Is` で `os.ErrNotExist` と `os.ErrPermission` を判定し、どちらでもなければ壊れた JSON として扱う形で行います。
`os.ErrPermission` は、ファイルがあって読めない場合と、途中のディレクトリを辿れない場合の両方で返る。
そこで `agent.json` 自身を stat し直し、stat も権限で拒まれれば、拒んでいるのはディレクトリであり有無は分からないとして `data_dir_unreadable` とする (2026-09-25)。
ファイルがあると述べると、無いファイルについて事実でないことを述べるためです。
層は `credentials_unreadable` と同じ 2 です。

`--json` は終了コードを変えない (2026-09-23)。
報告を出した実行の終了コードは、`--json` の最上位の `status` と同じ判定から決まり、`ok` が 0、`failed` が 1、`unknown` が 2 に当たる。
引数やフラグの誤りによる 2 と、設定の誤りによる 3 は、報告を作る前に止まります。
この場合は `--json` を付けても標準出力に JSON を出さず、誤りを標準エラー出力に書きます。

終了コード 1 が答える問いを、隣の 2 つと分けて書きます。
3 つとも問いが違う。

- `server doctor` の 1: ルールの転送の経路が壊れています
- `status` の 1: 配置全体に運用上の手当てが必要な劣化があります
- `agent doctor` の 1: このホストのエージェントが、今の状態では転送を担えない

[診断](README.md)
