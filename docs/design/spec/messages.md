# pubkey、state、heartbeat

stream のメッセージは 1 つの形 `Message` で表し、`type` で中身を選びます。
接続の手順と上限は [stream.md](stream.md) に、JSON の共通規則は [encoding.md](encoding.md) にあります。
意味と理由は[全体状態の配信とハートビート](../control/connection.md#52-全体状態の配信とハートビート)、[ハートビートと到達性](../control/heartbeat.md)、[全体状態の wire 形式](../control/state-wire.md)にあります。

## Message

| キー | 型 | 省略 | 載せるメッセージ |
| --- | --- | --- | --- |
| `type` | 文字列 | 省きません | すべて。`pubkey`、`state`、`heartbeat` のどれか |
| `public_key` | 文字列 | 空なら省きます | `pubkey` |
| `state` | オブジェクト | 不在なら省きます | `state` |
| `heartbeat` | オブジェクト | 不在なら省きます | `heartbeat` |
| `protocol_min` | 整数 | 不在なら省きます | `pubkey` |
| `protocol_max` | 整数 | 不在なら省きます | `pubkey` |
| `capabilities` | 文字列の配列 | 不在なら省きます。空の配列は `[]` と書きます | `pubkey` |

キーの順は表の順です。
読む側は、自分に関係の無いキーを読み飛ばします。

<a id="pubkey"></a>
## pubkey

agent が接続の直後に 1 通だけ送ります。

```json
{"type":"pubkey","public_key":"<44 文字の base64>","protocol_min":1,"protocol_max":1,"capabilities":[]}
```

- `public_key`:agent の WireGuard の公開鍵で、`agent.json` の `wg_private_key` から求めた値です
- `protocol_min`、`protocol_max`、`capabilities`:[版の交渉](stream.md#版の交渉)のとおりで、v1 の agent は常にこの値を送ります

v1 の agent が送る `pubkey` は 129 byte です。
server は最初のメッセージを 4096 byte まで読みます。
fixture は `testdata/spec/wire/pubkey.json` です。

<a id="state"></a>
## state

server が送る全体状態です。
差分ではなく、その agent に配る内容の全部を毎回送ります。

```json
{"type":"state","state":{"generation":42,"wg":{...},"rules":[...],"server_protocol_version":1,"server_capabilities":[]}}
```

### State

| キー | 型 | 省略 | 意味 |
| --- | --- | --- | --- |
| `generation` | 0 以上の整数 | 省きません | 世代。ルールの集合の全体に 1 つの数で、配る内容が変わると進みます |
| `wg` | オブジェクト | 省きません | WireGuard の設定 (`WGConfig`) |
| `rules` | 配列 | 省きません。v1 の server は空でも `[]` を書きます | その agent のルール (`AgentRule`) |
| `server_protocol_version` | 整数 | legacy v0 の agent には載せません | その接続で選んだ版 |
| `server_capabilities` | 文字列の配列 | legacy v0 の agent には載せません。空でも `[]` を書きます | server の機能。v1 は空です |
| `agent_disabled` | 真偽 | `false` なら省きます | server がこの agent を無効にしていること |

- `agent_disabled`:無効の間、server は `rules` のすべてを `enabled: false` の写しで送ります。
  agent が転送を止めるのは、この `enabled: false` によります。
  `agent_disabled` は agent 自身の診断 (`agent doctor`) のためだけにあり、守りには使いません
- 世代の比べ方:[stream.md](stream.md#全体状態を受けた-agent-の扱い)のとおり、接続の中だけで比べます

### WGConfig

| キー | 型 | 意味 |
| --- | --- | --- |
| `server_pubkey` | 文字列 | server の WireGuard の公開鍵 (base64、44 文字) |
| `endpoint` | 文字列 | server の WireGuard の `host:port`。`WGFT_WG_ENDPOINT` の値で、ホストは名前のままのことがあり、ポートは 10 進の数字です |
| `address` | 文字列 | agent のトンネルのアドレスと帯の長さ (`10.200.0.2/24` の形) |
| `mtu` | 整数 | トンネルの MTU。server の `WGFT_MTU` で、既定は 1420 です |
| `keepalive` | 整数 | WireGuard の persistent keepalive の秒数。v1 の server は常に 25 を送ります |
| `udp_timeout` | 整数 | VPS の `nf_conntrack_udp_timeout` の秒数 |
| `udp_timeout_stream` | 整数 | VPS の `nf_conntrack_udp_timeout_stream` の秒数 |

- 省略:`WGConfig` のキーは省きません
- UDP の timeout の 0:server は起動の直後に 2 つの値を読むまで 0 を送ることがあります。
  v1.x の古い server も 0 を送ります
- server のアドレス:全体状態は server のトンネルのアドレスを持ちません。
  agent は `address` の帯の先頭のホストのアドレス (`10.200.0.1`) を server のアドレスとみなします

各値を agent がどう使うか、0 と範囲の外の値をどう扱うかは tunnel.md (未作成、tunnel.md) にあります。

### AgentRule

| キー | 型 | 意味 |
| --- | --- | --- |
| `id` | 文字列 | ルールの ID。不透明な文字列で、128 byte 以下です |
| `proto` | 文字列 | `tcp` か `udp` |
| `listen_port` | 文字列 | `"2456"` か `"2456-2457"` の形のポートか範囲 |
| `target` | 文字列 | `host:port` の宛先。範囲のルールでは先頭のポートに当たります。259 byte 以下です |
| `enabled` | 真偽 | `false` のルールは転送しません |

- 省略:`AgentRule` のキーは省きません
- 配らない値:`vps_mode`、接続元の制限、レートの上限、`group`、`note` は配りません
- 範囲の写し方:`listen_port` の範囲の `p` 番目のポートは、`target` のポートに `p - 下端` を足したポートに写します。
  写した先が 65535 を超えるポートは転送しません
- `target` のホスト:IPv4 のアドレスかホスト名です。
  IPv6 のアドレスは server が保存の前に拒みます

### Go の性質:listen_port の読み方

`listen_port` は Go の `encoding.TextUnmarshaler` で読みます。
読めない値は、そのルールではなくメッセージ全体の読みの誤りになり、agent はその `state` を捨てます ([stream.md](stream.md#全体状態を受けた-agent-の扱い))。
読み方は次のとおりです。

- 形:最初の `-` で 2 つに分け、`-` が無ければ両端を同じ値にします
- 数:各部分の前後の空白を除き、10 進の符号の無い整数として読みます。
  先頭の 0 を受け、`+` を拒みます。
  0 と 65535 を超える値は誤りです
- 順:下端が上端より大きければ誤りです
- 書く形:単一のポートは `"2456"`、範囲は `"2456-2457"` です

Rust の `str::parse::<u16>` は `+` を受けるので、そのままでは Go の v1 と違う値を受けます。

<a id="heartbeat"></a>
## heartbeat

agent が送る自分の状態です。
送る契機は [stream.md](stream.md#ハートビートの送り方) にあります。

```json
{"type":"heartbeat","heartbeat":{"generation":42,"tunnel":{"state":"ok","endpoint":"203.0.113.10:51820","last_handshake":"2026-11-01T12:00:00.123456789Z"},"rules":[{"id":"r_01...","state":"ok"}]}}
```

### Heartbeat

| キー | 型 | 省略 | 意味 |
| --- | --- | --- | --- |
| `generation` | 0 以上の整数 | 省きません | 最後に適用した全体状態の世代。まだ無ければ 0 です |
| `tunnel` | オブジェクト | 省きません | トンネルの状態 |
| `rules` | 配列 | 省きません。空でも `[]` を書きます | ルールごとの状態 |

処理済みの世代は、ルールの一部が `error` でも進めます。
dataplane の全体の失敗で適用できなかった世代では進めません。

### TunnelStatus

| キー | 型 | 省略 | 意味 |
| --- | --- | --- | --- |
| `state` | 文字列 | 省きません | `ok` か `error` |
| `reason` | 文字列 | 空なら省きます | `error` の理由 |
| `endpoint` | 文字列 | 空なら省きます | 名前を解決した server の `ip:port` |
| `last_handshake` | 時刻 | 省きません | 今のトンネルの最終ハンドシェイク。成立していなければ `0001-01-01T00:00:00Z` です |

トンネルの理由のうち、server と `agent doctor` が文言で見分けるものは固定です。

| 理由 | 場合 |
| --- | --- |
| `handshake not established` | トンネルはあるが、ハンドシェイクがまだ成立していない |
| `no tunnel; full state not received` | 全体状態をまだ受け取っていない |
| `no tunnel; building it failed and will be retried` | トンネルの作成に失敗し、試し直しを待っている |
| `no tunnel; building it failed` | トンネルの作成が試し直さない失敗で終わった |
| `no tunnel` | 上に当たらない理由でトンネルが無い |
| `refused the wg configuration of generation <N>; the tunnel and rules stay as generation <M> left them: <誤り>` | カーネルモードの agent が届いた wg の設定を拒んだ |

トンネルが無いとき、agent は `rules` を `[]` にします。
上に当たらない `error` の理由は、トンネルの状態の読み取りの誤りの文言です。

### RuleStatus

| キー | 型 | 省略 | 意味 |
| --- | --- | --- | --- |
| `id` | 文字列 | 省きません | ルールの ID |
| `state` | 文字列 | 省きません | `ok` か `error` |
| `reason` | 文字列 | 空なら省きます | `error` の理由 |

- 並び:v1 の agent は `id` の byte の順に並べます
- 対象:agent が待ち受けを持つルールを報告します。
  `enabled: false` のルールは報告に載りません
- `error` の意味:待ち受けを開けない、TCP の宛先への試し接続の失敗、宛先の許可一覧による拒否のどれかです

### ルールの理由の語

server の `server doctor` は、agent が送ったルールの理由を部分文字列で分類します。
Rust の agent は、同じ場合の理由に次の語を含めなければなりません。
語を含めないと、`server doctor` はその理由を一般の `target_error` に分類します。

| 場合 | 理由に含める語 | v1 の agent の理由の例 |
| --- | --- | --- |
| 待ち受けを開けない | `bind failed`。`bind tcp ` か `bind udp ` でも当たります | `tcp/8080: bind failed: bind tcp 10.200.0.2:8080: port is in use` |
| 宛先の許可一覧が拒んだ | `WGFT_AGENT_ALLOW_TARGETS` か `is not allowed` | `tcp/8080: target 192.168.1.10:80 is not in WGFT_AGENT_ALLOW_TARGETS` |
| ブロードキャストとマルチキャストの宛先 | `the agent forwards only to unicast targets` | `udp/9000: target 192.168.1.255:9000 is the broadcast address of 192.168.1.0/24 on this host; the agent forwards only to unicast targets` |
| 名前の解決の失敗 | `name resolution`、`no such host`、`lookup `、`server misbehaving` のどれか | `tcp/8080: dial tcp: lookup nas.lan on 127.0.0.53:53: no such host` |
| 宛先が接続を拒んだ | `connection refused` | `tcp/8080: dial tcp 192.168.1.10:80: connect: connection refused` |
| 宛先が応えない | `did not answer`、`timeout`、`timed out` のどれか | `tcp/8080: target 192.168.1.10:80 did not answer within 2s` |
| 宛先に経路が無い | `no route to host` か `unreachable` | `tcp/8080: dial tcp 192.168.1.10:80: connect: no route to host` |
| ループバックの宛先 (カーネルモード) | `does not forward to loopback targets` | |
| ホストの転送の設定 (カーネルモード) | `net.ipv4.ip_forward`。値が分からなければ `its value is unknown` も | |
| 直前の解決の結果で転送を続けている (カーネルモード) | 名前の解決の失敗の語、`; still forwarding to <アドレス>`、` from the last successful resolution` の順 | |

- 例の書き方:v1 のユーザー空間モードの agent の理由は `<proto>/<port>: <誤り>` の形です。
  `<誤り>` の多くは Go の `net` の誤りの文言そのもので、形は保証の外です
- 判定の順:`server doctor` は表の下の 3 行のカーネルモードの語と許可一覧の語を、接続の誤りの語より先に見ます。
  語の照合と順は `internal/vpsd/doctor` の `targetReasonCode` が正本で、語の値は `internal/reasontext` にあります
- 名前の解決の失敗の文言:v1 の agent は、問い合わせごとに変わる送信元とサーバのソケットの組 (`read udp <送信元>-><サーバ>: `) を文言から除きます。
  除かないと同じ誤りが 30 秒ごとに状態の変化として報告されるためです

### 理由の切り詰め

agent は、トンネルとルールの理由を送る前に次の順で変換します。
ログには変換の前の理由を書きます。

1. 不正な UTF-8 の byte を、1 byte ごとに U+FFFD に置き換えます
2. 表示できない文字を escape に置き換えます。
   表示できない文字は Unicode の graphic でない文字で、C0 と C1 の制御文字、DEL、Cf (書式の制御、ゼロ幅の文字、双方向の上書き)、Zl、Zp、私用領域、未割り当ての文字を含みます。
   Zs の空白 (U+0020、U+00A0、U+3000 など) は置き換えません
3. 結果が 512 byte を超えたら、512 byte 以内の最後の文字の境目で切り、`... truncated` を足します。
   印は 512 byte の外に付きます

escape の形は Go の `strconv.QuoteRune` の引用符を除いた形です。

| 文字 | escape |
| --- | --- |
| U+0007、U+0008、U+000C、U+000A、U+000D、U+0009、U+000B | `\a`、`\b`、`\f`、`\n`、`\r`、`\t`、`\v` |
| 上以外の U+0000 から U+007F | `\x00` の形の 2 桁の小文字の 16 進 |
| U+0080 から U+FFFF | `\u0080` の形の 4 桁の小文字の 16 進 |
| U+10000 以上 | `\U000e0001` の形の 8 桁の小文字の 16 進 |
| 2 の手順に来た不正な UTF-8 の byte | `\xff` の形の小文字の 16 進。1 の手順の後には残りません |

- Go の性質:graphic の判定は Go の `unicode.IsGraphic` で、Go の `unicode` の表の版 (Go 1.27 では Unicode 17.0.0) に従います。
  Go 以外の実装は同じ版の表で判定します。
  版が違うと、新しく割り当てられた文字の扱いが変わります
- server の受信:v1.2.0 以降の server は、受けた理由に同じ 2 と 3 の変換を掛けてから保存します。
  変換は 2 回掛けても印の前の文言を変えません
- 他の文字列の上限:server はハートビートの `state` を 64 byte、`id` と `endpoint` を 128 byte、`reason` を 512 byte で同じように切ってから保存します。
  agent が送る値はどれもこの上限の内です
- JSON の大きさ:変換の後の理由は、書き換えを止めた JSON で印と引用符を含めて 1039 byte を超えません

fixture の `testdata/spec/wire/reasons.json` が、変換の前と後の理由の組を持ちます。

[agent と server の境目の仕様](README.md)
