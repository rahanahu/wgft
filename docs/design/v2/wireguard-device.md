# agent の WireGuard の device の層 (v2)

この文書は、v2 の Rust の agent が持つ WireGuard の device の層を定めます。
実装は crate の `crates/wgft-wireguard` です。
v1 の agent のユーザー空間モードでは、同じ役割を wireguard-go の `device.Device` が担います (`internal/dataplane/userspace/tunnel/tunnel.go`)。
v2 への移行の間、この crate は配布しません。
ラボと CI で動かすだけです。

## 位置付け

device の層は、UDP の datagram とトンネルの中の IPv4 の packet の間を変換します。
WireGuard のプロトコルの核は sanstun (crates.io、BSD-3-Clause) が持ちます。
sanstun はハンドシェイク、暗号、セッション、プロトコルの timer を持ち、socket、TUN、バッファ、ピアの表を持ちません。
device の層は sanstun が持たない部分を持ちます。
具体的には、ピアの表、暗号鍵の経路表 (AllowedIPs)、endpoint、ハンドシェイクを待つ packet、出力のキューです。

TCP と UDP の中継の層 (Rust の wgstack と制御プレーン) はこの crate の上に載ります。
この crate はそれらに依存しません。

## sanstun の隔離

sanstun を使うのは `src/protocol.rs` の 1 つの module と、その子の `src/sanstun_compat.rs` だけです。
`sanstun_compat` は sanstun の振る舞いへの手当てを集めた module です ([sanstun の振る舞いへの手当て](#sanstun-の振る舞いへの手当て))。
`protocol` の module は sanstun の型を外に出さず、wgft の型 (鍵、ピアの番号、バイト列、捨てた理由) だけで device の層と話します。
crate の公開の API にも sanstun の型は現れません。

差し替えのための trait と 2 つ目の実装は作りません。
所有者の決定に従います。
sanstun を別の実装に替える必要が出た場合は、`protocol.rs` を書き直します。

## sans-IO の形

`Device` は sans-IO です。
中にスレッド、実の時計、socket、乱数の源を持ちません。

入力は次の 3 つで、どれも呼び手が今の時刻 (`Instant`) を渡します。

| 入力 | 関数 | 中身 |
| --- | --- | --- |
| UDP の datagram | `handle_datagram(now, from, datagram)` | 届いた datagram と送信元のアドレス |
| トンネルの中の packet | `handle_packet(now, packet)` | トンネルの側から送る IPv4 の packet |
| timer | `handle_timeout(now)` | ハンドシェイクの再送、鍵の更新、keepalive、期限切れ |

出力は呼び手が `poll_*` で取り出します。

| 出力 | 関数 | 中身 |
| --- | --- | --- |
| 送る datagram | `poll_transmit()` | 宛先のアドレスと WireGuard の message |
| トンネルへ渡す packet | `poll_packet()` | 検査を通り、詰め物を切った IPv4 の packet |
| event | `poll_event()` | ハンドシェイクの受け付け、セッションの確立、endpoint の変化、ピアの期限切れ |
| 次に起こす時刻 | `poll_timeout()` | 次に `handle_timeout` を呼ぶ時刻 |

呼び手は、入力を 1 つ渡すたびに出力を取り出します。
取り出さない出力はキューの上限まで溜まり、溢れたものは捨てて数えます。

状態の読み出しは `peer_status` (endpoint、最後のハンドシェイクの時刻、送受信のバイト数)、`drops` (捨てた理由ごとの数)、`held` (キューが今持つ量) です。
制御プレーンが endpoint を引き直したときは `set_endpoint` で渡します。

### 時刻

時刻は呼び手が渡す単調な `Instant` だけを使います。
試験は基準の `Instant` に経過時間を足した偽の時計で回します。
渡された時刻が前の時刻より戻った場合、device は前の時刻を使い、sanstun には戻った時刻を渡しません。

ハンドシェイクの開始の message は壁時計の時刻 (TAI64N) を含みます。
再起動の前後でこの値が戻ると、相手は新しい開始を古い開始の再送とみなして捨てます。
この挙動は試験 `a_restarted_agent_needs_a_later_wall_clock` で確かめています。

印の秒は、Linux の WireGuard と wireguard-go と同じく 2^62 + 10 に Unix 時刻を足した値です。
sanstun 0.1.0 は 2^62 + 37 を足すので、そのままでは印が 27 秒進みます。
進んだ印を受けた server は、同じ鍵の Go の agent やカーネルモードの agent に戻したとき、その開始を古いものの再送として 27 秒の間捨てます。
sanstun は Unix 時刻を呼び手から受けるので、渡す時刻から 27 秒を引き、印を標準の値に揃えます (`sanstun_compat::stamp_base`)。
device の API の Unix 時刻 (`unix_floor` と `unix_high_water`) は、引く前の本当の Unix 時刻のままです。
試験 `initiations_carry_the_standard_tai64n_label` が、sanstun の相手が読んだ印の秒を確かめています。

製品の `Device::new` は、作成の時に壁時計を 1 回だけ読み、呼び手が渡す床 (`unix_floor`) の 1 秒後と比べて大きい方を印の基準にします。
床は、前の実行の `Device::unix_high_water` を呼び手が保存した値です。
`unix_high_water` は、それまでに付けた印の上限です。
呼び手は、正常な終了の時に `unix_high_water` を保存します。
動いている間は、保存の間隔を足した `unix_high_water + 間隔` を間隔ごとに保存します。
`unix_high_water` をそのまま定期的に保存するだけでは、落ちた時に、最後の保存の後に付けた印が床を超えます。
保存した床を渡せば、壁時計が戻った後の再起動でも、開始は相手に受け付けられます。
2^40 秒を超える Unix 時刻は壊れた時計とみなし、`ConfigError` で拒みます。
壁時計と乱数を読むのは、この作成の時だけです。

### 乱数

鍵の交換の一時鍵、index、cookie の秘密、timer の揺らぎは、すべて 32 バイトの種から作ります。
製品の `Device::new` は、オペレーティングシステムの乱数 (getrandom) から毎回新しい種を作ります。
種と Unix 時刻を呼び手が渡す `Device::with_seed` は、試験と crate の feature の `deterministic` だけで使えます。
試験と fuzz は固定の種を使い、同じ種から同じバイト列が出ることを確かめています。

### セッションの有無とハンドシェイクの開始

データプレーンは、device がピアとの使えるセッションを持つ間だけ上の層から packet を引き、持たない間は device にハンドシェイクを始めさせます ([データプレーンの駆動](wgstack-rs.md#1-回の起床))。
このための口は次のとおりです。
送る datagram の待ち行列が空かは、データプレーンが `poll_transmit` で取り出し切ったことで知ります。

- `has_session(peer, now)`:今のセッションで packet を待たせずに暗号にできるかを返します。
  sanstun はこの判定を公開しないので、sanstun が送信に使うセッションの条件を公開の値から写します。
  条件は、トンネルが期限切れでなく、今のセッションがあり、その年齢に `KEEPALIVE_TIMEOUT` を足して 180 秒以下であることです。
  sanstun はセッションの役を公開しないので、開始の側の条件を応答の側にも当てます。
  このため、応答の側のセッションの最後の `KEEPALIVE_TIMEOUT` の間は、まだ送れても偽を返し、データプレーンは新しいハンドシェイクを始めます。
  応答の側から新しいハンドシェイクを始めない sanstun の性質 ([起動、再試行、期限切れ](#起動再試行期限切れ)) を、送るものがあるときにも補います。
  送信の数の上限 (2^64 から 2^13 を引いた数) は見ません。
  真を返した後に暗号にできなかった packet は、ハンドシェイクを待つ待ち行列に入ります
- `start_handshake(now, peer)`:セッションの無いピアに packet を送ったときと同じく、ハンドシェイクを始めて開始の message を送る待ち行列に入れます。
  進行中のハンドシェイクがあるとき、ピアが endpoint を持たないとき、知らない鍵のときは何もしません

試験 `has_session_follows_the_handshake_and_the_session_age` と `a_responder_session_counts_as_gone_before_it_expires` が、開始の側と応答の側の境目の 170 秒の前後の値を確かめています。

## v1 の設定との対応

v1 の agent は wireguard-go に次の UAPI の設定を渡します (`tunnel.go` の `New`)。
`DeviceConfig::agent` は同じ情報を wgft の型で持ちます。

| v1 の UAPI | v2 の `DeviceConfig` | 値 |
| --- | --- | --- |
| `private_key` | `private_key` | agent.json の `wg_private_key` (標準の base64) |
| `public_key` | `peers[0].public_key` | server の公開鍵 |
| `allowed_ip` | `peers[0].allowed_ips` | server のトンネルのアドレスの /32 だけ |
| `persistent_keepalive_interval` | `peers[0].persistent_keepalive` | server が送る値。既定は 25 秒 |
| `endpoint` | `peers[0].endpoint` | 解決した server のアドレス |
| (TUN の MTU) | `mtu` | 1420。送る packet の上限は 16 の倍数に切り下げた 1408 ([MTU と詰め物](#mtu-と詰め物)) |

ピアは server の 1 つだけです。
preshared key は v1 が使わないので持ちません。

`Device::new` は設定を確かめ、範囲の外の値を `ConfigError` で拒みます。
persistent keepalive は `wg` と同じ 1 から 65535 秒です。
キューの上限は、件数が 65536 まで、バイト数が 256 MiB までです。
ハンドシェイクを待つ packet のバイト数の上限は件数と MTU の積で、積が溢れるか 256 MiB を超える設定も拒みます。
timer の上書きは試験のためのもので、0 を拒み、`REKEY_ATTEMPT_TIME` は 540 秒まで、`REKEY_TIMEOUT` と `KEEPALIVE_TIMEOUT` の和は 180 秒までです。
この範囲の外の値は sanstun の前提に反し、debug の build では sanstun の検査が panic します。

ピアの表は、公開鍵からピアを引く表と、受信の index からピアを引く表の 2 つを持ちます。
暗号鍵の経路表は prefix の長さごとの hash の表で、1 回の引きはピアの数に依りません。
server の役で多くのピアを持つ形は、この 2 つの表と経路表のまま足せます。
server の役は実装していません。

## sanstun の呼び手の責任

sanstun の README は、sans-IO のために sanstun が果たせない責任を呼び手に求めます。
device の層は次のように果たします。

| 責任 | 果たし方 | 置き場所 |
| --- | --- | --- |
| 暗号鍵の経路表 | 送信は宛先の最長一致でピアを選びます。受信は復号した packet の送信元を引き、送ってきたピアと一致しないものを捨てます | `device.rs`、`allowed_ips.rs` |
| ハンドシェイクの振り分け | 開始の message の静的公開鍵が設定したピアのものでなければ捨てます。知らない鍵のためにトンネルを作りません | `protocol.rs` |
| endpoint の更新 | 認証した message の後だけ、その datagram の送信元に移します。どの message で移すかはピアの `Roaming` が決めます (下の節) | `device.rs` |
| キューの上界 | 持つものすべてに件数とバイト数の上限を置きます (次節) | `queue.rs`、`device.rs` |
| 中身の検査 | IPv4 のヘッダの版、ヘッダ長、全長を確かめ、全長で詰め物を切ります | `ip.rs` |
| 誤り | 相手には何も返さず、理由ごとに数えます。cookie の返事だけはプロトコルの一部として送ります | `protocol.rs`、`drops.rs` |
| 時刻 | 単調な時刻を使い、戻った時刻を sanstun に渡しません | `device.rs` |
| 乱数 | 呼び手が渡す種だけを使います | `device.rs` |

### endpoint を動かす message

WireGuard は、認証したハンドシェイクかデータを受けるたびに、ピアの endpoint をその送信元に移します。
sanstun がハンドシェイクの開始の再送を見分ける記録 (開始の時刻の最大) はプロセスの中だけにあり、再起動で消えます。
再起動の後は、攻撃者が記録しておいた server の古い開始も認証を通ります。
WireGuard の規則のままでは、その開始の送信元へ endpoint が移り、agent の送信は攻撃者へ向かい続けます。

そこで、ピアごとの `Roaming` で endpoint を動かす message を選びます。

- `Roaming::Any`:WireGuard の規則です。
  endpoint をピアから知る server の役のためにあります。
- `Roaming::NotByInitiation`:agent が server に使う規則で、`DeviceConfig::agent` が選びます。
  データと keepalive の受け付け、こちらが始めたハンドシェイクへの応答では endpoint を動かします。
  相手からの開始では動かさず、応答だけをその送信元へ返します。
  ピアが期限切れになると、endpoint を設定した値に戻し、`EndpointChanged` で知らせます。

こちらが始めたハンドシェイクへの応答は、こちらの一時鍵に答えるので、古いものの再送ではありません。
データと keepalive は再送の窓で古いものを捨てます。
試験 `a_replayed_server_initiation_after_an_agent_restart_does_not_move_the_endpoint` と `the_agent_returns_to_the_configured_endpoint_when_the_server_expires` がこの規則を確かめています。

### 中身の検査

トンネルが運ぶのは IPv4 だけです。
復号した IPv4 でない packet は捨てます。
IPv4 の断片は再組み立てせず、そのまま渡します。
再組み立てと[packet の検査](../userspace/packet-validation.md)は上の層が行います。
v1 で wireguard-go が netstack の TUN の Write に渡したときと同じ分担です。
ヘッダの checksum は確かめません。
wireguard-go と Linux の WireGuard も確かめず、packet を受け取る IP の層が確かめます。

### MTU と詰め物

WireGuard はデータの message の平文を 16 バイトの倍数まで 0 で詰めます。
論文 (5.4.6 節)、wireguard-go、Linux の WireGuard は、詰めた長さを MTU で止めます。
sanstun 0.1.0 は MTU を知らず、常に 16 の倍数まで詰めます。
このままでは、MTU 1420 のちょうど 1420 バイトの packet が 1424 バイトに詰められ、datagram は 1452 バイトでなく 1456 バイトになります。
MTU を外側の経路の限度に合わせて選んだ場合 (例えば IPv6 の外側の経路の 1420) は、超えた分で外側の packet が断片化するか捨てられます。

そこで device は、送る packet の上限 (`Device::mtu`) を設定の MTU を 16 の倍数に切り下げた値にします (`sanstun_compat::inner_mtu`)。
1420 なら 1408 です。
詰めた後の平文は設定の MTU を超えず、datagram は設定の MTU に 32 バイトを足した長さ以下になります。
上の層 (wgstack の核と TUN の殻) にはこの値を渡すので、TCP の MSS は 1368 になり、1380 バイトを超える UDP の datagram は核が断片に分けます。
費用は packet ごとに最大 15 バイトの中身です。
v1 の agent は wireguard-go の上で 1420 を使うので、MSS は 12 バイト小さくなります。
MSS が小さくなる向きの違いなので、server の側に MSS のクランプは要りません ([tunnel.md の設定の対応](../spec/tunnel.md))。
試験 `padding_never_takes_a_data_message_past_the_mtu` が、576 から 9216 の MTU で datagram の長さを確かめています。

送信の packet が `Device::mtu` より長い場合は捨てます。
受信の packet の長さには MTU の上限を置きません。
Linux の WireGuard と wireguard-go と同じ扱いです。
受信の packet は、詰め物を除いた長さの新しいバッファに写してから渡すキューに入れます。
キューはバイト数を割り当てた容量で数えるので、短い packet を長い詰め物で送られても、キューの上限を超えて持ちません。

## キューと上界

`Device` の `Debug` の出力は、ピアの数、キューの件数とバイト数、捨てた数だけで、packet の中身を出しません。

暗号の処理は、入力を受けたその呼び出しの中で済ませます。
暗号の処理を別のスレッドへ渡すキューは持ちません。
sanstun は復号を別のスレッドへ回せる形の API を持ちますが、agent のピアは 1 つなので並列にする利点が小さいためです。
並列にする場合は、復号を待つ仕事のキューにも件数とバイト数の上限を置きます。

device が呼び出しの間に持つものと、既定の上限は次のとおりです (`Limits`)。

| 持つもの | 件数の上限 | バイト数の上限 | 溢れたとき |
| --- | --- | --- | --- |
| ハンドシェイクを待つ送信の packet (ピアごと) | 128 | 128 × MTU | 古いものから捨てます |
| 送る datagram | 256 | 512 KiB | 新しいものを捨てます |
| トンネルへ渡す packet | 256 | 512 KiB | 新しいものを捨てます |
| event | 64 | | 古いものから捨てます |

ハンドシェイクを待つ packet の 128 は、Linux の WireGuard と wireguard-go の `MAX_STAGED_PACKETS` と同じ数です。
古いものから捨てる扱いも Linux と同じです。

ピアが 1 つの agent では、device のキューが持つバイト数の上界は次の和です。

- ハンドシェイクを待つ packet:128 × 1420 バイト (約 178 KiB)
- 送る datagram:512 KiB
- トンネルへ渡す packet:512 KiB

このほかに sanstun の状態と、1 回の呼び出しの中で使う一時的なバッファがあります。
一時的なバッファは復号に使う datagram 1 つ分で、中身を写した後、呼び出しが返る前に解放します。
sanstun の状態は、設定したピアの数と、作り直したトンネルの index に比例します。
sanstun が設定に無い鍵のために状態を増やさないことは、sanstun の試験 (`initiations_from_unknown_peers_leave_no_state`) が確かめています。
上の和に sanstun の状態を足した値は測っていません。

## 起動、再試行、期限切れ

sanstun の persistent keepalive は、使えるセッションがあるときだけ送ります。
sanstun は通信の有無に依らず間隔ごとに送ります。
wireguard-go の persistent keepalive は、ピアへ送るか、ピアから認証した packet を受けるたびに間隔だけ先へ延びる timer です。
通信の間に sanstun が足す keepalive は、間隔ごとに 32 バイトの datagram が 1 つ増えるだけで、害はありません。
外から止めるには、sanstun が暗号化した keepalive を捨て、こちらの timer の期限に送り直す必要があります。
sanstun は keepalive を送る口を公開しないので送り直せず、捨てると外向きの通信が最大で間隔の 2 倍まで途切れます。
このため受け入れた違いとして残します。
期限が来たときにセッションが無ければ、wireguard-go はハンドシェイクを始めます。
device の層はこの timer をピアごとに持ちます。

- 起動:persistent keepalive と endpoint を持つピアの期限を、作成の時刻に置きます。
  最初の `handle_timeout` でハンドシェイクを始めます。
- 期限:sanstun の timer を先に進めます。
  使えるセッションがあれば、sanstun の keepalive の送信が期限を延ばします。
  それでも期限が来ていれば、間隔の間なにも送っていないので、ハンドシェイクを始めます。
- 期限切れ:sanstun が接続の期限切れ (`REKEY_ATTEMPT_TIME` の 90 秒の間に応答が無い、または最後のハンドシェイクから 540 秒) を知らせたら、そのピアの状態と待っている packet を捨て、同じ設定の新しいトンネルに替えます。
  期限は keepalive の間隔の後に置き直します。
- 送信:セッションの無いピアへの packet は、待たせてハンドシェイクを始めます。

### ハンドシェイクの開始の間隔と打ち切りの後の休止

論文 (6.1 節) は、ハンドシェイクの開始を `REKEY_TIMEOUT` (5 秒) に 1 回より多く送らないと定めます。
wireguard-go と Linux の WireGuard は、前の開始か応答の送信から 5 秒が経つまで新しい開始を送りません。
sanstun は進行中のハンドシェイクを 1 つに保つだけで、この間隔を持ちません。
agent のデータプレーンは使えるセッションが無い間、起きるたびに `start_handshake` を呼びます。
このため、90 秒の再試行の打ち切りでトンネルを取り替えた同じ起床で次の開始を送り、開始の間隔が 2 秒前後に縮んでいました。

device の層は、自分が始める開始 (`start_handshake`、セッションの無いピアへの packet、keepalive の期限) に次の規則を当てます。

- 間隔:ピアへ最後に開始か応答を送ってから `REKEY_TIMEOUT` が経つまで始めません。
  sanstun の timer が送る再送と鍵の更新は、sanstun が進行中の開始から間隔を取るので、そのまま送ります。
- 休止:接続の期限切れ (使ったトンネルの再試行の打ち切りか鍵の期限切れ) の後は、keepalive の間隔だけ `start_handshake` と keepalive の期限による開始を控えます。
  論文の規則 (打ち切りの後は新しいデータまで始めない) に合わせます。
  データの packet は休止の中でも開始を促し、間隔の規則だけを受けます。
  wireguard-go と同じです。
  keepalive を持たないピアには休止を置きません。
- 控えた要求:規則で控えた要求は覚えておき、許される時刻に `handle_timeout` が行います。
  `poll_timeout` はその時刻を含みます。
  その時までにセッションができていれば (相手が始めたハンドシェイクなど) 捨てます。

server が始めたハンドシェイクに答えた直後は、server の確認が届くまで agent のセッションは使えません。
前はこの間に agent が自分の開始を重ねていましたが、応答も間隔に数えるので、確認が先に届きます。
試験 `initiations_are_paced_and_pause_after_the_peer_gives_up`、`data_starts_a_handshake_during_the_pause_but_not_within_the_rekey_timeout`、`answering_the_server_holds_back_an_own_initiation` が確かめています。

### passive keepalive

論文 (6.5 節)、wireguard-go、Linux の WireGuard は、返事をしていない最初のデータの受信から `KEEPALIVE_TIMEOUT` (10 秒) の間なにも送らなければ keepalive を 1 つ送ります。
後から届いたデータでこの期限は延びません。
sanstun 0.1.0 は、データを受けるたびに期限を受信の時刻から 10 秒後へ延ばします。
10 秒より短い間隔で片向きのデータ (server から agent への UDP など) が届き続けると、sanstun は keepalive を送りません。
相手は返事の無いデータの 15 秒後に新しいハンドシェイクを始めるので、Linux の server は 15 から 25 秒ごとにハンドシェイクを繰り返します。
これは規則からの帰結で、ラボでは観測していません。
sanstun は keepalive を送る口を公開せず、空の平文の暗号化を拒みます。

device の層は、返事をしていない最初と最後のデータの受信の時刻をピアごとに持ちます (`sanstun_compat::PassiveKeepalive`)。
sanstun の送信の記録が進む呼び出し (データの暗号化、開始、応答、keepalive) で消します。
最初の受信から `KEEPALIVE_TIMEOUT` が経っても sanstun が送っていなければ、その 1 回の timer の呼び出しの間だけ、公開の `set_keepalive_timeout` で値を最後の受信からの経過に縮めます。
sanstun の passive keepalive の期限が今になり、sanstun が keepalive を送ります。
呼び出しの後で元の値に戻します。
縮めた値が sanstun 0.1.0 の中で効く箇所と、どれも余計な送信を生まない理由は `PassiveKeepalive::force` の文書に書きました。
この方法は sanstun 0.1.0 の timer の作りに依ります。
sanstun を上げるときは、試験 `one_way_data_gets_a_passive_keepalive_within_the_keepalive_timeout` がこの規則を確かめ直します。
この試験は、片向きのデータの間に agent が 11 秒より長く黙らないことと、server が新しいハンドシェイクを始めないことを確かめます。

server が始めたセッションでは、agent は応答の側です。
応答の側のセッションは 180 秒で使えなくなり、sanstun は応答の側から新しいハンドシェイクを始めません。
Linux の WireGuard の server は、送るデータが無ければハンドシェイクを始めません。
上の期限の規則が、この場合に agent の側からハンドシェイクを始めます。
試験 `an_idle_responder_keeps_contacting_the_server` は、600 秒の間に agent の送信が 40 秒より長く途切れないことを確かめています。

応答しない server に対しては、5 秒ごとの再送が 90 秒続き、keepalive の間隔の休止の後に同じ再送が始まります (下の「ハンドシェイクの開始の間隔と打ち切りの後の休止」)。

sanstun は、ハンドシェイクを一度もしていないトンネルも作成から 540 秒で期限切れにします。
期限の切れたトンネルはハンドシェイクを受けないので、device の層は同じように取り替えます。
ハンドシェイクを始めも受けもしていないトンネルの期限切れは、`PeerExpired` で知らせません。

server が再起動してセッションを失った場合、agent の keepalive だけでは新しいハンドシェイクが始まりません。
v1 の agent は keepalive の間隔ごとにトンネルの中で ping を送り、返事の無いデータの 15 秒後に始まるハンドシェイクで回復します (`tunnel.go` の `Run`)。
v2 でも制御プレーンがこの ping を送ります。
device の層の試験 `a_restarted_server_is_reached_again_by_traffic` は、この形の回復を偽の時計で確かめています。

## 試作の外側の殻 (Linux の TUN)

crate の `crates/wgft-wireguard-tun` は、`Device` を Linux の TUN と UDP の socket と tokio の event loop で動かす薄い殻です。
ライブラリとして `spawn` と `Handle` (状態、endpoint の変更、socket の付け替え、event、停止) を持ち、同じ名前のバイナリを持ちます。
ラボの試験と試作だけに使い、配布しません。
Linux 以外では `spawn` が `Unsupported` の誤りを返します。

agent はこの殻を使わなくなりました。
agent はデータプレーンのスレッドで device の層と Rust の wgstack の核を直接動かします ([Rust の agent の置き換えの設計のデータプレーンのスレッドと送る経路](agent-parity.md#データプレーンのスレッドと送る経路))。
殻は、device の層を Linux の WireGuard と wireguard-go に照らす `lab/wg-interop.sh` の道具として残し、ラボの一式が Rust の agent で通った後に消すかを決め直します。
以下はその道具としての作りと、TUN の試作の agent が使っていた間の判断の記録です。

TUN の試作の agent は、Rust の wgstack ができるまで、この殻の TUN を通してカーネルの TCP/IP stack を使いました。
ラボの VM の中で、agent の中継はカーネルの socket を開きます。
使い捨てのユーザー空間の TCP の stack は作りません。
理由は 2 つです。
1 つは、この段の目的が WireGuard の device の層と wire の相互運用を確かめることで、TCP の stack はその対象ではないためです。
もう 1 つは、使い捨ての stack の試験と修正の費用が、Rust の wgstack ができた時点で無駄になるためです。
この選択は試作の間だけのもので、v2 の agent のユーザー空間モードは TUN を使いません。

TUN の先のカーネルは、受け取った packet をホストのすべてのサービスへ渡し、転送が有効なら LAN へも送ります。
server がホストの別のサービスへ届かないように、殻は復号した packet を TUN へ書く前に呼び手の filter に通します。
filter は packet ごとに、渡す、捨てる、返事を送る (例えば規則の無いポートへの TCP の RST) のどれかを決めます。
返事は TUN から来た packet と同じく `Device::handle_packet` に入れます。
何を通すかの判断は制御プレーンが持ち、殻は filter を呼んで数えるだけです。
TUN から device への向きは filter に通しません。

### 殻の経路

乗っ取られた server がトンネルを通ってホストの別のサービスや LAN へ届かないように、殻は経路を次のように絞ります。

- main の表を変えません。トンネルのアドレスは /32 でリンクに付けるので、アドレスの帯を TUN へ向ける経路はできません。
  server が帯の広いアドレスを渡しても、LAN のルータのような帯の中のアドレスが TUN へ向くことはありません。
- server の /32 は専用の表 (既定は 5180) に入れ、`from <トンネルのアドレス> lookup <表>` の rule (既定の優先度は 5180) でだけ引きます。
  agent の中継の socket と ping の socket はトンネルのアドレスに bind するので、この rule に当たります。
  表の番号は wg-quick の既定の 51820 を避けました。
- 次の優先度の `from <トンネルのアドレス> unreachable` の rule で、トンネルのアドレスから表に無い宛先への通信を main の表へ落としません。
- その次の優先度の `iif <TUN> blackhole` の rule で、TUN から来て、このホスト宛てでないものを捨てます。
  このホスト宛ては優先度 0 の local の表で先に決まります。
  IPv4 の転送が有効なホストでも、トンネルから LAN へは届きません。
  殻は IPv4 の転送を変えません。
- 3 つの rule は `protocol kernel` で足します。
  systemd-networkd は、自分の設定に無い rule を起動し直しや reconfigure で消しますが、`kernel` の rule には触れません。
- 足す前に、前の実行が残した同じ rule を消します。
  それでも 3 つの優先度のどれかにほかの rule が残っているか、専用の表に経路があれば、ほかのソフトのものなので、混ぜずに止まります。
  トンネルのアドレスが既にこのホストにある場合も止まります。
  殻が止まるとき (設定の途中で失敗したときを含む) にも消します。
  表の経路はリンクとともに消えます。
- トンネルのアドレス以外を宛先にする packet は、filter の前に捨てて `wrong_destination` で数えます。
  server はそうした packet を送らないので、数が増えるのは server が乗っ取られたか壊れた兆しです。
  filter が捨てた数と device が捨てた数 (`Drops`) も、後の doctor が示せるように `Status` に出します。

strict の rp_filter でも受信が通ることは、`lab/wg-interop.sh` が strict にして確かめます。

TUN は `IFF_TUN_EXCL` で作り、同じ名前の持続する TUN が既にあれば付かずに失敗します。
`ip` は PATH を使わず、root が持ちほかの利用者が書けないシステムの場所 (`/usr/sbin`、`/sbin`、`/usr/bin`、`/bin`) から探します。
殻は TUN を閉じるときにリンクを消します。
カーネルが、持続の印の無い TUN のリンクを記述子とともに消すためです。

filter の panic は、その packet を捨てて数えます。
filter が packet ごとに panic しても出力が溢れないように、殻は filter の中の panic を 1 分に 1 行だけ書く panic の hook を、元の hook の前に差し込みます。
`panic = "abort"` で build したときは、プロセスが終わります。
TUN の読み出しの誤りなどでループが終わると、`Handle::finished` が解け、`Handle::stop` がその誤りを返します。
agent はトンネルを作り直します。

`bind_to_device` は socket に `SO_BINDTODEVICE` で TUN を結び付けます。
agent は待ち受けと ping の socket に使えます。

## 試験

- 単体の試験:鍵、prefix、経路表、IPv4 の検査、キュー。経路表は wireguard-go の `TestTrieIPv4` (Linux の `selftest/allowedips.h` から移したもの) の場合を写し、素朴な最長一致の模型との一致を proptest で確かめます。
- device の試験:2 つの `Device` を偽の時計と手で運ぶネットワークで向かい合わせます。
  ハンドシェイク、双方向のデータ、詰め物の除去、AllowedIPs の外の送信元、経路の無い宛先、MTU、IPv4 でない中身、誤りに返事をしないこと、再送された datagram、ハンドシェイクの開始、応答で endpoint が動かず返事もしないこと、roaming、知らない鍵、詰め物の長い packet の保持量、待つ packet の上界と順序、キューの上界、鍵の更新、persistent keepalive、応答の側で待つ間の keepalive の規則、期限切れと再試行、一度も使わなかったトンネルの期限切れ、timer の短縮、両側の再起動、時刻の戻り、決定性、設定の誤りと範囲の外の値を確かめます。
- fuzz:`crates/wgft-wireguard/fuzz` の `inbound` です。
  本物の相手の datagram を壊したもの、任意のバイト列、相手が検査を通さずに暗号化した任意の中身を agent の側に渡し、時計を進めます。
  任意の中身は crate の feature の `fuzzing` が開ける口で暗号化します。
  panic しないことと、持つものが `Limits` の中にあることを毎回確かめます。
  cargo-fuzz と nightly が要ります。
  `build-corpus` は、ハンドシェイクを済ませてデータを往復させる操作の列を種として書きます。

```sh
cd crates/wgft-wireguard/fuzz
cargo run --bin build-corpus
cd ..
cargo +nightly fuzz run inbound -- -max_len=12000
```

Linux の WireGuard と wireguard-go との相互運用は、この crate の上に積んだ TUN の殻と `lab/wg-interop.sh` で確かめます。

## sanstun の振る舞いへの手当て

sanstun 0.1.0 の振る舞いのうち、WireGuard の仕様と違い、外から直せるものは `src/sanstun_compat.rs` に集めて直します。
sanstun は改変しません。
手当てはそれぞれ 1 つの const か関数か型で、sanstun の版と、補う振る舞いを文書に書きます。
同じ module の試験が、手当てが頼る sanstun の振る舞いを固定します。
sanstun を上げてその振る舞いが直ると試験が落ち、消す手当てを指します。

| 手当て | 補う sanstun 0.1.0 の振る舞い | 固定する試験 | 消し方 |
| --- | --- | --- | --- |
| `stamp_base`:sanstun に渡す Unix 時刻から 27 秒を引く ([時刻](#時刻)) | 開始の印の秒が 2^62 + 37 + Unix 時刻 | `sanstun_stamps_initiations_27_seconds_ahead` | sanstun が 2^62 + 10 に直した版に上げるのと同じ変更で、`stamp_base` を消して時刻をそのまま渡します。印は前後で同じ値になり、server の側で戻りません。直った sanstun で消し忘れると印が 27 秒戻り、server は前の印より古い開始を 27 秒の間捨てます。agent の `agent.json.clock` の語の無い行を読む扱い ([agent の制御](agent-control.md)) は、前の版のファイルのためのもので、手当てとは別に残せます |
| `inner_mtu`:送る packet の上限を 16 の倍数に切り下げる ([MTU と詰め物](#mtu-と詰め物)) | 平文を MTU に依らず 16 の倍数まで詰める | `sanstun_pads_past_the_mtu` | sanstun が詰め物の上限を受ける口を持ったら、そこへ設定の MTU を渡し、`inner_mtu` を設定の MTU そのものにします。試験は口が増えても落ちないので、sanstun を上げるときに変更の記録を確かめます |
| `PassiveKeepalive`:passive keepalive を最初の受信から 10 秒に送らせる ([passive keepalive](#passive-keepalive)) | データを受けるたびに passive keepalive の期限を延ばす | `sanstun_postpones_the_passive_keepalive_on_every_receipt` | 型と、`protocol.rs` の `passive` の呼び出し (`on_data`、`on_send`、`deadline`、`force`) と、`Device::handle_timeout` の `passive_keepalive` の呼び出しを消します |

開始の間隔と打ち切りの後の休止 ([上の節](#ハンドシェイクの開始の間隔と打ち切りの後の休止)) は手当てでなく device の層の規則です。
sanstun が開始の間隔を持つようになっても残します。
データプレーンは起きるたびに開始を頼むので、控えた開始を許される時刻に送る規則が device の層に要るためです。

## WireGuard の仕様との違い

論文 (rev e2da747、2020-06-01)、wireguard.com/protocol、wireguard-go、Linux の WireGuard と照らした違いのうち、上の節で直したもの以外を挙げます。
どれも sanstun 0.1.0 の作りで、外から変えられないか、変える利点がありません。
sanstun を改変 (fork やパッチ) しない所有者の方針に従い、受け入れた違いとして残します。

| 違い | 仕様と他の実装 | sanstun と device の層 | 影響 |
| --- | --- | --- | --- |
| 再試行の打ち切り | 打ち切りでは待つ packet だけを捨て、セッションは残します | 打ち切り (`REKEY_ATTEMPT_TIME`) でトンネルの全セッションを捨て、device の層が新しいトンネルに替えます | 鍵の更新に失敗した後、まだ使えた古いセッションでの受信も止まります。相手が 90 秒応答しない状況なので、実害は小さいと見ます |
| 鍵を消す時刻 | 最後の鍵の導出から 540 秒 | 最後のハンドシェイクの完了か、トンネルの作成から 540 秒 | 使っていないトンネルは device の層が取り替え、知らせません。540 秒の直前に始めた開始は打ち切られます |
| 再送の窓 | 約 2000 (論文)、wireguard-go と Linux は 8128 | 8192 | 少し広いだけで、安全性は変わりません |
| 送信の index | 32 ビットの乱数 | 24 ビットの乱数のトンネルの番号と 8 ビットの通し番号 | 同じトンネルのハンドシェイクを結び付けて読めます。トンネルを取り替えると番号も替わります |
| セッションの数 | 現在、前、次の 3 つ | 8 つの環 | 古いセッションが少し長く残ります |
| 受けた cookie を使う時間 | 論文と wireguard-go は 120 秒、Linux は 115 秒 | 120 秒 | 古い mac2 は新しい cookie の返事を招くだけです |
| 負荷の判定と開始の上限 | ハンドシェイクの待ち行列の長さ、ピアごとに 1 秒あたり 50 回 | 1 秒あたり 100 回で cookie を求め、送信元ごとの bucket で絞ります | 未確認の節に書きました |
| TAI64N のナノ秒 | 2^24 ナノ秒の単位に丸めます | 丸めません | 未確認の節に書きました |
| persistent keepalive | 送るか受けるたびに延びる timer | 通信の有無に依らず間隔ごと | 上の「起動、再試行、期限切れ」に書きました |
| DSCP と ECN | ハンドシェイクに AF41 を付け、ECN を RFC 6040 で写します | どちらもしません | 中の wgstack は ECN を使わず、agent の 1 つのピアでは優先度の印の利点が小さいためです |
| 経路の無い宛先 | Linux は ICMP の宛先到達不能を返します | 黙って捨て、`NoRoute` で数えます | agent の宛先は server の /32 だけで、核が経路を選ぶので起きません |

## 判断と理由

- 暗号の処理を呼び出しの中で済ませます。
  理由はキューと上界の節に書きました。
- 出力は呼び手が取り出す形にし、件数とバイト数の上限を置きます。
  上限で捨てたものは理由ごとに数えます。
  上限を超えて持たないことを、呼び手の振る舞いに依らず保証するためです。
- persistent keepalive の期限で、device の層がハンドシェイクを始めます。
  sanstun の persistent keepalive がセッションの無いときに働かないためです。
  規則は wireguard-go の timer に合わせました。
- agent の server への endpoint は、相手からのハンドシェイクの開始では動かしません。
  理由は「endpoint を動かす message」の節に書きました。
  server の役には WireGuard の規則を `Roaming::Any` で残します。
- 製品の作成は種と壁時計を自分で読みます。
  呼び手が種を使い回す誤りと、壁時計の戻りで開始が拒まれる誤りを、API の形で防ぐためです。
- 経路表は prefix の長さごとの hash の表です。
  agent のピアは 1 つで、server の役でもピアの数に依らない引きの費用で足りるためです。
- 送信の packet の長さを MTU で抑え、受信の packet の長さは抑えません。
  受信の側を相手の MTU に合わせて絞ると、相手の設定の違いで黙って通らなくなるためです。
- sanstun の WireGuard の仕様との違いは、外から保証できるものを device の層で直します。
  直したものは TAI64N の基準、MTU を超える詰め物、開始の間隔と打ち切りの後の休止、passive keepalive の時刻です。
  外から直せないものは、sanstun を改変せず受け入れた違いとして文書に残します。
  依存を改変しない、資源を少し多く使う、性能を少し下げる、fork する、の順に選ぶ所有者の方針に従います。

## 未確認

- sanstun 0.1.0 は第三者の監査を受けていません (sanstun の README)。
- sanstun はハンドシェイクの開始の印 (TAI64N) にナノ秒までの時刻を入れます。
  WireGuard の仕様と Linux の実装は、時刻を 2^24 ナノ秒の単位に丸めて、印から送信の時刻を細かく読まれないようにします。
  Linux の WireGuard と wireguard-go がこの印を受け付けることは、`lab/wg-interop.sh` (#671 の本文に結果) で確かめました。
  印から時刻を細かく読まれることの影響は評価していません。
- sanstun は、ピアごとに 1 秒あたり 50 回の開始の上限 (Linux の WireGuard) を持ちません。
  代わりに、全体で 1 秒あたり 100 回を超えると cookie を求め、cookie を持つ開始を送信元の IP ごとの bucket で絞ります。
  この違いで負荷の高いときの挙動がどう変わるかは確かめていません。
- cookie の返事の経路 (負荷が高いときのハンドシェイク) は device の層の試験で通していません。
  sanstun の試験が sanstun の中で確かめています。
- 性能 (packet ごとの割り当て、1 秒あたりの packet の数、CPU) は測っていません。
- device のキューと sanstun の状態を合わせたメモリの保持量は測っていません。
- Windows と macOS では、CI が build と単体の試験を流すだけです。
  実機の相互運用は確かめていません。
- ホストの一時停止:device は呼び手が渡す `Instant` だけを時計に使うので、停止の間の時間を数えるかは呼び手の時計の選び方で決まります。
  `Instant::now()` をそのまま渡すと、Linux の `CLOCK_MONOTONIC` と macOS の時計は停止の間に進まず、device は壁時計では 180 秒より古いセッションをまだ新しいとみなし、相手はそれを捨てます。
  この場合は、返事の無いデータの 15 秒後に始まるハンドシェイクで回復すると見込みますが、確かめていません。
  停止の間も数えるには、呼び手が起動の時の `Instant` に、停止の間も進む時計 (Linux の `CLOCK_BOOTTIME`) の経過を足した値を渡します。
  agent のデータプレーンは、v1 と同じく Linux と macOS では停止の間に止まる `Instant` を、Windows ではスリープの間も進む時計を渡すと決めました ([agent の置き換えの時計](agent-parity.md#時計))。
  Linux と macOS の上の回復の見込みは確かめていません。
