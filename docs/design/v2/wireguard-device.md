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

sanstun を使うのは `src/protocol.rs` の 1 つの module だけです。
この module は sanstun の型を外に出さず、wgft の型 (鍵、ピアの番号、バイト列、捨てた理由) だけで device の層と話します。
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
`Device::new` は作成の時点の Unix 時刻を受け取ります。
再起動の前後でこの値が戻ると、相手は新しい開始を古い開始の再送とみなして捨てます。
この挙動は試験 `a_restarted_agent_needs_a_later_wall_clock` で確かめています。

### 乱数

`Device::new` は 32 バイトの種を `Zeroizing` に包んで受け取ります。
鍵の交換の一時鍵、index、cookie の秘密、timer の揺らぎは、すべてこの種から作ります。
製品ではオペレーティングシステムの乱数から毎回新しい種を作ります。
試験は固定の種を使い、同じ種から同じバイト列が出ることを確かめています。

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
| (TUN の MTU) | `mtu` | 1420 |

ピアは server の 1 つだけです。
preshared key は v1 が使わないので持ちません。

`Device::new` は設定を確かめ、範囲の外の値を `ConfigError` で拒みます。
persistent keepalive は `wg` と同じ 1 から 65535 秒です。
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
| endpoint の更新 | ハンドシェイクの開始への応答、ハンドシェイクの完了、データか keepalive の受け付けの後だけ、その datagram の送信元に移します | `device.rs` |
| キューの上界 | 持つものすべてに件数とバイト数の上限を置きます (次節) | `queue.rs`、`device.rs` |
| 中身の検査 | IPv4 のヘッダの版、ヘッダ長、全長を確かめ、全長で詰め物を切ります | `ip.rs` |
| 誤り | 相手には何も返さず、理由ごとに数えます。cookie の返事だけはプロトコルの一部として送ります | `protocol.rs`、`drops.rs` |
| 時刻 | 単調な時刻を使い、戻った時刻を sanstun に渡しません | `device.rs` |
| 乱数 | 呼び手が渡す種だけを使います | `device.rs` |

トンネルが運ぶのは IPv4 だけです。
復号した IPv4 でない packet は捨てます。
IPv4 の断片は再組み立てせず、そのまま渡します。
再組み立てと[packet の検査](../userspace/packet-validation.md)は上の層が行います。
v1 で wireguard-go が netstack の TUN の Write に渡したときと同じ分担です。
ヘッダの checksum は確かめません。
wireguard-go と Linux の WireGuard も確かめず、packet を受け取る IP の層が確かめます。

送信の packet が MTU より長い場合は捨てます。
受信の packet の長さには MTU の上限を置きません。
Linux の WireGuard と wireguard-go と同じ扱いです。
受信の packet は、詰め物を除いた長さの新しいバッファに写してから渡すキューに入れます。
キューはバイト数を割り当てた容量で数えるので、短い packet を長い詰め物で送られても、キューの上限を超えて持ちません。

## キューと上界

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
wireguard-go の persistent keepalive は、ピアへ送るか、ピアから認証した packet を受けるたびに間隔だけ先へ延びる timer です。
期限が来たときにセッションが無ければ、wireguard-go はハンドシェイクを始めます。
device の層はこの timer をピアごとに持ちます。

- 起動:persistent keepalive と endpoint を持つピアの期限を、作成の時刻に置きます。最初の `handle_timeout` でハンドシェイクを始めます。
- 期限:sanstun の timer を先に進めます。使えるセッションがあれば、sanstun の keepalive の送信が期限を延ばします。それでも期限が来ていれば、間隔の間なにも送っていないので、ハンドシェイクを始めます。
- 期限切れ:sanstun が接続の期限切れ (`REKEY_ATTEMPT_TIME` の 90 秒の間に応答が無い、または最後のハンドシェイクから 540 秒) を知らせたら、そのピアの状態と待っている packet を捨て、同じ設定の新しいトンネルに替えます。期限は keepalive の間隔の後に置き直します。
- 送信:セッションの無いピアへの packet は、待たせてハンドシェイクを始めます。

server が始めたセッションでは、agent は応答の側です。
応答の側のセッションは 180 秒で使えなくなり、sanstun は応答の側から新しいハンドシェイクを始めません。
Linux の WireGuard の server は、送るデータが無ければハンドシェイクを始めません。
上の期限の規則が、この場合に agent の側からハンドシェイクを始めます。
試験 `an_idle_responder_keeps_contacting_the_server` は、600 秒の間に agent の送信が 40 秒より長く途切れないことを確かめています。

応答しない server に対しては、5 秒ごとの再送が 90 秒続き、keepalive の間隔の後に同じ再送が始まります。

sanstun は、ハンドシェイクを一度もしていないトンネルも作成から 540 秒で期限切れにします。
期限の切れたトンネルはハンドシェイクを受けないので、device の層は同じように取り替えます。
ハンドシェイクを始めも受けもしていないトンネルの期限切れは、`PeerExpired` で知らせません。

server が再起動してセッションを失った場合、agent の keepalive だけでは新しいハンドシェイクが始まりません。
v1 の agent は keepalive の間隔ごとにトンネルの中で ping を送り、返事の無いデータの 15 秒後に始まるハンドシェイクで回復します (`tunnel.go` の `Run`)。
v2 でも制御プレーンがこの ping を送ります。
device の層の試験 `a_restarted_server_is_reached_again_by_traffic` は、この形の回復を偽の時計で確かめています。

## 試験

- 単体の試験:鍵、prefix、経路表、IPv4 の検査、キュー。経路表は wireguard-go の `TestTrieIPv4` (Linux の `selftest/allowedips.h` から移したもの) の場合を写し、素朴な最長一致の模型との一致を proptest で確かめます。
- device の試験:2 つの `Device` を偽の時計と手で運ぶネットワークで向かい合わせます。ハンドシェイク、双方向のデータ、詰め物の除去、AllowedIPs の外の送信元、経路の無い宛先、MTU、IPv4 でない中身、誤りに返事をしないこと、再送された datagram、ハンドシェイクの開始、応答で endpoint が動かず返事もしないこと、roaming、知らない鍵、詰め物の長い packet の保持量、待つ packet の上界と順序、キューの上界、鍵の更新、persistent keepalive、応答の側で待つ間の keepalive の規則、期限切れと再試行、一度も使わなかったトンネルの期限切れ、timer の短縮、両側の再起動、時刻の戻り、決定性、設定の誤りと範囲の外の値を確かめます。
- fuzz:`crates/wgft-wireguard/fuzz` の `inbound` です。本物の相手の datagram を壊したもの、任意のバイト列、相手が検査を通さずに暗号化した任意の中身を agent の側に渡し、時計を進めます。
任意の中身は crate の feature の `fuzzing` が開ける口で暗号化します。panic しないことと、持つものが `Limits` の中にあることを毎回確かめます。cargo-fuzz と nightly が要ります。

```sh
cd crates/wgft-wireguard
cargo +nightly fuzz run inbound -- -max_len=4096
```

Linux の WireGuard と wireguard-go との相互運用は、この crate の上に積んだ TUN の殻と `lab/wg-interop.sh` で確かめます。

## 判断と理由

- 暗号の処理を呼び出しの中で済ませます。理由はキューと上界の節に書きました。
- 出力は呼び手が取り出す形にし、件数とバイト数の上限を置きます。上限で捨てたものは理由ごとに数えます。上限を超えて持たないことを、呼び手の振る舞いに依らず保証するためです。
- persistent keepalive の期限で、device の層がハンドシェイクを始めます。sanstun の persistent keepalive がセッションの無いときに働かないためです。規則は wireguard-go の timer に合わせました。
- 経路表は prefix の長さごとの hash の表です。agent のピアは 1 つで、server の役でもピアの数に依らない引きの費用で足りるためです。
- 送信の packet の長さを MTU で抑え、受信の packet の長さは抑えません。受信の側を相手の MTU に合わせて絞ると、相手の設定の違いで黙って通らなくなるためです。

## 未確認

- sanstun 0.1.0 は第三者の監査を受けていません (sanstun の README)。
- cookie の返事の経路 (負荷が高いときのハンドシェイク) は device の層の試験で通していません。sanstun の試験が sanstun の中で確かめています。
- 性能 (packet ごとの割り当て、1 秒あたりの packet の数、CPU) は測っていません。
- device のキューと sanstun の状態を合わせたメモリの保持量は測っていません。
- Windows と macOS では、CI が build と単体の試験を流すだけです。実機の相互運用は確かめていません。
- ホストの一時停止:Rust の `Instant` は、Linux では停止の間に進まない `CLOCK_MONOTONIC`、macOS でも停止の間に進まない時計です。停止の後、device は壁時計では 180 秒より古いセッションをまだ新しいとみなし、相手は捨てます。返事の無いデータの 15 秒後に始まるハンドシェイクか、セッションの寿命で回復すると見込みますが、確かめていません。停止の間も進む時計 (Linux の `CLOCK_BOOTTIME`) から時刻を作る方法は、`Device` の API が `Instant` を受ける限りありません。
