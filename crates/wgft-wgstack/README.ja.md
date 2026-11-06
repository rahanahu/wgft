<!-- docs-pair: README.md -->
# wgstack

wgstack は、Rust のアプリケーションに組み込むユーザー空間の IPv4 の TCP/IP スタックです。
メモリの使用には、明示して会計した上界があります。

wgstack は sans-IO で、スレッド、ソケット、タイマー、乱数を持ちません。
アプリケーションが受けた IPv4 の packet、今の時刻、乱数の種を渡し、送る packet、次に起こす時刻、知らせを受け取ります。
VPN、トンネル、プロキシ、ネットワークの模擬のように、OS の TCP/IP スタックを使えないか使いたくないアプリケーションに向きます。

crate は標準ライブラリだけに依り、`unsafe` のコードを禁じています。
wgstack は [wgft](https://github.com/rahanahu/wgft) のために書いたもので、wgft は今も主な利用者です。
ただし、wgstack は wgft に依りません。

## 状態:Experimental

- API はどの版でも変わりえます。
- 配布は Git だけです。crates.io には出していません。
  package の名前 `wgft-wgstack` は仮の名前で、crates.io に出す前に変えます。
- wgft のユーザー空間のモードがこのスタックを使います。
  wgft の結合試験のラボで Linux の TCP を相手に試し、単体の試験、ホワイトボックスの試験、fuzz でも確かめています。

```toml
[dependencies]
wgft-wgstack = { git = "https://github.com/rahanahu/wgft" }
```

`rev = "..."` で revision を固定します。
この crate の tag はまだありません。

## 範囲と既知の制限

スタックは IPv4、TCP、UDP と、要る分の ICMPv4 (echo、誤り、経路の MTU の探索) を扱い、IPv4 の再組み立てを持ちます。
TCP は SACK、D-SACK、timestamp、窓の scale、RACK-TLP、不要な再送の取り消し、CUBIC と NewReno、SYN cookie を持ちます。

まだ持たないものは次のとおりです。

- **能動の open がありません。** スタックは接続を受けます (`listen_tcp`、`accept`) が、相手へ接続できません。
- **自分のアドレスは 1 つです。** スタックは IPv4 のアドレスを 1 つだけ持ち (`Config::addr`)、ほかの宛先の packet を捨てます。
  透過のプロキシや VPN のクライアントの側が要る、任意の宛先への接続を受けることはできません。
- IPv4 だけで、IPv6 はありません。
- ECN の交渉、TCP の keepalive、緊急のデータ、接続ごとの再送の打ち切りの設定がありません。
- ICMP の誤りをアプリケーションに渡しません。
- 送る packet は TOS 0、TTL 64 で、IP の option を持ちません。受けた IP の option は読み飛ばします。
- TIME_WAIT は 60 秒です。
- スタックは 1 つの所有者が `&mut` で動かし、中で並列に動きません。

RFC からの逸脱は、理由と共に wgft の設計文書 `docs/design/v2/wgstack-rs.md` に記録しています。

## sans-IO の API の使い方

`Stack` は、`Config`、`Budget` (下の boost の枠)、64 byte の乱数の種、`Hook` から作ります。
boost の知らせが要らないアプリケーションは、`Hook` に `NoHook` を渡します。
アプリケーションは次の 1 回の処理を繰り返します。

1. 受けた IPv4 の packet をそれぞれ `handle_packet` に渡します。
2. `poll_timeout` の時刻が来たら `handle_timeout` を呼びます。
3. `poll_event` の `Event` をそれぞれ取り出し、それに応じて操作します。
4. `poll_transmit` が buffer に書いた packet をそれぞれ送ります。3 の操作が積んだ packet もここで出ます。

`poll_transmit` の buffer は MTU 以上の長さが要ります。短い buffer では panic します。

操作はどれも待ちません。
今は進めない操作は `Error::WouldBlock` を返し、何も変えません。
進めるようになりうる時に、知らせが来ます。
知らせはきっかけで、状態ではありません。
知らせを受けたら操作を試し、`WouldBlock` なら次の知らせを待ちます。

```rust
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use wgft_wgstack::{Budget, Config, Event, NoHook, Stack, Time};

/// 1 回の処理:packet を渡し、タイマーを処理し、知らせに応じ、packet を送ります。
fn turn(stack: &mut Stack, now: Time, received: &[Vec<u8>], send: &mut impl FnMut(&[u8])) {
    for pkt in received {
        stack.handle_packet(now, pkt);
    }
    if stack.poll_timeout().is_some_and(|t| t <= now) {
        stack.handle_timeout(now);
    }
    while let Some(event) = stack.poll_event() {
        match event {
            Event::Acceptable(listener) => {
                while let Ok((conn, _peer)) = stack.accept(now, listener) {
                    // 新しい接続にはこの 6 byte の空きがあります。一部だけの書き込みと `WouldBlock` の
                    // 扱いは `examples/echo.rs` にあります。
                    let _ = stack.write(now, conn, b"hello\n");
                    stack.close_conn(now, conn);
                }
            }
            // Readable、Writable、Closed、UdpReadable、UdpWritable、PingReply ほか
            _ => {}
        }
    }
    let mut buf = vec![0u8; stack.config().mtu];
    while let Some(n) = stack.poll_transmit(now, &mut buf) {
        send(&buf[..n]);
    }
}

let addr = Ipv4Addr::new(10, 0, 0, 1);
let config = Config::new(addr, 1500);
let budget = Budget::new(config.limits.boost_slots)?;
let seed = [7u8; 64]; // 実際のコードでは OS の乱数から 64 byte を取ります
let mut stack = Stack::new(config, budget, &seed, NoHook)?;
let mut now = Time::from_nanos(0); // 起点は任意で、単調に進む時計です
stack.listen_tcp(now, SocketAddrV4::new(addr, 7))?;
for _ in 0..3 {
    turn(&mut stack, now, &[], &mut |_pkt| {});
    now = now + Duration::from_millis(10);
}
let closed = stack.close(now);
assert!(closed.held.is_zero());
# Ok::<(), Box<dyn std::error::Error>>(())
```

`examples/echo.rs` は、手で書いた相手との一往復を通して動かします (`cargo run --example echo`)。

時刻は、アプリケーションが選んだ起点からの nanosecond の `Time` です。
時刻を戻してはいけません。
乱数の種は初期の番号、timestamp、表の hash の鍵になるので、秘密の乱数にします。

## メモリ:上限、会計、上界

スタックが使う表は、作成の時に `Limits` から大きさを決め、伸ばしません。
buffer は 16 KiB の固定の chunk で、接続はデータが届くと、上限が決める予約の内で chunk を取ります。
`Bound::for_limits(&limits, mtu)` は、何かを確保する前に、スタックが要求する heap の最大を計算します。
`Stack::held` は今の保持を返し、`Stack::stats` は捨てた packet をすべて理由ごとに数えます。

上界の項は次のとおりです。

| 項 | 覆うもの |
| --- | --- |
| `fix` | 作成の時に確保する表:接続の枠、索引、握手の途中の行と TIME_WAIT の行、ポートごとの待ち受けと UDP の endpoint の表、タイマー、出力の list と制御の輪、知らせ、置き場に残す chunk |
| `floor_conn` | 接続の枠ごとの送信 256 KiB と受信 256 KiB の floor と、その記録と区間の配列 |
| `boost` | boost の枠:忙しい接続が借りる大きな buffer (向きごとに 4 MiB まで) |
| `frag` | 再組み立ての byte の上限 |
| `udp_rx`、`udp_tx` | UDP の受信と送信の byte の予算と、datagram の表 |
| `ping` | ping の endpoint と応答の buffer |

上限に達した時の動作は次のとおりです。

| 上限 | 達した時 |
| --- | --- |
| 接続の枠 (`max_flows` + `accept_queue`) | 新しい握手の最後の ACK を捨てます (`accept_overflow`)。相手は送り直せます |
| accept の待ち行列 (`accept_queue`、待ち受け 1 つで半分) | 最後の ACK を捨て、空きができるまで握手の途中の行を残します |
| 握手の途中の行 (`syn_rows`、待ち受け 1 つで半分) | SYN に SYN cookie で応えます。accept の待ち行列も満杯なら捨てます |
| TIME_WAIT の行 (`tw_rows`) | 最も古い行を外します (`tw_evicted`)。その 4 つ組では、古い重複の segment から守る力が弱まります |
| 接続の送信の buffer | `write` が `WouldBlock` を返します。確認されたデータが空きを作ると `Event::Writable` が来ます |
| 接続の受信の buffer | 知らせる窓が閉じます。区間の表を超える順序外のデータは捨てます (`ooo_dropped`) |
| boost の枠 (`boost_slots`) | 接続は floor のままです。需要の無い保有者は floor に戻されることがあります |
| 制御の輪 (`ctl_slots`) | 新しい制御の packet (RST、握手の応答、ICMP) を捨てます (`ctl_dropped`)。`send_ping` は `NoBufferSpace` を返します |
| 再組み立て (`frag_entries`、`frag_pieces`、`frag_bytes`) | 最も古い未完成の datagram を外します。外せなければ断片を捨てます |
| UDP の受信の予算 | 新しい datagram を捨てます (`udp_dropped`) |
| UDP の送信の予算 | `send_to` は `WouldBlock` を返し、後で `Event::UdpWritable` が来ます。`send_to_latest` は代わりに最も古い datagram を捨てます |
| ping の endpoint (16) | `open_ping` が `TableFull` を返します |

スタックが順序どおりに受けて確認したデータを、スタックが自分の判断で捨てることはありません。
このデータを捨てるのは次の場合だけです。

- アプリケーションが接続を終える場合:`abort`、未読のデータが残る接続への `close_conn` (Linux と同じく RST で終えます)、accept の待ち行列に接続が残る待ち受けへの `close_listener`、`Stack::close` です。
- スタックが内部の会計の不整合で接続を閉じる場合 (`Error::Accounting`) です。

boost の枠を取り戻す時は、SACK で知らせた順序外のデータを捨てることがあり (RFC 2018 の reneging)、相手が送り直します。
確保の失敗で異常終了しません。
表と buffer は失敗しうる確保で取り、`write` は状態を変えずに `Error::NoMemory` を返し、buffer を確保できない受信の segment は捨てます (`recv_no_memory`)。

### 上界に含まないもの

上界は、スタックが割り当て器に要求する大きさの和です。
プロセスの RSS は別の値です。

- 割り当て器は丸めと自分の管理の領域を足し、解放したメモリをプロセスに残すことがあります。
- 確保しても触れていないメモリは常駐しないことがあり、RSS が上界の使った分より小さいこともあります。
- 呼び手の packet の buffer、`Hook` の状態、呼び出しの stack、アプリケーションが接続ごとに持つものは、スタックの外です。

上界はスタックの保持の上限で、その内の確保が必ず成功するという約束ではありません。

スタックの全体の動的なメモリの予算は、まだありません。
表と buffer はそれぞれ固定の上限を持ち、上界はその和です。
使い方に応じて接続、UDP、再組み立ての間でメモリを動かすことは、まだしません。
この動的な配分は予定していて、予約をすべて正確に数える今の構造は、動的な配分を支えるためのものです。

### 既定の上限

`Limits::default()` (と `Config::new`) は小さく保守的な値です。
接続の枠は 16 + 16、握手の途中の行は 64、TIME_WAIT の行は 1024、制御の枠は 32 です。
再組み立ては 8 つの datagram、64 の断片、256 KiB です。
UDP の予算は向きごとに 256 KiB と 128 の datagram です。
boost の枠は 0 で、置き場に残す chunk は 8 です。

x86_64 の Linux、release の build、MTU 1420 で測った値は次のとおりです。

- 上界:21.6 MiB です。うち固定の項が 4.2 MiB、接続の floor が 16.7 MiB です。
- 作った時:4.1 MiB を確保し、RSS は 4.3 MiB 増えました。
  大半はポートごとの待ち受けと UDP の endpoint の表で、上限の値に依らない費用です。
- 1 本の接続で 4 MiB ずつ送受信:再送は 0 で、確保の最大は作成の分を含めて 4.2 MiB でした。
- 32 の枠をすべて使い、両方の floor を満たした時:確保は 20.8 MiB で、上界の内でした。
  33 本目の握手は `accept_overflow` で捨てました。

boost の枠が無いと、接続の窓は 256 KiB のままです。
往復 50 ms の経路で約 40 Mbit/s までです (計算の値で、測っていません)。
boost の枠 1 つは上界を約 7.8 MiB 増やし、忙しい接続 1 本の buffer を 4 MiB まで広げます。
`boost_slots` を設定し、同じ数で `Budget` を作ります。
多くの接続を受けるときは `max_flows` と `accept_queue` を上げます。
枠 1 つで上界は約 0.53 MiB 増えます。

```rust
use wgft_wgstack::{Bound, Limits};

let limits = Limits { max_flows: 64, accept_queue: 32, boost_slots: 2, ..Limits::default() };
let bound = Bound::for_limits(&limits, 1500);
assert!(bound.total < 128 << 20);
```

## 安全と panic

- `unsafe` のコードはありません (`#![forbid(unsafe_code)]`)。packet の解釈は境界を確かめる slice の上で行います。
- スタックの中の panic は不具合です。panic の後の `Stack` は捨て、使い続けません。
- この crate の試験と fuzz は桁あふれの検査を有効にして流します。利用者の release の build でも有効にします。

  ```toml
  [profile.release]
  overflow-checks = true
  ```

  桁あふれの検査は、コードを compile する crate の設定で、profile を決めるのはアプリケーションのワークスペースだけです。
  スタックの generic な部分 (`Stack<H>` のメソッド、`impl<H: Hook> Stack<H>`) と、そこから inline される小さな関数は、`Stack<...>` を名指す crate で、その crate の profile で compile されます。
  このため、`wgft-wgstack` だけの package ごとの設定では、そのコードが検査されません。
  設定を絞るときは、`wgft-wgstack` と `Stack<...>` を名指す crate の両方に設定します。
  検査が無いと、不具合の桁あふれは panic でなく値の回り込みになります。
  メモリの安全はこれに依りませんが、そのスタックの状態と会計は誤りえます。

## スレッド

`Stack<NoHook>` と `Budget` は `Send` です。
スタックはスレッドの間を移れますが、一度に動かす所有者は 1 つです。
複数のコアを使うときは、それぞれのアドレスを持つ複数のスタックを動かします。

## 来歴

wgstack は、wgft の作者が書いた wgft の Go の TCP/IP スタックの Rust への移植です。
gVisor、smoltcp、ほかの TCP/IP スタックのコードを含みません。

## ライセンス

MIT です。`LICENSE` を見てください。
