# wgstack の Rust 版

この文書は、v2 の Rust の agent が使う wgstack の Rust 版の設計を定めます。
wgstack は、agent のユーザー空間モードがトンネルの中の TCP、UDP、ICMP を終える、wgft が持つ TCP/IP の stack です。
Rust の agent はこの stack を使うので、root の権限も TUN も要りません。
未実装です。
構造、境目、検証、作業の順をここで決め、値と細部は[実装の時に決めること](#実装の時に決めること)に残します。

## この文書の読み方

振る舞いの正本は、Go の wgstack の設計文書のままです。

- 核の構造、不変条件、上界の式、尽きたときの動作:[エージェントの wgft の netstack](../userspace/wgstack.md)
- 性能の段階の機能 (SACK、RACK-TLP、CUBIC、受け手の ACK と窓):[wgstack の性能の段階](../userspace/wgstack-performance.md)
- 試験の形と期待した差:[wgstack の検証](../userspace/wgstack-verification.md)
- 入口の検査と UDP の会計:[IPv4 の断片、ICMP、TCP の MSS の検査](../userspace/packet-validation.md)、[UDP の受信と出力の会計](../userspace/udp-accounting.md)
- トンネルの中の約束:[トンネルの中の約束](../spec/tunnel.md)

この文書は、Rust に移すときに変わる部分と、移し方と、確かめ方だけを書きます。
Go の文書の規則をここに写しません。
Go の文書と食い違う点は、この文書が理由と共に挙げたものだけです。

各項目は、所有者が決めた「決定」と、この文書が勧める「提案」に分けて印を付けます。
提案は、実装の PR で確かめてから採ります。
採らなかった提案と変えた提案は、その PR でこの文書を直します。

### 前提となる所有者の決定

- 決定:Go の wgstack を Rust に移植します。smoltcp は SACK の回復、TCP の timestamp、RACK-TLP を持たないので使いません (2026-11-01)
- 決定:Rust の wgstack の核は sans-IO にします。入力は時刻、packet、操作で、出力は packet、次に起こす時刻、イベントです。核の中にスレッド、実時間のタイマー、ソケットを置きません ([設計の制約](README.md#設計の制約))
- 決定:Go の wgstack は参照の実装として今の形で凍結し、機能を足しません。Rust の実装が追いついた後に消します ([Go の wgstack](README.md#go-の-wgstack))
- 決定:移行の間、Rust の wgstack は凍結した Go の wgstack と同じ入力に同じ packet を返すことを求めます。Go の wgstack の記録とオフラインで bit の単位で照らし、追いついた後は自由に変えます (2026-11-01)
- 決定:適合の台本は混成で持ちます。直線の台本はデータの台本にし、Go の runner (Linux と gVisor に実時間で) と Rust の runner (Rust の engine に偽の時計で) が同じファイルを流します。反応する台本と測る台本は Go のまま残し、Rust の試験用のプログラムを標準入出力で時計ごと動かします。C ABI は作りません (2026-11-01)
- 決定:内部に触れる試験 (fuzz、不変条件、手で進める時計の試験、単体の試験) は実装と一緒に Rust に移します。実ネットワークの面から製品を確かめる試験は Go のまま残せます ([テスト](README.md#テスト))
- 決定:割り当て器は、予算を持つ保持を自前の置き場から取ることを前提に、OS の標準と mimalloc を測ってから選びます (2026-11-01)
- 決定:上界の表は `Bound` の計算から生成し、生成し直しの差分で検査します (2026-11-01)
- 決定:wgstack の実装の担当は Linux の source を読みません。Linux の振る舞いは文書で渡します。実装の担当は wgft 自身のコードである Go の wgstack を読んで写せます。GotaTun (MPL-2.0) のコードは写しません。gVisor と smoltcp のコードも写しません (2026-10-30、2026-11-01)
- 決定:需要で育つバッファは採用済みで、性能の段階の後に実装します ([決めたこと](../userspace/wgstack-buffers.md#決めたこと)、2026-10-31)
- 決定:server のユーザー空間モードは v2.0 に含めるので、Rust の wgstack には後で dial の側を足します ([wgstack の dial の側](../userspace/wgstack-dial.md))

## Go から Rust への対応

### 写すもの

決定的な核の規則と構造は、そのまま写します。
bit の一致を求める間は、写し方も Go と同じ順と同じ算術にします ([bit の一致の条件](#bit-の一致の条件))。

| Go のファイル | Rust の module | 中身 |
| --- | --- | --- |
| `stack.go`、`const.go`、`stats.go` | `stack`、`config`、`stats` | 核、作成、上界の計算、数え |
| `tcb.go`、`tcpin.go`、`tcpout.go`、`timers.go`、`fault.go` | `tcp::conn`、`tcp::input`、`tcp::output`、`tcp::timers` | 接続の枠、受け入れの判定、segment を作る処理、タイマー、会計の不整合 |
| `syn.go`、`listener.go` | `tcp::syn`、`tcp::listen` | 握手の途中の表、待ち受け、accept の待ち行列 |
| `timewait.go` | `tcp::timewait` | TIME_WAIT と FIN_WAIT_2 の行の表 |
| `ring.go`、`recv.go`、`records.go` | `buf::chunk`、`buf::recv`、`buf::records` | chunk の置き場、送受信の輪、区間の treap、送信の記録 |
| `ack.go`、`ackpolicy.go`、`rcvwin.go` | `tcp::rtt`、`tcp::ack_policy`、`tcp::rcv_window` | RTT と RTO、受け手の ACK、受信の窓の自動調整 |
| `scoreboard.go`、`rack.go`、`undo.go` | `tcp::sack`、`tcp::rack`、`tcp::undo` | SACK の scoreboard と回復、RACK-TLP、不要な再送の取り消し |
| `cc.go`、`hystart.go`、`cwndval.go`、`lazyegress.go` | `tcp::cc` | NewReno、CUBIC、HyStart++、窓の使用の判定、遅れた送り出し |
| `boost.go` | `budget` | boost の枠、回収、取り消し |
| `output.go` | `output` | 出力の 4 つの組と deficit round robin、制御の輪 |
| `wheel.go` | `wheel` | タイマーの輪 |
| `index.go`、`siphash.go` | `index`、`siphash` | 4 つ組の hash の表と SipHash-2-4 |
| `packet.go` | `wire` | IPv4、TCP、UDP、ICMP の解釈と組み立て、checksum |
| `udp.go` | `udp` | UDP の endpoint、受信と送信の予算、送信の断片化 |
| `icmp.go` | `icmp` | echo、ping の endpoint、ICMP の誤り |
| `frag.go` と `internal/ipv4frag` | `frag` | 断片の入口と再組み立ての表 |
| `trace.go` | `trace` | 試験と測定のための観測 |

Go の `internal/ipv4frag` は gVisor の経路と共有する葉の package ですが、Rust には gVisor の経路が無いので、wgstack の crate の module にします。

### 形を変えるもの

- 並行性:Go の Device は、wireguard-go が呼ぶ `Read` と `Write`、中継の goroutine、タイマーの goroutine から並行に呼ばれ、錠の 2 段で守ります。
  Rust の核は 1 つの所有者が `&mut` で呼ぶ値で、錠を持ちません。
  錠の順の規則と `TryLock` で相手を見送る規則は要らなくなります
- 時刻:Go の核は `Config.Clock` の時計を自分で読みます。
  Rust の核は、すべての操作で呼び手が渡す時刻だけを使います ([時刻と乱数](#時刻と乱数))
- アプリケーションの操作:Go の `Conn` は `net.Conn` で、読み書きは通知の channel で待ち、期限は壁時計で測ります。
  Rust の核の操作は待たずに戻り、できなければ「今はできない」を返します。
  待つことと期限は、外側の async の層が持ちます ([アプリケーションの操作](#アプリケーションの操作))
- 中継が型アサーションで探すメソッド:`Abort`、`CloseWrite`、`Delivered`、`CloseForDelivery`、`OnBoost` は、核の操作と、中継が使う Rust の trait になります ([中継から見た面](#中継から見た面))
- boost の回収の時計:Go では枠の集まりがプロセスで 1 つで、別の Device の保有者の需要の無い時間をその Device の時計で確かめます。
  Rust では枠の集まりを核が持ち、トンネルを作り直すときに古い核から新しい核へ渡します ([予算の持ち主](#予算の持ち主))
- 出力:Go の `Read` は wireguard-go の buffer に packet を書き、末尾に送信のバッチの印を書きます。
  Rust の核の `poll_transmit` は呼び手の buffer に packet を 1 つ書くだけです
- 上界の数え方:Go の `Bound` は、Go のヒープの確保の丸めを `append` の容量で測ります。
  Rust は `size_of` と確保の大きさから数えます ([上界の式の写し方](#上界の式の写し方))

### 移さないもの

- 送信の向きのバッチの台帳 (`batch.go`):wireguard-go の staged のキューと送信のキューに滞留する buffer を数えるための仕組みです ([送信の向きの予算](../userspace/wgstack-batching.md#送信の向きの予算))。
  Rust の agent では WireGuard の device の層を wgft が持ち、wgstack と UDP のソケットの間に隠れたキューがありません。
  呼び手は送れる分だけ `poll_transmit` で取り出して暗号にするので、台帳も印も鍵も要りません。
  核が乱数を直接読む例外もこれで無くなります
- `tun.Device` の面:`Name`、`File`、`Events`、`BatchSize` は wireguard-go との境目のもので、Rust の核は持ちません
- gVisor と並べるための差し替えの面:Go のトンネルの非公開の interface、`internal/nettun` と同じ形の `Create`、gVisor の挙動に合わせた互換の部分は移しません
- 読み書きの期限:核は期限を持ちません。Go の核が壁時計を読む例外はこれで無くなります
- `ManualClock` と Device のタイマーの goroutine:sans-IO の核は呼び手が時刻を渡すので、試験用の時計の型も、本番のタイマーの goroutine も要りません

### crate の分け方

提案:次の crate に分けます。

| crate | 中身 | 依存 |
| --- | --- | --- |
| `crates/wgft-wgstack` | sans-IO の核 | 標準ライブラリだけ |
| `crates/wgft-wgstack/fuzz` | cargo-fuzz の target | `wgft-wgstack`、`libfuzzer-sys` |
| `crates/wgft-wgstack-dut` | 試験用のプログラム `wgstack-dut`。配布せず、`wgft` のバイナリにも入りません | `wgft-wgstack` |
| `crates/wgft-agent` の module `netstack` | 核を tokio の上で動かす層、中継が使う TCP と UDP の handle | `wgft-wgstack`、`wgft-wireguard`、tokio |

`netstack` の module は、まず `wgft-agent` に置きます。
Rust の server が dial の側を使うときに、共有の crate に移すかを決めます ([実装の時に決めること](#実装の時に決めること))。

### 依存と隔離の検査

提案:Go の `internal/dataplane/deps_test.go` の `TestWgstackImports` に当たる検査を次の形で持ちます。

- 依存:`wgft-wgstack` の `[dependencies]` は空にします。
  CI の検査が `cargo tree` の通常の依存の辺で、この crate が何にも依らないことを確かめます
- sans-IO:`wgft-wgstack` の clippy の設定の `disallowed-methods` と `disallowed-types` で、`Instant::now`、`SystemTime::now`、スレッドの作成、`std::net` のソケット、OS の乱数の読み取りを禁じます。
  crate ごとの clippy の設定がワークスペースの中で効くかは、最初の PR で確かめます (未確認)
- unsafe:`wgft-wgstack` は `#![forbid(unsafe_code)]` にします。
  checksum も `chunks_exact` と `u64::from_be_bytes` の安全なコードで書きます
- I7 の隔離:後で作る agent のカーネルモードの crate が、推移的にも `wgft-wgstack` に依らないことを同じ `cargo tree` の検査で確かめます。
  カーネルモードの agent は wgstack を作りません

`no_std` で sans-IO を構造で強いる案は採りません。
`alloc` を使うには `extern crate alloc;` の宣言が要るうえ、禁止の一覧で同じ効果を得られるためです。

## sans-IO の API

この節の型と関数の名前は提案です。
形 (入力、出力、待たない操作、知らせ) は決定に従います。

### 入力

| 入力 | 関数 | 中身 |
| --- | --- | --- |
| トンネルから届いた packet | `handle_packet(now, &[u8])` | device の層が復号して検査した IPv4 の packet。核は呼び出しの間だけ読み、保持するものは自分の予約に写します |
| 時刻 | `handle_timeout(now)` | 期限の来たタイマー、行の期限、再組み立ての表の掃除 |
| アプリケーションの操作 | 後述 | TCP、UDP、ping の操作。どれも `now` を受けます |

`handle_packet` は誤りを返しません。
Go の `Write` が誤りを返すのは閉じた後と IPv4 でない packet だけです。
閉じた後の呼び出しは、核を閉じると値が無くなるので Rust では起きません。
IPv4 でない packet は device の層が捨てます。
捨てた packet は理由ごとに数え、1 分に 1 回までログの行の材料を出します ([誤りと捨てた数](#誤りと捨てた数))。

### 出力

| 出力 | 関数 | 中身 |
| --- | --- | --- |
| 送る packet | `poll_transmit(now, &mut [u8]) -> Option<usize>` | 次に送る IPv4 の packet を 1 つ呼び手の buffer に作り、長さを返します。無ければ `None`。buffer は MTU 以上の長さを持ちます |
| 次に起こす時刻 | `poll_timeout() -> Option<Time>` | 次に `handle_timeout` を呼ぶ時刻 |
| 知らせ | `poll_event() -> Option<Event>` | 接続とソケットの準備の変化 ([準備の知らせ](#準備の知らせ)) |

出力は Go と同じく待ち行列に積みません。
接続と行は「送るものがある」印を自分の中に持ち、`poll_transmit` の時にその場で packet を作ります ([出力](../userspace/wgstack.md#出力))。
制御の組だけが、作成の時に確保した制御の輪に積みます。
呼び手が `poll_transmit` を呼ばない間、出力の保持は増えません。

### アプリケーションの操作

操作はどれも待たずに戻ります。
「今はできない」は `WouldBlock` で返し、できるようになったら[準備の知らせ](#準備の知らせ)を出します。

- TCP の待ち受け:`listen_tcp(now, SocketAddrV4) -> Result<ListenerId>`、`accept(now, ListenerId) -> Result<ConnId>`、`close_listener(now, ListenerId)`。
  待ち受けを閉じると、Go と同じく accept の待ち行列の接続と握手の途中の行に RST を送ります
- TCP の接続:`read(now, ConnId, &mut [u8])`、`write(now, ConnId, &[u8])`、`close_write`、`close`、`abort`、`delivered`、`local_addr`、`peer_addr`。
  読み取りは、相手の FIN の後に `Eof` を、RST と会計の不整合の後に誤りを返します。
  `close_for_delivery` は Go と同じく `close` と同じ動作なので、中継の trait にだけ残します
- 写さずに読み書きする口:提案として、受信の輪の生きている範囲を 2 つの slice で見せる `read_slices` と `consume`、送信の輪の空きに直接書く `write_slices` と `commit` を足します。
  中継が LAN 側のソケットとの間で中身を 1 度だけ写すためです。
  採るかは CPU を測ってから決めます
- UDP:`bind_udp(now, SocketAddrV4) -> Result<UdpId>`、`recv_from(now, UdpId, &mut [u8]) -> Result<(usize, SocketAddrV4)>`、`send_to(now, UdpId, &[u8], SocketAddrV4)`、`close_udp`。
  `send_to` は送信の予算を予約できなければ `WouldBlock` を返し、予約できるようになったら知らせます。
  Go の `WriteTo` が予約できるまで待つ挙動は、外側の層の待ちになります
- keepalive の ping:`open_ping(now, Ipv4Addr) -> Result<PingId>`、`send_ping`、`recv_ping`、`close_ping`。
  表は Go と同じ固定の大きさで、満杯なら誤りを返します
- 会計の故障:`udp_receive_fault() -> Option<Fault>` が、`agent doctor` の `tunnel.udp_accounting` に使う最初の違反を返します ([会計の不整合](../userspace/udp-accounting.md#会計の不整合))
- 状態:`stats() -> Stats`、`bound() -> Bound`、`held() -> Held`

### handle と古い handle

`ConnId` は接続の枠の番号と 64 bit の世代の組です。
Go の古い接続の値と同じく、枠が TIME_WAIT の行に移った後や別の接続に使われた後の `ConnId` は次のように振る舞います ([今の境目](../userspace/wgstack.md#今の境目))。

- `delivered`:真を返します
- `close`:何もしません
- `read` と `write`:閉じた誤りを返します
- `abort`:元の接続の行が表に残っていれば行を外して RST を送り、残っていなければ何もしません

`ListenerId`、`UdpId`、`PingId` も番号と世代の組にし、閉じた後の handle を誤りにします。
handle は `Copy` の小さな値で、核への参照を持ちません。
このため、中継が handle を持ち続けても核の保持は増えません。

### 準備の知らせ

`Event` は次の種類を持ちます。

- `Readable(ConnId)`、`Writable(ConnId)`、`Closed(ConnId)`
- `Acceptable(ListenerId)`
- `UdpReadable(UdpId)`、`UdpWritable(UdpId)`
- `PingReply(PingId)`
- `Boost(ConnId, bool)`:boost を得たか、floor に戻ったか

知らせは待ち行列に積みません。
対象ごとに「知らせることがある」印の bit と順番の list の節を、枠と表の中に固定で持ち、`poll_event` がその list の先頭から取り出します。
同じ対象の同じ種類の知らせは、取り出すまで 1 つにまとまります。
このため、知らせの保持は枠と表の数で決まり、呼び手が取り出さなくても増えません。
知らせはきっかけで、状態の正本ではありません。
呼び手は知らせを受けたら操作を試し、`WouldBlock` なら次の知らせを待ちます。

### 時刻と乱数

- 時刻:核の時刻は `Time` で、任意の起点からの単調な ns の符号なしの整数です。
  Go の核の時刻 (起点からの int64 の ns) と同じ値を持てるので、記録の時刻をそのまま渡せます。
  外側の層は、作成の時の `Instant` からの経過を ns にして渡します。
  時刻が前の値より戻ったときは、前の値を使います
- 停止の間の時計:ホストの一時停止の間を数えるかは、device の層と同じ時計の選び方に従います。
  どちらの時計にするかは制御プレーンの設計で決めます (未決)
- 乱数:作成の時に 64 byte の種を渡します。
  Go と同じく、先頭の 16 byte を ISN の鍵、次の 16 byte を表の hash の鍵、残りの 32 byte を ChaCha8 の種にし、timestamp の鍵、IP の ID の始めの値、challenge ACK の揺らぎ、区間の treap の優先度は ChaCha8 から引きます。
  製品の外側の層は OS の乱数から種を作り、試験は固定の種を渡します
- ChaCha8:bit の一致のため、Go の `math/rand/v2` の `ChaCha8` と同じ列を出す生成器を wgft の中で書きます。
  この生成器は C2SP の `chacha8rand` の仕様に従うと読めるので、仕様から書き、Go が出す列と固定の値の試験で照らします (未確認)

### boost の知らせ

Go の `OnBoost(f)` は、接続の錠の中で f を呼び、`f(false)` が偽を返したら floor への戻りを取り消します。
`internal/netpipe` の `FollowBoost` は、LAN 側のカーネルのソケットが floor を超える受信のデータを持つ間、偽を返します。

提案:核は作成の時に呼び手の hook を受け取り、型の引数で持ちます (`Stack<H: BoostHook>`)。

- `granted(conn)`:boost を得た時に呼びます
- `may_return(conn) -> bool`:需要の無い保有者を floor に戻す前に呼び、偽なら戻りを取り消します

hook は核への参照を受け取らないので、核を呼び返せません。
中継の層は、`ConnId` から LAN 側のソケットを引く固定の大きさの表を持ち、`may_return` の中でそのソケットの受信のデータの量を読みます。
試験は、決まった答えを返す hook を渡します。
試験と測定の観測 (Go の `Config.Trace`) も同じ hook の trait に置きます。

### 誤りと捨てた数

数える種類と 1 分に 1 回までのログの門は Go と同じです ([尽きたときの動作](../userspace/wgstack.md#尽きたときの動作))。
門は核の時刻で判定します。
核はログを書かず、門を通った知らせを `poll_event` とは別の `poll_log() -> Option<LogLine>` で出します。
外側の層がそれを英語の 1 行にしてログに出します。

### agent の event loop での使い方

提案:agent のデータプレーンは、トンネルの世代ごとに 1 つの OS のスレッドで動かします。
そのスレッドは tokio の current-thread の実行環境を持ち、次のものを 1 つの値として所有します。

- WireGuard の device の層 (`wgft_wireguard::Device`)
- wgstack の核
- WireGuard の UDP のソケット
- 接続ごとの waker を置く固定の大きさの表

中継の接続の task も同じスレッドの local の task として動き、核を直接呼びます。
錠も channel も要らず、核の `&mut` の規則がそのまま成り立ちます。
制御プレーン (stream、ハートビート、制御ソケット) は別の多スレッドの実行環境に置き、データプレーンには容量の決まった channel で命令を送ります。
命令は待ち受けの開閉、状態の読み出し、ping のように頻度が低いものだけです。

1 回の起床で行うことは次のとおりです。

1. UDP のソケットから datagram を読み、`Device::handle_datagram` に渡し、`Device::poll_packet` が出す packet をすべて `handle_packet` に渡します
2. 時刻が来ていれば、device の層と核の `handle_timeout` を呼びます
3. ソケットが書ける間、`poll_transmit` で packet を 1 つずつ作り、`Device::handle_packet` で暗号にし、`Device::poll_transmit` が出す datagram を送ります。
   1 回の起床で作る packet の数には上限を置き、ほかの仕事を飢えさせません
4. `poll_event` の知らせで waker を起こします
5. device の層と核の `poll_timeout` の早い方でタイマーを張り直します

ソケットが書けない間は `poll_transmit` を呼ばないので、送り出しの詰まりは核の中に積もらず、TCP の再送で回復します。
これは Go の設計の「出力の詰まり」と同じ性質です。

1 つのスレッドにする理由は、核の `&mut` を保ちながら、中継の読み書きと暗号を同じ所で済ませられるためです。
暗号を含むデータプレーンが 1 つの CPU に縛られる点は危険として残ります。
byte あたりの CPU と速さを qbench とラボで測り、足りなければ暗号を別のスレッドに移す形を device の層の設計で決めます ([実装の時に決めること](#実装の時に決めること))。

### 中継から見た面

提案:中継が使う TCP の接続は、次の trait を満たす型にします。

- `tokio::io::AsyncRead` と `AsyncWrite`:核の `read` と `write` を呼び、`WouldBlock` なら waker を表に置きます
- `RelayConn`:`abort`、`close_write`、`delivered`、`close_for_delivery`、`set_boost_follower` を持ちます

中継は、LAN 側の OS のソケットの接続にも同じ trait を実装します。
`delivered` は OS のソケットでは常に真です。
Go の中継の挙動 (K を超えた接続の `Abort`、末尾の配送の間 K に数えること、`FollowBoost`) は、この trait の上で同じ規則で書きます。

UDP の中継は、`UdpId` を包んだ型の `recv_from` と `send_to` を使います。
送信元の文字列を表の鍵にする Go の中継の規則は、`SocketAddrV4` を鍵にする形に替えます。

### dial の側を足す継ぎ目

[wgstack の dial の側](../userspace/wgstack-dial.md)を後で足すときに、核の形を作り直さずに済むよう、最初から次の形にします。

- 確立の入口:確立した接続は、握手の途中の行からではなく、交渉した値の組 (MSS、窓の scale、SACK、timestamp、両方の ISN) から作ります。
  受動の open もこの入口を通ります ([受信の機械と共有するもの、新しいもの](../userspace/wgstack-dial.md#受信の機械と共有するもの新しいもの))
- 枠の状態:接続の枠の状態は enum で持ち、SYN-SENT を後で足せる形にします。
  `ConnId` は受動と能動の接続で同じ型です
- 宛先の集合:受け付ける宛先は、Go と同じくプレフィックスの集合で持ちます
- 4 つ組の検索:接続の表と TIME_WAIT の表の検索は、一時ポートを選ぶときの衝突の確認にも使える関数として分けておきます
- 表の大きさ:握手の途中の表と accept の待ち行列は 0 を許し、K の外の小さな枠の数を設定に持てる形にします。
  server の Device は待ち受けを持たないためです
- UDP の endpoint:endpoint の鍵を「ローカルのポートと、任意の相手のアドレス」にし、接続した UDP を後で足せる形にします
- 予算の会計:UDP、再組み立ての表、ICMP の速さの会計は小さな型に閉じ、後でピアのアドレスごとの上限を足せるようにします ([多くのエージェントが 1 つの Device を分け合うこと](../userspace/wgstack-dial.md#多くのエージェントが-1-つの-device-を分け合うこと))
- 知らせ:`Event` に `Connected` と `ConnectFailed` を後で足します。
  呼び手は知らない種類の知らせを無視できる形で受けます

dial の操作 (`connect`) と SYN-SENT の規則は、agent の置き換えが終わった後の段で実装します。

## メモリ

### 上界の式の写し方

上界の式の項と規則は Go と同じです ([上界の式](../userspace/wgstack.md#上界の式))。
I1 から I7 の不変条件もそのまま守ります ([不変条件](../userspace/wgstack.md#不変条件))。
変わるのは、項の大きさの数え方です。

- 固定の表:接続の枠、hash の表、握手の途中の表、TIME_WAIT の表、タイマーの輪、出力の list、制御の輪、UDP の管理の配列、知らせの list は、作成の時に `Box<[T]>` として確保します。
  大きさは要素の数と `size_of::<T>()` の積です。
  後から大きくしません。
  外側の層の waker の表も同じく作成の時に確保しますが、核の `Bound` の外で、agent の上界の項として数えます
- 枠と共に持つ配列:floor の送信の記録の輪と区間の表は、Go と同じく枠を初めて使う時に確保し、枠と共に持ちます。
  上界は作成の時に数えるので、確保の時機は上界を変えません
- chunk:16 KiB の固定の配列で、予約の内側でだけ確保します。
  返した chunk は 0 で埋めて置き場に置き、置き場の上限 (Go と同じ 64 個) を超えた分は解放します
- boost の配列:boost の記録の輪と区間の表は、boost を得た時に確保し、floor に戻る時か接続を閉じる時に解放します
- 割り当て器の丸め:Go の `Bound` が測っていたヒープの丸めは、Rust では割り当て器の外の無駄として扱い、上界の式に入れません。
  プロセスの上界は「生きている保持の上界と、割り当て器の無駄と、固定の分の和」で、割り当て器の無駄は測って係数にします

`Bound` の計算は、作成の時の設定と型の大きさだけから決めます。
Go の測った値 (c_conn、記録 1 件、区間 1 つ) は Rust の型の大きさで置き換わり、どの target でも同じかを試験で確かめます。

### 確保の規則

- 予約が先:保持する前に予算から予約し、予約の後に確保します (I2)
- 確保の失敗:確保は `Vec::try_reserve_exact` のように失敗を返す形で行い、失敗を予算が尽きたときと同じ動作にします。
  Rust の標準の確保は失敗するとプロセスを止めるためです
- 隠れた伸びの禁止:`Vec::push` のように容量を自動で伸ばす操作は、作成の時に容量を決めた配列の中でだけ使い、容量を超えないことを debug の assert で確かめます。
  `VecDeque`、`HashMap`、`BTreeMap` のように中で伸びる collection は核の保持に使いません
- 0 で埋める:置き場に返す chunk は 0 で埋めます。
  試験の build では 0 の代わりに目印の byte で埋め、目印が読み取りと送る segment に現れないことを確かめます ([使い回しと古い byte](../userspace/wgstack-buffers.md#使い回しと古い-byte))

### 予算の持ち主

Go では boost の枠の集まりがプロセスで 1 つで、トンネルを作り直しても増えません。

提案:Rust では枠の集まりを `Budget` という値にし、核がそれを所有します。
トンネルを作り直すときは、古い核を閉じて `Budget` を取り出し、新しい核に渡します。
古い核の接続はその前にすべて閉じているので、`Budget` の借りは 0 です。
このため枠の集まりはプロセスで 1 つのままで、Device の間で別の Device の接続を回収する処理も要りません。
古い核を閉じた後、その表と chunk は `Drop` で解放されるので、Go の上界が足していた「古い世代の M_fix」の項は要りません。

### 保持の量の測り方

- 核の会計:Go の `Stats` と同じく、chunk、記録の輪、区間の表、UDP の枠、再組み立ての表が今持つ量を核が数えます。
  この値は `held()` で読めます
- 確保の数え:試験と測定の build では、`GlobalAlloc` を包んで確保と解放の byte を数える割り当て器を使います。
  敵対的な保持の試験は、核の操作の前後の生きている byte の差が `Bound` 以下であること、核を閉じた後に元の値へ戻ることを確かめます。
  GC が無いので、この差は Go の試験の「生きているヒープ」より正確に保持を表します
- OS の値:ラボのメモリの測定は、Linux の `VmRSS` と `VmHWM` を読みます。
  Rust の agent は、測定用の cargo の feature を有効にした build だけが、核の会計と確保の数えを制御ソケットに出します。
  Go の build tag `labmemprobe` に当たります
- 割り当て器の比べ:OS の標準と mimalloc の両方で同じ負荷を流し、RSS と確保の数えの比を記録してから選びます

### 上界の表の生成

決定に従い、上界の表は `Bound` から生成します。

提案:`wgft-wgstack` の試験が、既定の設定と代表の K の値で `Bound` を計算し、項ごとの表を Markdown の断片として書き出します。
環境変数 `WGFT_UPDATE_GOLDEN=1` を付けたときだけファイルを書き直し、付けないときは差があれば失敗します。
Go の `-update` の形に当たります。
生成した表はこの文書から参照し、手で数を書きません。

### 需要で育つバッファとの関係

[需要で育つバッファ](../userspace/wgstack-buffers.md)は採用済みですが、凍結した Go の wgstack にはありません。

提案:Rust の wgstack は、まず Go と同じ floor と boost の枠の模型で書き、Go の記録との bit の一致を確かめます。
需要で育つバッファは、bit の一致を求める期間が終わった後の段で、Rust だけに入れます。
`Budget` の型は、boost の枠の集まりと、予算 G から段を借りる形の両方を表せるように作ります。
段を移す手順の「chunk の位置を割り当て直す」規則は、Rust の輪でも同じに書けます。

## agent の TUN を置き換える

### packet の流れ

試作の agent は、device の層が復号した packet を Linux の TUN に書き、ホストのカーネルの TCP/IP で終えています。
試作の形は、device の層と制御プレーンの PR が加える `docs/design/v2/wireguard-device.md` と `docs/design/v2/agent-control.md` にあります。
Rust の wgstack が入ると、packet は次のように流れます。

- 受信:UDP のソケット、`Device::handle_datagram`、`Device::poll_packet`、核の `handle_packet`
- 送信:核の `poll_transmit`、`Device::handle_packet`、`Device::poll_transmit`、UDP のソケット
- アプリケーション:中継の task が核の handle を読み書きし、LAN の宛先へは OS のソケットで接続します

TUN も、トンネルのアドレスの経路も、専用の経路表と rule も要らなくなります。
agent はどの OS でも利用者の権限で動き、Go の v1 のユーザー空間モードと同じ形に戻ります。
核は OS に依らないので、Windows と macOS でも同じ形で動きます。
CI はこの 2 つの OS で build と単体の試験を流しますが、実機での動作は未確認です。

device の層の `poll_packet` は packet ごとに `Vec` を確保して返します。
提案:最初はこの形のまま使い、CPU を測ってから、device の層に呼び手の buffer へ書く口を足すかを決めます。
送信の向きも同じです。

### 入口の検査の移り先

試作の `inbound` の module は、TUN の先のカーネルがホストのサービスと LAN に packet を渡すのを防ぐための検査でした。
wgstack では packet が核の中で終わり、転送の経路も、中継が開いていないポートの待ち受けもありません。
このため検査は核の規則に移り、`inbound` の module は消えます。
規則の正本は[トンネルの入口の検査](../spec/tunnel.md#トンネルの入口の検査)です。

| 試作の検査 | wgstack での扱い |
| --- | --- |
| 宛先が agent のアドレスで、開いているルールのポートへの TCP を通す | 宛先の集合と待ち受けの表で決まります。待ち受けの無いポートへの SYN には RST を返します |
| agent のアドレスへの echo reply を通す | ping の endpoint の表が受けます |
| 開いているポートの TCP を引用する Fragmentation Needed を、外側の送信元が引用の宛先と同じときだけ通す | ICMP の誤りの入口の検査と、RFC 5927 の番号の確認で受けます |
| 開いていないポートへの SYN に RST を返す | 同じです |
| MSS が 536 より小さい SYN を捨てる | 同じです。SYN-ACK にも同じ下限を掛けます |
| UDP を捨てる | 待ち受けのあるポートの UDP は受信の予算に入れ、待ち受けの無いポートには Port Unreachable を返します。v1 の約束に戻ります |
| echo request を捨てる | 自分のアドレス宛ての echo request に応答します。v1 の約束に戻ります |
| IPv4 の断片を捨てる | 再組み立ての表で組み立てます。v1 の約束に戻ります |
| agent のアドレス以外への packet を捨てる | 同じです。宛先の集合の外の packet を数えて捨てます |
| 捨てた数を数え、1 分に 1 回までログに出す | 核の数えと門が持ちます |

試作が UDP、echo request、断片を捨てていたのは、カーネルにホストの応答を作らせないためでした。
wgstack はそれらを自分で扱うので、[トンネルの中の約束](../spec/tunnel.md)の v1 の挙動に戻します。

### TUN の殻の扱い

提案:`crates/wgft-wireguard-tun` は、agent の経路から外し、ラボの試験の道具として残します。

- 残す理由:`lab/wg-interop.sh` は、TCP の stack と切り離して、device の層を Linux の WireGuard と wireguard-go に照らします。
  wgstack に不具合があっても WireGuard の相互運用を確かめられるので、移行の間は原因を分けるのに使えます
- 外すもの:`wgft-agent` の `tunnel` の module は、殻を使わずに device の層と核を直接動かします。
  `WGFT_WG_INTERFACE` を TUN の名前に読み替える試作の扱いもやめます
- 消す時機:移行の主な関門のラボの一式が、Rust の agent で server の両方のモードを通るようになった後に、殻を残すかを決め直します。
  ラボの一式が同じ相互運用を確かめるので、そこで消すことを勧めます

### 設定の扱い

- `WGFT_AGENT_NETSTACK`:決定どおり、`gvisor` と `wgstack` を受け付け、どちらでも Rust の wgstack で動かします。
  `gvisor` のときは使わない旨を英語の 1 行で出します
- `WGFT_MAX_TCP_FLOWS`:Go と同じく K として受け取り、接続の枠の数 N_c = K + Q を導きます
- `WGFT_AGENT_BATCH_MIB`:仕様は、受け付ける値の集合と誤りの文面を Go と同じにし、値から何を導くかは実装の送信の経路で決めるとしています ([WGFT_AGENT_BATCH_MIB](../spec/cli-config.md#wgft_agent_batch_mib))。
  提案:値は 1 回の起床で作る packet の数と、送信のバッチの buffer の上限に使い、`0` は 1 件ずつ送ることにします。
  導く式は送信の経路を測ってから決めます

## 検証

### 書き手の分離

[検証の原則](../userspace/wgstack-verification.md#検証の原則)の書き手の分離をそのまま当てます。

- 実装の担当:核のコードと、Go の wgstack の白箱の単体の試験を Rust に移したものを書きます。
  Linux の source は読みません
- 試験の担当:実装の担当とは別の担当です。
  データの台本、2 つの runner、試験用のプログラム、Go の側の adapter、記録と照合、fuzz の target、上界と敵対的な保持の試験を書きます。
  Rust の wgstack の実装のコードを読まず、公開の API の文書だけを読みます
- 期待した差の一覧:行を足せるのは、今と同じく試験の担当と所有者だけです

### データの台本

決定に従い、直線の台本をデータにします。

提案:

- 形式:JSON のファイルにし、リポジトリの直下の `testdata/tcpharness/` に置きます。
  Go と Rust の両方が標準の道具だけで読めるためです
- 中身:試験の側の TCP の模型 (SND.NXT、RCV.NXT、timestamp、窓の scale) を持つ相手、見た packet の欄を変数に取る捕捉、照合の述語 (フラグ、番号、ACK、option、窓の範囲、時刻の窓)、packet を入れる行、時刻を進める行、アプリケーションの操作の行です。
  ISN や timestamp のように実装ごとに決まる値は、今の台本と同じく変数に取り、関係で比べます
- 時刻:時刻の範囲は RTO の回数のような規格の単位で書きます。
  実時間でだけ効く余裕 (壁時計の流し直しの規則と、遅れを測って上限を広げる規則) は、Go の runner だけが使う欄に書きます
- check の id:今の台本の `Check` の id と期待した差の一覧の形を保ちます

runner は次の 2 つです。

- Go の runner:`internal/tcpharness` に置き、Linux (ラボの VM の TUN) と gVisor と凍結した Go の wgstack に流します
- Rust の runner:`wgft-wgstack` の試験に置き、Rust の核に in-process の偽の時計で流します。
  種を変えて同じ台本を繰り返し流します

台本をデータに移すときは、試験の担当が Go のコードの台本とデータの台本の両方を Linux に流し、同じ check が同じ結果になることを確かめてから、Go のコードの台本を消します。

### 反応する台本と測る台本

決定に従い、反応する台本 (SACK、RACK、回復、Limited Transmit など) と測る台本 (受信の溢れ、窓の開き方、縮小の確かめ) は Go のコードのまま残します。
Go の側は、Rust の試験用のプログラム `wgstack-dut` を子のプロセスとして起動し、標準入出力で時計ごと動かします。

提案:

- Go の adapter:`internal/tcpharness/rustdut` が `ClockedDUT` を満たし、`Inject`、`Poll`、`Advance`、`Now`、`Listen`、`ListenUDP` と接続の操作を frame にして送ります。
  `Delivered`、`CloseForDelivery`、`OnBoost` も frame で持つので、Go の wgstack と同じく台本が確かめられます。
  `OnBoost` の関数が返す答えは、接続ごとに frame で置く値にし、`wgstack-dut` の hook がその値を返します
- 読み書きの待ち:核の操作は待たないので、adapter が `Read` と `Write` の待ちを持ちます。
  今の `wgstackdut` と同じく、読み書きの期限だけを壁時計で測ります
- 起動:Go の試験は、環境変数 `WGFT_TEST_WGSTACK_DUT` が `wgstack-dut` の実行ファイルを指すときだけ流し、無ければ理由を付けて飛ばします
- 期待した差の一覧:Rust の engine の名前を `wgstack-rs` にし、一覧は凍結した Go の wgstack の一覧の写しから始めます

### DUT の frame

提案:標準入出力の frame は、長さ (u32 の little endian)、種類 (u8)、中身の並びです。
命令 1 つに応答 1 つを返します。
命令は、作成 (アドレス、MTU、上限、64 byte の種、boost の与え方と輻輳の制御の試験の選択)、packet の注入、時刻の前進、packet の引き取り、待ち受けと接続と UDP と ping の操作、`stats` と `bound` の読み出しです。
packet は byte のまま運び、文字列にしません。
frame の種類の一覧と中身の形は、試験の担当が最初の PR でこの文書の付録として書きます。

同じ frame の列を、記録のファイルの形式にも使います ([Go の wgstack の記録との bit の一致](#go-の-wgstack-の記録との-bit-の一致))。

### runner どうしの照合

2 つの runner の意味がずれる危険は、Go の runner を `rustdut` を通して Rust の engine に流すことで確かめます。
同じデータの台本を、Go の runner と `rustdut` で流した結果と、Rust の runner で in-process に流した結果が、同じ種で同じになることを求めます。
どちらも同じ engine と同じ偽の時計を使うので、違いが出れば runner の誤りです。
TUN と実時間を使わずにホストで流せます。

### Go の wgstack の記録との bit の一致

決定に従い、移行の間は凍結した Go の wgstack の記録と照らします。

- 記録の作り方:試験の担当が、Go の wgstack を DUT の frame で動かす記録用の adapter を Go の試験の道具として書きます。
  adapter は送った命令と Go の wgstack の応答を frame の列としてファイルに書きます。
  台本、FuzzCore の corpus、stream の一致の試験の種、敵対的な送り手の種を、この adapter を通して流します
- 照らし方:Rust の試験は記録の命令を順に Rust の核に与え、応答が byte の単位で同じであることを確かめます。
  最初に違った frame の位置と、両方の packet の解釈を失敗の報告に出します
- 置き場:小さく選んだ記録はリポジトリに置き、Go の wgstack を消した後も Rust の回帰の入力として残します。
  大きな記録は関門の中で Go から作って Rust で照らし、リポジトリに置きません。
  置く量の上限は最初の記録の大きさを見て決めます
- 段ごとの照合:記録は、相手が示す option (SACK、timestamp、窓の scale) と、試験の選択 (輻輳の制御、boost の与え方) で分けます。
  Rust の実装が段ごとに機能を足す間は、その段の機能だけを使う記録の集まりで一致を求めます
- 意図した違い:Go の不具合を Rust で直すときは、記録の違いを一覧のファイルに理由と共に書きます。
  行を足せるのは試験の担当と所有者だけで、期待した差の一覧と同じ扱いです

#### bit の一致の条件

同じ入力に同じ packet を返すには、次の点を Go と同じにします。

- 乱数:種の配分と、ChaCha8 から引く順と回数
- hash:SipHash-2-4 と鍵の使い方。hash の表の探し方は出力に出ませんが、枠の番号は出力の順に効くので、空きの枠の list の順 (小さい番号から、返した枠を先に使う) を同じにします
- 時刻:タイマーの輪の 1 ms の tick と切り上げ、ns の整数の算術
- 出力の順:4 つの組の deficit round robin、順番の list の順、制御の輪の順
- 番号:IP の ID の数え上げ、ISN と timestamp の offset の作り方
- 浮動小数点:CUBIC は `float64` の算術と 3 乗根と切り捨てを使います。
  四則は IEEE 754 で同じですが、3 乗根は Go の `math.Cbrt` と同じ値を返す実装が要ります。
  Rust の `f64::cbrt` は OS の数学ライブラリを呼ぶので、値が最後の桁で違いうるためです。
  浮動小数点から整数への変換の境界の扱いも Go に合わせます

一致を求める期間が終わった後は、この節の制約を外し、Rust に合った形 (例えば接続の表の形) を選べます。

### qbench

qbench は今、Go の中の `tun.Device` の境目で engine を動かします ([測定の計画](../userspace/wgstack-performance.md#測定の計画))。
Rust の engine には同じ口がありません。

提案:`wgstack-dut` に、Linux の TUN の上で実時間で核を動かす形を足します。
ラボの VM の network namespace の中で、qbench の Linux の DUT と同じく TUN を qbench の経路の DUT の側に繋ぎます。
アプリケーションの操作は、`linuxdut` と同じく制御用の pipe で受けます。
engine が別のプロセスになるので、byte あたりの CPU は Rust のプロセスだけを測れます。
判定の行列と規則は今と同じで、Linux と gVisor の基準も同じ VM で取ります ([判定の行列](../userspace/wgstack-performance.md#判定の行列))。
agent 全体の速さは、今と同じく `lab/tcpquality.sh` で Rust の agent を流して測ります。

### fuzz

Go の fuzz の target を cargo-fuzz に移します ([fuzzing](../userspace/wgstack-verification.md#fuzzing))。

| Go | Rust の target | 入力 |
| --- | --- | --- |
| `FuzzParse` | `parse` | packet の byte。Go の corpus をそのまま種にします |
| `FuzzCore` | `core` | op の列の byte |
| `FuzzAdversarialSender` | `adversarial_sender` | 64 bit の種 |
| (無し) | `replay` | DUT の frame の列。記録と corpus から作った列を種にします |

提案:`core` は、Go の `FuzzCore` の op の解釈と相手の TCP の模型を、同じ byte が同じ op になるように写します。
核が bit で一致する間は、Go の corpus の入力が Rust でも同じ意味になり、そのまま種に使えます。
一致を求める期間が終わった後も、解釈を変えなければ corpus は種として残ります。
各段の後に、核の会計の和が `Bound` 以下であること、表の数と予約が一致すること、核を閉じた後に会計が 0 に戻ることを確かめます。

関門の量は回数で決めます。
libFuzzer の `-runs` で回数を指定し、時間では指定しません。
並列の数と回数は、Rust の 1 秒あたりの回数を測ってから、関門の枠に収まるように決めます。
長い fuzz は別のマシンで流します。

### 上界と敵対的な保持の試験

[敵対的な保持の試験](../userspace/wgstack-verification.md#敵対的な保持の試験)の表の入力をすべて Rust に移します。
確かめることは同じで、生きているヒープの代わりに確保の数えで測ります。
stream の一致の試験 (受信と送信) も、種の数を含めて移します。
Go の `-race` の競合の試験は、核が錠を持たないので移しません。
代わりに、外側の層の試験で、多くの接続の読み書き、`close`、`abort`、待ち受けの `close`、トンネルの作り直しを同時に動かし、waker の表と核の会計が閉じた後に空に戻ることを確かめます。

台本の検出力は、今と同じく故障を入れた engine に台本を流して確かめます。
Rust では、cargo の feature で故障を 1 つずつ入れた build を作り、データの台本と `rustdut` の台本を流します。
変異の試験の道具 (例えば cargo-mutants) を使うかは、核が揃った後に決めます (未確認)。

### 関門

提案:Rust の wgstack を変える PR の関門は次の段からなります。

- B13 から B15 の Rust の検査
- `wgft-wgstack` の単体の試験と、上界と敵対的な保持の試験
- データの台本を Rust の runner で複数の種に
- Go の wgstack の記録の照合
- `rustdut` を通した反応する台本と測る台本 (Go の toolchain が要ります)
- runner どうしの照合
- fuzz の smoke (`parse`、`core`、`adversarial_sender`、`replay`)
- stream の一致の試験の全部の種

段の組み方は、今の `scripts/wgstack-gate.sh` に Rust の段を足すか別の script にするかを、最初の関門を作る PR で決めます。
ラボの一式は、所有者の規則どおり、ラボが動かすものを変えない Rust だけの変更では流しません。
Rust の agent が製品の経路で wgstack を使い始めた後は、agent の置き換えの判定に、server の両方のモードでラボの一式を流します。

## 実装の計画

### 積む PR

サイズは試験を含む行数の目安で、Go の wgstack の大きさから見積もった推定です。
担当の列の A は実装の担当、T は試験の担当です。

| 順 | PR | 担当 | 中身 | サイズの目安 | 前提 |
| --- | --- | --- | --- | --- | --- |
| 1 | この文書 | | 設計 | | |
| 2 | `feat(wgstack-rs): packets, checksums and reassembly` | A | crate の骨組み、依存と sans-IO の検査、`wire`、checksum、`frag`、`siphash`、ChaCha8、`Time`。fuzz の `parse` | 約 2,500 行 | 1 |
| 3 | `feat(wgstack-rs): tables, buffers and the bound` | A | 接続の枠、hash の表、握手の途中の表、TIME_WAIT の表、タイマーの輪、出力の list と制御の輪、chunk の置き場、送受信の輪、区間の treap、送信の記録、`Budget`、`Bound` と生成した表、確保の数えの試験の道具 | 約 3,000 行 | 2 |
| 4 | `feat(wgstack-rs): passive TCP to the completion level` | A | 受動の open、確立、データ、遅延 ACK、窓と persist、RTO、NewReno、RFC 5961 と RFC 7323、MSS と PMTU、FIN と TIME_WAIT、`close` と `abort`、アプリケーションの操作と知らせ | 約 5,000 行 | 3 |
| 5 | `feat(wgstack-rs): SACK, RACK-TLP, CUBIC and the receive window` | A | SACK の scoreboard と回復と PRR、RACK-TLP、CUBIC と HyStart++、受信の窓の自動調整、受け手の ACK と D-SACK、不要な再送の取り消し、boost の取得と回収と取り消し | 約 5,000 行 | 4 |
| 6 | `feat(wgstack-rs): UDP, ICMP and the ping endpoints` | A | UDP の endpoint と予算と会計の不整合、送信の断片化、echo と ping、ICMP の誤り、断片の入口の結合 | 約 2,500 行 | 4 |
| 7 | `feat(agent-rs): run the agent on wgstack instead of a TUN` | A | `netstack` の module、event loop、TCP と UDP の handle、中継の trait、ping、`tunnel.udp_accounting`、`inbound` の module と TUN の経路の削除 | 約 2,000 行 | 4 と 6。UDP の中継は 6 の後 |
| 8 | `test(wgstack-rs): qbench and the lab memory probe` | T と A | `wgstack-dut` の TUN の形、qbench の Rust の engine、測定用の feature | 約 1,000 行 | 5、7 |
| T1 | `test(tcpharness): data scenarios and the Go runner` | T | データの台本の形式、Go の runner、直線の台本の変換、Linux での照合 | Go 約 2,000 行と台本 | 1 |
| T2 | `test(tcpharness): DUT frames, rustdut and Go wgstack recordings` | T | frame の形式の付録、`rustdut`、記録用の adapter、最初の記録 | Go 約 1,500 行 | 1 |
| T3 | `test(wgstack-rs): the Rust runner, wgstack-dut and replay` | T | Rust の runner、`wgstack-dut` の標準入出力の形、記録の照合、runner どうしの照合 | Rust 約 2,000 行 | 4、T1、T2 |
| T4 | `test(wgstack-rs): fuzz targets and adversarial bounds` | T | `core`、`adversarial_sender`、`replay` の target、敵対的な保持の試験、stream の一致の試験 | Rust 約 3,000 行 | 3 (段ごとに 4 から 6 に合わせて足す) |

PR 4 と PR 5 は大きいので、実装の担当がレビューの単位に分けてよいとします。
分けるときも、各 PR は Go の白箱の試験のうちその範囲のものを含めます。

Go の変更 (T1、T2) は試験の道具だけで、製品の Go のコードを変えません。
ラボの一式を Go の agent の代わりに Rust の agent で流すためのラボの道具の変更は、agent の置き換えの別の作業で、この表に含めません。
Go の試験を変える PR は、規則どおり wgstack の関門を流します。
ラボの Linux で流す段 (T1 の照合) はラボの VM を使います。

### 並べられる仕事

- 試験の担当の T1 と T2 は、この文書の後すぐに、実装と並べて進められます。
  どちらも Go の側だけで完結し、凍結した Go の wgstack と Linux を相手にするためです
- 実装の 2、3、4 は順に積みます。
  核の型と表が後の段の土台になるためです
- 4 の後は、5 (TCP の性能の機能)、6 (UDP と ICMP)、7 の TCP の部分を並べられます。
  触る module が分かれるためです。
  7 の UDP の中継と ping は 6 の後に足します
- T3 は 4 の API が固まった後に始め、T4 は 3 の後から段ごとに足します
- 8 は 5 と 7 の後です

### 試験の担当の仕事

- データの台本の形式を決め、直線の台本をデータに移し、Go の runner と Rust の runner を書きます
- `rustdut` と `wgstack-dut` の標準入出力の形を書き、反応する台本と測る台本を Rust の engine に流します
- 凍結した Go の wgstack の記録を作り、Rust の照合を書き、意図した違いの一覧を保ちます
- fuzz の target と、上界と敵対的な保持の試験と、stream の一致の試験を書きます
- 故障を入れた build で台本の検出力を確かめます
- 期待した差の一覧と意図した違いの一覧に行を足すときは、理由を書きます

試験の担当は Rust の wgstack の実装のコードを読まず、公開の API の文書だけを読みます。
実装の担当は試験の担当の台本と runner を直しません。
台本が誤っていると考えたら、理由を書いて試験の担当に返します。

### 後の段

agent の置き換えが終わった後に、次の段を順に決めます。

- 需要で育つバッファ ([需要で育つバッファとの関係](#需要で育つバッファとの関係))
- 参照の Linux が 7.2 に移ったことで生じた受け手の変更の候補。
  候補の一覧は `docs/design/userspace/wgstack-receive-linux72.md` にあります
- dial の側と server の Device ([dial の側を足す継ぎ目](#dial-の側を足す継ぎ目))
- 送信の経路の system call のまとめ (Linux の `sendmmsg` と UDP の GSO) と、受信の経路のまとめ

## 実装の時に決めること

- 写さずに読み書きする口:`read_slices` と `write_slices` を足すか。CPU を測ってから決めます
- データプレーンのスレッド:1 つのスレッドで暗号と核と中継を済ませる形で、CPU の目標と速さに足りるか。
  足りなければ、暗号を別のスレッドに移す形を device の層で決めます
- device の層との受け渡し:`Device::poll_packet` と `Device::poll_transmit` が packet ごとに確保する形を、呼び手の buffer に書く形に替えるか
- `netstack` の module の置き場:server が dial の側を使うときに、`wgft-agent` から共有の crate に移すか
- ChaCha8 と 3 乗根:Go の `ChaCha8` と `math.Cbrt` と同じ値を出す実装を wgft の中で書くか、条件に合う crate を使うか。
  Go の実装を写す場合は Go の license の通知が要ります
- 記録の量:リポジトリに置く記録の量の上限と、関門の中で作る記録の範囲
- 記録の分け方:相手の option と試験の選択のどの組を、どの段の一致の条件にするか
- frame の形式:種類の一覧、中身の形、版の印
- データの台本の語彙:反応する振る舞いを組み込みにしないための線引き。
  組み込みが要る台本は、データにせず Go のコードに残します
- 関門の組み方:今の `scripts/wgstack-gate.sh` に段を足すか、別の script にするか。
  各段の回数と並列の数
- `WGFT_AGENT_BATCH_MIB`:値から 1 回の起床で作る packet の数と buffer の上限を導く式
- 割り当て器:OS の標準と mimalloc のどちらにするか (測ってから)
- 時計:ホストの一時停止の間を数える時計を使うか (device の層と同じ決定に従います)
- TUN の殻:ラボの一式が Rust の agent で通った後に消すか
- crate ごとの clippy の設定:`disallowed-methods` が `wgft-wgstack` だけに効く形で置けるか (未確認)。
  効かなければ、禁止を source の検査の試験で行います

## 未確認の点

- Rust の核の byte あたりの CPU と、Go の wgstack と gVisor との比は測っていません
- 1 つのスレッドのデータプレーンが、Windows と macOS の時計の分解能とスケジューラの下で、遅延 ACK と RTO の規則を保てるかは確かめていません
- Go の `ChaCha8` が C2SP の `chacha8rand` と同じ列を出すことは、仕様を読んだ範囲の判断で、試験では確かめていません
- 確保の数えで測る保持と RSS の比は、Rust の agent では測っていません
- 台本の変換で、Go のコードの台本とデータの台本が Linux で同じ結果になるかは、変換してみるまで分かりません

[v2: Rust への移行](README.md)
