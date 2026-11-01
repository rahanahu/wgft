# wgstack の Rust 版

この文書は、v2 の Rust の agent が使う wgstack の Rust 版の設計を定めます。
wgstack は wgft 自身の TCP/IP の stack です。
agent のユーザー空間モードは、トンネルの中の TCP、UDP、ICMP をこの stack で終えます。
このため Rust の agent は root の権限も TUN も要りません。
段を踏んで実装しています。
PR 6 の範囲 (受動の open、閉じる手順と TIME_WAIT、アプリケーションの操作と知らせ、データの送受信、RTO、窓の probe、SACK による回復と D-SACK、RACK-TLP、不要な再送の取り消し、CUBIC と NewReno、boost の取得と回収、UDP の endpoint と予算、echo と ping、ICMP の誤りと PMTU、断片の入口) まで実装しました。
構造、境目、メモリ、作業の順をここで決め、値と細部は[実装の時に決めること](#実装の時に決めること)に残します。

## この文書の読み方

振る舞いの正本は、Go の wgstack の設計文書のままです。

- 核の構造、不変条件、上界の式、尽きたときの動作:[エージェントの wgft の netstack](../userspace/wgstack.md)
- 性能の段階の機能 (SACK、RACK-TLP、CUBIC、受け手の ACK と窓):[wgstack の性能の段階](../userspace/wgstack-performance.md)
- 試験の形と期待した差:[wgstack の検証](../userspace/wgstack-verification.md)
- 入口の検査と UDP の会計:[IPv4 の断片、ICMP、TCP の MSS の検査](../userspace/packet-validation.md)、[UDP の受信と出力の会計](../userspace/udp-accounting.md)
- トンネルの中の約束:[トンネルの中の約束](../spec/tunnel.md)

この文書は、Rust に移すときに変わる部分と移し方だけを書きます。
Go の文書の規則をここに写しません。
Go の文書と食い違う点は、この文書が理由と共に挙げたものだけです。

関わる設計は次のとおりです。
agent の置き換えの設計はまだ `feat/v2-rust` に入っていないので、道で示します。

- [試験の道具の設計](test-tooling.md):台本の言語、2 つの runner、DUT の口、記録の照合、qbench、fuzz、関門の細部を持ちます。
  この文書の[検証](#検証)は、その設計の決定を前提にして要点だけを書きます
- agent の置き換え (#680、`docs/design/v2/agent-parity.md`):device の殻、データプレーンの駆動の実装、中継、UDP の中継、制御ソケットを持ちます。
  データプレーンの駆動の規則の正本はこの文書の[データプレーンの駆動](#データプレーンの駆動)で、#680 はそれを実装します

各項目には、所有者が決めた「決定」と、この文書が勧める「提案」の印を付けます。
所有者の確認を待つものは「仮の決定」と書きます。
提案は実装の PR で確かめてから採り、採らなかった提案と変えた提案はその PR でこの文書を直します。

### 前提となる所有者の決定

- 決定:Go の wgstack を Rust に移植します。smoltcp は SACK の回復、TCP の timestamp、RACK-TLP を持たないので使いません (2026-11-01)
- 決定:Rust の wgstack の核は sans-IO にします。入力は時刻、packet、操作で、出力は packet、次に起こす時刻、イベントです。核の中にスレッド、実時間のタイマー、ソケットを置きません ([設計の制約](README.md#設計の制約))
- 決定:Go の wgstack は参照の実装として今の形で凍結し、機能を足しません。Rust の実装が追いついた後に消します ([Go の wgstack](README.md#go-の-wgstack))
- 決定:移行の間、Rust の wgstack は凍結した Go の wgstack と同じ入力に同じ packet を返すことを求めます。Go の wgstack の記録とオフラインで bit の単位で照らし、追いついた後は自由に変えます (2026-11-01)
- 決定:適合の台本は混成で持ちます。直線の台本はデータにし、Go の runner と Rust の runner が同じファイルを流します。反応する台本と測る台本は Go のまま残し、Rust の試験用のプログラムを標準入出力で時計ごと動かします。C ABI は作りません (2026-11-01)
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
| `stack.go`、`const.go`、`stats.go` | `stack`、`stack::shared`、`config` | 核、作成、上界の計算、数え |
| `device.go` | `stack` と `config` | 作成の値の検査と核の作成。`tun.Device` の面とタイマーの goroutine は移しません |
| `conn.go`、`listener.go` の操作 | `stack::api` | 接続のアプリケーションの操作 (読み書き、`CloseWrite`、`Close`、`Abort`、`Delivered`、古い handle)。期限と通知の channel は移しません |
| `tcb.go`、`tcpin.go`、`tcpout.go`、`timers.go`、`fault.go` | `tcp::conn`、`tcp::ctx`、`tcp::input`、`tcp::output`、`tcp::timers` | 接続の枠と確立と閉じる手順、受け入れの判定、segment を作る処理、タイマー、会計の不整合 |
| `syn.go`、`listener.go` | `tcp::syn`、`tcp::listen` | 握手の途中の表、待ち受け、accept の待ち行列 |
| `timewait.go` | `tcp::timewait` | TIME_WAIT と FIN_WAIT_2 の行の表 |
| `ring.go`、`recv.go`、`records.go` | `buf::chunk`、`buf::recv`、`buf::records` | chunk の置き場、送受信の輪、区間の treap、送信の記録 |
| `ack.go`、`ackpolicy.go`、`rcvwin.go` | `tcp::ack`、`tcp::ack_policy`、`tcp::rcv_window` | RTT と RTO、受け手の ACK、受信の窓の自動調整 |
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
  待つことと期限は、外側の handle の層が持ちます ([アプリケーションの操作](#アプリケーションの操作))
- 中継が型アサーションで探すメソッド:`Abort`、`CloseWrite`、`Delivered`、`CloseForDelivery`、`OnBoost` は、核の操作と handle の層のメソッドになります
- boost の枠の集まり:提案として、プロセスで 1 つの集まりを `Budget` という値にし、トンネルを作り直すときに古い核から新しい核へ渡します ([予算の持ち主](#予算の持ち主))
- 出力:Go の `Read` は wireguard-go の buffer に packet を書き、末尾に送信のバッチの印を書きます。
  Rust の核の `poll_transmit` は呼び手の buffer に packet を 1 つ書くだけです
- 上界の数え方:Go の `Bound` は、Go のヒープの確保の丸めを `append` の容量で測ります。
  Rust は型の大きさと確保した容量から数えます ([上界の式の写し方](#上界の式の写し方))

### 移さないもの

- 送信の向きのバッチの台帳 (`batch.go`):提案として移しません。
  台帳は wireguard-go の staged のキューと送信のキューに滞留する buffer を数えるための仕組みです ([送信の向きの予算](../userspace/wgstack-batching.md#送信の向きの予算))。
  Rust の agent では device の層を wgft が持ち、核の出力を device の層に渡す規則 ([データプレーンの駆動](#データプレーンの駆動)) が滞留を device の層の上限の内に保つので、台帳も印も鍵も要りません。
  核が乱数を直接読む例外もこれで無くなります
- `tun.Device` の面:`Name`、`File`、`Events`、`BatchSize` は wireguard-go との境目のもので、Rust の核は持ちません
- gVisor と並べるための差し替えの面:Go のトンネルの非公開の interface、`internal/nettun` と同じ形の `Create`、gVisor の挙動に合わせた互換の部分は移しません
- 読み書きの期限:核は期限を持ちません。Go の核が壁時計を読む例外はこれで無くなります
- `ManualClock` と Device のタイマーの goroutine:sans-IO の核は呼び手が時刻を渡すので、試験用の時計の型も本番のタイマーの goroutine も要りません

### crate の分け方

提案:次の crate に分けます。

| crate | 中身 | 依存 | 書き手 |
| --- | --- | --- | --- |
| `crates/wgft-wgstack` | sans-IO の核 | 標準ライブラリだけ | 実装の担当 |
| `crates/wgft-netstack` | 核を tokio の上で使う handle の層。TCP、UDP、ping の非同期の handle、waker の表、操作の知らせ | `wgft-wgstack`、tokio | 実装の担当 |
| `crates/wgft-wgstack-bench` | 核の segment ごとの受信と送信の経路の criterion のベンチ。配布せず、`wgft` のバイナリにも入りません | `wgft-wgstack`、dev 依存の `criterion` | 実装の担当 |
| `crates/wgft-wgstack/fuzz` | cargo-fuzz の target。ワークスペースの member に入りません | `wgft-wgstack`、`libfuzzer-sys` | target ごとに[fuzz](#fuzz)の表が決めます |
| `crates/wgft-tcpharness`、`crates/wgft-wgstack-dut` | 試験の道具と DUT のバイナリ。配布せず、`wgft` のバイナリにも入りません | `wgft-wgstack` | 試験の担当 |

handle の層を `wgft-agent` から分けるのは、後で Rust の server が dial の側で同じ層を使うためです。
device の層と核を組み、UDP のソケットとタイマーを回す駆動の実装は `wgft-agent` に置き、#680 が持ちます。

### 依存と隔離の検査

提案:Go の `internal/dataplane/deps_test.go` の `TestWgstackImports` に当たる検査を次の形で持ちます。

- 依存:`wgft-wgstack` の `[dependencies]` は空にします。
  `[dev-dependencies]` にも試験の道具の crate を入れません。
  criterion のベンチも別の crate `crates/wgft-wgstack-bench` に置き、核の crate の依存の表を空に保ちます。
  crate の試験 (`src/scan_tests.rs`) が manifest を読み、依存の表が空であることを確かめます。
  CI の job を足さずに `rust-check` の中で流れるためです
- sans-IO と伸びる collection:`wgft-wgstack` の clippy の設定の `disallowed-methods`、`disallowed-types`、`disallowed-macros` で、`Instant::now`、`SystemTime::now`、スレッドの作成、`std::net` のソケット、ファイル (`std::fs`)、環境変数 (`std::env`)、プロセス (`std::process`)、標準入出力、OS の乱数の読み取りと、容量を自動で伸ばす操作 (`Box`、`Rc`、`Arc` の型と文字列を作る操作を含みます) ([確保の規則](#確保の規則)) を禁じます。
  設定は `crates/wgft-wgstack/clippy.toml` に置きます。
  clippy は crate の manifest の directory から上へ設定を探すので、この一覧はこの crate だけに効きます。
  PR 2 で、禁じた呼び出しを置いた build が警告になり、ほかの crate は警告にならないことを確かめました
- source の走査:clippy の一覧に加えて、同じ禁止の語で source を走査する試験を置きます。
  clippy が見ない cfg (`fuzzing` と故障の注入) の中のコードを確かめ、clippy の一覧から項目が消えていないことも確かめます。
  文字列の照合なので、注釈と試験の module は見ません
- unsafe:`wgft-wgstack` は `#![forbid(unsafe_code)]` にします。
  checksum も `as_chunks` と `u64::from_be_bytes` の安全なコードで書きます
- 製品の木:CI の `cargo tree` の検査が、`wgft` のバイナリの依存の木に `wgft-tcpharness` と `wgft-wgstack-dut` が無いこと、測定用の feature が有効でないことを確かめます。
  今の `rust-check` は crate の検査を、すべての target と feature を有効にした依存の木で行います。
  feature の検査は、測定用の feature を足す段で足します
- I7 の隔離:後で作る agent のカーネルモードの crate が、推移的にも `wgft-wgstack` に依らないことを、製品の木と同じ `cargo tree` の検査で確かめます。
  カーネルモードの agent は wgstack を作りません

`no_std` で sans-IO を構造で強いる案は採りません。
`alloc` を使うには `extern crate alloc;` の宣言が要るうえ、禁止の一覧で同じ効果を得られるためです。

## sans-IO の API

この節の型と関数の名前は提案です。
形 (入力、出力、待たない操作、知らせ) は決定に従います。

### 作成と終わり

- 作成:`Stack::new(config, budget, seed, hook)` が、作成の時の設定 (受け付ける宛先の集合、MTU、K、試験だけが小さくする上限の組、試験の選択) から表をすべて確保します
- MTU:576 から 9216 を受け付け、外の値は設定の誤りにします。
  server が送る範囲に合わせた範囲です。
  範囲の外の値を 1420 に替えるのは agent の側 (#680) です
- 受け付ける宛先の集合:agent ではトンネルのアドレスの /32 の 1 つだけです。
  提案 (PR 3 で採用):`Config` はこの 1 つのアドレスだけを持ちます。
  プレフィックスの集合は dial の側を足す段で `Config` に足します
- 作成の失敗 (提案、PR 3 で採用):`Stack::new` は設定の誤りと確保の失敗を `NewError` で返し、渡した `Budget` を `NewError::into_budget` で取り戻せます。
  作り直しが失敗しても `Budget` を失わないためです
- 表の大きさ (提案、PR 3 で採用):Go の package の中の `limits` に当たる値を公開の `Limits` にします。
  試験の担当が `FuzzCore` の小さな上限を外の crate から渡すためです。
  握手の途中の表と accept の待ち行列は 0 を受け付けます。
  待ち受け 1 つの accept の待ち行列と握手の途中の行は全体の半分までで、16 bit で数えるので、全体はその 2 倍を超えられません
- 終わり:`close(self, now) -> Closed` が、待ち受けと接続とソケットをすべて閉じ、`Budget` と最後の会計 (`Held`) を返します。
  最後の会計がすべて 0 であることを、試験と debug の build で確かめます

### 入力

| 入力 | 関数 | 中身 |
| --- | --- | --- |
| トンネルから届いた packet | `handle_packet(now, &[u8])` | device の層が復号して検査した IPv4 の packet。核は呼び出しの間だけ読み、保持するものは自分の予約に写します |
| 時刻 | `handle_timeout(now)` | 期限の来たタイマー、行の期限、再組み立ての表の掃除 |
| アプリケーションの操作 | 後述 | TCP、UDP、ping の操作。どれも `now` を受けます |

`handle_packet` は誤りを返しません。
Go の `Write` が誤りを返すのは閉じた後と IPv4 でない packet だけです。
閉じた後の呼び出しは、`close` が核を消費するので Rust では起きません。
IPv4 でない packet は device の層が捨てます。
捨てた packet は理由ごとに数えます ([誤りと捨てた数](#誤りと捨てた数))。

`handle_timeout` は、Go の `Tick` と同じく、期限の来たタイマーを新しい `now` の時刻で 1 回ずつ動かします。
期限そのものの時刻に戻って動かすことはしません。

### 出力

| 出力 | 関数 | 中身 |
| --- | --- | --- |
| 送る packet | `poll_transmit(now, &mut [u8]) -> Option<usize>` | 次に送る IPv4 の packet を 1 つ呼び手の buffer に作り、長さを返します。buffer は MTU 以上の長さを持ちます |
| 次に起こす時刻 | `poll_timeout() -> Option<Time>` | 次に `handle_timeout` を呼ぶ時刻 |
| 知らせ | `poll_event() -> Option<Event>` | 接続とソケットの準備の変化 ([準備の知らせ](#準備の知らせ)) |
| ログの行の材料 | `poll_log() -> Option<LogLine>` | 1 分に 1 回までの門を通った拒否の数 |

出力は Go と同じく待ち行列に積みません。
接続と行は「送るものがある」印を自分の中に持ち、`poll_transmit` の時にその場で packet を作ります ([出力](../userspace/wgstack.md#出力))。
制御の組だけが、作成の時に確保した制御の輪に積みます。
呼び手が `poll_transmit` を呼ばない間、出力の保持は増えません。

### アプリケーションの操作

操作はどれも待たずに戻ります。
「今はできない」は `WouldBlock` で返し、できるようになったら[準備の知らせ](#準備の知らせ)を出します。
`WouldBlock` を返す操作は核の状態を変えません。

- TCP の待ち受け:`listen_tcp(now, SocketAddrV4) -> Result<ListenerId>`、`accept(now, ListenerId) -> Result<(ConnId, SocketAddrV4)>`、`close_listener(now, ListenerId)`。
  待ち受けを閉じると、Go と同じく accept の待ち行列の接続と握手の途中の行に RST を送ります
- TCP の接続:`read(now, ConnId, &mut [u8])`、`write(now, ConnId, &[u8])`、`close_write`、`close_conn`、`abort`、`delivered`、`local_addr`、`peer_addr`。
  読み取りは、相手の FIN の後に `Eof` を、RST と会計の不整合の後に誤りを返します。
  `close_for_delivery` は Go と同じく `close_conn` と同じ動作です。
  PR 4a で、接続を閉じる操作の名前を `close` から `close_conn` に変えました。
  核を消費する `close(self, now)` と同じ名前を持てないためです。
  `read` は、`dst` が空でないときの 0 を EOF とします (std の `Read` と同じ約束です)。
  古い handle の `local_addr` と `peer_addr` は `None` を返します
- 写さずに読み書きする口:提案として、受信の輪の生きている範囲を 2 つの slice で見せる `read_slices` と `consume`、送信の輪の空きに直接書く `write_slices` と `commit` を足します。
  中継が LAN 側のソケットとの間で中身を 1 度だけ写すためです。
  採るかは CPU を測ってから決めます
- UDP:`bind_udp(now, SocketAddrV4) -> Result<UdpId>`、`recv_from(now, UdpId, &mut [u8]) -> Result<(usize, SocketAddrV4)>`、`send_to(now, UdpId, &[u8], SocketAddrV4)`、`close_udp`。
  `send_to` は送信の予算を予約できなければ `WouldBlock` を返し、予約できるようになったら知らせます。
  Go の `WriteTo` が予約できるまで待つ挙動は、handle の層の待ちになります
- keepalive の ping:`open_ping(now, Ipv4Addr) -> Result<PingId>`、`send_ping`、`recv_ping`、`close_ping`。
  表は Go と同じ固定の大きさで、満杯なら誤りを返します
- 会計の故障:`udp_receive_fault() -> Option<UdpFault>` が、`agent doctor` の `tunnel.udp_accounting` に使う最初の違反を返します ([会計の不整合](../userspace/udp-accounting.md#会計の不整合))
- 状態:`stats() -> Stats`、`bound() -> Bound`、`held() -> Held`
- 不変条件の確かめ:`check_invariants() -> Result<(), InvariantError>` が、予約の和が `Bound` 以下であること、表の数と予約が一致すること、chunk と配列の持ち主が 1 つであることを確かめます。
  公開の API として文書に書き、試験の担当の fuzz と敵対的な試験が使います。
  確かめるのは、表ごとの空きの list (範囲、重なり、使っている行を指さないこと) と使っている印と数の一致、hash の表の項目が探索で届くこと、list の向きと範囲、タイマーの輪の桶と印、区間の treap の順序と数、chunk の数と輪の一致、接続の枠の段と配列の一致、boost の枠の保有者と接続の一致と貸した枠が配列を持たないこと、accept の待ち行列の長さ、予約の和と上界です。
  範囲の外の番号は panic せずに違反として返します。
  検出の 1 つずつに、壊した状態を渡す試験があります。
  核の段が状態を足すたびに確かめを足します。
  呼んだ時だけ手間がかかり、製品は呼びません

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

提案:`Event` は次の種類を持ちます。

- `Readable(ConnId)`、`Writable(ConnId)`、`Closed(ConnId)`
- `Acceptable(ListenerId)`
- `UdpReadable(UdpId)`、`UdpWritable(UdpId)`
- `PingReply(PingId)`

知らせは待ち行列に積みません。
対象ごとに「知らせることがある」印の bit と順番の list の節を、枠と表の中に固定で持ち、`poll_event` がその list の先頭から取り出します。
同じ対象の同じ種類の知らせは、取り出すまで 1 つにまとまります。
枠や表の行を別の対象に使い直すときは、印の bit を消し、list から節を外します。
このため、知らせの保持は枠と表の数で決まり、呼び手が取り出さなくても増えず、古い対象の知らせが新しい対象に届くこともありません。
知らせはきっかけで、状態の正本ではありません。
提案 (PR 3 で採用):対象の番号は、接続の枠、待ち受けのポートの順に並べた 1 つの list にします。
UDP と ping の対象は、その表を作る段が足します。
呼び手は知らせを受けたら操作を試し、`WouldBlock` なら次の知らせを待ちます。

PR 4a で次のように決めました。

- `Readable` と `Writable` は、Go が読み取りと書き込みの通知の channel に知らせる所で付けます。
  `close_conn` は両方を、`close_write` は `Writable` を付けます。
  accept した接続の枠を返す時 (`abort`、閉じた後の RST、TIME_WAIT の表の行に移す時など) も、Go が通知の channel を
  閉じて待つ呼び手を起こすのと同じく両方を付けます。
  `Closed` は、接続が CLOSED になる所 (相手の RST、再送か窓の probe の打ち切り、会計の不整合、TIME_WAIT の期限) で
  `Readable` と `Writable` と一緒に付けます
- 枠を返した後に取り出した接続の知らせは、枠を最後に使った接続の handle (世代を 1 つ戻した値) で出します。
  枠を返すのはアプリケーションが閉じた後か、まだ accept していない接続だけなので、呼び手の handle は知らせと
  一致します。
  枠を確立に使い直すときに、その枠の印を消します
- `Acceptable` は accept の待ち行列に入れた時と、accept の後にまだ接続が残る時に付けます。
  待ち受けを開く時と閉じる時に、そのポートの印を消します
- accept の時には知らせを付けません。
  accept の前に届いたデータの `Readable` は、呼び手がまだ知らない handle で `Acceptable` より後に出ることがあります。
  呼び手は accept した接続を、待つ前に一度 `read` と `write` で試します
- 自分の FIN の確認で LAST_ACK から CLOSED に移り、アプリケーションが閉じていて枠を返す接続の `Writable` と
  `Closed` は、枠を返した後に取り出すので、上の規則どおり枠を最後に使った接続の handle で出ます

boost の変化は知らせに入れず、hook だけで伝えます ([boost の hook](#boost-の-hook))。

### 時刻と乱数

提案:

- 時刻:核の時刻は `Time` で、任意の起点からの単調な ns の符号なしの整数です。
  Go の核の時刻 (起点からの int64 の ns) と同じ値を持てるので、記録の時刻をそのまま渡せます。
  `Time` と `Duration` の足し算と、`Time` どうしの引き算は飽和します。核の中で panic を起こさないためです。
  駆動の層は、作成の時の `Instant` からの経過を ns にして渡します。
  PR 4a で、核は受けた時刻を `i64::MAX / 4` ns (約 73 年) で止めることにしました。
  核は時刻に期限の長さ (最も長いのは PAWS の 24 日) を足すので、止めないと上限の近くの時刻で足し算が溢れます。
  止めた後の時刻ではタイマーが進まなくなりますが、73 年を超える時刻を渡す呼び手は製品にありません
  時刻が前の値より戻ったときは、前の値を使います
- 停止の間の時計:駆動の層は、device の層に渡すものと同じ時刻を核に渡します。
  時計はデータプレーンの時計で、Linux と macOS では一時停止の間に止まり、Windows ではスリープの間も進みます ([agent の置き換えの時計](agent-parity.md#時計))
- 乱数:作成の時に 64 byte の種を渡します。
  Go と同じく、先頭の 16 byte を ISN の鍵、次の 16 byte を表の hash の鍵、残りの 32 byte を ChaCha8 の種にし、timestamp の鍵、IP の ID の始めの値、challenge ACK の揺らぎ、区間の treap の優先度は ChaCha8 から引きます。
  製品は OS の乱数から種を作り、試験は固定の種を渡します
- ChaCha8:bit の一致のため、Go の `math/rand/v2` の `ChaCha8` と同じ列を出す生成器を wgft の中で書きます。
  C2SP の `chacha8rand` の仕様から書き、Go のコードは写しません。
  Go が出す列と一致することを、いくつかの種でそれぞれ種の作り直しを 2 回越える数の値を照らす試験で確かめました。
  種の配分 (ISN の鍵、表の鍵、timestamp の鍵、IP の ID の始めの値) と、その後の範囲を決めた乱数も同じ試験で照らします

### boost の hook

Go の `OnBoost(f)` は、接続の錠の中で f を呼び、`f(false)` が偽を返したら floor への戻りを取り消します。
`internal/netpipe` の `FollowBoost` は、LAN 側のカーネルのソケットが floor を超える受信のデータを持つ間、偽を返します。

提案:核は作成の時に呼び手の hook を受け取り、型の引数で持ちます (`Stack<H: Hook>`)。

- `boost_granted(conn)`:boost を得た時に呼びます
- `may_return(conn) -> bool`:需要の無い保有者を floor に戻す前に呼び、偽なら戻りを取り消します
- `boost_returned(conn)`:floor に戻した後に呼びます
- `trace(event)`:Go の `Config.Trace` に当たる観測です。製品の hook は何もしません

hook は核への参照を受け取らないので、核を呼び返せません。
中継の層は、`ConnId` から LAN 側のソケットを引く固定の大きさの表を核の外に持ち、`may_return` の中でそのソケットの受信のデータの量を読みます。
試験は、決まった答えを返す hook を渡します。

### 誤りと捨てた数

数える種類と 1 分に 1 回までのログの門は Go と同じです ([尽きたときの動作](../userspace/wgstack.md#尽きたときの動作))。
門は核の時刻で判定します。
核はログを書かず、門を通った数を `poll_log` で出します。
駆動の層がそれを英語の 1 行にしてログに出します。

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

## データプレーンの駆動

この節は、agent が device の層と核を動かす規則の正本です。
#680 が `wgft-agent` に実装し、この節と食い違う実装はこの節を先に直します。

### スレッドと所有

提案:データプレーンは、トンネルの世代ごとに 1 つの OS のスレッドで動かします。
そのスレッドは tokio の current-thread の実行環境を持ち、次のものを `Rc<RefCell<Dataplane>>` の 1 つの値として持ちます。

- WireGuard の device の層 (`wgft_wireguard::Device`)
- wgstack の核
- `wgft-netstack` の waker の表 (作成の時に枠と表の数で確保します)

UDP のソケットは駆動の task が持ちます。
中継の接続の task も同じスレッドの local の task として動き、`wgft-netstack` の handle を通して核を呼びます。
制御プレーン (stream、ハートビート、制御ソケット) は別の多スレッドの実行環境に置き、データプレーンには容量の決まった channel で命令を送ります。
命令は待ち受けの開閉、状態の読み出し、ping のように頻度が低いものだけです。

agent の device の殻の段は、核と waker の表を 1 つの trait (`dataplane::Upper`) の背後に置いて、この形を実装しました。
核の段は、核と waker の表をこの trait で包んで繋ぎます。
継ぎ目の形と決めた値は [データプレーンのスレッドと送る経路](agent-parity.md#データプレーンのスレッドと送る経路)にあります。

`RefCell` には次の規則を置きます。

- 借用は同期の区間の中だけで取り、`.await` をまたいで持ちません
- waker は借用を返した後に起こします
- hook は `Dataplane` を借用しません。hook が使う LAN 側のソケットの表は `Dataplane` の外に置きます。
  hook は核の `&mut` の中で呼ばれるので、借用すると二重の借用になるためです

### 1 回の起床

駆動の task は、UDP のソケットの準備、タイマー、操作の知らせ (後述) の 3 つを待ち、起きたら次の順に処理します。

1. UDP のソケットから datagram を読み、`Device::handle_datagram` に渡し、`Device::poll_packet` が出す packet をすべて核の `handle_packet` に渡します
2. 時刻が来ていれば、device の層と核の `handle_timeout` を呼びます
3. 送り出しを次の規則で行います
4. `poll_event` の知らせで waker を起こし、`poll_log` の行をログに出します
5. device の層と核の `poll_timeout` の早い方でタイマーを張り直します

送り出しの規則は次のとおりです。

- 先に device の層:`Device::poll_transmit` が出す datagram を、ソケットが受け付ける間すべて送ります
- 核から取り出す条件:device の層がピアとの使えるセッションを持ち、device の層の送る datagram の待ち行列が空の間だけ、核の `poll_transmit` で packet を 1 つ作り、`Device::handle_packet` で暗号にし、出た datagram を送ります。
  これを 1 回の起床の上限の数まで繰り返します
- セッションが無いとき:核から取り出さず、device の層にハンドシェイクを始めさせます。
  セッションの無いピアへの packet はハンドシェイクを待つ待ち行列に入り、溢れると古いものから捨てられるためです。
  device の層の口は `Device::has_session` と `Device::start_handshake` です。
  `has_session` は、sanstun が送信に使うセッションの条件を公開の値から写した判定で、迷う所では偽を返します ([agent の WireGuard の device の層](wireguard-device.md#セッションの有無とハンドシェイクの開始))
- ソケットが書けないとき:核から取り出しません

この規則で、核の出力は device の層の上限の内側にだけ滞留し、wgstack と UDP のソケットの間に上限の外の待ち行列はできません。
核の出力は呼ばれない間も保持を増やさないので、送り出しの詰まりは核の中に積もらず、TCP の再送で回復します。
これは Go の設計の「出力の詰まり」と同じ性質です。

### 操作の知らせ

`wgft-netstack` の handle は、出力を生みうる操作の後に、同じスレッドの `tokio::sync::Notify` で駆動の task を起こします。
対象の操作は `write`、`close_write`、`close`、`abort`、`read` (窓の更新を生むため)、`close_listener`、`send_to`、ping の送信です。
駆動の task は起きたら 1 回の起床の処理を行います。

### スレッドを 1 つにする理由と危険

1 つのスレッドにするのは、核の `&mut` を保ちながら、中継の読み書きと暗号を同じ所で済ませられるためです。
暗号を含むデータプレーンが 1 つの CPU に縛られる点は危険として残ります。
CPU の目標は置き換えの条件に入れないので ([置き換えの判定](#置き換えの判定))、byte あたりの CPU と速さは置き換えの後に測ります。
足りなければ、暗号を別のスレッドに移す形を device の層の設計で決めます。

### 世代と予算の受け渡し

トンネルを作り直すときは、次の順にします。

1. 中継の接続と待ち受けを閉じます
2. データプレーンの実行環境を止め、スレッドを join します
3. 核の `close` が返す `Budget` を取り出します
4. 新しい世代のスレッドに `Budget` を渡して核を作ります

`Budget` は、作り直しが失敗して再試行の待ちに入る間も、作り直しを管理する task が持ち続けます。
データプレーンの panic は次のように扱います。

- local の task の panic:中継の task のように spawn した local の task の panic は tokio が捕まえ、スレッドは終わりません
- 核の呼び出しの panic:`wgft-netstack` は核を借用するたびに drop guard を置き、借用の中で巻き戻しが起きたら `Dataplane` に毒の印を付けます。
  核の状態は途中で壊れているかもしれないためです
- 駆動の終わり:駆動の task は毒の印を見たら終わり、スレッドも終わります。
  このため、核の呼び出しの中の panic は、どの task で起きてもその世代を終わらせ、agent が作り直します。
  核の外で panic した task はその task だけが終わり、巻き戻しで落ちる handle の `Drop` がその接続を `abort` して枠を返します
- 新しい `Budget`:終わった世代の `Budget` は取り出さず、agent は新しい `Budget` を作ってトンネルを作り直します。
  古い世代の `Dataplane` はスレッドの終わりで解放されるので、集まりはプロセスで 1 つのままです

ワークスペースは release の build でも panic を巻き戻します。
配布のために panic でプロセスを止める設定を選んだ場合は、この作り直しは起きず、プロセスが終わります。
データプレーンのスレッドがどの理由で終わっても、作り直しを管理する task はそれを知り、トンネルを作り直します。
device の層のハンドシェイクの時刻の高い水位 (`Device::unix_high_water`) も、同じ受け渡しで次の世代に渡します。

## メモリ

### 接続の枠の配置

決定 (所有者、2026-11-01):データプレーンのコードは CPU のキャッシュに合わせて配置します。
segment ごとの経路が触る欄をまとめ、まれにしか触らない欄から分けます。
tick ごとにたどるものは配列と番号で持ち、pointer をたどりません。
輪は連続した領域に置き、ほかのスレッドが読む数を segment ごとの欄の行に置きません。
配置は意味を変えないので、Go の wgstack の記録との bit の一致の条件はそのまま守ります。

PR 4a で次の形にしました。

- 接続の枠は、同じ番号で引く 3 つの配列に分けます。
  `Tcb` は segment ごとの経路が触る欄 (番号、窓、タイマーの期限、輻輳の窓、送信の記録の scoreboard、印) で、
  `repr(C, align(64))` で受信の入口が最初に触る欄を前に並べ、枠どうしがキャッシュの行を分け合わないようにします。
  `ConnCold` は不要な再送の取り消しと boost の需要のような、まれにしか触らない欄です。
  `ConnBufs` は送受信の輪と記録の輪の管理で、`repr(C)` で小さな管理の欄を前に、輪の chunk への pointer の配列
  (1 つの輪で 2 KiB) を後ろに置きます
- 前の段の `ConnSlot` は、2 つの輪の pointer の配列 (合わせて約 4 KiB) を接続の欄と同じ値に持っていました。
  segment ごとの欄はその間に散らばっていました。
  配列を `ConnBufs` に移したので、`Tcb` の行は配列に押し広げられません
- accept の待ち行列の節は、別の接続の処理が書き換えるので、接続の枠から出して番号で引く配列 (`QLink`) にし、
  核の共有の状態に置きます。
  接続の処理が自分の枠と共有の状態を同時に `&mut` で借りられるようにするためでもあります
- タイマーの輪、出力の list、知らせの list は前の段から番号の表です
- 数えと 1 分に 1 回の門は核の共有の状態にあり、`Tcb` の行にありません。
  核は 1 つのスレッドの値で、ほかのスレッドは読みません
- 上界の `conn_slots` の項は 3 つの配列と空きの list と待ち行列の節の型の大きさで数え、表を生成し直しました

#### 測り方と測った値

ベンチの crate `crates/wgft-wgstack-bench` は、公開の API だけで核と相手の接続を組み、segment ごとの経路を測ります。

- `recv_segment/N`:N 本の接続を順に回し、相手から順序どおりの 1380 byte の segment を 1 つ届け、核の出力を
  取り出し、アプリケーションが読みます
- `send_segment/N`:N 本の接続を順に回し、1 segment 分を書き、核が送る segment を取り出し、相手が確認します
- `rig_overhead/build_and_parse`:道具だけの費用です。同じ大きさの相手の packet を組み立てて checksum を計算し、
  ACK の大きさの packet を解きますが、核は呼びません
- `recv_segment_sack/N`、`send_segment_sack/N`:同じ負荷を、相手が SYN で SACK-permitted を示した接続で流します。
  ACK ごとの RACK の状態の更新と TLP の期限の張り直しを含みます

どの回も、駆動の層と同じく時刻を進めて `handle_timeout` を呼びます。
`recv_segment` と `send_segment` は相手の packet の組み立てと checksum を含むので、核の費用の目安は
`rig_overhead` を引いた値です。
N は 1、64、1024 です。
多数の接続を順に回すと、同じ接続の欄を触る間隔が長くなります。

```sh
cargo bench -p wgft-wgstack-bench --bench segment -- --warm-up-time 1 --measurement-time 3
```

キャッシュの事象は perf stat で数えます。
criterion の `--profile-time` は統計の処理をせずに決めた時間だけ回すので、事象の数が測る経路だけになります。
ホストの測定は `wgft-heavy --class tool --timing` で 1 つの車線に置きます。

```sh
cargo bench -p wgft-wgstack-bench --no-run
perf stat -e cache-misses,L1-dcache-load-misses,instructions,cycles \
  target/release/deps/segment-<hash> --bench --profile-time 5 'send_segment/64'
```

E コアは `L1-dcache-load-misses` を数えないので、E コアの車線では代わりに `mem_load_uops_retired.l1_miss` を
数えます。

2026-11-01 に、E コアの車線 (Core Ultra 7 270K Plus、rustc 1.99.1、release の build) で、3 つの配列に分けた配置と、
同じコードで 3 つの部分を 1 つの値に並べた配置 (前の段の `ConnSlot` と同じく、輪の pointer の配列が接続の欄と
同じ値にある形。64 byte の揃えも無し) を比べました。
後者は比べるためだけの一時の変更で、repo に入れていません。
値は criterion の中央の推定です。
`rig_overhead` はどちらも約 100 ns でした。

| ベンチ | 分けた配置 | 1 つの値の配置 |
| --- | ---: | ---: |
| `recv_segment/1` | 648.3 ns | 655.1 ns |
| `recv_segment/64` | 723.7 ns | 727.7 ns |
| `recv_segment/1024` | 718.2 ns | 728.0 ns |
| `send_segment/1` | 631.9 ns | 608.6 ns |
| `send_segment/64` | 653.8 ns | 615.2 ns |
| `send_segment/1024` | 636.1 ns | 636.9 ns |

受信は分けた配置が 1% から 2% 速く、送信の 1 本と 64 本は 1 つの値の配置が 4% と 6% 速く、送信の 1024 本は同じでした。
同じ配置を 2 回流した値の揺れ (分けた配置の `recv_segment/1024` で 688 ns と 718 ns) が差と同じ大きさなので、
このベンチでは配置による一貫した差は見えません。
`handle_timeout` を呼ばない前の版の道具では、送信の 64 本で逆に分けた配置が約 11% 速く出ていました。
perf stat の数 (1,000 命令あたり) は、どちらの配置でも LLC の miss が 0.2 未満で、1024 本でも作業の集合が
キャッシュに収まっていました。
L1 の miss も配置によって増える場合と減る場合がありました。
分けた配置を選んだ理由は、測った速さではなく、`Tcb` の行が輪の配列と boost の段の大きさに左右されないことです。
接続の数が L2 を超える負荷 (数千本の接続と大きな受信の窓) での差は測っていません。

PR 5 の後に、同じ車線で PR 4b の頭 (NewReno と boost を求めない既定) と PR 5 の頭 (CUBIC と需要による boost の既定) を比べました。
値は criterion の中央の推定です。
PR 5 の値は、記録の輪の添字の変更の前に、#705 のレビューで測り方 (時刻を進めて `handle_timeout` を呼ぶこと) を変える前のベンチで測りました。
このため上の表の値とは比べられません。

| ベンチ | PR 4b | PR 5 | PR 5 の SACK の組 |
| --- | ---: | ---: | ---: |
| `recv_segment/1` | 676.7 ns | 652.9 ns | 647.1 ns |
| `recv_segment/64` | 676.6 ns | 683.0 ns | 691.1 ns |
| `recv_segment/1024` | 679.4 ns | 697.5 ns | 729.0 ns |
| `send_segment/1` | 595.5 ns | 611.4 ns | 613.3 ns |
| `send_segment/64` | 616.7 ns | 629.8 ns | 633.0 ns |
| `send_segment/1024` | 662.4 ns | 678.8 ns | 670.4 ns |

SACK の無い接続の差は 3% 以内でした。
SACK の組は 1024 本の受信で 5% ほど遅くなりました。
`Tcb` が 2 行広がったことと ACK ごとの RACK の処理のどちらが効くかは、perf stat で分けていません。
1 本の受信は、需要で boost を得るので、既定の違いを含みます。

D-SACK の欄を受け手の行に移し、PRR の欄を `ConnCold` に移した後に、#705 のレビューの後のベンチで前後を比べました。
criterion の中央の推定は、同じコードを流し直しても 5% ほど揺れ、前後の差はその揺れの内でした
(`recv_segment_sack/1024` は 694 ns と 730 ns、`send_segment_sack/1024` は 652 ns と 680 ns、どちらも前、後の順)。
perf stat の 1,000 命令あたりの L1 の miss は、`recv_segment_sack/1024` で 11.6 から 10.2 に減り、`send_segment_sack/1024` で 12.3 と 12.1、
`recv_segment/1024` で 11.2 と 12.3 でした。
LLC の miss は 1,000 命令あたり 0.2 未満で変わりませんでした。
受け手だけの接続が ACK ごとに後ろの行を書かなくなったことは L1 の miss の減りに見えますが、時間の差は測れませんでした。

### 上界の式の写し方

上界の式の項と規則は Go と同じです ([上界の式](../userspace/wgstack.md#上界の式))。
I1 から I7 の不変条件もそのまま守ります ([不変条件](../userspace/wgstack.md#不変条件))。
変わるのは、項の大きさの数え方と、表の上限です。

- 固定の表:接続の枠、hash の表、握手の途中の表、TIME_WAIT の表、タイマーの輪、出力の list、制御の輪、UDP の管理の配列、知らせの list、待ち受けの表、UDP の endpoint の表は、作成の時に確保します。
  大きさは確保した容量と `size_of::<T>()` の積で数え、後から大きくしません
- 待ち受けと UDP の endpoint の上限:Go は待ち受けを map で持ち、数は信頼された設定で決まるとして式の外に置いていました。
  提案として、Rust では TCP の待ち受けの表と UDP の endpoint の表を、受け付けるアドレス 1 つあたりポートの数 (65,536) の固定の行で持ち、`Bound` に項 N_lt × c_lt と N_ue × c_ue を加えます。
  v1 はルールの範囲の幅に上限を置かないので、ポートの数が構造の上限です。
  提案 (PR 3 で採用):待ち受けの行は 20 byte (世代、開いている印、accept の待ち行列の先頭と末尾、待ち行列の長さ、握手の途中の行の数) です。
  受け付けるアドレスは 1 つなので、表は 1 つです。
  `ListenerId` と `UdpId` の世代は 32 bit です。
  ポートを開き直す回数は接続の枠の使い直しよりずっと少なく、行を小さく保つためです。
  UDP の endpoint の表は同じポートごとの行の表を使います。
  行の型と項 N_ue × c_ue は PR 6 で足しました ([PR 6 で決めたこと](#pr-6-で決めたこと))
- 枠と共に持つ配列:floor の送信の記録の輪と区間の表は、Go と同じく枠を初めて使う時に確保し、枠と共に持ちます。
  上界は作成の時に数えるので、確保の時機は上界を変えません
- boost の配列:提案として、B 本の枠の分の boost の記録の輪と区間の表を `Budget` の作成の時に確保し、`Budget` の中に置きます。
  boost を得た接続はその 1 組を借り、floor に戻るか閉じるときに返します。
  boost の取得の時に確保が失敗する場合が無くなります
- chunk:16 KiB の固定の配列で、予約の内側でだけ確保します。
  返した chunk は 0 で埋めて置き場に置き、置き場の上限 (Go と同じ 64 個) を超えた分は解放します
- 再組み立ての表:管理領域 (表、項目、断片の枠、Go の `Sweep` が返す知らせの写し) は、Go の linux/amd64 の型の大きさで数えます。
  保持 byte の上限に近いときの追い出しの時機が管理領域の大きさで変わり、移行の間は Go と同じ出力を求めるためです。
  Rust の型がその大きさ以下であることは compile の時に確かめるので、数えた値は実際の保持の上界です。
  Rust の表は知らせを写しの配列で返さず、`sweep_next` で 1 つずつ返しますが、写しの分も Go と同じく数えます
- 割り当て器の丸め:割り当て器は、要求の大きさを自分の大きさの区分に切り上げて持ちます。
  提案として、`Bound` は要求の大きさで数え、使う割り当て器ごとに丸めの係数を測って公開します。
  係数を掛けた値をプロセスの上界の式に使います

`Bound` の計算は、作成の時の設定と型の大きさだけから決めます。
Go の測った値 (c_conn、記録 1 件、区間 1 つ) は Rust の型の大きさで置き換わり、どの target でも同じかを試験で確かめます。
型の大きさは rustc の版で変わりうるので、toolchain を上げる PR は上界の表を生成し直し、差分を PR に書きます。

### 確保の規則

提案:

- 予約が先:保持する前に予算から予約し、予約の後に確保します (I2)
- 確保の失敗:確保は `Vec::try_reserve_exact` で失敗を返す形で行い、失敗を予算が尽きたときと同じ動作にします。
  Rust の標準の確保は失敗するとプロセスを止めるためです
- 上限のある配列の型:核の可変長の保持は、作成の時に容量を決める `FixedVec<T>` だけにします。
  `FixedVec` は `try_push` だけを持ち、容量を超えると誤りを返し、再確保しません。
  中身は `try_reserve_exact` で取った `Vec` で、`into_boxed_slice` には変えません。
  `try_reserve_exact` は要求より大きな容量を返すことがあり、`into_boxed_slice` はそのとき縮めるために再確保するためです。
  `Bound` と会計は `capacity()` の実際の値で数えます。
  禁止の一覧には `Vec` の型そのものも入れます。
  製品のコードの例外は `FixedVec` 自身の実装だけで、その module にだけ `#[expect(clippy::disallowed_types, clippy::disallowed_methods, reason = "...")]` を付けます。
  試験の module も同じ `#[expect]` で例外にします
- 伸びる API の禁止:`Vec::push`、`Vec::extend`、`Vec::insert`、`Vec::resize`、`vec!`、`VecDeque`、`HashMap`、`BTreeMap`、`String` への追加のように容量を自動で伸ばす API を、[依存と隔離の検査](#依存と隔離の検査)の禁止の一覧に入れます
- 0 で埋める:置き場に返す chunk は 0 で埋めます ([使い回しと古い byte](../userspace/wgstack-buffers.md#使い回しと古い-byte))。
  目印の build (`--cfg wgstack_sentinel`) は 0xa5 で埋めます
- chunk の確保:chunk は 16 KiB の配列の `Box` で、輪は Go と同じく枠ごとに chunk への pointer の配列を持ちます。
  `Box::new` は失敗するとプロセスを止めるので、`FixedVec` の module の関数が `try_reserve_exact` で取り、容量がちょうど 16 KiB のときだけ `into_boxed_slice` で `Box` にします。
  容量が違えば確保の失敗として扱います
- 輪への書き込みの失敗:Go の輪の書き込みは失敗しませんが、Rust の輪は chunk の確保が失敗しえます。
  書く操作は先に要る chunk を揃え、揃わなければ何も変えずに誤りを返します。
  受信のバッファの挿入は、このとき segment を状態を変えずに捨てた結果 (`no_memory`) を返します

### 予算の持ち主

Go では boost の枠の集まりがプロセスで 1 つで、トンネルを作り直しても増えません。

提案:Rust では枠の集まり (B 本の枠と、前節の boost の配列) を `Budget` という値にし、核がそれを所有します。
トンネルを作り直すときの受け渡しは[世代と予算の受け渡し](#世代と予算の受け渡し)の順に従います。
古い核の接続はその前にすべて閉じているので、受け渡す `Budget` の借りは 0 です。
このため枠の集まりはプロセスで 1 つのままで、別の Device の接続を回収する処理も要りません。
古い核の表と chunk は `close` で解放されるので、Go の上界が足していた「古い世代の M_fix」の項は要りません。

提案 (PR 3 で採用):boost の配列の貸し借りは値の移動です。
枠を得た接続は `Budget` から配列を受け取り、使っていない方の配列を枠の控えに置き、floor に戻るか閉じるときに配列を `Budget` に返します。
控えには、boost の間の floor の記録の輪と、受信が boost の段に移るまでの boost の区間の表 (移った後は floor の区間の表) を置きます。
枠の取り合いでは、floor に戻した保有者が `Budget::release` で枠を返し、新しい保有者が `Budget::hand_over` でその枠と配列を受け取ります。
枠を貸す順 (最も小さい空きの枠) と保有者をたどる順 (枠の順) は Go と同じです。
上界の boost の項は、`Budget` の枠の管理の配列も数えます。

### 保持の量の測り方

- 核の会計:Go の `Stats` と同じく、chunk、記録の輪、区間の表、UDP の枠、再組み立ての表が今持つ量を核が数えます。
  この値は `held()` で読めます
- 確保の数え:試験の build では、`GlobalAlloc` を包んで確保と解放の byte を数える割り当て器を使います。
  割り当て器は試験の道具の crate `crates/wgft-alloc-count` に置きます。
  `GlobalAlloc` の実装は unsafe を要し、核の crate は unsafe を禁じ、依存も持たないためです。
  この crate の試験が、作ったばかりの核の確保が上界の固定の項と boost と再組み立ての項の内にあり、閉じて `Budget` を捨てると元の値に戻ることを確かめます。
  敵対的な保持の試験は、この crate を dev-dependency にして使えます。
  敵対的な保持の試験は、核の操作の前後の生きている byte の差が `Bound` 以下であること、核を閉じた後に元の値へ戻ることを確かめます。
  GC が無いので、この差は Go の試験の「生きているヒープ」より正確に保持を表します
- OS の値:ラボのメモリの測定は、Linux の `VmRSS` と `VmHWM` を読みます。
  測定用の cargo の feature を有効にした build だけが、核の会計と確保の数えを制御ソケットに出します。
  Go の build tag `labmemprobe` に当たります。
  この feature はどの crate の依存の宣言でも有効にせず、ラボの build が `--features` で明示して渡すときだけ有効になります
- 割り当て器の比べ:OS の標準と mimalloc の両方で同じ負荷を流し、RSS と確保の数えの比と丸めの係数を記録してから選びます

### 上界の表の生成

決定に従い、上界の表は `Bound` から生成します。

提案:`wgft-wgstack` の試験が、既定の設定と代表の K の値で `Bound` を計算し、項ごとの表を Markdown の断片として書き出します。
環境変数 `WGFT_UPDATE_GOLDEN=1` を付けたときだけファイルを書き直し、付けないときは差があれば失敗します。
Go の `-update` の形に当たります。
生成した表はこの文書から参照し、手で数を書きません。

決定に従う形 (PR 3 で採用):表は [wgstack の Rust 版の上界の表](wgstack-bound.md) に生成し、試験は `bound::tests::bound_table_is_up_to_date` です。
試験は文書の印の間だけを書き直し、行の説明は手で書いた部分が持ちます。
項は確保した配列の要求の大きさで数えます。
別の試験が、作った核の表の `capacity()` から数えた byte が固定の項と一致することと、枠をすべて使い boost の枠をすべて貸してどの輪も満たした核の保持が、chunk、記録の輪、区間の表の項ごとに上界と一致することを確かめます。
型の大きさは試験の build でも製品の build と同じに保ちます。
試験だけの欄を型に足さないのはこのためで、確保の失敗の注入は型の外に置きます。
Linux、Windows、macOS の CI で同じ表になることを確かめました。
核の値の大きさは hook の無い核で数え、`Stack::bound` は使う hook の核の大きさで数えます。
UDP と ping の項は PR 6 で足しました。

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
- アプリケーション:中継の task が `wgft-netstack` の handle を読み書きし、LAN の宛先へは OS のソケットで接続します

TUN も、トンネルのアドレスの経路も、専用の経路表と rule も要らなくなります。
agent はどの OS でも利用者の権限で動き、Go の v1 のユーザー空間モードと同じ形に戻ります。
核は OS に依らないので、Windows と macOS でも同じ形で動きます。
CI はこの 2 つの OS で build と単体の試験を流しますが、実機での動作は未確認です。

device の層の `poll_packet` は packet ごとに `Vec` を確保して返します。
提案:最初はこの形のまま使い、CPU を測ってから、device の層に呼び手の buffer へ書く口を足すかを決めます。
送信の向きも同じです。

### 入口の検査と試作の守りの移り先

試作の `inbound` の module は、TUN の先のカーネルがホストのサービスと LAN に packet を渡すのを防ぐための検査でした。
wgstack では packet が核の中で終わり、転送の経路も、中継が開いていないポートの待ち受けもありません。
このため検査は核の規則に移り、`inbound` の module は消えます。
規則の正本は[トンネルの入口の検査](../spec/tunnel.md#トンネルの入口の検査)です。

| 試作の検査と守り | wgstack での扱い |
| --- | --- |
| 宛先が agent のアドレスで、開いているルールのポートへの TCP を通す | 宛先の集合と待ち受けの表で決まります。待ち受けの無いポートへの SYN には RST を返します |
| agent のアドレス以外への packet を捨てる | 同じです。受け付ける宛先の集合は agent のトンネルのアドレスの /32 だけで、外の packet を数えて捨てます |
| 待ち受けの相手を server のトンネルのアドレスに限る (`SO_BINDTODEVICE` と送信元の確かめ) | device の層の AllowedIPs が復号した packet の送信元を server の /32 に限るので、核に届く packet の送信元は server だけです。核の待ち受けは送信元で絞りません |
| ルールを消すか無効にするか宛先を変えると、そのポートの中継の接続を RST で切る | 中継が待ち受けを `close_listener` で閉じ、そのポートの確立した接続を `abort` で切ります。`close_listener` は accept の待ち行列と握手の途中の行にも RST を送ります |
| agent のアドレスへの echo reply を通す | ping の endpoint の表が受けます |
| 開いているポートの TCP を引用する Fragmentation Needed を、外側の送信元が引用の宛先と同じときだけ通す | ICMP の誤りの入口の検査と、RFC 5927 の番号の確認で受けます |
| MSS が 536 より小さい SYN を捨てる | 同じです。SYN-ACK にも同じ下限を掛けます |
| UDP を捨てる | 待ち受けのあるポートの UDP は受信の予算に入れ、待ち受けの無いポートには Port Unreachable を返します。v1 の約束に戻ります |
| echo request を捨てる | 自分のアドレス宛ての echo request に応答します。v1 の約束に戻ります |
| IPv4 の断片を捨てる | 再組み立ての表で組み立てます。v1 の約束に戻ります |
| 捨てた数を数え、1 分に 1 回までログに出す | 核の数えと門が持ちます |

試作が UDP、echo request、断片を捨てていたのは、カーネルにホストの応答を作らせないためでした。
wgstack はそれらを自分で扱うので、[トンネルの中の約束](../spec/tunnel.md)の v1 の挙動に戻します。

### TUN の殻の扱い

`crates/wgft-wireguard-tun` は、agent の経路から外し、ラボの一式が Rust の agent で通るまで `lab/wg-interop.sh` のためのラボの道具として残します。
#680 も同じ扱いです。

- 残す理由:`lab/wg-interop.sh` は、TCP の stack と切り離して、device の層を Linux の WireGuard と wireguard-go に照らします。
  wgstack に不具合があっても WireGuard の相互運用を確かめられるので、移行の間は原因を分けるのに使えます
- 外すもの:agent は殻を使わずに device の層と核を直接動かします。
  `WGFT_WG_INTERFACE` を TUN の名前に読み替える試作の扱いもやめます
- 消す時機:ラボの一式が Rust の agent で server の両方のモードを通った後に、残すかを決め直します

### 設定の扱い

- `WGFT_AGENT_NETSTACK`:決定どおり、`gvisor` と `wgstack` を受け付け、どちらでも Rust の wgstack で動かします。
  `gvisor` のときは使わない旨を英語の 1 行で出します
- `WGFT_MAX_TCP_FLOWS`:Go と同じく K として受け取り、接続の枠の数 N_c = K + Q を導きます
- `WGFT_AGENT_BATCH_MIB`:仕様は、受け付ける値の集合と誤りの文面を Go と同じにし、値から何を導くかは実装の送信の経路で決めるとしています ([WGFT_AGENT_BATCH_MIB](../spec/cli-config.md#wgft_agent_batch_mib))。
  提案:値は 1 回の起床で作る packet の数の上限に使い、`0` は 1 件ずつ送ることにします。
  導く式は送信の経路を測ってから決めます

## 置き換えの判定

仮の決定 (所有者の確認を待ちます):Rust の agent が Go の agent を置き換えられると判定する条件は、次の 2 つです。

- ラボの一式の agent の確認が、Rust の agent で server の両方のモードを通ること (#680 の完成の条件)
- qbench の cell が、凍結した Go の wgstack と同じく正しさの判定 (byte の列の一致と、接続が誤りなく終わること) を通ること

[目標と制約](../userspace/wgstack-performance.md#目標と制約)の性能の目標 (byte あたりの CPU が gVisor の 0.6 倍以下、スループットが Linux の 0.9 倍以上など) は置き換えの条件に入れません。
置き換えの後に測り、性能の段階として追います。
Linux の `sendmmsg` と UDP の GSO のような system call のまとめも、置き換えの後に回します。

Go の wgstack の記録がすべて一致することは、ラボの一式で置き換えを判定する前の条件です ([Go の wgstack の記録との bit の一致](#go-の-wgstack-の記録との-bit-の一致))。

## 検証

試験の道具の細部は、[試験の道具の設計](test-tooling.md)が決めます。
この文書は、その決定のうち核の設計に関わるものを採ります。

### 試験の道具の決定

試験の道具の設計の次の選択を採ります。

- 台本の形式:行を単位にした専用の形式 (`.scn`) で、`internal/tcpharness/scripts/` に置き、Go の runner は `go:embed` で読みます
- 時刻の確かめ:今の Go の台本と同じ絶対の時間の範囲で書き、手で進める時計でだけ効く確かめは `clocked()` で分けます
- Rust の runner の置き場所:別の crate `crates/wgft-tcpharness` に置き、核の crate の依存を空に保ちます
- runner どうしの照合:直線の台本の要求と応答の列 (transcript) が byte の単位で同じであることを求めます
- qbench:`wgstack-dut` を実時間で動かし、packet は socketpair を `tun.Device` として Go の経路に繋ぎます。
  TUN は使いません
- DUT の口:長さ、種類、本体の binary の frame を標準入出力で 1 要求に 1 応答で運び、同じ frame の列を記録の形式にします。
  `OnBoost` の答えは `BOOST_POLICY` で先に渡し、`wgstack-dut` の hook がその値を `may_return` で返します

### 書き手の分離

[検証の原則](../userspace/wgstack-verification.md#検証の原則)の書き手の分離をそのまま当てます。

- 実装の担当:核のコードと、Go の wgstack の白箱の単体の試験を Rust に移したものと、`parse` の fuzz の target を書きます。
  Linux の source は読みません
- 試験の担当:実装の担当とは別の担当です。
  台本、runner、DUT、記録と照合、`core`、`adversarial_sender`、`replay` の fuzz の target、上界と敵対的な保持の試験を書きます。
  Rust の wgstack の実装のコードを読まず、公開の API の文書だけを読みます
- 故障の注入:試験の担当が故障の一覧 (どの確かめを落とすはずか) を書き、実装の担当がその一覧から核の故障の点を書きます
- 期待した差の一覧と意図した違いの一覧:行を足せるのは、今と同じく試験の担当と所有者だけです

### Go の wgstack の記録との bit の一致

決定に従い、移行の間は凍結した Go の wgstack の記録と照らします。
記録の作り方、形式、印による段ごとの照合、意図した違いの一覧は[試験の道具の設計の記録](test-tooling.md#4-go-の-wgstack-の記録)に従います。
この文書が決めるのは、Rust の核が守る条件と、照らす範囲です。

- 比べる応答:引き取った packet の bytes と順序、アプリケーションの操作の結果、受け入れの結果、時刻です。
  `STATS`、`BOUND`、`HELD` の応答は byte の単位で比べません。
  Go と Rust で数の内訳と型の大きさが同じになる理由が無いためです
- 段ごとの照合:PR 4b からは、相手が SACK も timestamp も示さず、輻輳の制御に NewReno を、boost の与え方に boost を求めない方針 (Go の `BoostNever`) を選んだ記録が、握手の後のデータの転送まで一致します。
  受信の窓の自動調整と受け手の ACK の規則を PR 4b に入れるのはこのためです。
  timestamp に頼る不要な再送の取り消しと boost の取得は PR 5 で入ったので、timestamp と boost を使う記録は PR 5 から照らします
- 照らす範囲の広がり:PR 5 で SACK、timestamp、CUBIC、boost の印の記録、PR 6 で UDP と ICMP と断片と ping の印の記録が加わります
- 段の表:核に入った段は `crates/wgft-wgstack-dut/stages.json` の `landed` が持ちます。
  段を入れる PR は `landed` にその段を足し、その段の印の記録が一致することと、その段の台本が通ることを同じ PR で確かめます
- 前の条件:すべての記録が一致することを、#680 の「wgstack の上の agent」の段と、agent の置き換えをラボの一式で判定することの前の条件にします

#### bit の一致の条件

同じ入力に同じ packet を返すには、次の点を Go と同じにします。

- 乱数:種の配分と、ChaCha8 から引く順と回数
- hash:SipHash-2-4 と鍵の使い方。hash の表の探し方は出力に出ませんが、枠の番号は出力の順に効くので、空きの枠の list の順 (小さい番号から、返した枠を先に使う) を同じにします
- 時刻:タイマーの輪の 1 ms の tick と切り上げ、ns の整数の算術。
  `handle_timeout` は期限の来たタイマーを新しい `now` で 1 回ずつ動かし、Go の `Tick` と同じく期限の時刻に戻って動かしません
- 出力の順:4 つの組の deficit round robin、順番の list の順、制御の輪の順
- 番号:IP の ID の数え上げ、ISN と timestamp の offset の作り方
- 浮動小数点の算術:CUBIC は `float64` の四則と 3 乗根と切り捨てを使います。
  四則は IEEE 754 で同じですが、Go のコンパイラは target によって積和を 1 つの FMA の命令にまとめ、丸めが変わります。
  このため記録は linux/amd64 の `GOAMD64=v1` で作り、記録の meta に `GOARCH` と `GOAMD64` を残します。
  Rust は `mul_add` を使わず、コンパイラも積和をまとめません
- 3 乗根:Go の `math.Cbrt` と同じ値を返す実装が要ります。
  Rust の `f64::cbrt` は OS の数学ライブラリを呼ぶので、値が最後の桁で違いうるためです。
  PR 5 で Go の実装を写しました ([PR 5 で決めたこと](#pr-5-で決めたこと))
- 再組み立ての表の追い出し:管理領域を Go の型の大きさで数えます ([上界の式の写し方](#上界の式の写し方))
- 浮動小数点の比べと変換:Go の `min` と `max` の NaN と -0 の扱いと、浮動小数点から符号なしの整数への変換を、Rust の既定の挙動に頼らずに明示して写します。
  Rust の `as` は範囲の外の値を飽和させますが、Go の変換の結果は target に依るので、linux/amd64 の結果を写すか、範囲の外の値が来ないことを試験で示します

部品の単位で照らせる値 (SipHash、ChaCha8 の列と種の配分、TCP の header と option の組み立て、IPv4 の header の書き直し、IPv4 と TCP の解釈、再組み立ての表) は、記録を待たずに照らします。
解釈は、`FuzzParse` の種と組み立ての試験の segment を決まった乱数で壊した入力の結果を照らします。
再組み立ての表は、決まった乱数の断片と掃除の列への結果と保持の量を、手順ごとに照らします。
Go の試験 `TestRustGolden` が凍結した Go の wgstack のコードで値を作り、`crates/wgft-wgstack/testdata/go-golden.txt` に書き出します。
Rust の単体の試験がそのファイルと照らし、Go の試験はファイルが Go の値と同じであることを確かめます。
作り直すときは `go test ./internal/wgstack -run TestRustGolden -update-rust-golden` を流します。

一致を求める期間が終わった後は、この節の制約を外し、Rust に合った形 (例えば接続の表の形) を選べます。

### fuzz

| Go | Rust の target | 書き手 | 種 |
| --- | --- | --- | --- |
| `FuzzParse` | `parse` | 実装の担当 | Go の `FuzzParse` が `f.Add` で渡す値。repo に corpus のファイルはありません |
| `FuzzCore` | `core` | 試験の担当 | `internal/wgstack/testdata/fuzz/FuzzCore` の corpus の値。`go test fuzz v1` の形式から試験の道具の設計の `tools/fuzzseed` が取り出します |
| `FuzzAdversarialSender` | `adversarial_sender` | 試験の担当 | 64 bit の種 |
| (無し) | `replay` | 試験の担当 | 記録の要求の列 |

`parse` は、Go の `FuzzParse` の確かめ (checksum を定義どおりの和と照らし、IPv4 と TCP を解釈する) に加えて、UDP と ICMP の解釈と再組み立ての表を通します。
再組み立ての表には、入力の全体を 1 つの断片として渡した後、入力を「印の 1 byte、長さの 2 byte、packet」の列として読んで順に渡します。
印の bit 0 は IPv4 の header の checksum を直す印で、残りの bit は時刻を進めます。
変異で checksum が壊れただけの入力が入口で落ちるのを避けるためです。
種は `TestRustGolden` が Go の `FuzzParse` と同じ値を `fuzz/corpus/parse/` に書き出します。
見つけた落ちる入力は `fuzz/regressions/parse/` に置き、corpus と共に stable の単体の試験が流します。
`cargo fuzz run` は新しい入力を最初に渡した corpus の directory に書くので、手元で流すときは別の directory を先に渡します。
target は crate の `#[cfg(fuzzing)]` の `fuzz` module を呼び、この module は製品の build にありません。
fuzz の crate が依る `libfuzzer-sys` の license は `(MIT OR Apache-2.0) AND NCSA` です。
NCSA は寛容な license ですが `deny.toml` の許可の一覧に無く、fuzz の crate はワークスペースの外にあるので `cargo deny check` の対象に入りません。

`core` は、Go の `FuzzCore` の op の解釈と相手の TCP の模型を、同じ byte が同じ op になるように写します。
各段の後に `check_invariants` を呼び、最後に核を閉じて会計が 0 に戻ることを確かめます。
関門の量は libFuzzer の `-runs` の回数で決め、時間では決めません。

### 上界と敵対的な保持の試験

[敵対的な保持の試験](../userspace/wgstack-verification.md#敵対的な保持の試験)の表の入力をすべて Rust に移します。
確かめることは同じで、生きているヒープの代わりに確保の数えで測ります。
stream の一致の試験 (受信と送信) も、種の数を含めて移します。
Go の `-race` の競合の試験は、核が錠を持たないので移しません。
代わりに、`wgft-netstack` の試験で、多くの接続の読み書き、`close`、`abort`、待ち受けの `close`、核の作り直しを同時に動かし、waker の表と核の会計が閉じた後に空に戻ることを確かめます。

### 故障の注入と目印の build

提案:故障の注入と、置き場に返す chunk を目印の byte で埋める build は、cargo の feature ではなく `--cfg` で選びます。

- 選び方:`RUSTFLAGS` で `--cfg wgstack_fault="<名前>"` と `--cfg wgstack_sentinel` を渡します。
  feature はワークスペースの中で合わさり、製品の build に漏れうるためです
- 宣言:ワークスペースの `[workspace.lints.rust]` の `unexpected_cfgs` の `check-cfg` に 2 つの cfg を宣言し、source の中の `#[cfg(...)]` の名前と値の綴りの誤りを lint で捉えます。
  `RUSTFLAGS` で渡した `--cfg` の綴りの誤りは lint では捉えられないので、故障を入れた build の試験が、その故障を捉えるはずの確かめが落ちることで確かめます。
  `wgstack_fault` の値の一覧は、故障の点を足す PR が足します。
  それまでは値を持たない宣言で、source の中で値を書くと lint が捉えます
  cargo は crate の `[lints]` に `workspace = true` とほかの項目を併せて書けないので、crate ごとには宣言しません。
  名前が `wgstack_` で始まるので、ほかの crate に宣言が効いても害はありません。
  cargo-fuzz が付ける `fuzzing` も同じ所で宣言します
- 製品:リリースの build と B13 の通常の build はこの cfg を渡しません。
  `wgft` のバイナリの依存の木の検査 ([依存と隔離の検査](#依存と隔離の検査)) と合わせ、製品にどちらも入らないことを CI で確かめます
- 目印の確かめ:目印の build で、目印が読み取り、送る segment、記録と区間の欄の値に現れないことを、stream の一致の試験、敵対的な送り手の試験、`core` の fuzz で確かめます

### 関門と CI

[試験の道具の設計の関門と CI](test-tooling.md#7-関門と-ci)の選択を採ります。

- PR の関門:今の `scripts/wgstack-gate.sh` に Rust の段 (台本と記録の照合、`rustdut` の適合の台本、fuzz の smoke) を足します。
  別の script にはしません
- CI:cargo と Go の両方を要する照合の段を、新しい job `harness-rust-go` にします。
  この job は Go の試験を流すので、ラボの一式を省ける Rust だけの job には当たりません。
  テストの規範は Rust の job を `rust-*` の名前で数えてラボの一式を省くので、`rust-` で始めない名前にしています
- [テストの規範](../../development/testing.md)の変更:job を足す PR が、同じ PR で B 類の表と振り分けに `harness-rust-go` を足し、この job を変える PR がラボの一式を省けないことを書きます。
  job は `crates/**`、`internal/tcpharness/**`、`internal/dutproto/**`、`internal/wgstack/**` を変えた PR で流します

ラボの一式は、所有者の規則どおり、ラボが動かすものを変えない Rust だけの変更では流しません。
Rust の agent が製品の経路で wgstack を使い始めた後は、[置き換えの判定](#置き換えの判定)のとおり、server の両方のモードでラボの一式を流します。

## 実装の計画

### 積む PR

この文書の計画は、核と handle の層までです。
device の殻、駆動の実装、中継、UDP の中継は #680 の段が持ちます。
サイズは試験を含む行数の目安で、Go の wgstack の大きさから見積もった推定です。
担当の列の A は実装の担当、T は試験の担当です。
T の段の中身と大きさは[試験の道具の設計の段階の計画](test-tooling.md#8-段階の計画)のとおりです。

| 順 | PR | 担当 | 中身 | サイズの目安 | 前提 |
| --- | --- | --- | --- | --- | --- |
| 1 | この文書 | | 設計 | | |
| 2 | `feat(wgstack-rs): packets, checksums and reassembly` | A | crate の骨組み、依存と sans-IO の検査、`FixedVec`、`wire`、checksum、`frag`、`siphash`、ChaCha8、`Time`。fuzz の `parse` | 約 2,500 行 | 1 |
| 3 | `feat(wgstack-rs): tables, buffers and the bound` | A | 接続の枠、hash の表、握手の途中の表、TIME_WAIT の表、待ち受けと UDP の endpoint の表、タイマーの輪、出力の list と制御の輪、知らせの list、chunk の置き場、送受信の輪、区間の treap、送信の記録、`Budget`、`Bound` と生成した表、`check_invariants`、確保の数えの試験の道具 | 約 3,000 行 | 2 |
| 4a | `feat(wgstack-rs): passive open, close and the application API` | A | 受動の open と確立の入口、accept の待ち行列、FIN と TIME_WAIT、`close` と `abort`、古い handle、アプリケーションの操作と知らせ、出力の組 | 約 2,500 行 | 3 |
| 4b | `feat(wgstack-rs): the data path to the completion level` | A | データの送受信、受け手の ACK と quickack の規則、受信の窓の自動調整、遅延 ACK、窓と persist、RTO、NewReno、RFC 5961 と RFC 7323、MSS | 約 3,000 行 | 4a |
| 5 | `feat(wgstack-rs): SACK, RACK-TLP and CUBIC` | A | SACK の scoreboard と回復と PRR、受け手の SACK と D-SACK、RACK-TLP、CUBIC と HyStart++、不要な再送の取り消し、boost の取得と回収と取り消し | 約 4,500 行 | 4b |
| 6 | `feat(wgstack-rs): UDP, ICMP and the ping endpoints` | A | UDP の endpoint と予算と会計の不整合、送信の断片化、echo と ping、ICMP の誤り、PMTU (ICMP の frag-needed による MSS の引き下げ)、断片の入口の結合 | 約 2,500 行 | 4a |
| 7 | `feat(wgstack-rs): async handles over the core` | A | `wgft-netstack`:TCP、UDP、ping の非同期の handle、waker の表、操作の知らせ、hook の LAN 側のソケットの表 | 約 1,500 行 | 4b と 6 |
| T1a、T1b | 台本の言語と Go の runner、残りの台本の移し替え | T | 段階の計画のとおり | 約 2,000 行、約 +900 と -1,300 行 | 1 |
| T2a、T2b | DUT の frame と `dutserve` と `rustdut`、Go の wgstack の記録 | T | 段階の計画のとおり | 約 4,300 行、約 1,800 行と記録 (約 4.7 MB) | 1 |
| T3a、T3b | `wgft-tcpharness` の crate と構文解析器、Rust の runner と `harness-rust-go` の job | T | 段階の計画のとおり | 約 2,400 行、約 3,000 行 | T1b、T2a |
| T3c | `wgstack-dut` と記録の照合 | T | 段階の計画のとおり | 約 1,500 行 | T2b、T3b、4a |
| T4 | fuzz の target と敵対的な保持の試験 | T | 段階の計画のとおり。故障の一覧を含みます | 約 3,000 行。段ごとに分けます | 3 から。4a から 6 に合わせて足します |
| 8 | qbench の `wgstack-rs` の engine | T と A | `wgstack-dut` の実時間の形、socketpair の `tun.Device`、判定の切り替え | 約 1,000 行 | 5 と 7 |

PR 4b と PR 5 が大きくなれば、実装の担当がレビューの単位に分けてよいとします。
分けるときも、各 PR は Go の白箱の試験のうちその範囲のものを含めます。

Go の変更 (T1、T2) は試験の道具だけで、製品の Go のコードを変えません。
Go の試験を変える PR は、規則どおり wgstack の関門を流します。
ラボの一式を Go の agent の代わりに Rust の agent で流す変更は、#680 の「ラボの切り替え」の段です。

### 並べられる仕事

- 試験の担当の T1 と T2 は、この文書の後すぐに、実装と並べて進められます。
  どちらも Go の側だけで完結するためです。
  T3a と T3b も `dutserve` を相手にできるので、Rust の wgstack を待ちません
- 実装の 2、3、4a は順に積みます。
  核の型と表が後の段の土台になるためです
- 4a の後は、4b と 6 を並べられます。
  触る module が分かれるためです。
  5 は 4b の後です
- 7 は 4b と 6 の後で、5 と並べられます
- T3c は 4a の API が固まった後で、T4 は 3 の後から段ごとに足します
- 8 は 5 と 7 の後です
- #680 の「wgstack の上の agent」は 7 の後に始められます

### 試験の担当の仕事

試験の道具の設計の段階の計画の段に加えて、次のことを受け持ちます。

- 故障の一覧を書き、実装の担当が書いた故障の点で台本の検出力を確かめます
- 期待した差の一覧と意図した違いの一覧に行を足すときは、理由を書きます

試験の担当は Rust の wgstack の実装のコードを読まず、公開の API の文書だけを読みます。
実装の担当は試験の担当の台本と runner を直しません。
台本が誤っていると考えたら、理由を書いて試験の担当に返します。

### PR 4a と 4b で決めたこと

実装の担当が決めた点です。
理由と共に挙げ、所有者か監督が変えるときはこの節を直します。

- PR の分け方:受動の open と閉じる手順 (4a) と、データの経路 (4b) を 1 つの PR にしました。
  Go のコードでは、FIN の状態の遷移を ACK の処理が進め、窓の probe を入力の後の処理が張るように、2 つが同じ関数を
  通ります。
  分けると 4a に使い捨ての代わりの規則 (再送の無い送信、固定の窓) が要るためです。
  ベンチの crate は積んだ別の PR にしました
- SACK の交渉:PR 4a と 4b の核は SACK を交渉しませんでした。
  SACK の印付けと回復の無い核が SACK を交渉すると、Go と違う経路 (高速の再送の無い回復) を通るためです。
  PR 5 から Go と同じく相手の SYN の SACK-permitted に応えます
- HyStart++:Go の HyStart++ は輻輳の制御の種類によらず最初の slow start で働きます。
  NewReno の記録と同じ出力を返すため、PR 5 でなく PR 4b に入れました
- 輻輳の制御と boost の与え方:`Config` に `congestion` と `boost` を足しました。
  PR 4a と 4b の核は NewReno と boost を求めない方針だけを受け付けました。
  PR 5 で既定を Go と同じ CUBIC と需要による boost にし、`ConfigError::Unsupported` を消しました
- 時刻の算術:TCP の規則の中の時刻は Go と同じ符号つきの 64 bit の ns で持ち、0 を「無し」にします。
  Go は `now - curRTO()` のように負になりうる値を 0 と区別して使うので、飽和する `Time` の算術では同じ出力に
  なりません
- 古い handle の abort:Go は古い接続の値が持つ 4 つ組で TIME_WAIT の行を引きます。
  Rust の `ConnId` は 4 つ組を持たないので、TIME_WAIT の表に元の接続の枠ごとの行の list を持ち、元の枠と世代で引きます。
  手間は、その枠から移して表に残る行の数です。
  中継は規則を変えた時と閉じる時に、届けている途中の多くの接続を abort するので、表の全体をたどる形は採りませんでした。
  上界の `tw` の項は、行ごとの節と枠ごとの先頭を数えます
- 接続の枠の確保の失敗:握手の最後の ACK で floor の記録の輪と区間の表を確保できなければ、accept の待ち行列が
  満杯の時と同じく ACK を捨てて行を残し、`accept_overflow` を数えます
- 断片、UDP、ICMP:PR 6 までは捨てて理由ごとに数えました (`fragments_dropped`、`udp_dropped`、`icmp_dropped`)。
  PR 6 で入口を足しました
- chunk の確保の失敗:受信のバッファが chunk を確保できなければ、segment を状態を変えずに捨てて
  `recv_no_memory` を数えます。
  書き込みは `Error::NoMemory` を返します
- 白箱の試験:Go の `tcp_test.go`、`ackpolicy_test.go`、`orphan_test.go`、`reuse_refused_test.go`、
  `hystart_test.go` などのうち、この段の範囲の試験を移しました。
  SACK、D-SACK、boost、受信の窓の boost の段を使う試験 (`rcvwin_test.go` の多く) は PR 5 が移しました

### PR 5 で決めたこと

実装の担当が決めた点です。
理由と共に挙げ、所有者か監督が変えるときはこの節を直します。

- 欄の置き場所:RACK の状態、TLP の縮小の印、次の ACK に載せる D-SACK の block、CUBIC の状態は ACK ごとに触るので `Tcb` に置きました。
  D-SACK で倍率を上げた往復と倍率を保つ回復の数、D-SACK の累計、PRR、boost の需要と受信の段の印は、D-SACK と回復と boost の事象でだけ触るので `ConnCold` に置きました。
  並べ替えの窓の倍率は上限が 255 なので `u8` で持ちます。
  `Tcb` は 576 byte から 704 byte になり、上界の表を生成し直しました
- 試験だけの数え:Go の `scoreSteps` と `rackChanges` は欄に足しません。
  型の大きさを試験の build でも製品の build と同じに保つためです。
  `scoreSteps` は、試験の build だけにある thread の値 (`tcp::sack::steps`) で Go と同じ所で数え、ACK 1 つの手間の上界の試験に使います。
  `rackChanges` を読む試験は、ACK の前後の RACK の状態を試験の中で比べて数えます
- 3 乗根:Go の `math.Cbrt` (fdlibm の `s_cbrt.c` から来た Go のコード) を `tcp::cc::cbrt` に写し、Go の BSD-3-Clause の通知と元の C のコードの通知を source に残しました。
  同じ算法を持つ crate を使う案は、核の crate の依存を空に保つ規則で採りません。
  `GOAMD64=v1` の Go が書き出した値の表と bit の単位で一致することを単体の試験で確かめました
- CUBIC の浮動小数点:Go は定数の式を正確に計算してから丸めます。
  このため Reno と公平な領域の係数 3 (1 - β) / (1 + β) は、9/17 を 1 回の割り算で丸めた値にします。
  Go の `min` と `max` は NaN と -0 の扱いを明示した関数で写しました。
  窓の値の範囲では、Rust の `as` の変換は Go の変換と同じ値を返します
- boost の段の移し方:Go の輪は確保に失敗しませんが、Rust の輪は chunk の確保が失敗しえます。
  段を移す処理は新しい輪をすべて作ってから古い輪と替えるので、確保に失敗したら段を変えません。
  取得の時に送信の輪を作れなければ枠を返し、受信の輪を作れなければ受信を floor の段のままにして次の需要で試し直します。
  floor に戻す時は、送信と受信の新しい floor の輪を両方作ってから、古い輪をどちらも返します。
  このため一時に新旧の輪を合わせて持ちますが、新しい floor の輪はそれぞれ floor の量 (16 個の chunk) までで、floor に戻すのは一度に 1 本の接続だけなので、上界の一時の項 (8 MiB) に収まります。
  取り消しとその数えは輪を作る前に行うので、輪を作れずに boost の段のままにした時も取り消しは残ります。
  取り消したデータは相手が再送します。
  このため `may_return` が真を返しても、`boost_returned` が呼ばれるとは限りません
- boost の hook の順:Go の `OnBoost(false)` は問い合わせと知らせを兼ねます。
  Rust は取り消しの前に `may_return` を呼び、floor に戻した後に `boost_returned` を呼びます。
  `boost_granted` は送信の段を移した後、書き込みの知らせの前に呼びます。
  Go の `OnBoost` は登録の時に今の状態でも呼びますが、Rust の hook は変化だけを伝えます
- 枠の取り合い:Go は錠を `TryLock` で取れない保有者を飛ばしますが、Rust の核は錠を持たないので、枠の順にすべての保有者を調べます
- floor の区間の表の入れ直し:Go は受信が floor の段のまま floor に戻すときも、同じ表で `setIntervals` を呼び、区間を入れ直して優先度の数え上げを進めます。
  Rust も同じ数だけ数え上げを進めて入れ直します (`RecvBuf::rebuild_intervals`)。
  区間の木の形は出力に出ませんが、Go と同じ形に保ちます
- 書き込みと boost:Go の `Write` は boost を得た後に、同じ呼び出しの中で広がった空きに書き続けます。
  Rust の `write` は 1 回で書けた量を返し、広がった空きは次の `write` が使います。
  待つことは handle の層が持つためです ([アプリケーションの操作](#アプリケーションの操作))
- PMTU:Fragmentation Needed による PMTU の引き下げ (Go の `pmtuDrop` と `markLostLonger`) は、ICMP を入れる PR 6 で足しました。
  Go の PMTU の試験もその段で移しました
- 不変条件:`check_invariants` は、使っている接続ごとに scoreboard を記録から数え直して比べ (`tcp::sack::check_scoreboard`)、boost の無い接続が floor の受信の予約を持つことを確かめます。
  Go の試験は数え直しを `checkScoreboard` で行います。
  Rust は Go の試験が見逃した 2 つの変異 (最も右の SACK 済みの byte を更新しないことと、損失の境目を越えた記録を送った時刻の順の list に残すこと) も捉えるよう、SACK 済みの byte があれば最も右の SACK 済みの記録の端が `high_sack` と等しいこと、境目より手前の SACK 済みでない記録が list にあるなら今の世代で再送したものであることも確かめます。
  検出の 1 つずつに、壊した状態を渡す試験があります。
  boost の段を移す処理の確保の失敗 (取得の送信の輪、受信の輪、floor に戻す輪) は、chunk の確保の失敗を注入する試験で確かめます
- `Tcb` の行:次の ACK に載せる D-SACK の block と印は受け手の欄の行に置き、ACK を送るたびに印を書かず、立っている時だけ消します。
  受け手だけの接続が ACK ごとに後ろの行を書き換えないためです。
  PRR の欄と RecoverFS は SACK による回復の間だけ触るので `ConnCold` に置きました
- 記録の輪の添字:記録の輪の容量は 2 の冪でないので、剰余を割り算の命令にしないよう、先頭からの位置を 1 回の引き算で折り返します。
  意味は変わりません
- 試験:Go の `sack_test.go`、`scoreboard_test.go`、`prr_test.go`、`lostq_audit_test.go`、`dsack_test.go`、`cwndval_test.go`、`lazyegress_test.go`、`tlp_rto_test.go`、`rack_test.go`、`undo_test.go`、`cc_test.go`、`boost_test.go`、`rcvwin_test.go` を移しました。
  Go の試験が大きさ 1 の枠の集まりを作る所は、Rust の `Budget` の枠の数が固定なので、ほかの枠を別の接続で埋めてから取り合いを起こします
  試験は毎回 `check_invariants` を呼ぶので、ワークスペースの `Cargo.toml` で `wgft-wgstack` を dev と test の build でも `opt-level = 2` で作ります。
  溢れの検査と `debug_assert` は残ります。
  RACK の期限の敵対的な ACK の試験は Go と同じ ACK の数で流します。
  SACK の洪水の試験は Go の 20000 の ACK では 18 秒かかるので 5000 にし、ACK 1 つの手間の上界も確かめます。
  上界の式は ACK の数に比例するので、確かめる比は同じです
- 記録の照合:`crates/wgft-wgstack-dut/stages.json` の `landed` に 5 を足し、SACK、timestamp、CUBIC、boost の印の記録を照合に入れました。
  4b と 5 の段の印の記録はすべて Go の応答と byte の単位で一致し、2 節の台本もすべて通ります。
  意図した違いの一覧に足した行はありません

### PR 6 で決めたこと

実装の担当が決めた点です。
理由と共に挙げ、所有者か監督が変えるときはこの節を直します。

- UDP の endpoint の行:行は endpoint の 2 つの向きの予算、向きと大きさの区分ごとの今の chunk、受信の FIFO の先頭と末尾、送信の空きを待つ list の節を持ち、待ち受けと同じポートごとの行の表 (`PortTable`) に置きます。
  endpoint の byte の予算はいつも chunk の倍数なので chunk の数で持ち、datagram の番号は 16 bit にしました。
  このため `Limits` の UDP の datagram の数は 1 から 65,535 です。
  行はポートの表の世代と印を含めて 36 byte で、表は 2.3 MiB です ([上界の表](wgstack-bound.md))。
  受け付けるアドレス 1 つの agent の固定の項としては小さいので、密な表と番号の引き当ての 2 段にはしませんでした
- `Limits` の UDP の数:Go の試験だけが小さくする `udpRxDgrams` と `udpTxDgrams` に当たる `udp_rx_datagrams` と `udp_tx_datagrams` を `Limits` に足しました。
  試験の担当の `core` の fuzz と記録の `HELLO` の上限の組が使います。
  既定は Go の本番の値 (4096 と 1024) です。
  試験の `small_limits` は Go の `smallLimits` と同じく、再組み立ての表と UDP の予算を本番の値にしました
- 知らせの対象:UDP の endpoint は、同じポートの TCP の待ち受けと知らせの対象を分け合い、印 (`EV_ACCEPT`、`EV_UDP_READ`、`EV_UDP_WRITE`) で分けます。
  待ち受けと endpoint の開閉は自分の印だけを消します (`EventList::clear_bits`)。
  ポートの対象を別に並べると知らせの表が 65,536 個の対象の分だけ大きくなるためです。
  ping の endpoint の対象はポートの後に並べます
- `UdpWritable`:`send_to` が `WouldBlock` を返した endpoint だけを、行に通した待ちの list に入れます。
  送信の予約が 1 つでも返ったら、list の endpoint すべてに知らせて list を空にします。
  Go の `wakeTx` が、どの予約が返っても待つ書き手をすべて起こし、待つ書き手がいなければ何もしないのと同じです。
  Go の `Close` は待つ書き手をすべて起こしますが、Rust の `close_udp` は閉じた endpoint を list から外すだけで、ほかの endpoint に知らせません。
  閉じても送信の予約は返らないので、ほかの endpoint の `send_to` の結果は変わらないためです
- 閉じた endpoint の送り残し:Go では閉じた endpoint の値を送り残しの datagram が持ち続け、送り終えた時にその値の予算を返します。
  同じポートを開き直した endpoint の予算はその値と別です。
  Rust の datagram は持ち主のポートと開いた時の世代を持ち、送り終えた時に世代が違えば核の予算だけを返します
- chunk の確保の失敗:Go の chunk の置き場は確保に失敗しませんが、Rust の chunk の確保は失敗しえます。
  予約は要る chunk を先に揃え、揃わなければ取った chunk と datagram の番号を戻し、何も変えずに断ります。
  受信では核の予算で断ったことにして `udp_tunnel_full` に数えます。
  送信の `send_to` は、TCP の `write` と同じく待たずに `Error::NoMemory` を返し、endpoint を待ちの list に入れません。
  `UdpWritable` は送信の予約が返った時にだけ出すので、送信の FIFO が空のまま `WouldBlock` を返すと、知らせが来ずに待ち続けるためです
- 捨てた数とログ:受信の予算で断った datagram は、Go と同じく `udp_dropped` に数え、加えて endpoint の上限で断った数 (`udp_endpoint_full`) と核の予算で断った数 (`udp_tunnel_full`) に分けて数えます。
  1 分に 1 回までの門は 1 つで、`LogKind::UdpDropped` の数は予算で断った数の和です。
  Go のログの行は 2 つの数を書きますが、`LogLine` は 1 つの数だけを運ぶので、内訳は `stats` で読みます。
  ログの文面は記録の照合の対象ではありません。
  会計の不整合は門を通さずに 1 回だけ `LogKind::UdpFault` を出し、中身は `udp_receive_fault` が返します。
  ICMP の誤りの速さの制限で送らなかった数は `icmp_limited` に数えます
- 断片の数:`fragments_dropped` は、Go の `FragmentsDropped` と同じく、datagram を完成させなかった断片 (保持した断片、重なった断片、捨てた断片) を数えます
- 再組み立ての表の掃除の期限:`poll_timeout` は、表が項目を持つ間だけ次の掃除の時刻を返します (Go の `nextDeadline`)。
  呼び手の待ちのたびに表の全体をたどらないよう、表は使っている項目の数を持ちます
- 誤り:`Error` に `InvalidAddress`、`MessageTooLong`、`UdpStopped`、`TableFull`、`InvalidMessage`、`NoBufferSpace` を足しました。
  制御の輪が満杯の時の `send_ping` は、Go と同じく IP の ID を 1 つ使ってから `NoBufferSpace` を返します。
  Go と同じく、この拒否は `ctl_dropped` に数えません
- まれにしか触らない状態の置き場:UDP の状態、ping の表、ICMP の誤りの速さの制限、再組み立ての表の掃除の時刻は、核の共有の状態 (`Shared`) の中に置きます。
  `Shared` は 464 byte 大きくなり、segment ごとの経路が触る欄のキャッシュの行の中の位置がずれます。
  これらを作成の時に確保する別の値に移す形も試しましたが、`send_segment/1024` の L1 の miss は減らずに増えたので採りませんでした ([PR 6 の測定](#pr-6-の測定))
- ping の表:応答の置き場は作成の時に確保する配列です。
  応答の置き場は Go と同じく MTU の大きさで、Go は最初に使う時に確保しますが、Rust は 16 個すべてを作成の時に確保します。
  上界はどちらも 16 個の分を数えます
- PMTU:`pmtu_drop` を `tcp::input` に、`mark_lost_longer` を `tcp::sack` に Go と同じ形で写しました。
  `scoreboard_against_recount` の試験は、Go と同じく乱数の分岐で PMTU を引き下げます
- 試験:Go の `udp_test.go`、`frag_test.go`、`fragidle_test.go`、`checksum_test.go` の UDP の試験、`sack_test.go` と `observe_test.go` の PMTU の試験を移しました。
  Go の試験の読み書きの期限と、`Close` で待ちが解けることは handle の層の試験に移ります。
  `TestIdleDeviceSweepsAHeldFragment` は、Device のタイマーの goroutine の代わりに、`poll_timeout` の時刻を追う駆動が寿命の後に Time Exceeded を送ることを確かめます。
  受信の洪水の試験は 1 つの datagram ごとに `check_invariants` を呼ぶと遅いので、間を置いて呼びます。
  Go の試験に無い試験も足しました。
  送信の chunk の確保の失敗と取った chunk と番号の戻し、同じポートの待ち受けと endpoint が知らせの対象を分け合うこと、endpoint の chunk の上限と核の件数の上限の境目、ICMP の誤りへの誤りと multicast の送信元と引用の大きさの守り、断片を保持した時の掃除の時刻の張り直し、中身がちょうど新しい MSS の記録、PMTU の引き下げが損失の境目を数え直すこと、ログの数です
- 検出力:変異の試験で残った変異のうち、次のものは出力を変えないことを確かめ、Go と同じ形のために守りを残しました。
  核の datagram の件数の予算の比べ (空きの list が先に尽きます)、閉じた endpoint の送り残しが今の chunk を外す時の世代の比べ (その chunk は送り残しが持つ間ほかの endpoint に渡りません)、checksum の 0 を 0xffff にする所 (`write_udp_header` も同じ置き換えをします)、Fragmentation Needed の引用の送信元の比べ (接続の表を引用の送信元で引くので見つかりません)、ICMP の誤りの後続の断片の守り (呼び手は後続の断片を渡しません)、再組み立ての知らせの後続の断片の守りと最初の断片の有無 (`param_problem_ok` と `timeout_quote` が同じ条件で断ります)
- 不変条件:`check_invariants` は、UDP の chunk と datagram の空きの list、核と endpoint の予算と保持する chunk と datagram の一致、区分の枠の使っている数、受信と送信の FIFO、待ちの list、ping の行を確かめます。
  核の chunk の置き場の数は、接続の輪と UDP の chunk の和と比べます

#### PR 6 の測定

2026-11-01 に、E コアの車線 (`wgft-heavy --class tool --timing`、release の build) で、PR 5 の頭、PR 6 (UDP の状態を `Shared` の中に置く形)、UDP の状態を作成の時に確保する別の値に移した形の 3 つを比べました。
`perf stat` で `send_segment/1024` を 4 秒ずつ 4 回流し、1,000 命令あたりの L1 の miss (`mem_load_uops_retired.l1_miss`) と IPC を数えました。

| build | 1,000 命令あたりの L1 の miss | IPC |
| --- | --- | --- |
| PR 5 の頭 | 12.81、11.21、11.20、11.31 | 2.163 から 2.171 |
| PR 6 | 11.44、13.09、11.73、11.31 | 2.163 から 2.215 |
| 別の値に移した形 | 14.61、13.36、14.61、12.90 | 2.183 から 2.214 |

決まった時間に流した命令の数と IPC は 3 つで同じ程度でした。
`send_segment/1024` の criterion の中央の推定は、同じ build でも 631 ns と 677 ns の間で回ごとに変わり、3 つの差はこの揺れの内でした。
L1 の miss は別の値に移した形だけが多く、PR 6 の形と PR 5 の頭の差は回ごとの揺れの内でした。
別の値に移した形で増えた理由は調べていません。

### 送り手の不変条件

`check_invariants` は使っている接続ごとに `check_sender` を呼び、Go の敵対的な送り手の試験 (`runAudit`) が各段の後に確かめることと `checkScoreboard` を写します。

- SND.UNA ≤ SND.NXT ≤ SND.MAX と、輻輳の窓が 0 でないこと
- scoreboard の数え直し (PR 5 の `check_scoreboard`):記録が SND.UNA から SND.MAX まで隙間なく並ぶこと、SACK 済みの byte と数、境目から先の byte と数、再送の byte (`rtx_bytes`)、境目から先の RACK の損失の byte、位置の欄 (`loss_idx`、`rxt_idx`) の範囲、2 つの list (`t_list`、`lost_q`) の節と印と数と順
- pipe:増減で保つ欄から求めた値が、RFC 6675 の定義どおりに記録から求めた値と一致すること
- 分けて送っている記録の中の位置:`q_mid` の間は損失の待ち行列が空でなく `q_off` がその先頭の記録の長さより小さいこと、`rxt_mid` の間は `rxt_off` が `rxt_idx` の記録の長さより小さいこと

Go の「pipe は送り残しの 2 倍と 1 以下」は確かめません。
定義どおりの pipe は SACK 済みでない記録の長さの和と再送の印の記録の長さの和の和で、どちらも送り残し以下です。
このため、数え直した pipe と一致すればこの上限も満たし、別の確かめは届かない枝になるためです。
接続の欄だけを持つ `pipe` と `seg_mss` は `Tcb` を受ける関数にし、`Conn` の同じ名前の関数はそれを呼びます。
`rtx_bytes` の減らし忘れ (`drop_head` が減らさない故障) を入れると、核の単体の試験と記録の照合が段ごとに捉えることを確かめました。

### 後の段

agent の置き換えが終わった後に、次の段を順に決めます。

- 性能の目標の測定と、届かない点の作業 ([置き換えの判定](#置き換えの判定))
- 需要で育つバッファ ([需要で育つバッファとの関係](#需要で育つバッファとの関係))
- 参照の Linux が 7.2 に移ったことで生じた受け手の変更の候補。
  候補の一覧は `docs/design/userspace/wgstack-receive-linux72.md` にあります
- dial の側と server の Device ([dial の側を足す継ぎ目](#dial-の側を足す継ぎ目))
- 送信の経路の system call のまとめ (Linux の `sendmmsg` と UDP の GSO) と、受信の経路のまとめ

## 実装の時に決めること

- 写さずに読み書きする口:`read_slices` と `write_slices` を足すか。CPU を測ってから決めます
- device の層との受け渡し:`Device::poll_packet` と `Device::poll_transmit` が packet ごとに確保する形を、呼び手の buffer に書く形に替えるか
- 受け付けるアドレスが増えたときの待ち受けと UDP の endpoint の表の持ち方 (dial の側の段で決めます)
- 1 回の起床の上限:1 回に作る packet の数と、`WGFT_AGENT_BATCH_MIB` から導く式
- 割り当て器:OS の標準と mimalloc のどちらにするか (測ってから)。選んだ割り当て器の丸めの係数
- TUN の殻:ラボの一式が Rust の agent で通った後に消すか

## 未確認の点

- Rust の核の byte あたりの CPU と、Go の wgstack と gVisor との比は測っていません
- 1 つのスレッドのデータプレーンが、Windows と macOS の時計の分解能とスケジューラの下で、遅延 ACK と RTO の規則を保てるかは確かめていません
- FMA を使わない build で作った記録の浮動小数点の値に、Rust が同じ値で並べるかは、記録を作るまで分かりません
- 確保の数えで測る保持と RSS の比は、Rust の agent では測っていません

[v2: Rust への移行](README.md)
