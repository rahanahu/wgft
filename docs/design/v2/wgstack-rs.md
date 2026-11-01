# wgstack の Rust 版

この文書は、v2 の Rust の agent が使う wgstack の Rust 版の設計を定めます。
wgstack は wgft 自身の TCP/IP の stack です。
agent のユーザー空間モードは、トンネルの中の TCP、UDP、ICMP をこの stack で終えます。
このため Rust の agent は root の権限も TUN も要りません。
実装は、受動の open、閉じる手順と TIME_WAIT、アプリケーションの操作と知らせ、データの送受信、RTO、窓の probe、SACK による回復と D-SACK、RACK-TLP、不要な再送の取り消し、CUBIC と NewReno、boost の取得と回収、UDP の endpoint と予算、echo と ping、ICMP の誤りと PMTU、断片の入口を持つ核と、核の上の非同期の handle の層 (`wgft-netstack`) です。
dial の側は未実装です。
qbench の `wgstack-rs` の engine で、関門の表の cell の正しさの判定は凍結した Go の wgstack と同じでした ([qbench での測定](#qbench-での測定))。
構造、境目、メモリをここで決め、まだ決めていない値と細部は[実装の時に決めること](#実装の時に決めること)に残します。

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

- [試験の道具の設計](test-tooling.md):台本の言語、2 つの runner、DUT の口、記録の照合、qbench、fuzz、関門の細部を持ちます。
  この文書の[検証](#検証)は、その設計の決定を前提にして要点だけを書きます
- [agent の置き換えの設計](agent-parity.md):device の殻、データプレーンの駆動の実装、中継、UDP の中継、制御ソケットを持ちます。
  データプレーンの駆動の規則の正本はこの文書の[データプレーンの駆動](#データプレーンの駆動)で、agent の置き換えの設計はそれを実装する規則を足します

所有者が決めた項目には「決定」の印を付け、所有者の確認を待つものは「仮の決定」と書きます。
印の無い項目は実装した設計です。
「提案」の印は、まだ実装していない勧めに付けます。
提案を採るか変えるときは、同じ変更でこの文書を直します。

### 前提となる所有者の決定

- 決定:Go の wgstack を Rust に移植します。smoltcp は SACK の回復、TCP の timestamp、RACK-TLP を持たないので使いません (2026-11-01)
- 決定:Rust の wgstack の核は sans-IO にします。入力は時刻、packet、操作で、出力は packet、次に起こす時刻、イベントです。核の中にスレッド、実時間のタイマー、ソケットを置きません ([設計の制約](README.md#設計の制約))
- 決定:Go の wgstack は参照の実装として今の形で凍結し、機能を足しません。Rust の実装が追いついた後に消します ([Go の wgstack](README.md#go-の-wgstack))
- 決定:移行の間、Rust の wgstack は凍結した Go の wgstack と同じ入力に同じ packet を返すことを求めます。Go の wgstack の記録とオフラインで bit の単位で照らし、追いついた後は自由に変えます (2026-11-01)
- 決定:適合の台本は混成で持ちます。直線の台本はデータにし、Go の runner と Rust の runner が同じファイルを流します。反応する台本と測る台本は Go のまま残し、Rust の試験用のプログラムを標準入出力で時計ごと動かします。C ABI は作りません (2026-11-01)
- 決定:内部に触れる試験 (fuzz、不変条件、手で進める時計の試験、単体の試験) は実装と一緒に Rust に移します。実ネットワークの面から製品を確かめる試験は Go のまま残せます ([テスト](README.md#テスト))
- 決定:割り当て器は、予算を持つ保持を自前の置き場から取ることを前提に、OS の標準と mimalloc を測ってから選びます (2026-11-01)
- 決定:device の層は datagram ごとに確保せず、buffer を使い回します。割り当て器は OS の標準のまま、Linux の build は musl の静的な build のままにします。glibc に動的に結ぶ build は、バッチの段で写しを減らした後に残る差を測り直してから決めます ([割り当て器と libc の比べ](#割り当て器と-libc-の比べ)、2026-11-02)
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
| `boost.go` | `budget`、`tcp::boost`、`stack::boost` | boost の枠、回収、取り消し |
| `output.go` | `output` | 出力の 4 つの組と deficit round robin、制御の輪 |
| `wheel.go` | `wheel` | タイマーの輪 |
| `index.go`、`siphash.go` | `index`、`siphash` | 4 つ組の hash の表と SipHash-2-4 |
| `packet.go` | `wire` | IPv4、TCP、UDP、ICMP の解釈と組み立て、checksum |
| `udp.go` | `udp` | UDP の endpoint、受信と送信の予算、送信の断片化 |
| `icmp.go` | `icmp` | echo、ping の endpoint、ICMP の誤り |
| `frag.go` と `internal/ipv4frag` | `frag` | 断片の入口と再組み立ての表 |
| `trace.go` | 移しません | 試験と測定は、ACK ごとの観測の代わりに `Stats` と知らせと `check_invariants` を読みます |

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
- boost の枠の集まり:プロセスで 1 つの集まりを `Budget` という値にし、トンネルを作り直すときに古い核から新しい核へ渡します ([予算の持ち主](#予算の持ち主))
- 出力:Go の `Read` は wireguard-go の buffer に packet を書き、末尾に送信のバッチの印を書きます。
  Rust の核の `poll_transmit` は呼び手の buffer に packet を 1 つ書くだけです
- 上界の数え方:Go の `Bound` は、Go のヒープの確保の丸めを `append` の容量で測ります。
  Rust は型の大きさと確保した容量から数えます ([上界の式の写し方](#上界の式の写し方))

### 移さないもの

- 送信の向きのバッチの台帳 (`batch.go`):移しません。
  台帳は wireguard-go の staged のキューと送信のキューに滞留する buffer を数えるための仕組みです ([送信の向きの予算](../userspace/wgstack-batching.md#送信の向きの予算))。
  Rust の agent では device の層を wgft が持ち、核の出力を device の層に渡す規則 ([データプレーンの駆動](#データプレーンの駆動)) が滞留を device の層の上限の内に保つので、台帳も印も鍵も要りません。
  核が乱数を直接読む例外もこれで無くなります
- `tun.Device` の面:`Name`、`File`、`Events`、`BatchSize` は wireguard-go との境目のもので、Rust の核は持ちません
- gVisor と並べるための差し替えの面:Go のトンネルの非公開の interface、`internal/nettun` と同じ形の `Create`、gVisor の挙動に合わせた互換の部分は移しません
- 読み書きの期限:核は期限を持ちません。Go の核が壁時計を読む例外はこれで無くなります
- `ManualClock` と Device のタイマーの goroutine:sans-IO の核は呼び手が時刻を渡すので、試験用の時計の型も本番のタイマーの goroutine も要りません

### crate の分け方

次の crate に分けます。

| crate | 中身 | 依存 | 書き手 |
| --- | --- | --- | --- |
| `crates/wgft-wgstack` | sans-IO の核 | 標準ライブラリだけ | 実装の担当 |
| `crates/wgft-netstack` | 核を tokio の上で使う handle の層。TCP、UDP、ping の非同期の handle、waker の表、操作の知らせ | `wgft-wgstack`、tokio | 実装の担当 |
| `crates/wgft-wgstack-bench` | 核の segment ごとの受信と送信の経路の criterion のベンチ。配布せず、`wgft` のバイナリにも入りません | `wgft-wgstack`、dev 依存の `criterion` | 実装の担当 |
| `crates/wgft-wgstack/fuzz` | cargo-fuzz の target。ワークスペースの member に入りません | `wgft-wgstack`、`libfuzzer-sys` | target ごとに[fuzz](#fuzz)の表が決めます |
| `crates/wgft-tcpharness`、`crates/wgft-wgstack-dut` | 試験の道具と DUT のバイナリ。配布せず、`wgft` のバイナリにも入りません | `wgft-wgstack` | 試験の担当 |

handle の層を `wgft-agent` から分けるのは、後で Rust の server が dial の側で同じ層を使うためです。
device の層と核を組み、UDP のソケットとタイマーを回す駆動の実装は `wgft-agent` に置きます。

### 依存と隔離の検査

Go の `internal/dataplane/deps_test.go` の `TestWgstackImports` に当たる検査を次の形で持ちます。

- 依存:`wgft-wgstack` の `[dependencies]` は空にします。
  `[dev-dependencies]` にも試験の道具の crate を入れません。
  criterion のベンチも別の crate `crates/wgft-wgstack-bench` に置き、核の crate の依存の表を空に保ちます。
  crate の試験 (`src/scan_tests.rs`) が manifest を読み、依存の表が空であることを確かめます。
  CI の job を足さずに `rust-check` の中で流れるためです
- sans-IO と伸びる collection:`wgft-wgstack` の clippy の設定の `disallowed-methods`、`disallowed-types`、`disallowed-macros` で、`Instant::now`、`SystemTime::now`、スレッドの作成、`std::net` のソケット、ファイル (`std::fs`)、環境変数 (`std::env`)、プロセス (`std::process`)、標準入出力、OS の乱数の読み取りと、容量を自動で伸ばす操作 (`Box`、`Rc`、`Arc` の型と文字列を作る操作を含みます) ([確保の規則](#確保の規則)) を禁じます。
  設定は `crates/wgft-wgstack/clippy.toml` に置きます。
  clippy は crate の manifest の directory から上へ設定を探すので、この一覧はこの crate だけに効きます。
  禁じた呼び出しを置いた build が警告になり、ほかの crate は警告にならないことを確かめました
- source の走査:clippy の一覧に加えて、同じ禁止の語で source を走査する試験を置きます。
  clippy が見ない cfg (`fuzzing` と故障の注入) の中のコードを確かめ、clippy の一覧から項目が消えていないことも確かめます。
  文字列の照合なので、注釈と試験の module は見ません
- unsafe:`wgft-wgstack` は `#![forbid(unsafe_code)]` にします。
  checksum も `as_chunks` と `u64::from_be_bytes` の安全なコードで書きます
- 製品の木:CI の `cargo tree` の検査が、`wgft` のバイナリの依存の木に `wgft-tcpharness` と `wgft-wgstack-dut` が無いこと、測定用の feature が有効でないことを確かめます。
  今の `rust-check` は crate の検査を、すべての target と feature を有効にした依存の木で行います。
  feature の検査は、測定用の feature を足すときに足します
- I7 の隔離:後で作る agent のカーネルモードの crate が、推移的にも `wgft-wgstack` に依らないことを、製品の木と同じ `cargo tree` の検査で確かめます。
  カーネルモードの agent は wgstack を作りません

`no_std` で sans-IO を構造で強いる案は採りません。
`alloc` を使うには `extern crate alloc;` の宣言が要るうえ、禁止の一覧で同じ効果を得られるためです。

## sans-IO の API

形 (入力、出力、待たない操作、知らせ) は決定に従います。

### 作成と終わり

- 作成:`Stack::new(config, budget, seed, hook)` が、作成の時の設定 (受け付ける宛先の集合、MTU、K、試験だけが小さくする上限の組、試験の選択) から表をすべて確保します
- MTU:576 から 9216 を受け付け、外の値は設定の誤りにします。
  server が送る範囲に合わせた範囲です。
  範囲の外の値を 1420 に替えるのは agent の側です
- 受け付ける宛先の集合:agent ではトンネルのアドレスの /32 の 1 つだけです。
  `Config` はこの 1 つのアドレスだけを持ちます。
  プレフィックスの集合は dial の側を足すときに `Config` に足します
- 作成の失敗:`Stack::new` は設定の誤りと確保の失敗を `NewError` で返し、渡した `Budget` を `NewError::into_budget` で取り戻せます。
  作り直しが失敗しても `Budget` を失わないためです
- 表の大きさ:Go の package の中の `limits` に当たる値を公開の `Limits` にします。
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
  接続を閉じる操作の名前が `close` でなく `close_conn` なのは、核を消費する `close(self, now)` と同じ名前を持てないためです。
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
  核に状態を足すときは、確かめも足します。
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

`Event` は次の種類を持ちます。

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
対象の番号は、接続の枠、待ち受けのポート、ping の endpoint の順に並べた 1 つの list にします。
UDP の endpoint は同じポートの待ち受けと対象を分け合います ([UDP と ICMP と断片で決めたこと](#udp-と-icmp-と断片で決めたこと))。
呼び手は知らせを受けたら操作を試し、`WouldBlock` なら次の知らせを待ちます。

知らせを付ける所と handle は次のとおりです。

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

- 時刻:核の時刻は `Time` で、任意の起点からの単調な ns の符号なしの整数です。
  Go の核の時刻 (起点からの int64 の ns) と同じ値を持てるので、記録の時刻をそのまま渡せます。
  `Time` と `Duration` の足し算と、`Time` どうしの引き算は飽和します。核の中で panic を起こさないためです。
  駆動の層は、作成の時の `Instant` からの経過を ns にして渡します。
  核は受けた時刻を `i64::MAX / 4` ns (約 73 年) で止めます。
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

核は作成の時に呼び手の hook を受け取り、型の引数で持ちます (`Stack<H: Hook>`)。

- `boost_granted(conn)`:boost を得た時に呼びます
- `may_return(conn) -> bool`:需要の無い保有者を floor に戻す前に呼び、偽なら戻りを取り消します
- `boost_returned(conn)`:floor に戻した後に呼びます

hook は核への参照を受け取らないので、核を呼び返せません。

製品が要らないものは製品に入れません (所有者の 2026-11-02 の規則)。
試験と fuzz だけが使う口と欄 (書き換えた枠だけの確かめ、核の使い回し) は、`cfg(test)` か核の crate の feature `harness` の build だけにあり、製品の build には型も処理もありません。
feature `harness` は試験の道具の crate (`wgft-wgstack-dut`) だけが付け、製品の binary の build (`-p wgft`) は付けません。
ワークスペースの `default-members` は製品の crate だけなので、引数の無い `cargo build` も試験の道具の crate を同じ build に入れず、この feature を付けません。
CI の `product features` の段が、`-p wgft` と引数の無い形の両方で、依存の木にこの feature が無いことを確かめます。
hook はこれらの口を持たず、製品の hook と同じです。
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

dial の操作 (`connect`) と SYN-SENT の規則は、agent の置き換えが終わった後に実装します。

## データプレーンの駆動

この節は、agent が device の層と核を動かす規則の正本です。
`wgft-agent` がこの節を実装し、この節と食い違う実装はこの節を先に直します。

### スレッドと所有

データプレーンは、トンネルの世代ごとに 1 つの OS のスレッドで動かします。
そのスレッドは tokio の current-thread の実行環境を持ち、次のものを `Rc<RefCell<Dataplane>>` の 1 つの値として持ちます。

- WireGuard の device の層 (`wgft_wireguard::Device`)
- wgstack の核
- `wgft-netstack` の waker の表 (作成の時に枠と表の数で確保します)

UDP のソケットは駆動の task が持ちます。
中継の接続の task も同じスレッドの local の task として動き、`wgft-netstack` の handle を通して核を呼びます。
制御プレーン (stream、ハートビート、制御ソケット) は別の多スレッドの実行環境に置き、データプレーンには容量の決まった channel で命令を送ります。
命令は待ち受けの開閉、状態の読み出し、ping のように頻度が低いものだけです。

`wgft-agent` は、核と waker の表を 1 つの trait (`dataplane::Upper`) の背後に置いて、この形を実装します。
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

`wgft-netstack` の handle は、出力を生みうる操作の後に、同じスレッドの知らせで駆動の task を起こします。
agent のデータプレーンの知らせは錠を持たない `Cell` の印と waker で、`LocalNetstack` は `tokio::sync::Notify` です。
対象の操作は `write`、`close_write`、`close`、`abort`、`read` (窓の更新を生むため)、`close_listener`、`send_to`、ping の送信です。
`accept` は出力を生まないので起こしません。
boost を accept の時に与える方針で受信のバッファが広がっても、窓の更新は最初の `read` が送ります。
窓を満たした接続を accept しても segment が出ないことは、使い捨ての試験で確かめました。
`WouldBlock` を返した操作は核の状態を変えないので、起こしません。
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

核 (`wgft-wgstack`)、WireGuard の device (`wgft-wireguard`) と、その下の WireGuard の protocol の crate (`sanstun`) は、release の build でも整数の桁あふれを検査します (`Cargo.toml` の `[profile.release.package.*]` の `overflow-checks = true`)。
どれも相手が送る packet を読む crate で、桁あふれは相手が届かせうる誤りです。
`sanstun` への指定は build の profile の設定で、依存のソースは変えません。
検査が無いと値が黙って回り込み、表の添字や長さの誤りとして先へ進みます。
検査があれば panic になり、上のとおり世代を終えてトンネルを作り直すので、結果の範囲が決まります。
このため、panic を巻き戻す設定 (`panic = "unwind"`) と組で保ちます。

segment ごとの経路の費用は、criterion の `recv_segment`、`send_segment` と `_sack` の組で、検査を入れる前の build を基準に測りました (開発機、測定用の CPU の車線、中央の推定の変化)。

| 組 | 1 本 | 64 本 | 1024 本 |
| --- | --- | --- | --- |
| `recv_segment` | +0.3% | +0.6% | +1.4% |
| `recv_segment_sack` | -0.2% (差なし) | +2.9% | +2.2% |
| `send_segment` | +2.5% (差なし) | +0.6% | +2.3% |
| `send_segment_sack` | +0.7% | +2.9% | -3.3% |
| `rig_overhead` (道具だけ) | +0.2% (差なし) | | |

変化は -3.3% から +2.9% で、同じコードを流し直したときの揺れ (5% ほど) の内でした。
device の層 (`wgft-wireguard`) は criterion のベンチを持たないので、検査の費用は測っていません。

`sanstun` の費用は、`sanstun` 0.1.0 の criterion のベンチ `data_path` で、検査を入れない build を基準に 2 回ずつ測りました (開発機、測定用の CPU の車線、中央の推定の変化)。

| 段 | 64 byte | 1280 byte |
| --- | --- | --- |
| `begin_encapsulate` | +0.6%、+0.1% | -0.3%、+0.4% |
| `encrypt` | +0.1%、-0.4% | -1.2%、+0.2% |
| `receive` | +0.1%、+0.8% | +0.8%、+0.4% |
| `begin_decapsulate` | +1.0%、+3.1% | +1.2%、-0.3% |
| `decrypt` | -0.7%、+0.1% | +0.8%、+0.4% |
| `commit_decapsulate` | -8.7%、+1.1% | -4.8%、+1.3% |
| `poll_event` | +0.3%、+2.9% | 0.0%、-1.1% |

1 つの packet の費用の大半を占める `encrypt` と `decrypt` の変化は ±1.3% の内で、ほかの段の変化も 2 回の間の揺れより小さいか同じ程度でした。

## メモリ

### 接続の枠の配置

決定 (所有者、2026-11-01):データプレーンのコードは CPU のキャッシュに合わせて配置します。
segment ごとの経路が触る欄をまとめ、まれにしか触らない欄から分けます。
tick ごとにたどるものは配列と番号で持ち、pointer をたどりません。
輪は連続した領域に置き、ほかのスレッドが読む数を segment ごとの欄の行に置きません。
配置は意味を変えないので、Go の wgstack の記録との bit の一致の条件はそのまま守ります。

接続の枠は次の形にします。

- 接続の枠は、同じ番号で引く 3 つの配列に分けます。
  `Tcb` は segment ごとの経路が触る欄 (番号、窓、タイマーの期限、輻輳の窓、送信の記録の scoreboard、印) で、
  `repr(C, align(64))` で受信の入口が最初に触る欄を前に並べ、枠どうしがキャッシュの行を分け合わないようにします。
  `ConnCold` は不要な再送の取り消しと boost の需要のような、まれにしか触らない欄です。
  `ConnBufs` は送受信の輪と記録の輪の管理で、`repr(C)` で小さな管理の欄を前に、floor の段の輪の chunk への pointer の配列
  (1 つの輪で 128 byte) を後ろに置きます
- boost の段の輪の chunk への pointer の表 (1 つの輪で 2 KiB) は、boost の記録の輪と区間の表と同じく `Budget` が作成の時に確保し、boost の枠と共に貸し借りします。
  boost の枠は B 本なので、接続の枠のどれもが boost の段の大きさの表 (2 つの輪で 4 KiB) を持つと、使わない表を枠の数だけ作成の時に 0 で埋めて持ち、既定の K で約 10 MiB になるためです。
  輪は表を段で選び、floor の段では枠の中の配列を、boost の段では借りた表を使います
- 輪の pointer の配列は `ConnBufs` にあるので、`Tcb` の行は配列に押し広げられず、segment ごとの欄が配列の間に散らばりません
- accept の待ち行列の節は、別の接続の処理が書き換えるので、接続の枠から出して番号で引く配列 (`QLink`) にし、
  核の共有の状態に置きます。
  接続の処理が自分の枠と共有の状態を同時に `&mut` で借りられるようにするためでもあります
- タイマーの輪、出力の list、知らせの list は番号の表です
- 数えと 1 分に 1 回の門は核の共有の状態にあり、`Tcb` の行にありません。
  核は 1 つのスレッドの値で、ほかのスレッドは読みません
- 上界の `conn_slots` の項は 3 つの配列と空きの list と待ち行列の節の型の大きさで数えます

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

3 つの配列に分けた配置と、3 つの部分を 1 つの値に並べた配置 (輪の pointer の配列が接続の欄と同じ値にある形) の差は、このベンチでは流し直しの揺れの内で、1024 本でも作業の集合はキャッシュに収まります。
分けた配置を選んだ理由は、測った速さではなく、`Tcb` の行が輪の配列と boost の段の大きさに左右されないことです。
接続の数が L2 を超える負荷 (数千本の接続と大きな受信の窓) での差は測っていません。

### 上界の式の写し方

上界の式の項と規則は Go と同じです ([上界の式](../userspace/wgstack.md#上界の式))。
I1 から I7 の不変条件もそのまま守ります ([不変条件](../userspace/wgstack.md#不変条件))。
変わるのは、項の大きさの数え方と、表の上限です。

- 固定の表:接続の枠、hash の表、握手の途中の表、TIME_WAIT の表、タイマーの輪、出力の list、制御の輪、UDP の管理の配列、知らせの list、待ち受けの表、UDP の endpoint の表は、作成の時に確保します。
  大きさは確保した容量と `size_of::<T>()` の積で数え、後から大きくしません
- 待ち受けと UDP の endpoint の上限:Go は待ち受けを map で持ち、数は信頼された設定で決まるとして式の外に置いていました。
  Rust では TCP の待ち受けの表と UDP の endpoint の表を、受け付けるアドレス 1 つあたりポートの数 (65,536) の固定の行で持ち、`Bound` に項 N_lt × c_lt と N_ue × c_ue を加えます。
  v1 はルールの範囲の幅に上限を置かないので、ポートの数が構造の上限です。
  待ち受けの行は 16 byte (世代、accept の待ち行列の先頭と末尾、待ち行列の長さ、握手の途中の行の数) です。
  開いている印は行に持たず、ポートごとに 1 bit の集合 (8 KiB) に持ちます ([不変条件の検査の手間](#不変条件の検査の手間))。
  受け付けるアドレスは 1 つなので、表は 1 つです。
  `ListenerId` と `UdpId` の世代は 32 bit です。
  ポートを開き直す回数は接続の枠の使い直しよりずっと少なく、行を小さく保つためです。
  UDP の endpoint の表は同じポートごとの行の表を使います。
  UDP の endpoint の行は [UDP と ICMP と断片で決めたこと](#udp-と-icmp-と断片で決めたこと)にあります
- 枠と共に持つ配列:floor の送信の記録の輪と区間の表は、Go と同じく枠を初めて使う時に確保し、枠と共に持ちます。
  上界は作成の時に数えるので、確保の時機は上界を変えません
- accept の待ち行列の枠の送信の floor:floor の項は N_c = K + Q 本の枠のどれにも送信の floor f_s を数えます。
  accept の前の接続は送信のデータを持ちませんが、この分は上界の過大な見積もりではありません。
  核は accept した接続の数を K で抑えず (Go と同じ)、待ち行列の Q 本と枠の数 N_c だけを抑えるためです。
  K を超えた接続を `abort` で終えるのは核の外の中継です。
  中継が閉じた後も送り残しを送っている接続は、枠と送信のデータを持ったまま中継の K に数えられません。
  このため、K + Q 本の枠がすべて accept されて両方の輪を満たす状態に届きえます。
  確保の数え (`crates/wgft-alloc-count` の `wgstack_held`) では、中身の無い accept の前の接続は floor の記録の輪と区間の表の 21,712 byte を持ち、届いたデータの分は受信の floor (256 KiB) までの chunk を持ち、送信の chunk は 0 でした。
  K = 4、Q = 8 の核は 12 本を accept し、12 本の両方の輪を満たした会計は floor の項にちょうど届き、超えませんでした。
  待ち行列の枠を送信の floor から外すには、核が accept した接続の数を K で抑える変更 (accept の意味の変更) が要るので、採りません
- boost の配列:B 本の枠の分の boost の記録の輪と区間の表と、送信と受信の輪の chunk の表を `Budget` の作成の時に確保し、`Budget` の中に置きます。
  boost を得た接続はその 1 組を借り、floor に戻るか閉じるときに返します。
  boost の取得の時に確保が失敗する場合が無くなります
- 段を変える間の一時の保持:Go の `Bound` は B × (f_s + f_r) を式の和とは別の `Transient` として返しますが、Rust の `Bound` はこの項を持ちません。
  段を変えるのは boost の枠を持つ接続だけで、枠は段を移す前に受け取り、floor に戻した後に返します。
  核は 1 つのスレッドで動くので、1 回の移しは 1 本の接続の 1 回の呼び出しの中で終わり、その間にほかの接続が枠と chunk を取ることはありません。
  枠を持つ接続の予約は、両方の向きの boost の段の 8 MiB (chunk 512 個) です。
  移す間の保持は、この予約と接続ごとに比べます。
  送信の輪は確認した分の chunk を返すので、floor 以下の生きている範囲に掛かる 17 個までの chunk を持ちます。
  この前提は不変条件の検査が確かめます (送信の輪が確認を待つ範囲の外に chunk を持たないこと)。
  受信の取り消しは区間の表だけを変えるので、floor に戻す時の古い受信の輪は boost の段の 256 個までの chunk を持ったままです。
  最も多く持つのは floor に戻す時で、古い受信の輪の 256 個、新しい受信の輪の 16 個、古い送信の輪の 17 個、新しい送信の輪の 16 個の和の 305 個 (4,880 KiB) です。
  boost に上がる時は、送信だけなら 49 個、受信なら boost の送信の輪を含めて 289 個です。
  どれも接続の予約の 512 個の内にあります。
  コンパイル時の検査 (`bound::STAGE_CHANGE_FITS`) がこの大小を確かめます。
  単体の試験 (`stack::tests::demote_holds_within_the_connection_s_reservation`) は、受信の輪を順序外のデータで満たした boost の接続を floor に戻し、移す間に輪が持つ chunk の最大がちょうど 305 個に届き、予約の内にあることを確かめます。
  敵対的な保持の試験は確保の最大値を Rust の `total` と比べます
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
型の大きさは rustc の版で変わりうるので、toolchain を上げるときは同じ変更で上界の表を生成し直し、差分を PR に書きます。

### 確保の規則

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

Rust では枠の集まり (B 本の枠と、前節の boost の配列) を `Budget` という値にし、核がそれを所有します。
トンネルを作り直すときの受け渡しは[世代と予算の受け渡し](#世代と予算の受け渡し)の順に従います。
古い核の接続はその前にすべて閉じているので、受け渡す `Budget` の借りは 0 です。
このため枠の集まりはプロセスで 1 つのままで、別の Device の接続を回収する処理も要りません。
古い核の表と chunk は `close` で解放されるので、Go の上界が足していた「古い世代の M_fix」の項は要りません。

boost の配列の貸し借りは値の移動です。
枠を得た接続は `Budget` から配列を受け取り、使っていない方の配列を枠の控えに置き、floor に戻るか閉じるときに配列を `Budget` に返します。
控えには、boost の間の floor の記録の輪と、受信が boost の段に移るまでの boost の区間の表 (移った後は floor の区間の表) と受信の輪の chunk の表を置きます。
送信の輪の chunk の表は、boost の段に移った送信の輪が持ちます。
輪の chunk の表は会計の外です。
`Budget` の作成の時に確保して貸し借りするだけで、核を作った後の確保の数えを増やさないためです。
枠の取り合いでは、floor に戻した保有者が `Budget::release` で枠を返し、新しい保有者が `Budget::hand_over` でその枠と配列を受け取ります。
枠を貸す順 (最も小さい空きの枠) と保有者をたどる順 (枠の順) は Go と同じです。
上界の boost の項は、`Budget` の枠の管理の配列も数えます。

### 保持の量の測り方

- 核の会計:Go の `Stats` と同じく、chunk、記録の輪、区間の表、UDP の枠、再組み立ての表が今持つ量を核が数えます。
  この値は `held()` で読めます
- 確保の数え:試験の build では、`GlobalAlloc` を包んで確保と解放の byte を数える割り当て器を使います。
  割り当て器は試験の道具の crate `crates/wgft-alloc-count` に置きます。
  `GlobalAlloc` の実装は unsafe を要し、核の crate は unsafe を禁じ、依存も持たないためです。
  割り当て器は、プロセス全体の数えと、測りの窓を開いたスレッドだけの数えを持ちます。
  核はスレッドを持たないので、核を試験のスレッドから駆動する試験はスレッドの数えで測ります。
  libtest は試験を別のスレッドで動かし、main のスレッドは試験を起動した後に、結果を待つための登録を確保します。
  この確保は測りの窓と並行に起こるので、プロセス全体の数えには混ざることがあります。
  macOS の std の mutex は初めての lock で pthread の mutex を確保するので、macOS では混ざる量が増えます。
  この crate の試験が、作ったばかりの核の確保が上界の固定の項と boost と再組み立ての項の内にあり、閉じて `Budget` を捨てると元の値に戻ることを確かめます。
  核を作った後に増えた byte は、`Held` の chunk、記録の輪、区間の表、再組み立ての写し、UDP の chunk、置き場の chunk (`pool_bytes`) の和から、boost の枠を持つ接続が `Budget` から借りている配列 (`lent_array_bytes`) を引いた値とちょうど一致します。
  借りている配列は `Budget` の作成の時に確保したもので、会計の記録の輪と区間の表にも数えるためです。
  試験 `wgstack_held` が、accept の前の接続、すべての枠を accept して満たした核、確認で置き場に戻った chunk、boost の枠を借りた接続でこの一致を確かめます。
  敵対的な保持の試験は、この crate を dev-dependency にして使えます。
  敵対的な保持の試験は、核の操作の前後の生きている byte の差が `Bound` 以下であること、核を閉じた後に元の値へ戻ることを確かめます。
  GC が無いので、この差は Go の試験の「生きているヒープ」より正確に保持を表します
- OS の値:ラボのメモリの測定は、Linux の `VmRSS` と `VmHWM` を読みます。
  測定用の cargo の feature を有効にした build だけが、核の会計と確保の数えを制御ソケットに出します。
  Go の build tag `labmemprobe` に当たります。
  この feature はどの crate の依存の宣言でも有効にせず、ラボの build が `--features` で明示して渡すときだけ有効になります
- 割り当て器の比べ:2026-11-02 に測った値と所有者の決定は [割り当て器と libc の比べ](#割り当て器と-libc-の比べ) にあります。
  割り当て器は OS の標準のままで、丸めの係数はまだ測っていません

### 割り当て器と libc の比べ

この節は、所有者の決定 (2026-11-01、割り当て器は OS の標準と mimalloc を測ってから選ぶ) に従って測った値と、それを受けた所有者の決定 (2026-11-02) です。
決定は節の終わりの [決めたこと](#決めたこと) にあります。

#### datagram ごとの確保の所在

速さを制限しない経路の測定 ([割り当て器と libc](agent-throughput.md#割り当て器と-libc)) で、musl の build の CPU の大きな部分が datagram ごとの `calloc` と `free` でした。
この確保は sanstun の中ではなく、wgft の device の層 (`wgft-wireguard`) にあります。
sanstun のデータの経路は呼び手の buffer を使います。
`PendingDecapsulate::decrypt` は呼び手が渡す任意の buffer (`AsMut<[u8]>`) に復号し、`PendingEncapsulate::encrypt` は呼び手の slice に書きます。
`Interface::receive` はデータの message のヘッダを読むだけで、確保しません。
sanstun が確保するのは、ハンドシェイク、cookie の返事、keepalive の datagram (`Datagram` の `Box`) だけです。

device の層の確保は、データの packet 1 つにつき次のとおりです。

- 受ける向き:`Protocol::receive` の復号の buffer (`vec!` の零埋め) と、`Device::deliver` の平文の写し (`to_vec`)
- 送る向き:`Device::handle_packet` の packet の写し (`to_vec`) と、`Protocol::encapsulate` の datagram の buffer (`vec!` の零埋め)

駆動は、受けた packet を核に渡した後と、datagram を送った後に、その `Vec` を解放します。
核と `wgft-netstack` の handle の層は、packet ごとに確保しません。

#### 測った build

| 印 | target と libc | 割り当て器 | device の層 |
|---|---|---|---|
| C | `x86_64-unknown-linux-musl` (`cargo zigbuild`)、zig の同梱の libc | zig の `c.malloc` (`heap.SmpAllocator`) | 今の形 |
| A | `x86_64-unknown-linux-gnu.2.17` (`cargo zigbuild`)、glibc 2.17 以上に動的に結ぶ | glibc の `malloc` | 今の形 |
| B | C と同じ | mimalloc 3.3.2 (crate `mimalloc` 0.1.52、既定の feature) | 今の形 |
| D | C と同じ | 試作:OS の標準を包み、データプレーンのスレッドで解放した block を、全体で 8 個の枠に layout (大きさと整列) ごと持ち、layout のちょうど同じ確保にだけ返す。枠が埋まっていれば順に入れ替える | 今の形 |
| E | C と同じ | C と同じ | 試作:復号は device が持つ 1 つの buffer に行い、渡す packet と送る datagram の buffer は呼び手が返したものを使い回す |
| E+A | A と同じ | A と同じ | E と同じ |

ラボの今の build は C です。
C の libc は musl の名前の target ですが、`cargo zigbuild` は zig の同梱の libc を結び、`malloc` と `free` は zig の実装です。
B から E は測るための試作で、製品には入れていません。

E の使い回しは向きごとに 8 個までで、容量が MTU と 32 byte を超える buffer は持たずに解放します。
持つ量は 2 × 8 × (MTU + 32) byte で、最大の MTU (9216) で約 145 KiB の決まった項になります。
復号の buffer は最大の datagram の 64 KiB で、今の上界の device の項が数える「復号に使う datagram 1 つ分」と同じ大きさです。
渡す packet の buffer はどれも容量が MTU と 32 byte になり、送る datagram も buffer の容量で待ち行列の byte に数えます。
このため小さな packet でも 1 つを MTU と 32 byte に数え、byte の上限の内に入る件数が減ります。
既定の上限と MTU 1420 では、件数の上限 (256) が先に効くので変わりません。

#### byte あたりの CPU と速さ

`lab paired` の iperf3 で、速さを制限しない経路 (`fast`) を 1 stream、4 round × 3 回で流しました。
比は、最後の行を除いて C を分母にした値で、括弧は 95% の区間です。
区間は組を独立に引き直した bootstrap で、round の間の揺れのため、round を単位にした区間の約 0.7 倍の幅に狭く出ています ([round の間の揺れ](../userspace/wgstack-performance.md#round-の間の揺れ))。
CPU はエージェントのプロセスの byte あたりの CPU (`RATIO`)、速さは同じ組の速さの比 (`MBITRATIO`) です。

```sh
# 例:A と C。B、D、E は試作の commit を作業ツリーにし、--base に C の commit を渡します。
# WGFT_LAB_PAIR_CPUS は 2 台の VM を置く CPU の集合です (lab/README.md の「byte あたりの CPU を組にして比べる」)
WGFT_LAB_PAIR_CPUS="16-23 8-15" lab/lab paired --tool iperf3 --direction down|up \
  --rust-target x86_64-unknown-linux-gnu.2.17 --base <C> fast rust base:rust
```

| build | 送る向きの CPU | 送る向きの速さ | 受ける向きの CPU | 受ける向きの速さ |
|---|---|---|---|---|
| A (glibc) | 0.937 (0.928 から 0.954) | 1.054 (1.037 から 1.071) | 0.815 (0.810 から 0.821) | 1.203 (1.189 から 1.212) |
| B (mimalloc) | 0.979 (0.963 から 0.988) | 1.021 (1.007 から 1.036) | 0.935 (0.924 から 0.941) | 1.070 (1.050 から 1.087) |
| D (自前の置き場) | 0.978 (0.974 から 0.986) | 1.013 (1.006 から 1.025) | 0.929 (0.922 から 0.940) | 1.074 (1.053 から 1.092) |
| E (device の層の使い回し) | 0.944 (0.922 から 0.959) | 1.061 (1.034 から 1.080) | 0.856 (0.849 から 0.860) | 1.130 (1.115 から 1.150) |
| E+A を E で割った値 | 0.988 (0.978 から 0.996) | 1.009 (0.998 から 1.022) | 0.917 (0.910 から 0.926) | 1.077 (1.065 から 1.105) |

E+A と C の比は、E と C の比に E+A と E の比を掛けた見積もりで、送る向きの CPU が約 0.93、受ける向きの CPU が約 0.79 です。
直接は測っていません。
C の速さは送る向きで約 1.6 から 1.7 Gbit/s、受ける向きで約 4.2 Gbit/s でした。
E の送る向きは決まっていません。
round の中央値は、x を VM a に置いた round で 0.977 と 1.013、VM b に置いた round で 0.864 と 0.906 に分かれ、`vm_a_over_b` は 1.053 でした。
VM の側の差が比を左右しているので、E の送る向きは 0.9 から 1.0 の間とだけ言えます。

D の最初の版は、枠が埋まると入れ替えずに素通しにしたので、起動の時の大きさの block が 8 個の枠を埋めたまま、熱い大きさが入りませんでした (送る向き 1.015、受ける向き 1.014)。
表の値は、埋まった枠を順に入れ替える版の値です。

ホストで device の層だけを 1400 byte の packet で回した測り (P コア 1 個) では、packet あたりの時間は次のとおりでした。

| build | 受ける | 送る |
|---|---|---|
| C | 約 810 ns | 約 680 ns |
| D (すべて置き場から取れた) | 約 790 ns | 約 660 ns |
| C を glibc で | 約 650 ns | 約 540 ns |
| E | 約 625 ns | 約 495 ns |
| E を glibc で | 約 565 ns | 約 500 ns |

この測りでは、確保をすべて置き場から取っても 3% しか減りませんでした。
差の大部分は、`calloc` の零埋めと、写しの `memcpy` と `memset` の速さです。
E は零埋めと写し 1 回を除き、glibc はその上で `memcpy` が速いと考えます。
ラボの D が受ける向きで 7% 減ったのは、この測りより割り当て器の費用が大きいことを示しますが、理由は確かめていません。

#### メモリ

`lifecycle.sh kernel 5 5b` を `WGFT_LAB_RSS_PHASES=1` で流し、check 5 (UDP 4096、TCP 1024 の上限) の中でエージェントの RSS を段ごとに測りました。
段は、起動の後、エージェントが 512 MiB を受けた後、洪水の最中、TCP の洪水の接続が閉じた後、エージェントが 512 MiB を送った後、UDP のセッションが無通信の期限 (120 秒) で閉じた後です。
check 5 と 5b はどの build でも通りました。

| build | 起動の後 | 受けた後 | 洪水 | TCP の洪水の後 | 送った後 | UDP の期限の後 | VmHWM | 5b の洪水 |
|---|---|---|---|---|---|---|---|---|
| C | 26 | 26 | 69 | 76 | 76 | 96 | 98 | 107 |
| A | 27 | 28 | 62 | 66 | 66 | 67 | 67 | 92 |
| B | 51 | 51 | 93 | 97 | 90 | 97 | 97 | 129 |
| D | 26 | 26 | 70 | 76 | 76 | 94 | 96 | 107 |
| E | 26 | 26 | 70 | 77 | 77 | 94 | 95 | 110 |
| E+A | 28 | 28 | 63 | 67 | 67 | 68 | 68 | 91 |

値は MiB です。
起動の後から送った後までの段と 5b の洪水は 2 回ずつ測り (D と E+A は 1 回)、表は 2 回目の値です。
2 回の差は、段の値で 1 MiB 以内、5b の洪水で最大 6 MiB (C で 113 と 107、B で 123 と 129) でした。
UDP の期限の後と VmHWM は 1 回ずつの測りです。
B は起動の直後から 25 MiB 多く、上界の固定の基礎 (32 MiB) の見積もりの前提が崩れます。
どの build も、洪水の後に RSS を OS へ目立って返しませんでした。
zig の割り当て器の C、D、E は、UDP のセッションが閉じた後に RSS が 17 から 20 MiB 増えました。
glibc の A と E+A は同じ段で増えず、洪水の RSS も C より 6 から 16 MiB 少なくなりました。
起動の後は glibc の方が 1 から 2 MiB 多くなりました。
zig の割り当て器の増え方の理由は確かめていません。
5b の洪水はどの build も上界 (1972 MiB) と余裕の和を大きく下回りました。

#### 実行ファイルと配布

| build | 実行ファイル (strip 済み) | 配布の帰結 |
|---|---|---|
| C、D、E | 約 6.0 MiB | 静的。libc の無い環境と Alpine でも動きます |
| B | 約 6.1 MiB | 静的。mimalloc の C の source を zig の C の compiler で build します |
| A、E+A | 約 6.1 MiB | glibc 2.17 以上に動的に結びます (`libc.so.6`、`libpthread.so.0`、`libdl.so.2`)。2012 年以降の glibc の Linux で動き、musl の Linux (Alpine) と libc を持たないコンテナの image では動きません。名前の解決は glibc の `getaddrinfo` で、`/etc/nsswitch.conf` の module (mDNS など) に従います |

コンテナの image への影響は具体的です。
agent の image (`deploy/Dockerfile.agent`) は libc を持たない `gcr.io/distroless/static-debian12` の上にあります。
glibc の build にすると、glibc を持つ土台 (`gcr.io/distroless/base-debian12` か `cc-debian12`) に替え、image の大きさと Docker の手順の文書も変わります。

Windows と macOS は、どの案でも OS の標準の割り当て器 (`HeapAlloc` と libmalloc) を使います。
B を選べば、Windows と macOS も mimalloc に替わります。
E は OS によりません。

#### D の評価

D は動き、Miri の試験も通りましたが、採用を勧めません。

- 正しさ:置き場の block はすべて OS の標準の割り当て器が同じ layout で確保したもので、返すときも同じ layout で渡します。
  大きさを丸めないので、ほかの確保の大きさは変わりません。
  ほかのスレッドが確保した block を解放しても、その layout のまま置き場に入るだけです。
  零埋めの確保は、置き場から取った block を `memset` します。
  `realloc` はそのまま渡します
- スレッドの終わり:スレッドの局所の値は const の初期化で `Drop` を持たず、確保の中で読んでも確保しません。
  後始末はデータプレーンのスレッドの関数が持つ guard が行い、guard を落とすと置き場を OS の標準に返します
- 上界:持つ量は 8 × 9280 byte (73 KiB) を超えず、決まった項として数えられます
- 危険:unsafe の `GlobalAlloc` を製品に入れます。
  置き場の block は sanitizer から見ると確保されたままなので、AddressSanitizer は置き場を通る解放の後の使用を見逃します。
  glibc の tcache のような二重解放の検査もありません。
  OS ごとの違いはスレッドの局所の値だけで、Windows と macOS では試していません
- 検証に要るもの:Miri の試験 (layout の一致、スレッドをまたぐ解放、入れ替え、guard の後始末)、乱数の確保と解放の列の性質の試験、sanitizer の build で置き場を切る設定、lab の一式です。
  今は Miri の試験だけを試作の中で流しました
- 効果:E は datagram ごとの確保そのものを除くので、E の後の D は置き場に入れるものがほとんどありません。
  E の後に D を重ねた値は測っていません

#### 決めたこと

所有者が 2026-11-02 に次のとおり決めました。

1. device の層を E の形にします。
   復号は device が持つ 1 つの buffer に行い、渡す packet と送る datagram の buffer は呼び手が返したものを向きごとに 8 個まで使い回します。
   使い回しの量 2 × 8 × (MTU + 32) byte を上界の device の項に足します。
   unsafe も依存も増やさずに、C に対して受ける向きの CPU を 14% 減らしました。
   送る向きは 0.9 から 1.0 の間で、決まっていません。
   buffer はバッチの段が持つので、実装はバッチの段と一緒に入れます。
   バッチの段では、使い回しの数を 1 回のまとめの深さに合わせ、項は 2 × (まとめの深さ) × (MTU + 32) byte になります。
   E の効果はバッチの無い形で測った値で、[バッチで減らせる分の見積もり](agent-throughput.md#バッチで減らせる分の見積もり)の `malloc` と `free` の行 (送る向き 6.1%、受ける向き 14.6%) に当たります
2. 割り当て器は OS の標準のままにし、mimalloc と自前の割り当て器 (D) は採りません。
   mimalloc は起動の後の RSS が 25 MiB 増え、効果は E より小さいためです。
   D は unsafe を製品に入れる割に、効果が E より小さく、E の後に残る効果は小さいためです
3. Linux の build は、今は musl の静的な build (C の target) のままにします。
   glibc に動的に結ぶ build (`x86_64-unknown-linux-gnu.2.17` と aarch64 の同じ形) は、バッチの段で写しを減らした後に、残る差を測り直してから決めます。
   今の測りでは、E の後も glibc の build は受ける向きの CPU が 8% 少なく、速さが 8% 高くなりました。
   メモリは起動の後に 1 から 2 MiB 多く、洪水の後は C より少なく、UDP のセッションが閉じた後に RSS が増える C の振る舞いもありません。
   差の大部分は `memcpy` と `memset` の速さで、バッチの段で写しが減ると差も変わる見込みです。
   glibc の build は、静的な 1 つのファイルで musl の Linux と libc を持たない image でも動く、という性質を失い、agent の image の土台も替わります ([実行ファイルと配布](#実行ファイルと配布))。
   後で glibc に替える場合は、バッチの段の目標の基準の値 ([目標](agent-throughput.md#目標)) を測り直し、目標を導き直します。
   替える前に、E+A と C の UDP の往復の遅れ (`--udp-ping`) を測ります

まだ確かめていないことは次のとおりです。

- E+A と C を直接比べた値。表の値は掛け合わせた見積もりです
- どの build の UDP の往復の遅れ (`--udp-ping`) も測っていません
- glibc の build は glibc 2.41 (ラボの Debian 13) の上でだけ動かしました。2.41 より古い glibc の上では動かしていません
- glibc の build で、NSS の module が名前の解決に使うメモリが、上界の名前の解決の項 (スレッドごとに `getaddrinfo` の作業の 64 KiB) に収まること
- glibc の `malloc` の arena が、長く動かした間に育つ量
- mimalloc は既定の設定 (`MIMALLOC_*` の環境変数を付けない) でだけ測りました
- libc か割り当て器を替えた後の、上界の固定の基礎 (32 MiB) の測り直し
- aarch64、Windows、macOS

### 上界の表の生成

決定に従い、上界の表は `Bound` から生成します。

`wgft-wgstack` の試験 `bound::tests::bound_table_is_up_to_date` が、既定の設定と代表の K の値で `Bound` を計算し、項ごとの表を [wgstack の Rust 版の上界の表](wgstack-bound.md) に書き出します。
環境変数 `WGFT_UPDATE_GOLDEN=1` を付けたときだけファイルを書き直し、付けないときは差があれば失敗します。
Go の `-update` の形に当たります。
試験は文書の印の間だけを書き直し、行の説明は手で書いた部分が持ちます。
この文書は生成した表を参照し、手で数を書きません。
項は確保した配列の要求の大きさで数えます。
別の試験が、作った核の表の `capacity()` から数えた byte が固定の項と一致することと、枠をすべて使い boost の枠をすべて貸してどの輪も満たした核の保持が、chunk、記録の輪、区間の表の項ごとに上界と一致することを確かめます。
型の大きさは試験の build でも製品の build と同じに保ちます。
試験だけの欄を型に足さないのはこのためで、確保の失敗の注入は型の外に置きます。
Linux、Windows、macOS の CI で同じ表になることを確かめました。
核の値の大きさは hook の無い核で数え、`Stack::bound` は使う hook の核の大きさで数えます。

### 需要で育つバッファとの関係

[需要で育つバッファ](../userspace/wgstack-buffers.md)は採用済みですが、凍結した Go の wgstack にはありません。

Rust の wgstack は Go と同じ floor と boost の枠の模型で書き、Go の記録との bit の一致を確かめます。
提案:需要で育つバッファは、bit の一致を求める期間が終わった後に、Rust だけに入れます。
`Budget` の型は、boost の枠の集まりと、予算 G から段を借りる形の両方を表せるように作ります。
段を移す手順の「chunk の位置を割り当て直す」規則は、Rust の輪でも同じに書けます。

## agent での使い方

### packet の流れ

agent では packet は次のように流れます。

- 受信:UDP のソケット、`Device::handle_datagram`、`Device::poll_packet`、核の `handle_packet`
- 送信:核の `poll_transmit`、`Device::handle_packet`、`Device::poll_transmit`、UDP のソケット
- アプリケーション:中継の task が `wgft-netstack` の handle を読み書きし、LAN の宛先へは OS のソケットで接続します

TUN も、トンネルのアドレスの経路も、専用の経路表と rule も要りません。
agent はどの OS でも利用者の権限で動き、Go の v1 のユーザー空間モードと同じ形です。
核は OS に依らないので、Windows と macOS でも同じ形で動きます。
CI はこの 2 つの OS で build と単体の試験を流しますが、実機での動作は未確認です。

device の層の `poll_packet` は packet ごとに `Vec` を確保して返し、agent はこの形のまま使います。
device の層に呼び手の buffer へ書く口を足すかは、CPU を測ってから決めます。
送信の向きも同じです。

### 入口の検査

TUN で packet をホストのカーネルに渡す形では、カーネルがホストのサービスと LAN に packet を渡さないよう、agent が入口で検査を要します。
wgstack では packet が核の中で終わり、転送の経路も、中継が開いていないポートの待ち受けもありません。
このため入口の検査は核の規則が受け持ち、agent は別の検査の module を持ちません。
規則の正本は[トンネルの入口の検査](../spec/tunnel.md#トンネルの入口の検査)です。
TUN を使う形で要る守りと、wgstack での扱いの対応は次のとおりです。

| TUN を使う形の検査と守り | wgstack での扱い |
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

TUN を使う形で UDP、echo request、断片を捨てるのは、カーネルにホストの応答を作らせないためです。
wgstack はそれらを自分で扱うので、[トンネルの中の約束](../spec/tunnel.md)の v1 の挙動に従います。

### 設定の扱い

- `WGFT_AGENT_NETSTACK`:決定どおり、`gvisor` と `wgstack` を受け付け、どちらでも Rust の wgstack で動かします。
  `gvisor` のときは使わない旨を英語の 1 行で出します
- `WGFT_MAX_TCP_FLOWS`:Go と同じく K として受け取り、接続の枠の数 N_c = K + Q を導きます
- `WGFT_AGENT_BATCH_MIB`:仕様は、受け付ける値の集合と誤りの文面を Go と同じにし、値から何を導くかは実装の送信の経路で決めるとしています ([WGFT_AGENT_BATCH_MIB](../spec/cli-config.md#wgft_agent_batch_mib))。
  提案:値は 1 回の起床で作る packet の数の上限に使い、`0` は 1 件ずつ送ることにします。
  導く式は送信の経路を測ってから決めます

## 待ち受けの守り

凍結した Go の wgstack と意図して違う所のうち、待ち受けへの入力の扱いをここに書きます。
どちらも記録との bit の一致から外れる所です。
外れる記録は、意図した違いの一覧 (`testdata/wgstack-rec/divergences.json`) に理由と共に載せます。

### SYN cookie

決定:Rust の wgstack は RFC 4987 の SYN cookie を持ちます (2026-11-01)。
凍結した Go の wgstack は持たないので、Go と意図して違う所です。
Go の設計は、SYN cookie の要否を既定を gVisor から替える前に決める点としていました ([後の段階の機能](../userspace/wgstack.md#後の段階の機能))。

理由:server のカーネルモードでは、DNAT と MASQUERADE を経て、インターネットの任意の相手の SYN が agent の wgstack に届きます。
握手の途中の行は待ち受け 1 つで N_syn の半分 (既定で 512 行) までで、1 つの行は SYN-ACK の再送を終えるまで約 63 秒残ります。
このため、待ち受け 1 つに毎秒 8 程度の偽の SYN を送るだけで、その待ち受けへの新しい握手がすべて断られます。
今の Go の agent の既定の gVisor は SYN cookie を持ちます。

#### 使う時

待ち受けへの SYN に行を作れない時だけ、cookie で応えます。
待ち受けが握手の途中の表の自分の分 (N_syn の半分) を使い切った時と、表の全体が満杯の時です。
表の全体が満杯の時も含めるのは、ほかの待ち受けへの洪水で表が埋まった時にも新しい握手を通すためです。
表に空きがある間は今までどおり行を作り、Go と同じ packet を返します。

accept の待ち行列の枠 (待ち受けの分と全体の Q) か空きの接続の枠も尽きている時は、cookie で応えずに SYN を捨てて `syn_accept_full` を数えます (`LogKind::SynAcceptFull`)。
cookie で応えても、最後の ACK はその満杯の待ち行列に届きます。
SYN を捨てれば相手の側の接続はまだ開いておらず、相手は SYN を送り直し、その時に空きがあれば握手を終えます。
表に行を作れる時は、待ち行列が満杯でも今までどおり行を作ります。

TIME_WAIT の 4 つ組を使い直す SYN には cookie で応えず、今までどおり SYN を捨てて TIME_WAIT を残します。
cookie の ISN は、前の接続の SND.NXT より先に置けないためです。

cookie の SYN-ACK は制御の輪から送ります。
SYN ごとに行も接続の枠も使わず、何も確保しません。
制御の輪が満杯なら SYN-ACK を捨てて `ctl_dropped` を数え、相手の SYN の再送を待ちます。
SYN-ACK を再送しないことも行と違う点で、相手が再送した SYN には新しい cookie で応えます。

#### 符号化

- 鍵:SipHash-2-4 の 128 bit の鍵です。
  核を作る時に、ISN の鍵から用途の印で導きます。
  核はトンネルの世代ごとに OS の乱数の種で作り直すので、鍵も世代ごとに替わります。
  乱数の生成器から引かないので、Go と同じ乱数の列を保ちます
- 時刻の数:30 秒ごとに 1 進む数です。
  cookie は作った数とその次の数の間だけ通るので、寿命は 30 秒以上 60 秒未満です
- ISN の 32 bit:上位から MAC の 27 bit、時刻の数の下位 2 bit、MSS の表の番号の 3 bit です。
  MAC は 4 つ組、相手の ISN、時刻の数、相手の option (MSS の番号、timestamp の有無、窓の scale、SACK の許可) を覆います
- MSS の表:536、1200、1280、1340、1380、1400、1440、1460 の 8 つで、相手の MSS 以下で最も大きい値を選びます。
  相手が示した値との差は、送る segment が小さくなる分だけです
- timestamp:SYN が timestamp を持つ時は、SYN-ACK の TSval の下位 5 bit に窓の scale (無ければ 15) と SACK の許可を入れます。
  最後の ACK の TSecr からその値を取り戻し、MAC で確かめます。
  入れた後の値が時計の値を超える時は、1 つ下の 32 ms の区切りに入れます。
  SYN-ACK の TSval が後の segment の TSval (時計の値) を超えると、相手の PAWS が後の segment を古いとみなして捨てるためです。
  このため TSval は時計より最大 63 ms 小さくなり、cookie の接続は最後の ACK の TSecr を RTT の標本にしません
- ECN:wgstack は ECN を持たないので運びません

#### 確かめ

どの行にも当たらず、SYN と RST を持たない待ち受けへの ACK を cookie として確かめます。
確認番号から 1 を引いた値を自分の ISN、番号から 1 を引いた値を相手の ISN とし、時刻の数の差が 0 か 1 で MAC が合えば通します。
通れば行を経ずに接続を作って accept の待ち行列に入れ、ACK が運んだデータと FIN を処理します。
accept の待ち行列の枠 (待ち受けの分と全体の Q) と空きの接続の枠は、行の最後の ACK と同じ規則で予約します。
予約できない時の扱いは [待ち行列が満杯の時の cookie の接続](#待ち行列が満杯の時の-cookie-の接続) で述べます。
通らない ACK のうち中身も FIN も持たないものは、今までどおりどの行にも当たらない segment として RST を受けます。
中身か FIN を持つ ACK は、RST を返さずに捨てます。
最後の ACK と最初の中身を失った相手の次の segment は、番号が相手の ISN の次でないので cookie が通りません。
RST で切らずに捨てれば、相手は最初の中身を送り直し、その segment で cookie が通ります。

握手の途中の行に当たる ACK の確認番号が行の ISN に合わない時も、cookie を送る窓の内なら RST の前に cookie として確かめます。
cookie の SYN-ACK が遅れる間に相手が SYN を送り直し、その時に表に空きがあれば、送り直した SYN が行を作ります。
その後に相手が遅れて届いた cookie の SYN-ACK に応えると、ACK は行の ISN に合いません。
cookie が通れば cookie の値で接続を作って行を外し、通らなければ今までどおり RST を返します。

確かめるのは、最後に cookie を送った時刻の数との差が 1 以下の間だけです。
洪水の無い時は ACK の扱いが Go と同じで、偽の ACK で MAC を総当たりする機会もありません。

数は `Stats` の `syn_cookies_sent`、`syn_cookies_accepted`、`syn_cookies_rejected`、`syn_cookies_deferred`、`syn_cookies_reset` です。
`syn_cookies_rejected` は、確かめた上で通らなかった ACK だけを数えます。
`syn_cookies_accepted` は、cookie の値の行から後で作った接続も数えます。
cookie で応えた SYN は `syn_table_full` に数えません。
送った数は 1 分に 1 回までの門を通り、駆動の層が SYN の洪水の疑いとしてログに出します (`LogKind::SynCookies`)。

#### 待ち行列が満杯の時の cookie の接続

cookie には固有の限界があります。
RFC 4987 の 3.6 節は、握手を終える ACK が失われると、受ける側のアプリケーションは接続を知らないまま、始めた側は接続ができたと思い込むことを述べています。
受ける側が先に話す protocol では、始めた側は届かない最初の中身を待ち続け、自分の timeout まで止まります。
例は SMTP、FTP、IMAP、POP、MySQL、VNC です。
SSH は始めた側も版の文字列を先に送るので、ACK を失っても次の segment で cookie が通ります。
最後の ACK はネットワークの中で失われうるので、この限界は cookie を使う限り残ります。
wgstack は、待ち受けの分か表の全体が満杯の時だけ cookie を使うので ([使う時](#使う時))、この限界にさらされるのは洪水か握手の集中の間だけです。

cookie が通った最後の ACK を wgstack 自身が捨てると、ネットワークで失われるのと同じ結果を自分で作ります。
accept の待ち行列か接続の枠が満杯の時も、wgstack はこの ACK を黙って捨てず、次のように扱います。

- 表の全体に空きがあれば、cookie から取り戻した値 (ISN、相手の ISN、MSS、窓の scale、SACK の許可、timestamp の offset と TS.Recent、広告した窓) で握手の途中の行を作り、`syn_cookies_deferred` を数えます。
  RFC 9293 の SYN-RECEIVED の回復を取り戻すためで、行は SYN-ACK を最初の再送の期限 (1 秒後) から再送します ([cookie の値の行](#cookie-の値の行))。
  接続を開いた相手は、自分の受ける番号より前の SYN-ACK の写しに ACK を返します (RFC 9293 3.10.7.4)。
  その ACK は行に当たり、待ち行列に空きがあれば行の最後の ACK と同じく接続を作ります。
  この回復を実際の相手 (Linux のカーネルの TCP、server の gVisor) で確かめていません。
  ラボの一式はこの経路に届かず、核の単体の試験だけが通ります
- 待ち受けの分は見ません。
  cookie を使うのはその分が満杯の時なので、分を守るとほぼすべてが次の RST になります。
  この行を作れるのは cookie を通した相手、つまり握手を終えた相手だけで、経路の外から表を埋めることはできません。
  ほかの待ち受けの行の空きは減りますが、表の全体の大きさは変わらず、`Bound` の表の項も変わりません
- 同じ 4 つ組の行が既にあれば (cookie の SYN-ACK が遅れる間に相手が SYN を送り直した場合)、相手の知らない ISN を持つその行を外し、cookie の値の行に替えます
- 表も満杯なら、中身も FIN も持たない ACK に RST を返し、`syn_cookies_reset` を数えます。
  相手は待ち続けずに、接続を断られたことをすぐに知ります
- 表も満杯で、ACK が中身か FIN を持つ時は、RST を返さずに捨てます。
  相手はその中身を送り直すので、その時にもう一度 cookie を確かめます。
  確かめる窓が閉じた後の再送は、どの行にも当たらない segment として RST を受けます

#### cookie の値の行

cookie の値の行は、行を作った時刻から普通の行と同じ予定で SYN-ACK を再送します。
1 秒後に最初の再送をし、間隔を倍にしながら再送を使い切るまで続けます。
最初の SYN は cookie で応えたので、行には SYN からの再送の履歴が無く、回数は行を作った時から数えます。
間隔は 1 秒以上で、確立した相手が SYN-ACK の写しに返す ACK の速さの制限 (Linux では 1 つの接続に 500 ms に 1 回) より長くなります。

再送する SYN-ACK は cookie の ISN と、cookie から取り戻した option を繰り返します。
行が持てるのは cookie が運ぶものだけです。
MSS は表の値に丸め、窓の scale と SACK の許可は相手が timestamp を示した時だけ持ちます。
TSval は今の時計の値で、cookie の SYN-ACK の値 (下位の bit を option に替えた値) 以上なので、相手の PAWS は SYN-ACK の写しを古いとみなしません。

行は、確認番号が自分の ISN の次で、番号が窓の内にある segment をすべて受けます。
相手は確立した後に中身を送っていることがあり、その中身はこちらが捨てたので、相手の次の番号は相手の ISN の次より先にあります。
最初の中身は相手の再送で届きます。

相手は握手を終えて接続を開いたと思っているので、cookie の値の行は再送を使い切ったら黙って消さずに RST を送り、`syn_cookies_reset` を数えます。
RST は行の出力で送り、送った時に行を外すので、制御の輪が満杯でも失いません。
普通の行は、最後の ACK を待ち行列が満杯で捨てた後も、今までどおり期限で黙って消します。
凍結した Go の wgstack と記録が一致する所で、Go の記録には待ち行列が溢れた後に期限で消える行が含まれます。

残る失い方は、表が満杯の時に返す RST を制御の輪が満杯で捨てる場合です。
この RST は状態を持たないので送り直せず、`ctl_dropped` に数えます。
実際の負荷で起こるかは確かめていません。

#### Linux との違い

Linux は、accept の待ち行列が満杯の時に cookie が通った ACK を捨て、何も残しません。
RST も SYN-ACK も送らず、`tcp_abort_on_overflow` の値も見ません。
このため受ける側が先に話す protocol の相手は、Linux の相手でも待ち続けます。
wgstack は Linux と違い、cookie の接続も、Linux が普通の要求の行に行うのと同じ方法 (行を残し、SYN-ACK を再送し、後の正しい segment で接続を作る) で回復します。

表も満杯の時の RST は、Linux の既定 (`tcp_abort_on_overflow` が 0) と違い、1 の時の挙動に当たります。
Linux の既定の黙って捨てる扱いは、相手が先に送る protocol なら相手の再送で短い集中を乗り切れますが、受ける側が先に話す相手は待ち続けます。
wgstack は相手を待たせないことを選び、中身の無い ACK には RST を返します。
中身か FIN を持つ ACK は捨てて相手の再送を待つので、相手が先に送る protocol は Linux の既定と同じく乗り切れます。

次の点は Linux と同じです。

- accept の待ち行列が満杯の間は、cookie を使う状況でも SYN を捨てます
- ACK を cookie として確かめるのは、cookie を送った後の窓の内だけです

Linux の待ち行列の大きさの比べ方は「上限を超えたら満杯」で、実際に入る数は上限より 1 つ多くなります。
wgstack は「上限に達したら満杯」で、入る数は上限と同じです。
1 つの差は挙動の性質を変えません。

#### timestamp の無い相手で失うもの

SYN が timestamp を持たない相手には、cookie の SYN-ACK で窓の scale と SACK の許可を示しません。
ISN には option を入れる bit が残らないためで、RFC 4987 と gVisor の扱いと同じです。
この相手との接続は、窓が 64 KiB までに限られ、SACK による回復を使いません。
どの相手でも MSS は表の 8 つの値に丸めます。
表に空きがある時の握手は、今までどおりすべての option を使います。

#### 安全の性質

- 偽造:経路の外の相手が cookie を通すには MAC の 27 bit を当てる必要があり、1 回の推測が通る確率は 2^-27 です。
  相手の ISN、MSS の番号、TSecr の option の bit は偽る側が選べ、時刻の数の 2 bit は自分の SYN への cookie から読めるので、残るのは MAC だけです。
  確かめる窓の外では推測を受け付けませんが、偽る側は待ち受け 1 つに毎秒 8 程度の偽の SYN で窓を開け続けられます。
  偽の接続 1 つに要る ACK は平均で約 1.34 × 10^8 で、毎秒 100 万の packet で約 2.2 分、10 万で約 22 分、1 万で約 3.7 時間です。
  通らない ACK のうち中身の無いものには RST を 1 つずつ返すだけで、増幅はありません。
  偽った接続は、偽った送信元のアドレスからの片道の接続で、相手は wgstack が返す segment を見られません。
  期限で切れるまで accept の枠を 1 つ使い、中継はその中身を LAN に届けるので、送信元のアドレスを信じる LAN の側のサービスは欺かれえます。
  比べると、行の握手を経路の外から偽るには ISN の 32 bit を当てる必要があり、確率は 2^-32 です
- 期限:時刻の数を MAC が覆うので、60 秒を過ぎた cookie は通りません。
  ISN は時刻の数の下位 2 bit だけを持つので、4 周期の倍の後の写しは差が 0 か 1 に見えますが、MAC が合いません
- 書き換え:MSS の番号、窓の scale、SACK の許可、timestamp の有無を MAC が覆うので、ACK で書き換えた値は通りません。
  相手の ISN も覆うので、最初の segment が失われた後のデータの segment は通らず、捨てられます。
  通すと、失われた中身を飛ばして受け取るためです
- 写し:cookie の寿命 (60 秒未満) は TIME_WAIT の長さ (60 秒) 以下です。
  自分から閉じて TIME_WAIT を経た接続では、最後の ACK の写しは cookie が通る間ずっと TIME_WAIT の行に当たり、新しい接続を作りません。
  相手から閉じた接続、RST か abort で閉じた接続、追い出された TIME_WAIT の行では、寿命の内の写しが新しい接続を作りえます。
  写しを送れるのは経路の上で ACK を見た相手だけで、その相手は cookie が無くても握手を偽れます。
  悪意の無い写しもありえます。
  ネットワークが最初の中身の segment を複製して遅れて届けると、閉じた後でも寿命の内なら cookie が通り、相手の知らない接続ができて、同じ要求が 2 度届きます。
  これは cookie を送る窓の内、つまり洪水の間だけ起こります
- 保持:cookie の SYN は何も確保せず、行も持ちません。
  cookie の値の行は握手の途中の表の行で、表の大きさの内にあります。
  cookie の接続は、行からの接続と同じく accept の待ち行列と接続の枠の上限の内にあり、`Held` の項と、`Bound` の表と枠の項は変わりません。
  核の値に鍵、最後に送った時刻、数、ログの門が加わり、`Bound` の `stack` の項が 144 byte 増えました
- CPU:cookie で応える SYN と確かめる ACK は、それぞれ MAC の 24 byte の SipHash-2-4 を 1 回計算します。
  相手が timestamp を示した時は、timestamp の offset の 16 byte の SipHash-2-4 も 1 回計算します

#### Go の記録との違い

握手の途中の表を満たす記録は、cookie の SYN-ACK を返す所から Go と違います。
今の記録の集まりには、待ち受けの分を満たす記録がありません。
`fuzzcore` の記録は相手のポートが 8 つで待ち受けの分 (`fuzz_limits` で 8 行) を超えず、ほかの記録は 1 つか少数の接続です。
このため cookie を入れた後も、git の記録と手元の cache の大きな記録の集まりのすべてが Go と一致し、意図した違いの一覧に行はありません。
洪水を含む記録を足した時は、cookie の SYN-ACK から違うので、その記録を意図した違いの一覧に載せます。
cookie の値の行と、満杯の待ち行列の前で SYN を捨てる扱いも cookie を使う時だけ働くので、今の記録はすべて Go と一致します。

### 待ち受けへの SYN と FIN の組

Rust の wgstack は、待ち受けへの SYN と FIN を両方持つ segment を捨てます。
凍結した Go の wgstack はこの segment にも握手の途中の行を作り、理由を付けて受け入れていました ([未確認の点と未決の点](../userspace/wgstack.md#未確認の点と未決の点))。
SYN と FIN の組は正しい相手が送らない組で、受け入れると表の行を使い、表が満杯の時は cookie で応えることになるためです。
TIME_WAIT の 4 つ組への組も、TIME_WAIT を外さずに、使い直せない SYN と同じく速さを抑えた ACK を返します。
閉じたポートへの組には、今までどおり RST を返します。
今の記録の集まりにこの組を待ち受けに送る記録は無く、どの記録も Go と一致します。

## 置き換えの判定

仮の決定 (所有者の確認を待ちます):Rust の agent が Go の agent を置き換えられると判定する条件は、次の 2 つです。

- ラボの一式の agent の確認が、Rust の agent で server の両方のモードを通ること ([agent の置き換えの設計の完成の条件](agent-parity.md#範囲と完成の条件))
- qbench の cell が、凍結した Go の wgstack と同じく正しさの判定 (byte の列の一致と、接続が誤りなく終わること) を通ること

[目標と制約](../userspace/wgstack-performance.md#目標と制約)の性能の目標 (byte あたりの CPU が gVisor の 0.6 倍以下、スループットが Linux の 0.9 倍以上など) は置き換えの条件に入れません。
置き換えの後に測り、性能の段階として追います。
Linux の `sendmmsg` と UDP の GSO のような system call のまとめも、置き換えの後に回します。

qbench の条件は関門の表で確かめました ([qbench での測定](#qbench-での測定))。

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

### 試験の担当の仕事

試験の担当は、[試験の道具の設計](test-tooling.md)の道具に加えて、次のことを受け持ちます。

- 故障の一覧を書き、実装の担当が書いた故障の点で台本の検出力を確かめます
- 期待した差の一覧と意図した違いの一覧に行を足すときは、理由を書きます

試験の担当は Rust の wgstack の実装のコードを読まず、公開の API の文書だけを読みます。
実装の担当は試験の担当の台本と runner を直しません。
台本が誤っていると考えたら、理由を書いて試験の担当に返します。
Go の試験の道具を変えるときは、製品の Go のコードを変えず、規則どおり wgstack の関門を流します。

### Go の wgstack の記録との bit の一致

決定に従い、移行の間は凍結した Go の wgstack の記録と照らします。
記録の作り方、形式、印による段ごとの照合、意図した違いの一覧は[試験の道具の設計の記録](test-tooling.md#4-go-の-wgstack-の記録)に従います。
この文書が決めるのは、Rust の核が守る条件と、照らす範囲です。

- 比べる応答:引き取った packet の bytes と順序、アプリケーションの操作の結果、受け入れの結果、時刻です。
  `STATS`、`BOUND`、`HELD` の応答は byte の単位で比べません。
  Go と Rust で数の内訳と型の大きさが同じになる理由が無いためです
- 段ごとの照合:核の機能を段に分け、段ごとの印の記録を照らします。
  4b の段は、相手が SACK も timestamp も示さず、輻輳の制御に NewReno を、boost の与え方に boost を求めない方針 (Go の `BoostNever`) を選んだ記録を、握手の後のデータの転送まで照らします。
  受信の窓の自動調整と受け手の ACK の規則が 4b の段に入るのはこのためです。
  5 の段は SACK、timestamp、CUBIC、boost の印の記録を、6 の段は UDP と ICMP と断片と ping の印の記録を加えます
- 段の表:核に入った段は `crates/wgft-wgstack-dut/stages.json` の `landed` が持ち、今はすべての段が入っています。
  段を足すときは `landed` にその段を足し、その段の印の記録が一致することと、その段の台本が通ることを同じ変更で確かめます
- 前の条件:すべての記録が一致することを、agent の置き換えをラボの一式で判定することの前の条件にします

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
  `tcp::cc::cbrt` が Go の実装を写します ([回復と輻輳の制御と boost で決めたこと](#回復と輻輳の制御と-boost-で決めたこと))
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
| `FuzzCore` | `core` | 試験の担当 | `internal/wgstack/testdata/fuzz/FuzzCore` の corpus の値。`go test fuzz v1` の形式から Go の試験 `TestRustFuzzSeeds` が取り出します |
| `FuzzAdversarialSender` | `adversarial_sender` | 試験の担当 | 64 bit の種 |
| (無し) | `replay` | 試験の担当 | 記録の要求の列 |
| (無し) | `raw_adversary` | 実装の担当 | 決まった種から作った長い入力 (example の `raw_seeds`) |

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
`core`、`adversarial_sender`、`replay` の本体の置き場、入力の形、seed の書き出し、測った速さと関門の回数は、[試験の道具の設計の fuzz](test-tooling.md#6-fuzz) が持ちます。

### 上界と敵対的な保持の試験

[敵対的な保持の試験](../userspace/wgstack-verification.md#敵対的な保持の試験)の表の入力をすべて Rust に移します。
確かめることは同じで、生きているヒープの代わりに確保の数えで測ります。

表の入力のうち `crates/wgft-wgstack-dut/tests/holding.rs` が持つのは、偽の送信元からの SYN の洪水、`accept` されない接続、短い接続の入れ替わり、中身の無い segment の洪水 (重複した ACK と 1 byte ずつ進む ACK)、順序外の洪水、読まない相手、どの接続にも当たらない segment の洪水、遅い読み手への小さな書き込み、出力の詰まりです。
保持は設定の上限でなく、実際に持つ量で確かめます。

- 確保の数え:核を作った後に増えた生きている byte が、`Held` の文書の式 (chunk、送信の記録、区間の表、再組み立ての写し、UDP の chunk、置き場の chunk の byte の和から、借りている boost の配列の byte を引いた値) にちょうど一致すること。
  boost の枠を借りた接続がある間も、同じ式で照らします
- 核を閉じた後に、生きている byte が核を作る前の値へ戻ること。生きている byte と最大値が `Bound` の内にあること
- 入力ごとの確かめ:洪水の間に生きている byte が増えないこと、表の行が表の大きさと待ち受けごとの上限の内にあること、上限で捨てた数が数えられること、入力が止まった後に表が空に戻ること

確かめの中で分かったこと:接続が終わった後も、核は空いた接続の枠の floor の送信の記録の輪と区間の表と、置き場の chunk を持ち続けます。
どれも `Held` に出ていて上界の項の内にあり、核を閉じると元の値に戻ります。
SACK の block を持つ ACK の洪水、需要の無いまま boost の枠を持つ接続 (確立から 1 秒の内は返さず、1 秒を過ぎると返すこと)、断片の洪水 (項目の数の上限と byte の上限のそれぞれ)、読まない UDP の endpoint への洪水 (endpoint の数と byte の上限と、核の全体の予算) も持ちます。
確保の数えと会計の一致には UDP の chunk の byte を含めます。

表の入力のうち、次のものはまだ移していません。

- 需要の無いまま boost の枠を持つ接続のうち、黙った相手が古い窓へ送ったデータが捨てられて再送されることと、floor の外に順序外のデータを残して黙った保有者の枠が返り、そのデータが取り消されて (`boost_reneged_bytes`) 再送されること
- floor に戻った保有者への送信の再開と、その後の読み手の停止 (Windows の再送の回数を超える長さ)
- stream の一致の試験 (受信と送信)
stream の一致の試験 (受信と送信) も、種の数を含めて移します。
Go の `-race` の競合の試験は、核が錠を持たないので移しません。
代わりに、`wgft-netstack` の試験で、多くの接続の読み書き、`close`、`abort`、待ち受けの `close`、核の作り直しを同時に動かし、waker の表と核の会計が閉じた後に空に戻ることを確かめます。

### 故障の注入と目印の build

故障の注入と、置き場に返す chunk を目印の byte で埋める build は、cargo の feature ではなく `--cfg` で選びます。

- 選び方:`RUSTFLAGS` で `--cfg wgstack_fault="<名前>"` と `--cfg wgstack_sentinel` を渡します。
  feature はワークスペースの中で合わさり、製品の build に漏れうるためです
- 宣言:ワークスペースの `[workspace.lints.rust]` の `unexpected_cfgs` の `check-cfg` に 2 つの cfg を宣言し、source の中の `#[cfg(...)]` の名前と値の綴りの誤りを lint で捉えます。
  `RUSTFLAGS` で渡した `--cfg` の綴りの誤りは lint では捉えられないので、故障を入れた build の試験が、その故障を捉えるはずの確かめが落ちることで確かめます。
  `wgstack_fault` の値の一覧は、故障の点を足すときに足します。
  それまでは値を持たない宣言で、source の中で値を書くと lint が捉えます
  cargo は crate の `[lints]` に `workspace = true` とほかの項目を併せて書けないので、crate ごとには宣言しません。
  名前が `wgstack_` で始まるので、ほかの crate に宣言が効いても害はありません。
  cargo-fuzz が付ける `fuzzing` も同じ所で宣言します
- 製品:リリースの build と B13 の通常の build はこの cfg を渡しません。
  `wgft` のバイナリの依存の木の検査 ([依存と隔離の検査](#依存と隔離の検査)) と合わせ、製品にどちらも入らないことを CI で確かめます
- 目印の確かめ:目印の build で、目印が読み取り、送る segment、記録と区間の欄の値に現れないことを、stream の一致の試験、敵対的な送り手の試験、`core` の fuzz で確かめます
- 故障の置き場と一覧:核の故障は核の crate に置き、adapter の側には作りません。
  理由と故障の一覧 (どの確かめが落ちるはずか) は[試験の道具の設計の関門](test-tooling.md#pr-の関門)にあります

### 関門と CI

[試験の道具の設計の関門と CI](test-tooling.md#7-関門と-ci)の選択を採ります。

- PR の関門:`scripts/wgstack-gate.sh` が Rust の段 (台本と記録の照合、fuzz の smoke) を流します。
  別の script にはしません。
  `wgstack-dut` に対する `rustdut` の適合の台本はまだ関門にありません
- CI:cargo と Go の両方を要する照合の段は job `harness-rust-go` (B16) です。
  この job は Go の試験を流すので、Rust だけの job (`rust-*`) と分け、`rust-` で始めない名前にしています
- [テストの規範](../../development/testing.md):B 類の表と振り分けの `harness` の契機が `harness-rust-go` を持ち、ラボの一式を省けるかを決めます

ラボの一式は、所有者の規則どおり、ラボが動かすものを変えない Rust だけの変更では流しません。
Rust の agent が製品の経路で wgstack を使い始めた後は、[置き換えの判定](#置き換えの判定)のとおり、server の両方のモードでラボの一式を流します。

## 実装で決めたこと

実装の担当が決めた点を、理由と共に話題ごとに挙げます。
変えるときは、この節を同じ変更で直します。

### TCP の接続とデータの経路で決めたこと

- HyStart++:Go の HyStart++ は輻輳の制御の種類によらず最初の slow start で働きます。
  Rust も NewReno のときを含めて働かせ、NewReno の記録と同じ出力を返します
- 輻輳の制御と boost の与え方:`Config` の `congestion` と `boost` で選びます。
  既定は Go と同じ CUBIC と需要による boost です
- 時刻の算術:TCP の規則の中の時刻は Go と同じ符号つきの 64 bit の ns で持ち、0 を「無し」にします。
  Go は `now - curRTO()` のように負になりうる値を 0 と区別して使うので、飽和する `Time` の算術では同じ出力に
  なりません
- 古い handle の abort:Go は古い接続の値が持つ 4 つ組で TIME_WAIT の行を引きます。
  Rust の `ConnId` は 4 つ組を持たないので、TIME_WAIT の表に元の接続の枠ごとの行の list を持ち、元の枠と世代で引きます。
  list は世代の新しい順 (枠の世代は使うたびに進み、行は先頭に入る) なので、引く世代より古い行に着いたら止めます。
  手間は、その枠から移して表に残る行のうち引く世代より新しい行の数です。
  表に無い世代の handle (行が期限で消えた接続や、行に移らずに閉じた接続) は、その後に同じ枠を使って行に移った接続の数だけたどって止まり、枠の最新の行より新しければ先頭の 1 行で終わります。
  `check_invariants` が list の世代の順を確かめます。
  中継は規則を変えた時と閉じる時に、届けている途中の多くの接続を abort するので、表の全体をたどる形は採りません。
  上界の `tw` の項は、行ごとの節と枠ごとの先頭を数えます
- 接続の枠の確保の失敗:握手の最後の ACK で floor の記録の輪と区間の表を確保できなければ、accept の待ち行列が
  満杯の時と同じく ACK を捨てて行を残し、`accept_overflow` を数えます
- chunk の確保の失敗:受信のバッファが chunk を確保できなければ、segment を状態を変えずに捨てて
  `recv_no_memory` を数えます。
  書き込みは `Error::NoMemory` を返します
- 白箱の試験:Go の `tcp_test.go`、`ackpolicy_test.go`、`orphan_test.go`、`reuse_refused_test.go`、
  `hystart_test.go` などに当たる試験を持ちます。
  SACK、D-SACK、boost、受信の窓の boost の段を使う試験 (`rcvwin_test.go` の多く) は次の節の試験です

### 回復と輻輳の制御と boost で決めたこと

- 欄の置き場所:RACK の状態、TLP の縮小の印、次の ACK に載せる D-SACK の block、CUBIC の状態は ACK ごとに触るので `Tcb` に置きました。
  D-SACK で倍率を上げた往復と倍率を保つ回復の数、D-SACK の累計、PRR、boost の需要と受信の段の印は、D-SACK と回復と boost の事象でだけ触るので `ConnCold` に置きました。
  並べ替えの窓の倍率は上限が 255 なので `u8` で持ちます
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
- 試験:Go の `sack_test.go`、`scoreboard_test.go`、`prr_test.go`、`lostq_audit_test.go`、`dsack_test.go`、`cwndval_test.go`、`lazyegress_test.go`、`tlp_rto_test.go`、`rack_test.go`、`undo_test.go`、`cc_test.go`、`boost_test.go`、`rcvwin_test.go` に当たる試験を持ちます。
  Go の試験が大きさ 1 の枠の集まりを作る所は、Rust の `Budget` の枠の数が固定なので、ほかの枠を別の接続で埋めてから取り合いを起こします
  試験は毎回 `check_invariants` を呼ぶので、ワークスペースの `Cargo.toml` で `wgft-wgstack` を dev と test の build でも `opt-level = 2` で作ります。
  溢れの検査と `debug_assert` は残ります。
  RACK の期限の敵対的な ACK の試験は Go と同じ ACK の数で流します。
  SACK の洪水の試験は Go の 20000 の ACK では 18 秒かかるので 5000 にし、ACK 1 つの手間の上界も確かめます。
  上界の式は ACK の数に比例するので、確かめる比は同じです

### UDP と ICMP と断片で決めたこと

- UDP の endpoint の行:行は endpoint の 2 つの向きの予算、向きと大きさの区分ごとの今の chunk、受信の FIFO の先頭と末尾、送信の空きを待つ list の節を持ち、待ち受けと同じポートごとの行の表 (`PortTable`) に置きます。
  endpoint の byte の予算はいつも chunk の倍数なので chunk の数で持ち、datagram の番号は 16 bit にしました。
  このため `Limits` の UDP の datagram の数は 1 から 65,535 です。
  行はポートの表の世代を含めて 32 byte で、表は開いている印の bit の集合と合わせて 2.0 MiB です ([上界の表](wgstack-bound.md))。
  受け付けるアドレス 1 つの agent の固定の項としては小さいので、密な表と番号の引き当ての 2 段にはしません
- `Limits` の UDP の数:`Limits` は、Go の試験だけが小さくする `udpRxDgrams` と `udpTxDgrams` に当たる `udp_rx_datagrams` と `udp_tx_datagrams` を持ちます。
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
- 誤り:`Error` は UDP と ICMP のために `InvalidAddress`、`MessageTooLong`、`UdpStopped`、`TableFull`、`InvalidMessage`、`NoBufferSpace` を持ちます。
  制御の輪が満杯の時の `send_ping` は、Go と同じく IP の ID を 1 つ使ってから `NoBufferSpace` を返します。
  Go と同じく、この拒否は `ctl_dropped` に数えません
- まれにしか触らない状態の置き場:UDP の状態、ping の表、ICMP の誤りの速さの制限、再組み立ての表の掃除の時刻は、核の共有の状態 (`Shared`) の中に置きます。
  このため segment ごとの経路が触る欄のキャッシュの行の中の位置がずれます。
  これらを作成の時に確保する別の値に移す形は採りません。
  その形は `send_segment/1024` の L1 の miss を減らさず、`Shared` に置く形との速さの差も criterion の揺れの内だったためです
- ping の表:応答の置き場は作成の時に確保する配列です。
  応答の置き場は Go と同じく MTU の大きさで、Go は最初に使う時に確保しますが、Rust は 16 個すべてを作成の時に確保します。
  上界はどちらも 16 個の分を数えます
- PMTU:`pmtu_drop` を `tcp::input` に、`mark_lost_longer` を `tcp::sack` に Go と同じ形で写しました。
  `scoreboard_against_recount` の試験は、Go と同じく乱数の分岐で PMTU を引き下げます
- 試験:Go の `udp_test.go`、`frag_test.go`、`fragidle_test.go`、`checksum_test.go` の UDP の試験、`sack_test.go` と `observe_test.go` の PMTU の試験に当たる試験を持ちます。
  Go の試験の読み書きの期限と、`Close` で待ちが解けることは handle の層の試験に移ります。
  `TestIdleDeviceSweepsAHeldFragment` は、Device のタイマーの goroutine の代わりに、`poll_timeout` の時刻を追う駆動が寿命の後に Time Exceeded を送ることを確かめます。
  受信の洪水の試験は 1 つの datagram ごとに `check_invariants` を呼ぶと遅いので、間を置いて呼びます。
  Go の試験に無い試験も持ちます。
  送信の chunk の確保の失敗と取った chunk と番号の戻し、同じポートの待ち受けと endpoint が知らせの対象を分け合うこと、endpoint の chunk の上限と核の件数の上限の境目、ICMP の誤りへの誤りと multicast の送信元と引用の大きさの守り、断片を保持した時の掃除の時刻の張り直し、中身がちょうど新しい MSS の記録、PMTU の引き下げが損失の境目を数え直すこと、ログの数です
- 検出力:変異の試験で残った変異のうち、次のものは出力を変えないことを確かめ、Go と同じ形のために守りを残しました。
  核の datagram の件数の予算の比べ (空きの list が先に尽きます)、閉じた endpoint の送り残しが今の chunk を外す時の世代の比べ (その chunk は送り残しが持つ間ほかの endpoint に渡りません)、checksum の 0 を 0xffff にする所 (`write_udp_header` も同じ置き換えをします)、Fragmentation Needed の引用の送信元の比べ (接続の表を引用の送信元で引くので見つかりません)、ICMP の誤りの後続の断片の守り (呼び手は後続の断片を渡しません)、再組み立ての知らせの後続の断片の守りと最初の断片の有無 (`param_problem_ok` と `timeout_quote` が同じ条件で断ります)
- 不変条件:`check_invariants` は、UDP の chunk と datagram の空きの list、核と endpoint の予算と保持する chunk と datagram の一致、区分の枠の使っている数、受信と送信の FIFO、待ちの list、ping の行を確かめます。
  核の chunk の置き場の数は、接続の輪と UDP の chunk の和と比べます

### handle の層で決めたこと

- 核に届く道:handle は `Access` の trait (`with`、`wake_driver`、`is_poisoned`) を通して核を借用します。
  agent のデータプレーンは device の層と核を 1 つの `RefCell` に置くので、handle の層が別の `RefCell` を持つと持ち主が 2 つになるためです。
  核と waker の表は `Netstack` の 1 つの値にし、駆動の口 (`handle_packet`、`handle_timeout`、`poll_transmit`、`poll_timeout`、`poll_wakers`、`poll_log`、`close`) は `dataplane::Upper` と同じ形で時刻を `Instant` で受けます。
  agent のデータプレーンは、`Local` に `Access` を、`Netstack` に `Upper` を実装して繋ぎます。
  `LocalNetstack` は核だけを持つ同じ形の実装で、試験とほかの駆動 (後の server) が使います
- 作成の失敗:`Netstack::new` は、`Stack::new` の誤りと waker の表の確保の失敗を `NetstackError` で返し、`Budget` を取り戻せます。
  waker の表とポートの頁は `try_reserve_exact` で確保し、頁の確保の失敗は待ち受けと endpoint を開く操作の `NoMemory` の誤りにします。
  agent のデータプレーンも上の層の作成を失敗しうる形にし、失敗した作成は受けた予算を返します ([核との継ぎ目](agent-parity.md#核との継ぎ目))
- 時刻:`Netstack` は作成の時の `Instant` と時計の関数を持ち、handle の操作の時刻はその時計から取ります。
  駆動はデータプレーンの時計と同じ関数を渡します。
  agent はデータプレーンの時計 (`dataplane::clock::now`) を渡します。
  handle が駆動の起床を待たずに核を呼ぶためです
- waker の表:接続の枠ごとに読みと書きの waker を 1 つずつ持ち、作成の時に枠の数だけ確保します。
  TCP の待ち受けの accept と UDP の endpoint の読みの waker は、256 個のポートの頁に分けて持ちます。
  頁はその範囲のポートで初めて開く時に確保し、核を閉じるまで持ちます。
  65,536 個のポートの分を作成の時に確保すると、待ち受けの少ない agent でも約 2 MiB を持つためです。
  ping は核の表と同じ数です。
  上界は 64 bit の target で、接続の枠の数 × 32 byte、ポートの頁をすべて開いた 2 MiB、頁の表の 4 KiB、ping と UDP の送りの待ちの分の和で、K の既定で約 2.1 MiB です。
  `Netstack::waker_bound` が計算し、試験がすべての頁を開いた表の大きさと一致することを確かめます。
  waker の表と、駆動が借用の外で起こすために waker を移す list は、核の `Bound` の外です。
  agent のメモリの上界の行がこれらを数えます ([メモリの上界の行](agent-parity.md#メモリの上界の行))。
  表は知らない種類の知らせを試験と debug の build で止めます。
  dial の側が `Connected` と `ConnectFailed` を足す時に、表が黙って捨てないためです
- 待つ task の数:接続の読みと書き、待ち受け、UDP の受け取り、ping は、向きごとに 1 つの task だけが待ちます。
  handle の操作が `&mut self` を取るので、同じ向きを 2 つの task で待てません。
  UDP の送りだけは、UDP の中継のセッションの task が同じ endpoint から送るので、複製できる `UdpSender` で複数の task が待ちます。
  送りの待ち手は核の全体で 1 つの `tokio::sync::Notify` を分け合います。
  核は送信の予約が 1 つ返ると待つ endpoint すべてに `UdpWritable` を出すので、全体で 1 つにしても起こす相手は変わりません。
  待ち手の節は待つ future の中にあるので、表は伸びません。
  `poll_wakers` はこの `Notify` を起こす waker を 1 つ出すので、待ち手を起こすのも借用を返した後です。
  `Notify` は中に錠を持ち、`UdpWritable` は送信の予算が尽きた時だけ出ます。
  1 回の知らせで起きる送り手は、UDP の中継の応答のバッファの枠の数 (64) までです
- 駆動を起こす道:handle は操作ごとに `wake_driver` を呼びます。
  `LocalNetstack` は `tokio::sync::Notify` の `notify_one` で起こし、駆動の task が待っている時は `Notify` の錠を取ります。
  packet ごとではなく操作ごとの費用です。
  agent の `Local` は 1 つのスレッドの `Cell` に置いた印と waker で起こし、錠を取りません ([操作の知らせ](#操作の知らせ))
- 取り消し:どの future も核の操作を 1 回の poll の中で終えます。
  進んだら `Ready` を返し、`WouldBlock` なら waker を登録して `Pending` を返します。
  核の `WouldBlock` は状態を変えないので、future をどこで落としても核は一貫します。
  落とした future の waker は表に残り、次の知らせで一度起きるか、handle を閉じる時に捨てられます
- 閉じ方:`TcpStream` を `close` で閉じずに落とすと `abort` (RST) します。
  中継の終わり方の表でポートの消滅と停止は RST で、task の取り消しと panic もこの経路を通るためです。
  ただし送信の向きを閉じた後 (`close_write` か tokio の `shutdown`) に、巻き戻しの途中でなく落とした時は、`close` と同じく閉じます。
  書いて `shutdown` して落とす tokio の書き方で、書いたデータを RST で失わないためです。
  未読の受信のデータがあれば、Linux と同じく RST で終えます。
  ルールの削除と停止の中継は、明示の `abort` を使います。
  `close` は `Closing` を返します。
  核は届け終えたことを知らせないので、中継は Go の `AwaitDelivered` と同じく、間隔を伸ばしながら `Closing::delivered` を問い直します。
  `Closing::abort` は TIME_WAIT の表に移った行にも RST を送ります。
  閉じた後の枠は別の接続に使われているかもしれないので、`Closing::abort` は枠の waker を捨てません。
  捨てると新しい接続の知らせを失います。
  `TcpListener`、`UdpSocket`、`Ping` は落とすと閉じます。
  `UdpSocket` を閉じると、その endpoint から送ろうと待つ `UdpSender` が起き、閉じた誤りを受けます。
  毒の印の後、handle は操作に誤りを返し、落とす時も核に触りません。
  毒の印の時に handle で待っている task は起きないので、駆動の持ち主がそれらの task を落とします。
  agent のデータプレーンは世代の終わりに local の task をすべて落とします
- 誤り:核の `Error` を種類の合う `io::ErrorKind` の `io::Error` にし、核の誤りを中に置きます。
  呼び手は `get_ref` と `downcast_ref` で核の誤りを取り出せます
- tokio の `AsyncRead` と `AsyncWrite`:`TcpStream` に実装しました。
  中継が LAN 側のソケットとの間で tokio の写しの道具を使えるようにするためです。
  `poll_flush` は何もせず、`poll_shutdown` は `close_write` です
- ログの文面:`poll_log` は Go の wgstack と同じ文面の行を返します。
  文面の正本は handle の層の 1 か所だけです。
  核の `LogLine` は `Display` を持ちません。
  核はログを書かず、駆動の層が英語の 1 行にする決まり ([誤りと捨てた数](#誤りと捨てた数)) に合わせ、UDP の内訳と会計の故障の中身を読める層に置くためです。
  MSS の下限の行は、Go が書く最後の相手のアドレス (the latest from) を書きません。
  `LogLine` がアドレスを運ばないためです。
  UDP の捨てた数の行の内訳は `stats` から取ります
- LAN 側のソケットの表:`LanSockets<T>` は接続の枠の数の行を作成の時に確保し、行は接続の handle とソケットの組です。
  中継は accept の後、最初の読み書きの前に `register` で組を登録し、返る登録の値を LAN 側のソケットを閉じる前に落とします。
  hook は handle の世代も照らすので、枠を使い直した接続に古い組は届きません。
  同じ接続を 2 回登録すると後の組に替わり、先の登録の値を落としても後の組は外れません。
  表は核の `RefCell` の外の `Rc` で、hook と中継が分け合います。
  hook は核の借用の中で呼ばれるためです。
  boost を accept の時に与える方針では、boost の知らせが accept の中で登録より先に来ます。
  hook は変化だけを伝えるので ([回復と輻輳の制御と boost で決めたこと](#回復と輻輳の制御と-boost-で決めたこと))、この方針では最初の知らせが LAN 側に届きません。
  この方針は試験と測定だけが選ぶので、知らせを溜めて登録の時に渡す仕組みは作りません。
  製品の既定の需要による boost は読み書きの後に来るので、登録が先です
- handle の層が使う核の口:`PingId::index`、`Stack::hook`、定数の `MAX_PINGS`、`MIN_MSS`、`UDP_RX_BYTES`、`UDP_ENDPOINT_SHARE` です。
  waker の表とログの文面が核の値を写さずに使うためです
- dial の側の余地:`TcpStream` は `ConnId` から作り、waker の表は接続の枠の番号で引くので、受動と能動の接続で同じ形です。
  dial の側は、`connect` の future と、`Connected` と `ConnectFailed` の知らせで書きの waker を起こす行を足します
- 試験:試験の中の代わりの駆動が、1 回の起床と同じ順で、止めた tokio の時計の上の核を動かします。
  核は能動の open を持たないので、TCP の相手は試験の中の台本の相手です。
  UDP と ping は 2 つの核を向かい合わせます。
  future を落とした後の一貫、空きを待つ書き込みが知らせで起きること、操作の知らせで駆動が時計を待たずに起きること、閉じた接続の枠を使い直した接続の知らせ、`shutdown` の後に落とした接続が書いたデータを届けること、毒の印、packet ごとにヒープが伸びないこと (確保の数え) を確かめます。
  試験の本体は自分の task として動かします。
  `run_until` の中で直に poll すると、ほかの task が起きるたびに本体も poll され、失った知らせが隠れるためです。
  知らせを失った試験は、止めた時計の上の期限で止まらずに失敗します

### 送り手の不変条件

`check_invariants` は使っている接続ごとに `check_sender` を呼び、Go の敵対的な送り手の試験 (`runAudit`) が各段の後に確かめることと `checkScoreboard` を写します。

- SND.UNA ≤ SND.NXT ≤ SND.MAX と、輻輳の窓が 0 でないこと
- scoreboard の数え直し (`check_scoreboard`):記録が SND.UNA から SND.MAX まで隙間なく並ぶこと、SACK 済みの byte と数、境目から先の byte と数、再送の byte (`rtx_bytes`)、境目から先の RACK の損失の byte、位置の欄 (`loss_idx`、`rxt_idx`) の範囲、2 つの list (`t_list`、`lost_q`) の節と印と数と順
- pipe:増減で保つ欄から求めた値が、RFC 6675 の定義どおりに記録から求めた値と一致すること (Go の `checkScoreboard` と同じ)
- 分けて送っている記録の中の位置:`q_mid` の間は損失の待ち行列が空でなく `q_off` がその先頭の記録の長さより小さいこと、`rxt_mid` の間は `rxt_off` が `rxt_idx` の記録の長さより小さいこと

Go の `checkScoreboard` も pipe を記録から数え直すので、この数え直しは Go の確かめを写したもので、強めたものではありません。
Go の「pipe は送り残しの 2 倍と 1 以下」は別に確かめません。
定義どおりの pipe は 2 つの和を足した値です。
1 つは損失の境目から先の SACK 済みでなく失われてもいない記録の長さの和、もう 1 つは SACK 済みでなく今の世代の再送の印を持つ記録の長さの和で、どちらも送り残し以下です。
数え直した pipe と一致すればこの上限も満たすので、別の確かめは届かない枝になります。
接続の欄だけを持つ `pipe` と `seg_mss` は `Tcb` を受ける関数にし、`Conn` の同じ名前の関数はそれを呼びます。
`rtx_bytes` の減らし忘れ (`drop_head` が減らさない故障) を入れると、核の単体の試験、記録の照合、試験の担当の `core` の fuzz (`-runs=25000 -seed=1`) が段ごとに捉えることを確かめました。

### 不変条件の検査の手間

試験と fuzz は `check_invariants` を各段の後に呼ぶので、手間は表の大きさに比例しても、表の大きさによらない固定の部分を持たないようにします。
知らせの list の確かめが対象ごとに印と list の節を比べ、待ち受けと UDP の endpoint の表の確かめが開いている行を探して 65,536 行をたどると、試験の小さな表でも 1 回に約 100 µs かかり、ほとんどがポートの数に比例する部分になります。
k 回に 1 回だけ確かめる形は、壊れた段を後の段で見つけることになるので採りません。

- list の節の印:`Dlist` の「list に入っている」印は、1 節 1 bit の集合 (`BitSet`) で持ちます。
  確かめは list をたどり、たどった数と印の数 (64 節で 1 語の popcount) を比べます。
  たどった節はどれも印を持ち前の節を指すので、同じ節を 2 度通りません。
  このため数が等しければ印を持つ節はすべて list にあります
- 知らせの印:`EventList` の確かめは、list の対象がどれも印を持つことと、印のある対象の数が list の長さと等しいことを確かめます。
  印の数え上げは 128 対象ずつ `u8` で足し、分岐を持たない vector の命令にします。
  塊の中の数は 128 を超えないので、溢れの確かめの無い足し算にします。
  release の build でも核の crate は溢れの確かめを残すので、確かめのある足し算は vector の命令にならず、数え上げが 1 段の確かめの大部分を占めていました
- ポートの表:行が開いているかを行に持たず、ポートごとに 1 bit の集合だけに持ちます。
  開いている行をたどる処理と確かめは bit の集合の語をたどり、開いている数と popcount を比べます。
  印が 1 か所にしか無いので、行と印の食い違いは起きません。
  このため待ち受けの行は 16 byte、UDP の endpoint の行は 32 byte に収まります ([上界の表](wgstack-bound.md))
- 空きの list の重なりの印:接続の枠と握手の途中の表と TIME_WAIT の表の空きの list の確かめは、印を 1 行 1 bit にし、確かめの間だけ確保します。
  1 つの印の配列を使い回す形は採りません。
  使い回す配列は `&self` の確かめの中で書くので内部の可変性 (`Cell` か atomic) を要し、製品の核に試験のためだけの常駐の配列 (既定の表で 8 KiB) が加わります。
  小さな表での確保は 1 回 0.02 µs で、確かめの手間の中で無視できます
- 輪の chunk の数:`Ring::held_chunks` は輪の容量の内の chunk の位置だけを数えます。
  容量の外に chunk が無いことは、同じ検査の中で `Ring::check` が確かめます。
  製品の `held` も同じ関数を使うので、会計を読む手間も減ります

segment ごとの経路では、`Dlist` の印の読み書きは bit の演算です。
ポートの表の引き当ては、行に加えて bit の集合の語を読みます。
TCP の確立した接続の segment はポートの表を引きませんが、UDP は datagram ごとに引きます。
UDP の datagram ごとの手間は、UDP の bench が無いので測っていません。

この形と[作成と確かめの細部](#作成と確かめの細部)で、試験の小さな表 (K = 16) の `check_invariants` は 1 回に約 7 µs です。
既定の表の `check_invariants` は、表の行の数 (TIME_WAIT の表の 65,536 行、接続の枠ごとの輪の chunk の位置) に比例する部分が大部分で、この形の対象ではありません。
小さな表で残る約 7 µs は、接続の枠ごとの輪の容量の外の chunk の位置の確かめ、送り手と scoreboard の確かめ、UDP の datagram の管理の配列の確かめです。
segment ごとの経路の criterion の組の差は、道具だけの費用の揺れの内でした。

#### 作成と確かめの細部

各段の確かめと核の作成は、確かめの範囲と関係の無い手間を次の形で避けます。
どれも読む位置と語を変えないので、確かめの範囲は変わりません。

- 表を埋める処理:`FixedVec::try_filled` は長さの分かる iterator の `extend` で、先に取った容量へ書きます。
  要素ごとに容量を比べず、確保し直さないので、同じ値で埋める配列は vector の命令の書き込みになります。
  ポートの数の表 (待ち受けの表と知らせの対象) を埋める手間の多くがこれで決まります。
  製品の核の作成、`Budget` の作成、枠を初めて使う時の floor の配列の確保も同じ関数を通ります。
  `Vec` を伸ばす語を使えるのは `fixed_vec.rs` だけなので、source の検査の例外に `.extend(` があります
- 輪の容量の外の確かめ:`Ring::check` は容量の外の位置を途中で止まらない畳み込みで確かめ、位置の比べを vector の命令にします。
  容量の外の位置は floor の輪で多く、接続の枠ごとに 2 つの輪を見るので、位置ごとに分岐する形では枠の確かめの多くを占めます
- bit の集合の数え上げとたどり:x86-64 の既定の命令の集合は popcount の命令を持たないので、1 語の数え上げが 10 命令ほどになります。
  `BitSet` は 8 語の塊ごとに OR で 0 かを見て、印の無い塊を数えずに飛ばします。
  ポートの表の bit の集合はほとんどの語が 0 なので、開いている数の数え上げと開いている行のたどりが速くなります

2026-11-01 に 1 つの車線で測った値は次のとおりです。
criterion の組は 2 回ずつ流し、車線の揺れが小さかった回の値です。

| 測った値 | 値 |
| --- | --- |
| `check_invariants/small/1` | 6.1 µs |
| `check_invariants/small/16` | 6.9 µs |
| `check_invariants/default/1` | 0.84 から 0.86 ms |
| 試験の小さな表の核を作って閉じる (crate の中の時計、debug assertions つき) | 100 µs |

segment ごとの経路の組 (`recv_segment`、`send_segment` と `_sack` の組) はこれらのコードを通らず、揺れの小さかった回の差は -1% から +1% でした。
`stack_new/default_limits` は回ごとに 2.3 ms から 5.1 ms まで揺れ、差を読み取れませんでした。
既定の表の作成は接続の枠ごとの配列が大部分で、ポートの数の表の割合が小さいためと見ています (未確認)。
fuzz の速さは[試験の道具の設計の実行の速さ](test-tooling.md#実行の速さ)にあります。

### 書き換えた所だけの確かめ

fuzz と白箱の試験は、各段の後に `check_invariants_touched` で不変条件を確かめます。
前の確かめから書き換えた接続の枠だけを確かめ直し、枠ごとの数え (chunk、予約、boost) の和と知らせの印の数は増減で保ちます。
すべての枠を確かめて数え直す `check_invariants` も残し、2 つが同じ状態に同じ答えを返すことを試験が並べて確かめます。
k 段に 1 回だけ確かめる形と同じく、確かめる不変条件を減らして速くする形は採りません。
この確かめと書き換えの印は試験と fuzz の build だけにあります ([boost の hook](#boost-の-hook)の後の規則)。

- 書き換えの印:接続の枠の配列 (`ConnSlots`) は型の外から見えません。
  試験と fuzz の build では、書き換えの口 (`tcb_mut`、`bufs_mut`、`parts_mut`、`alloc`、`free_all`) がどれも、書き換える枠に 1 枠 1 bit の印を付けます。
  `check_invariants_touched` は印のある枠を確かめ直して印を外します。
  枠ごとの数えとその和は核の外の値 (`TouchedCheck`) が持ちます。
  `TouchedCheck` は 1 つの核に属します。
  別の核に渡すと、印の無い枠の数えが前の核の値のまま残り、答えが変わります。
  核を作り直したら `TouchedCheck::new` で作り直します (最初の呼び出しはすべての枠を確かめます)
  製品の build に印と印を付ける処理はありません。
  上界の式の `stack` の項は製品の核の大きさで数え、試験と fuzz の build だけにある欄を入れません
- 同じ答えになる理由:枠だけを読む確かめ (輪の容量の外の chunk、受信の区間の表、段、`check_conn`、送り手と scoreboard) は、枠の 3 つの配列の要素と、それが持つ配列だけを読みます。
  印の無い枠はこれらが前の確かめの時のままなので、前と同じく通り、数えも前と同じ値です。
  共有の表の確かめと、枠と共有の表の間の確かめ (接続の表の印、boost の保有者、タイマーと wheel、出力の list、待ち受けの待ち行列、空きの list) は、毎段すべての枠で行います。
  別の枠の処理が共有の表を書き換えても、ここで捉えます。
  最初の呼び出しと誤りを返した後の呼び出しは、すべての枠を確かめて数え直します。
  印のある枠を小さい順に確かめるので、誤りの文も `check_invariants` と同じです
- 知らせの印:試験と fuzz の build では、印を書く唯一の口 (`EventList::set`) が、書くたびに前の値と新しい値から印を持つ対象の数を増減します。
  数は印を書く呼び手の誤り (list に入れ忘れる、外し忘れる) に関係なく印を持つ対象の数に等しいので、各段の確かめはポートの数の対象を数え直さずにこの数を list の長さと比べ、数え直しと同じ答えを返します。
  `check_invariants` は配列を数え直し、試験と fuzz の build ではこの数とも比べます。
  この数は試験と fuzz の build だけにあり、製品の核の常駐の欄と知らせの経路の足し算にはなりません
- 空きの boost の枠の chunk の表:`Budget::check` は空きの枠の chunk の表が chunk を持たないことを確かめ、boost の枠の数 × 送受信 × 表の行 (約 64 KiB) をたどります。
  試験と fuzz の build では、空きの枠の配列を置き換える唯一の口 (`Budget::release`) が枠に印を付けます (`Budget::acquire` と `Budget::hand_over` は配列を取り出して枠を貸します)。
  書き換えた所だけの確かめは、印のある空きの枠の表だけをたどって印を外します。
  印の無い空きの枠の表は前の確かめの時のままなので、答えは同じです。
  `check_invariants` と最初の呼び出しはすべての空きの枠をたどります。
  `Budget` は核から核へ渡るので、前の核の印は新しい核の最初の呼び出しが外します
- 試験:白箱の試験の道具 `TestNet` は各段で 2 つの確かめを並べ、答えと誤りの文が同じことを確かめます。
  stable の試験 `fuzz_corpus` も、fuzz の `Net` を使う target の種を 2 つの確かめを並べて流します。
  `touched_tests` は、書き換えの口が枠に印を付けること、書き換えた枠の誤りを同じ文で捉えること、最初の呼び出しがすべての枠を確かめることを確かめます
- 採らなかった形:書き換えた枠を hook に知らせ、記録を試験の hook に持つ形は、製品の書き換えの口に知らせの引数と空の hook の呼び出しが残るので採りません。
  印を製品の build にも置く形は、試験のためだけの常駐の配列を製品の核に足すので採りません ([不変条件の検査の手間](#不変条件の検査の手間)の空きの list の重なりの印と同じ理由)

2026-11-02 に 1 つの車線で、fuzz の計装の無い release の build に debug assertions を足した build で入力を 1 つずつ流して測った値は次のとおりです。
入力は `core` の libFuzzer が作った長い入力の集まり (平均約 250 段) で、値は 1 入力の時間です。

| 確かめ | 1 入力 |
| --- | --- |
| 変える前の `check_invariants` | 6.01 ms |
| 数え直しの足し算を変えた `check_invariants` | 1.26 ms |
| `check_invariants_touched` | 0.98 ms |

`check_invariants_touched` の残りの多くは、毎段すべてを確かめる共有の表です。
2026-11-01 の測り (boost の段の chunk の表を `Budget` から借りる変更の前) では、UDP の chunk の表の確かめ (表の全体と空きの list をたどります) が 1 段に約 0.4 µs、握手の途中の表と TIME_WAIT の表、wheel、空きの list、接続の表がそれぞれ 0.1 µs から 0.2 µs で、書き換えた枠の確かめは約 0.3 µs でした。
共有の表にも書き換えの印を足せば減りますが、印を付ける口が表ごとに増えるので、この段では足していません。
ほかの target の値は[試験の道具の設計の実行の速さ](test-tooling.md#実行の速さ)にあります。

### 核の使い回し

fuzz の target は、閉じた核のポートの数の行を持つ表 (待ち受けの表、UDP の endpoint の表、知らせの list) を作成の時の値に戻し、次の入力の核に渡します (`Stack::close_keeping` と `Stack::new_reusing`)。
ほかの表は `Stack::new` と同じ口で新しく作ります。
この 3 つの表は小さな表の核でも 3 MiB ほどあり、作成の手間の大部分を占めます。
使い回しの口と欄は試験と fuzz の build だけにあり、製品の build にはありません ([boost の hook](#boost-の-hook)の後の規則)。

- 戻す範囲:3 つの表のうち作成の時と違う値を持ちうるのは、開いたことのあるポートの行の世代と、開いたままの行と、list に残った印と節です。
  閉じた行は世代のほかは作成の時の値です (閉じる時に行を既定の値にします)
- 開いたことのある印:`PortTable::open` は行の世代を変える唯一の口です。
  試験と fuzz の build では、ここで開いたことのある印 (ポートごとに 1 bit) も付けます。
  `close_keeping` は核を閉じた後に、印のある行を作成の時の値に戻して印を外します。
  手間は開いたことのある行の数と bit の集合の語の数に比例します
- 知らせの list:試験と fuzz の build では、`Dlist::remove` が外した節を作成の時の値 (`NIL`) に戻すので、空の list は作成の時の list と同じです。
  印の残る知らせの list と、大きさの違う知らせの list (接続の枠の数の違う設定) は使い回さず、次の核が新しく作ります
- 同じ核になる理由:3 つの表は作成の時の値に戻り、ほかの表は `Stack::new` と同じ口で作るので、使い回した核は新しく作った核と同じ状態です。
  上界は設定と製品の型の大きさだけで決まるので同じ値です。
  `Spare::is_fresh` は戻した表をすべての行で新しい表と比べ、試験が使います
- 試験:白箱の試験 `a_reused_stack_matches_a_new_one` は、待ち受け、接続、UDP、ping、閉じて開き直すポートを使う台本を新しい核で流した後に表を戻し、戻した表が新しい表と同じであること、使い回した核が同じ台本に同じ出力と知らせと会計を返すこと、上界が同じことを確かめます。
  stable の試験 `fuzz_corpus` は、fuzz の `Net` を使う target の種を新しい核と、ほかのポートを開いて閉じた核の表を使い回した核で流し、外から見える出力 (送った packet、各段の保持と事象の数と次の起床の時刻、最後の会計) の hash が同じことと、閉じた後に戻した表が新しい表と同じことを確かめます。
  `Net` の既定は新しい核で、cargo-fuzz の target だけが初期化で使い回しを選びます。
  保持の試験 (`holding`) は核を作った後の確保を数えるので、使い回した表が数えの起点に入らないことを確かめます
- 前の判断の見直し:前は、ポートの表の世代を作成の時と同じにするには表の全体を書き直すので、作成と同じ手間がかかるとして使い回しを採りませんでした。
  開いたことのある印を持てば速くなります。
  この印は試験と fuzz の build だけに置くので、製品の核に試験のためだけの常駐の配列は加わりません

[書き換えた所だけの確かめ](#書き換えた所だけの確かめ)と同じ測りで、`core` の長い入力の 1 入力は 0.98 ms から 0.91 ms に、git の種 (短い入力が多い) は 0.49 ms から 0.41 ms になりました。

### qbench の engine で決めたこと

qbench は `wgstack-rs` の engine を持ち、判定する engine を切り替えられます。
口の細部 (`--clock real`、`ACCEPT`、`CONN_SOCKET`、`RTO_AT`、CPU の数え方、中継の 1 段の測り方) は[試験の道具の設計の実時間の DUT と qbench で決めたこと](test-tooling.md#実時間の-dut-と-qbench-で決めたこと)にあります。

- 判定の切り替え:`QBENCH_SUBJECT=wgstack-rs` で Rust の wgstack を判定します。
  関門は凍結した Go の wgstack も同じ seed で測り、同じ規則の判定を `QBENCH-BESIDE` の行に出します。
  Go の wgstack の判定は表の判定に入れず、Rust の判定と比べるためだけに出します
- segment ごとのベンチの Go の組:`internal/wgstack/segment_bench_test.go` に、`crates/wgft-wgstack-bench` と同じ形のベンチ (`BenchmarkSegmentRecv`、`BenchmarkSegmentSend`、それぞれの SACK の組、`BenchmarkSegmentRigOverhead`) を置きました。
  MTU と MSS、接続の数 (1、64、1024)、1 回ごとに 10 µs 進めてタイマーを回すこと、相手の packet を 1 つの buffer に組み立てて checksum を計算することを Rust の道具と同じにしました。
  Go の wgstack は手で進める時計で動かし、アプリケーションは Go の agent の中継と同じく `Conn` で読み書きします

#### qbench での測定

2026-11-01 に、E コアの車線 (`wgft-heavy --class tool --timing`、Core Ultra 7 270K Plus の E コア 8 個) で測りました。
ホストは Fedora の kernel 7.2.13 で、Linux の engine と Linux の client はユーザーとネットワークの名前空間の中で動きます。
参照の Linux (ラボの Debian 13 と kernel 7.2.11) ではありません。
`wgstack-dut` は release の build で、qbench は関門の表 (`TestQBenchGate`、cell ごとに 9 回、線から 5% 以内の cell は 18 回、8 回ずつ同時) です。
経路は片道 25 ms、20 Mbit/s、200 packet の列、中身で決める損失の模型です。

正しさ:関門の表のすべての cell (判定しない gVisor の client の cell を含みます) で、どの engine のどの実行も、byte の列の一致と誤りの無い終わりを通りました。
判定する cell で、Rust の wgstack は `recv/loss5%/linux-client` と `thin-recv/loss5%/linux-client` が UNDETERMINED で、残りが PASS でした。
測った後に、同じ実行の Go の wgstack の値に同じ規則を当てると、同じ 2 つの cell が UNDETERMINED で、残りが PASS でした。
bulk の cell は記録の seed ごとの値から判定の計算 (seed ごとの比の中央値と bootstrap の区間) を写して判定し直し、途絶と細い stream の cell は表の値と区間を線と比べました。
上の記録は `QBENCH-BESIDE` の行を持たないので、Go の wgstack の判定は記録の値から求めました。
`QBENCH-BESIDE` は主題の判定が線に近い時に増やした実行をそのまま使い、自分では実行を増やしません。
UNDETERMINED の 2 つは、どちらの wgstack も値が線の近くにあり、区間が線をまたいだためです。
このため、[置き換えの判定](#置き換えの判定)の qbench の条件は満たしました。

判定する cell の値は次のとおりです。
bulk の cell は Mbit/s の中央値と最小から最大、途絶の cell は回復の時間 (ms) の中央値と最小から最大、細い stream の cell は全実行を合わせた p99 (ms) と run を単位にした bootstrap の 95% の区間です。
この節の中央値は、値が偶数個の時は中央の 2 つの平均です。
qbench の判定と `QBENCH-SUMMARY` の中央値は上の側の値を取るので、少しずれることがあります。

| cell | wgstack-rs | wgstack | gVisor | Linux |
| --- | --- | --- | --- | --- |
| `send/loss0%` | 18.71 (18.49 から 18.76) | 18.70 (18.64 から 18.75) | 18.69 (18.67 から 18.71) | 18.76 (18.53 から 18.77) |
| `send/loss1%` | 3.59 (2.48 から 5.64) | 3.76 (2.63 から 5.68) | 3.70 (2.87 から 5.74) | 3.74 (2.47 から 5.94) |
| `send/loss5%` | 1.13 (0.92 から 2.01) | 1.13 (0.98 から 1.94) | 1.54 (1.19 から 2.30) | 1.02 (0.82 から 1.89) |
| `send/reorder` | 18.74 (8.81 から 18.86) | 18.71 (18.58 から 18.82) | 9.34 (6.29 から 13.46) | 18.75 (18.68 から 18.82) |
| `send/outage2s` | 482 (474 から 496) | 503 (476 から 579) | 1322 (1315 から 1347) | 616 (395 から 641) |
| `thin-send/loss1%` | 96 (77.8 から 96.6) | 97 (78.2 から 97.4) | 97 (77.7 から 97.6) | 87 (77.8 から 97.1) |
| `thin-send/loss0%` | 29 (28.8 から 29.2) | 30 (29.8 から 30.6) | 29 (28.4 から 28.7) | 29 (28.6 から 29.3) |
| `thin-send/loss5%` | 118 (103.0 から 123.5) | 118 (100.1 から 122.5) | 5259 (117.3 から 5612.6) | 348 (160.8 から 635.7) |
| `thin-send/outage2s` | 1998 (1997.0 から 1998.4) | 1996 (1994.6 から 1995.5) | 9760 (9760.0 から 9760.0) | 2042 (2033.2 から 2050.7) |
| `recv/loss0%/linux-client` | 18.87 (18.86 から 18.88) | 18.88 (18.86 から 18.90) | 18.88 (18.86 から 18.89) | 18.87 (18.80 から 18.88) |
| `recv/loss1%/linux-client` | 3.24 (2.01 から 5.29) | 3.27 (2.03 から 5.33) | 3.25 (2.00 から 5.33) | 3.19 (1.92 から 5.30) |
| `recv/loss5%/linux-client` | 1.00 (0.84 から 1.56) | 0.99 (0.82 から 1.67) | 1.02 (0.85 から 1.68) | 0.95 (0.82 から 1.66) |
| `recv/reorder/linux-client` | 18.85 (18.79 から 18.87) | 18.86 (18.84 から 18.88) | 18.86 (18.80 から 18.87) | 18.86 (18.80 から 18.88) |
| `recv/outage2s/linux-client` | 982 (975 から 985) | 831 (765 から 1019) | 999 (783 から 1014) | 964 (963 から 1024) |
| `thin-recv/loss0%/linux-client` | 28 (27.6 から 28.2) | 27 (27.1 から 27.3) | 27 (27.2 から 27.4) | 27 (27.3 から 27.4) |
| `thin-recv/loss1%/linux-client` | 97 (78.5 から 97.6) | 97 (77.9 から 97.3) | 97 (78.0 から 97.4) | 97 (78.4 から 97.7) |
| `thin-recv/loss5%/linux-client` | 539 (191.4 から 777.6) | 537 (189.7 から 773.6) | 526 (195.3 から 770.7) | 409 (168.2 から 773.0) |
| `thin-recv/outage2s/linux-client` | 2060 (2044.7 から 2061.1) | 2041 (2039.2 から 2055.7) | 2059 (2046.5 から 2061.4) | 2030 (2026.6 から 2045.9) |

Rust の wgstack と Go の wgstack は、ほとんどの cell で揺れの内で同じ値でした。
判定する bulk の cell の seed ごとの比 (Rust / Go の Mbit/s) の中央値は 0.98 から 1.01 でした。
はっきり違ったのは次の点です。

- `send/reorder`:Rust の wgstack は 18 回のうち 5 回が 17.5 Mbit/s を下回り、最も遅い回は 8.81 Mbit/s でした。
  Go の wgstack は 18 回とも 18.58 Mbit/s 以上でした。
  1 回ずつ流し直しても (`QBENCH_PARALLEL=1`、18 回)、Rust は 1 回が 11.51 Mbit/s で、Go は 18 回とも link を満たしました。
  遅い回の packet の記録では、最初の窓の先頭の segment が並べ替えで 3 ms 遅れ、5 つの重複の ACK で不要な再送をした後、窓が slow start に戻らずに数秒かけて育っていました。
  同じ seed の Go の記録も同じ時刻に同じ不要な再送をしましたが、次の 200 ms で link を満たしました。
  Rust の統計は不要な再送の取り消し (`spurious_undos=1`) と、約 270 ms の 2 回目の回復を示します。
  原因は核の違いではなく、実時間の入力の時機です。
  packet の記録を手で進める時計で Go と Rust の核に与え直すと、同じ入力に同じ packet を返しました。
  どちらの駆動も、出力を作る前に読める入力を読み切ります。
  3 つ目の重複の ACK が 2 つ目の約 25 µs 後に届き、駆動が 2 つ目を処理する時にはまだ読めないと、核は limited transmit の segment を送った後、同じ 1 ms の TSval の刻みの中で速い再送を送ります。
  回復を終える ACK は TSecr に再送の時刻 (`retrans_ts`) と同じ値を返すので、取り消しの条件 (TSecr が `retrans_ts` より前) を満たしません。
  このため不要な回復が取り消されず、CUBIC は 7 から 8 segment の窓から約 5 秒かけて育ちます。
  Go の wgstack がこれをほとんど避けるのは、出力を Link の読み手が `Read` を呼ぶ時 (300 から 1,000 µs 後) に作るためで、規則の違いではありません。
  8 回ずつ同時に流した記録でこの形を数えると、Rust が 18 回のうち 3 回、Go が 18 回のうち 1 回でした。
  決定:今は受け入れ、駆動に時機をずらす回避は入れません。
  直し方は [置き換えの後の作業](#置き換えの後の作業) に挙げます
- 判定しない gVisor の client の cell:`recv/loss1%` と `recv/loss5%` で、Rust の wgstack は seed ごとに Go の 1.18 倍から 1.49 倍速く、ACK の数が data の packet あたり約 0.76 で、Go の約 0.63 より多くありました。
  別のプロセスの駆動が packet ごとに早く起き、ACK をまとめる機会が少ないためと考えます。
  Linux の client では差が無いので、gVisor の送り手が ACK の数に応じて窓を育てる差です

byte あたりの CPU:Rust の wgstack の子のプロセスの CPU を、受け手が読んだ byte で割った値です。
核のほかに、プロセスの起動と `Netstack::new` (既定の表で約 2.5 ms)、握手、駆動、`wgstack-dut` の要求の処理 (制御の口と `ACCEPT` の問い合わせ)、Unix ソケットの中継の 1 段、`SOCK_SEQPACKET` の socketpair の system call を含みます。
このため stack どうしの公平な比べではなく、qbench の形での Rust の wgstack の費用です。
製品の agent では、中継は LAN 側のカーネルのソケットに、socketpair は WireGuard の UDP のソケットに替わります。

| cell | ns/byte の中央値 (最小から最大) |
| --- | --- |
| `send/loss0%` | 7.3 (6.8 から 8.9) |
| `recv/loss0%/linux-client` | 7.7 (7.4 から 8.1) |
| `send/loss1%`、`recv/loss1%/linux-client` | 15.0、17.5 |
| `send/loss5%`、`recv/loss5%/linux-client` | 27.7、33.3 |
| `send/outage2s`、`recv/outage2s/linux-client` | 6.4、12.2 |
| 細い stream の cell | 350 から 790 |

20 Mbit/s の経路では、packet ごとの起床と system call の固定の費用が大部分です。
同じ車線で経路の速さを外すと (`QBENCH_RATE_MBIT=0`、損失なし、1 回ずつ 5 回)、Rust の wgstack は送る向きで 226 Mbit/s、受ける向きで 486 Mbit/s (gVisor の client) と 151 Mbit/s (Linux の client) で、byte あたりの CPU は 1.0 から 1.1 ns でした。
Go の wgstack は 216、497、117 Mbit/s でした。
Rust の子のプロセスはこの速さで 1 つのコアの数 % しか使わないので、この速さは Rust の wgstack の CPU で決まる上限ではなく、往復の時間あたりの窓で決まります ([qbench の値で比べられるもの](#qbench-の値で比べられるもの))。
細い stream の cell は 20 ms ごとに 200 byte なので、値はタイマーと起床の費用です。

中継の 1 段 (`TestQBenchRelayStage`、5 回):中継は 256 MiB の写しで 0.093 から 0.097 ns/byte です。
20 Mbit/s の経路の cell では子のプロセスの CPU の 2% 未満ですが、速さを外して遅れを 1 ms にした受ける向き (0.65 ns/byte) では約 15% に当たります。
細い stream の遅れの p50 は直の Unix ソケットの 0.54 から 0.61 ms に対して 0.67 から 0.71 ms で、p99 は 1.05 から 2.31 ms に対して 1.13 から 1.26 ms でした。
qbench の `thin-recv/loss0%/linux-client` で Rust の wgstack の p99 が Go より約 0.6 ms 長いのは、中継の 1 段と socketpair のプロセスの境目の分と考えます。
`thin-send/loss0%` では逆に Rust が約 1.5 ms 短くありました。

segment ごとの費用:Go の組は `-count 6 -benchtime 2s` の 6 回の中央値で、Rust の組は criterion を 3 回流した中央の推定の中央値です。
どちらの組も 1 回の確保もしません (Go の `-benchmem` で 0 allocs/op)。
入口は同じではありません。
Go の組はアプリケーションの読み書きを `Conn` (錠と条件の待ちを持つ handle の層) で行い、Rust の組は核の API (`Stack::read` と `Stack::write`) を直に呼びます。
Rust の handle の層 (`wgft-netstack`) を通す組は作っていないので、表の差には handle の層の差が入ります。

| ベンチ | Go (ns) | Rust (ns) | Go / Rust | 道具を引いた Go / Rust (ns) | 道具を引いた比 |
| --- | ---: | ---: | ---: | ---: | ---: |
| recv `/1` | 1105.0 | 661.7 | 1.67 | 721 / 566 | 1.28 |
| recv `/64` | 1178.5 | 703.7 | 1.67 | 795 / 608 | 1.31 |
| recv `/1024` | 1185.5 | 705.3 | 1.68 | 802 / 609 | 1.32 |
| recv SACK `/1` | 1121.5 | 668.2 | 1.68 | 738 / 572 | 1.29 |
| recv SACK `/64` | 1190.5 | 707.6 | 1.68 | 807 / 612 | 1.32 |
| recv SACK `/1024` | 1201.0 | 714.4 | 1.68 | 817 / 618 | 1.32 |
| send `/1` | 857.9 | 617.9 | 1.39 | - | - |
| send `/64` | 884.9 | 631.9 | 1.40 | - | - |
| send `/1024` | 934.2 | 677.9 | 1.38 | - | - |
| send SACK `/1` | 887.3 | 622.6 | 1.43 | - | - |
| send SACK `/64` | 932.3 | 639.8 | 1.46 | - | - |
| send SACK `/1024` | 1053.5 | 661.5 | 1.59 | - | - |
| 道具だけ (`rig_overhead`) | 383.6 | 96.1 | 3.99 | - | - |

最小と最大の差は、Go の 6 回で中央値の 1% から 9%、Rust の 3 回で 1% から 6% でした。
`rig_overhead` は受信の組の相手の packet (1380 byte の中身と checksum) の費用で、受信の組から引くと核の費用の目安は Go が 722 から 817 ns、Rust が 566 から 618 ns です。
送信の組の相手は 40 byte の ACK を作るだけなので、送信の組からは引きません (引くと核の費用を少なく見積もります)。
道具を引いた受信の比は 1.27 から 1.32 倍で、引かない比 (約 1.68 倍) の多くは道具の差です。
道具の差 (約 4 倍) は同じ形の 1 の補数の和の loop の差で、Go の profile では道具の和 (`ones` と `binary.BigEndian.Uint16`) が受信の組の約 30% でした。
Rust が同じ loop を速く回す理由 (vector の命令にするか) は確かめていません。

差の内訳は、Go の `pprof` (1024 本の組) と Rust の `perf record` (E コアの `cycles:u`、`--profile-time 5`) で分けました。

- 16 KiB の chunk を返す時の 0 埋め:Go の `chunkPool.put` は受信で 22%、送信で 27% (約 260 ns) で、Rust の `memset` は受信と送信で 37% (約 260 ns) でした。
  ほぼ同じ時間で、どちらの核も segment ごとに 1 つの chunk を埋めています。
  ベンチは segment を 1 つずつ読み終えるか確認を受けるので、そのたびに輪が空になります。
  輪の `trim` は生きている範囲に掛からない chunk を返すので、空の輪は持つ chunk を置き場に返して埋め、次の segment で取り直します
- checksum:Go の核の `checksum` は受信で 8% (約 95 ns)、送信で 12% (約 110 ns) で、Rust の `wire::checksum` は受信で 20% (約 140 ns)、送信で 21% (約 145 ns) でした。
  この部分は Rust の方が遅くなっています
- 残り:0 埋め、checksum、道具を除いた残りは、受信の 1024 本で Go が約 450 ns、Rust が約 210 ns でした。
  Go の残りは `Conn` の層の錠と条件の待ちを含み、Rust の残りは handle の層を含まないので、核どうしの差ではありません。
  Go の側には、ほかに手で進める時計の atomic の読み (`ManualClock.Now` が約 5%) と、`Device.Poll` と `chunkPool` の mutex が入ります。
  GC は確保が無いので動きません

最適化の候補 (提案、未実施):

- chunk の 0 埋め:輪が空になっても最後の chunk を持ち続けるか、書いた範囲だけを埋めます。
  上の内訳では segment ごとの時間の 4 割近くで、道具を引いた受信の費用 (約 600 ns) の 4 割余りに当たります。
  0 埋めは次の接続に前の中身を残さないための規則なので、書いた範囲を覚える形でも同じ約束を保てます
- checksum:Go の核の実装より約 1.4 倍遅い 1 の補数の和を、64 bit の加算か vector の命令にします。
  受信と送信の両方の 1 segment ごとに約 140 ns です
- qbench の起床の費用:20 Mbit/s の経路の byte あたりの CPU (約 7.5 ns) は、速さを外した経路 (約 1 ns) の 7 倍で、packet ごとの起床と system call の固定の費用です。
  製品のデータプレーンでも packet ごとに起きるので、`sendmmsg` と `recvmmsg` のまとめ ([置き換えの後の作業](#置き換えの後の作業)) で減る見込みです。
  製品のデータプレーンの起床の費用は測っていません
- 並べ替えの直後の窓 (`send/reorder`):原因は上のとおり取り消しの判定で、直し方は [置き換えの後の作業](#置き換えの後の作業) に挙げます

#### qbench の値で比べられるもの

qbench の速さは、20 Mbit/s の経路では経路で決まります。
速さを外した経路で何が速さを決めるかを見るため、2026-11-01 に同じ車線で、engine を 1 つずつ、速さを外して損失なしで 3 回ずつ流し、試験のプロセスの CPU を Go の `pprof` で分けました (`QBENCH_RATE_MBIT=0`、`QBENCH_DELAY_MS`)。

| 片道の遅れ | 向き | wgstack-rs | wgstack | gVisor | Linux |
| --- | --- | --- | --- | --- | --- |
| 25 ms | 送る (gVisor の client) | 209 から 240 | 215 から 232 | 299 から 300 | 213 から 302 |
| 25 ms | 受ける (Linux の client) | 130 から 143 | 97 から 117 | 169 から 206 | 106 から 146 |
| 1 ms | 送る (gVisor の client) | 4206 から 4244 | 4058 から 4539 | 3044 から 3066 | 3544 から 4248 |
| 1 ms | 受ける (Linux の client) | 3092 から 3518 | 2096 から 2250 | 4250 から 5262 | 2985 から 3340 |

値は Mbit/s の最小から最大です。
遅れを 25 ms から 1 ms に縮めると、どの engine も 10 倍から 30 倍速くなります。
25 ms の経路の速さは、CPU ではなく往復の時間あたりの窓で決まります。

受ける向きでは、1 ms の値も engine の窓で決まると考えます。
25 ms の値から往復の時間 (50 ms) あたりの窓を求め、往復の時間を 2 ms にして割り戻すと、Rust が約 3.4 Gbit/s、Go が約 2.6 Gbit/s、gVisor が約 4.6 Gbit/s、Linux が約 3.2 Gbit/s で、測った値と近いためです。
同じ試験の道具が gVisor の engine では 4.2 から 5.3 Gbit/s を運ぶので、受ける向きの 1 ms の値は道具では止まっていません。
受ける向きの差 (25 ms で Rust の 130 から 143 Mbit/s と Go の 97 から 117 Mbit/s) は受信の窓の育て方の差で、CPU の速さではなく TCP の振る舞いの差です。

送る向きの 1 ms では、Rust の wgstack の子のプロセスは 1 つのコアの約 47% しか使わず (0.89 から 0.91 ns/byte)、速さは窓から割り戻した値 (約 5.6 Gbit/s) より低い 4.2 Gbit/s でした。
このため送る向きの 1 ms の速さは、試験の道具の側 (受け手の gVisor の client、送り手の stream の生成と受け手の照合、Link) で止まると考えますが、確かめていません。
試験のプロセスは 3.5 から 7.4 ns/byte を使い、その内訳は gVisor の client (送る向きで約 2.2 ns/byte)、stream の生成と照合 (1.1 から 1.6 ns/byte)、tun と socketpair の読み書き、Link です。
どの goroutine が止めるかは分けていません。

比べ方の区別は次のとおりです。

- 核の費用の比べ:segment ごとの費用 (Go と Rust の同じ形のベンチ)。
  同じ入力を同じ形で与えます。
  ただし Go は handle の層を通し、Rust は核の API を直に呼ぶので、道具を引いた受信の比 (1.27 から 1.32 倍) は handle の層の差を含みます
- qbench の形での Rust の費用:Rust の wgstack の子のプロセスの byte あたりの CPU。
  起動、制御の口、中継、socketpair を含むので、stack どうしの比べには使いません
- 正しさと TCP の振る舞いの比べ:20 Mbit/s の経路の関門の表と、速さを外した経路の受ける向きの値。
  値は回復、窓の育ち方、遅れの比べで、CPU の速さの比べではありません
- 比べに使わない値:速さを外した経路の送る向きの Mbit/s。
  25 ms では窓で、1 ms では試験の道具で止まるとみられるので、engine の速さの順位には使いません

agent の水準の比べ (一部を実施):ラボの `lab/tcpquality.sh` と `lab/tcpquality-cpu.sh` は、WireGuard を通した agent の転送の速さ、回復、byte あたりの CPU (プロセスごとの cgroup) を測ります。
`tcpquality.sh` のモード `rust` は Rust の agent を、`gvisor` と `wgstack` は Go の agent を、カーネルモードの server と同じ経路で動かします。
byte あたりの CPU は `lab/lab paired` で 2 つの腕を同時に流して比べます ([CPU の比べ方](../userspace/wgstack-performance.md#cpu-の比べ方))。
server のユーザー空間モードを相手にした比べは、まだ道具がありません。
経路は `tcpquality-cpu.sh` の `fast` (netem なし、1 GiB) と `rate` (片道 25 ms、20 Mbit/s) で、`DIRECTION=up` と既定の down の両方です。
細い stream の遅れは今の `tcpquality.sh` が測らないので、qbench の `runThin` と同じ 20 ms ごとの 200 byte の流れを足すことを提案します。
`fast` の速さは VM の vCPU の数と WireGuard の暗号に左右されるので、CPU の数を固定し (`wgft-heavy` の車線)、byte あたりの CPU を主な値にします。
速さを制限しない経路の速さ、byte あたりの CPU、UDP の往復の遅れの基準の値と、CPU の行き先の profile は [速さを制限しない経路の agent の性能](agent-throughput.md) にあります。

## 置き換えの後の作業

agent の置き換えが終わった後に、次の作業を順に決めます。

- 性能の目標の測定と、届かない点の作業 ([置き換えの判定](#置き換えの判定))
- 需要で育つバッファ ([需要で育つバッファとの関係](#需要で育つバッファとの関係))
- 参照の Linux が 7.2 に移ったことで生じた受け手の変更の候補。
  候補の一覧は `docs/design/userspace/wgstack-receive-linux72.md` にあります
- dial の側と server の Device ([dial の側を足す継ぎ目](#dial-の側を足す継ぎ目))
- 送信の経路の system call のまとめ (Linux の `sendmmsg` と UDP の GSO) と、受信の経路のまとめ。
  目標と制約は [速さを制限しない経路の agent の性能](agent-throughput.md#目標) にあります
- 受ける向きの大きな転送の間の UDP の遅れ:速さを制限しない経路で、client から LAN へ大きな TCP の転送が走る間、UDP の中継の往復の p50 が約 7 ms で、gVisor の約 3 ms より長くなります。
  本番のゲームの UDP の流れに対する gVisor からの後退です。
  UDP の datagram は、WireGuard のソケットの受信の待ち行列に溜まった TCP のデータの後ろに並びます。
  待ち行列の量は wgstack の受信の窓と、その上はソケットの受信のバッファで頭を打ちます ([UDP の往復の遅れ](agent-throughput.md#udp-の往復の遅れ))。
  直し方は、遅れの目標で受信の窓を頭打ちにする変更として、バッチの作業の [受信の窓の段](agent-throughput.md#受信の窓の段) で行います
- 不要な速い再送の取り消し:再送を確認した最初の ACK で判定する Eifel の検出 (RFC 3522) と、RFC 4015 の応答。
  同じ TSval の刻みの中で再送した回復も取り消せるようにします ([qbench での測定](#qbench-での測定)の `send/reorder`)。
  凍結した Go の wgstack と出力が変わるので、Go の記録との bit の一致を求める期間が終わった後に入れます

## 実装の時に決めること

- 写さずに読み書きする口:`read_slices` と `write_slices` を足すか。CPU を測ってから決めます
- device の層との受け渡し:`Device::poll_packet` と `Device::poll_transmit` が packet ごとに確保する形を、呼び手の buffer に書く形に替えるか。
  2026-11-02 に使い回す形に決めました ([決めたこと](#決めたこと))。
  実装はバッチの段と一緒に入れます
- 受け付けるアドレスが増えたときの待ち受けと UDP の endpoint の表の持ち方 (dial の側を足すときに決めます)
- 1 回の起床の上限:1 回に作る packet の数と、`WGFT_AGENT_BATCH_MIB` から導く式
- glibc に動的に結ぶ build:バッチの段で写しを減らした後に、musl の静的な build との差を測り直して決めます ([決めたこと](#決めたこと))
- 割り当て器の丸めの係数:OS の標準の割り当て器の係数を測ります

## 未確認の点

- Rust の wgstack の byte あたりの CPU は qbench の子のプロセスとして測りましたが、Go の wgstack と gVisor は試験と同じプロセスで動くので、qbench の中での比は測っていません。segment ごとの費用は Go の wgstack と比べました ([qbench での測定](#qbench-での測定))
- 1 つのスレッドのデータプレーンが、Windows と macOS の時計の分解能とスケジューラの下で、遅延 ACK と RTO の規則を保てるかは確かめていません
- FMA を使わない build で作った記録の浮動小数点の値に、Rust が同じ値で並べるかは、記録を作るまで分かりません
- 確保の数えで測る保持と RSS の比は、Rust の agent では測っていません

[v2: Rust への移行](README.md)
