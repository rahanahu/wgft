# Rust の agent が Go の agent を置き換えるための設計

この文書は、v2 の Rust の agent が Go の v1 の agent のユーザー空間モードを置き換えるまでに要るものを定めます。
対象は、Rust の wgstack 自身を除くすべてです。
契約は [agent と server の境目の仕様](../spec/README.md) です。
この文書は、その契約を Rust の agent でどう満たすかと、どの順で作るかを書きます。
実装済みの段は「設定の層」、「platform の層」、「agent の device の殻」、「宛先と予算」、「制御ソケット」、「agent doctor の骨組み」、「agent doctor の稼働中の検査」、[ラボの切り替え](#ラボの切り替え)、「wgstack の上の agent」です。ほかの内容は未実装です。

## 範囲と完成の条件

置き換える対象は、agent のホストで使う Go の v1 の `wgft` のうち、ユーザー空間モードの agent とその周りのコマンドです。
具体的には `wgft agent run`、`agent pubkey`、`agent rotate-key`、`agent doctor`、`agent teardown`、`wgft version` です。

次のものはこの文書の範囲の外です。

- Rust の wgstack:sans-IO の TCP/IP の核 (`crates/wgft-wgstack`) と、中継が使う handle の層 (`crates/wgft-netstack`) と、その上界と、Linux との照合です。
  [wgstack の Rust 版の設計 (#681)](https://github.com/rahanahu/wgft/pull/681)が定めます。
  この文書はその口の上に書き、前提を各節に明記します
- agent のカーネルモード:移行の順のとおり最後の段で移します
- VPS の側のコマンド:`wgft agent join-string`、`agent ls`、`agent disable` などの管理用 API のコマンドと、`server`、`rule`、`status` です。
  server を移す段で扱います

WireGuard の device の殻、データプレーンの event loop、中継はこの文書が受け持ちます。
event loop とスレッドの形は、#681 の `docs/design/v2/wgstack-rs.md` の「agent の event loop での使い方」の節を唯一の正本とし、この文書は[データプレーンのスレッドと送る経路](#データプレーンのスレッドと送る経路)でそれを実装する規則だけを足します。
#681 が入った後、この参照を文書の中のリンクに直します。

完成の条件は、ラボの一式の agent の確認を Go の agent の代わりに Rust の agent で流し、server のカーネルモードとユーザー空間モードの両方ですべて通ることです。
どの確認が条件に入るかは[ラボの切り替え](#ラボの切り替え)に書きます。
製品の経路は root も TUN も使いません。

段の途中で `feat/v2-rust` に入れ、後の段で解く制約は次のとおりです。

- v2.0.0 の前に解く制約:`agent doctor` と `agent teardown` は、カーネルモードの記録を持つデータディレクトリを終了コード 3 で拒みます。
  agent のカーネルモードを移す段で外します

## 今の Rust の agent

「wgstack の上の agent」の段の時点で、Rust の agent は次を持ちます。
作りは [Rust の agent の制御プレーン](agent-control.md) と [agent の WireGuard の device の層](wireguard-device.md) にあります。

| crate | 持つもの |
| --- | --- |
| `wgft-proto` | wire の版 1 の型、接続文字列、登録の要求と応答、理由の整形、仕様の fixture との照合 |
| `wgft-wireguard` | sanstun の上の sans-IO の WireGuard の device |
| `wgft-wgstack` と `wgft-netstack` | Rust の wgstack の sans-IO の核と、その上の非同期の handle |
| `wgft-wireguard-tun` | 試作の Linux の TUN の殻。agent は使わず、`lab/wg-interop.sh` の道具として残す |
| `wgft-agent` | 登録、認証情報、stream、全体状態の適用、ハートビート、トンネルの監視と作り直し、データプレーンのスレッド、wgstack の上の TCP の中継、制御ソケット、設定の層 (module `config`) |
| `wgft` | `wgft agent` のコマンドと `wgft version`。clap への接続と、設定を読んで入口を通す手順 |

トンネルの packet はプロセスの中の wgstack で終わるので、root も `CAP_NET_ADMIN` も要りません。
UDP のルールは `error` を報告するだけです。
設定は[設定の層](#設定の層)が読みます。カーネルモードは持たない機能なので終了コード 3 で拒みます。宛先の許可一覧とフロー数の上限は[宛先と予算](#宛先と予算)の作りで効かせます。バッチの予算は、値を受けて、まだ効かせていない旨を 1 行出します。

## 差分の一覧

Go の v1 の agent と仕様に対して、今の Rust の agent に無いものと違うものを挙げます。
「段」の列は[段の計画](#段の計画)の PR の名前です。
「wgstack」は wgstack の担当が作り、この文書の段はそれを使うだけのものです。
「Go の性質」は、仕様の書き方と同じく、Go の標準ライブラリか実行環境の性質で決まる v1 の挙動です。

### トンネルとデータプレーン

| 項目 | 仕様 | 今の Rust | 段 |
| --- | --- | --- | --- |
| TUN とカーネルの TCP/IP | [tunnel.md の範囲と前提](../spec/tunnel.md#範囲と前提)。netstack はプロセスの中に持ち、ホストのアドレスと経路と firewall を変えない | 仕様のとおり。データプレーンのスレッドの Rust の wgstack で終える | 「wgstack の上の agent」で済み |
| トンネルの入口の検査 | [tunnel.md のトンネルの入口の検査](../spec/tunnel.md#トンネルの入口の検査)。断片の再組み立て、MSS の下限、ICMP の誤りの送信元、UDP の受信の予算 | wgstack の核が持つ。`inbound` の module は消した | wgstack と「wgstack の上の agent」で済み |
| 入口の検査が捨てた数 | [tunnel.md のトンネルの入口の検査](../spec/tunnel.md#トンネルの入口の検査)。捨てた数を数え、英語のログに 1 分に 1 回まで出す | 核が理由ごとの数と門を持ち、データプレーンが Go の wgstack と同じ文面で出す | 「wgstack の上の agent」で済み |
| 待ち受けの無いポート | SYN に RST、UDP に Port Unreachable | 仕様のとおり (核) | wgstack で済み |
| MSS | MTU から 40 を引いた値を示す | 仕様のとおり (核) | wgstack で済み |
| keepalive の ping | [tunnel.md の keepalive の ping](../spec/tunnel.md#keepalive-の-ping) | wgstack の ping の endpoint から送る | 「wgstack の上の agent」で済み |
| MTU | server は 576 から 9216 を送る。v1 の agent は検査しない | 576 から 9216 は核にそのまま渡し、外なら 1420 を使う | 「wgstack の上の agent」で済み |
| WireGuard のソケットのバッファ | [socket-buffers.md](../userspace/socket-buffers.md)。7 MiB を要求し、FORCE も試し、トンネルを立てるたびに測り、条件に届かなければ英語の 1 行を出す | 仕様のとおり。`agent doctor` の `tunnel.socket_buffers` も載せる | 「agent の device の殻」と「wgstack の上の agent」で済み |
| 受信の誤りで止まらないこと | [tunnel.md の受信の goroutine の停止](../spec/tunnel.md#go-の性質受信の-goroutine-の停止)。Windows の `WSAECONNRESET` | データプレーンが Windows で `SIO_UDP_CONNRESET` を切り、受信の誤りを数えて読み続ける | 「agent の device の殻」と「wgstack の上の agent」で済み |
| サスペンドの間の時計 | [tunnel.md のサスペンドの間の時計](../spec/tunnel.md#go-の性質サスペンドの間の時計)。Windows ではスリープの間も進む時計 | データプレーンの時計が持ち ([時計](#時計))、トンネルの監視も同じ時計で測る | 「wgstack の上の agent」で済み |
| 新しいハンドシェイクで stream の待ちを打ち切ること | [tunnel.md のハンドシェイクの監視と作り直し](../spec/tunnel.md#ハンドシェイクの監視と作り直し) | 見張りが新しいハンドシェイクを観測したら、待ちを打ち切って直ちに繋ぎ、待ちを 1 秒に戻す | 「agent の device の殻」 |

### 中継

| 項目 | 仕様 | 今の Rust | 段 |
| --- | --- | --- | --- |
| TCP の中継の土台 | [tunnel.md の TCP の中継](../spec/tunnel.md#tcp-の中継) | トンネルの側は `wgft-netstack` の handle | 「wgstack の上の agent」で済み |
| 終わり方の表 | 上限と拒否は握手の後に RST、宛先の失敗は FIN、ポートの消滅と停止は RST | handle の `abort` と `close` に写す ([中継との継ぎ目](#中継との継ぎ目)) | 「wgstack の上の agent」で済み |
| 中継が終わった後の末尾の配送 | Go の性質:`netpipe.PipeHold` と `AwaitDelivered`。両側が送り残しを届け終えるまで枠を持つ | 同じ規則 ([中継との継ぎ目](#中継との継ぎ目)) | 「wgstack の上の agent」で済み |
| LAN の側のソケットの受信の扱い | [wgstack.md の今の境目](../userspace/wgstack.md#今の境目) の `OnBoost` と `FollowBoost` | `LanSockets` の hook で同じ値に固定する。Linux だけ | 「wgstack の上の agent」で済み |
| LAN の側の TCP の keepalive | Go の性質:宛先への接続は `net.Dialer` の既定の keepalive を持つ。無通信 15 秒、間隔 15 秒、9 回 | socket2 で同じ値を付ける | 「宛先と予算」で済み |
| 宛先への接続の試し方 | [tunnel.md の宛先への接続の試し方](../spec/tunnel.md#go-の性質宛先への接続の試し方)。同じ族を先に、300 ミリ秒後にもう一方、期限をアドレスで分ける | 仕様のとおり。許可一覧の有無によらず同じ試し方 | 「宛先と予算」で済み |
| 宛先の名前の解決 | Go の性質:Go の resolver で引き、RFC 6724 の順に並べる。許可一覧があれば 5 秒の期限 | [名前の解決](#名前の解決)のとおり。同じ名前を引く途中の呼び手は結果を相乗りする | 「宛先と予算」で済み |
| 宛先の試し接続 | [tunnel.md の宛先の試し接続](../spec/tunnel.md#宛先の試し接続)。待ち受けを開いたときと 30 秒ごと、2 秒、32 件 | 仕様のとおり。期限 2 秒は名前の解決を含む | 「宛先と予算」で済み |
| 宛先の許可一覧 | [targets.md の宛先の許可一覧](../userspace/targets.md#宛先の許可一覧) | IP リテラルは適用のとき、ホスト名は接続のときに判定する | 「設定の層」と「宛先と予算」で済み |
| ブロードキャストとマルチキャスト | [targets.md](../userspace/targets.md#ブロードキャストとマルチキャストの宛先) | 拒む。判定の単位と報告は許可一覧と同じ | 「宛先と予算」で済み |
| フロー数の上限 | [tunnel.md のフロー数の上限](../spec/tunnel.md#フロー数の上限) と [flow-limits.md](../userspace/flow-limits.md)。プロセス全体とルールごと、最低分と予備、拒否の理由 | TCP の中継が使う。UDP の pool は作るが、使うのは「UDP の中継」 | 「宛先と予算」で済み |
| UDP の中継 | [tunnel.md の UDP の中継](../spec/tunnel.md#udp-の中継) | ルールを `error` にする | 「UDP の中継」。設計は [UDP の中継](#udp-の中継) |

### 制御ソケットと診断

| 項目 | 仕様 | 今の Rust | 段 |
| --- | --- | --- | --- |
| 制御ソケット | [control-socket.md](../spec/control-socket.md)。`rotate-key` と `doctor` | 済み。応答の中身は [応答の中身の今の範囲](#応答の中身の今の範囲) | 「制御ソケット」と「wgstack の上の agent」 |
| `agent doctor` | [control-socket.md の agent doctor --json](../spec/control-socket.md#agent-doctor---json) と [検査の一覧](../diagnosis/agent-evidence.md#検査の一覧と証拠の出どころ) | CLI の検査と、agent の応答のフロー数の予算、セッションとフローの数、宛先の誤り、ソケットのバッファ、UDP の会計は済み | 「agent doctor の骨組み」、「agent doctor の稼働中の検査」、「wgstack の上の agent」 |

### CLI と設定

| 項目 | 仕様 | 今の Rust | 段 |
| --- | --- | --- | --- |
| コマンド | [cli-config.md のコマンド](../spec/cli-config.md#コマンド) | `agent run`、`pubkey`、`rotate-key`、`doctor`、`teardown` の拒否、`version` | 「制御ソケット」と「agent doctor の骨組み」 |
| `wgft version` | 2 行。版と `protocol range: v1-v1` | 2 行。版はビルドの時の環境変数 `BUILD_RELEASE_VERSION` で埋め (実行時の設定ではない)、無ければ `dev-rust-<crate の版>` | 済み |
| `--version` と `-v` | 版の 1 行 | 版の 1 行 | 済み |
| 優先順位 | フラグ、環境変数、dotenv、既定。出所を覚える | 出所を覚えて解決する。clap の `env` は使わない | 済み |
| dotenv | [cli-config.md の dotenv の構文](../spec/cli-config.md#dotenv-の構文)。読み取りの誤りと権限の文面 | 仕様と fixture のとおり | 済み |
| 有効な設定の行 | [cli-config.md の有効な設定の行](../spec/cli-config.md#有効な設定の行) | fixture と同じ | 済み |
| 入口での検査の順 | [cli-config.md の入口での検査の順](../spec/cli-config.md#入口での検査の順) | 仕様の順 | 済み |
| `WGFT_WG_INTERFACE` の検査 | `dev_valid_name` に合わせた判定と文面 | 仕様のとおり | 済み |
| `WGFT_MODE=kernel` | Linux 以外は Linux の前提の拒否。Linux では「このビルドにカーネルモードが無い」拒否 | 仕様のとおり | 済み |
| 整数のフラグ | Go の整数の書き方 (`0x`、先頭の 0 の 8 進、`_`) | 仕様のとおり | 済み |
| 真偽値のフラグ | `--json` と `--json=false` の形だけ | 値の解釈と clap の属性を持つ。使うコマンドは「制御ソケット」と「agent doctor の骨組み」が足す | 済み。コマンドは各段 |
| フラグの誤りの出力と終了コード | `Error: <文>` の 1 行で使い方を書かない。終了コード 1、`agent doctor` は 2 | 仕様のとおり | 済み |
| 既定のパス | Linux、macOS、Windows の表。macOS は `$HOME`、Windows は `%ProgramData%` | 済み (`platform::paths`)。3 つの OS の表をどの OS の試験でも確かめる。設定の層の `config::Defaults::for_host` はその薄い包みである | 済み |
| 設定ファイルの権限の警告 | Unix で other が読める dotenv が `WGFT_JOIN` を持つとき | 仕様のとおり | 済み |
| メモリの行 | `memory soft limit:` の行。Go 以外は書かなくてよい | 無い | 「UDP の中継」が `memory bound:` の行を書く。[メモリの上界の行](#メモリの上界の行) |
| `docs/cli.md` | Go の `TestCLIDocUpToDate` | 無い | 「CLI の文書の照合」 |

### 認証情報と platform

| 項目 | 仕様 | 今の Rust | 段 |
| --- | --- | --- | --- |
| Windows の DACL | [credentials.md の Windows の DACL](../spec/credentials.md#windows-の-dacl) | 済み (`platform::winsec`)。Windows の CI で確かめる | 「platform の層」 |
| ロック | `flock` と `LockFileEx` | `File::try_lock` で同じ方式 | 済み。Windows の試験は「platform の層」で足した |
| 一時ファイルの片付け | ロックを取った後に消す | 消す | 済み |
| 時刻の印の水位 | Go の agent には無い | `agent.json.clock` に残す | 済み。Rust だけのファイルで、Go の agent は読まない |
| ファイル記述子の上限 | Go の性質:Go の実行環境は Unix で起動の時に soft の `RLIMIT_NOFILE` を hard の値まで上げる。macOS では `kern.maxfilesperproc` で頭を打つ。同梱の unit と plist は `LimitNOFILE` を書かず、これに頼る | 済み (`platform::fdlimit`)。`wgft` の起動で呼ぶ | 「platform の層」 |

## UDP の中継

UDP の中継の契約は [tunnel.md の UDP の中継](../spec/tunnel.md#udp-の中継) です。
作りの理由は [UDP の中継と応答のバッファ](../userspace/udp-relay.md) と [UDP の受信と出力の会計](../userspace/udp-accounting.md) にあります。
Rust の agent は、結果を v1 と同じにし、仕組みを Rust の非同期の実行環境に合わせます。

### wgstack の UDP の口

UDP の中継は、[wgstack の Rust 版の設計 (#681)](https://github.com/rahanahu/wgft/pull/681)の口を使います。
核の操作は待たずに戻り、待ちは handle の層 (`netstack`) が準備の知らせ (`UdpReadable`、`UdpWritable`) で作ります。
#681 の設計が次の意味を変えた場合は、この節を同じ PR か直後の PR で直します。

| 口 | 意味 |
| --- | --- |
| `bind_udp` | トンネルのアドレスとポートで、接続しない endpoint を開きます。同じポートが使用中なら誤りを返し、中継はルールを `error` にして理由を `udp/<port>: bind ...` の形で報告します |
| `recv_from` | 呼び手のバッファに中身を写し、長さと送信元を返します。写した時点で、核はその datagram の受信の予約を返します。handle の層は読む物が無ければ `UdpReadable` を待ちます |
| `send_to` | 送信の予算 (Device の全体と endpoint 1 つの上限) を予約できなければ `WouldBlock` を返し、handle の層は `UdpWritable` を待ちます。MTU を超える datagram は核が DF を立てずに断片に分けます |
| `close_udp` | endpoint を閉じ、受けて読まれていない datagram の予約を返します。送り残しの datagram は、Go と同じく送り終えた時に予約を返します。handle の層は待っている受け取りと送るを解きます |
| `stats` と `poll_log` | 理由ごとの捨てた数と、1 分に 1 回までの門を通ったログの知らせです。agent が英語の 1 行にしてログに出し、`agent doctor` にも使います。MSS の下限で捨てた数もここから取ります |
| `udp_receive_fault` | Device の UDP の会計が不変条件の違反で止まっていれば、最初の違反を返します。`agent doctor` の `tunnel.udp_accounting` に使います |

次のことは wgstack の中で行い、中継は関わりません。

- 受信の予算:Device の全体で 4 MiB と 4096 件、endpoint 1 つでその 4 分の 1 です
- 待ち受けの無いポートへの UDP に Port Unreachable を返すこと
- 待ち受けに届いた Port Unreachable を捨てること

中継の task はデータプレーンのスレッドの local の task として動き、handle の層を通して核を呼びます。

### セッション

- 鍵:待ち受けごとに、送信元の IPv4 のアドレスとポートでセッションを引きます
- 受け取りのバッファ:待ち受けごとに 65535 byte のバッファを 1 つ持ちます。
  v1 の待ち受け 1 つの固定費と同じです ([flow-limits.md](../userspace/flow-limits.md))
- 作るとき:新しい送信元の最初の datagram で、次の順に作ります。
  1. フロー数の予算 (後述) で 1 本を予約します。
     予約できなければ datagram を ICMP を返さずに捨て、拒否を理由ごとに数えます
  2. ルールの実効宛先の名前を[名前の解決](#名前の解決)で解決します
  3. 解決したアドレスを、ユニキャストの判定と許可一覧で順に判定します
  4. 通ったアドレスへ、OS の UDP のソケットを開いて接続します。
     macOS では送信バッファを 65535 byte に上げます
  5. 最初の datagram を宛先へ送ります
- 宛先が使えないとき:どのアドレスにも接続できなければ予約を返し、datagram を捨てます。
  捨てたことは待ち受けごとに 1 分に 1 回までログに出します
- 名前の解決を待つ場所:v1 と同じく、待ち受けの受け取りのタスクの中で待ちます。
  この間、その待ち受けの受け取りは止まり、datagram は wgstack の endpoint の上限の中に溜まります。
  別のタスクに出すと、解決の間に届く同じ送信元の datagram を置く場所と上限が新しく要るためです

### 向き

- トンネルから宛先へ:待ち受けのタスクが受け取り、セッションのソケットへ書きます。
  書き込みの失敗でセッションを閉じ、そのことを待ち受けごとに 1 分に 1 回までログに出します
- 宛先からトンネルへ:セッションごとのタスクが、バッファを持たずに読みの準備と誤りを待ちます。
  待ち方は tokio のソケットの `ready(Interest::READABLE | Interest::ERROR)` です。
  読める準備が来たら、応答のバッファの枠を 1 つ借ります。
  枠に `try_recv` で datagram の全体を読み、`send_to` で核へ渡します。
  渡し終えたら枠を返します。
  準備が偽で読む物が無ければ、枠を返して待ちに戻ります
- 宛先の誤り:誤りの準備が来たら `take_error` を読みます。
  Linux は接続した UDP のソケットへの ICMP の拒否を `EPOLLERR` だけで知らせ、読める準備を立てないためです。
  `take_error` はソケットの誤りを取り出して消すので、続けて `try_recv` を呼んでも `WouldBlock` が返るだけです。
  このため、`take_error` が返す誤りか、読める準備で呼んだ `try_recv` が返す誤り (Linux と macOS の `ECONNREFUSED`、Windows の `WSAECONNRESET`) のどちらかでセッションを閉じます。
  トンネルへ ICMP は送りません。
  同じ送信元の次の datagram で新しいセッションを作ります

到着だけを待つ仕組みは、v1 では Unix の 1 byte の `MSG_PEEK` と Windows の 0 byte の `WSARecv` でした。
Rust では tokio (mio) の readiness が同じ役割を果たします。
Linux の epoll の振る舞いは上のとおりです。
macOS の kqueue と Windows の AFD の poll で、到着と ICMP の拒否が同じ待ち方で取れるかは確かめていません。
CI の単体の試験で確かめる予定です。
取れない OS があれば、その OS だけ待ち方を変えます。

### 応答のバッファの枠

- 数:プロセス全体で 64 個、1 個は 65535 byte です。
  `tokio::sync::Semaphore` の許可で数え、バッファの置き場はプロセスで 1 つの pool です。
  データプレーンのスレッドはトンネルの世代ごとに替わるので、pool はスレッドの外に置き、世代の間で数を保ちます
- 保持の上界:pool が作るバッファを 64 個までにし、貸している枠と返された枠の置き場を合わせて 64 × 65535 byte です。
  セッションの数、ルールの本数、OS によりません。
  Go の pool は返されたバッファの回収を GC に任せましたが、Rust の pool は作った分を持ち続けるので、置き場も上界に入れて数えます
- 枠を持つ間の仕事:読み取り 1 回と、`send_to` での 1 回の受け渡しです。
  `send_to` が `WouldBlock` を返して `UdpWritable` を待つ間は枠を持ち続けます。
  v1 と同じく、送信の予算が尽きるのはトンネルの送信が止まったときで、そのときは全ルールの応答が同じく止まるので、枠がルールの間の新しい飢餓を作りません
- 待ちを解くとき:待ち受けを閉じたときと、セッションを閉じたときです
- 待ちの観測:待った回数と時間を内部で数えます。
  ログ、`agent doctor`、wire には出しません

### 無通信の期限

- 期限:全体状態の `wg.udp_timeout_stream` の秒数です。
  0、負の値、2147483647 を超える値は 120 秒です
- 延長:どちらの向きの datagram も期限を延ばします
- 点検:期限の 4 分の 1 ごとに、20 ミリ秒を下限として点検します。
  セッションは期限から期限の 1.25 倍の間に閉じます
- `wg.udp_timeout`:使いません
- 照合:期限の既定と点検の間隔は `testdata/spec/tunnel/relay-timing.json` と照らします

### 閉じるとき

- セッションを閉じる:宛先のソケットを閉じ、セッションのタスクを止め、フロー数の予約を返します
- 待ち受けを閉じる:ルールの削除、無効化、実効宛先の変更、agent の停止で閉じます。
  持つセッションをすべて閉じ、wgstack の待ち受けを閉じます
- トンネルの作り直し:wg の変更、`rotate-key`、作り直しの閾値では、全部の待ち受けとセッションを閉じます

### フロー数の予算

Go の `internal/resource` の pool を Rust に移します。
規則は [flow-limits.md](../userspace/flow-limits.md) と [7a.10 節](../resource/admission.md#7a10-resource-guard-の再設計) が正本です。

- プロセス全体の上限:`WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS` です
- ルールごと:プロセス全体の上限から導く上限と、最低分と、予備です
- 拒否の理由:`budget`、`rule_cap`、`reserve`、`floor`、`spare` で、ルールと理由ごとに数えます。
  数はトンネルを作り直すと 0 に戻します
- 上限に当たったとき:新しいフローだけを拒みます。
  UDP は datagram を ICMP を返さずに捨て、TCP は握手の後に RST で閉じます。
  拒んだことは待ち受けごとに 1 分に 1 回までログに出します

pool は I/O を持たない型にし、Go の pool の試験を Rust の単体の試験に移します。
TCP と UDP の中継の両方がこの pool を使うので、「宛先と予算」の段で TCP の中継と一緒に入れます。

### 試験

- 単体:wgstack の核を試験の殻で動かし、宛先はループバックの UDP のソケットにします。
  期限、点検の間隔、枠の数の上限、待ち受けの閉鎖で待ちが解けること、宛先の Port Unreachable でセッションが閉じること、フロー数の拒否で ICMP を返さないことを確かめます
- OS:同じ試験を CI の Windows と macOS でも流します
- ラボ:`e2e.sh` の UDP と 3000 byte の UDP、`usage.sh` のゲームのような UDP、`split-merge.sh` のセッションの継続、`lifecycle.sh` の予算の確認です

## データプレーンのスレッドと送る経路

データプレーンは、#681 の「agent の event loop での使い方」のとおり、トンネルの世代ごとに 1 つの OS のスレッドで動きます。
そのスレッドが WireGuard の device、wgstack の核、WireGuard の UDP のソケットを 1 つの値として持ち、中継の task も同じスレッドで動きます。
制御プレーン (stream、ハートビート、制御ソケット) は別の実行環境に置き、容量の決まった channel で命令を送ります。
この文書は、その形に次の規則を足します。

- 送る経路の順:起床のたびに、まず `Device::poll_transmit` が出す datagram を、ソケットが書ける間すべて送ります。
  wgstack の核の出力 (`poll_transmit`) を引くのは、device にセッションがあり、device の送る datagram のキューが空の間だけです。
  セッションが無い間に引くと、packet はハンドシェイクを待つ device のキューに溜まり、溢れて古いものから捨てられるためです。
  キューが空でない間に引くと、詰まりが核の外の device のキューに移り、核の出力の詰まりとして TCP の再送で回復する性質を失うためです
- 起こし方:中継の task が出力を生みうる核の操作 (書き込み、読み取り、close、abort、`send_to` など。一覧は [wgstack-rs.md の操作の知らせ](wgstack-rs.md#操作の知らせ)) をするたびに、データプレーンのスレッドの local の知らせを鳴らし、駆動する task を起こします。
  核の出力は操作の結果として増えるので、ソケットの準備やタイマーを待たずに引くためです。
  知らせは同じスレッドの中だけで使うので、`tokio::sync::Notify` でなく、印の `Cell<bool>` と駆動の task の waker の `Cell` で作り、錠を取りません。
  待つ者がいない間の知らせは印として残り、次の待ちがすぐに解けます
- 上界:1 回の起床で作る packet の数の上限は #681 の値に従います
- 時計:device と核に渡す時刻の時計は同じものにします ([時計](#時計))

agent の device の殻の段は、この節を `crates/wgft-agent/src/dataplane` に実装しました。
「wgstack の上の agent」の段で、核を繋ぎ、agent の経路をこのデータプレーンに替えました。
止め方には次の規則を足しました。

- 止めるときの最後の送り出し:止める命令で駆動の task が終わると、スレッドは local の task (中継と ping) を落とした後に、核に残った出力を 1 回だけ送り出してから実行環境を落とします。
  落ちる handle の `Drop` は接続を `abort` し、RST を核の制御の輪に積みます。
  駆動の task がもう動かないので、この送り出しが無いと RST がトンネルに出ません。
  agent は先に中継を閉じてから止めるので、ふだんの RST は駆動が動いている間に出ます。
  この送り出しは、中継を閉じずに止まった場合の残りのためです。
  上限は 4096 packet で、セッションが無いかソケットが書けなければ送らずに終えます。
  毒の印の後は核に触らないので送りません。
  `abort` の RST は核の制御の輪 (256 枠) に積むので、送り出しの前に輪に入るのは 256 本までです。
  それを超えた RST は核が捨てて `CtlDropped` に数えます。
  その接続の server の側は、次の segment が接続を持たない核 (作り直した後の世代) に届いて RST を受けるか、自分の再送の打ち切りで終わります

### 核との継ぎ目

核と `wgft-netstack` の waker の表は、`Upper` の trait の背後に置きます。
核の段は、核と waker の表をこの trait で包んで繋ぎます。

- 入力:`handle_packet`、`handle_timeout` です。
  時刻はデータプレーンの時計の `Instant` で渡し、核の `Time` への変換は包む側が行います
- 出力:`poll_transmit` は呼び手の MTU の長さの buffer に書きます。
  `poll_timeout`、`poll_wakers`、`poll_log` が次に起こす時刻、起こす waker、ログの行を出します。
  駆動の task は waker を借用を返した後に起こし、ログの行に時刻を付けて出します
- 作成:作成の関数はデータプレーンのスレッドの上で呼び、作成の時刻、MTU、前の世代の `Budget` を受けます。
  `Budget` が無いときは新しく作ります。
  核の設定の検査は呼び手 (`tunnel`) が制御プレーンで先に済ませます。
  作成は失敗しうる形 (`Result<U, UpperError<B>>`) にしました。
  核の作成 (`Netstack::new`) と `Budget::new` は確保に失敗しうるためです。
  失敗した作成は受けた `Budget` を `UpperError` で返し、データプレーンの作成の失敗 (`StartError`) が carry に入れて呼び手に返すので、次の試みに予算が渡ります。
  確保の失敗を panic にすると、予算を失い、作り直しの規則でなく巻き戻しの経路に入るためです
- 終わり:`close` が `Budget` を返します
- 操作:`Local` が核への借用を貸します。
  `with` は出力を生まない操作に、`operate` は出力を生みうる操作に使い、`operate` は借用を返した後に駆動の task を起こします。
  借用の間に巻き戻しが起きたら毒の印を付けて駆動の task を起こします。
  借用の前から巻き戻しの途中だった場合は、巻き戻しで落ちる handle の `Drop` の借用なので印を付けません
- 命令:制御プレーンは容量 16 の channel で、状態の読み出し、endpoint の変更、データプレーンのスレッドで動かす閉包を送ります。
  閉包は local の task を立てられるので、待ち受けの開閉と ping の命令はこの形で足します
- handle の層:`wgft-netstack` の handle は `Access` の trait を通して核を借用します。
  核の段は `Local` に `Access` を、`Netstack` (核と waker の表) に `Upper` を実装します ([PR 7 で決めたこと](wgstack-rs.md#pr-7-で決めたこと))

### 送り出しと受信の値

- 1 回の起床の上限:核から引く packet と、ソケットから読む datagram は、どちらも 1 回の起床で 64 までにします。
  上限で止まったときは他の task に順を譲ってからすぐに起きます。
  値は仮の値で、`WGFT_AGENT_BATCH_MIB` から導く式と一緒に送信の経路を測ってから決めます
- 書けない datagram:ソケットが `WouldBlock` で拒んだ datagram は 1 つだけ持ち、書けるようになるまで何も引きません。
  ほかの送信の誤りは数えて捨てます
- 受信の誤り:数えて読み続けます。
  受信の誤りでデータプレーンを止めません ([受信の goroutine の停止](../spec/tunnel.md#go-の性質受信の-goroutine-の停止))
- ハンドシェイクを始める時機:セッションが無い起床のたびに `Device::start_handshake` を呼びます。
  進行中のハンドシェイクがあれば何もしません。
  server が答えない間は、5 秒ごとの再送が 90 秒続いてピアが期限切れになると、同じ起床で次の再送の組が始まります。
  device の層だけなら、期限切れの後は keepalive の間隔だけ待ってから始めます。
  データプレーンは核に送るものがあるかを知らないので、この待ちを置きません。
  違いは組の間の最大 25 秒の間隔だけで、再送の頻度は 5 秒に 1 回のままです
- device の event:容量 256 の channel に流し、溢れたものは捨てます

### WireGuard の UDP のソケット

- 開き方:IPv4 の 1 つのソケットを、既定では `0.0.0.0` の任意のポートに bind します。
  v1 の agent と同じく、ポートはトンネルを立てるたびに変わります
- バッファ:bind の前に受信と送信のバッファを 7 MiB ずつ要求し、Linux では `SO_RCVBUFFORCE` と `SO_SNDBUFFORCE` でも要求し、どの誤りも無視します。
  bind の後に Linux だけで `SO_RCVBUF` と `SO_SNDBUF` を読み、どちらも 14680064 に届かなければ Go と同じ文面の警告を 1 分に 1 回までログに出します ([socket-buffers.md](../userspace/socket-buffers.md))。
  Go はポートの IPv4 と IPv6 のソケットの小さい方を測りますが、Rust の agent のソケットは 1 つで、開いたソケットをそのまま測ります。
  測った値は状態の読み出しで返し、`agent doctor` の `tunnel.socket_buffers` が使います
- Windows:bind の前に `SIO_UDP_CONNRESET` を切ります。
  切れなかったときは英語の 1 行を出して続けます。
  受信の誤りは数えて読み続けるので、切れなくても受信は止まりません

### 時計

データプレーンの時計は、Linux と macOS では `Instant` で、ホストの一時停止の間に止まります。
Windows では `QueryInterruptTimePrecise` の経過を最初に読んだ `Instant` に足した値で、スリープの間も進みます。
v1 と同じ時機で作り直すためです ([サスペンドの間の時計](../spec/tunnel.md#go-の性質サスペンドの間の時計))。
`QueryInterruptTime` でなく `QueryInterruptTimePrecise` を使うのは、Microsoft の説明では前者の値がタイマーの割り込みごとにしか進まず、既定の間隔の約 15.6 ms が核の RTT の測定と遅延 ACK に粗すぎるためです。

Windows の時計は `Instant` とずれうるので、データプレーンの時刻と比べる時刻もこの時計から取ります。
待ちは、残りの時間を tokio の `sleep` で待つことを期限に届くまで繰り返します。
Windows では 1 回の `sleep` を 5 秒までに区切ります。
tokio の timer が使う `Instant` がスリープの間に止まる場合も、復帰から 5 秒以内にこの時計を読み直して期限を判定するためです。
トンネルの監視 (ハンドシェイクの新しさ、作り直しの閾値、トンネルを立てた時刻) も同じ時計で測ります。

### 世代と予算

[世代と予算の受け渡し](wgstack-rs.md#世代と予算の受け渡し)を次の形で実装しました。

- 止め方:`Dataplane::stop` が止める命令を送り、スレッドが駆動の task を終えて実行環境と local の task を落とした後、核の `close` で `Budget` を取り出します。
  呼び手はスレッドを join し、device の `unix_high_water` と `Budget` を `Carry` で受けます
- 毒の印の後:核の `close` を呼ばず、`Budget` を返しません
- 駆動の task の中の panic:駆動の task が呼んだ核の中の panic は、スレッドを巻き戻して終わらせます。
  join はそれを知って英語の 1 行を出し、`Budget` を返しません
- 高い水位:データプレーンは起床のたびに `unix_high_water` を共有の値に書きます。
  スレッドが panic で終わっても、最後に書いた値を次の世代に渡します
- 受け渡し:`Generations` が `Carry` を持ち、次の世代の作成に渡します。
  作成に失敗したら、受けた `Carry` を返し、次の試し直しまで持ち続けます。
  `Generations::exited` は、スレッドがどの理由で終わっても解け、呼び手は作り直しの規則に従って `Generations::start` を呼び直します
- 作り直しの規則:いつ作り直すかは今の監視 (`run.rs`) の規則のままです。
  agent は `Generations` を 1 つ持ち、トンネル (`tunnel::Tunnel`) は今の世代の handle (`dataplane::Handle`) だけを持ちます。
  トンネルの監視の task は handle の `finished` でスレッドの終わりを知り、30 秒を待たずに作り直させます。
  `Generations::exited` と同じ知らせで、制御プレーンの task が `Generations` を借りずに待てる形です。
  トンネルを閉じるときは、先に中継を閉じ、次に `Generations::stop` で予算を carry に残します。
  `agent.json.clock` の水位は `Generations::raise_floor` で carry の下限に入れます

## 名前の解決

宛先の名前 (TCP の接続 1 本ごと、UDP のセッション 1 つごと、試し接続) は、すべて次の 1 つの resolver で引きます。
WireGuard のエンドポイントの名前は A レコードだけを引く別の規則 ([tunnel.md のエンドポイントの解決](../spec/tunnel.md#エンドポイントの解決)) ですが、同じ仕組みの上で引きます。

- 仕組み:OS の `getaddrinfo` を、上限のある blocking のスレッドで呼びます。
  OS の resolver の設定に従うためです
- 相乗り:同じ名前を引いている途中の呼び手は、新しく引かずにその結果を待ちます。
  Go の `net.Resolver` が同じ名前の問い合わせを 1 つにまとめるのと同じです。
  範囲のルールの試し接続と、1 つのルールへの接続のフラッドが、同じ名前で許可を使い切らないためです
- 同時の数:`tokio::sync::Semaphore` で、宛先の名前を同時に引く数を 8 に抑えます。
  相乗りがあるので、許可が抑えるのは同時に引く別々の名前の数です。
  許可を待つ時間も期限に含めます
- エンドポイントの許可:WireGuard のエンドポイントの名前は、宛先の名前とは別の許可 1 つで引きます。
  宛先の名前の解決が許可を使い切っても、トンネルの名前の引き直しが止まらないようにするためです。
  引き直しは同じ名前で相乗りするので、`getaddrinfo` が応答しなければ、その名前の後の引き直しは戻るまで同じ結果を待ち、期限で失敗します。
  許可を増やしても同じ名前には効かず、効くのは名前が変わったときだけなので、1 つにします
- 期限:v1 と同じく、許可一覧の有無で分けます。
  許可一覧が無いときは、名前の解決は接続の期限の 10 秒の中に入ります。
  許可一覧があるときは、名前の解決に 5 秒の期限を持ち、接続の期限の 10 秒は解決の後から数えます ([targets.md の宛先の許可一覧](../userspace/targets.md#宛先の許可一覧))。
  試し接続は、名前の解決を含めた全体を 2 秒で打ち切ります。
  仕様の「1 件の期限は 2 秒」と、Go の v1 が試し接続の全体を 2 秒で打ち切る作りに合わせるためです。
  エンドポイントの名前の期限は 5 秒です
- 期限を過ぎたとき:呼び手は誤りを受け、結果を待ちません。
  スレッドは `getaddrinfo` が戻るまで動き続け、まだ待っている呼び手に結果を配ってから許可を返します。
  このため、応答しない resolver が許可を持ち続けると、後の解決は許可を待って期限で失敗します。
  許可を待つ名前は、呼び手がすべて期限で去った後も、引いている途中の名前の表に残り、許可が空けば引かれます。
  表が育つ上限は、ルールが宛先に書く別々のホスト名の数です
- 順:引いたアドレスは、v1 の Go の resolver と同じ RFC 6724 の宛先の規則で wgft が並べ直します。
  `getaddrinfo` の順は libc と設定 (`gai.conf`) で変わるためです
- 上界:スレッドの数は許可の数で決まり、スレッド 1 本はスタックと `getaddrinfo` の作業の領域を持ちます。
  [メモリの上界の行](#メモリの上界の行)に許可の数 × スレッド 1 本の大きさを入れます

## 宛先と予算

「宛先と予算」の段は、フロー数の予算と宛先の規則を、トンネルの側の作りに依らない 2 つの module に置きました。
「wgstack の上の agent」の段で中継の土台が wgstack に替わり、2 つはそのまま使っています。

### フロー数の予算の作り

- 置き場:`wgft-agent` の module `flowpool` です。
  Go の `internal/resource` の `Pool` を写し、判定の順、帳簿の足し引き、退役した登録のフローの帰属の規則、拒否の理由の語と文を同じにします
- 表の形:登録、待ち受け、cell は添字で引く表に置き、ポインタを辿りません。
  判定は接続 1 本に 1 回で、1 つの排他の中で行います。
  cell は登録と待ち受けの一覧の中の自分の位置を持ち、一覧から外すときに探しません。
  範囲の広いルールでも、排他の中の仕事は一覧の長さによりません
- 枠の返し方:フロー 1 本の枠 (`Lease`) は、落とすと返ります。
  Go の二重の返却は型で起こらないので、その数は持ちません
- 待ち受けの枠:待ち受けを開く前に保留の枠を作り、bind が通ってから受け付けにします。
  bind に失敗した待ち受けと、適用のときに拒んだ IP リテラルの宛先の待ち受けのルールは、ルールの数 N に入りません
- 拒否の数:pool は中継とともにトンネルごとに作るので、数はトンネルを作り直すと 0 に戻ります
- 試験:Go の pool の試験を移しました。
  式から作り直す参照の pool と同じ操作列を流して毎手照らす試験、7a.10 節の場面、拒否の文の期待値、無作為の列、並行の操作、式の性質です。
  拒否の文は Go の試験の期待値をそのまま写したので、Go が生成する fixture は置いていません

### 宛先の規則の作り

- 置き場:`wgft-agent` の module `targets` です。
  許可一覧の判定は設定の層の `AllowList::allows` が持ちます
- 判定の順:ブロードキャストとマルチキャストの拒否を許可一覧より先に見ます。
  許可一覧に加えても通らない宛先だからです
- 判定の時機:IP リテラルの宛先は適用のときに判定し、拒めば待ち受けを開かずにルールを `error` にします。
  30 秒ごとの見回りで開き直すときも同じ判定をします。
  ホスト名の宛先は接続 1 本ごとに、解決したアドレスで判定します
- 許可一覧が無いとき:Go の v1 は名前を `net.Dialer` に渡し、拒否を接続の `Control` で当てていました。
  Rust は許可一覧の有無によらず、自分で解決し、拒まないアドレスだけを同じ試し方で試します。
  違いは、すべて失敗したときに返す誤りの選び方だけです。
  Go の `net.Dialer` は最初の誤りを返し、Rust は許可一覧があるときの v1 と同じく最後に試したアドレスの誤りを返します。
  理由の文言は保証の外です
- 試し方の部品:同じ族を先に試し、300 ミリ秒の後にもう一方の族を並行して試す規則は、接続の関数を引数に取る部品にしました。
  「UDP の中継」の段は、族を分けない同じ部品で接続した UDP のソケットを開きます
- 期限:許可一覧が無いときは名前の解決も 10 秒の中に入り、許可一覧があるときは解決に 5 秒、接続に解決の後から 10 秒です ([名前の解決](#名前の解決))。
  期限を過ぎた接続の試みは、Go と違って自分の期限まで走らせず、その場で閉じます
- LAN の側の keepalive:接続の後に socket2 で無通信 15 秒、間隔 15 秒、9 回を付けます。
  Go の `net.Dialer` と同じく接続の後に付け、付けられなくても接続を使います
- 試し接続:TCP の待ち受けを開いたときと 30 秒ごとに、同時に 32 件まで試します。
  1 件の期限は名前の解決を含めて 2 秒です。
  走らせる分の試し接続だけを作るので、待ち受けの数によらず、同時に持つのは 32 件分です。
  適用は試し接続の結果を待ってから終わります。
  試し接続も許可一覧とユニキャストの判定に従い、拒否はルールの理由になります
- 30 秒ごとの試し接続と排他:見回りは agent の排他の中で試す宛先の一覧を写し、排他を放して試し、結果を書くときだけ排他を取り直します。
  応えない宛先が多いと 1 周は長くなり、その間 stream のハートビートと適用を止めないためです。
  結果を書くときは、試した後に閉じたか、開き直されたか、宛先が変わった待ち受けの結果を捨てます (Go の `applyProbes` と同じ)。
  適用の中の試し接続は、適用が結果を待つ仕様なので排他の中で行います
- stream の ping:stream のタスクは、ハートビートを組むために agent の排他を待つ間、pong を読めません。
  待った長さだけ pong の期限を延ばし、生きている接続を排他の待ちで切りません
- 誤りの文:`server doctor` はルールの理由を語で分類するので ([messages.md のルールの理由の語](../spec/messages.md#ルールの理由の語))、接続の誤りを Go の `net` の形で書きます。
  `dial tcp <アドレス>: connect: <理由>`、期限切れは `dial tcp <アドレス>: i/o timeout`、名前の解決の失敗は `lookup <名前>: <理由>` です。
  `<理由>` は OS の誤りを小文字で書き、拒否、経路が無いこと、到達できないこと、時間切れは OS によらず Unix の文 (`connection refused` など) に揃えます。
  許可一覧の拒否、ユニキャストの拒否、試し接続の期限切れの文は Go と同じです
- 名前の解決の仕組み:引く名前ごとに 1 本の OS のスレッドで `getaddrinfo` を呼び、スレッドの数を許可の数で抑えます。
  宛先の名前は `std::net::ToSocketAddrs` で両方の族を、エンドポイントの名前は `AF_INET` を指定して A レコードだけを引きます。
  許可を待つのは名前ごとの tokio のタスクで、呼び手はそれぞれの期限で結果を待ちます。
  tokio の `spawn_blocking` を使わないのは、実行環境を落とすときに blocking のタスクの終わりを待つためです。
  応答しない resolver があると、トンネルの世代を閉じる処理がそこで止まります。
  許可を待つタスクが実行環境とともに落ちたときは、待っている呼び手が誤りを受け、次の呼び手が引き直します

### 中継との継ぎ目

- 受け付けの順:予算の枠を取ってから宛先へ接続します。
  予算の拒否と宛先の拒否は、トンネルの側を握手の後に RST (`abort`) で閉じ、宛先への接続の失敗は FIN (`close`) で閉じます。
  待ち受けは送信元で絞りません。
  核に届く packet の送信元は device の層の AllowedIPs が server の /32 に限るためです
- 置き場:待ち受けの開閉の帳簿 (`relay::Manager`) は制御プレーンにあり、待ち受けと中継の接続はデータプレーンのスレッドの local の task です。
  帳簿は待ち受けを開くのをデータプレーンへの頼み (`Handle::call`) 1 回にまとめます。
  範囲の広いルールでも往復が待ち受けの数だけ重ならないためです。
  頼みの中で核に待ち受けを開き、開けたら予算の枠を受け付けにしてから受け付けの task を立てます。
  閉じるときは、すべての待ち受けに止める知らせを送ってから終わりを待ちます
- LAN の側:宛先へのソケットは同じスレッドの tokio の実行環境で開きます。
  中継は 2 つの向きを同じ task の中で交互に進めます。
  向きごとに 2 KiB のバッファを持ち、読みがそれを満たしたら 32 KiB のバッファを借り、データが 200 ミリ秒途切れたら返します (Go の `internal/netpipe` の `copyConn`)。
  返したバッファは、データプレーンのスレッドごとに 16 個まで次の借り手のために置き、超えた分は解放します。
  置く分の 16 × 32 KiB は[メモリの上界の行](#メモリの上界の行)の TCP の中継の項に入れます
  片方の向きの EOF は反対側の送る向きを閉じて伝え、読み書きの誤りは両方の向きを止めます
- 中継の終わり:Go の `PipeHold` と `AwaitDelivered` と同じく、トンネルの側を `close` で閉じ、LAN の側は Linux では受信のメモリが 0 なら `shutdown(SHUT_RDWR)` で止め、そうでなければ RST で終えます。
  閉じる側を先にします。
  両側が送り残しを届け終えるまで、`Closing::delivered` と LAN の側の送信のキューの量と状態を、50 ミリ秒から 2 秒まで倍に伸ばす間隔で問い直し、その間は予算の枠と接続の数えを持ちます。
  待ちの途中で待ち受けが閉じられたら、トンネルの側を RST で切ります。
  Linux 以外の LAN の側は、Go と同じく通常の close で閉じて待ちません
- boost の hook:中継は accept の後、最初の読み書きの前に LAN の側のソケットを `LanSockets` に登録し、中継が終わったら外します。
  hook は Go の `FollowBoost` と同じく、boost の間は受信のバッファを 4 MiB、そうでなければ 128 KiB に固定し、窓の上限を 4 MiB に置きます。
  floor に戻す前に受信のメモリが floor を超えていれば戻させません。
  Go の `OnBoost` が登録の時に今の状態で関数を呼ぶのと同じく、組にした時点で floor に固定し、窓の上限を置きます。
  固定しないと、トンネルの側が止まった中継の LAN の側の受信のバッファが `net.ipv4.tcp_rmem` の上限まで自動で育つためです。
  Linux だけで、他の OS では何もしません
- 排他:中継が取る錠は接続 1 本ごとの操作のものだけです (宛先のユニキャストの判定の `getifaddrs` の結果の錠、フロー数の pool の錠、待ち受けの `target_err`、`refuse_log`、`dial_log`)。
  packet ごとの経路は錠を取りません
- 試験の範囲:中継の終わり方 (受け付けの拒否の RST、宛先の失敗の FIN、トンネルの側の末尾の配送、待ちの途中で待ち受けを閉じたときの RST) は、ループバックの試験の server の device と台本の TCP の相手で確かめます。
  LAN の側を `shutdown` で止めて送信のキューの配送を待つことと、閉じる側を先にする順は、ラボの一式だけが確かめます
- 状態:待ち受けの誤りは、bind の失敗か適用のときの拒否を先に、試し接続の失敗か接続のときの拒否を後に報告します。
  接続のときの拒否は、接続が通れば消えます。
  試し接続の失敗は、次の試し接続でだけ変わります
- ログ:次の行は Go と同じ文です。
  `<宛先>` は Go の `net.JoinHostPort` と同じく、`:` を含むホストを角括弧で囲みます。
  `listener tcp/<port> -> <宛先> opened; rule <ID>`、`listener tcp/<port> closed`、`listener tcp/<port>: <誤り>`、`tcp/<port>: <拒否の文>; refusing new connections` (待ち受けごとに 1 分に 1 回まで)、`tcp/<port>: dial <宛先>: <誤り>` (同じ)、`listener tcp/<port>: cannot connect to target <宛先>: <誤り>` と `listener tcp/<port>: target <宛先> is reachable again` (到達性が変わったときだけ) です

## メモリの上界の行

`agent run` は起動の時に `memory bound: <N> MiB, derived from the flow caps; it counts what the process holds, not the kernel socket buffers` を書きます。
Go の `memory soft limit:` の行の代わりで、ラボの `lifecycle.sh` の check 5 と 5b がこの値を読みます。
`<N>` は次の和で、`WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS` から導きます。

- 固定の基礎:実行ファイル、tokio の実行環境、制御ソケットのスレッド、stream と TLS の状態です。
  起動の直後のラボの測定から定数を決めます
- wgstack の上界:核の `bound()` が返す値と、handle の層の waker の表の上界 (`Netstack::waker_bound`) です (#681)
- データプレーンの駆動:1 回の起床で起こす waker を移す `Vec` です。
  waker の表の行の数で頭を打ちます
- WireGuard の device:[device のキューと上界](wireguard-device.md#キューと上界) の値です
- TCP の中継:接続 1 本の固定の大きさと、データが流れる間だけ借りる写しのバッファ (向きごとに 32 KiB、Go の `internal/netpipe` と同じ) の和 × `WGFT_MAX_TCP_FLOWS` と、置き場に残す 16 × 32 KiB の和です
- UDP の中継:応答のバッファの枠の 64 × 65535 byte、セッション 1 つの固定の大きさ × `WGFT_MAX_UDP_FLOWS`、待ち受け 1 つの固定の大きさ × 開いた待ち受けの数です。
  待ち受けの数は server が配る全体状態が決め、agent は上限を持たないので、起動の時の行には待ち受けの数を入れず、行の式から外したことを設計に書きます
- 名前の解決:許可の数 (宛先の 8 とエンドポイントの 1) × スレッド 1 本の大きさです

行に入れないものは、カーネルのメモリ (WireGuard のソケット、宛先のソケットの受信と送信のバッファ) です。
v1 と同じく、宛先のソケットの受信バッファは大きくしません。

ラボの check 5 と 5b は、Rust の agent では RSS がこの値と余裕の和を超えないことを確かめます。
余裕は 32 MiB とします。
上界は保持するバイトを数え、RSS は割り当て器の管理の領域と断片化、触れたスタックの頁、実行ファイルの頁を含むためです。
Go の agent の確認が使う 100 MiB の余裕は GC の目標に対するもので、Rust の上界には大きすぎます。
32 MiB は見積もりで、「UDP の中継」の段のラボの測定で確かめ、足りなければ理由を書いて直します。

ラボの静的なビルドは musl の割り当て器を使います。
musl の割り当て器は解放したメモリを早く OS に返しますが、スレッドの間の競合で遅くなります。
割り当て器を替えるかは移行の調査の未決の点で、替えた場合も余裕の理由は変わりません。

## 制御ソケットと agent doctor

制御ソケットの契約は [control-socket.md](../spec/control-socket.md) です。
診断の意味は [10.2c 節](../diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor) と [総合判定を動かす検査](../diagnosis/agent-judgment.md) にあります。

### 制御ソケットの受け口

- 実行の場所:制御ソケットは専用の OS のスレッドで待ち受けます。
  tokio は Windows の AF_UNIX を持たないためです
- 接続の扱い:接続はそれぞれ短命のスレッドで扱い、同時に扱う数を 4 までにします。
  黙ったまま繋ぎ続ける相手がいても、次の `doctor` が待たないためです。
  超えた接続は、待ち受けのスレッドが 200 ミリ秒の期限で要求を読み、要求の形に合わせた理由の 1 行を書いて閉じます。
  `doctor` には `{"error": ...}` の 1 行を、`rotate-key` には `error: ` の 1 行を返し、要求を読めなければ書かずに閉じます
- ソケット:`socket2` の AF_UNIX を Linux、macOS、Windows で使います。
  `socket2` の AF_UNIX は Windows の CI の実行で動くことを確かめました。実機での挙動は未確認です
- 開き方:起動のたびに同じパスの古いファイルを消してから待ち受けます。
  パスが 103 byte を超えて開けなければ、その旨をログに出して制御ソケットを使わずに動きます
- 権限:Unix では 0600 にし、失敗を無視します。
  Windows では開いた直後に [credentials.md の DACL](../spec/credentials.md#windows-の-dacl) を付け、付けられなければソケットを閉じて使わずに動きます
- 期限:要求の 1 行を読む期限と応答を書く期限は、それぞれ 2 秒です。
  応答を実行時の側から待つ長さは下の「応答を待つ長さ」にあります。
  どの接続も受け付けてから 30 秒以内に終わり、仕様の期限を満たします
- 要求:前後の空白を除いて `rotate-key`、`doctor` と照らし、それ以外には `error: unknown command` を返します
- 実行時への受け渡し:スレッドは要求を容量の決まった tokio の channel へ待たずに入れ (`try_send`)、応答を std の channel で待ちます。
  channel が埋まっていれば、その旨の誤りの 1 行を返します。
  `rotate-key` は鍵を作り直して `agent.json` に保存し、トンネルを作り直し、`ok <公開鍵>` を返します
- 応答を組む処理の失敗:接続のスレッドの中の処理だけを `catch_unwind` で囲みます。
  実行時の tokio のタスクの panic は、応答の送り手が値を送らずに落ちる形で届くので、スレッドはそれを失敗として扱います。
  どちらの場合も `{"error": ...}` の 1 行を返し、転送を止めません
- 止め方:停止のとき、実行時は止める印を立ててから自分のソケットに 1 回接続し、accept で止まっているスレッドを起こします。
  待ち受けのスレッドは印を見て待ち受けを閉じ、ファイルを消して終わり、実行時はそれを待ちます。
  扱い中の接続のスレッドは待ちません。どれも上の期限と応答を待つ長さで終わります

実装では次のことも決めました。

- 要求の処理の場所:`doctor` は専用の受け渡しのタスクが受け、要求ごとに別のタスクで組みます。
  実行時のループが全体状態の適用や 30 秒ごとの見回りを処理している間も受け取るので、実行時の排他を待つ 2 秒の期限がそのまま効きます。
  組むタスクの panic は応答の送り手が消える形でスレッドに届きます。
  `rotate-key` は実行時のループの中で処理し、panic を受け止めません。
  鍵の保存とトンネルの作り直しの途中で落ちた状態のまま動き続けるより、プロセスが落ちて同梱の unit が立て直すほうがよいためで、Go の v1 と同じ判断です
- stream の観測と宛先の許可一覧:agent の排他の外に置き、`doctor` の応答はそれらを排他を待たずに読みます
- 要求の行の上限:1024 byte までに改行が来なければ、知らない要求として `error: unknown command` を返します。
  Go の v1 は上限を持たずに改行まで読みますが、返す応答は同じです
- 応答を待つ長さ:`doctor` は 5 秒です。
  実行時の側は排他を 2 秒まで待って応答を組むので、その上に余裕を足し、CLI が応答を待つ 10 秒より短くしました。
  `rotate-key` は、始まるのを 20 秒まで待ち、始まった後は要求を受けてから 26 秒まで終わりを待ちます。
  CLI が要求と応答の全体に掛ける 30 秒の中で応答を書き終えるためです。
  待ち切れなければ、`rotate-key` には `error: ` の 1 行を、`doctor` には `{"error": ...}` の 1 行を返します。
  Go の v1 は応答を書かずに接続の期限で閉じます。どちらも CLI からは要求が通らなかった実行です
- 取り下げた `rotate-key`:要求は共有の状態を持ち、`Pending` から、実行時の側が排他を取った後に鍵を変え始める `Started` か、受け口が始まるのを待ち切れずに取り下げる `Abandoned` の、どちらか一方だけに移ります (compare-and-swap)。
  取り下げた要求で実行時の側は何もしません。
  諦めた要求が後で鍵を変えると、CLI の打ち直しと重なって server の鍵の変更の頻度の上限に当たりうるためです。
  始まった要求は終わりを待ち、それも待ち切れなければ、鍵が変わったかもしれないので agent のログで結果を読むよう答えます。
  「鍵を変えていない」と答えるのは、取り下げが通った場合だけです
- accept の誤り:ログに出して 200 ミリ秒待ってから待ち受けを続けます。
  Go の v1 は待ち受けを止めます
- 応答を読む側の寛容さ:知らないキーは Go の `encoding/json` と同じく読み飛ばします。
  知らないキーを拒むのは fixture の照合の試験だけです
- `rotate-key` の後の stream:stream は接続を終えて待たずに繋ぎ直し、新しい公開鍵を送ります。
  再接続の待ちの間に頼まれた場合は待ちを縮めず、次の接続が新しい鍵を送ります。Go の v1 と同じです
- CLI の `agent pubkey`:agent が動いている間は、DACL を付け直さない読みで `agent.json` を読みます。
  止まっている間はロックを取ってから読み書きするので、付け直す読みを使います
- 利用者名:応答の `process.user` は uid から引き、Windows では Go と同じく空です。
  `agent doctor` の人向けの文で CLI の利用者を示すときだけ、Windows では `USERDOMAIN` と `USERNAME` の環境変数から `DOMAIN\user` の形で作ります。
  Go は OS の API で引くので、`NT AUTHORITY\SYSTEM` のような値で違いえます。保証の外です

### 応答の中身の今の範囲

agent の応答は Go の v1 の応答と同じ形です。
「wgstack の上の agent」の段で、次のキーを載せました。

- `tunnel.socket_buffers`:データプレーンが WireGuard の UDP のソケットを開いたときに測った値です。
  ソケットは 1 つなので `sockets` は 1 です
- `tunnel.udp_accounting`:核の `udp_receive_fault` です。
  データプレーンのスレッドが終わっていて読めなければ載せません

今の中継は TCP だけを開くので、UDP のルールは待ち受けを持たない `error` のルールとして載り、UDP の予算はフローを持ちません。
「UDP の中継」の段が UDP の待ち受けを足すと、同じ集計に入ります。

### DoctorResponse

応答の形は Go の `internal/agent/controlapi` の型と同じにします。
[control-socket.md の DoctorResponse](../spec/control-socket.md#doctorresponse) は、Rust の agent と Go の v1 の CLI を組ませる場合はこの応答の形も合わせることを求めます。
型は `wgft-agent` の中の module に置き、Rust の CLI と agent が共有します。
`testdata/spec/control/doctor-reply.json` を読んで同じ 1 行に書き戻す試験を置きます。

ユーザー空間モードの Rust の agent は、`runtime_state` の `mode` と `kernel` を書きません。
Go の v1 のユーザー空間モードと同じです。
各キーを埋める部品は次のとおりです。

| キー | Rust の出どころ | wgstack に依るか |
| --- | --- | --- |
| `allow_targets` | 設定の層の値と正規化した一覧 | 依らない |
| `stream` | stream のタスクの状態。試作が持つ値に ping と pong の時刻を足す | 依らない |
| `process` | 実効 uid と利用者名。Windows は uid に -1。`cap_net_admin` は Linux だけで `/proc/self/status` の `CapEff` から読む | 依らない |
| `runtime_state.generation`、`agent_disabled` | 全体状態の適用 | 依らない |
| `runtime_state.tunnel` の状態と理由と `endpoint`、`last_handshake` | ハートビートと同じ値 | 依らない |
| `tunnel.rx_bytes`、`tx_bytes`、`started_at`、`watchdog` | device の `peer_status` と実行時の監視 | 依らない |
| `tunnel.socket_buffers` | agent の device の殻が測った値 | 依らない。Linux だけ測る |
| `tunnel.udp_accounting` | wgstack の会計の故障 | 依る |
| `rules` | 中継の待ち受けの状態、試し接続の結果、セッションとフローの数 | 待ち受けの開閉の結果だけ依る |
| `budgets`、`refusals_since` | フロー数の pool | 依らない |
| `runtime_state_timeout` | 実行時の排他を 2 秒で取れなかったとき | 依らない |

応答の中の 1 つの文字列は 512 byte で切ります。

### agent doctor のコマンド

`wgft agent doctor` は Go の `cmd/wgft/agentdoctor*.go` を Rust に移します。

- 検査:検査の ID、並び、理由の符号、総合判定を動かす検査、停止中に成立する検査は [検査の一覧](../diagnosis/agent-evidence.md#検査の一覧と証拠の出どころ) のとおりです。
  Go の `TestAgentDoctorCheckIDsMatchTheDesign` と `TestAgentDoctorReasonsMatchTheDesign` に当たる試験を Rust に置き、設計の表と照らします
- 人向けの文:`label`、`detail`、`next` の文は保証の外ですが、Go の文を写します。
  ラボの `lifecycle.sh` が `detail` の文を照らすためです
- `--json`:`testdata/spec/control/agent-doctor.json` と `agent-doctor-stopped.json` を読んで同じ byte 列に書き戻す試験を置きます
- 終了コード:0、1、2、3 の意味と、2 を 1 より優先する規則は [cli-config.md の wgft agent doctor](../spec/cli-config.md#wgft-agent-doctor) のとおりです。
  フラグの誤りは 2 です
- dotenv:権限で読めなければ拒まずに所見にします
- `host.platform`:OS、アーキテクチャ、版を示します。
  Go の「memory soft limit would be」の予測の代わりに、[メモリの上界の行](#メモリの上界の行)と同じ値を示します。
  `detail` は人向けなので、この置き換えは保証の範囲を変えません。
  上界の行が入る「UDP の中継」の段までは、値の代わりにフロー数の上限と、上界をまだ示さない旨を書きます。
  設定ファイルを読めない実行の `unknown` と `config_unreadable` は Go と同じです
- `host.privileges`:Windows では Go と同じく作成の可否を判定せず `permission_not_determined` にします
- カーネルモードの検査:`dataplane.interface`、`dataplane.table`、`host.forwarding` は、ユーザー空間モードでは Go と同じく `not_tested` と `userspace_mode` です
- カーネルモードの記録:`agent.json` がカーネルモードを記録している場合、Rust のビルドはカーネルを読めないので診断しません。
  `agent teardown` と同じく、種別 `prerequisite`、対象 `WGFT_MODE` の `cannot continue` で拒み、終了コードは 3 です。
  理由は `this build does not include the agent's kernel mode yet, so it cannot diagnose a kernel-mode agent; use a build that includes it` です

### 段と値の出どころ

`agent doctor` は 2 つの PR に分けます。

- 骨組み:コマンド、停止中にも成立する検査 (`host.*`、`agent.*`、`tunnel.resolve`)、`agent.control` の接続と理由、DoctorResponse から読む `stream.*`、`tunnel.*`、`relay.*` の検査、報告の JSON と文の出力、総合判定と終了コード、設計の表との照合です。
  「制御ソケット」の段の上に積みます
- 稼働中の検査:agent の応答に、フロー数の pool から来る `budgets`、ルールの `sessions` と `flows`、宛先の試し接続の `target_errors` を載せます。
  「宛先と予算」の段の上に積みます

CLI の検査は DoctorResponse だけを読む関数なので、骨組みの段ですべて移しました。
稼働中の agent の検査の結果は、Go の CLI と Rust の CLI のどちらで読んでも同じになります。
骨組みの段で、どの応答が来ても Go の v1 にない理由の符号を出さないためでもあります。
2 つ目の段で足すのは agent の側の値で、今も載せない値は[応答の中身の今の範囲](#応答の中身の今の範囲)にあります。

骨組みで決めたことは次のとおりです。

- 照合:`agent-doctor.json` と `agent-doctor-stopped.json` を、fixture と同じ証拠 (認証情報、ロックの状態、インタフェース、制御ソケットの応答 `doctor-reply.json`) から Rust の診断で作り直し、`host.platform` の所見を除いて同じ byte 列になることを確かめます。
  `host.platform` は版と上の置き換えのために違います
- 理由の符号:設計の表にある符号のうち、カーネルモードの検査だけが使うものは持ちません。
  試験はその一覧を明示し、表との差がちょうどその一覧であることを確かめます
- 人向けの文のうち、ライブラリの誤りの文 (JSON の読み取りの誤り、名前の解決の誤り、OS の誤り) は Rust の文になり、Go と一致しません
- 名前の解決:`host.resolve` と `tunnel.resolve` は、[名前の解決](#名前の解決)の宛先の名前と同じ resolver で引き、5 秒で待つのをやめます。
  CLI は tokio の実行環境を持たないので、その場で小さな実行環境を作って待ちます。
  A と AAAA を引いて RFC 6724 の順に並べるので、Go の `LookupHost` と同じ範囲の答えです
- インタフェースの一覧:Unix は `getifaddrs`、Windows は `GetAdaptersAddresses` から、名前、up、ループバック、アドレスを OS が返す順に読みます。
  Go の並びと違う OS があっても、人向けの文だけが変わります
- カーネルモードの拒否:`agent.json` の記録か稼働中の agent の応答の `mode` が `kernel` なら、検査を組む前に拒みます。
  記録が `userspace` でも `kernel` でもない値なら、その値を名指して同じ種別と対象で拒みます

稼働中の検査で決めたことは次のとおりです。

- 1 回の読み:ルールの状態とリスナーの集計は、中継のリスナーの状態を 1 回読んだ値から作ります。
  ハートビートのルールの状態も同じ関数で作るので、`doctor` の `state` と `reason` はハートビートと同じ判定です。
  Go の `usermode.Read` と同じです。
  `doctor` はハートビートのうちトンネルの状態だけを使い、リスナーを 2 度読みません。
  ハートビートは接続の数と枠の数を読まないので、30 秒ごとに予算の排他を取りません。
  範囲のルールはリスナーが 65535 まであるので、枠の数は全リスナーの分を予算の排他 1 回で読みます
- リスナーの並び:Go の `Manager.Status` と同じく、リスナーの名前 (`tcp/<port>`) の文字列の順に並べます。
  ルールの状態の理由と `bind_error`、`target_error` は、この順で最初の誤りから取ります。
  `tcp/10` は `tcp/9` より前なので、範囲のルールで理由に出るポートが Go と同じになります
- 誤りの分け方:待ち受けを開けていないリスナーは `bind_errors` に数え、理由は bind の失敗か IP リテラルの宛先の拒否です。
  開いている待ち受けで宛先の誤りを持つリスナーは `target_errors` に数え、理由は試し接続の失敗か、接続のときの宛先の拒否です
- `sessions`:中継が持つ接続の数で、トンネルの側は枠を取った後に、宛先の側は繋がった後に数え、中継が終われば両方を引きます。
  Go の `tcpServer.conns` と同じ数え方です。
  Go は中継の終わりに送り残しを届けるまで枠を持ち、`conns` からは先に外します。
  そのため Go では、枠の数に比べて接続の数が少ない時間が一時的にあります。
  Rust はトンネルの側の数えと枠を同時に返すので、この時間はありません
- `flows`:フロー数の pool の待ち受けごとの枠の数をそのまま読みます。
  上限の判定の対象と同じ量です
- `budgets`:TCP と UDP の順に、pool を 1 回の排他で読みます。
  Go は値ごとに排他を取りますが、1 回で読むほうが値の組が揃います。
  拒否は 0 でないものだけを、ルール ID と理由の語の順に並べます
- `refusals_since`:中継はトンネルと一緒に作り直すので、`tunnel.started_at` と同じ時刻です

wgstack の内部に依るのは `tunnel.udp_accounting` だけです。
`tunnel.socket_buffers` と `tunnel.transfer` は WireGuard の device とその殻に、`relay.*` は中継とフロー数の pool に依ります。

## CLI と設定と終了コード

### Rust のビルドが持つコマンド

| コマンド | 扱い |
| --- | --- |
| `wgft agent run` | 仕様のとおり。ユーザー空間モードだけ |
| `wgft agent pubkey` | 仕様のとおり |
| `wgft agent rotate-key` | 仕様のとおり。停止中でカーネルモードの記録があれば、Go と同じく古い鍵を `previous_wg_private_key` に移します。ファイルの操作だけで、カーネルに触れません |
| `wgft agent doctor` | [agent doctor のコマンド](#agent-doctor-のコマンド) |
| `wgft agent teardown` | Linux 以外は仕様のとおり拒みます。Linux でも、データディレクトリとインタフェースの名前を検査した後、種別 `prerequisite` と対象 `WGFT_MODE` で拒み、終了コードは 3 です。理由は `this build does not include the agent's kernel mode yet, so it cannot remove what a kernel-mode agent left; use a build that includes it` です |
| `wgft version`、`wgft --version`、`wgft -v` | 仕様のとおり |
| `wgft help <コマンド>`、`-h`、`--help` | 説明を標準出力に書き、終了コード 0 |

VPS の側の `wgft agent` の下位のコマンドと、`server`、`rule`、`status` は server を移す段まで持ちません。
これらを指すと未知のコマンドの誤りになります。
cobra の `completion` と、Windows のダブルクリックの案内は持ちません。
どちらも仕様が持たなくてよいとしたものです。

### コマンドラインの解釈

clap の derive でコマンドの構成とフラグの名前を書き、値の解釈と誤りの出力は wgft が持ちます。

- clap の `env` の機能を使いません。
  優先順位と出所は設定の層が決めます
- フラグの値:すべて文字列で受け、整数のフラグは Go の `strconv.ParseInt` の基数 0 の規則で解釈します。
  解釈した値を 10 進で書き直し、有効な設定の行と範囲の検査に使います
- 真偽値のフラグ:`--json` と `--dry-run` は値なしで真、`--json=<値>` の形でだけ値を受けます。
  受け付ける値は Go の `strconv.ParseBool` の集合です
- フラグの位置:`--data-dir` と `--config` は `wgft agent` の global の引数にし、`wgft agent --data-dir X pubkey` を受けます
- 誤りの出力:clap の `try_parse` の誤りを受け、使い方を書かずに `Error: <文>` の 1 行を標準エラーに書きます。
  終了コードは 1 で、`agent doctor` だけ 2 です。
  文の言い回しは保証の外なので、clap の文をそのまま使います
- 拒否の出力:`Error: refusing to start [<種別> <対象>]: <理由>. <直し方>` の形で、`agent run` 以外は `cannot continue` です。
  終了コードは 3 で、拒否を別の誤りが包んでも 3 のままです

### 設定の層

設定の層は、コマンドの入口で 1 回だけ設定を読み、各項目の値と出所 (`flag`、`env`、`file`、`default`) を持ちます。

- dotenv の場所:`--config`、`WGFT_CONFIG`、既定の順です。
  `WGFT_CONFIG` は環境変数でだけ受けます
- dotenv の構文と誤りの文面:[cli-config.md の dotenv の構文](../spec/cli-config.md#dotenv-の構文) のとおりで、行の中身と値を出しません
- 値の検査:[入口での検査の順](../spec/cli-config.md#入口での検査の順) のとおりです。
  `WGFT_AGENT_ALLOW_TARGETS` の解釈は Go の `net/netip` の性質を写します
- 知らない名前:`WGFT_*` のうちそのコマンドが読まない名前は無視します
- 照合:`testdata/spec/config/` の `dotenv.json`、`values.json`、`allow-targets.json`、`refusals.json`、`effective-config.json` を Rust の試験で読み、Go と同じ結果になることを確かめます。
  `values.json` の `goos` は Rust の `target_os` に読み替えます

作りは次のとおりです。

- 置き場:`wgft-agent` の module `config` が優先順位、dotenv、値の検査、有効な設定の行、起動ログの行を持ちます。
  `wgft` の crate は clap への接続 (`cli`)、設定を読んで入口を通す手順 (`agent_run`)、失敗と終了コード (`failure`) を持ちます。
  入口の検査は環境変数の引き元と OS の名前を引数に取り、試験は fixture を実際の経路で通します
- 出所:フラグは `Option` で受け、書かれたかどうかで出所を決めます。
  値が既定と同じでも出所はフラグです。
  整数のフラグは解釈した値を 10 進に書き直して渡すので、範囲の検査は環境変数と同じ `Atoi` の規則で行います。
  `--max-udp-flows 016` が 14 になり、環境変数の `016` が 16 になる差は、この経路から自然に出ます
- フラグの形:値を取るフラグは、次の語が `-` で始まっても値にし、同じフラグを繰り返せば最後の値が勝ちます。
  `--config` と `--data-dir` は `wgft agent` の global の引数です
- UTF-8 でない値:Go はバイト列のまま受けます。
  Rust は値を `String` で持つので、環境変数の値と dotenv の値が UTF-8 でなければ、別の値に化かさず、その名前をコマンドが読むときだけ種別 `config` の拒否にします。
  dotenv のコメントと空行と、読まない名前の値は UTF-8 でなくてかまいません。
  データディレクトリのパスを黙って変えないためです
- 引用:`%q` の引用は Go の `strconv.Quote` を写します。
  印字できるかの判定は、一般カテゴリの表で行います。
  表の Unicode の版は Go が新しいことがあり、新しい版で割り当てられた文字は Rust の文面では `\u` の形になります。
  差は文面だけで、文面は保証の外です
- 持たない機能の拒否:カーネルモードは仕様の文で拒みます。
  入口の検査の後に判定するので、値の誤りが先に出ます。
  宛先の許可一覧とフロー数の上限は「宛先と予算」の段で効かせ、拒否と「まだ効かせていない」旨の行を外しました。
  送信の向きのバッチは、値があるときだけ、まだ効かせていない旨を 1 行出します。
  対応する段が入るときに、この行を外します
- 値を取るフラグ:`--config` と `--data-dir` は `OsString` で受けます。`--config` は空の値を許し、空のパスは存在しないファイルと同じです。
  `--help` には、環境で決まる既定の値を `[default: ...]` で出します
- 起動ログの順:許可一覧の行は、Go と同じ文で、一覧があるときも無いときも `agent starting` の行より前に書きます。
  後者を `wgft_agent::run` が書くためです。
  ログの順は保証の外です
- データディレクトリ:作れなければ `data dir: <誤り>` で終了コード 1 です。
  `wgft agent` の説明と、`wgft` だけの呼び出しは、説明を標準出力に書いて終了コード 0 です。
  未知のサブコマンドは誤りで終了コード 1 です。
  余分な引数と `--help` を一緒に書くと、Go は説明を書きますが、Rust は余分な引数の誤りを先に返します。保証の外なので合わせません
  `agent doctor` の引数の誤りが終了コード 2 になる判定は、誤りを無視して解釈し直したコマンドで決めます。
  ルートの知らないフラグのように解釈し直してもコマンドが決まらないときは、`-` で始まらない語の並びで決めます
  `wgft agent foo` を Go は説明で 0 にしますが、保証の外なので合わせません

### 既定のパス

| OS | `WGFT_DATA_DIR` の既定 | dotenv の既定 |
| --- | --- | --- |
| Linux と他の Unix | `/var/lib/wgft` | `/etc/wgft/agent.env` |
| macOS | `$HOME/Library/Application Support/wgft` | 同じディレクトリの `agent.env` |
| Windows | `%ProgramData%\wgft` | 同じディレクトリの `agent.env` |

既定はプロセスの起動の時に 1 回だけ決め、`--help` の既定の表示にも同じ値を出します。
macOS で `HOME` が空なら作業ディレクトリの `wgft`、Windows で `ProgramData` が空なら `C:\ProgramData` を使います。
Windows の環境変数の名前は大文字と小文字を区別せずに引きます。
Rust の `std::env::var` は Windows の API を使うので同じ扱いになります。Windows の CI で確かめました。

### ファイル記述子の上限

platform の層は、Unix で起動の時に soft の `RLIMIT_NOFILE` を hard の値まで上げます。
Go の実行環境が v1 で行っていたことで、同梱の unit と plist はこれに頼って `LimitNOFILE` を書きません。
macOS では hard の値が無制限でも `kern.maxfilesperproc` を超える値を設定できないので、その値で頭を打ちます。
上げられなければ英語の 1 行を出して起動を続けます。
試験は、soft の値を下げた子のプロセスで起動の処理を呼び、上がることを確かめます。
ラボでは、`ulimit -n` を上げる行を持たない起動で、多数の接続を受けられることを確かめます。

### 起動ログ

起動ログの順と行は [cli-config.md の起動ログ](../spec/cli-config.md#起動ログ) のとおりです。
行の文面は保証の外ですが、ラボの確認が照らす行は Go と同じ文面にします。
該当する行は次のとおりです。

| 行 | 照らす確認 |
| --- | --- |
| `effective config:` と有効な設定の行 | 設定の照合の fixture |
| `wgft <版> agent starting: name <名前>, mode userspace, ...` | `agent-handover.sh`。もう一方の実装の `agent.json` から登録し直さずに動いたこと |
| `stream: connected to` と `server selected protocol v1` | `upgrade.sh`、`version-skew.sh`、`agent-handover.sh` |
| `not registered and no join string` | `upgrade.sh`。行が無いことを確かめ、同じログの `server selected protocol v1` と組にする |
| `applied generation <N>: ...` | `agent-handover.sh` が待つ。行の後ろの要約は照らさない |
| `tunnel: up addr=` | `lifecycle.sh` の check 12。下の警告の行が無いことの確認と組にする |
| `warning: the WireGuard UDP sockets` | `lifecycle.sh` の check 12 |
| `listener tcp/<port> closed` | `lifecycle.sh` の check 2 |
| `listener tcp/<port>: bind ...` | `lifecycle.sh` の check 2 と 11。行が無いことを確かめる |
| `listener tcp/<port> -> <宛先> opened; rule <ID>` | `lifecycle.sh` の check 2 と 11。上の行が無いことの確認と組にし、開き直した後の行があることを確かめる |
| `<待ち受け>: <理由>; refusing new connections` | フロー数の拒否。`lifecycle.sh` の check 5e が `rule <ID> holds ... for a rule added later` を照らす。`<理由>` は Go の `internal/resource/pool.go` の拒否の文 (`flow budget full: ...`、`rule <ID> holds ... for a rule added later`、`... below its minimum ...` など) をそのまま写します |
| `memory bound: <N> MiB, ...` | `lifecycle.sh` の check 5 と 5b ([メモリの上界の行](#メモリの上界の行)) |
| `dropped TCP handshakes that advertise an MSS below 536` | `exhaustion.sh` の kernel の `mss`。wgstack の捨てた数の口が要る |

行が無いことを確かめる `absent` の確認は、Rust の agent が別の文面を書いても通ってしまいます。
ラボの切り替えの PR で、Rust の agent で流す確認のうち agent のログに `absent` を当てるもの (`lifecycle.sh` の check 2、11、12) を、同じ出来事で必ず出る行の存在の確認と組にしました。
`lifecycle.sh` の check 11 が `agent doctor` の出力に当てる `absent` は、同じ出力の終了コードと状態の確認とすでに組になっています。
この表は、同じ PR でラボの台本が agent のログを照らす箇所を数え直したものです。

Go と変える行は次のとおりです。

- メモリ:`memory soft limit:` の行を書かず、[メモリの上界の行](#メモリの上界の行)を書きます。
  `GOMEMLIMIT` は読まず、行も書きません
- netstack:`WGFT_AGENT_NETSTACK` の出所が既定でなく、値が `wgstack` でなければ、`WGFT_AGENT_NETSTACK=<値>: unused, since this build has one network stack, wgstack, and runs on it; the setting is kept so the same agent.env works` を書きます。
  値は `gvisor` も `wgstack` も受け付け、どちらでも Rust の wgstack で動きます。
  実験的の警告の行は書きません
- 送信の向きのバッチ:受け付ける値と誤りの文面は仕様のとおりです。
  値から導く量と行の中身は、#681 の提案 (1 回の起床で作る packet の数と送信のバッチの上限に使う) と一緒に決めます

### 終了コード

[cli-config.md の終了コード](../spec/cli-config.md#終了コード) のとおりです。
`agent run` は SIGINT と SIGTERM で `shutting down` を書いて 0 で終わります。
Windows では Ctrl+C と Ctrl+Break を同じに扱います。
同梱の unit、plist、compose は変えません。
unit と plist が頼るファイル記述子の上限は、[ファイル記述子の上限](#ファイル記述子の上限)のとおり Rust の agent が自分で上げます。

### docs/cli.md の照合

`docs/cli.md` は v2.0.0 まで Go の `TestCLIDocUpToDate` が生成し、Go の v1 の `wgft` を説明します。
Rust の側は、agent のホストのコマンドのフラグが Go と同じであることを試験で確かめます。

- 比べるもの:Rust のビルドが持つコマンドごとの、フラグの表 (名前、型、既定の値) と 1 行の説明 (`Short`) です。
  `docs/cli.md` の同じ見出しの節から読み、Rust の clap のコマンドの情報と比べます
- 比べないもの:長い説明 (`Long`) と使用例 (`Example`) です。
  Rust の説明は Rust の agent を説明し、CLAUDE.md の約束のとおりラボで確かめた挙動だけを書きます。
  Go の説明を写すと、Rust で確かめていない挙動を書くことになるためです
- 説明の置き場:Go の `cmd/wgft/helptext.go` に当たる module を `crates/wgft` に置きます。
  clap のコマンドの定義には 1 行の `about` だけを置きます
- 使用例:実行できるコマンドに使用例があることを、Go の `TestHelpTextsCoverCommands` と同じく確かめます
- 比べる範囲:コマンドの 1 行の説明は `docs/cli.md` の冒頭の表にある葉のコマンドだけを比べます。
  `wgft` と `wgft agent` の節には 1 行の説明が無いので比べません。
  型は `string`、`int`、真偽値に分け、既定の値は `docs/cli.md` の `(default ...)` と clap の説明の `[default: ...]` から読みます
- 差の一覧:Rust のビルドがまだ持たないコマンドとフラグは、試験の `EXPECTED_DIFFERENCES` の 1 か所に書きます。
  実際の差の集合と一覧が一致しなければ落ちるので、新しい差は気づかれ、段が入って差が消えたら一覧から消します
- OS:既定のパスが OS で変わるので、Go と同じく Linux でだけ比べます
- v2.0.0 の後:Go の試験を消し、Rust の試験が `WGFT_UPDATE_CLI_DOC=1` で `docs/cli.md` 全体を書き直す形に替えます

## ラボの切り替え

### 実装の選択

ホストの変数 `WGFT_LAB_AGENT_IMPL` で agent の実装を選びます。
値は `go` と `rust` で、省略は `go` です。
`lab/lab` は `WGFT_LAB_AGENT_NETSTACK` と同じく、この値を VM の中のすべての実行に環境変数として渡します。
`lab/lab suite` は `--agent-impl go|rust|both` を受けます。

### ビルドと置き場所

- ビルド:`rust` のとき、`lab/lab build` は `cargo zigbuild --release --locked --target x86_64-unknown-linux-musl -p wgft` で静的なバイナリを作り、`bin/rust/wgft` に置きます
- 置き場所:VM の中では `/usr/local/lib/wgft-rust/wgft` に置きます。
  ファイル名を `wgft` に保つのは、ラボの台本がプロセスを comm の `wgft` と cmdline の ` agent run` で探すためです
- ビルドの契機:`WGFT_LAB_AGENT_IMPL=rust` の `lab/lab build`、`--agent-impl` に `rust` を含む `lab/lab suite`、試作の道具を作る `WGFT_LAB_RUST=1` です
- 試作の物:試作の `wgft-rs` の名前は、ラボの切り替えの PR で置かなくなりました。
  `wgft-rs` を使っていたのは `lab/rust-agent.sh` だけで、その後を継ぐ `lab/agent-handover.sh` は同じバイナリを `/usr/local/lib/wgft-rust/wgft` から呼ぶためです。
  TUN の殻 (`wgft-wireguard-tun`) とラボのための wireguard-go は、device の層を Linux と wireguard-go と照らす `lab/wg-interop.sh` の道具として、ラボの一式が Rust の agent で通るまで残します。
  「wgstack の上の agent」の段で、agent の経路からは殻を外しました
  通った後は、ラボの一式が同じ相互運用を確かめるので、殻と `wg-interop.sh` を消します

### 台本の継ぎ目

ラボの台本は `wgft` を PATH から呼び、server と agent が同じバイナリです。
切り替えは、ユーザー空間モードの agent のホストで呼ぶコマンドだけを差し替えます。

- `lab/sandbox.sh` が変数 `AGENT_WGFT` を決めます。
  `rust` なら `/usr/local/lib/wgft-rust/wgft`、それ以外は `wgft` です
- 書き換える呼び出し:ユーザー空間モードの `wgft agent run` と、それに向けた `agent doctor`、`agent rotate-key`、`agent pubkey` を `"$AGENT_WGFT" agent ...` に書き換えます。
  `agentdoctor.sh` の `DOCTOR_BIN` の既定も、ユーザー空間モードの節では `AGENT_WGFT` にします
- 書き換えない呼び出し:`WGFT_MODE=kernel` の起動と、カーネルモードの agent に向けた `agent doctor`、`agent rotate-key`、`agent teardown` は Go の `wgft` のままです。
  VPS の側の `wgft agent ls`、`agent join-string`、`agent enable` などと `wgft server` も書き換えません
- 書き換え漏れの検査:agent のホストのコマンドを `wgft` のまま呼ぶ行を見つける検査をラボの道具に足します。
  意図して Go の `wgft` を呼ぶ行には、行末に印 `# lab: go agent` を付け、検査はこの印の行だけを許します。
  検査は `tools/labhost` の Go の試験 `TestScenariosCallTheAgentThroughAgentWgft` で、`go test ./...` と CI の A 類で流れます。
  `lab/*.sh` のコメントでない行から、`wgft agent run`、`doctor`、`rotate-key`、`pubkey`、`teardown` を文字のまま呼ぶ形を探します。
  変数を通した呼び出し (`"$bin" agent run`) は見えないので、そうした呼び出しは変数を決める行で `AGENT_WGFT` か Go の `wgft` を選びます。
  文字の照合なので、見出しの `echo` の中の `wgft agent doctor` も拾います。
  見出しからは `wgft` を外しました
- `go` のとき:書き換えは機械的で、挙動は変わりません
- 一式の外の台本:`version-skew.sh` と `upgrade.sh` の「今のビルドの agent」、`scale.sh` と `rcvwin.sh` のユーザー空間モードの agent も `AGENT_WGFT` にします。
  `version-skew.sh` は今のビルドの agent の版を `"$AGENT_WGFT" version` で確かめます。
  Go の netstack を比べる `tcpquality.sh` と、Go のメモリの probe を読む `agentmem.sh` は、Go の `wgft` のままにします

### 確認の分け方

`lab/suite.txt` の確認は、`lifecycle.sh` の check 4 を除いて agent を起動します。
完成の条件に入る確認と、Go の agent を使い続ける確認を次のように分けます。

| 分類 | 確認 | `rust` のときの扱い |
| --- | --- | --- |
| 条件に入る | `e2e.sh`、`ipv6.sh`、`usage.sh`、`rates.sh`、`split-merge.sh`、`import-export.sh`、`connlimit.sh`、`lifecycle.sh` の各 check、`exhaustion.sh` の `postclose` (server がユーザー空間モード)、`acceptq`、`ackflood`、`wgstall` と kernel の `mss`、`agentdoctor.sh` の userspace の節 | Rust の agent で流します |
| カーネルモードの agent | `agentkernel.sh`、`agentdoctor.sh` のカーネルモードの節、userspace の `exhaustion.sh mss` (server の netstack を確かめるため agent をカーネルモードで起動する) | `rust` の組では流さず、結果を `go` の組から取ります。agent のカーネルモードを移す段で条件に入れます |
| opt-in | `agentmem.sh`、`exhaustion.sh kernel postclose`、`version-skew.sh`、`agent-handover.sh` | 下に書きます |

`lab/suite.txt` は、`rust` の組で流さない確認に `agent=go` の印を付けます。
印の付く確認は、カーネルモードの agent の行と `exhaustion.sh kernel postclose` です。
`WGFT_LAB_AGENT_IMPL=rust` の `labhost run all` は、印の付いた確認を計画から外し、`summary.json` の `from_go` に名前を残します。
`tools/labhost` の試験は、印がこれらの確認だけに付くことを確かめます。

`agentdoctor.sh` の userspace の節は、ユーザー空間モードの agent を起動して `agent doctor` を確かめます。
ラボの切り替えの PR で、`agentdoctor.sh` に 2 つ目の引数 (`kernel` か `userspace`、省略は両方) を足し、節を別に呼べる形にしました。
`lab/suite.txt` は server のモードごとに 2 つの節を別の行にし、userspace の節を `AGENT_WGFT` で流します。
節ごとに server を起動し直すので、一式の行は 2 つ増え、所要時間は server の起動の分だけ延びます。
この節の `baseline_compare` は、`AGENTDOCTOR_BASELINE` の `wgft` の診断と今の診断の ID と状態と理由を比べます。
比べる前に、カーネルモードの項目 (`dataplane.*` と `host.forwarding`) を両方の側から外します。
古い版は項目を持たず、今の版はこの節の確認が別に照らすためです。
`rust` の組では `AGENTDOCTOR_BASELINE` の既定を Go の `wgft` にし、Go の CLI が Rust の agent の制御ソケットを読む組み合わせを毎回確かめます。

Go の実行環境に依る読み取りは次のように扱います。

- `lifecycle.sh` の check 5 と 5b:agent の `memory soft limit:` の行の代わりに `memory bound:` の行を読み、RSS がその値と[余裕](#メモリの上界の行)の和を超えないことを確かめます。
  server の側の行は今のまま Go の server を読みます
- `exhaustion.sh` の gctrace:既定の確認のうち、判定に使うヒープは server のもの (ユーザー空間モードの `postclose`) です。
  `acceptq` と `ackflood` は agent のヒープを測って示すだけで、判定に使いません。
  `rust` のときこれらの行は値を持たず、RSS だけを示します。
  `wgstall` が示すヒープは server のものなので、`rust` でもそのまま示します
- `exhaustion.sh kernel postclose`:カーネルモードの server の後ろで、agent の netstack の閉じた後の接続の表を agent のヒープで確かめます。
  Go の gVisor の表に固有の確認なので、Rust では wgstack の TIME_WAIT の表の設計が測り方 (表の行の数か wgstack の保持量) を決め、それまで `rust` では流しません
- `agentmem.sh`:Go の wgstack の memprobe に依るので、`rust` のときは `SKIP` を出します。
  Rust の wgstack の保持量の測り方は #681 の「保持の量の測り方」が決めます
- `version-skew.sh`:Rust の agent と古い Go の server の組み合わせを確かめるので、リリース候補の関門で `rust` の組でも流します
- `agent-handover.sh`:下の[試作の台本](#試作の台本)のとおりです

### netstack の軸

Rust の agent は netstack を 1 つしか持たないので、`--netstack` の軸を持ちません。
`--agent-impl rust` と `--netstack wgstack` か `both` の組み合わせでは、`rust` の組を 1 回だけ流します。
`--agent-impl both --netstack both` は、`go` と既定の netstack、`go` と wgstack、`rust` の組を流します。

### 結果の報告

- `summary.json` に `agent_impl` を記録し、合わせるときに異なる値が混ざれば誤りにします。
  この項目より前の `summary.json` は `go` と読みます
- 組ごとの出力は `<out>/<agent_impl>/<netstack>/` に置き、見出しを `==== lab suite: agent=<impl>, netstack=<netstack>, N VMs` にします。
  `rust` の組の netstack は `default` です
- `rust` の組の報告には、カーネルモードの agent の確認を `go` の組から取った結果として印を付けて載せます。
  `lab/lab suite` は `go` の組を先に合わせ、`rust` の組を合わせる `labhost merge` に最初の `go` の組の `summary.json` を `-go-summary` で渡します。
  合わせた結果は `from go:` の行で確認ごとに出し、`summary.json` の `from_go_verdicts` に残します。
  取った結果は `rust` の組の件数と終了コードに入れません。
  `go` の組の終了コードにすでに入っているためです。
  `--agent-impl rust` だけで流したときは、`go` の組が無い旨を出します。
  `-go-summary` のファイルが読めないか、`summary.json` でないか、`go` の組のものでなければ、警告にして取った結果を出さず、`rust` の組の統合はそのまま書いて示します
- `lab/lab suite` の終了コードは組ごとの結果を合わせます。
  `rust` の組は「UDP の中継」の段まで報告だけなので、`go` の組も流したときは `rust` の組の失敗を示すだけにし、終了コードに入れません。
  その段で `lab/lab` の `SUITE_RUST_GATES` を 1 にし、`rust` の組の失敗も終了コードに入れます。
  初めの計画は「wgstack の上の agent」の段で 1 にすることでしたが、UDP の中継の前は UDP のルールを使う確認が必ず落ちるので、1 つ後の段に移しました
  `rust` の組だけを流したときは、その結果が終了コードです
- `labhost run all` は、`WGFT_LAB_AGENT_IMPL=rust` で Rust の `wgft` が入っていなければ、流す前に止まります
- PR の本文には組ごとに、確認ごとの PASS と FAIL を書きます。
  完成の条件の判定には `rust` の組で「条件に入る」確認がすべて PASS であることを使います

### 試作の台本

`lab/rust-agent.sh` の確認のうち、Go の agent と Rust の agent の間の `agent.json` の引き継ぎは、TUN に依らない価値があるので残します。
TUN、入口の検査、root に依る確認は外し、台本の名前を `lab/agent-handover.sh` に替え、両方のバイナリを作ったときだけ流す opt-in の確認にします。
外したのは、TUN の device のアドレスと停止の後の削除、keepalive の ping (カーネルモードの server での tcpdump と、ユーザー空間モードの server の応答)、規則の無いポートへの接続の拒否です。
いずれも一式が Rust の agent で確かめます。
残したのは、Rust の agent の登録と転送、Go の agent の登録と転送、互いの `agent.json` からの起動と転送です。
Rust の agent は試作のあいだ root で動きます。

### 流す頻度と関門

ラボの切り替えが入った後、agent の crate を変える PR は、ラボの一式の `rust` の組を積みの先頭で 1 回流します。
「wgstack の上の agent」の段より前は、Rust の agent が TUN の試作の形だったので、`rust` の組の結果は報告だけに使い、マージの関門にしませんでした。
「wgstack の上の agent」の段から「UDP の中継」の段までは、UDP のルールを使う確認と `lifecycle.sh` の check 5 と 5b が `rust` の組で落ちます。
その間は、`rust` の組の結果を前の積みの結果と比べ、新しく落ちた確認が無いことを手で確かめます ([テストの規範](../../development/testing.md#マージの前に流すテスト))。
「UDP の中継」の段から後は、`rust` の組の結果をマージの関門にします。
ラボの切り替えの PR は、この扱いを[テストの規範](../../development/testing.md)の契機の表に `rust-agent` として書きました。
対象は、`crates/**` のうち TUN の殻の `crates/wgft-wireguard-tun/**` を除くものと、`Cargo.toml`、`Cargo.lock`、`rust-toolchain.toml` です。
TUN の殻は Rust の agent のビルドに入らないためです。
ラボの切り替えの PR そのものは lab の変更なので、両方の netstack で `go` の一式を流します。

## Windows と macOS

### CI で build と単体の試験を流すもの

B14 (`rust-windows` と `rust-macos`) で、次をすべて build し、単体の試験を流します。

| 部品 | Windows | macOS |
| --- | --- | --- |
| 既定のパス | `%ProgramData%` と空のときの代わり | `$HOME` と空のときの代わり |
| ロック | `LockFileEx` の排他を別の handle が取れないこと | `flock` の同じ試験 |
| DACL | `agent.json`、一時ファイル、ロック、ソケット、新しいディレクトリに付けた DACL を読み返し、SDDL と照らす | 該当しない |
| 認証情報の置き換え | 既存のファイルへの rename が置き換えること | 0600 で作ること |
| ファイル記述子の上限 | 該当しない | `kern.maxfilesperproc` で頭を打って上がること |
| 制御ソケット | AF_UNIX で `doctor` と `rotate-key` を往復すること、103 byte を超えるパスの扱い、止め方 | 同じ |
| dotenv の権限 | 権限の拒否の文に DACL を評価しない旨が付くこと | Unix の文面と警告 |
| WireGuard のソケット | `SIO_UDP_CONNRESET` を切ったソケットで、ICMP の Port Unreachable の後も受信が止まらないこと | 該当しない |
| UDP の中継 | ループバックの宛先で、到着の待ち、Port Unreachable でのセッションの閉鎖、枠の上限 | 同じ試験と、送信バッファを 65535 byte に上げること |
| 名前の解決 | 期限と同時の数の上限 | 同じ |
| wgstack と中継の結合 | wgstack の核を試験の殻で動かす中継の試験 | 同じ |
| `agent doctor` | `host.privileges` が `permission_not_determined` になること、`tunnel.socket_buffers` が `not_tested` になること | `tunnel.socket_buffers` が `not_tested` になること |

Windows の DACL とソケットの操作には `windows-sys` を使います。
ライセンスは MIT と Apache-2.0 の選択で、`cargo deny` の許可の一覧に入ります。

### platform の層の作り

`crates/wgft-agent` の module `platform` に、OS の差を閉じ込めます。

- `paths`:OS の分類と環境の引き方を引数に取る純粋な関数で、3 つの OS の表をどの OS の試験でも確かめます。
  `wgft` の既定の表示は起動の時に 1 回だけ決めます
- `fdlimit`:`agent run` の起動だけで、soft を hard まで上げます。
  上げた上限は子のプロセスへ引き継がれます。Go は 1.21 から exec の前に元の値へ戻すので、子を起こす段は `original_soft` の値を `pre_exec` で戻します。
  hard が無制限の Linux では、soft を `fs.nr_open` まで上げます。Go は上げません
  macOS の頭打ちと上がることは macOS の CI の子のプロセスの試験で確かめました
  hard が無制限のときは、macOS で `kern.maxfilesperproc`、Linux で `fs.nr_open` で頭を打ちます。
  試験は soft を下げた子のプロセスで呼び、上がることを確かめます
- `winsec`:`windows-sys` で DACL を付けます。
  ファイルと一時ファイルは `CreateFileW` の `SECURITY_ATTRIBUTES` で作成の時点から付け、既存のファイルは開いた handle に `SetSecurityInfo` で付け直します。
  ディレクトリは `OICI` つきで作ります。
  利用者が SYSTEM か Administrators のときは、同じ ACE を重ねません
- 既存のファイルの付け直し:`agent.json` を読むときとロックを取るときに、`WRITE_DAC` つきで開いた同じ handle に付けます。
  付けられなければ Go と同じく拒みます。
  読みでは `secure credentials file: ...` の誤りにし、ロックでは握ったロックを手放してから誤りを返します。
  この読みは DACL を呼び出した利用者の SID で書き換えるので、`agent doctor` と制御ソケットの段は、DACL に触れない別の読みを使います
- ロックファイル:Windows では `OPEN_ALWAYS` で DACL つきで作り、通常のファイルであることを確かめます
- 制御ソケットのパスの長さ:上限は OS が決める値 (Linux と Windows は 107 byte、macOS は 103 byte) に従い、socket2 の判定を使います。
  Go が開けるパスは Rust も開けます。
  古いファイルを消す前に判定します。
  ソケットの drop は名前でファイルを消すので、認証情報のロックより先に drop します
- DACL の照合:読み返した SDDL は、保護の印と ACE の集合で比べ、trustee は SID に揃えます。
  並びや継承の印の書き方の違い、組み込みの Administrator を `LA` と書くような別名で落とさないためです。
  Windows の CI の実行で、別名が現れることを確かめました
- `ctlsock`:`socket2` の AF_UNIX の待ち受けと接続です。
  読みと書きには接続ごとの全体の期限が付きます。
  受け口のスレッドと要求の処理は「制御ソケット」の段が作ります

### 実機で確かめること

次は CI で確かめられないので、v2.0.0 の前にリリース候補の関門 (D1 と D2) と同じ項目で実機で確かめます。
それまでは未確認として扱います。

- 実機の Windows と macOS の agent が、インターネット越しに Go の v1 の server と組んで転送すること
- スリープと復帰の後にトンネルが戻ること
- 他の利用者から `agent.json` と制御ソケットが見えないこと
- 署名しないバイナリを SmartScreen と Gatekeeper が止めるか
- Windows の firewall の問い合わせと、サービスや常駐としての起動の手順
- macOS と Windows の WireGuard のソケットのバッファと UDP の受信の溢れ
- 長い時間の動作でのメモリの保持量

## 段の計画

段は gh stack の積んだ PR にします。
base はすべて `feat/v2-rust` で、#679 の上に積みます。
並行の段は、#679 の上で枝分かれした別の積みにします。
大きさは差分の行の目安で、試験を含みます。

並行の積みが同じファイルを変える場合は、先に入った積みの上に後の積みを載せ直します。
該当しやすいのは `crates/wgft/src/main.rs`、`Cargo.toml`、`Cargo.lock`、`crates/wgft-agent/src/run.rs`、`lab/lab`、`lab/sandbox.sh` です。

### wgstack を待たずに始める段

| PR | 中身 | 大きさの目安 | 依存 | 並行 |
| --- | --- | --- | --- | --- |
| 設定の層 (`feat(agent-rs): read the agent settings from flags, the environment and dotenv`) | 優先順位と出所、dotenv、値の検査、拒否の形、有効な設定の行、整数と真偽値のフラグ、誤りの出力、`version` と `--version`、`WGFT_MODE=kernel` の拒否、仕様の config の fixture との照合 | 1500 から 2000 | #679 | platform の層と並行 |
| platform の層 (`feat(agent-rs): add the platform layer for data dirs, file security and the control socket transport`) | 既定のパス、Windows の DACL、AF_UNIX の待ち受けと接続、ファイル記述子の上限、Windows と macOS の単体の試験 | 900 から 1300 | #679 | 設定の層と並行 |
| 制御ソケット (`feat(agent-rs): serve the control socket and add pubkey, rotate-key and teardown`) | 制御ソケットの受け口と止め方、`rotate-key`、`pubkey`、`teardown` の拒否、DoctorResponse の型と fixture の照合 | 800 から 1200 | 設定の層、platform の層 | |
| agent doctor の骨組み (`feat(agent-rs): add agent doctor with the checks that hold while the agent is stopped`) | [段と値の出どころ](#段と値の出どころ)の骨組み | 1200 から 1600 | 制御ソケット | 宛先と予算と並行 |
| 宛先と予算 (`feat(agent-rs): add the flow budget, the target allowlist and target probes`) | フロー数の pool、許可一覧とユニキャストの判定、名前の解決、宛先への接続の試し方、LAN の側の keepalive、試し接続。今の TCP の中継に組み込む | 1700 から 2200 | 設定の層 | agent doctor の骨組みと並行 |
| agent doctor の稼働中の検査 (`feat(agent-rs): add agent doctor's live checks`) | [段と値の出どころ](#段と値の出どころ)の稼働中の検査 | 1200 から 1600 | agent doctor の骨組み、宛先と予算 | |
| agent の device の殻 (`feat(agent-rs): drive the WireGuard device from the data plane thread`) | [データプレーンのスレッドと送る経路](#データプレーンのスレッドと送る経路)の device の側。データプレーンのスレッド、WireGuard の UDP のソケット、送る経路の順と起こし方、ソケットのバッファの要求と測定と警告、Windows の `SIO_UDP_CONNRESET`、時計の選択。核を繋ぐまでは、2 つの device をループバックで組む単体の試験で確かめる | 900 から 1300 | #679 | 上のどれとも並行。核を繋ぐ所は空けておく |
| ラボの切り替え (`test(lab): run the lab suite with the Rust agent in place of the Go agent`) | `WGFT_LAB_AGENT_IMPL`、ビルド、`AGENT_WGFT` の継ぎ目と書き換え漏れの検査、`agentdoctor.sh` の分割、`absent` の組、報告、`agent-handover.sh`、読み取りの読み替え、テストの規範の契機の表 | 600 から 1000 | #679 の lab の変更 | すべてと並行。lab の変更なので `go` の一式を両方の netstack で流す |
| CLI の文書の照合 (`test(agent-rs): check the agent commands' flags against docs/cli.md`) | 説明の module、`docs/cli.md` の節の読み取り、フラグの表と 1 行の説明の照合、使用例の有無の試験 | 700 から 1000 | 制御ソケット、agent doctor の骨組み | |

### wgstack が入った後の段

| PR | 中身 | 大きさの目安 | 依存 |
| --- | --- | --- | --- |
| wgstack の上の agent (`feat(agent-rs): run the agent on the Rust wgstack instead of a TUN`) | データプレーンのスレッドに核を繋ぐ event loop、TCP の中継を #681 の中継の trait に移す、keepalive の ping、捨てた数のログ、`inbound` の module の削除、agent の経路から TUN の殻を外す、root を要らなくする | 1500 から 2000 | #681 の核と `netstack` の handle の層、agent の device の殻、宛先と予算 |
| UDP の中継 (`feat(agent-rs): relay UDP rules over the wgstack`) | [UDP の中継](#udp-の中継) の全部、[メモリの上界の行](#メモリの上界の行)、`tunnel.udp_accounting` の値 | 1300 から 1800 | wgstack の上の agent |
| 仕上げ | `rust` の組の一式を両方の server のモードで流し、落ちた確認を直す。通った後に TUN の殻と `lab/wg-interop.sh` を消す | 落ちた数による | UDP の中継、ラボの切り替え |

main へ入れる前に、所有者の規則のとおりリファクタリングと、sanstun の使い方を含む安全の点検を行います。

### 並行の見通し

wgstack を待たずに始める段のうち、設定の層、platform の層、agent の device の殻、ラボの切り替えは同時に始められます。
その後、制御ソケットと宛先と予算が並び、agent doctor の骨組み、稼働中の検査、CLI の文書の照合が続きます。
wgstack が入った後の段は順に積みます。
wgstack の口が前提と違えば、wgstack の上の agent と UDP の中継の段だけが影響を受けます。

## 未決の点

それぞれ、推奨を採って先へ進め、実装の PR で確かめます。

- MTU の範囲:決めました。
  server が送る 576 から 9216 をそのまま wgstack の核に渡し、範囲の外だけ 1420 にします。
  核の受ける範囲も 576 から 9216 です
- メモリの上界の行の式:wgstack の項は #681 の `bound()` に合わせます。
  余裕の 32 MiB は「UDP の中継」の段のラボの測定で確かめます
- `WGFT_AGENT_BATCH_MIB` から導く量:Rust の wgstack の送信の経路が決まるまで決めません。
  受け付ける値と誤りの文面は今の仕様のままです
- インタフェースの一覧の取り方:決めました。
  Unix で `getifaddrs`、Windows で `GetAdaptersAddresses` を `hostaddr` が呼びます。
  追加の crate は使わず、`windows-sys` だけです

## 未確認の点

- 30 秒ごとの試し接続の 1 周は、agent の主な待ちの `select!` の中で待つので、その間は停止の合図 (SIGTERM、トンネルの外殻の停止) への応答が遅れます。
  遅れは最大で、試す待ち受けの数を 32 で割って切り上げた数 × 2 秒です。
  後の段で、1 周を別のタスクで走らせるか、停止の合図と並べて待つ形に直します

- LAN の側の keepalive の 3 つの値は、Linux の単体の試験で読み返して確かめました。
  macOS と Windows で同じ値が付くことは確かめていません
- Windows はループバックの閉じたポートへの接続にも SYN を送り直すので、試し接続の 2 秒の期限で `connection refused` でなく `did not answer` になりうると見込み、単体の試験の文の照合を Windows で外しました。
  実際の挙動は確かめていません
- エンドポイントの名前を `AF_INET` で引く Windows の経路は、Windows の CI の build と試験だけで、実機では確かめていません
- wgstack の UDP の口は #681 の提案で、#681 のレビューで変わりえます
- macOS の kqueue と Windows の AFD の poll で、接続した UDP のソケットへの ICMP の拒否が読みか誤りの準備として届くこと
- Windows の接続した UDP のソケットが、宛先の Port Unreachable の後に `WSAECONNRESET` を返すこと
- `GetAdaptersAddresses` が返す adapter の名前 (FriendlyName) が、TUN の名前と一致すること
- musl と glibc の `getaddrinfo` の順と Go の resolver の順の違い。wgft が並べ直すので結果には効かない見込みです
- 設定の層の Windows と macOS の挙動:既定のパス、dotenv を権限で読めないときの文面、環境変数の名前の大文字と小文字の区別は、実機で確かめていません
- 設定の層の Unicode の版の差:`%q` の引用は、Go が新しい版で割り当てた文字の扱いだけが Rust と違います
- 大きさの目安は、Go の対応するコードと今の Rust の試作の大きさからの見積もりです
- Windows の実機で、`SIO_UDP_CONNRESET` を切ったソケットが閉じたポートへの送信の後も受信を続けること。
  単体の試験はありますが、CI の Windows で流すだけです
- Windows の実機で、`QueryInterruptTimePrecise` がスリープの間も進み、データプレーンの待ちがスリープの後に期限どおりに解けること
- 1 回の起床の上限の 64 が、送信の速さと他の task の遅れに対して十分かどうか
- 中継が LAN の側のソケットを核の hook で固定する受信のバッファの値は、単体の試験では確かめていません。
  boost の変化を起こす量の転送はラボの一式だけが流します
- 1 つのスレッドのデータプレーンが中継の写しと暗号を同じ CPU で行うときの byte あたりの CPU と速さは測っていません
- macOS の UDP の `sendto` は、送信の待ち行列が溢れたときに `WouldBlock` でなく `ENOBUFS` を返すことがあると言われます。
  データプレーンは `ENOBUFS` を送信の誤りとして数えて捨て、引くことを止めません。
  この場合は書けないときに引かない規則が効かず、詰まりは核の再送で回復する見込みですが、確かめていません

[v2: Rust への移行](README.md)
