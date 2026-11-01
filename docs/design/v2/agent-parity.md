# Rust の agent が Go の agent を置き換えるための設計

この文書は、v2 の Rust の agent が Go の v1 の agent のユーザー空間モードを置き換えるまでに要るものを定めます。
対象は、Rust の wgstack 自身を除くすべてです。
契約は [agent と server の境目の仕様](../spec/README.md) です。
この文書は、その契約を Rust の agent でどう満たすかと、どの順で作るかを書きます。
この文書の内容はすべて未実装です。

## 範囲と完成の条件

置き換える対象は、agent のホストで使う Go の v1 の `wgft` のうち、ユーザー空間モードの agent とその周りのコマンドです。
具体的には `wgft agent run`、`agent pubkey`、`agent rotate-key`、`agent doctor`、`agent teardown`、`wgft version` です。

次のものはこの文書の範囲の外です。

- Rust の wgstack:sans-IO の TCP/IP の核と、中継が使う handle の層 (`crates/wgft-agent` の module `netstack`) と、その上界と、Linux との照合です。
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

## 今の Rust の agent

#679 の時点で、Rust の agent は次を持ちます。
作りは [Rust の agent の制御プレーン](agent-control.md) と [agent の WireGuard の device の層](wireguard-device.md) にあります。

| crate | 持つもの |
| --- | --- |
| `wgft-proto` | wire の版 1 の型、接続文字列、登録の要求と応答、理由の整形、仕様の fixture との照合 |
| `wgft-wireguard` | sanstun の上の sans-IO の WireGuard の device |
| `wgft-wireguard-tun` | 試作だけの Linux の TUN の殻 |
| `wgft-agent` | 登録、認証情報、stream、全体状態の適用、ハートビート、トンネルの監視と作り直し、TUN の入口の検査、カーネルのソケットの上の TCP の中継 |
| `wgft` | `wgft agent run` と `wgft version` |

試作の中継はカーネルの TCP/IP を TUN 越しに使うので、root か `CAP_NET_ADMIN` が要ります。
試作の UDP のルールは `error` を報告するだけです。
試作に無い設定 (`WGFT_CONFIG`、`WGFT_AGENT_ALLOW_TARGETS`、`WGFT_MAX_*_FLOWS`、`WGFT_AGENT_BATCH_MIB`) は終了コード 3 で拒みます。

## 差分の一覧

Go の v1 の agent と仕様に対して、今の Rust の agent に無いものと違うものを挙げます。
「段」の列は[段の計画](#段の計画)の PR の名前です。
「wgstack」は wgstack の担当が作り、この文書の段はそれを使うだけのものです。
「Go の性質」は、仕様の書き方と同じく、Go の標準ライブラリか実行環境の性質で決まる v1 の挙動です。

### トンネルとデータプレーン

| 項目 | 仕様 | 今の Rust | 段 |
| --- | --- | --- | --- |
| TUN とカーネルの TCP/IP | [tunnel.md の範囲と前提](../spec/tunnel.md#範囲と前提)。netstack はプロセスの中に持ち、ホストのアドレスと経路と firewall を変えない | TUN の殻とカーネルの TCP/IP。root が要る | wgstack と「wgstack の上の agent」 |
| トンネルの入口の検査 | [tunnel.md のトンネルの入口の検査](../spec/tunnel.md#トンネルの入口の検査)。断片の再組み立て、MSS の下限、ICMP の誤りの送信元、UDP の受信の予算 | `inbound` の module が TUN の前で判定する。断片は捨てる | wgstack。`inbound` の module は消す |
| 入口の検査が捨てた数 | [tunnel.md のトンネルの入口の検査](../spec/tunnel.md#トンネルの入口の検査)。捨てた数を数え、英語のログに 1 分に 1 回まで出す | `inbound` の module が自分の判定の数を数えてログに出す | wgstack が理由ごとの数を持ち、「wgstack の上の agent」が Go と同じ文面で出す |
| 待ち受けの無いポート | SYN に RST、UDP に Port Unreachable | SYN に RST。UDP には返さない | wgstack |
| MSS | MTU から 40 を引いた値を示す | カーネルが決める | wgstack |
| keepalive の ping | [tunnel.md の keepalive の ping](../spec/tunnel.md#keepalive-の-ping) | カーネルの ICMP のソケット | 「wgstack の上の agent」が wgstack の ping の口に替える |
| MTU | server は 576 から 9216 を送る。v1 の agent は検査しない | 576 から 9000 の外なら 1420 を使う | 「wgstack の上の agent」が wgstack の受ける範囲に合わせる。未決の点に挙げる |
| WireGuard のソケットのバッファ | [socket-buffers.md](../userspace/socket-buffers.md)。7 MiB を要求し、FORCE も試し、トンネルを立てるたびに測り、条件に届かなければ英語の 1 行を出す | 無い | 「agent の device の殻」 |
| 受信の誤りで止まらないこと | [tunnel.md の受信の goroutine の停止](../spec/tunnel.md#go-の性質受信の-goroutine-の停止)。Windows の `WSAECONNRESET` | Linux の殻だけ | 「agent の device の殻」が Windows で `SIO_UDP_CONNRESET` を切る |
| サスペンドの間の時計 | [tunnel.md のサスペンドの間の時計](../spec/tunnel.md#go-の性質サスペンドの間の時計)。Windows ではスリープの間も進む時計 | `Instant` | 未決の点に挙げる |
| 新しいハンドシェイクで stream の待ちを打ち切ること | [tunnel.md のハンドシェイクの監視と作り直し](../spec/tunnel.md#ハンドシェイクの監視と作り直し) | 待ちの上限を 10 秒にする扱いはある。待ちの途中で打ち切るかは確かめていない | 「agent の device の殻」で確かめ、無ければ足す |

### 中継

| 項目 | 仕様 | 今の Rust | 段 |
| --- | --- | --- | --- |
| TCP の中継の土台 | [tunnel.md の TCP の中継](../spec/tunnel.md#tcp-の中継) | トンネルの側もカーネルのソケット | 「wgstack の上の agent」が wgstack の TCP の口に替える |
| 終わり方の表 | 上限と拒否は握手の後に RST、宛先の失敗は FIN、ポートの消滅と停止は RST | 停止とポートの消滅の RST は `SO_LINGER` 0 で作る | 「wgstack の上の agent」が wgstack の abort と close に写す |
| LAN の側のソケットの受信の扱い | [wgstack.md の今の境目](../userspace/wgstack.md#今の境目) の `OnBoost` と `FollowBoost` | 無い | 「wgstack の上の agent」。wgstack の口が決まってから |
| LAN の側の TCP の keepalive | Go の性質:宛先への接続は `net.Dialer` の既定の keepalive を持つ。無通信 15 秒、間隔 15 秒、9 回 | 付けていない | 「宛先と予算」が socket2 で同じ値を付ける |
| 宛先への接続の試し方 | [tunnel.md の宛先への接続の試し方](../spec/tunnel.md#go-の性質宛先への接続の試し方)。同じ族を先に、300 ミリ秒後にもう一方、期限をアドレスで分ける | 名前のまま 10 秒で接続する | 「宛先と予算」 |
| 宛先の名前の解決 | Go の性質:Go の resolver で引き、RFC 6724 の順に並べる。許可一覧があれば 5 秒の期限 | tokio の解決に任せる | 「宛先と予算」。設計は[名前の解決](#名前の解決) |
| 宛先の試し接続 | [tunnel.md の宛先の試し接続](../spec/tunnel.md#宛先の試し接続)。待ち受けを開いたときと 30 秒ごと、2 秒、32 件 | 無い | 「宛先と予算」 |
| 宛先の許可一覧 | [targets.md の宛先の許可一覧](../userspace/targets.md#宛先の許可一覧) | 設定を拒む | 「設定の層」が値を読み、「宛先と予算」が判定する |
| ブロードキャストとマルチキャスト | [targets.md](../userspace/targets.md#ブロードキャストとマルチキャストの宛先) | 無い | 「宛先と予算」 |
| フロー数の上限 | [tunnel.md のフロー数の上限](../spec/tunnel.md#フロー数の上限) と [flow-limits.md](../userspace/flow-limits.md)。プロセス全体とルールごと、最低分と予備、拒否の理由 | 無い | 「宛先と予算」 |
| UDP の中継 | [tunnel.md の UDP の中継](../spec/tunnel.md#udp-の中継) | ルールを `error` にする | 「UDP の中継」。設計は [UDP の中継](#udp-の中継) |

### 制御ソケットと診断

| 項目 | 仕様 | 今の Rust | 段 |
| --- | --- | --- | --- |
| 制御ソケット | [control-socket.md](../spec/control-socket.md)。`rotate-key` と `doctor` | 無い | 「制御ソケット」 |
| `agent doctor` | [control-socket.md の agent doctor --json](../spec/control-socket.md#agent-doctor---json) と [検査の一覧](../diagnosis/agent-evidence.md#検査の一覧と証拠の出どころ) | 無い | 「agent doctor の骨組み」と「agent doctor の稼働中の検査」 |

### CLI と設定

| 項目 | 仕様 | 今の Rust | 段 |
| --- | --- | --- | --- |
| コマンド | [cli-config.md のコマンド](../spec/cli-config.md#コマンド) | `agent run` と `version` | 「制御ソケット」と「agent doctor の骨組み」 |
| `wgft version` | 2 行。版と `protocol range: v1-v1` | `wgft <crate の版>` の 1 行 | 「設定の層」 |
| `--version` と `-v` | 版の 1 行 | 無い | 「設定の層」 |
| 優先順位 | フラグ、環境変数、dotenv、既定。出所を覚える | clap の `env` で読み、dotenv を読まない | 「設定の層」 |
| dotenv | [cli-config.md の dotenv の構文](../spec/cli-config.md#dotenv-の構文)。読み取りの誤りと権限の文面 | 読まずに拒む | 「設定の層」 |
| 有効な設定の行 | [cli-config.md の有効な設定の行](../spec/cli-config.md#有効な設定の行) | 無い | 「設定の層」 |
| 入口での検査の順 | [cli-config.md の入口での検査の順](../spec/cli-config.md#入口での検査の順) | 一部 | 「設定の層」 |
| `WGFT_WG_INTERFACE` の検査 | `dev_valid_name` に合わせた判定と文面 | 1 から 15 byte で、`/`、`%`、空白を拒む独自の判定 | 「設定の層」 |
| `WGFT_MODE=kernel` | Linux 以外は Linux の前提の拒否。Linux では「このビルドにカーネルモードが無い」拒否 | 値の誤りとして拒む | 「設定の層」 |
| 整数のフラグ | Go の整数の書き方 (`0x`、先頭の 0 の 8 進、`_`) | 試作は値を受けない | 「設定の層」 |
| 真偽値のフラグ | `--json` と `--json=false` の形だけ | 無い | 「設定の層」 |
| フラグの誤りの出力と終了コード | `Error: <文>` の 1 行で使い方を書かない。終了コード 1、`agent doctor` は 2 | clap の既定。使い方を書き、終了コード 2 | 「設定の層」 |
| 既定のパス | Linux、macOS、Windows の表。macOS は `$HOME`、Windows は `%ProgramData%` | Linux と固定の `C:\ProgramData` | 「platform の層」 |
| 設定ファイルの権限の警告 | Unix で other が読める dotenv が `WGFT_JOIN` を持つとき | 無い | 「設定の層」 |
| メモリの行 | `memory soft limit:` の行。Go 以外は書かなくてよい | 無い | 「UDP の中継」が `memory bound:` の行を書く。[メモリの上界の行](#メモリの上界の行) |
| `docs/cli.md` | Go の `TestCLIDocUpToDate` | 無い | 「CLI の文書の照合」 |

### 認証情報と platform

| 項目 | 仕様 | 今の Rust | 段 |
| --- | --- | --- | --- |
| Windows の DACL | [credentials.md の Windows の DACL](../spec/credentials.md#windows-の-dacl) | 無い | 「platform の層」 |
| ロック | `flock` と `LockFileEx` | `File::try_lock` で同じ方式 | 済み。Windows の試験を「platform の層」が足す |
| 一時ファイルの片付け | ロックを取った後に消す | 消す | 済み |
| 時刻の印の水位 | Go の agent には無い | `agent.json.clock` に残す | 済み。Rust だけのファイルで、Go の agent は読まない |
| ファイル記述子の上限 | Go の性質:Go の実行環境は Unix で起動の時に soft の `RLIMIT_NOFILE` を hard の値まで上げる。macOS では `kern.maxfilesperproc` で頭を打つ。同梱の unit と plist は `LimitNOFILE` を書かず、これに頼る | 上げない | 「platform の層」 |

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
| `close_udp` | endpoint を閉じ、予約をすべて返します。handle の層は待っている受け取りと送るを解きます |
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
- 起こし方:中継の task が核の操作 (書き込み、close、accept、`send_to`、`close_udp` など) をするたびに、データプレーンのスレッドの local の知らせ (`tokio::sync::Notify` の類) を鳴らし、駆動する task を起こします。
  核の出力は操作の結果として増えるので、ソケットの準備やタイマーを待たずに引くためです
- 上界:1 回の起床で作る packet の数の上限は #681 の値に従います
- 時計:device と核に渡す時刻の時計は同じものにします (未決の点のサスペンドの間の時計)

## 名前の解決

宛先の名前 (TCP の接続 1 本ごと、UDP のセッション 1 つごと、試し接続) は、すべて次の 1 つの resolver で引きます。
WireGuard のエンドポイントの名前は A レコードだけを引く別の規則 ([tunnel.md のエンドポイントの解決](../spec/tunnel.md#エンドポイントの解決)) ですが、同じ仕組みの上で引きます。

- 仕組み:OS の `getaddrinfo` を、上限のある blocking のスレッドで呼びます。
  OS の resolver の設定に従うためです
- 同時の数:`tokio::sync::Semaphore` で、宛先の名前を同時に引く数を 8 に抑えます。
  許可を待つ時間も期限に含めます
- エンドポイントの許可:WireGuard のエンドポイントの名前は、宛先の名前とは別の許可 1 つで引きます。
  宛先の名前の解決が許可を使い切っても、トンネルの名前の引き直しが止まらないようにするためです
- 期限:v1 と同じく、許可一覧の有無で分けます。
  許可一覧が無いときは、名前の解決は接続の期限の 10 秒の中に入ります。
  許可一覧があるときは、名前の解決に 5 秒の期限を持ち、接続の期限の 10 秒は解決の後から数えます ([targets.md の宛先の許可一覧](../userspace/targets.md#宛先の許可一覧))。
  試し接続も同じ分け方で、接続の期限の代わりに試し接続の 2 秒を使います。
  エンドポイントの名前の期限は 5 秒です
- 期限を過ぎたとき:呼び手は誤りを受け、結果を待ちません。
  スレッドは `getaddrinfo` が戻るまで動き続け、戻った結果を捨ててから許可を返します。
  このため、応答しない resolver が許可を持ち続けると、後の解決は許可を待って期限で失敗します
- 順:引いたアドレスは、v1 の Go の resolver と同じ RFC 6724 の宛先の規則で wgft が並べ直します。
  `getaddrinfo` の順は libc と設定 (`gai.conf`) で変わるためです
- 上界:スレッドの数は許可の数で決まり、スレッド 1 本はスタックと `getaddrinfo` の作業の領域を持ちます。
  [メモリの上界の行](#メモリの上界の行)に許可の数 × スレッド 1 本の大きさを入れます

## メモリの上界の行

`agent run` は起動の時に `memory bound: <N> MiB, derived from the flow caps; it counts what the process holds, not the kernel socket buffers` を書きます。
Go の `memory soft limit:` の行の代わりで、ラボの `lifecycle.sh` の check 5 と 5b がこの値を読みます。
`<N>` は次の和で、`WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS` から導きます。

- 固定の基礎:実行ファイル、tokio の実行環境、制御ソケットのスレッド、stream と TLS の状態です。
  起動の直後のラボの測定から定数を決めます
- wgstack の上界:核の `bound()` が返す値です (#681)
- WireGuard の device:[device のキューと上界](wireguard-device.md#キューと上界) の値です
- TCP の中継:接続 1 本の固定の大きさと、データが流れる間だけ借りる写しのバッファ (向きごとに 32 KiB、Go の `internal/netpipe` と同じ) の和 × `WGFT_MAX_TCP_FLOWS` です
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
- 順:スレッドは接続を 1 つずつ扱います。
  1 つの接続が期限の 30 秒まで握り続けると、その間の次の接続は待ちます。
  相手は同じホストの CLI だけで、要求の頻度も低いので、この待ちを許します
- ソケット:`socket2` の AF_UNIX を Linux、macOS、Windows で使います。
  `socket2` は Windows の AF_UNIX の型を持ちますが、Windows の実行時の挙動は確かめていません
- 開き方:起動のたびに同じパスの古いファイルを消してから待ち受けます。
  パスが 103 byte を超えて開けなければ、その旨をログに出して制御ソケットを使わずに動きます
- 権限:Unix では 0600 にし、失敗を無視します。
  Windows では開いた直後に [credentials.md の DACL](../spec/credentials.md#windows-の-dacl) を付け、付けられなければソケットを閉じて使わずに動きます
- 期限:接続ごとに読みと書きの全体を 30 秒で打ち切ります
- 要求:前後の空白を除いて `rotate-key`、`doctor` と照らし、それ以外には `error: unknown command` を返します
- 実行時への受け渡し:スレッドは要求を tokio の channel で実行時のタスクへ渡し、応答を待ちます。
  `rotate-key` は鍵を作り直して `agent.json` に保存し、トンネルを作り直し、`ok <公開鍵>` を返します
- 応答を組む処理の失敗:制御ソケットのスレッドの中の処理だけを `catch_unwind` で囲みます。
  実行時の tokio のタスクの panic は、応答の oneshot が値を送らずに落ちる形で届くので、スレッドはそれを失敗として扱います。
  どちらの場合も `{"error": ...}` の 1 行を返し、転送を止めません
- 止め方:停止のとき、実行時は止める印を立ててから自分のソケットに 1 回接続し、accept で止まっているスレッドを起こします。
  スレッドは印を見て待ち受けを閉じ、ファイルを消して終わります

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
  `detail` は人向けなので、この置き換えは保証の範囲を変えません
- `host.privileges`:Windows では Go と同じく作成の可否を判定せず `permission_not_determined` にします
- カーネルモードの検査:`dataplane.interface`、`dataplane.table`、`host.forwarding` は、ユーザー空間モードでは Go と同じく `not_tested` と `userspace_mode` です
- カーネルモードの記録:`agent.json` がカーネルモードを記録している場合、Rust のビルドはカーネルを読めないので診断しません。
  `agent teardown` と同じく、種別 `prerequisite`、対象 `WGFT_MODE` の `cannot continue` で拒み、終了コードは 3 です。
  理由は `this build does not include the agent's kernel mode yet, so it cannot diagnose a kernel-mode agent; use a build that includes it` です

### 段と値の出どころ

`agent doctor` は 2 つの PR に分けます。

- 骨組み:コマンド、停止中にも成立する検査 (`host.*`、`agent.*`、`tunnel.resolve`)、`agent.control` の接続と理由、報告の JSON と文の出力、総合判定と終了コード、設計の表との照合です。
  「制御ソケット」の段の上に積みます
- 稼働中の検査:DoctorResponse から読む `stream.*`、`tunnel.*`、`relay.*` の検査です。
  `relay.sessions` と `relay.refusals` の値がフロー数の pool から来るので、「宛先と予算」の段の上に積みます

wgstack の内部に依るのは `tunnel.udp_accounting` だけです。
`tunnel.socket_buffers` と `tunnel.transfer` は WireGuard の device とその殻に、`relay.*` は中継とフロー数の pool に依ります。
wgstack の口が入るまで、agent は `udp_accounting` を応答に入れず、`tunnel.udp_accounting` は `unknown` と `udp_accounting_not_reported` になります。

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

### 既定のパス

| OS | `WGFT_DATA_DIR` の既定 | dotenv の既定 |
| --- | --- | --- |
| Linux と他の Unix | `/var/lib/wgft` | `/etc/wgft/agent.env` |
| macOS | `$HOME/Library/Application Support/wgft` | 同じディレクトリの `agent.env` |
| Windows | `%ProgramData%\wgft` | 同じディレクトリの `agent.env` |

既定はプロセスの起動の時に 1 回だけ決め、`--help` の既定の表示にも同じ値を出します。
macOS で `HOME` が空なら作業ディレクトリの `wgft`、Windows で `ProgramData` が空なら `C:\ProgramData` を使います。
Windows の環境変数の名前は大文字と小文字を区別せずに引きます。
Rust の `std::env::var` は Windows の API を使うので同じ扱いになると見込みますが、確かめていません。

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
| `stream: connected to` と `server selected protocol v1` | `upgrade.sh`、`version-skew.sh` |
| `warning: the WireGuard UDP sockets` | `lifecycle.sh` の check 12 |
| `listener tcp/<port> closed` | `lifecycle.sh` の check 2 |
| `listener tcp/<port>: bind ...` | `lifecycle.sh` の check 2 と 11。行が無いことを確かめる |
| `listener tcp/<port> -> <宛先> opened; rule <ID>` | 上の行が無いことの確認と組にする |
| `<待ち受け>: <理由>; refusing new connections` | フロー数の拒否。`lifecycle.sh` の check 5 の系列。`<理由>` は Go の `internal/resource/pool.go` の拒否の文 (`flow budget full: ...`、`rule <ID> holds ... for a rule added later`、`... below its minimum ...` など) をそのまま写します |
| `dropped TCP handshakes that advertise an MSS below 536` | `exhaustion.sh` の `mss`。wgstack の捨てた数の口が要る |

行が無いことを確かめる `absent` の確認は、Rust の agent が別の文面を書いても通ってしまいます。
ラボの切り替えの PR は、Rust の agent で流す確認の `absent` を、同じ出来事で必ず出る行の存在の確認と組にします。
同じ PR で、ラボの台本が agent のログを照らす箇所を数え直し、この表を直します。

Go と変える行は次のとおりです。

- メモリ:`memory soft limit:` の行を書かず、[メモリの上界の行](#メモリの上界の行)を書きます。
  `GOMEMLIMIT` は読まず、行も書きません
- netstack:`WGFT_AGENT_NETSTACK` の出所が既定でなければ、`WGFT_AGENT_NETSTACK=<値>: unused, since this build has one network stack, wgft's own; the setting is kept so the same agent.env works` を書きます。
  値は `gvisor` も `wgstack` も受け付けますが、どちらも実装を選ばず、使いません。
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
- 試作の物:`wgft-rs` は、TUN が製品の経路から外れる段で置かなくなります。
  TUN の殻 (`wgft-wireguard-tun`) とラボのための wireguard-go は、device の層を Linux と wireguard-go と照らす `lab/wg-interop.sh` の道具として、ラボの一式が Rust の agent で通るまで残します。
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
  意図して Go の `wgft` を呼ぶ行には、行末に印 `# lab: go agent` を付け、検査はこの印の行だけを許します
- `go` のとき:書き換えは機械的で、挙動は変わりません

### 確認の分け方

`lab/suite.txt` の確認は、`lifecycle.sh` の check 4 を除いて agent を起動します。
完成の条件に入る確認と、Go の agent を使い続ける確認を次のように分けます。

| 分類 | 確認 | `rust` のときの扱い |
| --- | --- | --- |
| 条件に入る | `e2e.sh`、`ipv6.sh`、`usage.sh`、`rates.sh`、`split-merge.sh`、`import-export.sh`、`connlimit.sh`、`lifecycle.sh` の各 check、`exhaustion.sh` の `postclose` (server がユーザー空間モード)、`acceptq`、`ackflood`、`wgstall` と kernel の `mss`、`agentdoctor.sh` の `== userspace` の節 | Rust の agent で流します |
| カーネルモードの agent | `agentkernel.sh`、`agentdoctor.sh` のカーネルモードの節、userspace の `exhaustion.sh mss` (server の netstack を確かめるため agent をカーネルモードで起動する) | `rust` の組では流さず、結果を `go` の組から取ります。agent のカーネルモードを移す段で条件に入れます |
| opt-in | `agentmem.sh`、`exhaustion.sh kernel postclose`、`version-skew.sh` | 下に書きます |

`agentdoctor.sh` の `== userspace` の節は、ユーザー空間モードの agent を起動して `agent doctor` を確かめます。
ラボの切り替えの PR で、この節をカーネルモードの節と分けて呼べる形にし、`AGENT_WGFT` で流します。
この節の `baseline_compare` は、`AGENTDOCTOR_BASELINE` の `wgft` の診断と今の診断の ID と状態と理由を比べます。
`rust` の組で `AGENTDOCTOR_BASELINE` に Go の `wgft` を渡すと、Go の CLI が Rust の agent の制御ソケットを読む組み合わせを確かめられます。

Go の実行環境に依る読み取りは次のように扱います。

- `lifecycle.sh` の check 5 と 5b:agent の `memory soft limit:` の行の代わりに `memory bound:` の行を読み、RSS がその値と[余裕](#メモリの上界の行)の和を超えないことを確かめます。
  server の側の行は今のまま Go の server を読みます
- `exhaustion.sh` の gctrace:既定の確認のうち、判定に使うヒープは server のもの (ユーザー空間モードの `postclose`) です。
  `acceptq`、`ackflood`、`wgstall` は agent のヒープを測って示すだけで、判定に使いません。
  `rust` のときこれらの行は値を持たず、RSS だけを示します
- `exhaustion.sh kernel postclose`:カーネルモードの server の後ろで、agent の netstack の閉じた後の接続の表を agent のヒープで確かめます。
  Go の gVisor の表に固有の確認なので、Rust では wgstack の TIME_WAIT の表の設計が測り方 (表の行の数か wgstack の保持量) を決め、それまで `rust` では流しません
- `agentmem.sh`:Go の wgstack の memprobe に依るので、`rust` のときは `SKIP` を出します。
  Rust の wgstack の保持量の測り方は #681 の「保持の量の測り方」が決めます
- `version-skew.sh`:Rust の agent と古い Go の server の組み合わせを確かめるので、リリース候補の関門で `rust` の組でも流します

### netstack の軸

Rust の agent は netstack を 1 つしか持たないので、`--netstack` の軸を持ちません。
`--agent-impl rust` と `--netstack wgstack` か `both` の組み合わせでは、`rust` の組を 1 回だけ流します。
`--agent-impl both --netstack both` は、`go` と既定の netstack、`go` と wgstack、`rust` の組を流します。

### 結果の報告

- `summary.json` に `agent_impl` を記録し、合わせるときに異なる値が混ざれば誤りにします
- 組ごとの出力は `<out>/<agent_impl>/<netstack>/` に置き、見出しを `==== lab suite: agent=<impl>, netstack=<netstack>, N VMs` にします
- `rust` の組の報告には、カーネルモードの agent の確認を `go` の組から取った結果として印を付けて載せます
- PR の本文には組ごとに、確認ごとの PASS と FAIL を書きます。
  完成の条件の判定には `rust` の組で「条件に入る」確認がすべて PASS であることを使います

### 試作の台本

`lab/rust-agent.sh` の確認のうち、Go の agent と Rust の agent の間の `agent.json` の引き継ぎは、TUN に依らない価値があるので残します。
TUN、入口の検査、root に依る確認は外し、台本の名前を `lab/agent-handover.sh` に替え、両方のバイナリを作ったときだけ流す opt-in の確認にします。

### 流す頻度と関門

ラボの切り替えが入った後、agent の crate を変える PR は、ラボの一式の `rust` の組を積みの先頭で 1 回流します。
「wgstack の上の agent」の段より前は、Rust の agent が TUN の試作の形なので、`rust` の組の結果は報告だけに使い、マージの関門にしません。
「wgstack の上の agent」の段から後は、`rust` の組の結果をマージの関門にします。
ラボの切り替えの PR は、この扱いを[テストの規範](../../development/testing.md)の契機の表に書きます。
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

- サスペンドの間の時計:Linux と macOS の `Instant` はサスペンドの間に止まり、v1 と同じです。
  Windows の `Instant` は `QueryPerformanceCounter` で、スリープの間に進むかを確かめていません。
  推奨は、Windows では `QueryInterruptTime` から作る時計を device と監視に渡すことです。
  これには `windows-sys` の呼び出しが要ります
- MTU の範囲:server は 576 から 9216 を送ります。
  推奨は、この範囲をそのまま wgstack に渡し、範囲の外だけ 1420 にすることです。
  wgstack の受ける上限が 9216 より小さければ、wgstack の設計に合わせて直します
- メモリの上界の行の式:wgstack の項は #681 の `bound()` に合わせます。
  余裕の 32 MiB は「UDP の中継」の段のラボの測定で確かめます
- `WGFT_AGENT_BATCH_MIB` から導く量:Rust の wgstack の送信の経路が決まるまで決めません。
  受け付ける値と誤りの文面は今の仕様のままです
- インタフェースの一覧の取り方:ブロードキャストの判定はホストのインタフェースのアドレスとプレフィクス長を読みます。
  推奨は、Unix で `getifaddrs`、Windows で `GetAdaptersAddresses` を platform の層で呼ぶことです。
  寛容なライセンスの crate で同じことができれば、それを使います
- 新しいハンドシェイクで stream の再接続の待ちを打ち切ること:#679 が待ちの途中で打ち切るかを確かめます。
  打ち切らなければ agent の device の殻の段で足します

## 未確認の点

- wgstack の UDP の口は #681 の提案で、#681 のレビューで変わりえます
- macOS の kqueue と Windows の AFD の poll で、接続した UDP のソケットへの ICMP の拒否が読みか誤りの準備として届くこと
- Windows の接続した UDP のソケットが、宛先の Port Unreachable の後に `WSAECONNRESET` を返すこと
- `socket2` の AF_UNIX が Windows の実行時に動くこと
- Rust の `std::env::var` が Windows で環境変数の名前の大文字と小文字を区別しないこと
- musl と glibc の `getaddrinfo` の順と Go の resolver の順の違い。wgft が並べ直すので結果には効かない見込みです
- ラボの台本が照らす agent のログの行の一覧は、調べた範囲のもので、ラボの切り替えの PR で数え直します
- 大きさの目安は、Go の対応するコードと今の Rust の試作の大きさからの見積もりです

[v2: Rust への移行](README.md)
