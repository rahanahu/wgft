# API の境界 (N5)

この文書は、推奨の構成 S の、protocol と I/O に依らない API の境界を定めます。
shard ごとの sans-IO の核、engine、link の adapter、トンネルの変換、アプリケーションの API、受動と能動の open に共通の TCP の状態の模型を扱います。
未実装の dial は、並列の構成に依らない TCP の仕様として整理し、この提案では製品に実装しません。
未採用の提案です([提案の索引](README.md))。

## 層の分け方

```mermaid
flowchart TB
  APP[アプリケーション<br/>agent の中継 / ライブラリの利用者]
  ENG[engine<br/>shard のスレッド / 持ち主の選び方 / 予算と置き場 / 輪]
  CORE[shard ごとの sans-IO の核<br/>TCP / UDP / ICMP / 再組み立て]
  TR[トンネルの変換<br/>WireGuard か何もしない変換]
  LINK[link の adapter<br/>WireGuard の UDP / 平らな UDP / TUN / ライブラリ / 将来の AF_XDP]
  APP <--> ENG
  ENG <--> CORE
  ENG <--> TR
  TR <--> LINK
```

- 核は I/O、スレッド、時計、乱数、錠、atomic を持たず、今と同じく `&mut` で呼ぶ値です
- engine はスレッド、持ち主の選び方、予算と置き場、輪、link と変換の駆動を持ちます
- 変換は link の datagram と核の IPv4 packet の間を変えます
- link は外の世界との datagram の受け渡しだけを持ちます

## shard ごとの sans-IO の核

核は今の `Stack` の API ([sans-IO の API](../../v2/wgstack-rs.md#sans-io-の-api)) を保ち、次を加えます。

| 加えるもの | 中身 |
|---|---|
| shard の文脈 | 作成の時に shard の番号と N を受け、IP ID の間隔と乱数の種を決めます。N = 1 では今と同じ値です |
| 入口の判定 | shard 0 の核は、4 つ組の表の項が別の shard の接続を指す時、処理せずに (持ち主、枠、世代) を返します。今の入口の検索の結果を使い、2 回引きません |
| 渡す確立 | shard 0 の核は、握手の最後の ACK で、確立する代わりに交渉した値の組を返し、表の項を持ち主の枠に替えます |
| 受ける確立 | 持ち主の核は、交渉した値の組と最後の ACK の packet から接続を確立します。dial の設計が決めた、交渉した値の組から始める確立の入口と同じです |
| dial の予約 | shard 0 の核は、一時ポートを選び、表に (持ち主、枠、世代) の項を入れます。持ち主の核は、その枠に SYN-SENT の接続を作ります |
| TIME_WAIT の行の返却 | 持ち主の核は、行に移る時に行の中身を返し、枠を空けます。shard 0 の核は行を入れ、表の項を行に替えます |
| 予算の credit | 全体の予算を直接持たず、engine が渡す credit から借ります |

核の型は shard 0 と持ち主で同じです。
持ち主の核は、待ち受け、握手の途中、TIME_WAIT の表、再組み立ての表、UDP の endpoint の容量を 0 にして作ります。
今の核はすでに握手の途中の表の容量 0 を受け付けます([dial の側を足す継ぎ目](../../v2/wgstack-rs.md#dial-の側を足す継ぎ目))。

## engine

- 作成:設定 (アドレス、上限、MTU) と link と変換を受け、起動の時の CPU の数から N を決めます。
  N の設定は持ちません([CPU の数ごとの動かし方](performance.md#cpu-の数ごとの動かし方))
- N = 1:Inline の駆動の経路をそのまま使います。
  N が 2 以上の経路とは別の関数にし、N = 1 の経路に輪と atomic を置きません(設計判断)
- スレッド:N が 2 以上の時、持ち主の shard のスレッドを作成の時に作り、スタックの大きさを明示します
- 停止:engine を閉じると全 shard を止め、予算と置き場を返します。
  今の `close` と同じく、次の世代に予算を渡せます
- 実行環境:各 shard は自分の event loop を持ちます。
  agent では今と同じく tokio の current-thread の実行環境を shard ごとに持ち、中継の task は接続の持ち主の shard で動きます

## link の adapter

link の adapter は、datagram のバッチの受け渡しと、その能力を示します。

| 能力 | 意味 |
|---|---|
| queue の数 | 受ける queue の数。最初の試作は 1 だけを扱います |
| queue の振り分け | queue が 1 つか、flow の hash で分けた複数か |
| まとめた受け渡し | 1 回の呼び出しで複数の datagram を受け渡せるか (`recvmmsg`、`sendmmsg`) |
| 結合と分割 | 受信の結合と送信の分割 (UDP の GRO と GSO) を持つか |
| 枠の持ち主 | 受けた枠が engine の置き場のものか、link が貸すもの (AF_XDP の UMEM) か |
| 最大の datagram | 受け渡す datagram の最大の大きさ |

| adapter | 中身 | 段階 |
|---|---|---|
| WireGuard の UDP | 今の外側の UDP のソケットとバッチ | 最初から |
| 平らな UDP | 暗号の無い UDP で IPv4 packet を運びます。試験と、暗号を別に持つ利用者のためです | 試作の P2 |
| TUN | TUN の device の IPv4 packet を読み書きします | 汎用のスタックとしての利用で加えます |
| ライブラリの直接の呼び出し | アプリケーションが packet を渡し、packet を受け取ります | 試作の P0 |
| AF_XDP | NIC の queue の UMEM の枠を貸し借りします | 将来の候補で、作るかは未決です |

借りた枠の規則は、所有者の写しの方針に従います([バッチの作りの規則](../../v2/agent-throughput.md#バッチの作りの規則))。

- 短く終わる処理 (header の読み、復号、checksum) は link の枠を借用します
- 長く持つデータは、予算のある置き場に写して枠を返します
- link が貸す枠は、スレッドをまたぐ前に平文の block に写します。
  持ち主の処理を待たせて link の枠を押さえないためです([持ち主ごとの block の上限](memory.md#持ち主ごとの-block-の上限))

TAP は L2 の header と近隣の解決を要し、核は IPv4 の L3 だけを扱うので、この提案の範囲に入れません。

## トンネルの変換

| 向き | 呼ぶ所 | 形 |
|---|---|---|
| 受信 | shard 0 | 今の `Device::handle_datagram` の 1 回の呼び出し。復号、replay の確定、endpoint の更新を datagram の順に行います |
| 送信 (shard 0) | shard 0 | 今の `Device::handle_packet` の 1 回の呼び出し。UDP、制御の packet、N = 2 の shard 0 の接続です |
| 送信の貸し出し | shard 0 | device の層に加える口で、`begin_encapsulate` を在庫の分だけ呼び、`PendingEncapsulate` と endpoint を返します |
| 送信 (持ち主) | 持ち主の shard | 借りた `PendingEncapsulate::encrypt` で暗号化します。状態を持たず、どのスレッドでも動きます |
| 制御 | shard 0 | ハンドシェイク、cookie、keepalive、鍵の交換、タイマー |

sanstun は変えません。
使う口はどれも sanstun の公開の API です。
`PendingEncapsulate` をスレッドの間で渡せる型であること (`Send`) は、コードの読みでは鍵の写しと数値だけを持つ値ですが、型の確認は実装の時に行います(未確認)。

何もしない変換は大きさ 0 の型で、受信は link の枠をそのまま平文として借用させ、送信の貸し出しを作りません。
engine は変換を型の引数で受けるので、何もしない変換の時は貸し出しの輪と暗号の呼び出しを作らず、その費用を払いません(設計判断)。

## アプリケーションの API

### 接続の識別

| 識別子 | 中身 |
|---|---|
| `ConnId` | shard の番号、その shard の枠の番号、64 bit の世代 |
| `ListenerId`、`UdpId` | ポートと 32 bit の世代。今と同じです |
| `PingId` | 今と同じです |

接続は作成の後に shard を移らないので、`ConnId` に shard の番号を含め、操作を 1 回で持ち主に届けられます。
N = 1 の shard の番号は常に 0 です。

### 操作の届け方

- agent の中継:中継の task は接続の持ち主の shard の上で動き、今の handle の層 (`wgft-netstack`) を通して自分の shard の核を同じスレッドで呼びます。
  accept の loop は shard 0 で動き、accept した接続の中継を持ち主の shard で始めるよう、engine の口で求めます
- ライブラリの利用者:利用者のスレッドは shard の外にあるので、engine は操作を持ち主の shard の命令の輪に載せ、結果と知らせを利用者の側の輪で返します。
  命令の輪が満ちた時は、操作は状態を変えずに `WouldBlock` を返します
- 読み書きの約束:`read` と `write` は今と同じく、できない時は状態を変えずに `WouldBlock` を返し、後で知らせが届きます。
  ライブラリの利用者には、命令の結果が届くまで待つ同期の口と、結果を後で受け取る非同期の口の両方を置きます
- 知らせの順:1 つの接続の知らせは、その持ち主の shard だけが出すので、1 つの輪の順に届きます。
  別の接続の知らせの間の順は約束しません
- accept:accept の待ち行列は shard 0 にあり、ライブラリの利用者の accept は shard 0 から (持ち主、枠、世代) を受け取ります

### TCP の API

今の操作 (`listen_tcp`、`accept`、`close_listener`、`read`、`write`、`close_write`、`close_conn`、`close_for_delivery`、`abort`、`delivered`、`local_addr`、`peer_addr`) を保ち、dial のために次を加えます。

| 加えるもの | 中身 |
|---|---|
| `dial_tcp(now, remote, local, deadline)` | 能動の open を始め、`ConnId` を返します。完了は知らせで届きます |
| `Event::Connected(ConnId)` | 確立した知らせです |
| `Event::ConnectFailed(ConnId, reason)` | 拒否、期限、再送の上限、同時の open、ポートの不足のどれかで失敗した知らせです |
| `abort` の SYN-SENT での意味 | 取り消しです。RST を送らずに枠を返します |

### UDP と ping

UDP と ping の今の操作を保ちます。
接続した UDP のための口 (endpoint の鍵をポートと任意の相手の組にすること、`WaitReadable`、Port Unreachable での終わり) は、[UDP の接続したセッション](../../userspace/wgstack-dial.md#udp-の接続したセッション)の決定に従います。

## 受動と能動の open に共通の TCP の状態の模型

```mermaid
stateDiagram-v2
  [*] --> LISTEN: listen_tcp (shard 0)
  [*] --> SYN_SENT: dial_tcp (shard 0 が予約し、持ち主が作る)
  LISTEN --> SYN_RCVD: SYN を受ける (shard 0 の握手の途中の行)
  SYN_RCVD --> ESTABLISHED: 最後の ACK (持ち主の shard へ渡す)
  LISTEN --> ESTABLISHED: cookie の ACK (持ち主の shard へ渡す)
  SYN_SENT --> ESTABLISHED: 受け入れられる SYN-ACK (持ち主)
  SYN_SENT --> CLOSED: RST、期限、再送の上限、同時の open、取り消し
  SYN_RCVD --> [*]: SYN-ACK の再送の上限
  ESTABLISHED --> FIN_WAIT_1: close
  ESTABLISHED --> CLOSE_WAIT: FIN を受ける
  FIN_WAIT_1 --> FIN_WAIT_2
  FIN_WAIT_1 --> CLOSING
  FIN_WAIT_2 --> TIME_WAIT
  CLOSING --> TIME_WAIT
  CLOSE_WAIT --> LAST_ACK: close
  LAST_ACK --> CLOSED
  TIME_WAIT --> TIME_WAIT_ROW: 行に移る (shard 0 へ返す)
  TIME_WAIT_ROW --> [*]: 期限
  CLOSED --> [*]: アプリケーションが閉じる
```

| 項目 | 受動の open | 能動の open | 共通の扱い |
|---|---|---|---|
| 置き場 | 握手の途中の行か cookie (shard 0)、確立で持ち主の枠へ | SYN を送る時から持ち主の枠 | 確立の後は同じ枠の状態機械です |
| 確立の入口 | shard 0 が交渉した値の組を作り、持ち主へ渡します | 持ち主が SYN-ACK から交渉した値の組を作ります | 交渉した値の組 (MSS、窓の scale、SACK、timestamp、両方の ISN、timestamp の値) から 1 つの確立の処理を通ります |
| 接続の識別 | 4 つ組と `ConnId` | 同じ | 同じ |
| ISN と timestamp の offset | 4 つ組の鍵つきの hash | 同じ | 向きに依りません |
| ポート | 待ち受けのポート | shard 0 が選ぶ一時ポート | 4 つ組は shard 0 の表で、接続、握手の途中、SYN-SENT、TIME_WAIT のどれとも衝突しません |
| 再送 | SYN-ACK の再送 (shard 0) | SYN の再送 (持ち主) | 確立の後は RTO、RACK、TLP で同じです |
| 取り消し | 待ち受けを閉じると握手の途中の行に RST を送ります | `abort` で RST を送らずに枠を返します | |
| 期限 | SYN-ACK の再送の上限 | 呼び出し側の期限か再送の上限 | |
| 閉じ方 | 同じ | 同じ | FIN と RST の規則は今と同じで、TIME_WAIT の行は shard 0 に返します |

## TCP の能動の open

dial の仕様は、並列の構成に依らない TCP の仕様です。
[wgstack の dial の側](../../userspace/wgstack-dial.md)の決定をそのまま使い、要点とこの提案で変える点を次に挙げます。

### 使い続ける決定

- SYN-SENT の置き場:接続の枠に置きます。
  K に数えない dial のために、K の外に小さな固定の枠を置きます
- ポート:RFC 6056 の乱数を使う選び方で選び、4 つ組の衝突を確かめます。
  尽きたら誤りを返し、数えて 1 分に 1 回までログに出します
- SYN の再送:最初の RTO は 1 秒で、再送ごとに倍にします。
  呼び出し側の期限か再送の上限で失敗します。
  SYN を再送した接続の初期の輻輳の窓は 1 segment です
- SYN-SENT の入力:RFC 9293 3.10.7.3 に従います。
  ICMP の誤りは接続を終えない柔らかい誤りです
- 同時の open:持ちません。
  SYN-SENT で ACK の無い SYN を受けたら dial を失敗させます (知った上での違い)
- client の option:SYN に MSS、SACK-permitted、timestamp、窓の scale を載せ、SYN-ACK で使うかを決めます
- 誤りの約束:拒否、期限、確立の後の RST、相手の FIN の後の読み取りを見分けられる誤りを返します
- 接続した UDP とエージェントごとの上限:dial の側の文書の決定のままです

### この提案で変える点

| 点 | dial の側の文書 | この提案 |
|---|---|---|
| 実装の置き場 | Go の `internal/wgstack` の名前で書かれています | v2 の Rust の核 (`crates/wgft-wgstack`) に置きます。規則は変えません |
| 誤りの形 | Go の `errors.Is` と `net.Error` で書かれています | 核は誤りの種類 (拒否、期限、リセット、終わり、ポートの不足、同時の open) を返し、言語ごとの形への写しは handle の層が持ちます |
| 予約と作成 | 1 つの核の中で行います | shard 0 が一時ポートを選んで表に項を入れ、持ち主が SYN-SENT を作ります。衝突の確かめは shard 0 の表で完結するので、規則は変わりません |
| 確立の入口 | 交渉した値の組から始める形に分けると決めています | 受動の open も同じ入口を、持ち主の shard で使います |
| 取り消し | 枠を返し、RST を送りません | 持ち主が枠を返し、解放の知らせで shard 0 が表の項を外します。後から届いた SYN-ACK は表に項が無いので、shard 0 が RST を返します |

dial の側の文書の「実装の時に決めること」(一時ポートの幅、TIME_WAIT の 4 つ組の自分の側での使い直し、SYN の再送の回数の上限、疎通確認の枠の数、UDP の chunk の単位と予算、server の Device の表の大きさ) は、この提案でも実装の時に決めます。

## 製品の build に入れないもの

- 決定的に shard の交互の順を作る試験の実行器、メモリの順の模型の検査、fuzz の口は、`cfg` か feature で製品の build から外します([正しさの試験](verification.md#正しさの試験))
- 段ごとの時間の分布と輪の深さの計測器は、ラボの計測の feature を付けた build だけに入れます
- 製品の build に入るのは、ログの 1 分の門と既存の数えと同じ種類の数えだけです

[提案の索引](README.md)
