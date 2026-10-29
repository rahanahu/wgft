# エージェントの wgft の netstack

wgstack は、ユーザー空間モードのエージェントが gVisor の netstack の代わりに選べる、wgft が持つ netstack です。
wgstack は未実装の提案です。
構造と上界の形をここで決め、値と細部は実装の時に決めます。
検証の計画は[wgstack の検証](wgstack-verification.md)に分けます。

## 目的と範囲

ユーザー空間モードのエージェントは、トンネルから届く利用者の TCP を gVisor の netstack で終端します。
前に立つ VPS はカーネルモードで DNAT と MASQUERADE を行うので、利用者と運用者が受け取る TCP の品質とメモリの挙動は、エージェントの netstack の品質と挙動です。
`vpsd` がユーザー空間モードの組でも、エージェントは `vpsd` の netstack からの接続を受け付けるだけなので、wgstack の範囲は変わりません。
gVisor の netstack には、構造上の上限を持たない保持点と、短い障害の後の遅い回復が残ります([上界に含めない保持点](memory-limits.md#中身の無い-segment-の処理待ち)、[短い障害の後の回復](../vps/userspace.md#63-ユーザー空間モード)、[netstack の依存の固定](netstack-dependency.ja.md))。
wgft は依存にパッチを当てません。
smoltcp、lwIP、既存の fork を調べた結果はどれも採らず、wgft が Go で netstack を書くことを所有者が決めました。
Go で書くので、リリースは `CGO_ENABLED=0` の単一のバイナリのままです。

wgstack が扱う範囲は次のとおりです。

- 対象:エージェントのトンネルだけです。
  `vpsd` のユーザー空間モード(`internal/dataplane/userspace/utun`)は gVisor の netstack を使い続けます
- 開き方:受動の open だけです。
  エージェントはトンネルからの接続を受け付け、LAN の宛先へは今までどおり OS のソケットで接続します
- プロトコル:IPv4 だけで、トンネルの MTU は Device を作るときに固定します。
  UDP、ICMP、IPv4 の断片の再組み立ては、今の `internal/nettun` が扱う範囲を扱います。
  gVisor を置き換えると、これらもすべて置き換わるためです
- アドレス:宛先は設定したプレフィックスの集合に入るアドレスを受け付け、送信元はどのアドレスでも受け付けます。
  今の集合はエージェントのトンネルのアドレスの /32 の 1 つです。
  将来、拠点ごとの仮想の /16 をエージェントが受け付ける可能性があります。
  wgstack はその機能を作りませんが、表のキーと待ち受けの束縛は集合を前提にし、その機能を妨げない形にします

### 完成と性能の目標

最初の目標を「完成」と呼び、次の 3 つの条件で判定します。

- 正しさ:Linux を参照の実装とする適合の試験で、期待した差だけを残して一致します([wgstack の検証](wgstack-verification.md#適合の試験))
- 保持の上界:空の segment、順序外の洪水、読まない相手、SYN の洪水、TIME_WAIT の入れ替わりのような敵対的な入力の下で、保持する量が導いた上界で止まります
- 退行が無いこと:CLI、API、終了コード、ラボの一式に退行がありません

性能の目標は完成の後に追います。
スループットは Linux の 80% 以上かつ gVisor 以上、短い障害からの回復は Linux の回復の時間に RTO 1 回分を足した時間以内、通信量の少ない stream の遅れの p99 は Linux の 1.5 倍以内、CPU は gVisor の 1.2 倍以内です。
完成は NewReno で判定します。
SACK の scoreboard、RACK の時刻、CUBIC は性能の段階で加え、そのときにデータ構造を作り直さずに済む形を今の段階で選びます([後の段階の機能](#後の段階の機能))。

wgstack は、ユーザー空間モードのエージェントの実験的な選択肢として、明示した場合だけ使います。
既定は gVisor のままとし、ステージングの環境で長く動かして確かめるまで既定を変えません。
この設計と実装を載せる長期のブランチは、性能の目標を満たすまで main にマージしません。

### 不変条件

wgstack は次の不変条件を守ります(所有者の草稿)。

- I1 有限:論理的な資源のすべてに、入力の量、種類、順序によらない、設定から決まる有限の上限があります
- I2 保持の前の予約:保持する前に予約し、上限の無い代わりの置き場を持ちません
- I3 所有:保持するものはすべて、持ち主、容量、作る条件、返す条件を 1 つずつ持ちます
- I4 TCP の正しさ:再送に要る未確認のデータを黙って捨てません。
  義務を果たせないときは、安全に閉じる方を選びます
- I5 自己増殖の禁止:タイマー、再送、誤りの処理は、外からの入力なしに、上限の無い持続するオブジェクトを作りません
- I6 制御できること:停止、`Close`、予算の枯渇、誤りは資源を回収します
- I7 隔離:wgstack の失敗はカーネルモードに影響しません

尽きたときの方針も所有者が決めました。
枠が無ければ新しい接続を拒み、受信は広告する窓で絞り、再送の容量を予約できなければ新しいアプリケーションのデータを拒み、再組み立ての予算を超える断片を捨て、バッファを見えないところで増やしません。
各資源への当てはめは[尽きたときの動作](#尽きたときの動作)に書きます。

## トンネルとの境目と選択

### 今の境目

エージェントのトンネル(`internal/dataplane/userspace/tunnel`)は、`internal/nettun` の次の面だけを使います。
wgstack は同じ面を持ち、トンネルの中で差し替えます。

- 作成:`nettun.Create(addr, mtu)` が Device を作ります
- wireguard-go との境目:Device は `tun.Device` を満たし、`wgbind.NewDevice` が wireguard-go の device に組み込みます。
  使うのは `Name`、`File`(nil)、`Events`(作成の直後に `EventUp`)、`MTU`、`BatchSize`(1)、`Read`、`Write`、`Close` です。
  `Read` は 1 回に 1 件を返し、`Close` の後は `os.ErrClosed` を返します。
  `Write` はバッチの 1 件が失敗しても残りを処理し、受け取った件数と最初の誤りを返します。
  誤りにするのは閉じた後の `Write` と IPv4 でない packet だけで、捨てた断片、UDP の会計による拒否、MSS の下限による拒否は誤りにしません([TUN の Write の誤り](packet-validation.md#tun-の-write-の誤り))
- TCP の待ち受け:`ListenTCP(netip.AddrPort)` が `net.Listener` を返します。
  `Accept` が返す接続は `net.Conn` に加えて、中継と `internal/netpipe` が型アサーションで探す `Abort`、`CloseWrite`、`Delivered`、`CloseForDelivery`、`OnBoost` を持ちます
- UDP の待ち受け:`ListenUDP(netip.AddrPort)` が `net.PacketConn` を返します。
  `WriteTo` は送信の余地ができるまで待ち、`Close` の後の操作は `net.ErrClosed` を返します([UDP の接続](udp-accounting.md#udp-の接続))
- keepalive の ping:`DialPing(laddr, raddr)` が、echo を 1 つ書き、応答を 1 つ期限つきで読む `net.Conn` を返します([keepalive の ping の endpoint](udp-accounting.md#keepalive-の-ping-の-endpoint))
- 会計の故障:`UDPReceiveFault()` が、`agent doctor` の `tunnel.udp_accounting` の判定に使う誤りを返します

トンネルの外の package は `internal/nettun` を名指さず、中継と `internal/netpipe` は前述のメソッドを型アサーションで探します。
本番のファイルで `internal/nettun` を import するのは、トンネルと `utun` だけです。
このため、トンネルの中に 2 つの実装が満たす非公開の interface を置けば、中継と `internal/agent` を変えずに差し替えられます。

`Write` の入口で今の Device が行う検査は、wgstack でも同じ規則で行います。
IPv4 の Total Length より後ろの byte の切り捨て、[断片の入口と再組み立ての表](packet-validation.md#再組み立ての表)、[ICMP の誤りの送信元の確認](packet-validation.md#icmp-の誤りの入口)、[Fragmentation Needed の MTU の下限 552](packet-validation.md#fragmentation-needed-の-mtu-の下限)、[SYN の MSS の下限 536](packet-validation.md#tcp-の-mss-の下限)、[UDP の受信の予算](udp-accounting.md#udp-の受信の予算)、自分宛ての packet を中で折り返さないことがこれに当たります。
MSS の下限の検査は、gVisor の option の読み方ではなく、wgstack 自身が TCP の処理で使う読み方で行います。
捨てた数の数え方と、1 分に 1 回までのログも同じにします。

次の仕組みは gVisor の挙動を抑えるためのものなので、wgstack には移しません。

- 中身の無い ACK の予算:wgstack は segment を処理待ちに積まず、`Write` の中で同期して処理します。
  1 つの ACK の処理は送り残しの segment の数によらない手間で済むので、予算が抑えていた処理待ちの増加が構造上起きません
- 閉じた後の接続の表:後述の [TIME_WAIT の表](#time_wait-の表)に置き換えます
- 書き込みの数の上限:送信のバッファは byte の輪であり、書き込み 1 回ごとの管理の構造を持ちません
- 受信のメモリの非公開のフィールドの読み取り:wgstack は自分の会計を持ちます

### 中継から見える違い

中継が今の gVisor の挙動を前提にしている点のうち、wgstack で変わる点は次のとおりです。
どれも、中継の試験を両方の実装に流して確かめます。

- 待ち受けの開き直し:TIME_WAIT の接続は待ち受けの束縛と衝突しません。
  gVisor では TIME_WAIT の間に同じポートを開けませんでした([TCP の中継と終了](tcp-relay.md))。
  wgstack の挙動は、`SO_REUSEADDR` を付けた Linux の待ち受け(Go の `net.Listen` の既定)と同じです
- `CloseForDelivery`:wgstack では通常の `Close` と同じです。
  送り残しを持つ接続は接続の枠に残り、TIME_WAIT の表に入るのは送ったデータと FIN がすべて確認された後だけなので、表の追い出しで末尾を失いません
- accept の待ち行列の RST:握手を終えて待ち行列にいる接続が RST を受けたら、wgstack は待ち行列から外して枠を返します。
  gVisor は待ち行列に残して `Accept` で返し、その `RemoteAddr` は nil でした
- `Delivered` の判定:CLOSED、TIME_WAIT、受信のバッファが空の FIN_WAIT_2 を届け終えたとします。
  条件は今と同じで、判定に gVisor の非公開のフィールドを使いません

### 実装の選択

実装の選択は `WGFT_AGENT_NETSTACK` で受け取り、フラグ `--agent-netstack` はその別名です([設定の渡し方](../security/configuration.md#11a-設定の渡し方))。
値は `gvisor` と `wgstack` で、省略と空の値は `gvisor` です。
環境から推測せず、値を指定したときだけ wgstack を使います。

- エージェントだけが読みます。
  `vpsd` は他のプロセス向けの `WGFT_*` として無視します
- 知らない値は設定の誤りとして終了コード 3 で止めます
- カーネルモード(`WGFT_MODE=kernel`)では netstack を使わないので、空でない値を設定の誤りとして終了コード 3 で止めます
- 選択はプロセスで 1 つで、トンネルを作り直しても変わりません。
  wgstack の作成に失敗しても gVisor に切り替えず、今のトンネルの作成の失敗と同じく試し直します
- 起動ログの有効な設定の印字に値と出所が載ります。
  wgstack のときは、実験的な選択肢であることを英語の 1 行で出します
- `wgft status`、管理用 API、wire protocol、`agent doctor` の JSON は変えません

選択の値は、`usermode` が受け取ってトンネルの宣言に渡します。
トンネルの宣言は wgstack の接続の枠の数を導くために、同時フロー数のプロセス全体の上限 K(`WGFT_MAX_TCP_FLOWS`)も受け取ります。
`WGFT_AGENT_NETSTACK` の名前と値は、このブランチが main に入るときに公開のサーフェスになります。
[設定の渡し方](../security/configuration.md#11a-設定の渡し方)と[互換性](../compatibility.md)への記載は、実装と同じ変更で行います。

## package の配置

[package の配置](../architecture/packages.md#7a7-package-配置)と `internal/dataplane/deps_test.go` の規則に合わせ、次のように置きます。

- `internal/wgstack`:wgstack の本体です。
  後述の決定的な核と、それを `tun.Device` として動かす Device を持ちます。
  モジュールの外からは標準ライブラリと `golang.zx2c4.com/wireguard/tun`(`tun.Device` と `tun.Event` の型)だけを import します。
  `gvisor.dev/gvisor`、`internal/nettun`、`internal/dataplane` とその下位、`internal/agent`、`internal/vpsd` を import しません
- 再組み立ての表:今の `internal/nettun` の再組み立ての表は gVisor を import しないので、葉の package に移して 2 つの実装で共有します。
  移すのは表だけで、gVisor の Time Exceeded の経路は `internal/nettun` に残ります
- `internal/dataplane/userspace/tunnel`:2 つの実装が満たす非公開の interface を持ち、宣言の値で実装を選びます。
  `internal/nettun` と `internal/wgstack` の両方を import する唯一の package です

`internal/wgstack` は `internal/dataplane` の下に置かないので、`TestDependencyDirection` の「dataplane の実装どうしは import しない」規則に触れません。
トンネルは `internal/dataplane/userspace` の下にあり、制御プレーンでも別の dataplane の実装でもない package を import するだけです。
実装のときに、`internal/wgstack` の import の制限と、`internal/agent/kernelmode` と `internal/agent/agentdp` が推移的にも `internal/wgstack` に依存しないことを検査に加えます。
後者がカーネルモードの側の I7 を構造で支えます。
プロセスの中の隔離として、カーネルモードのエージェントは wgstack を作らず、wgstack のコードはカーネルモードの経路で動きません。

## 並行性と時計

wgstack は、Device ごとに 1 つの goroutine だけを持ちます。
この goroutine はタイマーを動かし、再組み立ての表の期限の掃除も行います。
ほかの処理は呼び出し側の goroutine で動きます。

- 入力:wireguard-go が呼ぶ `Write` の中で、packet を同期して処理します。
  入力の待ち行列を持たないので、入力の洪水は wgstack の中に積もらず、wireguard-go の有限のキューとソケットのバッファで止まります
- 出力:wireguard-go が呼ぶ `Read` の中で、次に送る packet をその場で作り、wireguard-go のバッファに直接書きます([出力](#出力))
- アプリケーションの操作:中継の goroutine が呼ぶ `Read`、`Write`、`Accept`、`Close` は、接続ごとの通知の channel(容量 1)で待ちます。
  期限は接続ごとに向きあたり 1 つの runtime のタイマーを、作成の時に作って置き直します

接続ごと、packet ごと、タイマーごとの goroutine は作りません。
`Close` はこの 1 つの goroutine の終了を待ちます。

TCP、UDP、ICMP、再組み立ての状態は決定的な核が持ちます。
核は goroutine を作らず、時計と乱数を直接読みません。
核の操作は「packet と時刻を受けて状態を変え、出力を返す」「時刻を受けてタイマーを進める」「アプリケーションの操作」の 3 種類だけです。
時計(単調な時刻)と乱数(ISN の鍵、表の hash の種、challenge ACK の揺らぎ)は作成の時に渡し、本番は単調な時計と暗号論的な乱数を使います。
試験は手で進める時計と固定の種を渡し、Device の goroutine を使わずに核を直接進めます。

錠は Device の表の錠と接続ごとの錠の 2 段です。
表の錠は検索、追加、削除の間だけ持ち、表の錠を持ったまま接続の錠を取りません。
接続の枠は世代の番号を持ち、表の錠を離した後に古い検索の結果を見分けます。
錠の細部と CPU の目標に向けた分け方は、実装と性能の段階で決めます。

## メモリの模型

wgstack が保持するものは、すべて作成の時に容量を決めた表か、作成の時に決めた予算から予約する buffer のどちらかです。
表は作成の時に確保し、後から大きくしません。
buffer の中身は 16 KiB の chunk で持ち、予約した量まで必要になった時に確保します。
16 KiB は Go のメモリの大きさの区分と一致するので、chunk の確保に切り上げの無駄がありません。
TCP のバッファの floor と boost の値と規則は、今の[TCP バッファ](tcp-buffers.md)と同じにします。
`internal/netpipe` の `FollowBoost` が、LAN 側のカーネルのソケットの受信のバッファを boost の知らせに合わせるためです。

### 接続の表

接続の表は、作成の時に数 N_c を決めた固定の枠の配列と、4 つ組から枠を引く固定の大きさの開番地法の hash の表です。
hash は作成の時の乱数の種で鍵を付け、相手が選ぶ送信元のアドレスとポートで衝突を集められないようにします。
キーはローカルのアドレスを含む 4 つ組で、ローカルのアドレスが集合のどれでも同じ形です。
N_c は K と accept の待ち行列の全体の数 Q の和で、設定項目にしません。
中継は K を超えた接続を `Abort` で即座に終えるので、定常の状態で枠を持つ接続は、中継が数える K 本と accept の待ち行列の Q 本までです。
送り残しを届けている接続も中継が K に数えます([中継が終わった後の末尾の配送](tcp-retention.md#中継が終わった後の末尾の配送))。

### 接続ごとの buffer

確立した接続は、確立の時に受信の floor を予約し、送信の floor を予約します。
予約は accept の待ち行列にいる間にも持ちます。
Linux と同じく、`Accept` の前に届いたデータも受信のバッファに入るためです。
boost は今と同じくプロセスで 16 本の枠から予約し、得られなければ floor のまま続けます。

- 送信のバッファ:予約した容量の byte の輪です。
  中身は累積の確認で外し、SACK で確認された分も累積の確認まで保持します。
  再送はこの輪から segment を作り直します
- 送信の記録:送った segment ごとに、開始の番号、長さ、送った時刻、印(再送、後の段階の SACK 済みと損失)を持つ固定の容量の輪です。
  容量は送信のバッファの予約を、送り残しを分ける大きさの下限の 472 byte([TCP の MSS の下限](packet-validation.md#tcp-の-mss-の下限))で割った数です。
  記録の輪が満杯なら、確認で空くまで新しい segment を送りません
- 受信のバッファ:予約した容量の byte の輪で、順序どおりの未読のデータと順序外のデータを同じ輪に置きます。
  順序外のデータは輪の中の自分の位置に書き、届いた範囲を固定の数 H の区間の表で持ちます。
  H 個を超える区間を作る segment は捨て、穴を埋めるか既存の区間を伸ばす segment は受け入れます。
  広告する窓の右端は輪の空きから決め、後ろへ戻しません
- floor へ戻すとき:boost を返すのは、受信の側で広告した右端と保持する順序外のデータが floor の内側に収まり、送信の側で送り残しが floor の内側に収まったときだけです。
  広告済みの窓を縮めず、SACK で知らせた順序外のデータを捨てないためです。
  戻す前に窓の右端を伸ばすのを止め、右端が floor の内側に入るのを待ちます

中身の無い segment と小さな segment は、受信の側で中身の byte の外に何も残しません。
小さな書き込みも送信の輪に byte として入るだけです。

### TIME_WAIT の表

TIME_WAIT と、アプリケーションが閉じた後の FIN_WAIT_2 の接続は、buffer を持たない小さな行の表に移します。
行は 4 つ組、送受信の次の番号、相手の最後の timestamp、期限、状態だけを持ちます。
表の行の数 M は固定で、設定項目にしません。
期限は状態ごとに一定(どちらも 60 秒)なので、行を固定の配列の上の両方向の list に入れた順で並べ、先頭から期限を過ぎた行を外します。
FIN_WAIT_2 の行が相手の FIN で TIME_WAIT に移ったときは、list の末尾に付け直します。
満杯のときは最も古い行を外して数え、1 分に 1 回までログに出します。
外した行の 4 つ組にその後届いた segment は、どの接続にも当たらない segment として扱います。

行の接続は送ったデータと FIN がすべて確認されているので、追い出しは末尾を失いません。
TIME_WAIT の行は再送された FIN に ACK を返し、RFC 6191 の条件を満たす新しい SYN を受けたら行を外して待ち受けに渡します。
FIN_WAIT_2 の行にデータが届いたら、Linux と同じく RST を返して行を外します。

### 握手の途中の表と accept の待ち行列

握手の途中の接続(SYN-RCVD)は、接続の枠とは別の、buffer を持たない固定の数 N_syn の表に置きます。
行は 4 つ組、両方の ISN、交渉した option、SYN-ACK の再送の回数、期限だけを持ちます。
待ち受け 1 つが使える行は N_syn の半分までです。
SYN-ACK の再送の予定は回数ごとに一定なので、TIME_WAIT の表と同じく順序つきの list で期限を管理します。
握手の最後の ACK が届いた時に接続の枠と送受信の floor を予約し、確立した接続を accept の待ち行列に入れます。
SYN に載ったデータは受け入れません。

accept の待ち行列は Device 全体で Q 本、待ち受け 1 つで Q の半分までです。
待ち受けごとに backlog の分を持たないので、待ち受けの数を増やしても待ち行列の保持は増えません。

### UDP、ICMP、再組み立て

- UDP の受信:Device の予算(4 MiB と 4096 件)と endpoint 1 つの上限(予算の 1/4)を今と同じ値で持ちます([UDP の受信の予算](udp-accounting.md#udp-の受信の予算))。
  datagram の中身は chunk に、管理の情報は 4096 件の固定の配列に置きます。
  会計は保持そのものなので、gVisor の統計の差から受理を判定する手順は要りません
- UDP の送信:Device の予算(4 MiB と 1024 件)と endpoint 1 つの上限(予算の 1/4)を持ちます。
  `WriteTo` は予約できるまで待ちます。
  MTU を超える datagram は、DF を立てず、0 でない ID で断片に分けて送ります(今の[UDP の送信時の断片化](udp-accounting.md#udp-の送信時の断片化)と同じ結果です)
- ICMP の echo:`DialPing` の endpoint は固定の数の表に置き、識別子を `Close` で返します。
  表が満杯なら `DialPing` は誤りを返します。
  自分のアドレス宛ての echo request には、後述の制御の出力の輪から応答します
- 再組み立て:今の表(未完成の datagram 128 件、断片 512 個、保持 4 MiB、期限 30 秒)を共有して使います([再組み立ての表](packet-validation.md#再組み立ての表))。
  Time Exceeded と Parameter Problem は wgstack が自分で作ります

### 出力

出力は、送る準備のできた接続の順番の list と、小さな制御の packet の固定の輪の 2 つです。
TCP の data と ACK は待ち行列に積まず、`Read` の時に順番の list の先頭の接続が送信の輪から 1 つの segment を作ります。
接続は list に高々 1 回入り、list の節は接続の枠の中にあるので、出力の保持は接続の数で決まります。
RST、どの接続にも当たらない segment への応答、ICMP の誤りと echo の応答は、MTU の大きさの枠を固定の数だけ持つ制御の輪に入れます。
`Read` は制御の輪、TCP の順番の list、UDP の送信の順に 1 件を選びます。

### タイマー

接続の枠は、再送、窓の probe、遅延 ACK、keepalive、閉じた後の期限のタイマーの節を枠の中に固定で持ちます。
節はタイマーの輪(timing wheel)に入れ直すだけで、タイマーを張るたびに確保しません。
TIME_WAIT の表と握手の途中の表は、前述の順序つきの list で期限を管理し、行ごとのタイマーを持ちません。
このため、タイマーの数は N_c と枠の中の節の数の積を超えず、入力が止まった後に新しいタイマーは生まれません。

## 上界の式

wgstack が保持する量の上界を、次の項の和とします。
byte の項は、予約と固定の配列が生きているヒープに持つ量を数えます。

```
M_wgstack = M_fix
          + N_c x (c_conn + f_s + f_r + r_f)
          + B x (d_s + d_r + d_rec)
          + N_syn x c_syn + M x c_tw + Q_ctl x s_ctl
          + M_udp_rx + M_udp_tx + M_frag + N_ping x c_ping
```

| 項 | 意味 | 決め方 |
|---|---|---|
| M_fix | Device の固定の構造、hash の表、タイマーの輪、順番の list の頭 | 実装で測って定数にします |
| N_c | 接続の枠の数 | K + Q。Q は Device 全体の accept の待ち行列の数で、初期の値は 512 です |
| c_conn | 接続の枠 1 つの構造(状態、H 個の区間、タイマーの節、chunk の表) | 実装で測ります。H の初期の値は 32 です |
| f_s、f_r | 送信と受信の floor | どちらも 256 KiB([TCP バッファ](tcp-buffers.md)) |
| r_f | floor の送信の記録の輪 | 256 KiB / 472 byte の 556 件に記録 1 件の大きさを掛けた値です |
| B | boost の枠の数 | プロセスで 16 本 |
| d_s、d_r | boost が floor に加える送信と受信の分 | どちらも 4 MiB - 256 KiB |
| d_rec | boost が加える送信の記録の分 | 4 MiB / 472 byte の 8,887 件と 556 件の差に記録 1 件の大きさを掛けた値です |
| N_syn、c_syn | 握手の途中の表の行の数と 1 行の大きさ | 初期の値は 1024 行です |
| M、c_tw | TIME_WAIT の表の行の数と 1 行の大きさ | 初期の値は 65,536 行です |
| Q_ctl、s_ctl | 制御の出力の輪の枠の数と 1 枠の大きさ | 初期の値は 256 枠で、1 枠は MTU です |
| M_udp_rx | UDP の受信の予算の中身と、4096 件の管理の配列 | 4 MiB と配列の大きさの和 |
| M_udp_tx | UDP の送信の予算の中身と、1024 件の管理の配列 | 4 MiB と配列の大きさの和 |
| M_frag | 再組み立ての表 | 4 MiB(表の管理領域と完成の複製 1 つを含む、今の数え方) |
| N_ping、c_ping | echo の endpoint の表 | 初期の値は 16 件です |

初期の値は動作を確かめるための値であり、最適値として探した値ではありません。
どの値も設定項目にしません。

既定の K の 2048 で、記録 1 件を 32 byte、c_conn を 4 KiB、表の 1 行を 128 byte と仮に置くと、項の和は約 1.5 GiB です。
大きいのは floor の項(2560 × 512 KiB で 1.25 GiB)と boost の項(約 124 MiB)です。
この値は設計の上の算術であり、測っていません。
今のエージェントの上界の式では、カーネルモードの `vpsd` の後ろで、TCP の待ち受け 1 つごとに accept の待ち行列の項(約 1,790 MiB)が加わります([エージェントとホストのメモリの条件](memory-agent-host.md#accept-の待ち行列))。
wgstack の accept の待ち行列は Device 全体で Q 本なので、この式に待ち受けの数に比例する項はありません。

式は次のものを含みません。

- Go のランタイムの費用:GC が回収を待つ間の余裕、span の断片化、ランタイムの管理の構造です。
  RSS は生きているヒープより大きく、その係数は[フロー数とメモリのソフト上限](flow-limits.md)と[上界に含めない保持点](memory-limits.md)の数え方で扱います
- OS のソケット:LAN の宛先への TCP と UDP のソケット、WireGuard の UDP のソケットのバッファです
- wireguard-go:ピアと device のキュー、TUN の読み書きのバッファ、受信の包みの固定のバッファです([フロー数とメモリのソフト上限](flow-limits.md))
- 中継と `internal/netpipe`:コピーのバッファ、goroutine のスタック、セッションの表です
- 待ち受け 1 つあたりの小さな構造:待ち受けの数は信頼された設定で決まり、今の式でも外にあります([TCP のポートごとの待ち受け](memory-limits.md#tcp-のポートごとの待ち受け))

## 尽きたときの動作

どの資源も、尽きた時に新しい保持を拒み、既存の保持を追い出しません。
例外は TIME_WAIT の表と再組み立ての表の追い出しで、どちらも追い出した数を数えます。
数えた拒否は種類ごとに Device で数え、1 分に 1 回まで英語の 1 行をログに出します。
`wgft status`、管理用 API、wire protocol には載せません。

| 資源 | 尽きたときの動作 |
|---|---|
| 握手の途中の表 | 新しい SYN を、状態を作らずに捨てます。待ち受けの無いポート宛ての SYN には RST を返します |
| accept の待ち行列と接続の枠 | 握手の最後の ACK を捨てます。握手の途中の行は残り、SYN-ACK の再送の回数を使い切ると消えます。Linux の `tcp_abort_on_overflow=0` と同じ挙動です |
| 受信のバッファ | 窓を広げません。窓の外のデータは捨てて ACK で窓を知らせます。H 個を超える区間を作る順序外の segment は捨てます |
| 送信のバッファと送信の記録 | `Write` はバッファに空きができるまで待ちます。記録の輪が満杯なら新しい segment を送らず、データは送信の輪に残ります |
| boost の枠 | floor のまま続け、次の需要の区間で求め直します |
| TIME_WAIT の表 | 最も古い行を外して新しい行を入れ、外した数を数えます |
| 再組み立ての表 | 今と同じく、同じ datagram 以外の最も古い未完成の項目を外し、1 つの datagram だけで満ちるときはその断片を捨てます([表が満杯のときの扱い](packet-validation.md#表が満杯のときの扱い)) |
| UDP の受信の予算 | datagram を捨て、ICMP を返しません。endpoint の上限と Device の予算の拒否を分けて数えます |
| UDP の送信の予算 | `WriteTo` は予約できるまで待ち、期限と `Close` で解けます |
| 制御の出力の輪 | 新しい制御の packet を捨てます。TCP の data と ACK はこの輪を使わないので影響を受けません |
| echo の endpoint の表 | `DialPing` が誤りを返します |
| challenge ACK と ICMP の速さの制限 | 速さを超えた分を送りません |

TCP の義務を果たせない時は、接続を安全に閉じます。
再送の回数を使い切った接続と、wgstack が自分の会計の不整合を検出した接続は、RST を送って枠を返し、アプリケーションの読み書きに誤りを返します。
データを黙って捨てて接続を続けることはしません。

## 不変条件と設計の対応

| 不変条件 | 設計の対応 |
|---|---|
| I1 有限 | 表はすべて作成の時の固定の容量で、buffer は予約の量までしか確保しません。上限は K と固定の定数から決まり、入力によりません |
| I2 保持の前の予約 | 接続の枠と floor は確立の時に、boost は枠の取得の時に、UDP の datagram は配送の前に予約します。予約できなければ前節の動作になり、代わりの置き場はありません |
| I3 所有 | 接続の枠、TIME_WAIT の行、握手の途中の行、chunk、datagram の枠は、それぞれ 1 つの表か 1 つの接続が持ち、作る条件と返す条件を前節までに定めます |
| I4 TCP の正しさ | 送信の輪は累積の確認まで中身を保持し、記録の輪の満杯は送信を止めるだけです。順序外のデータは、接続が開いている間、SACK を知らせた後は捨てません |
| I5 自己増殖の禁止 | タイマーの節は枠と行に固定で埋め込み、再送は既存の輪から segment を作り直すだけです。出力は待ち行列を持たず、`Read` の時に作ります |
| I6 制御できること | `Abort` は RST を送って即座に枠を返し、`Close` の後の保持は TIME_WAIT の表の行だけです。Device の `Close` は待っている操作を `net.ErrClosed` で解き、すべての予約を返します |
| I7 隔離 | カーネルモードは wgstack を作らず、package の依存も持ちません。選択は明示で、既定は gVisor です |

## TCP の機能

### 完成に含める機能

参照の実装は Linux です。
規格が値を幅で定めるところは Linux の既定の値に合わせ、合わせない点は[期待した差](wgstack-verification.md#期待した差の一覧)に記録します。

- RFC 9293:受動の open からの状態の遷移、同時の close、segment の受け入れの判定、窓の更新の規則、送り手と受け手の SWS の回避、RST の処理、ハーフクローズ(`CloseWrite` で FIN を送った後も読み続けます)を持ちます。
  未読のデータを持ったまま閉じた接続は Linux と同じく RST で終えます。
  緊急のデータは、通常のデータとして扱い、知らせません
- RFC 6298:SRTT と RTTVAR から RTO を求め、再送ごとに倍にします。
  最小の RTO は Linux と同じ 200 ms、最大は 120 秒です
- RFC 7323:窓の scale、timestamp による RTT の測定、PAWS を持ちます。
  窓の scale は boost の 4 MiB を広告できる値を握手の時に決めます
- RFC 5961:窓の内側で番号が一致しない RST と確立後の SYN に challenge ACK を返し、ACK の受け入れの範囲を確かめます。
  challenge ACK の速さは Device 全体の token bucket で抑えます
- MSS:相手の MSS に従い、MSS の option の無い SYN では 536 を使います。
  入口の[MSS の下限](packet-validation.md#tcp-の-mss-の下限)と、Fragmentation Needed による PMTU の引き下げ(下限 552)を持ちます。
  自分が示す MSS は MTU から 40 byte を引いた値です
- 輻輳の制御:RFC 5681 の slow start と輻輳の回避、RFC 6582 の NewReno の高速の再送と回復を持ちます
- SACK:握手で SACK を交渉し、受け手として区間の表から SACK の block を返します。
  送り手としては受け取った SACK の block を検査するだけで、回復には使いません。
  RFC 2018 は送り手が SACK の情報を使わないことを許すので、後の段階で送り手の側だけを足せます
- 窓の probe:相手の窓が 0 の間は persist のタイマーで probe を送り、相手が probe に応える間は打ち切りません
- 遅延 ACK:Linux と同じく、MSS 2 つ分ごとか遅延の期限で ACK を返します
- Nagle:使いません。
  Go の `net.TCPConn` の既定の `TCP_NODELAY` と同じ扱いで、適合の試験の Linux の側にも同じ設定を与えます
- 再送の打ち切り:握手の後は Linux の `tcp_retries2`、SYN-ACK は `tcp_synack_retries` の既定の回数で打ち切ります
- ISN:RFC 6528 の鍵付きの hash で作ります

keepalive は、今の中継が無通信のタイムアウトを持たず([TCP の中継と終了](tcp-relay.md))、今の gVisor の接続も keepalive を使わないので、完成に含めません。
タイマーの節は枠に用意し、必要になった時に有効にします。
ECN は交渉しません。

### 後の段階の機能

次の機能は完成に含めず、性能の段階で加えます。

- SACK による損失の回復(RFC 2018、RFC 6675):送信の記録の輪の印を scoreboard にします
- RACK-TLP(RFC 8985):送信の記録の輪の送った時刻を使います。
  最小の RTT を持つ欄は、RTT の推定の構造に今から置きます
- CUBIC(RFC 9438):輻輳の制御は、ACK、損失、RTO の 3 つの知らせを受ける interface の後ろに置き、NewReno をその最初の実装にします

次の機能は性能の目標とは別に、既定を gVisor から替える判断の前に要否を決めます。

- SYN cookie(RFC 4987):握手の途中の表が満杯の時に状態を持たずに応える仕組みです。
  gVisor と Linux はどちらも使うので、持たない wgstack は SYN の洪水の間の新しい接続の成功率が両者より低くなります。
  保持の上界には影響しません

## 未確認の点と未決の点

- 実際の量:c_conn、記録 1 件、表の 1 行の大きさと、生きているヒープが上界の式の値に収まることは未確認です。
  実装で測り、試験で固定します
- 初期の値:Q の 512、N_syn の 1024、H の 32、M の 65,536 が通常の利用で足りるかは未確認です。
  特に H は、boost の窓で損失が多い時の回復の速さに関わるので、性能の段階で見直します
- CPU:同期の入力と 2 段の錠で、CPU の目標(gVisor の 1.2 倍以内)を満たせるかは未確認です
- Windows と macOS:時計の分解能とスケジューラの違いが遅延 ACK と RTO に与える影響は未確認です
- 会計の不整合の知らせ方:wgstack が自分の会計の不整合を検出した時に、接続を閉じることに加えて `agent doctor` に示すかは未決です。
  `UDPReceiveFault` の判定を広げるか、別の判定を足すかは、どちらも公開のサーフェスの変更を伴います
- 実装の見え方:どちらの実装で動いているかを `agent doctor` と制御ソケットに示すかは未決です。
  今の設計では起動ログだけで示します
- カーネルモードでの値:空でない `WGFT_AGENT_NETSTACK` を止める代わりに、無視してログに出す案もあります。
  止める案は、指定した値に従えないときは提示して止めるという約束に合わせた選択です
- 再組み立ての表の共有:表を葉の package に移すと、既定の gVisor の経路のコードも動きます。
  移さずに写す案は、規則の正本が 2 つになるので採りません
- 中継の前提:中継とその試験が、前述の 4 点のほかに gVisor の挙動を前提にしているかは未確認です。
  中継の試験を両方の実装に流して確かめます
- 緊急のデータ:Linux の既定(`SO_OOBINLINE` を付けない)は緊急の 1 byte を stream から外します。
  wgstack はその byte を通常のデータとして渡すので、緊急のデータを使う相手では中継される byte の列が Linux と違います
- 拠点ごとの /16:待ち受けを集合のすべてのアドレスに束縛するか、アドレスごとに束縛するか、ping の送信元をどう選ぶかは、その機能の設計の時に決めます

[ユーザー空間の仕様](README.md)
