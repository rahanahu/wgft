# UDP の受信と出力の会計

UDP の受信は、プロセス共通の予算と endpoint ごとの上限で数えます。
netstack の出力にも滞留の上限とキューの隔離を設けます。


<a id="udp-の受信の会計"></a>
- UDP の受信の会計:TUN の `Write` は、この Device のアドレス宛ての完成した IPv4 の UDP の datagram を、UDP の受信の会計(`internal/nettun`)に通してから netstack に渡す。
  会計は、Device の全ての UDP の endpoint の受信のキューに溜まる datagram を数えます。
  UDP Length が IPv4 の残りより短い場合も配送し、読み取り時に照合する長さには UDP Length を使います。
  予算には IPv4 の残り全体を算入し、後続の byte を含む packet の保持を覆う。
  UDP Length が UDP ヘッダーより短い場合や IPv4 の残りを超える場合は配送しません。
  更新後の gVisor は受信キューに `PacketBuffer.MemSize()` を算入します
<a id="udp-の受信の予算"></a>
- UDP の受信の予算:Device ごとに 1 つで、4 MiB と 4096 件を上限とします。
  byte は、IPv4 ヘッダーの後ろにある UDP ヘッダーを除いた全 byte に 1 件あたり 64 byte を足して数えます。
  UDP Length が示す利用者データより後ろに byte があれば、その分も算入します。
  読み取り時に照合する `ReadResult.Total` は UDP Length から UDP ヘッダーの長さを引いた値であり、予算の byte とは異なる。
  数えた byte は Go のヒープの実際の費用ではない(次の項)。
  値は設定項目にしません。
  datagram は endpoint に渡す前に予約し、読み手が読んだときと endpoint を閉じたときに返します。
  予約できない datagram は捨て、ICMP を返さない。
  gVisor の endpoint の受信のキューが満杯のときと同じ扱いです。
  4 MiB は、ラボの通常の負荷で 1 MiB が応答の一部を拒んだことを受けて、資源の上界として十分に小さく、実際の費用を説明できる値として採った([以前の検証 2026-09-27](https://github.com/rahanahu/wgft/blob/c5a6dc454468733e9ff4b2a4eb2b5a17ed4bdf4e/docs/design.md#L687))。
  最適値として探した値ではなく、この量までの burst を失わない保証でもない。
  `vpsd` とエージェントは同じ値を使います。
  両者の Device は役割が違うが、別の値を置く根拠となる実測が無いためである(2026-09-27、所有者の決定)
<a id="予算と実際の費用の関係"></a>
- 予算と実際の費用の関係:固定版の gVisor では、受信のキューに入った datagram 1 件が使う Go のヒープは、約 0.7 KiB の固定の部分(gVisor の packet の管理の構造など)に、IPv4 と UDP のヘッダーを含む packet 全体を 2 の冪に切り上げた大きさを足した量である(試験で測った)。
  IPv4 の option の無い packet 全体は payload に 28 byte を足した大きさで、会計が数える byte(payload に 64 byte を足した値)より小さい。
  したがって切り上げた大きさは数えた byte の 2 倍未満であり、受信のキューが使う生きているヒープは、Device ごとに「使用中の数えた byte の 2 倍 + 使用中の件数 × 約 0.7 KiB」を目安とします。
  予算いっぱいでは約 11 MiB になります。
  この換算は固定版の gVisor の作りから導いた見積もりであり、gVisor を更新すると変わりうる
<a id="endpoint-1-つの上限"></a>
- endpoint 1 つの上限:endpoint 1 つが持てる量は、byte と件数のどちらでも Device の予算の 1/4 まで(1048576 byte、1024 件)とします。
  目的は、読み手が止まった 1 つの endpoint による Device 全体の飢餓の封じ込めです。
  4 つ程度の止まった endpoint が同時に予算を使えば、Device 全体の予算は依然として尽きうる。
  更新後の gVisor は packet 全体と `PacketBuffer` の構造を受信キューに算入します。
  会計は endpoint を開くとき、gVisor の受信キューの上限を会計の byte 上限に最大 IPv4・UDP ヘッダーと `PacketBuffer` の構造の費用を件数上限分加えた値にします。
  会計の byte と件数の上限が先に効くようにするためです。
  ルールごとの予約や完全な公平性は提供しません。
  これ以上の分離は、必要性が実測された場合に検討します。
  上限を置く理由は、通常の故障で 1 つのルールの読みが止まるためです。
  エージェントの UDP の待ち受けは、新しいセッションの宛先の名前解決を読み取りと同じ goroutine で待つので、名前解決が応答しないだけで読みが止まります。
  上限の無い形では、このときに同じエージェントの別のルールの UDP が大きく失われた([以前の検証 2026-09-27](https://github.com/rahanahu/wgft/blob/c5a6dc454468733e9ff4b2a4eb2b5a17ed4bdf4e/docs/design.md#L687))
<a id="予算による拒否の知らせ方"></a>
- 予算による拒否の知らせ方:会計は、endpoint 1 つの上限による拒否と Device の予算による拒否を別々に数え、拒否があれば、2 つの数と 2 つの上限を英語の 1 行のログに出す。
  行は Device ごとに 1 分に 1 回までに絞る。
  `wgft status`、Web UI、wire protocol、admin API には載せない。
  gVisor 自身の endpoint の受信のキューの上限は前項のとおり会計の byte と件数の上限が先に効く値に設定します。
  上限まで受理する条件では、受信のキューの溢れで gVisor が datagram を先に捨てないことを試験で確かめた。
  仮に gVisor が捨てた場合は、会計はその予約をすぐに返し、その datagram はこの 2 つの数にもログの行にも入りません
<a id="受理の判定とロックの範囲"></a>
- 受理の判定とロックの範囲:会計は、予約した datagram を gVisor に渡した後、宛先の endpoint の公開の統計(`PacketsReceived` と受信の誤りの数)の差で、その 1 件を endpoint が受け取ったかを判定します。
  受け取らなかった datagram(checksum の誤り、接続済みの endpoint への別の送信元、受信のキューの溢れなど)の予約はすぐに返します。
  この差を 1 件に帰属させるため、同じ endpoint への配送、読み取り、閉鎖は endpoint ごとのロックで直列にします。
  Device 全体の帳簿のロックは加減と表の参照の間だけ持ち、gVisor への配送の間は持ちません。
  TCP、ICMP、断片、この Device 宛てでない packet は、どちらのロックも取らない。
  例外は、どの endpoint も登録していないポート宛ての UDP です。
  この datagram は帳簿のロックを持ったまま 1 回だけ gVisor に渡し、gVisor が Port Unreachable を返します。
  同じポートを同時に開く endpoint が、予約の無い datagram を受け取らないためです。
  ロックの順は endpoint のロックから帳簿のロックの 1 方向だけです
<a id="udp-の-endpoint-の作り方"></a>
- UDP の endpoint の作り方:Device の UDP の endpoint は、`DialUDP` と `ListenUDP` が登録表を通して作り、作ると同時に会計に登録します。
  Device は gVisor の stack を外に出さない。
  登録表の外で作った UDP の endpoint は予約の無い datagram を受け取り、会計の不変条件を壊すためです。
  Device は gVisor の `HandleLocal` を無効にしており、この Device のアドレス宛ての packet を netstack の中で折り返さない。
  自分宛ての送信は TUN の出力に出るだけで、受信の会計に入る経路は TUN の `Write` だけです。
  `HandleLocal` が無効だと、gVisor は送信元がこの Device のアドレスの入力を捨てません。
  そうした packet をトンネルから入れない守りは、WireGuard の AllowedIPs(両側の /32)だけです。
  製品の経路に自分宛ての通信は無く、サーバの Device は agent のアドレスにだけ接続し、agent の Device は待ち受けとサーバへの ping だけを行います
<a id="udp-の接続"></a>
- UDP の接続:`DialUDP` と `ListenUDP` は、gVisor の `gonet.UDPConn` の代わりに wgft の接続を返します。
  読み取りを会計に通すためです。
  期限、短い読み取り、誤りの形は `gonet.UDPConn` と同じにした(試験で同じ手順を与えて比べた)。
  違いは、`Close` の後の読み取りと、`Close` で解かれた読み取りの待ちが `net.ErrClosed` を返すことです。
  `gonet.UDPConn` はこの場合に `io.EOF` を返した
<a id="udp-の送信時の断片化"></a>
- UDP の送信時の断片化:管理下の UDP endpoint は PMTU discovery を無効にします。
  更新後の gVisor の既定値は DF を立て、MTU を超えたローカル送信を断片化しても各断片の DF と ID 0 を残します。
  この断片は受信側の検査で拒否される。
  PMTU discovery を無効にすると、断片の DF が下がり、同じ非ゼロ ID を持つため、再組み立てを通る。
  TCP と ICMP の設定は変えません
<a id="会計の不整合"></a>
- 会計の不整合:会計は、予約の無い datagram を読み取った場合、読み取った datagram の長さが予約と一致しない場合、1 回の配送で 2 件以上を受け取ったと読める場合、統計が逆に動いた場合を、不変条件の違反として扱う。
  違反を検出すると、その Device の UDP を止めます。
  以後、この Device 宛ての UDP を捨て、`DialUDP` と `ListenUDP` は誤りを返します。
  TCP は止めません。
  止まった状態は Device を閉じるまで続き、プロセスを再起動すれば戻る。
  検出したときは、違反の内容と再起動の案内を含む英語の行をログに 1 回だけ出す。
  最初に検出した違反を保ち、後の違反で内容を置き換えない。
  エージェントでは `agent doctor` の `tunnel.udp_accounting` が FAILED を示す([10.2c 節](../diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor))。
  ユーザー空間モードの `vpsd` では、ログの行だけで知らせる(2026-09-27、所有者の決定)。
  `server doctor` の JSON、管理用 API、Web UI、wire protocol は変えません。
  観測の面が違うのは、エージェントには同じホストの中の制御ソケットと `agent doctor` という面があり、`vpsd` で同じことをするには公開している管理用 API と JSON の契約を増やす必要があるためです。
  稀な内部の不変条件の違反のために今その契約を増やす必要はありません。
  `vpsd` で診断のコマンドからの機械的な検出が要る実例が出たら、別に判断します。
  この停止は資源の逼迫のときの動作ではなく、依存の更新や wgft 自身の不具合による不変条件の違反を安全側で検出するものです。
  違反の後に会計だけを外して UDP を続ける形は、会計が作る保持の上限を失うので採らない(2026-09-27、所有者の決定)。
  外部の入力だけでは違反を起こせないことを、断片、長さの誤り、option、checksum の誤り、broadcast と multicast の宛先を混ぜた packet の列を与える試験で確かめた。
  あらゆる入力について示したものではありません
<a id="keepalive-の-ping-の-endpoint"></a>
- keepalive の ping の endpoint:エージェントが keepalive ごとにトンネル内へ送る ping は、ping ごとに ICMP の endpoint を 1 つ作り、`vpsd` のトンネルアドレスへ接続して echo を 1 つ送り、応答を読むか期限が来たら閉じます。
  endpoint は bind しません。
  固定版の gVisor の ICMP の endpoint は、bind で登録した identifier を、続く接続でも閉鎖でも解放しません。
  bind と接続を続けて行うと ping ごとに endpoint と identifier が 1 つずつ残り、identifier の範囲を使い切った後は ping が毎回失敗します。
  bind しない endpoint は接続のときに identifier を 1 つだけ登録し、閉鎖でそれを解放します。
  送信元のアドレスは接続の経路が選ぶ。
  Device はアドレスを 1 つしか持たないので、選ばれるのはエージェントのトンネルアドレスです。
  `DialPing` は接続の後に endpoint の送信元のアドレスを確かめ、渡されたアドレスと違えば endpoint を閉じて誤りを返します
<a id="netstack-の出力"></a>
- netstack の出力:netstack が送り出すパケットは、gVisor の `channel.Endpoint` が持つ深さ 1024 の FIFO のキュー 1 つに入ります。
  wireguard-go の読み取り(TUN の `Read`)は、このキューから 1 回に 1 件ずつ取り出す(pull)。
  gVisor と wireguard-go の間のキューはこの 1 つだけです。
  キューが満杯のときは新しく送り出すパケットを捨て、送り出す側の netstack は待ちません。
  捨てたパケットは、TCP では再送で補われ、UDP のデータグラム、ICMP の応答、TCP の RST では失われる。
  満杯による損失を ICMP の誤りや TCP の RST に変えて相手に知らせることはしません。
  `Close` は読み取りを先に取り消し、待っている `Read` を `os.ErrClosed` で返します
<a id="出力のキューの隔離"></a>
- 出力のキューの隔離:プロトコルごとのキュー、ルールごとのキュー、公平化のための順序の入れ替えは持ちません。
  このため過負荷のときは、負荷と無関係な通信(別のルールの通信や、送る量の少ないフロー)にも少量のパケットの欠落が起こることがあります。
  欠落は負荷が終われば止まります。
  ユーザー空間モードは、カーネルモードと同等の QoS と DoS の隔離を保証しません。
  [7a.10 節](../resource/admission.md#7a10-resource-guard-の再設計)のルール 1 本の上限とルールごとの最低分はフローの数に効き、このキューの中のパケットには効きません

[ユーザー空間の仕様](README.md)
