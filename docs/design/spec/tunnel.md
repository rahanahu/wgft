# トンネルの中の約束

agent と server は、WireGuard のトンネルの中を IPv4 の通信だけで使います。
変更していない Go の v1 の server と組む agent は、トンネルの中と周りで次の規則を守り、server の側の次の振る舞いに頼れます。
メッセージの形は [messages.md](messages.md)、stream の寿命は [stream.md](stream.md)、設定の名前と構文は [cli-config.md](cli-config.md) にあります。

## 範囲と前提

- 対象の agent:ユーザー空間モードの agent です。
  WireGuard と netstack をプロセスの中に持ち、ホストのアドレスと経路と firewall を変えません。
  カーネルモードの agent の違いは[後の節](#カーネルモードの-agent)に短く書きます
- 対象の server:server のモードは 3 つあります。
  カーネルモードは Linux の WireGuard と nftables の DNAT と MASQUERADE で転送します ([6.1 節](../vps/kernel.md#61-カーネルモード))。
  プロキシモードのルールは server のプロセスが TCP を受けて agent へ接続し直します ([6.2 節](../vps/proxy.md#62-プロキシモード))。
  ユーザー空間モードは wireguard-go と gVisor の netstack で全ルールを中継します ([6.3 節](../vps/userspace.md#63-ユーザー空間モード))。
  agent はどのモードの server とも同じ規則で動き、server のモードを知りません
- アドレスの族:トンネルの中は IPv4 だけです。
  IPv6 の packet は送らず、受けた IPv6 の packet は捨てます
- 制御プレーンとの関係:stream はトンネルを通りません。
  トンネルを作り直す間も stream は続き、stream が切れている間もトンネルとルールは動き続けます

## WireGuard のピア

agent は、全体状態の `wg` ([messages.md](messages.md#wgconfig)) と認証情報の秘密鍵 ([credentials.md](credentials.md)) から、ピアが 1 つの WireGuard のトンネルを作ります。
導き方は fixture の [wg-config.json](../../../testdata/spec/tunnel/wg-config.json) と同じです。

- 秘密鍵:`agent.json` の秘密鍵を使います
- ピア:ピアは server の 1 つだけです。
  公開鍵は `wg.server_pubkey` で、base64 の 32 byte として読めなければトンネルを作りません
- 自分のアドレス:`wg.address` は IPv4 の CIDR です。
  agent はアドレスの部分だけを自分のトンネルのアドレスとして持ち、帯の長さは server のアドレスを導くためだけに使います。
  CIDR として読めないか IPv4 でなければ、トンネルを作りません
- server のアドレス:全体状態は server のアドレスを持ちません。
  agent は `wg.address` の帯の先頭のアドレスの次 (`10.200.0.0/24` なら `10.200.0.1`) を server のアドレスとします。
  server はこの決め方に合わせて自分のアドレスを帯の先頭の次に置き、帯を `/30` 以下の長さに限ります ([4 節](../network.md#4-ネットワーク))
- AllowedIPs:server のアドレスの `/32` だけです。
  このため agent が受け入れるトンネルの packet は送信元が server のアドレスのものだけで、agent がトンネルへ送れる宛先も server のアドレスだけです
- 待ち受けのポート:agent は WireGuard の UDP のポートを固定しません。
  トンネルを作るたびに OS が選んだポートを使うので、作り直しと鍵の変更のたびに送信元のポートが変わります
- ハンドシェイクを始める側:最初のハンドシェイクは agent が始めます。
  server は agent のピアにエンドポイントも persistent keepalive も設定せず、agent のハンドシェイクからエンドポイントを学ぶためです ([6.3 節](../vps/userspace.md#63-ユーザー空間モード))。
  agent はトンネルを立てた直後に、エンドポイントを解決できていれば、通信を待たずに keepalive を 1 つ送ってハンドシェイクを始めます
- persistent keepalive:`wg.keepalive` の秒数です。
  0、負の値、65535 を超える値は 25 秒として扱います。
  v1 の server は常に 25 を送ります
- MTU:`wg.mtu` を netstack の MTU にします。
  agent の netstack は TCP の MSS を MTU から 40 を引いた値で示すので、server と agent の MTU が揃っていれば、server の側に MSS のクランプは要りません ([4 節](../network.md#4-ネットワーク))。
  server が送る値は 576 から 9216 で、既定は 1420 です

v1 の agent は、wireguard-go の device に次の UAPI の設定を 1 回で渡します。
`endpoint` の行は、エンドポイントを解決できたときだけ加えます。
device から読み返した値は fixture の [uapi-peer.json](../../../testdata/spec/tunnel/uapi-peer.json) と同じです。

```text
private_key=<agent の秘密鍵の hex>
public_key=<server の公開鍵の hex>
allowed_ip=<server のアドレス>/32
persistent_keepalive_interval=<keepalive の秒数>
endpoint=<解決した IPv4 のアドレス>:<ポート>
```

<a id="エンドポイントの解決"></a>
### エンドポイントの解決

`wg.endpoint` は `host:port` の形です。
agent はこれを IPv4 のアドレスとポートに直してピアのエンドポイントにします。
規則は fixture の [endpoint.json](../../../testdata/spec/tunnel/endpoint.json) と同じです。

- ホスト:IPv4 のアドレスならそのまま使います。
  IPv6 のアドレスと IPv4-mapped IPv6 のアドレスは拒みます。
  ホスト名なら A レコードだけを 5 秒の期限で引き、アドレスの小さい順に並べた先頭を使います
- ポート:10 進の数字として読みます。
  サービス名と 65535 を超える値は拒みます
- 解決の失敗:エンドポイントを設定しないままトンネルを立て、引き直しに任せます。
  失敗の文言はトンネルの状態の理由になります ([messages.md](messages.md#tunnelstatus))
- 引き直し:keepalive の間隔ごとに、ハンドシェイクが一度も成立していないか、最終ハンドシェイクが keepalive の 5 倍より古ければ、名前を引き直します。
  結果が今のエンドポイントと違うときだけ、ピアのエンドポイントを書き換えます
- 空の値:server は `WGFT_WG_ENDPOINT` が空なら空の文字列を送ります。
  agent はこれを解決の失敗として扱います

#### Go の性質:ポートの読み方

ポートの読み方は Go の `net.SplitHostPort` と `strconv.ParseUint` によります。
次の点は Go の v1 の振る舞いであり、Go 以外の実装は同じ結果を出すように明示して書きます。

- 角括弧の IPv4 のアドレス:`[203.0.113.10]:51820` を受けます
- 先頭の 0:`051820` を 51820 として受けます
- 符号:`+51820` を拒みます。
  Rust の `str::parse::<u16>` は `+` を受けるので、そのままでは使えません
- 0 のポート:`203.0.113.10:0` を受けます。
  server はポートを 1 から 65535 に直してから送るので、この値は届きません

#### Go の性質:エンドポイントの名前の解決

名前の解決は Go の `net.DefaultResolver` で行います。
Go 以外の実装は、OS の resolver の設定に従って A レコードを引けば同じ結果になります。
どの resolver を使ったかで変わる結果は保証の外です。

## トンネルを作る時機と作り直し

- 起動の時:認証情報に前回の全体状態 (`last_state`) があれば、stream に接続する前にその状態でトンネルを立て、ルールの待ち受けを開きます。
  server が止まっていても、server の側にピアが残っていれば転送が戻るためです
- wg の変更:届いた全体状態の `wg` が今のトンネルの値と 1 つでも違えば、トンネルを閉じてから作り直します。
  比べるのは `wg` の全部のキーで、`udp_timeout` と `udp_timeout_stream` も含みます。
  作り直すと、中継中の TCP の接続と UDP のセッションは切れます。
  `wg` が同じなら、ルールの待ち受けだけを合わせます
- 鍵の変更:`rotate-key` は今のトンネルを閉じ、新しい鍵で同じ全体状態を適用し直します ([stream.md](stream.md))
- 作れない `wg`:秘密鍵、server の公開鍵、アドレスが読めない全体状態ではトンネルを作らず、次の全体状態を待ちます。
  同じ全体状態で試し直しません
- 作成の失敗:それ以外の理由でトンネルを作れなかったときは、トンネルの無い状態で残り、[後述](#ハンドシェイクの監視と作り直し)の予定で試し直します

- 保証の外:`udp_timeout` か `udp_timeout_stream` だけが変わったときにトンネルを作り直すことは、v1 の agent の振る舞いですが、server はこれに頼りません。
  server は起動の直後に 0 を送り、conntrack の値を読んだ後に世代を上げずに値を入れることがあるので ([messages.md](messages.md#wgconfig))、v1 の agent はその時点で 1 回作り直します

## keepalive の ping

agent は、トンネル内で server のアドレスへ ICMP の echo request を送ります。

- 間隔:persistent keepalive と同じ間隔 (既定で 25 秒) です。
  最初の ping はトンネルを立ててから 1 間隔の後に送ります
- 中身:送信元は agent のトンネルのアドレス、宛先は server のアドレスです。
  echo の data は ASCII の `wgft` の 4 byte です。
  sequence は時計から作る値で、identifier は netstack が選びます
- 応答の待ち:2 秒だけ待ち、結果を使いません
- 目的:ping は WireGuard の data packet です。
  data packet を送った側は、相手から何も届かなければ約 15 秒 (WireGuard の `KeepaliveTimeout` と `RekeyTimeout` の和) で新しいハンドシェイクを始めます。
  相手の WireGuard は、data packet を受けて 10 秒の間に送るものが無ければ keepalive を返すので、健全なトンネルではこのハンドシェイクは起きません。
  server が再起動などでセッションを失ったとき、keepalive だけでは鍵の寿命の 120 秒まで戻りませんが、ping があれば約 15 秒で戻ります
- server の応答:agent は応答に頼りません。
  ユーザー空間モードの server は gVisor の netstack が応答します。
  カーネルモードの server は、wgft の nftables の `input` が wg0 から入る新しいフローを落とすので、応答しないとコードから読めます (未確認)

### Go の性質:echo の identifier

v1 の agent は echo の identifier に 1 を書きますが、gVisor と wgstack の endpoint がそれを自分の値に書き換えます。
Go 以外の実装は任意の identifier を使えます。
gVisor の ICMP の endpoint を bind すると identifier が解放されない問題があり、v1 は bind せずに接続します ([keepalive の ping の endpoint](../userspace/udp-accounting.md#keepalive-の-ping-の-endpoint))。
この問題は gVisor に固有で、Go 以外の実装には当たりません。

<a id="ハンドシェイクの監視と作り直し"></a>
## ハンドシェイクの監視と作り直し

agent は 30 秒ごとに今のトンネルの最終ハンドシェイクを読み、新しいハンドシェイクが無い時間が長ければトンネルを作り直します。
理由は [トンネルの作り直し](../userspace/tunnel-recovery.md#トンネルの作り直し)と[作り直しの閾値](../userspace/tunnel-recovery.md#作り直しの閾値)にあります。

- 時間の測り方:最終ハンドシェイクの値そのものと、その値を最初に観測した時刻を覚えます。
  新しいハンドシェイクが無い時間は、観測した時刻とトンネルを立てた時刻の遅い方から、単調な時計で測ります。
  壁時計の飛びで作り直しを起こさず、抑えもしません ([経過時間の測り方](../userspace/tunnel-recovery.md#経過時間の測り方))
- 閾値:最初の作り直しは 300 秒です。
  作り直すたびに間隔を 2 倍にし、900 秒で止めます。
  0 でない新しいハンドシェイクを観測したら 300 秒に戻します ([作り直しの間隔](../userspace/tunnel-recovery.md#作り直しの間隔))
- 作り直し方:同じ鍵、アドレス、エンドポイントで、device と netstack ごと作り直し、ルールの待ち受けを開き直します。
  server の側のピアの設定は変わりません。
  WireGuard の送信元のポートは変わり、server は次のハンドシェイクで学びます
- 作成の失敗の試し直し:トンネルの作成そのものに失敗したら、最初は次の 30 秒の点検で試し、続けて失敗するほど 300 秒、600 秒、900 秒と広げ、900 秒で止めます。
  `rotate-key` と停止で閉じたトンネルと、全体状態をまだ受け取っていない状態は試し直しません ([作成に失敗したときの再試行](../userspace/tunnel-recovery.md#作成に失敗したときの再試行))
- 見せ方:作り直しと作成の失敗のたびに英語のログを 1 行出します ([作り直しの見せ方](../userspace/tunnel-recovery.md#作り直しの見せ方))
- stream との関係:新しいハンドシェイクの観測は、stream の再接続の待ちを打ち切る合図にも使います ([stream.md](stream.md#再接続))

server の側の前提は次のとおりです。

- 健全なトンネル:agent は 25 秒ごとに送り、WireGuard は鍵を作ってから 120 秒を過ぎた最初の送信で新しいハンドシェイクを始めます。
  このため server が見る最終ハンドシェイクは 145 秒より古くなりません。
  `server doctor` の `tunnel.handshake` はこれを前提に判定します ([10.2a 節](../diagnosis/server-observations.md#102a-転送の診断-server-doctor))
- 案内の文言:`server doctor` は、agent が 30 秒ごとに試し直し、300 秒ハンドシェイクが無ければトンネルを作り直すと案内します。
  Go 以外の実装もこの 2 つの値を保ちます

### Go の性質:サスペンドの間の時計

単調な時計がサスペンドの間に進むかどうかは、Go の runtime が OS ごとに読む時計で決まります ([サスペンドの扱い](../userspace/tunnel-recovery.md#サスペンドの扱い))。
Linux の `CLOCK_MONOTONIC` と macOS の `mach_absolute_time` はサスペンドの間に進まず、Windows の `InterruptTime` はスリープの間も進みます。
Go 以外の実装が v1 と同じ時機で作り直すには、Linux と macOS ではサスペンドの間に止まる時計を、Windows ではスリープの間も進む時計を使います。
サスペンドの後の作り直しの時機は server から見えず、保証の外です。

### Go の性質:受信の goroutine の停止

作り直しが要る主な故障は、wireguard-go の受信の goroutine が回復できない誤りで終わり、起こし直されない状態です。
Windows では、標準の Registered I/O のバインドが ICMP の Port Unreachable を `WSAECONNRESET` として返し、受信が止まりました。
v1 はこれを避けるために Windows で `conn.NewStdNetBind()` を使います ([トンネルの回復と作り直し](../userspace/tunnel-recovery.md))。
Go 以外の実装は、一時的な受信の誤りで受信を止めないようにします。
作り直しの規則は、それでも戻らない故障への備えとして保ちます。

## トンネルの状態

agent はハートビートでトンネルの状態を報告します。
形と固定の理由の文言は [messages.md](messages.md#tunnelstatus) にあります。
状態は、次の場合のうち上から最初に当たるもので決まります。

- トンネルが無い:`error` です。
  理由は、作成の失敗の後の試し直しを待つ場合、試し直さない失敗の場合、全体状態をまだ受け取っていない場合、それ以外の場合で分けます。
  このとき `rules` は `[]` です
- トンネルがあり、エンドポイントの解決に失敗している:`error` で、理由は解決の失敗の文言です
- トンネルがあり、ハンドシェイクが一度も成立していない:`error` で、理由は `handshake not established` です。
  作り直した直後もこの状態になります
- それ以外:`ok` です

トンネルがあるときの値は次のとおりです。

- `endpoint`:最後に解決できたエンドポイントです。
  WireGuard がハンドシェイクの後に学んだ相手のアドレスではありません
- `last_handshake`:今のトンネルの最終ハンドシェイクです。
  作り直す前のトンネルの値と、鍵を変える前の鍵の値は載せません

トンネルの理由の文言は agent の `agent doctor` が見分けます ([control-socket.md](control-socket.md))。
v1 の server は理由をそのまま表示するだけで、トンネルの理由を文言で分類しません。

## server から agent への通信

agent の待ち受けに届く通信は、すべて server のトンネルのアドレス (既定で `10.200.0.1`) から来ます。
server は自分のトンネルのアドレスで待ち受けず、トンネルの中の通信はすべて server の側か agent の keepalive の ping から始まります ([4 節](../network.md#4-ネットワーク))。

| server のモードとルール | agent から見た送信元 | 宛先のポート | 中身 |
| --- | --- | --- | --- |
| カーネルモードの DNAT のルール | server のアドレス。MASQUERADE が書き換えます | 公開ポートのまま | クライアントの packet そのもの |
| カーネルモードのプロキシのルール | server のアドレスの一時ポート | `listen_port` のポート | server のプロセスが中継する TCP の stream |
| ユーザー空間モードの server | server のアドレスの一時ポート。TCP の接続と UDP のセッションごとに 1 つです | `listen_port` のポート | server の netstack が中継する TCP の stream と UDP の datagram |

- クライアントのアドレス:agent はクライアントのアドレスを知りません。
  `proxy_protocol` のルールでは、server が TCP の stream の先頭に PROXY protocol v2 のヘッダを書きます。
  agent はヘッダを読まず、ほかの中身と同じく宛先へそのまま転送します ([待ち受けの失敗と宛先の許可](../userspace/targets.md))
- ポートの一致:DNAT はポートを書き換えないので、ルールの `listen_port` は VPS の公開ポートと同じです。
  agent はどのモードでも `listen_port` のポートで待ち受けます
- UDP のセッションの見分け:送信元のアドレスは常に同じなので、agent の UDP のセッションは実質は送信元のポートで分かれます
- agent どうし:server は agent から agent への通信を通しません。
  カーネルモードの server は wg0 から wg0 への forward を落とし、agent の AllowedIPs も server のアドレスだけです

## ルールの待ち受け

agent は、有効なルールの `listen_port` の各ポートで、自分のトンネルのアドレスの TCP か UDP を待ち受けます。
どの待ち受けを開くかと実効宛先は、fixture の [listeners.json](../../../testdata/spec/tunnel/listeners.json) と同じです。

- 単位:待ち受けは `(proto, port)` の組で、ルールの範囲の 1 ポートに 1 つです
- 実効宛先:範囲の下端から `k` 番目のポートは、`target` のポートに `k` を足した宛先へ中継します。
  65535 を超えるポートは待ち受けません。
  `target` を IPv4 の `host:port` として読めないルールは、待ち受けを 1 つも開きません
- 無効なルール:`enabled: false` のルールは待ち受けません。
  ハートビートの `rules` にも載りません
- 無効な agent:server が agent を無効にすると、全ルールが `enabled: false` で届きます。
  agent は全部の待ち受けを閉じ、トンネルと keepalive は続けます。
  `agent_disabled` は診断のためだけにあり、agent はこれで転送を止めません ([messages.md](messages.md#state))
- 収束:ポートごとに今の待ち受けと宣言を比べ、無いものを開き、余るものを閉じ、実効宛先が変わったものを閉じてから開き、所属するルールの ID だけが変わったものはそのまま残します ([リスナーの収束とフローの帰属](../userspace/listeners.md))
- 開けない待ち受け:そのルールを `error` として報告し、30 秒ごとに開き直します。
  同じルールのほかのポートは転送を続けます
- 閉じたポートの再利用:中継の側から切った接続は、そのポートの待ち受けをすぐ開き直せる状態で閉じます。
  ルールを無効にした直後に有効に戻す操作と、実効宛先を変えて開き直す操作がこれに頼ります
- 保証の外:2 本の有効なルールが同じ `(proto, port)` を持つと、v1 の agent は配列の後ろのルールを使います。
  server はポートの重なるルールを保存しないので、この値は届きません

### Go の性質:閉じたポートの TIME_WAIT

gVisor の netstack は、通常の `Close` で閉じた TCP の接続を TIME_WAIT に 60 秒残し、その間は同じポートで待ち受けを開けません。
v1 の agent は、中継の側から切る接続を RST で閉じてこれを避けます ([TCP の中継と終了](../userspace/tcp-relay.md))。
宛先が先に閉じた接続は TIME_WAIT に残るので、その直後に閉じ直したルールの待ち受けは、v1 では次の 30 秒ごとの試し直しまで開かないことがあります。
Go 以外の実装は、Linux の `SO_REUSEADDR` を付けた待ち受けのように、TIME_WAIT の接続と待ち受けを衝突させない作りにできます。
wgstack はこの作りです ([中継から見える違い](../userspace/wgstack.md#中継から見える違い))。

## TCP の中継

- 受け付けの順:agent はトンネルの側の TCP の握手を先に終え、その後で宛先へ接続します。
  server の疎通確認は、この順に頼って結果を分類します ([後述](#server-からの疎通確認))
- 宛先への接続:接続ごとに OS の TCP のソケットで宛先へ接続します。
  期限は 10 秒です。
  宛先から見た送信元は agent のホストのアドレスです
- ハーフクローズ:片方向の終わり (FIN) を反対側へ伝え、反対の向きの中継を続けます。
  両方向が終わったら両側を閉じます ([6.2 節](../vps/proxy.md#62-プロキシモード))
- 無通信:TCP の中継は無通信の期限を持ちません
- PROXY protocol:ヘッダは中身としてそのまま転送します

agent がトンネルの側の接続を閉じる方法は次のとおりです。

| 場合 | トンネルの側の終わり方 |
| --- | --- |
| フロー数の上限、宛先の許可一覧の拒否、ブロードキャストとマルチキャストの宛先 | 握手の後、データを送る前に RST |
| 宛先への接続の失敗 (上の拒否を除く) | データを送らずに閉じます。受け取ったデータが残っていなければ FIN です |
| ポートが宣言から消えた、実効宛先が変わった、agent の停止 | RST |
| 宛先の側の EOF | FIN を伝え、反対の向きを続けます |

- 疎通確認との関係:server の疎通確認は、接続の直後の EOF か RST を「agent までは届くが宛先に届かない」と読みます。
  このため宛先への接続の失敗では、agent はトンネルの側の接続を待たずに閉じます
- 誤りによる終わり:片側の読み書きが RST などの誤りで終わったときの反対側の閉じ方は保証の外です。
  v1 の agent は、トンネルの側の誤りでは宛先の側を通常の close で閉じ、宛先の側の誤りではトンネルの側を送り残しを届けた後に閉じます

### 宛先の試し接続

agent は、TCP の宛先へ届くかを定期に確かめ、ルールの状態に載せます ([ハートビートと到達性](../control/heartbeat.md))。

- 時機:TCP の待ち受けを開いたときと、その後 30 秒ごとです。
  適用は、開いた待ち受けの試し接続の結果を待ってから終わるので、最初の状態は適用の直後のハートビートに載ります。
  agent は適用が待つ試し接続の数に上限を置いてかまいません。
  上限の外の待ち受けの最初の状態は誤りを持たず、適用の後に始まる 30 秒ごとの試し接続の 1 周で決まります。
  その時に前の 1 周が走っていれば、その終わりの後に始まる 1 周です。
  1 周は応えない宛先 32 件ごとに 2 秒かかるので、範囲の広いルールでは最初の状態が決まるまで長くかかります (応えない宛先が 65535 件なら約 68 分)。
  v1 の Go の agent は上限を置かず、Rust の agent は 256 件で区切ります ([agent-parity.md の宛先の規則の作り](../v2/agent-parity.md#宛先の規則の作り))
- 方法:宛先へ TCP で接続し、すぐ閉じます。
  宛先には、データの無い接続が周期ごとに 1 本届きます
- 期限と数:1 件の期限は 2 秒で、同時に試すのは 32 件までです
- 結果:失敗したルールは `error` になり、理由は `did not answer` などの語を含みます ([messages.md](messages.md#ルールの理由の語))。
  `error` は報告だけに使い、中継を止めません
- UDP:送るだけでは届いたかが分からないので、試し接続をしません

期限と同時の数は fixture の [relay-timing.json](../../../testdata/spec/tunnel/relay-timing.json) と同じです。

## UDP の中継

- セッション:送信元の `(アドレス, ポート)` ごとに 1 つのセッションを持ちます。
  新しい送信元の最初の datagram でセッションを作り、宛先へ OS の UDP のソケットを接続します。
  宛先のホスト名はセッションを作るときに解決するので、DNS の変更は新しいセッションだけに効きます
- 応答:宛先からの datagram は、そのセッションの送信元へ、待ち受けのポートから送ります
- 無通信の期限:`wg.udp_timeout_stream` の秒数です。
  0、負の値、2147483647 を超える値は 120 秒として扱います。
  どちらの向きの datagram も期限を延ばします。
  v1 の agent は期限の 4 分の 1 ごとに点検するので、セッションは期限から期限の 1.25 倍までの間に閉じます
- `udp_timeout`:agent は使いません。
  server の conntrack は assured になる前のフローを `udp_timeout` で消すので、数 packet で終わるフローでは agent に死んだセッションがしばらく残ります ([UDP の中継と応答のバッファ](../userspace/udp-relay.md))
- 宛先の誤り:宛先への書き込みの失敗と、宛先からの読み取りの失敗でセッションを閉じます。
  宛先の Port Unreachable による読み取りの失敗もこれに当たります。
  agent はこの誤りをトンネルへ ICMP として伝えず、同じ送信元の次の datagram で新しいセッションを作ります
- 大きい datagram:MTU を超える UDP の datagram は、DF を立てず、0 でない ID の IPv4 の断片に分けて送ります ([UDP の送信時の断片化](../userspace/udp-accounting.md#udp-の送信時の断片化))
- 待ち受けの無いポート:agent は、待ち受けの無いポートへの UDP に、自分のトンネルのアドレスから ICMP の Port Unreachable を返します。
  server の中継は Port Unreachable を受けるとそのセッションを閉じます ([ICMP の誤りの入口](../userspace/packet-validation.md#icmp-の誤りの入口))

期限の既定と点検の間隔は fixture の [relay-timing.json](../../../testdata/spec/tunnel/relay-timing.json) と同じです。

### Go の性質:宛先の Port Unreachable

宛先の Port Unreachable で読み取りが失敗するのは、接続した UDP のソケットに OS が `ECONNREFUSED` を返すためです。
Go 以外の実装も、接続した UDP のソケットを使えば同じ結果になります。

## フロー数の上限

agent は、同時に中継するフローの数を 3 段で抑えます ([フロー数とメモリのソフト上限](../userspace/flow-limits.md))。

- プロセス全体:TCP は `WGFT_MAX_TCP_FLOWS` (既定 2048)、UDP は `WGFT_MAX_UDP_FLOWS` (既定 8192) です
- ルールごと:プロセス全体の値から導く内部の値で、設定項目ではありません
- 送信元ごと:agent では数えません。
  送信元が常に server のアドレスだからです
- 上限での動作:新しいフローだけを拒み、既存のフローを追い出しません。
  TCP は握手の後に RST で閉じ、UDP は新しい送信元の datagram を ICMP を返さずに捨てます。
  拒んだことは待ち受けごとに 1 分に 1 回までログに出し、server には知らせません
- server から見えること:カーネルモードの server では、クライアントが RST を受けるか、UDP の応答が来ません。
  server の中継を挟むモードでは、server の中継が agent の RST を受けて公開側の接続を閉じます ([TCP の中継と終了](../userspace/tcp-relay.md))

## 宛先の扱い

- 許可一覧:`WGFT_AGENT_ALLOW_TARGETS` があれば、一覧に入らない宛先へ接続しません。
  構文は [cli-config.md](cli-config.md)、判定の規則は[宛先の許可一覧](../userspace/targets.md#宛先の許可一覧)にあります。
  許可一覧はルールの宛先だけに効き、全体状態の `wg.endpoint` (WireGuard のエンドポイント) には効きません。
  server は `wg.endpoint` で agent の WireGuard の UDP の送り先を任意のアドレスとポートにできます。
  v1 の agent と同じです
- ユニキャストだけ:ブロードキャストとマルチキャストのアドレスへは、許可一覧の有無によらず転送しません ([ブロードキャストとマルチキャストの宛先](../userspace/targets.md#ブロードキャストとマルチキャストの宛先))
- 判定の時機:IP リテラルの宛先は適用のときに判定し、拒めばそのポートの待ち受けを開かずにルールを `error` にします。
  ホスト名の宛先は、TCP の接続 1 本ごとと UDP のセッション 1 つごとに、解決したアドレスで判定します
- ループバックの宛先:ユーザー空間モードの agent は、`127.0.0.1` のようなループバックの宛先にも、ほかの宛先と同じ規則で接続します。
  カーネルモードの agent は、許可一覧が名指すときだけ転送します ([ループバックの宛先](../kernel-agent/targets.md#ループバックの宛先))
- 宛先のアドレスの族:`target` に IPv6 のアドレスは書けませんが、ホスト名の解決は IPv4 と IPv6 の両方を返しうるので、agent は LAN の側で IPv6 の宛先へ接続することがあります

### Go の性質:宛先への接続の試し方

許可一覧が無いとき、v1 の agent は宛先を名前のまま Go の `net.Dialer` に渡します。
`net.Dialer` は名前を両方の族で解決し、TCP では先頭と同じ族を先に試して 300 ミリ秒の後にもう一方の族を並行して試し、接続の期限をアドレスの間で分けます。
許可一覧があるとき、v1 の agent は同じ試し方を自分で行います ([宛先の許可一覧](../userspace/targets.md#宛先の許可一覧))。
Go 以外の実装は、どちらの場合もこの試し方を写します。

<a id="server-からの疎通確認"></a>
## server からの疎通確認

server は、管理者が求めたときだけ、トンネルの中から agent の待ち受けへ TCP で接続します。
`POST /api/v1/rules/{id}/check`、Web UI の疎通確認、`server doctor --probe` は同じ確認を使います ([10.1 節](../interface.md#101-web-ui))。

- 対象:有効な TCP のルールで、agent が登録済みで無効でないものだけです。
  UDP のルールは確かめません
- 送るもの:server のトンネルのアドレスから、agent のアドレスとルールの `listen_port` の下端のポートへ、TCP の接続を 1 本開きます。
  接続の期限は 5 秒です。
  接続できたら何も送らず、3 秒の間 1 byte を読みます
- 分類:server は agent の振る舞いから次のように分類します

| agent の振る舞い | server の分類 |
| --- | --- |
| SYN に RST を返す (待ち受けが無い) | `none`。ルールが適用されていないと読みます |
| 5 秒の間応えない | `none`。トンネルか agent に届かないと読みます |
| 接続の直後に EOF か RST で閉じる | `agent`。agent までは届くが宛先に届かないと読みます |
| 3 秒の間に 1 byte 以上が届く | `target`。宛先が応えたと読みます |
| 3 秒の間、接続が開いたまま何も届かない | `target`。宛先へ繋がって応答を待っていると読みます |

- agent の義務:待ち受けの無いポートへの SYN には RST を返します。
  宛先へ接続できなければ、トンネルの側の接続をすぐ閉じます。
  宛先へ繋がったら、宛先の中身をそのまま返します
- ICMP と UDP:server は疎通確認のために ICMP の echo も UDP も送りません
- 保証の外:宛先が SYN を黙って捨てる場合、agent の宛先への接続は 10 秒の期限まで終わらず、server は 3 秒の時点で `target` と分類します。
  これは v1 の組み合わせの振る舞いで、コードから読んだもので未確認です

## トンネルの入口の検査

agent の netstack は、トンネルから届いた packet を netstack に渡す前に次の検査をします。
これらは wgft 自身の規則で、v1 の 2 つの netstack (gVisor と wgstack) が同じ規則で行います。
Go 以外の実装も同じ規則で行います。

- IPv4 だけ:IPv4 でない packet は捨てます
- Total Length:IPv4 のヘッダの Total Length より後ろの byte を切り捨ててから扱います ([IPv4 の Total Length](../userspace/packet-validation.md#ipv4-の-total-length))
- 断片の再組み立て:IPv4 の断片は wgft の再組み立ての表で組み立て、完成した datagram だけを扱います。
  表は未完成の datagram 128 件、断片 512 個、4 MiB を上限とし、未完成の datagram の期限は 30 秒で、1 秒ごとに期限切れを消します ([再組み立ての表](../userspace/packet-validation.md#再組み立ての表))
- 表が満杯:同じ datagram 以外の最も古い未完成の項目を消して空きを作ります。
  1 つの datagram だけで満ちるときは、その断片を捨てます ([表が満杯のときの扱い](../userspace/packet-validation.md#表が満杯のときの扱い))
- 断片の検査:ヘッダの checksum、長さ、flag、option の形を確かめ、重なる断片と矛盾する断片はその datagram ごと捨てます ([断片の検査](../userspace/packet-validation.md#断片の検査))
- 断片への ICMP:期限を過ぎた項目のうち、最初の断片を持ち自分宛てのものにだけ Time Exceeded を返します。
  option の不正な断片には Parameter Problem を返します ([断片に対する ICMP](../userspace/packet-validation.md#断片に対する-icmp))
- ICMP の誤りの送信元:ICMP の誤りは、外側の送信元が引用された datagram の宛先と一致するときだけ受け入れ、それ以外は黙って捨てます ([ICMP の誤りの入口](../userspace/packet-validation.md#icmp-の誤りの入口))
- Fragmentation Needed の下限:next-hop MTU が 552 より小さい Fragmentation Needed は捨てます ([Fragmentation Needed の MTU の下限](../userspace/packet-validation.md#fragmentation-needed-の-mtu-の下限))
- MSS の下限:MSS の option の値が 536 より小さい SYN と SYN-ACK は捨て、ICMP も RST も返しません。
  MSS の option が無い segment は通します ([TCP の MSS の下限](../userspace/packet-validation.md#tcp-の-mss-の下限))
- UDP の受信の予算:自分宛ての UDP の datagram は、netstack の全体で 4 MiB と 4096 件、待ち受け 1 つでその 4 分の 1 までを保持します。
  超えた datagram は ICMP を返さずに捨てます ([UDP の受信の予算](../userspace/udp-accounting.md#udp-の受信の予算))
- 捨てた数:捨てた数を数え、英語のログに 1 分に 1 回まで出します。
  server には知らせません

server から見える効果は、捨てた packet に応答が無いことだけです。
カーネルモードの server はクライアントの SYN を MSS ごとそのまま通すので、MSS を 536 より小さく示すクライアントは agent に接続できません。

### Go の性質:断片への ICMP の細部

断片に返す ICMP の送らない条件、引用の長さ、送る速さは、固定版の gVisor の結果に合わせてあります。
既知の差は [断片に対する ICMP](../userspace/packet-validation.md#断片に対する-icmp) に 3 つあり、wgft はその差を試験で固定しています。
server はこれらの ICMP に頼らないので、引用の長さと速さは保証の外です。

### Go の性質:中身の無い ACK の予算

gVisor の netstack を使う v1 の agent は、中身の無い TCP の ACK を接続ごとの予算で抑えます ([中身の無い ACK の予算](../userspace/packet-validation.md#中身の無い-ack-の予算))。
gVisor が中身の無い ACK を上限なしに処理待ちへ積むためで、wgstack はこの予算を持ちません。
Go 以外の実装は、ACK の処理待ちの保持に上限があれば足ります。
予算の値は保証の外です。

## netstack と wgstack

v1 の agent は、netstack の実装を `WGFT_AGENT_NETSTACK` で選びます ([実装の選択](../userspace/wgstack.md#実装の選択))。
値は `gvisor` と `wgstack` で、省略と空の値は `gvisor` です。
wgstack は wgft が Go で書いた netstack で、受動の open だけを持ちます ([エージェントの wgft の netstack](../userspace/wgstack.md))。

- 契約に入るもの:この文書の要件は、どちらの netstack でも同じです。
  トンネルの入口の検査、TCP の MSS を MTU から 40 を引いた値で示すこと、待ち受けの無いポートの SYN に RST を返すこと、待ち受けの無い UDP のポートに Port Unreachable を返すこと、UDP の受信の予算がこれに当たります
- 保証の外:wgstack を選んだときの転送の品質と資源の挙動は、互換性の保証に含めません ([互換性の保証](../compatibility.md))。
  TCP の option の組、輻輳の制御、RTO、窓の大きさ、SACK の扱い、TIME_WAIT の扱い、尽きたときの細部 ([尽きたときの動作](../userspace/wgstack.md#尽きたときの動作)) がこれに当たります
- 自分宛ての echo:agent は自分のアドレス宛ての ICMP の echo request に応答します。
  server は agent へ echo を送らないので、この応答は保証の外です

## カーネルモードの agent

カーネルモードの agent は netstack を持たず、Linux の WireGuard のインタフェースと nftables の DNAT で LAN の宛先へ転送します ([7b 節](../agent-kernel.md#7b-データプレーン自宅側カーネルモード))。
server から見た違いは次のとおりです。

- TCP の終端:agent は TCP を終端しないので、トンネルを通る SYN の MSS をクランプします
- keepalive:`wg.keepalive` の 0 は persistent keepalive を無効にします。
  ユーザー空間モードの agent は 0 を 25 秒として扱います
- 作り直し:トンネルを作り直す規則を持ちません
- 待ち受けの無いポート:公開していないポートへの新しい接続を黙って捨てます。
  server の疎通確認は、このとき接続の期限まで待ちます
- ループバックの宛先:許可一覧が名指すときだけ転送します

Rust の最初の実装はユーザー空間モードだけなので、カーネルモードの細部はこの文書の範囲の外です。

## 保証の外の振る舞い

次の振る舞いは v1 で観測できますが、server も agent も頼ってはなりません。

- 性能:転送の速さ、遅れ、CPU の使い方
- TCP の細部:再送の時機、輻輳の制御、窓とバッファの大きさ、SACK と timestamp の扱い
- バッファ:WireGuard の UDP のソケットのバッファの大きさと警告 ([WireGuard のソケットの動作条件](../userspace/socket-buffers.md))、UDP の応答のバッファの枠、netstack の出力のキューの深さと溢れたときの捨て方 ([netstack の出力](../userspace/udp-accounting.md#netstack-の出力))
- WireGuard の内部:受信と送信の 1 回の件数、ハンドシェイクの limiter の送信元の扱い ([WireGuard のハンドシェイクの送信元の保持](../userspace/wireguard-sources.ja.md))
- 閉じ方:誤りで終わった TCP の中継の反対側の閉じ方
- 文言:[messages.md](messages.md#ルールの理由の語) の語と固定のトンネルの理由を除く、理由とログの文言
- ping の細部:echo の identifier、sequence、応答を待つ時間
- 報告の選び方:ルールのどのポートの誤りを理由に選ぶか

## 未確認の点

- カーネルモードの server が agent の ping に応答しないことは、nftables の行から読んだもので、実機では確かめていません
- ユーザー空間モードの agent は `wg.mtu` を検査しません。
  server が送る範囲 (576 から 9216) の外の値、特に 0 と負の値を受けたときの振る舞いは確かめていません
- 宛先が SYN を黙って捨てるときに server の疎通確認が `target` と分類することは、コードから読んだもので確かめていません
- カーネルモードの server の MASQUERADE がクライアントの送信元のポートを保つかどうかは確かめていません。
  agent はポートの値に頼りません
- Linux の `CLOCK_MONOTONIC` がサスペンドの間に止まることと、Windows の `InterruptTime` がハイバネートの間も進むことは、OS の文書によるもので、実機では確かめていません ([サスペンドの扱い](../userspace/tunnel-recovery.md#サスペンドの扱い))

[agent と server の境目の仕様](README.md)
