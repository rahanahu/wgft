# IPv4 の断片、ICMP、TCP の MSS の検査

トンネルの入口で IPv4 の断片、ICMP の誤り、TCP のハンドシェイクの MSS を検査します。
再組み立てには予算があり、表が満杯になった場合の拒否を区別します。


- wireguard-go と gVisor の netstack でユーザー空間にトンネルを持ちます
<a id="ipv4-の断片の入口"></a>
- IPv4 の断片の入口:TUN の `Write` は、受け取った IPv4 の断片をすべて wgft の再組み立ての表(`internal/nettun`)に渡し、完成した datagram だけを netstack に渡す。
  断片を gVisor の再組み立てには渡さない。
  固定版の gVisor の再組み立ては、断片化された datagram ごとに期限の処理のタイマーを取り消さずに残し、そのタイマーは期限の 30 秒まで生きるので、保持する量が上限ではなく断片の届く速さで決まるためである([以前の検証 2026-09-27](https://github.com/rahanahu/wgft/blob/c5a6dc454468733e9ff4b2a4eb2b5a17ed4bdf4e/docs/design.md#L676))
<a id="再組み立ての表"></a>
- 再組み立ての表:Device ごとに 1 つで、未完成の datagram 128 件、保持する断片 512 個、保持 byte 4 MiB を上限とし、未完成の datagram の期限は 30 秒です。
  保持 byte は、表の固定の管理領域、保持する断片の複製、完成した datagram の複製 1 つ分を数えます。
  数えた byte は Go のヒープの実際の費用ではありません。
  値は設定項目にしません。
  表は 1 秒ごとに期限を過ぎた項目を消す。
  `vpsd` のユーザー空間モードでは、表を全エージェントのピアで共有します
<a id="表が満杯のときの扱い"></a>
- 表が満杯のときの扱い:新しい断片に、項目、断片の枠、保持 byte、完成した datagram の複製の余地のどれかが足りないときは、その断片と同じ datagram 以外で最も古い未完成の項目を 1 件ずつ消して空きを作る。
  消せる項目が無いとき、つまり 1 つの datagram だけで上限に届くときは、その断片を捨てます。
  新しい断片を拒む方式は採らない。
  その方式では、損失で断片の欠けた少数の datagram が表を期限の 30 秒占め、その間は全ルールの断片化された UDP が完成しなくなるためです。
  1 つの datagram の断片が続けて届けば、表が満杯でも完成します。
  同じ datagram の断片の間に表を 1 周させる数の断片が挟まると、その datagram は完成しません
<a id="断片の検査"></a>
- 断片の検査:ヘッダーの checksum、長さ、flag、option の形を検査し、重なる断片と矛盾する断片はその datagram ごと捨てます。
  後続の断片は copy bit の立った option だけを持てる。
  完成した datagram のヘッダーには最初の断片のヘッダーを使い、どれかの断片が CE なら ECN を CE にします
<a id="断片に対する-icmp"></a>
- 断片に対する ICMP:期限を過ぎた項目は、最初の断片を持ち、宛先がこの Device のアドレスであるときだけ、gVisor の `OnReassemblyTimeout` に渡して Time Exceeded を送る。
  追い出した項目には送らない。
  期限を過ぎて消去を待つ間(最大 1 秒)に追い出された項目にも送らない。
  option の不正な断片には、wgft が組み立てた Parameter Problem を返します。
  送らない条件、引用の長さ、送る速さの制限は、同じ入力を与えたときの固定版の gVisor の結果を試験の期待値にしています。
  既知の差は 3 つあります。
  1 つ目として、後続の断片が copy bit の無い option を持つと、wgft はその断片を捨て、option の型の byte を指す Parameter Problem を返します。
  pointer の値は IPv4 ヘッダーの先頭からの offset で、この場合は 20 です。
  固定版の gVisor は、正しい Timestamp か Record Route の option を持つ後続の断片を受け入れて組み立てた(試験で同じ入力を与えて確かめた)。
  2 つ目として、Timestamp の flags が不正な後続の断片には、固定版の gVisor は flags の byte を指す pointer 23 を返し、wgft は 1 つ目と同じ pointer 20 を返します。
  3 つ目として、最初の断片が copy bit の無い option を、長さは正しく中身が不正な形で持つとき、固定版の gVisor はその断片に直ちに Parameter Problem を返して捨てます。
  wgft は option の中身を検査せずにその断片を保持します。
  datagram が完成すると、gVisor が組み立てた datagram を検査し、それを引用して同じ pointer の Parameter Problem を返します。
  完成しなければ、期限の Time Exceeded になります。
  どちらの場合も datagram は届かない。
  wgft はこの 3 つの差を試験で固定し、gVisor の option の検査の手順を写さない。
  断片を ICMP を送らずに黙って捨てる方式にはしません
<a id="tun-の-write-の誤り"></a>
- TUN の `Write` の誤り:`Write` はバッチの中の 1 件を処理できなくても残りを処理し、受け取った件数と最初の誤りを返します。
  断片を捨てたこと、後述の UDP の受信の会計が datagram を捨てたこと、後述の MSS の下限で segment を捨てたことは、誤りとして返さない。
  wireguard-go は `Write` の誤りをバッチごとに回数を絞らずログへ出すので、断片や UDP の入力でログが埋まらないようにするためです。
  誤りを返すのは、閉じた後の `Write` と IPv4 でない packet だけです
<a id="ipv4-の-total-length"></a>
- IPv4 の Total Length:TUN の `Write` は、IPv4 のヘッダーの Total Length より後ろの byte を切り捨ててから扱う。
  固定版の wireguard-go は `Write` に渡す前に同じ切り捨てを行うが、wgft はその挙動に頼らない。
  gVisor は Total Length より後ろの byte を読まず、後述の UDP の受信の会計は gVisor に渡す長さで予約するので、2 つの長さを wgft の側で一致させるためです
<a id="icmp-の誤りの入口"></a>
- ICMP の誤りの入口:TUN の `Write` は、完成した IPv4 の datagram のうち ICMP の誤り(Destination Unreachable、Source Quench、Redirect、Time Exceeded、Parameter Problem)を、外側の送信元が引用された datagram の宛先と一致するときだけ netstack に渡す。
  断片で届いた誤りは再組み立ての後に確かめる。
  引用の宛先を読めない短い誤りも捨てます。
  `vpsd` のユーザー空間モードでは全エージェントのピアが 1 つの Device を共有し、wireguard-go が確かめるのは、外側の送信元が送ってきたピアの AllowedIPs(そのエージェントのトンネルのアドレス 1 つ)に入ることだけです。
  固定版の gVisor は、外側の送信元と引用の宛先の一致も、引用された TCP のシーケンス番号も確かめない。
  この確認が無ければ、あるエージェントは、`vpsd` と別のエージェントの間のフローを引用した Port Unreachable でそのフローの UDP のセッションを閉じさせ、Fragmentation Needed でそのフローの TCP の segment を縮められる。
  トンネルの中に途中のルータは無いので、正当な誤りを出すのは引用された datagram の宛先、すなわち相手のエージェントのトンネルのアドレスです。
  カーネルモードのエージェントが転送した先の自宅の LAN で生まれた誤りは、エージェントのホストの conntrack が、引用の宛先と外側の送信元の両方をエージェントのトンネルのアドレスに書き換えてから wgft0 へ送るので、この確認を通る。
  ラボで、LAN のホストが返した Port Unreachable がこの形で wgft0 に出ることと、`vpsd` の中継がその誤りを受けてセッションを閉じることを確かめた。
  エージェントのホスト自身が転送の途中で出す Fragmentation Needed が同じ形になるかは未確認です。
<a id="fragmentation-needed-の-mtu-の下限"></a>
- Fragmentation Needed の MTU の下限:TUN の `Write` は、next-hop MTU が 552 より小さい Fragmentation Needed を、送信元によらず捨てます。
  固定版の gVisor は下限を持たず、68 を受けると、その TCP の接続の segment の payload を 1 byte まで縮める。
  552 は Linux の既定の `min_pmtu`(`net.ipv4.route.min_pmtu`)で、カーネルモードの `vpsd` のホストが PMTU を下げる下限と同じ値です。
  IPv4 の最小の再組み立ての大きさの 576 は採らない。
  Linux が受け入れる 552 から 575 の値まで捨てる理由が無いためです。
  値は設定項目にしません。
  LAN の MTU が 552 以上であれば、この下限は誤りを捨てないので、PMTU の発見は今までどおり働く。
  宛先のホスト自身のインタフェースの MTU が 552 より小さい場合は、そのホストが SYN-ACK で示す MSS が `vpsd` の segment を抑えるので、この誤りに頼らない。
  552 より小さいのが途中の区間だけの場合は、`vpsd` の側の PMTU を下げられないので、大きな segment は届かない([7b.7 節](../kernel-agent/limits.md#7b7-未確認の点)の、LAN の側の小さい MTU の区間と同じ場合である)。
  Linux は `min_pmtu` より小さい MTU を受けると、誤りを捨てずに PMTU を 552 に固定し、以後は DF を立てずに送るので、途中のルータの断片化で届く。
  wgft は誤りを捨てるので、この点で Linux と異なる。
  この下限の経路での 1 segment の中身の下限は、後述の[TCP の MSS の下限](#tcp-の-mss-の下限)の項に書きます
<a id="捨てた-icmp-の誤り"></a>
- 捨てた ICMP の誤り:ICMP を返さず、ログにも出さない。
  gVisor が自分で捨てる誤りと同じ扱いです。
  Device は IPv4 だけを扱い、IPv6 の packet は `Write` の誤りになるので、ICMPv6 の誤りに当たる確認は持ちません。
  エージェントの Device にも同じ確認が効く。
  エージェントに packet を送れるピアは `vpsd` だけで、`vpsd` の netstack が出す誤りの送信元は `vpsd` のトンネルのアドレスなので、エージェントの側で正当な誤りを捨てることはありません
<a id="tcp-の-mss-の下限"></a>
- TCP の MSS の下限:TUN の `Write` は、完成した IPv4 の datagram のうち SYN の立った TCP の segment(SYN と SYN-ACK)を、MSS の option の値が 536 より小さいときに捨てます。
  固定版の gVisor は、送った segment を確認されるまで 1 つずつ管理の構造ごと持ち、その構造は 1 つで約 0.62 KiB(`tcp.SegOverheadSize`)です。
  相手の MSS は 48 まで受け入れ、segment の中身の上限は MSS から option の枠の最大の 40 byte を引いた値です。
  wgft は SACK を有効にしているので、相手が SYN で timestamp と SACK を示すと、中身の上限は 8 byte まで下がります。
  同じ送り残しの byte で、segment の数は後述の下限の 496 byte のときの約 62 倍、MTU 1420 のときの約 170 倍になります。
  エージェントの netstack は待ち受けるので SYN を受け、`vpsd` の netstack はエージェントへ dial するので SYN-ACK を受けます。
  カーネルモードの `vpsd` の後ろのユーザー空間のエージェントでは、SYN の MSS を選ぶのは `vpsd` の DNAT を通る公開側の利用者であり、WireGuard の鍵の持ち主を信頼しても防げないので、どちらの向きにも同じ検査を掛けます。
  MSS は、固定版の gVisor が SYN と SYN-ACK の option を読むのと同じ `header.ParseSynOptions` で読み、gVisor が使う値を検査します。
  MSS の option が無い segment、MSS の値が 0 の segment、MSS の値を読む前に読めない形の option で gVisor が読み終える segment は、gVisor が既定の 536 を使うので通します。
  48 より小さい値は gVisor が 48 に上げるので捨てます。
  断片で届いた SYN は再組み立ての後に確かめる。
  IPv4 か TCP のヘッダーの壊れた packet は検査せずに netstack に渡し、gVisor が捨てます。
  TCP の checksum は確かめない。
  checksum の誤った segment は、この検査で捨てても gVisor が捨てても netstack の状態を変えないためです。
  捨てた segment には ICMP も RST も返しません。
  捨てた数を Device ごとに数え、1 分に 1 回まで、それまでの数と最後の送信元をログに出します。
  536 は MSS の option が無いときの既定値(RFC 1122)で、`WGFT_MTU` の下限 576 の netstack が示す MSS でもあるので、wgft の netstack どうしの接続は捨てません。
  値は設定項目にしません。
  MSS が 536 より小さい相手とは接続できません。
  segment の中身の上限は、gVisor が送り残しを segment に分ける大きさ(`MaxPayloadSize`)です。
  これを相手の入力で下げる経路は、SYN の MSS と、前述の Fragmentation Needed の 2 つです。
  MSS の経路では、下限の 536 から option の枠の 40 byte を引くので、上限は 496 byte 以上です。
  Fragmentation Needed の経路では、gVisor は next-hop MTU の 552 から IPv4 のヘッダーの 20 byte、TCP のヘッダーの 20 byte、option の枠の 40 byte を引くので、上限は 472 byte 以上です。
  このため、送り残しを分ける大きさは 472 byte を下回りません。
  これより小さい segment も送られます。
  確認を待つ segment が無いとき、gVisor は相手の受信の窓の大きさで分けるので、窓が 1 byte なら 1 byte の segment を送ります。
  ただし、そのとき確認を待つ segment は 1 つだけです。
  小さな書き込みの数は、送信のキューの[書き込みの数の上限](tcp-buffers.md#書き込みの数の上限)が抑えます

[ユーザー空間の仕様](README.md)
