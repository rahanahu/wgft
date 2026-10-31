# 接続を張る Linux

この文書は、TCP の接続を張る側(能動の open)としての Linux の挙動を、実装する人が Linux のコードを読まずに作れる形で定めます。
[wgstack の dial の側](wgstack-dial.md)の能動の open は、この文書を参照の挙動として使います。
相手の待ち受けが Linux のときに、接続を張る側から見える挙動も含めます。
wgstack との違いと適合の台本は、決定ではなく選ぶ点と案として[wgstack で選ぶ点](#wgstack-で選ぶ点)と[適合の台本の案](#適合の台本の案)に書きます。

各項目は、ラボの 6.1 と、参照の 7.2 の 2 つの版について書きます。
参照の Linux は、第 2 段階が main に入った直後に Debian 13 の trixie-backports の 7.2 に移ると決まっています([dial の側の決めたこと](wgstack-dial.md#決めたこと))。
7.2 の記述は、ラボを Debian の 7.2 に更新した後にそこで観測して確かめます。
6.1 の観測は、移る前のラボの挙動と、版による違いの記録として残します。
この文書の 6.1 はラボの 6.1.0-53 を指し、mainline の `v6.1` のタグとは「`v6.1` のタグ」と書いて区別します。
6.1 の挙動は主にラボの VM で観測し、観測していない挙動はソースから読んだと書きます。
7.2 の挙動は `v7.2` のタグのソースから読み、Debian の 7.2 ではまだ観測していません。
ホストの Fedora の 7.2.13 で同じ観測を参考に流した値は、「ホストの 7.2」と書きます。
関数の名前は、Linux の挙動を確かめる人のための目印です。

## 参照のカーネル

### 6.1

ラボの VM のカーネルは Debian の 6.1.0-53 で、package の版は 6.1.187-1 です。
基の版は mainline の `v6.1` のタグで、接続を張る側に効く次の修正を Debian の stable の更新で含みます。

- `tcp_metrics: properly set tp->snd_ssthresh in tcp_init_metrics()` と `tcp_metrics: do not create an entry from tcp_init_metrics()`(Debian 6.1.64-1 から):確立の時の ssthresh の扱いが変わります(後述)
- `tcp: Don't drop SYN+ACK for simultaneous connect().`(6.1.112-1 から):同時の open で相手の SYN-ACK を受け入れます(後述)
- `tcp: avoid reusing FIN_WAIT2 when trying to find port in connect() process`(6.1.115-1 から):FIN_WAIT_2 の間の 4 つ組を新しい接続に使い直しません(後述)
- `tcp: fix __tcp_close() to only send RST when required`(6.1.158-1 から):閉じる時に読まれていないデータがあるかの判定から、FIN だけを除きます

VM で確かめるには、`uname -v` で `Debian 6.1.187-1` を読み、`/usr/share/doc/linux-image-$(uname -r)/changelog.gz` を上の件名で探します。
このカーネルの changelog の名前は `changelog.gz` で、`changelog.Debian.gz` はありません。
上の 4 つの版は、この VM の changelog で確かめた値です。

### 7.2

7.2 は、参照の Linux として決まった Debian 13(trixie)の trixie-backports のカーネルの版です。
この文書の 7.2 の挙動は `v7.2` のタグのソースから読み、各変化の最初の版を mainline のタグで示します。
Debian の 7.2.11 の stable の修正は確かめていません。
`v7.2` の後から読んだ時点の mainline までの変化は、[7.2 の後の変化](#72-の後の変化)に書きます。

ホストの Fedora の 7.2.13 は、設定の値がラボと違います。
例えば `tcp_rmem` の上限が 32 MiB なので、SYN の窓の scale が 10 になります。
ホストの 7.2 の観測は、版による違いを確かめる参考に使い、参照の値には使いません。

### sysctl の既定の値

接続を張る側に関わる値は次のとおりです。
新しい network namespace は多くの値をカーネルの既定から取り、`tcp_rmem` などを初めの namespace から写すので、値は観測した namespace の値です。

| sysctl | ラボの 6.1 | ホストの 7.2 | 意味 |
|---|---|---|---|
| `tcp_syn_retries` | 6 | 6 | SYN の再送の回数 |
| `tcp_syn_linear_timeouts` | 無し | 4 | SYN の再送の間隔を倍にしない回数(v6.5 から) |
| `tcp_timestamps` | 1 | 1 | timestamp を使い、offset を乱数にします |
| `tcp_sack`、`tcp_window_scaling` | 1 | 1 | SYN に載せます |
| `tcp_rmem` | 4096 131072 6291456 | 4096 131072 33554432 | 2 つ目が最初の受信のバッファ、3 つ目が窓の scale の基準です |
| `ip_local_port_range` | 32768 60999 | 32768 60999 | 一時ポートの幅 |
| `ip_local_port_step_width` | 無し | 0 | 一時ポートを探す歩幅の乱数化(v7.1 から、0 で無効) |
| `tcp_tw_reuse` | 2 | 2 | TIME_WAIT の 4 つ組の使い直し(2 は loopback だけ) |
| `tcp_tw_reuse_delay` | 無し | 1000 | 使い直しまでの ms(v6.14 から) |
| `tcp_fin_timeout` | 60 | 60 | 閉じたソケットの FIN_WAIT_2 の秒 |
| `tcp_max_tw_buckets` | 8192 | 131072 | TIME_WAIT の数の上限(接続の hash の表の大きさの半分) |
| `tcp_rfc1337` | 0 | 0 | TIME_WAIT で RST を受けると TIME_WAIT を終えます |
| `tcp_ecn` | 2 | 2 | 接続を張る側では ECN を求めません |
| `tcp_no_metrics_save` | 0 | 0 | 閉じた接続の RTT を宛先ごとに覚えます |
| `tcp_min_snd_mss` | 48 | 48 | 送る MSS の下限 |
| `tcp_invalid_ratelimit` | 500 | 500 | 窓の外への重複した ACK と challenge ACK の速さの制限(ms) |
| `tcp_challenge_ack_limit` | 2147483647 | 2147483647 | 全体の challenge ACK の制限(既定は無制限) |

## 観測の方法

観測には、リポジトリに入れない使い捨ての試験を使いました。
試験は `internal/tcpharness/linuxdut` の TUN を新しい user と network の namespace に作り、その namespace の中で Linux のソケットに非同期の `connect` をさせます。
試験の側は待ち受けの役で SYN を受け、作った segment と ICMP を TUN へ入れて、Linux の出す packet と `connect` の結果の errno を記録します。
6.1 は使い捨てのラボの VM で、ホストの 7.2 はホストの user の namespace で流しました。
時刻は試験の側の壁時計で、packet を読む時の遅れを含みます。
個々の記録の要約は、この文書を加えた PR の本文にあります。

6.1 の実行では、Fragmentation Needed の場面がこの宛先の path MTU を 1000 にし、後の場面の SYN の MSS が 960 になりました。
この文書の SYN の値は、その場面より前の値です。

## ISN と timestamp の offset

ISN は、4 つ組の鍵付きの hash に、64 ns ごとに 1 進む時計を足した値です(`secure_tcp_seq`)。
鍵は起動ごとに 1 つで、network namespace によりません。
ISN は一時ポートを選んだ後に求めます。
時計は 1 µs に 15.625 進み、約 274 秒で 1 周します。

- 6.1 の観測:同じ 4 つ組の SYN を 200 ms ずつ空けて 5 回送らせると、ISN は 1 µs あたり約 15.6 ずつ増えました
- ホストの 7.2 の観測:同じ増え方でした

RFC 9293 3.4.1 は時計で動く ISN を求め(MUST-8)、RFC 6528 の方式を勧めます(SHLD-1)。
RFC 6528 の時計は 4 µs ごとに進む時計で、Linux の時計はその 64 倍の細かさです。
Linux は、1 周が MSL の 2 倍より長い範囲で細かい時計を選んでいます。

TIME_WAIT の 4 つ組を使い直す接続は、hash を使わず、前の接続の SND.NXT の 65537 先を ISN にします([TIME_WAIT の 4 つ組の使い直し](#time_wait-の-4-つ組の使い直し))。

timestamp の offset は、`tcp_timestamps=1` のときだけ乱数にし、それ以外では 0 です。
timestamp の時計は 1 ms ごとに進みます。
offset の求め方は版で違います。

- 6.1:アドレスの組の鍵付きの hash です(`secure_tcp_ts_off`)。
  同じ相手への接続の TSval は、ポートが違っても続いた値になります。
  観測では、ポートの違う接続の TSval が 1 ms の時計どおりに続きました
- 7.2:ISN と同じ 4 つ組の hash から求めます(v7.0 の `tcp: secure_seq: add back ports to TS offset`)。
  同じ 4 つ組の接続の TSval は続き、ポートの違う接続の TSval は互いに無関係になります。
  ホストの 7.2 の観測では、ポートの違う接続の TSval がばらばらでした

SYN の TSecr は 0 です。
TIME_WAIT の 4 つ組を使い直す SYN だけは、前の接続の TS.Recent を TSecr に載せます(6.1 とホストの 7.2 で観測)。

## 一時ポートと 4 つ組

### 選び方

一時ポートの幅は既定で 32768 から 60999 で、28232 個です。
RFC 6056 3.2 は 1024 から 65535 の全体を使うことを勧め、Linux の既定はその一部です。

Linux は RFC 6056 3.3.4 の Algorithm 4(double-hash)を変えた形でポートを選びます(`__inet_hash_connect`)。

- 表:65536 個の数の表を起動の後の最初の使用で乱数で埋めます
- 鍵:自分のアドレス、相手のアドレス、相手のポートと、10 秒ごとに変わる値の鍵付きの hash から、表の位置と最初の offset を決めます
- 探し方:offset から、幅の下端と同じ偶奇のポート(既定では偶数)を 2 つ飛びに探し、無ければ反対の偶奇を探します。
  `bind` で選ぶ一時ポートは反対の偶奇を先に探すので、`connect` と `bind` のポートは分かれます
- 進め方:見つけた後、表の値を、試したポートの数と 0 から 7 の乱数の 2 倍の大きい方に 2 を足しただけ進めます

RFC 6056 の Algorithm 4 の例は表の値を 1 ずつ進め、表の長さに 10 を挙げます。
Linux は表を大きくし、偶奇で分け、乱数で進めます。
乱数で進めるのは、続いたポートから鍵を推測されないためです。

観測では、同じ宛先への続いた接続のポートは偶数で、2 から 16 の差で増えました。
相手のポートの違う宛先への接続は、別の位置から始まりました。
6.1 とホストの 7.2 で同じ形でした。

7.2 では次の選択肢が加わり、どちらも既定では働きません。

- `ip_local_port_step_width`(v7.1):0 でない値では、接続ごとに幅と素な歩幅を乱数で選びます(RFC 6056 の Algorithm 5 に近い形)
- ソケットの `IP_LOCAL_PORT_RANGE`(v6.3)で幅を狭めた接続は、偶奇で分けず 1 つずつ探します(v6.8)

### 衝突の確かめ

各ポートで次の順に確かめます。

1. 予約したポート(`ip_local_reserved_ports`)は飛ばします
2. `bind` で使われているポートは飛ばします
3. `connect` だけが使うポートは、接続の表で 4 つ組が重ならなければ使います。
   同じ一時ポートを、宛先の違う接続が分け合えます
4. 4 つ組が TIME_WAIT の接続と重なるときは、使い直しの条件を満たすときだけ使い、満たさなければ次のポートへ進みます
5. 4 つ組が TIME_WAIT 以外の接続(SYN-SENT を含む)と重なるときは、次のポートへ進みます

すべてのポートを確かめて使えなければ、`connect` はその場で EADDRNOTAVAIL を返し、SYN を送りません。

観測では、幅を 2 つのポートにして同じ宛先へ 3 つの接続を張らせると、3 つ目がその場で EADDRNOTAVAIL を返しました。
相手のポートの違う宛先への接続は、使われているポートを分け合いました。
幅を 1 つのポートにして TIME_WAIT を作ると、同じ宛先への接続は EADDRNOTAVAIL を返し、相手のポートの違う宛先への接続は同じポートを使いました。
6.1 とホストの 7.2 で同じでした。

### TIME_WAIT の 4 つ組の使い直し

既定の `tcp_tw_reuse=2` は、自分か相手のアドレスが loopback の接続だけで使い直しを許します。
トンネルのアドレスの接続では、TIME_WAIT の 4 つ組を使い直さず、そのポートを飛ばします。

`tcp_tw_reuse=1` では、次の条件をすべて満たす TIME_WAIT の 4 つ組を使い直します(`tcp_twsk_unique`)。

- timestamp:前の接続が timestamp を使っていました
- 状態:TIME_WAIT の状態で、閉じたソケットの FIN_WAIT_2 ではありません。
  FIN_WAIT_2 の除外は、6.1.0-53 では Debian の修正(6.1.115-1)、mainline では v6.12 からです
- 待ち:6.1 では、前の接続が TS.Recent を最後に更新した秒より、今の秒が後であることです。
  待ちは 0 秒から 1 秒の間です。
  7.2 では、TIME_WAIT に入ってから `tcp_tw_reuse_delay`(1000 ms)より長く経ったことです(v6.14 から)

使い直す接続は、ISN を前の接続の SND.NXT の 65537 先にし、前の接続の TS.Recent を引き継ぎます。
相手は、続いた TSval の PAWS で前の接続の segment を捨てられます。
6.1 では TSval の offset がアドレスの組で決まり、7.2 では 4 つ組で決まるので、どちらも同じ 4 つ組の TSval は続きます。

`bind` で決めたポートから張る接続は、待ちと sysctl によらず、前の接続が timestamp を使っていれば使い直します。
この経路はソースからだけ読み、観測していません。

観測(6.1 とホストの 7.2 で同じ):

- `tcp_tw_reuse=2`:TIME_WAIT に入った直後の接続は EADDRNOTAVAIL でした
- `tcp_tw_reuse=1`:0.3 秒の後は EADDRNOTAVAIL で、1.4 秒の後は使い直し、ISN は前の接続の SND.NXT の 65537 先でした
- timestamp の無い前の接続:`tcp_tw_reuse=1` でも 1.5 秒の後に EADDRNOTAVAIL でした

RFC 9293 3.6.1 は TIME-WAIT からの開き直しを、相手の SYN を受ける側の選択(MAY-2)として定めます。
RFC 6191 は、その受ける側の判定に timestamp を使う方法です。
接続を張る側が自分の TIME-WAIT の 4 つ組を使い直すことは RFC に定めが無く、Linux の拡張です。

## SYN

### option と並び

SYN の option は、MSS、SACK-permitted、timestamp、NOP、窓の scale の順で、20 byte です(`tcp_syn_options`、`tcp_options_write`)。
SACK-permitted と timestamp は 1 つの 4 byte の境界の組にまとめ、NOP を挟みません。
timestamp を使わない設定では、MSS、NOP、NOP、SACK-permitted、NOP、窓の scale の順です。
6.1 とホストの 7.2 で、どの SYN もこの並びでした。

- MSS:経路の MTU から 40 を引いた値です。
  TUN の MTU 1420 では 1380 です。
  timestamp の 12 byte は引きません。
  アプリケーションが `TCP_MAXSEG` を与えればその値で抑えます
- 窓の scale:`tcp_rmem` の上限と `rmem_max` の大きい方を、65535 を左に移して覆える最小の移し幅です。
  6 MiB では 7、32 MiB では 10 です。
  0 でも載せます
- SACK-permitted、timestamp:sysctl が 1 なら載せます。
  TSval は今の時計に offset を足した値で、TSecr は 0 です

6.1 では、Fragmentation Needed で path MTU が下がった後の再送の SYN は、下がった path MTU から求めた MSS を載せました(1000 に対して 960)。
同じ宛先への後の接続の SYN も同じ MSS でした。
ホストの 7.2 では、同じ ICMP の後も SYN の MSS が 1380 のままでした。
この違いの原因は確かめていません。

### 窓と IP の欄

SYN の窓の欄は scale を掛けない値です(RFC 7323 2.2)。
値は、最初の受信のバッファ(`tcp_rmem` の 2 つ目の値、128 KiB)を窓に換算した 64 KiB を MSS の倍数に切り下げ、65535 で抑えた値です(`tcp_select_initial_window`)。
MSS 1380 では 64860 で、6.1 とホストの 7.2 の観測もこの値でした。
TS.Recent を引き継いだ接続(TIME_WAIT の 4 つ組の使い直し)は、MSS から timestamp の 12 byte を引いた値で切り下げます。
観測では、MSS 960 で 65412、MSS 1380 で 64296 でした。
経路に `initrwnd` があれば、その MSS 倍で抑えます。
rcv_ssthresh の最初の値はこの窓です。

v6.10 で受信の窓の最初の値の 64 KB の上限が外れましたが(`tcp: remove 64 KByte limit for initial tp->rcv_wnd value`)、SYN の欄は 65535 を超えず、既定の設定では値は変わりません。

IP の欄は、DF を立て、TTL は 64、ID はソケットごとの乱数から始めて 1 ずつ増やします。
`tcp_ecn=2` では ECE と CWR を立てません。
SYN はデータを持ちません。
`tcp_fastopen=1` の接続を張る側の Fast Open は、アプリケーションが求めたときだけ働きます。

## SYN-ACK の option の受け入れ

SYN-ACK の option は、自分の SYN に載せた種類だけを読みます。

- MSS:0 でない値を、送る segment の上限にします。
  アプリケーションの `TCP_MAXSEG` が小さければそちらを使います。
  値 0 と欠落では 536 を使います。
  RFC 9293 3.7.1 は欠落に 536 を求め(MUST-15)、0 の扱いは定めません
- 送る segment の大きさ:path MTU から 40 を引いた値と上の上限の小さい方を、`tcp_min_snd_mss`(48)で下から抑え、timestamp を使う接続ではそこから 12 を引きます
- 窓の scale:SYN-ACK が持てば、両方の向きで scale を使います。
  14 より大きな値は 14 として扱い、速さを制限したログを出します。
  RFC 7323 2.3 の求め(ログを SHOULD、14 の使用を MUST)と同じです。
  SYN-ACK が持たなければ、両方の向きで scale を使わず、自分の窓の上限を 65535 にします
- SACK-permitted:SYN-ACK が持てば SACK を使います
- timestamp:SYN-ACK が持てば、すべての segment に載せます。
  持たなければ使いません。
  TSecr は後述の確かめに掛けます
- 窓:SYN-ACK の窓の欄を、scale を掛けずに送る窓にします。
  窓 0 でも確立し、送るデータは窓の probe を待ちます

観測(6.1 とホストの 7.2 で同じ):

- option の無い SYN-ACK:536 byte の segment を送り、ACK に timestamp を載せず、窓の欄は scale の無い 64860 でした
- MSS 0 と timestamp の SYN-ACK:524 byte(536 から 12 を引いた値)の segment を送りました
- MSS 1 の SYN-ACK:timestamp を使う接続は 36 byte、使わない接続は 48 byte の segment を送りました
- MSS 600、窓の scale 15、SACK-permitted の無い SYN-ACK:588 byte の segment を送り、接続は動きました。
  14 として扱うこととログはソースからだけ読みました
- 窓 0 の SYN-ACK:確立し、書き込んだデータの代わりに、SND.UNA の 1 つ前を番号にした中身の無い probe を約 0.2 秒、0.4 秒、0.8 秒の間隔で送りました

## SYN の再送と打ち切り

### 再送の間隔

最初の RTO は 1 秒です(RFC 6298 2.1)。
再送の SYN は、同じ ISN、同じ option、新しい TSval を持ちます。

- 6.1:再送のたびに RTO を倍にし、120 秒で抑えます。
  再送の回数が `tcp_syn_retries` に届いた後の次の期限で打ち切ります(`tcp_write_timeout`)。
  既定では SYN を 0、1、3、7、15、31、63 秒に送り、127 秒で打ち切ります
- 7.2:最初の `tcp_syn_linear_timeouts`(4)回の再送は RTO を 1 秒のまま保ち、その後に倍にします(v6.5 の `tcp: make the first N SYN RTO backoffs linear`)。
  回数の上限は `tcp_syn_retries` に `tcp_syn_linear_timeouts` を足した 10 です。
  時間の上限は 6.1 と同じく、`tcp_syn_retries` 回を倍にした場合の 127 秒です。
  既定では SYN を 0、1、2、3、4、5、7、11、19、35、67 秒に送り、回数の上限で 131 秒に打ち切ります

観測:

- 6.1:SYN を 0、1.01、3.03、7.22、15.41、31.54、64.05 秒に送り、129.6 秒に ETIMEDOUT でした
- ホストの 7.2:SYN を 11 回、0 から 68.1 秒に送り、134.1 秒に ETIMEDOUT でした

タイマーの遅れが再送ごとに積もるので、打ち切りは計算の値より数秒遅れます。

アプリケーションは、ソケットごとに次の値で打ち切りを早められます。

- `TCP_SYNCNT`:`tcp_syn_retries` の代わりの回数です。
  6.1 では 2 で SYN を 0、1、3 秒に送り、7 秒に打ち切りました(観測は 7.29 秒)。
  7.2 では回数の上限が 2 に 4 を足した 6 になり、時間の上限の 7 秒が先に来ます。
  ホストの 7.2 では SYN を 0 から 5 秒に 1 秒ごとに送り、7.16 秒に打ち切りました
- `TCP_USER_TIMEOUT`:最初の SYN からの時間の上限です。
  RTO を残りの時間で抑えます。
  2500 ms で、6.1 は SYN を 0、1 秒に送り 2.52 秒に打ち切り、ホストの 7.2 は 0、1、2 秒に送り 2.50 秒に打ち切りました

打ち切りの errno は ETIMEDOUT です。
ソケットをアプリケーションが持つ間に ICMP の誤りが届いていた場合は、その誤りの errno になります([SYN-SENT での ICMP の誤り](#syn-sent-での-icmp-の誤り))。

RFC 1122 4.2.3.5 と RFC 9293 3.8.3 は、SYN の R2 を 3 分以上にすることを求めます(MUST-23)。
Linux の既定の約 2 分はこの求めより短く、Linux の RFC からの逸脱です。
同じ節は、アプリケーションがそれより早く諦めることを許します。
7.2 の最初の 4 回の倍にしない再送は、RFC 6298 5.5 の再送のたびに RTO を倍にする求めからの逸脱です。

### アプリケーションの期限

Go の dialer と同じく、非同期の `connect` の後に期限でソケットを閉じると、SYN-SENT の接続は segment を送らずに消え、ポートを返します(`tcp_close`)。
後から届いた SYN-ACK は、どの接続にも当たらない segment として、番号を SEG.ACK にした ACK の無い RST を受けます。
6.1 とホストの 7.2 で観測しました。

`vpsd` の 5 秒の期限では、6.1 は SYN を 0、1、3 秒の 3 回、7.2 は 0 から 4 秒の 5 回送ります。

ブロックする `connect` に `SO_SNDTIMEO` を与えた場合は、期限で EINPROGRESS を返し、接続は裏で続きます。
これはソースからだけ読みました。

### errno の一覧

| 事象 | errno | 時期 | 確かめ |
|---|---|---|---|
| 受け入れられる ACK を持つ RST | ECONNREFUSED | すぐ | 6.1、ホストの 7.2 で観測 |
| 打ち切り | ETIMEDOUT | 上の期限 | 6.1、ホストの 7.2 で観測 |
| 一時ポートが尽きた | EADDRNOTAVAIL | `connect` がすぐ返します | 6.1、ホストの 7.2 で観測 |
| 経路が無い | ENETUNREACH | `connect` がすぐ返します | ソース |
| Destination Unreachable の code 0、6、9、11 | ENETUNREACH | すぐ | code 0 を 6.1、ホストの 7.2 で観測 |
| Destination Unreachable の code 1、10、12、13、14、15 | EHOSTUNREACH | すぐ | code 1 と 13 を観測 |
| Destination Unreachable の code 2 | ENOPROTOOPT | すぐ | 観測 |
| Destination Unreachable の code 3 | ECONNREFUSED | すぐ | 観測 |
| Destination Unreachable の code 5、7、8 | EOPNOTSUPP、EHOSTDOWN、ENONET | すぐ | ソース |
| Time Exceeded | EHOSTUNREACH | すぐ | 観測 |
| Parameter Problem | EPROTO | すぐ | 観測 |
| Source Quench、Fragmentation Needed | 打ち切りません | | 観測 |

## SYN-SENT の入力

SYN-SENT の接続は、届いた segment を次の順に確かめます(`tcp_rcv_synsent_state_process`)。

### ACK を持つ segment

1. ACK の確かめ:SEG.ACK が ISS より後で SND.NXT 以下なら受け入れます。
   SYN がデータを持たないので、受け入れるのは ISS+1 だけです。
   受け入れられない ACK には、segment が RST を持たなければ、番号を SEG.ACK にした ACK の無い RST を返して捨てます(RFC 9293 3.10.7.3)
2. 早い再送:受け入れられない ACK を受けた時にまだ SYN を再送していなければ、SYN の再送を約 2 jiffy の後にします。
   この ACK は RST を伴う segment でも同じです。
   相手が古い接続を持っていると見て、返した RST で古い接続を消させ、すぐに SYN を送り直すためです(RFC 9293 3.5.1 の半開きの接続の回復)。
   この早い再送は再送の 1 回に数えるので、6.1 では次の再送が 2 秒の後になります
3. timestamp の確かめ:segment が 0 でない TSecr を持つとき、TSecr が最初の SYN を送った時から今までの範囲に無ければ、受け入れられない ACK と同じく RST を返して捨てます。
   早い再送はしません。
   TSecr が 0 なら確かめません
4. RST:受け入れられる ACK を持つ RST で接続を閉じ、`connect` は ECONNREFUSED を返します。
   RST の番号は確かめません
5. SYN も RST も持たない segment:捨てます(RFC 9293 3.10.7.3 の 5 番目)
6. SYN-ACK:確立します([ESTABLISHED への移り](#established-への移り))

観測(6.1 とホストの 7.2 で同じ):

- 受け入れられない ACK(ISS+1000):番号を ISS+1000 にした RST を返し、SYN を再送しました。
  再送までは 6.1 で約 8 ms、ホストの 7.2 で約 3 ms でした。
  ラボの Debian のカーネルの jiffy は 4 ms、ホストは 1 ms と見込みます。
  同じ ACK をもう一度受けた時は RST だけを返しました
- ACK を ISS にした SYN-ACK:番号を ISS にした RST を返しました
- ACK を ISS にした RST:何も返さず、SYN を 6.1 で約 11 ms、ホストの 7.2 で約 3 ms の後に再送しました
- ACK を ISS+2 にした RST:何も返さず、何もしませんでした
- 番号を 12345、ACK を ISS+1 にした RST:ECONNREFUSED でした
- 最初の SYN より後の未来の TSecr と、最初の SYN より前の TSecr の SYN-ACK:どちらも番号を ISS+1 にした RST を返し、SYN-SENT に留まりました。
  その後の TSecr 0 の SYN-ACK で確立しました
- ACK を ISS+1 にした中身の無い ACK:何も返しませんでした

timestamp の確かめは RFC 7323 に無く、Linux の拡張です。
RFC 9293 3.10.7.3 は、RFC 5961 の対策を持つ実装が SYN-SENT の RST の番号を RCV.NXT と比べることを勧めます(SHOULD)。
SYN-SENT の RCV.NXT はまだ決まっておらず、RFC 5961 3.2 は SYN-SENT の RST を ACK の確かめだけで受け入れると定めます。
Linux は RFC 5961 3.2 に従い、番号を確かめません。

### ACK を持たない segment

1. RST:捨てます
2. PAWS:TS.Recent を持つ接続(TIME_WAIT の 4 つ組の使い直し)は、TSval が古い segment を捨てます
3. SYN:同時の open として SYN-RECEIVED に移り、同じ ISS の SYN-ACK を送ります(RFC 9293 3.10.7.3 の 4 番目)。
   SYN-ACK は SYN と同じ option の並びで、TSecr に相手の TSval を載せます。
   SYN が持つデータは捨てます
4. それ以外:捨てます

同時の open の SYN-RECEIVED では、相手の ACK で確立します。
6.1.0-53 と 7.2 は、相手が送る SYN-ACK(交差した SYN への応答)でも確立し、その SYN の番号を D-SACK の block にした ACK を返します。
`v6.1` のタグはこの SYN-ACK を challenge ACK で捨て、接続は相手の ACK を待っていました(ソースから)。
mainline では v6.11 の修正で、6.1.0-53 は Debian の 6.1.112-1 からの修正です。
観測では、6.1 とホストの 7.2 で、相手の ACK と相手の SYN-ACK のどちらでも `connect` が成功しました。

RFC 9293 3.10.7.3 は、同時の open の SYN のデータを確立の後の処理のために残すと定めます。
Linux はそのデータを捨てます。

### challenge ACK

SYN-SENT の接続は challenge ACK を送りません。
RFC 5961 の challenge ACK は同期した状態の規則で、SYN-SENT の RST は上の ACK の確かめで扱います。

確立の後に届いた重複の SYN-ACK は、同期した状態の SYN として challenge ACK を受けます(RFC 5961 4.2)。
challenge ACK はソケットごとに `tcp_invalid_ratelimit`(500 ms)に 1 つまでです。
全体の制限は、既定の `tcp_challenge_ack_limit` では働きません(v6.0 から)。
観測(6.1 とホストの 7.2 で同じ):確立の 0.1 秒後の重複の SYN-ACK に ACK を返し、その 0.3 秒後の SYN-ACK には返さず、さらに 0.7 秒後の SYN-ACK には返しました。

### SYN-SENT での ICMP の誤り

ICMP の誤りは、引用された TCP の header の 4 つ組で接続を探し、引用された番号が SND.UNA から SND.NXT の範囲(ISS か ISS+1)にあるときだけ扱います(`tcp_v4_err`)。
外側の送信元は確かめません。

- Destination Unreachable(code 15 以下で、Fragmentation Needed を除く)、Time Exceeded、Parameter Problem:接続をすぐに閉じ、`connect` は[errno の一覧](#errno-の一覧)の errno を返します
- アプリケーションがその時にソケットを持っていた場合:接続を閉じず、誤りを柔らかい誤りとして覚えます。
  後の打ち切りの errno がこの誤りになります
- Fragmentation Needed:path MTU を下げ、接続を閉じません
- Source Quench:捨てます(RFC 6633)
- 範囲の外の番号:捨てます

観測(6.1 とホストの 7.2 で同じ):

- Destination Unreachable の code 0、1、2、3、13、Time Exceeded、Parameter Problem:どれも 1 ms 以内に `connect` が誤りを返しました
- 引用の宛先と違う送信元(経路の途中のルーターに当たるアドレス)からの code 1 と Time Exceeded:同じく誤りを返しました
- 引用の番号を ISS+100 にした code 1、Source Quench、Fragmentation Needed:接続は続き、1 秒後に SYN を再送しました

RFC 1122 4.2.3.9 は、Destination Unreachable の code 0、1、5 と Time Exceeded と Parameter Problem を柔らかい誤りとし、接続を打ち切らないことを求めます(MUST NOT)。
Linux は SYN-SENT と SYN-RECEIVED でこれらを打ち切りの誤りとして扱い、この求めから逸脱します。
RFC 5461 4.1 は、この扱いを Linux が 2.0 から持つ標準でない挙動として記録し、標準は変えていません。
mainline の v6.8 で一部の code の打ち切りをやめる変更が入り、同じ版の中で戻されたので、7.2 の挙動は 6.1 と同じです。

## ESTABLISHED への移り

### 確立の処理

受け入れられる SYN-ACK で、Linux は次の値を決めて ESTABLISHED に移ります(`tcp_finish_connect`、`tcp_init_transfer`)。

- RCV.NXT:SYN-ACK の番号の次です
- 送る窓:SYN-ACK の窓の欄です
- RTT:timestamp を使う接続は、SYN を再送していても TSecr から最初の RTT を測ります。
  timestamp を使わない接続は、SYN を再送していなければ SYN の往復から測り、再送していれば測りません(Karn の規則)。
  観測では、SYN を 2 回再送した timestamp の接続の最初の RTO は 3 秒でなく約 0.4 秒でした(後述の初期の輻輳の窓)
- RTO:RTT を測れなければ 3 秒にします(RFC 6298 5.7)。
  閉じた前の接続の RTT を宛先ごとに覚えている場合(既定の `tcp_no_metrics_save=0`)は、その RTT が SYN の往復より大きければ、最初の RTO をその RTT から求めます。
  同じエージェントへ張り直す接続はこの値を受けます。
  ソースからだけ読みました
- ssthresh:無限にします。
  SYN の再送は ssthresh を下げますが、確立の時に戻します。
  宛先ごとに覚えた ssthresh は、既定の `tcp_no_ssthresh_metrics_save=1` では使いません。
  6.1.0-53 と 7.2 は、確立の時に宛先の記録を新しく作りません(mainline の v6.7 の 2 つの修正、Debian の 6.1.64-1)

### 最初の ACK と 3 つ目の segment

Linux は SYN-ACK を受けるとすぐに ACK を返します。
観測では SYN-ACK から 0.1 ms 以内に、中身の無い ACK を返しました(6.1 とホストの 7.2)。
ACK の窓の欄は最初の窓を scale で割って切り上げた値で、6.1 では 507(64860 を 128 で割った値)でした。

次のどれかのときは、最初の ACK を最大 200 ms 遅らせ、データに載せます。

- アプリケーションが接続を待つ書き込みをしている(ブロックするソケットで `connect` の完了を待つ `write`)
- ソケットに `TCP_DEFER_ACCEPT` がある
- `TCP_QUICKACK` を 0 にして対話の流れの印を付けている

Go の dialer は `connect` の完了を待ってから書くので、どれにも当たりません。
観測では、最初の ACK の後にデータの segment が別に出ました。
遅らせる場合はソースからだけ読みました。

SYN-ACK が持つデータは、Fast Open を使わない接続では捨てます。
最初の ACK は SYN だけを確認し、相手はデータを再送します。
観測(6.1 とホストの 7.2):5 byte のデータを持つ SYN-ACK に SYN だけを確認する ACK を返し、アプリケーションは何も読めず、再送された同じデータは受け入れました。
SYN-ACK の FIN も同じく捨てると読めますが、観測していません。
RFC 9293 3.10.7.3 は SYN-ACK のデータを 6 番目の手順で処理すると定め、Linux の破棄はこの手順からの逸脱です。
データは再送で届くので、相互運用は保たれます。

### 初期の輻輳の窓

初期の cwnd は 10 segment です(RFC 6928)。
経路の `initcwnd` があればその値です。
RFC 6928 の上限の式(10 MSS と 14600 byte と 2 MSS の組み合わせ)を Linux は使わず、MSS によらず 10 segment にします。
MTU 1420 のトンネルでは 10 segment が 14600 byte より小さいので、この違いは現れません。

SYN を再送した接続は、次の両方のときだけ cwnd を 1 にします。

- SYN を 2 回以上再送した
- SYN-ACK の TSecr が最初の SYN の TSval と同じでない(最初の SYN への応答なら、再送は不要だったと分かります)

RFC 5681 3.1 は SYN が失われた後の初期の窓を 1 segment にすることを求め(MUST)、RFC 6928 2 節は 2 回以上の再送の後だけ 1 にすることを勧めます。
Linux は RFC 6928 に従います。

観測(6.1 とホストの 7.2 で同じ):

- SYN を再送しない接続:10 segment を続けて送りました。
  その約 10 ms 後に新しいデータの 11 個目を、約 210 ms 後に最初の segment の再送を送りました。
  前者は TLP の probe、後者は RTO で、どちらも確認を返さない試験の側の振る舞いへの応答です
- SYN を 1 回再送した接続:10 segment を送りました
- SYN を 2 回再送した接続:1 segment を送り、約 0.2 秒後に TLP の probe、約 0.4 秒後に再送を送りました
- SYN を 2 回再送し、SYN-ACK の TSecr が最初の SYN の TSval の接続:10 segment を送りました

## 先に閉じる側と TIME_WAIT

### 閉じ方

- SYN-SENT の `close`:segment を送らずに消えます([アプリケーションの期限](#アプリケーションの期限))
- 読まれていないデータを持つ `close`:FIN の代わりに RST を送ります(RFC 9293 3.6.1 の SHLD-3)。
  6.1.0-53 と mainline の v6.18 からは、残りが FIN だけなら RST を送りません。
  ソースからだけ読みました
- 先に送る FIN:FIN_WAIT_1 から FIN_WAIT_2 を経て、相手の FIN で TIME_WAIT に入ります。
  アプリケーションが閉じたソケットの FIN_WAIT_2 は `tcp_fin_timeout`(60 秒)で終わり、その間は TIME_WAIT と同じ小さな行で持ちます。
  この行は一時ポートの使い直しの対象になりません

### TIME_WAIT の長さと挙動

TIME_WAIT の長さは、RTO や MSL によらず 60 秒です(`tcp_time_wait`)。
観測では、6.1 で 61.2 秒から 62.4 秒の間、ホストの 7.2 で約 61.3 秒の後に、同じ 4 つ組の接続を張れました(1.2 秒ごとに試した値)。
RFC 9293 3.6.1 は TIME-WAIT を MSL の 2 倍とし(MUST-13)、3.4.2 は MSL を 2 分とするので、Linux の 60 秒はこの求めより短く、RFC からの逸脱です。

TIME_WAIT の接続は、届いた segment を次のように扱います(`tcp_timewait_state_process`)。

- 再送された FIN:ACK を返し、期限を 60 秒から数え直します。
  観測では ACK を返しました(6.1 とホストの 7.2)
- 番号が RCV.NXT の RST:`tcp_rfc1337=0` では TIME_WAIT をすぐに終えます。
  観測では、RST の 0.1 秒後に同じ 4 つ組の接続を張れました(6.1 とホストの 7.2)
- PAWS で捨てる segment と窓の外の segment:速さを制限して重複した ACK を返します
- 相手からの新しい SYN:番号が RCV.NXT より後か、TSval が TS.Recent より新しければ、新しい接続として受けます(後述)

RFC 9293 3.10.7.4 は TIME-WAIT の RST で接続を閉じると定め、Linux の既定はこれに従います。
RFC 1337 は、この RST で TIME-WAIT が早く終わる危険を挙げて RST を無視することを勧め、Linux は `tcp_rfc1337=1` でだけこれに従います。

### TIME_WAIT の数の上限

TIME_WAIT の数は `tcp_max_tw_buckets` までです。
既定は接続の hash の表の大きさの半分で、ラボの VM では 8192、ホストでは 131072 です。
上限に届いた後に閉じる接続は TIME_WAIT を持たずに消え、速さを制限したログ(`TCP: time wait bucket table overflow`)を出します。
その接続のポートはすぐに空きます。
ソースからだけ読み、観測していません。

### ポートの入れ替わりの限度

既定の `tcp_tw_reuse=2` では、トンネルのアドレスの TIME_WAIT の 4 つ組を使い直さないので、先に閉じた接続はポートを 60 秒持ちます。
1 つの宛先(エージェントのアドレスとポートの組)に張り続ける接続の速さは、一時ポートの数を 60 秒で割った約 470 本毎秒が上限です。
これを超えると `connect` が EADDRNOTAVAIL を返します。
宛先のアドレスかポートが違えば 4 つ組の空間は別なので、上限は宛先ごとです。

### 相手の待ち受けの TIME_WAIT

相手の Linux が先に閉じて TIME_WAIT を持つ 4 つ組に、接続を張る側が同じ 4 つ組で SYN を送ると、相手は次のように応えます。

- SYN の番号が前の接続の RCV.NXT より後か、TSval が前の接続の TS.Recent より新しい場合:TIME_WAIT を外して新しい接続として受け、ISN を前の接続の SND.NXT の 65537 先にした SYN-ACK を返します。
  RFC 9293 3.6.1 の MAY-2 と RFC 6191 の形です。
  4 つ組が同じなので ISN の hash も同じで、新しい ISN は前の ISN から経った時間の分だけ進みます。
  前の接続が送った量がその時間の時計の進み(1 秒に約 1560 万)より少なければ、番号の条件を満たします
- どちらでもない場合:前の接続の ACK を返します。
  接続を張る Linux はこれを受け入れられない ACK として RST を返し、早い再送で SYN を送り直します。
  RST は相手の TIME_WAIT を終えるので(`tcp_rfc1337=0`)、送り直した SYN で接続できます

6.1 でも 7.2 でも同じ 4 つ組の TSval は続くので、timestamp を使う接続では TSval の条件も満たされます。
この節はソースからだけ読み、相手の Linux の TIME_WAIT は観測していません。

## 6.1 と 7.2 の違い

| 項目 | 6.1.0-53 | 7.2(ソース) | 変わった版 | ホストの 7.2 |
|---|---|---|---|---|
| timestamp の offset | アドレスの組の hash | 4 つ組の hash | v7.0 `tcp: secure_seq: add back ports to TS offset` | 4 つ組ごとに違う値を観測 |
| SYN の再送の間隔 | 1 秒から倍 | 最初の 4 回は 1 秒、その後に倍 | v6.5 `tcp: make the first N SYN RTO backoffs linear` | 観測 |
| 既定の SYN の数と打ち切り | 7 回、127 秒 | 11 回、131 秒 | v6.5 | 11 回、134.1 秒を観測 |
| 5 秒の期限までの SYN | 3 回(3.5 秒の期限で観測) | 5 回 | v6.5 | 3.5 秒の期限で 4 回を観測 |
| `TCP_SYNCNT` の意味 | 再送の回数の上限 | 回数の上限に 4 を足し、時間の上限が先に来ることがあります | v6.5 | 観測 |
| TIME_WAIT の使い直しの待ち(`tcp_tw_reuse=1`) | TS.Recent の更新の秒より後の秒(0 から 1 秒) | TIME_WAIT に入ってから 1000 ms(`tcp_tw_reuse_delay`) | v6.14 `tcp: Measure TIME-WAIT reuse delay with millisecond precision` | 0.3 秒で拒み 1.4 秒で使い直しを観測 |
| 一時ポートの歩幅の乱数化 | 無し | `ip_local_port_step_width`、既定 0 で無効 | v7.1 | 既定の 0 を観測 |
| ソケットごとのポートの幅の偶奇 | 偶奇で分けます | `IP_LOCAL_PORT_RANGE` の接続は分けません | v6.8 | 観測していません |
| Fragmentation Needed の後の SYN の MSS | 下がった path MTU に従う(観測) | ソースからは決めていません | 未確認 | 1380 のまま |

次の項目は `v6.1` のタグと違いますが、ラボの 6.1.0-53 は Debian の修正で 7.2 と同じ挙動です。

| 項目 | `v6.1` のタグ | 6.1.0-53 と 7.2 | mainline の版 | Debian の版 |
|---|---|---|---|---|
| 同時の open の相手の SYN-ACK | challenge ACK で捨てます | 受け入れて確立します | v6.11 | 6.1.112-1 |
| FIN_WAIT_2 の行の使い直し | `tcp_tw_reuse` で使い直します | 使い直しません | v6.12 | 6.1.115-1 |
| 確立の時の宛先の記録 | 新しく作ります | 作りません | v6.7 | 6.1.64-1 |
| 閉じる時の RST の判定 | FIN だけの残りでも RST | FIN だけなら FIN | v6.18 | 6.1.158-1 |

相手の待ち受けの Linux の次の挙動も、6.1 と 7.2 で違います。
接続を張る側から見えるのは、確立の直後の ACK と RST への応答です。

- 待ち受けの SYN-RECEIVED の TSecr:7.2 は、最後の ACK の TSecr が自分の送った SYN-ACK の TSval の範囲に無ければ challenge ACK を返します(v6.15)
- 待ち受けの SYN-RECEIVED の RST:7.2 は、番号が RCV.NXT と一致しない窓の内側の RST に challenge ACK を返します(v7.2)。
  6.1 は握手の途中の行を消します
- 確立した 4 つ組への PAWS に落ちる SYN:v6.4 から challenge ACK を返します
- 窓の右端を越える segment:7.2 は受信の待ち行列が空でなければ捨てます(v6.17)
- まだ送っていない番号を確認する ACK:7.2 は速さを制限した challenge ACK を返します(v7.1)。
  6.1 は黙って捨てます

### 7.2 の後の変化

`v7.2` の後から読んだ時点の mainline までに、接続を張る側に効く次の変化があります。

- v7.3:BPF の sockops が与える最初の受信の窓を、接続を張る側にも使います。
  BPF を使わなければ変わりません
- v7.3:経路の advmss の下限を 88 にします。
  通常の MTU では変わりません
- v7.3:受け入れた古い ACK でも TS.Recent を更新します。
  確立した後の挙動です

## RFC からの逸脱

| 挙動 | RFC | Linux |
|---|---|---|
| ISN の時計 | RFC 6528 は 4 µs の時計 | 64 ns の時計 |
| 一時ポートの幅 | RFC 6056 3.2 は 1024 から 65535 を勧めます | 32768 から 60999 |
| 一時ポートの表 | RFC 6056 の Algorithm 4 の例は表の長さ 10、1 ずつ進めます | 65536 の表、偶奇で分け、乱数で進めます |
| SYN の再送の打ち切り | RFC 1122 4.2.3.5、RFC 9293 3.8.3 は 3 分以上(MUST-23) | 約 127 秒(6.1)、約 131 秒(7.2) |
| SYN の再送の間隔 | RFC 6298 5.5 は再送のたびに倍 | 7.2 は最初の 4 回を倍にしません |
| SYN-SENT の柔らかい ICMP の誤り | RFC 1122 4.2.3.9 は打ち切らない(MUST NOT) | 打ち切ります(RFC 5461 4.1 が記録した挙動) |
| SYN-SENT の RST の番号 | RFC 9293 3.10.7.3 は RCV.NXT との一致を勧めます | 確かめません(RFC 5961 3.2 に従います) |
| SYN-ACK のデータ | RFC 9293 3.10.7.3 は処理を続けます | 捨てます |
| 同時の open の SYN のデータ | RFC 9293 3.10.7.3 は確立の後のために残します | 捨てます |
| SYN を失った後の初期の窓 | RFC 5681 3.1 は 1 segment(MUST) | 2 回以上の再送の後だけ 1(RFC 6928 の勧め) |
| 初期の窓の上限 | RFC 6928 は 14600 byte の式 | MSS によらず 10 segment |
| TIME-WAIT の長さ | RFC 9293 3.6.1 は 2 MSL(4 分) | 60 秒 |
| TIME-WAIT の RST | RFC 1337 は無視を勧めます | 既定で TIME_WAIT を終えます(RFC 9293 3.10.7.4 に従います) |
| 自分の TIME-WAIT の 4 つ組の使い直し | 定め無し | `tcp_tw_reuse` と timestamp の条件で使い直します |
| SYN-SENT の TSecr の確かめ | 定め無し | 範囲の外の TSecr に RST を返します |

## wgstack で選ぶ点

次の点は、wgstack が Linux に倣うか、RFC に倣うか、違いを記録するかを選ぶ点です。
所有者が決めた点(参照の版、同時の open)は決めたことを示し、ほかは決定ではありません。

1. timestamp の offset:[wgstack の設計](wgstack.md#完成に含める機能)はアドレスの組の hash(6.1 の形)を定め、[dial の側の骨格](wgstack-dial.md#受信の機械と共有するもの新しいもの)は 4 つ組の hash と書いています。
   参照の 7.2 は 4 つ組の形なので、目標は 4 つ組の hash です。
   2 つの文書の食い違いは、この文書の外で直す点として残します
2. 一時ポートの選び方:RFC 6056 の Algorithm 4 を Linux と同じく変えるか、Algorithm 1 か 5 の簡単な形にするかを選びます。
   `vpsd` は `bind` で一時ポートを選ばないので、偶奇で分ける理由はありません。
   幅は Linux と同じ 32768 から 60999 か、より広い幅かを選びます
3. TIME_WAIT の 4 つ組の使い直し:Linux の既定に倣って使い直さないか、`tcp_tw_reuse=1` の条件(timestamp、FIN_WAIT_2 の除外、待ち、ISN と TS.Recent の引き継ぎ)で使い直すかを選びます。
   使い直さなければ、1 つの宛先への入れ替わりの限度は約 470 本毎秒です。
   wgstack の TIME_WAIT の表は古い行を追い出すので、追い出された 4 つ組は TIME_WAIT を持たずに使えるようになります
4. SYN の窓:Linux は 64 KB 程度を広告し、wgstack の受け手は floor の 256 KiB を最初から使います。
   SYN の欄は 65535 を超えられないので、SYN の欄の値と窓の scale を Linux に揃えるかを選びます
5. SYN の再送の間隔:参照の 7.2 に倣って最初の 4 回を 1 秒に保つか、RFC 6298 5.5 に倣って倍にするかを選びます。
   5 秒の期限の中の SYN の数は、7.2 の形で 5 回、倍にする形で 3 回です
6. 再送の回数の上限と打ち切りの errno:`vpsd` の期限は 5 秒なので、回数の上限は期限より先に来ません。
   上限を Linux と同じにするか、期限に任せるかを選びます
7. 受け入れられない ACK の後の早い再送:Linux に倣うかを選びます。
   エージェントが古い接続を持つ場合の回復が約 1 秒速くなります
8. SYN-SENT の TSecr の確かめ:Linux の拡張に倣うかを選びます
9. SYN-SENT の ICMP の誤り:Linux に倣ってすぐ打ち切るか、RFC 1122 に倣って柔らかい誤りとして期限の誤りに添えるかを選びます。
   [ICMP の誤りの入口](packet-validation.md#icmp-の誤りの入口)は引用の宛先からの誤りだけを受け入れるので、Linux と違い、経路の途中からの誤りは届きません
10. 同時の open:持たないと決まり、SYN-SENT で ACK の無い SYN を受けた dial は失敗します([dial の側の決めたこと](wgstack-dial.md#決めたこと))。
    6.1.0-53 と 7.2 は相手の SYN-ACK と ACK のどちらでも確立するので、この点は Linux との期待した差になります
11. SYN-ACK のデータ:Linux に倣って捨てるか、RFC 9293 に倣って受け入れるかを選びます。
    捨てても相手の再送で届きます
12. SYN を失った後の初期の窓:[dial の側の骨格](wgstack-dial.md#syn-の再送と期限)は再送した接続を 1 segment にすると書いており、Linux(2 回以上の再送の後だけ 1)と違います。
    骨格のままにするか、Linux と RFC 6928 に倣うかを選びます
13. 確立の後の RTO の種:Linux は閉じた前の接続の RTT を宛先ごとに覚えて最初の RTO に使います。
    wgstack はこの記録を持たないので、違いとして記録するかを選びます
14. TIME_WAIT の長さと RST:wgstack の TIME_WAIT は Linux と同じく 60 秒で、受動の側で確立した規則を共有します。
    先に閉じる側でも同じ規則のままにするかを確かめます

## 適合の台本の案

次の台本は、接続を張る役の適合の試験の案です。
台本の名前は仮で、確かめの範囲は Linux で測った値から試験の書き手が決めます。
DUT の面に `Dial` を加え、Linux の DUT は network namespace の中の非同期の `connect` で実装できることを、この文書の観測で確かめました。
各台本の期待の値は、参照の 7.2 で測った値から決めます。
ラボの更新の前に書く台本は 6.1 で通し、更新の後に 7.2 で測り直します。

- `dial-syn-options`:SYN の option の並び、MSS、窓の scale、窓の欄、ECN の印の無いこと、TSecr 0 を確かめます。
  窓の欄と窓の scale は、選ぶ点 4 の結果で範囲を決めます
- `dial-syn-retransmit`:応えない相手への SYN の再送の時刻と回数、期限で閉じた後に segment を送らないこと、遅れて届いた SYN-ACK への RST の番号を確かめます。
  6.1 と 7.2 で間隔が違うので、期待の値は 7.2 で測ります
- `dial-refused`:ACK の無い RST と受け入れられない ACK の RST を無視し、受け入れられる ACK の RST で拒まれたことを返すことを確かめます
- `dial-bad-ack`:受け入れられない ACK と、ACK を ISS にした SYN-ACK に、番号を SEG.ACK にした RST を返すことを確かめます。
  早い再送の有無は選ぶ点 7 で決めます
- `dial-bad-tsecr`:範囲の外の TSecr の SYN-ACK への応答と、TSecr 0 の SYN-ACK での確立を確かめます
- `dial-icmp`:引用の番号が合う Destination Unreachable の各 code、Time Exceeded、Parameter Problem、Source Quench への応答と時刻、番号の合わない誤りの無視を確かめます。
  経路の途中の送信元からの誤りは、wgstack の入口の規則で Linux と違う結果になるので、期待した差に記録します
- `dial-synack-options`:option の無い SYN-ACK、MSS 0、MSS 1、窓の scale 15、SACK-permitted の無い SYN-ACK の後の segment の大きさと option の使い方を確かめます
- `dial-synack-data`:SYN-ACK のデータの扱いと、再送されたデータの受け入れを確かめます
- `dial-dup-synack`:確立の後の重複の SYN-ACK への challenge ACK と、その速さの制限を確かめます
- `dial-simultaneous`:ACK の無い SYN を受けた dial が失敗し、SYN-ACK を送らないことを確かめます。
  Linux は確立するので、Linux の結果は期待した差に記録します
- `dial-iw`:確立の後の最初の送り出しの segment の数と、SYN を 1 回と 2 回再送した接続の初期の窓を確かめます
- `dial-zero-window`:窓 0 の SYN-ACK の後の確立と窓の probe を確かめます
- `dial-time-wait`:先に閉じた後の TIME_WAIT の長さ、再送された FIN への ACK、RST で終わること、同じ 4 つ組の接続の扱いを確かめます。
  一時ポートの幅を DUT ごとに狭める設定を DUT の面に加えます
- `dial-port-choice`:同じ宛先への続いた接続のポートが重ならず、尽きた時に `Dial` が誤りを返し、宛先の違う接続がポートを分け合えることを確かめます。
  [dial の側の検証](wgstack-dial.md#検証)の多くのピアの台本と合わせます

[wgstack の dial の側](wgstack-dial.md) · [ユーザー空間の仕様](README.md)
