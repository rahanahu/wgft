# v2 の試験の道具

この文書は、Rust に移る wgstack を確かめる試験の道具の設計を定めます。
対象は、適合の台本をデータにする言語、台本を流す 2 つの runner、Rust の DUT を別のプロセスとして叩く標準入出力の口、凍結した Go の wgstack の記録との照合、qbench、fuzz、関門です。
1 節の台本の言語と 2 節の Go の runner は実装済みで、ほかの節は未実装です。
実装は 8 節の順に積んだ PR で行い、各 PR がこの文書の該当する節を実装に合わせて直します。

Rust の wgstack そのもの (sans-IO の API、crate の分け方、bit の一致の条件、実装の PR の順) は、wgstack の Rust 版の設計 (`docs/design/v2/wgstack-rs.md`) が決めます。
試験の道具の細部はこの文書が持ち、wgstack の Rust 版の設計はこの文書を参照します。
2 つの文書の名前と段の対応と、この文書が違う形を選んだ点は 10 節にまとめます。

## 前提

試験の置き場所は[v2 の設計](README.md#テスト)の規則に従います。

- 実ネットワークの面から製品を外から叩く試験は Go に残します。
  `internal/tcpharness` の台本、`linuxdut` と `gvisordut`、qbench、ラボの一式がこれに当たります
- 内部に触れる試験は Rust に移します。
  fuzz、不変条件と上界の確かめ、単体の試験がこれに当たります
- Go と Rust を C ABI で結ぶ試験の継ぎ目は作りません。
  Go の道具が Rust の engine を叩くときは、別のプロセスとして標準入出力で話します

台本は 2 つに分けます。

- 直線の台本:packet を入れ、時計を進め、出た packet を照らす流れが分岐の少ない一本の列になる台本です。
  データ (台本の言語のファイル) にし、Go の runner と Rust の runner の両方で流します
- 反応と測定の台本:相手の模型が DUT の送った量に応じて ACK と SACK を返し続ける台本、決まった segment を落とす台本、窓を埋めるまで送り続ける台本、実際の遅れを測って上限を広げる台本です。
  Go のまま残し、Rust の engine には 3 節の口を通して手で進める時計ごと流します

この分け方の理由は、反応する台本まで言語で書くと組み込みの振る舞いが増え、2 つの runner で同じ意味を保つ費用が台本を Go のまま残す費用を超えるためです。

移行の間、Rust の wgstack は凍結した Go の wgstack と同じ入力に同じ packet を返します。
4 節の記録がこれを確かめます。
試験は速く保ちます。
Rust の wgstack の核は sans-IO で、台本と記録と fuzz は偽の時計で全速で流れます。

## 全体の形

| 部品 | 置き場所 | 言語 | 役割 |
| --- | --- | --- | --- |
| 台本のファイル | `internal/tcpharness/scripts/*.scn` | 言語に依らない | 直線の台本 |
| 構文の fixture | `internal/tcpharness/scripts/testdata/` | 言語に依らない | 2 つの構文解析器が同じ木を作ることの確かめ |
| Go の runner | `internal/tcpharness` (`script*.go`) | Go | 台本を `tcpharness.Scenario` にし、今の DUT のすべてに流す |
| DUT の口の符号 | `internal/dutproto` | Go | 3 節の frame の符号化と復号。モジュールの中の何も import しない |
| Go の DUT の server | `internal/wgstack` の試験のバイナリの `dutserve` の形 | Go | 凍結した Go の wgstack を 3 節の口で出す |
| 別のプロセスの DUT | `internal/tcpharness/rustdut` | Go | 3 節の口の client。`tcpharness.ClockedDUT` を実装する。相手は Rust の `wgstack-dut` か、確かめのための `dutserve` |
| Rust の道具の crate | `crates/wgft-tcpharness` | Rust | 口の符号、packet の組み立て、台本の構文解析器と runner、記録の照合 |
| Rust の DUT | `crates/wgft-wgstack-dut` | Rust | Rust の wgstack を `ClockedDut` に合わせる adapter と、3 節の口の server のバイナリ `wgstack-dut` |
| 記録 | `testdata/wgstack-rec/` | 言語に依らない | 凍結した Go の wgstack の入出力 |
| wgstack の fuzz | `crates/wgft-wgstack/fuzz/` | Rust | cargo-fuzz の target |

`crates/wgft-tcpharness` と `crates/wgft-wgstack-dut` は試験の道具で、製品のバイナリに入りません。
どちらも `publish = false` で、リリースのワークフローはこれらを作りません。
Rust の wgstack の核の crate は `crates/wgft-wgstack` です。
試験の道具はこの crate の公開の API だけを使い、核の crate の `[dependencies]` と `[dev-dependencies]` に試験の道具を足しません。

## 1. 台本の言語

### ファイルと置き場所

台本は 1 つのファイルに 1 つで、拡張子は `.scn`、ファイル名は台本の名前です (`fin-passive-close.scn`)。
置き場所は `internal/tcpharness/scripts/` です。
Go の runner は `go:embed` でファイルを取り込み、Rust の runner は `CARGO_MANIFEST_DIR` からの相対のパスで読みます。

形式は行を単位にした文の列です。
JSON や YAML ではなく専用の形にした理由は次のとおりです。

- 台本には RFC の根拠を書く注釈が要ります。JSON は注釈を持てません
- 照合の述語と観察の文字列には、どの形式を選んでも小さな式の言語が要ります。式を文字列として JSON に埋めると、構文解析器を 2 つ書く費用は減らず、読みにくさだけが増えます
- Rust の YAML の crate は保守の状態が定まっていません。依存を増やさずに済む形にします

2 つの構文解析器のずれは、構文の fixture で捉えます。
`scripts/testdata/parse/` の各 `.scn` に、正規化した構文木を JSON で書いた `.ast.json` を対にして置きます。
`scripts/*.scn` の本物の台本の構文木は `scripts/testdata/ast/` に置きます。
Go の試験は `-update` で対を作り直せ、Go と Rust の試験は両方とも、自分の構文解析器の出力が `.ast.json` と同じ JSON の値になることを確かめます。
JSON は差分を小さく保つため、空白の無い 1 行で書きます。
整数は 10 進の文字列で書き、64 bit の値も JSON の数の精度に頼りません。
空の `else` は構文木に出さず、`else` の無い `if` と同じ形になります。

名前が `err-` で始まる fixture は誤りの例で、`.ast.json` は誤りの行と種類 (kind) だけを持ちます。
英語の文は 2 つの構文解析器で違ってよく、比べません。
種類は `layout` (tab と閉じない文字列)、`header`、`block` (`if`、`else`、`end`、`stop`)、`template`、`syntax`、`unknown-statement`、`unknown-function`、`arity`、`named-argument`、`bind`、`unbound`、`unreachable` です。
Go の構文解析器は fuzz の対象 (`FuzzParseScript`) を持ち、台本と fixture を種にして、panic せず、誤りがどれも種類を持つことを確かめます。

### 文の形

```text
file    = header { stmt }
header  = "scenario" NAME NL "refs:" TEXT NL { "linux:" PATH "=" VALUE NL }
stmt    = simple NL [ attrs ]
        | "if" expr NL { stmt } [ "else" NL { stmt } ] "end" NL
simple  = VERB { arg } [ "->" IDENT ]
arg     = expr | IDENT "=" expr
attrs   = INDENT "what:" TEMPLATE NL INDENT "got:" TEMPLATE NL
```

- 注釈:文字列の literal の外の `#` から行末までです。`what:` と `got:` の template の中でも同じです
- 文:1 行に 1 つで、先頭の語が動詞です。結果を持つ文は `-> 名前` で結果を名前に結びます
- 引数:引数は空白で区切ります。1 つの引数は括弧の外に空白を持たない式で、空白を含む式は括弧で包みます (`match=(is_fin(s) && s.seq == f.seq)`)。`名前=` は名前つきの引数で、`=` の前後に空白を置きません。`let`、`set`、`if`、`check`、`require`、`measure` は、行の残りを 1 つの式として読みます
- 字下げ:意味を持つのは `check` と `require` の `what:` と `got:` の行だけです。`if` の中は `end` で閉じます
- 分岐:`if`、`else`、`end` だけを持ち、繰り返しを持ちません。台本は `stop` で正常に終われます
- 名前:台本全体で 1 つの名前空間です。同じ名前に結び直せ、`if` の中で結んだ名前は後でも見えます
- 静的な検査:構文解析の後、流す前に次を確かめます。2 つの構文解析器は同じ規則と同じ種類で検査し、構文の fixture に誤りの例を含めます
  - 文の位置の引数の数、受け付ける名前つきの引数、`->` を付けられること。`->` は結果を持つ文 (`listen`、`send_fresh_ack`、`await`、`quiet`、`quiet_since`、`collect`、`write`、`read`、`recv` と、T1b で足す IP の文) だけに付けられます
  - 呼ぶ関数があること、その引数の数、名前つきの引数を `with` だけが取ること
  - 結び:どの名前もその読み取りに至るすべての経路で先に結ばれていること。`if` で片方の枝だけが結ぶ名前を後で読む台本は誤りです。`stop` で終わる枝はすべての名前を結んだものと数えます
- 名前つきの引数:同じ名前を 2 度渡すこと、`=` の後に空白を置くこと (`match= x`) は誤りです
- 文字列:`what:` と `got:` の text の中の `"` は対で書きます。閉じない `"` は、行の終わりまでを文字列とみなす誤りを避けるため、`layout` の誤りです
- `linux:` の行:`tcpharness.Scenario.Linux` と同じく、参照の Linux がこの台本だけに使う sysctl です。`=` の前後の空白は捨てます。今移す台本は使いません

### 式と型

式の演算子は、優先の低い順に `||`、`&&`、`!`、比較 (`==`、`!=`、`<`、`<=`、`>`、`>=`)、`|`、`+` と `-`、`*` と `/` と `%`、単項の `-`、後置 (`.欄`、`[i]`、`[a:b]`、関数の呼び出し) です。
`&&` と `||` は左から評価し、結果が決まった時点で右を評価しません。

| 型 | 書き方と値 | 規則 |
| --- | --- | --- |
| int | `1380`、`0xd1` | 符号つき 64 bit。割り算は 0 に向けて切り捨てる |
| bool | `true`、`false` | |
| bytes | `"bye"`、`pattern(n, salt)`、`x[a:b]` | 文字列の literal は UTF-8 の bytes。`\\`、`\"`、`\n`、`\t`、`\xHH` を持つ |
| duration | `500ms`、`1s`、`35s` | int との掛け算と割り算、duration どうしの足し算、引き算、比較 |
| time | `now`、捕捉の `.at` | time どうしの引き算は duration |
| seq | 捕捉の `.seq` と `.ack`、相手の `snd_nxt` など | 32 bit の剰余の数。seq と int の足し算と引き算は seq、seq どうしの引き算は差を int32 にした int、順序の比較は差の int32 の符号で決める (RFC 9293 3.4) |
| addr と addrport | `addr("10.200.0.9")`、`PEER_ADDR`、`DUT_ADDR`、`with_port(ap, n)` | |
| segment と ipv4 | 捕捉、組み立ての関数 | 欄は後述 |
| list | 関数の結果 | `[i]`、`len` |
| none | `none` | 無い option。none の欄を読むと台本の誤り |

型の合わない演算は台本の誤りです。
Go の panic に当たる場面は、どちらの runner でも台本の誤りとして、ファイルと行を付けてその台本を落とします。
Go の runner は、台本が呼んだ補助の関数の中の panic も同じく扱います。
数を表す引数 (`pattern` の長さ、`read` の byte 数) は 0 以上です。

### 相手の模型

相手 (`peer`) は試験の側の 1 つの接続の端で、`tcpharness.Peer` と同じ状態を持ちます。

| 欄 | 意味 | 動く時 |
| --- | --- | --- |
| `local`、`remote` | 4 つ組 | 作った時 |
| `iss`、`snd_nxt` | 試験の側の ISN と次の番号 | `send_data` と `send_fin` が進める。`set` で書ける |
| `dut_iss`、`rcv_nxt` | DUT の ISN と、試験の側が次に待つ DUT の番号 | 握手で決まる。`set` で書ける |
| `ws`、`dut_ws`、`sack`、`ts` | 交渉の結果 | 握手と `adopt` |
| `window` | 試験の側が送る窓の欄 | `set` で書ける |
| `ts_recent`、`syn_ts_val` | DUT の最新の TSval と、SYN の TSval | 受けた segment ごと |
| `dut_ack`、`dut_window` | DUT の最新の ACK と、scale した窓 | 受けた segment ごと |
| `synack`、`conn` | `connect` の SYN-ACK と、受け入れた接続 | `connect` |

timestamp の時計は 1 ms に 1 つ進み、起点は台本の乱数で決まります。
送る segment は、交渉した時だけ timestamp の option を持ちます。
これらの規則は `harness.go` の `Peer` の規則そのものです。
Go の runner は `Peer` をそのまま使い、Rust の runner は同じ規則を写します。

### 捕捉

待つ文は、見た segment を名前に結びます。
捕捉は `ok` (見えたか) と `at` (見えた時刻) と segment の欄を持ちます。
見えなかった捕捉の欄は、Go の空の `Segment` と同じく 0 と空と none です。

segment の欄は `src`、`dst`、`seq`、`ack`、`flags`、`window`、`len` (payload の byte 数)、`seq_len` (SYN と FIN を含む番号の幅)、`payload`、`mss`、`ws` (無ければ -1)、`sack_permitted`、`sack` (`block(l, r)` の list)、`ts` (`val` と `ecr`、無ければ none)、`df`、`ttl`、`id` です。
ipv4 の欄は `src`、`dst`、`proto`、`id`、`df`、`ttl`、`payload` です。

### 照合の述語

待つ文の `match=` は、`s` を候補の segment (か packet) に結んで評価する bool の式です。
`await` は相手の 4 つ組の segment だけを候補にし、ほかの flow の segment と TCP でない packet を読み飛ばしてログに残します (`Peer.Next` の規則)。
`collect` はすべての flow の segment を集めます。

よく使う述語は関数として持ちます。
`is_data(s)`、`is_pure_ack(s)`、`is_fin(s)`、`is_rst(s)`、`is_synack(s)`、`acks(s, seq)`、`has(s, SYN|ACK)` です。
旗の定数は `SYN`、`FIN`、`RST`、`PSH`、`ACK` で、`|` で組み合わせます。

list を受ける関数は、2 つ目の引数を要素ごとに `s` に結んで評価します。
`filter(l, 述語)`、`first(l, 述語)` (無ければ見えなかった捕捉)、`any(l, 述語)`、`count(l)`、`max_of(l, 式)`、`sum_of(l, 式)` です。

述語の中の `s` は、外で `s` という名前を結んでいても、その述語の中では候補を指します。
述語が読む外の名前と相手の欄は、文を始めた時の値に固定します。
待つ間に `Peer.Next` が `dut_ack`、`dut_window`、`ts_recent` を更新しても、述語の中の値は変わりません。
今の Go の台本の述語は、`acks(p.SndNxt)` のように作った時の値を取るか、待つ間に変わらない欄 (`RcvNxt` など) だけを読むので、この規則で意味は変わりません。

### 時刻の確かめ

同じファイルを、実時間で動く Linux と gVisor と、手で進める時計で動く wgstack に流します。
このため、台本は時刻を 3 つの形でだけ確かめます。

- 順序:文の並びが順序です。後の待ちは前の待ちが終わってから始まります
- 上限:待つ文の時間は上限で、RFC の上限か、それより広い値を書きます。例は遅延 ACK の 500 ms です
- 下限:捕捉の `at` の差を比べる `check` で書きます。RFC が下限を決める所だけに置き、例は SYN-ACK の再送の 900 ms です

タイマーの正確な値は確かめず、`measure` でログに出します。
規格が直ちに返す segment は `prompt` を上限にします。
`prompt` は、手で進める時計では 0、実時間では 100 ms です (`H.Prompt`)。
実時間だけで要る余裕は、`clocked(a, b)` (手で進める時計なら a、実時間なら b) で書きます。
負荷で試験の過程が止まった台本を流し直す規則と、tail loss probe の上限を広げる規則は Go の harness の規則のままで、台本には書きません。

### 確かめと観察の文字列

`check ID 式` は `H.Check` に当たり、`require ID 式` は `H.Require` に当たります。
`what:` は期待の説明、`got:` は観察の文字列で、どちらも `{式}` を埋め込む template です。
観察の文字列は、期待した差の一覧の `Observed` と照らされるので、今の Go の台本と 1 文字も違わない文字列を作ります。
そのために、今の Go の台本が使う説明の関数を、同じ名前と同じ出力で持ちます。

| 関数 | Go の関数 | 出力 |
| --- | --- | --- |
| `seg_desc(a)` | `segDesc` | `FIN\|ACK len=0`、`no segment` |
| `ack_desc(a, base)`、`sack_desc(a, base)` | `ackDesc`、`sackDesc` | `ACK of base+3000` など |
| `synack_desc(p, a)` | `synackString` | |
| `err_kind(e)`、`err_string(e)` | `errKind`、`errString` | `nil`、`timeout`、`EOF`、`closed`、`reset`、`error` と、誤りの文 |
| `yes_no(c, a, b)` | `yesNo` | |
| `echo_desc`、`reply_desc`、`pmtu_desc` | `echoDesc`、`replyDesc`、`pmtuDesc` | |
| `quote(b)` | `%q` | Go の `strconv.Quote` と同じ |
| `seconds_text(d, k)` | `%.kf` の秒 | 小数 k 桁、Go と同じ丸め |

`seg_desc`、`ack_desc`、`sack_desc`、`synack_desc` は、最後の省略できる引数で捕捉の `ok` の代わりの bool を受けます。
Go の台本が `segDesc(s, !quiet)` のように別の条件を渡す所に使います。
`yes_no` と `clocked` は選んだ側の引数だけを評価します。
template は int と seq を 10 進で、bool を `true` か `false` で、bytes をそのまま書きます。
ほかの型を埋め込むと台本の誤りです。
`text(x)` は同じ規則で bytes にし、bytes は `+` でつなげます。
ほかに `seq(i)`、`int(q)`、`ms(d)`、`ts_val(P)` (相手の timestamp の時計の今の値)、`has(s, 旗)` を持ちます。

`measure 名前 式` は `MEASURE` の行を出し、何も確かめません。
`log template` はログに 1 行を書きます。

### 文の一覧

| 文 | 意味 | Go の対応 |
| --- | --- | --- |
| `listen L port [-> err]` | 待ち受け。台本の終わりに閉じる。`-> err` があれば失敗を誤りの値で返し、無ければ台本を止める | `H.Listen`、`DUT.Listen` |
| `connect P L port [syn=] [window=] [syn_window=] [ack_delay=]` | 握手と受け入れ。`P.synack` と `P.conn` を持つ | `H.ConnectWith` |
| `handshake P port [...]` | 受け入れない握手 | `H.Handshake` |
| `accept C L` | 2 s の内の受け入れ | `H.Accept` |
| `peer P port`、`reincarnate Q P iss= [ts_base=]`、`adopt P syn synack` | 相手を作る、同じ 4 つ組で作り直す、交渉を取り込む | `NewPeer`、`Reincarnate`、`adopt` |
| `send P 式`、`send_data P b`、`send_ack P`、`send_fin P [b]`、`send_fresh_ack P -> ts` | segment を入れる | `Peer` の同名の操作 |
| `inject_ip 式` (T1b) | IPv4 の packet か list を入れる | `H.InjectIP` |
| `set P.欄 = 式`、`let 名前 = 式` | 相手の欄を書く、名前に値を結ぶ | |
| `await P d [match=] -> a` | 上限 d の内に述語に合う segment を待つ | `Peer.Await`、`Peer.Next` |
| `quiet P d -> q`、`quiet_since P d ts f C -> q` | d の間に何も出ないこと | `Peer.Quiet`、`Peer.QuietSince` |
| `collect d -> l`、`collect_flow P d -> l` (T1b) | d の間に出た segment の list | `H.Collect`、`Peer.Next` の繰り返し |
| `await_ip d match= -> pkt` (T1b) | IPv4 の packet を待つ | `H.Packet` |
| `write C b [-> w]`、`read C n d -> r` | 書く、n byte を d の内に読む。`-> w` の無い `write` は誤りで台本を止める | `Conn.Write`、`readFull` |
| `close X`、`close_write C`、`abort C` | 閉じる。`close_write` は誤りで台本を止める | |
| `listen_udp U port`、`udp_read U d -> r`、`udp_write U b to= -> w` (T1b) | UDP | `H.ListenUDP`、`readDatagram`、`WriteTo` |
| `check`、`require`、`measure`、`log`、`stop` | 確かめと記録と終わり | |

(T1b) と印した文と関数は、T1b が残りの台本を移す時に足します。

結果を持つ文が `->` で結ぶ値の欄は次のとおりです。
待つ文の捕捉は、segment か packet の欄に加えて `ok` と `at` (返った時の時計) を持ちます。

| 文 | 欄 |
| --- | --- |
| `await`、`quiet` の `seg` | 捕捉 (`ok`、`at`、segment の欄) |
| `listen` | 誤り。成功なら none |
| `send_fresh_ack` | 送った TSval (seq) |
| `quiet` | `quiet`、`seg` |
| `quiet_since` | `quiet`、`stale`、`timed_out`、`seg`、`desc` (Go の台本と同じ観察の文字列) |
| `collect` | 捕捉の list |
| `write` | `n`、`err` |
| `read` | `data`、`err` |
| `recv` | `data`、`dups`、`max_len` |

組み込みの手順は、今の Go の台本の補助の関数を 1 つの文にしたものです。
Go の runner はその関数を呼び、Rust の runner は手で進める時計の場合の意味だけを写します。
Rust の runner は手で進める時計の DUT しか流さないので、実時間の補正 (`QuietSince` の待ちや `atOnce` の 5 ms) は写しません。

| 文 | Go の関数 |
| --- | --- |
| `alive ID P C` | `alive` |
| `delivered ID C` | `delivered` (DUT が `Deliverer` を持つ場合だけ確かめる) |
| `flight P C n salt -> f`、`burst P -> b` (T1b) | `flight`、`burst` |
| `recv P n d -> r` | `receive` (最大の segment の長さも返す) |
| `at_once l -> l2` (T1b) | `atOnce` |
| `echo ipid ident seq b [cuts=] -> m` (T1b) | `echo` |
| `await_datagram d match= -> r` (T1b) | `udpLarge` の断片を集める繰り返し |

packet を作る関数は `segment(P, 旗, seq[, payload])` (`Peer.Segment`)、`syn(P, opts)` (ISS の SYN で窓は 65535)、`raw(P, 旗, seq)` (ほかの欄が Go の空の `Segment` と同じ segment。空の `Options` は窓の scale 0 を持つ)、`ts(val, ecr)`、`with(x, 欄=式, ...)` (欄を差し替えた写し)、`opts_standard()`、`opts_nosack()`、`opts_none()`、(T1b) `udp(src, dst, id, b)`、`icmp_echo(...)`、`fragments(pkt, cuts...)`、`fragments_every(pkt, n)`、`frag(pkt, from, to)`、`frag_needed(from, 元の packet, mtu)`、`corrupt(pkt, off, xor)`、`set_bytes(pkt, off, b)`、`wire(x)` (packet の bytes)、`wire_len(x)` です。

### 例

`fin-passive-close` の台本 (`internal/tcpharness/scripts/fin-passive-close.scn`) を写します。
台本の中の注釈と文言は、今の Go の台本と同じく英語で書きます。

```text
# The testbench closes first: the DUT acknowledges the FIN, the application reads the data and
# then EOF, may still send in CLOSE-WAIT, and its Close sends a FIN after that data.
scenario fin-passive-close
refs: RFC 9293 3.6 and 3.10.7.4 CLOSE-WAIT and LAST-ACK

listen l 8011
connect p l 8011 syn=opts_standard()
send_fin p "bye"
# RFC 9293 does not ask for an immediate ACK here, and Linux delays it by its delayed-ACK timer,
# about 40 ms; RFC 1122 4.2.3.2 bounds a delayed ACK at 500 ms.
await p 500ms match=acks(s, p.snd_nxt) -> a
check fin.acked a.ok
  what: the DUT acknowledges the data and the FIN within the 500 ms delayed-ACK bound
  got: {seg_desc(a)}
read p.conn 3 1s -> r
check data-before-fin r.err == none && r.data == "bye"
  what: the application reads the data that came with the FIN
  got: {quote(r.data)}, error {err_kind(r.err)}
read p.conn 1 1s -> r
check eof err_kind(r.err) == "EOF"
  what: the next read returns EOF
  got: error {err_kind(r.err)}

write p.conn "after" -> w
await p 1s match=is_data(s) -> d
check close-wait.sends w.err == none && d.ok && d.seq == p.rcv_nxt && d.payload == "after"
  what: the application can still send in CLOSE-WAIT
  got: write error {err_kind(w.err)}; {seg_desc(d)}
if d.ok
  set p.rcv_nxt = d.seq + d.len
  send_ack p
end
close p.conn
await p 1s match=is_fin(s) -> f
check last-ack.fin f.ok && f.seq == p.rcv_nxt
  what: Close sends a FIN after the data
  got: {seg_desc(f)}
let ack_ts = seq(0)
if f.ok
  set p.rcv_nxt = f.seq + f.seq_len
  send_fresh_ack p -> ack_ts
end
# A FIN resent before the ACK got there, as a tail loss probe on a loaded machine, is passed over;
# anything sent once the DUT had the ACK fails the check.
quiet_since p 500ms ack_ts f p.conn -> q
check closed.quiet q.quiet
  what: nothing follows the ACK of the DUT's FIN
  got: {q.desc}
measure resent-before-the-ack q.stale
delivered delivered p.conn
```

### 言語を育てない規則

台本の言語は、直線の台本を書ける最小の形に留めます。

- 繰り返し、関数の定義、並行を持ちません。アプリケーションの読み書きを別の goroutine で回す台本は Go に残します
- 組み込みの手順と関数を足すのは、Go の補助の関数に対応があり、データに依る繰り返しが要らず、Go と Rust の runner で同じ意味を書ける場合だけです。足す時はこの文書の表を同じ PR で直します
- 反応する相手 (送った量に応じて ACK と SACK を返し続ける受け手、決まった segment を落とす規則、送り直しの見張り) は組み込みにしません

### 移す台本と Go に残す台本

| 台本 | 扱い | 理由 |
| --- | --- | --- |
| `handshake-options`、`handshake-bare`、`handshake-mss-floor` | 移す | |
| `ooo-sack`、`rfc5961`、`paws` | 移す | |
| `fin-passive-close`、`half-close`、`close-unread-rst`、`active-close-fin-ack`、`timewait-reuse`、`listener-close` | 移す | |
| `early-ack`、`ack-unsent`、`synrcvd-syn`、`close-ooo-only`、`fin-zero-window` | 移す | |
| `icmp-echo` と `icmp-frag-needed` の族 | 移す | |
| `udp-datagram`、`udp-large`、`udp-reassembly`、`udp-reassembly-timeout`、`udp-closed-port` | 移す | |
| `rfc2525-initial-window`、`rfc2525-rto-slow-start`、`rfc2525-synack-rto`、`rfc2525-close-fin`、`rfc2525-data-after-close` | 移す | |
| `retransmit-rto`、`rto-after-burst` | Go に残す | 再送の間隔の列を数え、その数で確かめが変わる |
| `newreno-recovery`、`sack-*`、`limited-transmit`、`limited-transmit-rack` | Go に残す | 受け手の模型と送り直しの見張りが DUT に応じて答え続ける |
| `rack-reorder`、`tlp-tail-loss`、`thin-stream-loss`、`chained-recovery`、`reorder-wait-recovery` | Go に残す | 同上。`tlp-tail-loss` は実際の遅れで上限を広げる |
| `window-scale`、`zero-window-probe`、`rfc2525-window-deflation`、`rfc2525-stretch-ack` | Go に残す | 窓に応じて送る量を変える繰り返しか、probe の数を数える繰り返しを持つ |
| `rcv-overflow-*`、`rcv-window-pacing*` | Go に残す | 窓を埋めるまで送り続け、別の goroutine で読む |
| `CongestionScenarios` (CUBIC と HyStart++) | Go に残す | 往復ごとに窓の模型と比べる |

移した台本は、`tcpharness.Scenarios` の表の同じ位置に残ります。
表の項目は Go の関数の代わりに台本のファイルを指し、名前、`Refs`、`Linux` は台本の header から取ります。
このため、`Run`、期待した差の一覧、`gvisordut` の故障を入れた試験、`linuxdut` のラボでの実行は、表を使う形のまま変わりません。
構文の誤りがある台本は、その名前の台本が誤りを報告して落ちる項目になり、ほかの台本と package の import を止めません。

移す PR は、台本ごとに Go の関数と台本を同じ DUT と同じ種で流し、確かめの ID、結果、観察の文字列の列が一致することを確かめます。
移した Go の関数は、直線の台本をすべて移し終えるまで `tcpharness.LegacyScenarios` に残し、照らしの試験 (`TestScriptsMatchGoFunctions`) が毎回並べて流します。
T1b が最後の台本を移した後に、Go の関数と照らしの試験を消します。

- `wgstackdut`:手で進める時計で、種 1 から 5。`RecordTrace` が返すログの行 (送った segment、見た segment、待ちとその上限、確かめ、`MEASURE`、記録した失敗) を、行ごとの DUT の時刻を付けて 1 行ずつ比べます
- `gvisordut`:実時間で、種 1 と 2。segment の行は gVisor の乱数で変わるので、確かめの行と `MEASURE` の名前だけを比べます (`CheckLines`)。食い違った組は 3 回まで流し直します
- `linuxdut`:ラボの使い捨ての VM で、`gvisordut` と同じ比べ方です。2 つの実行は 1 つの network namespace を共有するので、台本の側と流し直しには別の種を使います。同じ種だと、同じ 4 つ組が前の実行の TIME-WAIT に当たり、2 つの実行が同じように落ちます。T1b が照らしの試験を消すまで、`-test.run` を付けずに流す `linuxdut` のラボの試験は、適合の試験に加えて照らしの試験も流します

どの DUT でも、Go の関数の実行が通らなかった組は一致の証拠にしません。
2 つの実行が同じように落ちれば行は一致しますが、DUT の状態の誤りを見ているだけかもしれないためです。
通らなかった実行には、確かめの失敗のほか、確かめの外の `Fatalf` (listen、write、`CloseWrite`、注入の失敗、台本の誤り、MTU を超える packet) も含めます。
`CheckLines` も記録した失敗をすべて残します。

`wgstackdut` の時刻つきのログが捉えるものと捉えないものを、台本を 1 か所ずつ変える試験で確かめました。
`Peer.Await`、`Peer.Next`、`Peer.Quiet`、`Peer.QuietSince` は待ちの上限をログに書くので、上限を変えると、待ちが上限まで続かない場合も食い違いが出ます。

| 台本の変更 | 結果 |
| --- | --- |
| 何も来ない `quiet` の上限を短くする | 捉えた |
| segment が早く来る `await` の上限を広げる | 捉えた (上限のログの行) |
| 文を 1 つ消す (`send_ack`) | 捉えた |
| 同じ segment に合う範囲で述語を弱める (`acks(s, p.snd_nxt)` を `has(s, ACK)` に) | 見逃した |
| 通る実行で結果の変わらない範囲で確かめの条件を弱める | 見逃した |

述語と条件の弱まりは、通る DUT の上では同じ動きになるので、ログでは捉えられません。
これらはレビューで台本を Go の関数と読み比べて確かめます。

## 2. runner

### Go の runner

Go の runner は `internal/tcpharness` の中に置き、台本の文を `H` と `Peer` の操作と今の補助の関数の呼び出しに写します。
`H` の内部 (`adopt`、`recorder`、`QuietSince` の定数) を使うので、別の package にしません。
DUT は今の `tcpharness.DUT` と `ClockedDUT` のままで、どの DUT にも同じ台本が流れます。

- `linuxdut`:ラボの VM の network namespace の TUN と Linux のソケット、実時間
- `gvisordut`:製品から外れた後も比べる相手として残す gVisor、実時間
- `wgstackdut`:凍結した Go の wgstack、手で進める時計
- `rustdut`:3 節の口で別のプロセスの DUT を叩く。Rust の wgstack はこれで流れる

`gvisordut` は今 TUN を通さずに gVisor を同じプロセスで動かしています。
gVisor を TUN に出す形には変えません。
gVisor は Go で、DUT の境目は TUN でなくても黒箱として同じ意味を持つためです。

### Rust の runner

Rust の runner は `crates/wgft-tcpharness` の lib にあり、DUT を次の trait で受けます。

```rust
pub trait ClockedDut {
    fn now(&self) -> Duration; // DUT を作ってからの時間
    fn advance(&mut self, d: Duration);
    fn inject(&mut self, batch: &[&[u8]]) -> Result<(), DutError>;
    fn poll(&mut self) -> Option<Vec<u8>>;
    fn listen(&mut self, port: u16) -> Result<Handle, DutError>;
    fn accept(&mut self, l: Handle) -> Op<Accepted>;
    fn read(&mut self, c: Handle, max: usize) -> Op<Vec<u8>>;
    fn write(&mut self, c: Handle, b: &[u8]) -> Op<usize>;
    // close、close_write、abort、delivered、UDP の操作が続く
}
```

`Op` は「結果」「待つ必要がある (would block)」「EOF」「reset」「closed」「その他の誤り」を区別します。
操作はすべて待たずに戻ります。
実装は 2 つです。
`crates/wgft-wgstack-dut` の adapter が Rust の wgstack を同じプロセスで包み、`crates/wgft-tcpharness` の `ProcessDut` が 3 節の口で別のプロセスを叩きます。
adapter は `inject` を同じ時刻の `handle_packet` の列に、`advance` を新しい時刻での 1 回の `handle_timeout` に、`poll` を `poll_transmit` に写します。
1 回の `handle_timeout` は、Go の `ManualClock.Advance` の後の 1 回の `Tick` と同じく、新しい時刻までに期限の来たタイマーをすべて動かします。
`poll_event` の知らせは adapter が読み捨て、操作の結果だけを runner に返します。
台本を Rust の wgstack に流す試験は `crates/wgft-wgstack-dut/tests/scenarios.rs` に置きます。

偽の時計の規則は Go の harness と同じです。
待つ文は `poll` で packet を引き取り、無ければ時計を 1 ms 進めます。
時計を次に起きる時刻まで飛ばす近道は取りません。
同じプロセスの中の 1 回の呼び出しは軽く、30 秒の待ちも 3 万回の呼び出しで済むためです (推定、未測定)。
近道を取らなければ、2 つの runner は DUT への呼び出しの列まで一致し、次節の確かめが使えます。

読み書きが待つ必要を返した時、Rust の runner は待たずに timeout として扱います。
Rust の runner は 1 つの流れで動き、待っている間に DUT の状態を変える者がいないためです。
Go の harness も手で進める時計の DUT では読み書きの間に時計を進めないので、結果は同じです。

台本の乱数は Go と同じ値にします。
台本の種は `ScenarioSeed` (実行の種と、台本の名前の FNV-1a の xor) で、相手のポート、ISN、timestamp の起点は Go の `math/rand/v2` の PCG から `Uint32` と `IntN` で取ります。
Rust の runner はこの PCG と `Uint32` と `IntN` を写し、Go の試験が書き出した値の列 (`scripts/testdata/rng.json`) と照らします。
種は Go と同じ環境変数 `WGFT_TEST_TCPHARNESS_SEED` で固定でき、固定しなければ乱数で選んでログに出します。

確かめの結果は Go と同じ形の行 (`PASS`、`FAIL`、`KNOWN DIFFERENCE`、`CHANGED DIFFERENCE`、`UNEXPECTED PASS`、`MEASURE`) で出します。
Rust の wgstack の engine の名前は `wgstack-rs` です。
その期待した差の一覧は、Go の map でなく `internal/tcpharness/rustdut/known-wgstack-rs.json` に置き、Go の `rustdut` と Rust の runner が同じファイルを読みます。
一覧は凍結した Go の wgstack の一覧の写しから始め、行を足せるのは今と同じく試験の担当と所有者だけです。
台本ごとに 1 つの試験として `cargo nextest` に見せるため、試験の入口は `harness = false` にして、試験の一覧を動的に作る crate (候補は libtest-mimic) を使います。

### 2 つの runner の一致の確かめ

2 つの runner の意味のずれは、DUT への呼び出しの列で捉えます。
台本の言語の台本を、同じ DUT と同じ種と手で進める時計で 2 つの runner が流すと、3 節の口の要求と応答の列 (transcript) が byte の単位で一致することを求めます。

- Go の runner の transcript は、`rustdut` が pipe に書いた要求と読んだ応答です
- Rust の runner の transcript は、`ClockedDut` の呼び出しを同じ符号で書き出す包みが作ります

transcript の一致を求めるのは、台本の言語の台本だけです。
Go に残す台本のうち別の goroutine で読み書きする台本 (受信の溢れ、窓の開き方など) は、goroutine の進み方で要求の順が変わるので、確かめの ID と結果と観察の文字列の一致だけを求めます。
それらの台本は Rust の runner では流れないので、比べる相手は同じ台本を `wgstackdut` で流した結果と、`rustdut` で凍結した Go の wgstack に流した結果です。

Rust の wgstack ができる前は、DUT に `dutserve` (3 節。凍結した Go の wgstack) を使い、Rust の runner は `ProcessDut` でそれを叩きます。
これで、Rust の runner の意味を Rust の wgstack を待たずに確かめられます。
Rust の wgstack ができた後は、`wgstack-dut` のバイナリを両方の runner が叩きます。

実時間の待ちで呼び出しの数が変わらないように、`rustdut` は送り直さない規則を持ちます。
問い合わせの要求は、前の同じ問い合わせの後に状態を変える要求を送っていなければ、送り直さずに前の応答を使います。
答えが変わりえない問い合わせを送り直さないので、transcript は壁時計の待ちに依りません。
要求の分け方は次の表のとおりで、この表が規則の正本です。

| 分け方 | 要求 | 扱い |
| --- | --- | --- |
| 状態を変える要求 | `INJECT`、`ADVANCE`、`POLL`、`TCP_LISTEN`、`UDP_LISTEN`、`CLOSE`、`CLOSE_WRITE`、`ABORT`、`CLOSE_FOR_DELIVERY`、`BOOST_POLICY`、`EVENTS`、`UDP_SEND`、`PING_OPEN`、`PING_SEND`、`PING_CLOSE`。結果を返した `ACCEPT`、`READ`、`WRITE`、`UDP_RECV`、`PING_RECV` | 送るたびに、それまでの問い合わせの応答を使えなくする |
| 問い合わせ | `NOW`、`DELIVERED`、`STATS`、`BOUND`、`HELD`。`WOULD_BLOCK` か 0 byte を返した `ACCEPT`、`READ`、`WRITE`、`UDP_RECV`、`PING_RECV` | 状態を変える要求が間に無ければ送り直さない |

`ACCEPT` などは応答を見るまで分け方が決まりません。
`rustdut` は、`WOULD_BLOCK` の応答を得た要求を問い合わせとして覚え、同じ要求を次に送る前にこの規則を当てます。
DUT の側は、`WOULD_BLOCK` を返す要求で engine の状態を変えません (3 節)。

## 3. DUT の口 (標準入出力)

### プロセス

DUT のプロセスは、1 つの DUT を作り、標準入力で要求を受け、標準出力で応答を返します。
標準エラーはログで、Go の `rustdut` は行ごとに `t.Logf` に渡します。
要求と応答は 1 つずつ同期で、応答は要求の順に 1 つずつ返ります。
DUT は台本の試行ごとに新しいプロセスで作ります。
標準入力が閉じたらプロセスは終わり、口の誤りでは誤りの応答を書いて終了コード 2 で終わります。

時計には 2 つの形があります。

- `--clock fake`:手で進める時計です。台本、記録、fuzz の seed の作成はこの形だけを使います
- `--clock real`:実時間の外側の層で engine を動かします。qbench だけが使い、packet は標準入出力でなく、起動の時に受け渡す `SOCK_SEQPACKET` の socketpair (fd 3) を通ります。Linux だけです

### frame

frame は、長さ (u32、little endian、種類と本体の byte 数)、種類 (u8)、本体の順に並びます。
本体の整数は little endian、byte の列は u32 の長さと中身、文字列は u16 の長さと UTF-8 です。
addrport は IPv4 の 4 byte (ネットワークの順) と u16 のポートです。
時刻と時間は DUT を作ってからの u64 の nanosecond です。
packet は binary なので、JSON でなく binary の frame にします。
人が読む形は、`crates/wgft-tcpharness` と `internal/dutproto` が持つ表示の関数で出します。

### 要求と応答

| 要求 | 本体 | 応答 |
| --- | --- | --- |
| `HELLO` | 口の版、時計の形、アドレス、MTU、64 byte の乱数の種、上限の組、boost の与え方、輻輳の制御の試験の選択 | `HELLO_OK` (engine の名前、口の版) か誤り |
| `INJECT` | packet の list (1 回の書き込みのバッチ) | `OK` か誤り |
| `POLL` | 最大の数 | packet の list (空なら何も無い) |
| `ADVANCE` | 進める時間 | `NOW` |
| `NOW` | なし | `NOW` |
| `TCP_LISTEN`、`UDP_LISTEN` | ポート | `HANDLE` か誤り |
| `ACCEPT` | 待ち受けの handle | `HANDLE` と相手の addrport か `WOULD_BLOCK` |
| `READ` | 接続、最大の byte 数 | `DATA`、`WOULD_BLOCK`、`EOF`、`RESET`、`CLOSED`、誤り |
| `WRITE` | 接続、bytes | `WROTE` (受け取った byte 数。0 なら待つ必要がある) か誤り |
| `CLOSE`、`CLOSE_WRITE`、`ABORT`、`CLOSE_FOR_DELIVERY` | handle | `OK` か誤り |
| `DELIVERED` | 接続 | bool |
| `BOOST_POLICY` | 接続、floor に戻る時の答え | 今 boost を持つか |
| `EVENTS` | なし | boost の変化の list |
| `UDP_RECV` | handle | 送り手と bytes か `WOULD_BLOCK` |
| `UDP_SEND` | handle、宛先、bytes | `OK` か誤り |
| `PING_OPEN`、`PING_SEND`、`PING_RECV`、`PING_CLOSE` | 宛先、handle、bytes | handle、`OK`、返事か `WOULD_BLOCK`、誤り |
| `STATS` | なし | `key=value` の文字列 |
| `BOUND`、`HELD` | なし | 上界の式の値と、今の保持の量の `key=value` の文字列 |
| `RTO_AT` | 接続、時刻 | その時刻に使っていた RTO か不明 (`--clock real` だけ) |
| `CONN_SOCKET` | 接続、Unix ソケットのパス | `OK` (`--clock real` だけ。後述) |

誤りの応答は、種類 (timeout、EOF、closed、reset、broken pipe、その他) と英語の文を持ちます。
`rustdut` は種類を Go の誤りに戻します。
`WOULD_BLOCK` は締め切りを過ぎた時に `Timeout()` が真の誤り、reset は `connection reset` を含む誤り、closed は `net.ErrClosed`、EOF は `io.EOF` です。
今の台本の `errKind` は、この形で同じ文字列を返します。

`POLL` の最大の数は、手で進める時計の台本では 1 にします。
1 つずつ引き取る `ClockedDUT.Poll` と同じ意味を保つためです。
`WOULD_BLOCK` を返す要求は engine の状態を変えません。
DUT の側はこれを守り、2 節の送り直さない規則はこれに頼ります。

`OnBoost` の関数は接続の錠の中で同期に呼ばれ、戻り値が engine の判断を変えます。
Rust の wgstack では、これが hook の `may_return` に当たります。
口をまたいで同期の呼び返しはできないので、`BOOST_POLICY` で答えを先に渡し、`wgstack-dut` の hook がその答えを返し、変化を `EVENTS` で渡します。

frame の種類の番号と本体の並びの正本は、T2a の PR が `internal/dutproto` の Go の定義と、この節に足す付録の表で持ちます。
Rust の符号は同じ表から書き、2 つの符号が同じ bytes を作ることを、Go の試験が書き出した frame の例 (`internal/dutproto/testdata/frames/`) で照らします。

### Go の DUT の adapter (`rustdut`)

`rustdut` は 3 節の client で、`tcpharness.ClockedDUT`、`Listener`、`Conn`、`Deliverer`、`DeliveryCloser`、`Booster` と UDP の `net.PacketConn` を実装します。
今の DUT と同じく `New(addr, mtu)` と `Engine(known)` を持ちます。
`Engine` の `New` は、`wgstackdut` が Go の wgstack に渡す乱数の源 (台本の種から作った鍵の `math/rand/v2` の `ChaCha8`) を同じ形で作り、その先頭の 64 byte を `HELLO` の種にします。
Go の wgstack は作成の時に乱数の源から 64 byte だけを読むので、同じ台本の種なら `wgstackdut`、`dutserve`、Rust の wgstack が同じ 64 byte を受け取ります。
バイナリのパスは環境変数 `WGFT_TEST_WGSTACK_DUT` で受け、無ければ試験を SKIP にします。
このため、`go test ./...` は cargo の無い環境でもそのまま通ります。

待つ操作は `rustdut` が壁時計で待ちます。
`Read` は `READ` を送り、`WOULD_BLOCK` なら 2 節の規則で締め切りまで待ち、締め切りで timeout を返します。
`Write` は受け取られなかった残りを同じ規則で送り直します。
`Accept(ctx)` は `ACCEPT` を同じ規則で送り直します。
これは `wgstackdut` の `Conn` が締め切りを壁時計で測るのと同じ意味です。

### Go の server (`dutserve`)

`dutserve` は、凍結した Go の wgstack を 3 節の口で出す Go の server です。
用途は 3 つです。
4 節の記録を作ること、`rustdut` 自身の確かめ (同じ台本を `wgstackdut` で直接流した結果と、`rustdut` で `dutserve` に流した結果が一致すること)、Rust の runner の確かめです。

`dutserve` は独立したコマンドでなく、`internal/wgstack` の試験のバイナリの 1 つの形です。
`go test -c -o bin/wgstack-dutserve.test ./internal/wgstack` で作り、環境変数 `WGFT_WGSTACK_DUTSERVE=1` を与えて起こすと、`TestMain` が試験を流さずに標準入出力で口を出します。
コードはすべて `internal/wgstack` の `_test.go` にあり、凍結した製品のコードは変えません。

package の中に置く理由は、待たずに戻る操作を正しく作るためです。
Go の wgstack の公開の `Read`、`Write`、`Accept` は待つ操作で、締め切りを過ぎた `Read` と `Write` はデータの有無より先に timeout を返し、`Accept` は締め切りを持ちません。
`dutserve` は、`FuzzCore` と同じ package の中の確かめで、操作が待たずに戻ると分かった時だけ公開の操作を呼び、待つ場合は呼ばずに `WOULD_BLOCK` を返します。

- `ACCEPT`:待ち受けの列に接続がある時だけ `Accept` を呼びます
- `READ`:`readable` が真の時だけ `Read` を呼びます。データ、EOF、誤りのどれでも待たずに戻ります
- `WRITE`:`room` が 0 より大きい時は、その量までを `Write` に渡します。接続が書けない状態 (閉じた後、誤りの後、送信の向きを閉じた後) なら `Write` を呼んで誤りを受け取ります。どちらでもなければ `WOULD_BLOCK` を返します
- `UDP_RECV` と `PING_RECV`:同じ形の受信の列の確かめを `_test.go` に足して使います

`dutserve` は壁時計で待たず、受け入れの goroutine も持たないので、transcript は要求の列だけで決まります。

`dutserve` は Go の wgstack を公開の `New` で作り、既定の上限だけを受け付けます。
既定でない上限の組を持つ `HELLO` は誤りで断ります。
小さな上限の記録 (`FuzzCore` など) は、4 節の `testNet` の記録だけが作ります。
boost の枠の集まりはプロセスで 1 つですが、`dutserve` は DUT ごとに新しいプロセスなので、別の DUT の状態は混ざりません。

### Rust の wgstack に求める口

`wgstack-dut` の adapter は、wgstack の Rust 版の設計の sans-IO の API だけを使います。
使う口は、作成 (アドレス、MTU、上限の組、boost の hook、64 byte の種、輻輳の制御の試験の選択)、`handle_packet`、`handle_timeout`、`poll_transmit`、`poll_timeout`、`poll_event`、TCP と UDP と ping の操作、`stats`、`bound`、`held` です。
上限の組は Go の `limits` の欄に当たる値で、`FuzzCore` が使う小さな上限も渡せる必要があります。
3 節の口と記録は、この API に無い操作を求めません。
API の名前が実装で変わったときは、adapter とこの段落を同じ PR で直します。

4 節の記録と一致させる条件 (種の配分、ChaCha8、SipHash、タイマーの輪の 1 ms の tick、枠と出力の順、`math.Cbrt`) は、wgstack の Rust 版の設計の「bit の一致の条件」が決めます。
試験の道具は種と上限の組を `HELLO` で渡すだけで、これらの条件を持ちません。

## 4. Go の wgstack の記録

### 記録するもの

記録は、凍結した Go の wgstack に対する 3 節の要求と応答の列 (transcript) です。
`HELLO` が乱数の種と上限の組と boost の方針を持つので、記録だけで同じ engine を作り直せます。
比べる応答は、引き取った packet の bytes と順序、アプリケーションの操作の結果、受け入れの結果、時刻です。
`STATS`、`BOUND`、`HELD` の応答は byte の単位で比べません。
Go と Rust で数の内訳と確保の大きさが同じになる理由が無いためです。
これらの要求は記録に残し、照合は Rust の側でも同じ要求を送って、応答の形が正しいことだけを確かめます。

Go の送信のバッチの印の鍵は `crypto/rand` から読みますが、記録には入りません。
`wgstackdut`、`dutserve`、`testNet` はどれも `Config.SendBatch` を与えません。
バッチを使わない Device は台帳を作らず、鍵を読みません。
バッチを使う Device でも、鍵から作る印は packet の後ろの buffer の領域に書き、packet の bytes には出ません。
どちらもコードから読んで確かめました。

記録の元は次のとおりです。

- 適合の台本:Go の台本と台本の言語の台本のすべてを、`rustdut` で `dutserve` に流します。種は関門と同じ 1 から 5 です
- `FuzzCore`:repo の corpus と、fuzzing で増えた入力から選んだもの
- 乱数の stream の試験 (`TestReceiveStreamIntegrity`、`TestSendStreamIntegrity`) と `TestAdversarialSender`:既定の種

後の 3 つは `internal/wgstack` の中の試験で、`ClockedDUT` を通りません。
`internal/wgstack` の試験の補助 (`testNet`) に、環境変数 `WGFT_WGSTACK_RECORD` で記録の先の directory を与えた時だけ働く包みを足し、`inject`、`drain`、`advance` とアプリケーションの操作を同じ要求と応答の列に書きます。
足すのは `_test.go` だけで、凍結した Go の wgstack の製品のコードは変えません。
`internal/dutproto` はモジュールの中の何も import しないので、`internal/wgstack` の試験から import しても循環しません。

### 形式

記録の 1 つのファイルは、gzip で圧縮した次の列です。

1. magic (`WGFTREC1`)
2. meta の長さ (u32) と meta (JSON):元の試験の名前、台本の名前、種、Go の commit、Go の版、`GOARCH`、`GOAMD64`、印 (後述)
3. 要求の frame と応答の frame の組の列

meta は作った日時を持ちません。
gzip の header の更新時刻 (ModTime) は 0 にし、名前の欄は空にします。
同じ入力から同じ bytes のファイルができ、作り直しが git の差分にならないためです。
照合と、2 回作って同じになる確かめは、3 の frame の部分だけを比べます。

記録は linux/amd64 で `GOAMD64=v1` に固定して作ります。
CUBIC の浮動小数点の値は、Go の compiler が積和の命令を使うかで最後の桁が変わりうるので、作る環境を 1 つに決めて meta に書きます。
作る手順は、この組でない環境では記録を作らずに止まります。

置き場所は `testdata/wgstack-rec/<元>/<名前>.rec.gz` です。
Rust で読むのに使う crate は、gzip に flate2、meta に serde と serde_json です。
どれも寛容なライセンスで、`deny.toml` の許可の範囲です。

### 照らし方

Rust の試験 (`crates/wgft-wgstack-dut/tests/replay.rs`) は、記録ごとに、`HELLO` から Rust の wgstack を作り、要求を 1 つずつ `wgstack-dut` の server の処理に同じプロセスで渡し、返った応答の frame を記録の応答と byte の単位で比べます。
最初に食い違った所で止め、その位置、要求、期待した応答、得た応答を、packet を解いた形で出します。
相手の後の packet は Go の wgstack の出力から作られているので、食い違った後の比較には意味が無いためです。

Rust の wgstack は段階を踏んで機能を足すので、記録に印を付けます。
印は記録を作る時に入力から決めます。
相手が示す option (`sack`、`ts`、`ws`)、試験の選択 (輻輳の制御、boost の与え方)、入力の種類 (`udp`、`icmp`、`frag`、`ping`) です。
`replay.rs` は Rust の wgstack が持つと宣言した印の集まりを持ち、印がすべてその中にある記録だけを照らし、残りを数えて報告します。
すべての記録が一致すること (意図した違いの一覧の行を除く) は、agent を wgstack の上で動かす段 (agent の置き換えの設計の「wgstack の上の agent」) のマージの前の条件で、ラボの一式で Rust の agent が Go の agent を置き換えられるとする判定の前の条件でもあります。

Go の不具合を Rust で直したときのように、意図して出力を変えた所は、意図した違いの一覧 (`testdata/wgstack-rec/divergences.json`) に書きます。
1 行は、記録の名前、最初に食い違う frame の位置、Rust の応答、理由です。
照合は、一覧と同じ位置で同じ応答に食い違った記録を、そこで止めて既知の違いとして数えます。
位置か応答が一覧と違えば落とします。
行を足せるのは、期待した差の一覧と同じく試験の担当と所有者だけです。

### 作り方と量

適合の台本の記録は、`rustdut` が `dutserve` との間の frame の列を書き出して作ります。
残りは `WGFT_WGSTACK_RECORD` を付けた `go test ./internal/wgstack` が作ります。
`testNet` の記録は 1 つずつ順に作ります。
Go の wgstack の boost の枠の集まりはプロセスで 1 つなので、同じプロセスで並行に作ると別の Device の状態が混ざるためです。
`dutserve` は DUT ごとに別のプロセスなので、並行に作れます。
同じ Go の commit と種から作った記録が同じ bytes になることを、作る手順が 2 回作って確かめます。

git に入れるのは、圧縮した合計が 5 MiB 以下の集まりです。
適合の台本の記録はすべて入れ、残りは上限に収まる数を選びます。
stream の試験の全部の種 (段階の関門の数) のような大きな集まりは git に入れず、手元の cache に作り、Go の wgstack がある間の段階の関門で使います。
上限の 5 MiB は、記録の大きさを測る前に置いた値です。

### 保つ期間とその後

照合を求めるのは移行の間です。
Go の wgstack を消す PR で、応答を比べる照合の試験を消し、git の記録の要求の列を 6 節の `replay` の seed と回帰の入力に移します。
記録はその後も Rust の回帰の入力として残り、不変条件と panic の無いことを確かめます。
それより後に Rust の wgstack が意図して出力を変えても、記録を作り直す手段はありません。
Go の wgstack が無くなるためです。

## 5. qbench

qbench は、判定の規則と cell の表と基準の値をそのまま使い、Rust の wgstack を新しい engine (`wgstack-rs`) として足します。
engine は `wgstack-dut` のバイナリを `--clock real` で起こします。

- packet:Go の側が socketpair を作り、片方を子のプロセスの fd 3 に渡し、もう片方を `tun.Device` として Rig の Link につなぎます
- アプリケーション:受け入れた接続ごとに、Go の側が Unix ソケットで待ち、`CONN_SOCKET` でそのパスを渡します。子のプロセスは接続して、engine の接続と Unix ソケットの間で byte を中継します。Go の側は通常の `net.Conn` を受け取るので、`runBulk` と `runThin` は変わりません。`Abort` は `ABORT` を送ります
- 統計:`Stats` は `STATS` と子のプロセスの CPU 時間 (`wait4` の rusage) を出し、`RTOAt` は `RTO_AT` を使います

TUN を使わない理由は次のとおりです。
qbench の経路は、client と DUT の間の packet をすべて Go の Link が受け取り、中身で決める損失、並べ替え、途絶を engine の間で同じに入れます。
`linuxdut` が TUN を使うのは、TUN の向こうのカーネルが DUT そのものだからです。
Rust の engine が TUN を開くと、TUN の向こうはカーネルになり、Go の Link は packet の通り道に入れません。
Link を netem に置き換えると、損失の模型が変わり、`testdata/reference.json` の基準を測り直すことになります。
socketpair は TUN と同じく packet の境目を保ち、カーネルの経路を通らないので、Link をそのまま挟めます。
Linux の TUN の上で Rust の engine を動かす確かめは、qbench でなく、ラボで Rust の agent を流す `lab/tcpquality.sh` が受け持ちます。

中継の 1 段は製品の中継と同じ形で、engine の CPU は子のプロセスの分として Go の CPU と分けて測れます。
一方で、Unix ソケットの中継は子のプロセスの CPU に加わり、細い stream の遅れにも 1 段が加わります。
子のプロセスの CPU は engine だけの CPU ではありません。
判定の前に、中継だけを流す形 (engine を通さずに Unix ソケットの間で byte を写す) で、この 1 段の CPU と遅れを測って記録します。

判定は環境変数 `QBENCH_SUBJECT=wgstack-rs` で、判定する engine を Rust の wgstack にします。
移行の間、関門は Go の wgstack も測り、判定せずに並べて出します。
`--clock real` は Rust の wgstack の実時間の外側の層を使うので、その層ができた後に作ります。

## 6. fuzz

| Go の対象 | 移る先 | seed |
| --- | --- | --- |
| `internal/wgstack` の `FuzzCore` | `crates/wgft-wgstack/fuzz/` の `core` (試験の担当) | Go の corpus の bytes をそのまま |
| (無し) | 同じ所の `replay` (試験の担当) | 記録の要求の列 |
| `internal/wgstack` の `FuzzParse` | 同じ所の `parse` (実装の担当) | Go の corpus の bytes をそのまま |
| `FuzzAdversarialSender` | 同じ所の `adversarial_sender` (試験の担当) | u64 の種を 8 byte の little endian に |
| `proto`、`credentials`、`enroll`、`allowtargets`、`policy`、`vpsd` の fuzz | それぞれを移す crate の `fuzz/` | 1 つの引数の対象は bytes をそのまま、複数の引数の対象は対象ごとに決めた並び |

`core` は `FuzzCore` の解釈器 (`op%8` で操作を選び、相手の模型 `peerConn` が packet を作る) を同じ byte の読み方で写します。
同じ読み方なので Go の corpus はそのまま seed になります。
相手の模型は DUT の出力に応じて packet を作るので、Rust の wgstack の出力が Go と同じ間は同じ経路をたどり、違えば別の経路をたどります。
どちらでも seed としては働きます。

`replay` の入力は 3 節の要求の列で、壊れた末尾は捨てて読みます。
`INJECT` の packet には checksum を直すかの印を持たせ、変異で checksum が壊れただけの入力が入口で落ちるのを避けます。
不変条件 (予約が上界以下、表の数と予約の一致、`Close` の後に予約が 0) の確かめは、Rust の wgstack が試験のために出す口を使います。

Go の corpus は `go test fuzz v1` の形式です。
変換の道具 (`tools/fuzzseed`) が 1 行目を読み、値を取り出して cargo-fuzz の corpus の directory に書きます。
seed は `fuzz/corpus/<対象>/` に置き、見つけた落ちる入力は `fuzz/regressions/<対象>/` に置きます。
`regressions` は stable の `cargo nextest` が流す試験も読みます。
nightly の無い CI でも、見つけた入力の回帰を確かめるためです。
cargo-fuzz の crate は `[workspace]` を自分で持ち、ワークスペースの member に入りません。

## 7. 関門と CI

### PR の関門

| 段 | 中身 | 時間の見込み |
| --- | --- | --- |
| Go の試験 | `go test ./...`。台本の構文の fixture、移した台本の表、`rustdut` の SKIP | 今と同じ |
| Rust の試験 (B13) | `cargo nextest`。構文の fixture、乱数の照合、台本を偽の時計で同じプロセスで、記録の照合、fuzz の回帰 | 1 分未満 (推定) |
| 道具の照合 | Go の runner の `rustdut` で `dutserve` と `wgstack-dut` に全部の台本を種 1 から 5 で、Rust の runner との transcript の一致 | 数分 (推定) |
| fuzz の smoke | `parse`、`core`、`adversarial_sender`、`replay` を libFuzzer の `-runs` の回数で流す | 回数は Rust の実行の速さを測ってから、1 段 2 分以内に決める |
| ラボ | `linuxdut` の適合の実行は表を使うので、移した台本も今と同じく流れる | 今と同じ |

道具の照合の段は、CI に新しい job (`harness-rust-go`) として足します。
cargo と Go の両方が要り、`crates/**`、`internal/tcpharness/**`、`internal/dutproto/**`、`internal/wgstack/**` を変えた PR で流します。
この job は Go の試験を流すので、ラボの一式を省ける Rust だけの CI の job には当たりません。
[テストの規範](../../development/testing.md)は Rust の job を `rust-*` の名前で数えてラボの一式を省くので、この job は `rust-` で始めない名前にします。
job を足す PR は、同じ PR で testing.md の B 類の表と振り分けに `harness-rust-go` を足し、この job を変える PR がラボを省けないことを書きます。

ホストの関門 (`scripts/wgstack-gate.sh`) には、Rust の段 (Rust の台本と記録の照合、`rustdut` の適合の種 1 から 5、fuzz の smoke) を足します。
対象の crate やバイナリが無い木では、今の段と同じく SKIP にします。
凍結した Go の wgstack の段は、Go の wgstack を消すまで残します。
別の script にせず今の script に段を足すのは、1 つの表で全部の段の結果と時間を見られ、並列の数の上限を共有できるためです。

台本の検出力は、今の `gvisordut` の故障を入れた試験と同じ考えで、Rust の wgstack に故障を 1 つずつ入れた build で確かめます。
故障は cargo の feature でなく、`RUSTFLAGS="--cfg wgstack_fault=\"名前\""` で選びます。
feature はワークスペースの中で統合され、別の crate の試験の build に故障が漏れうるためです。
故障の名前の一覧は `Cargo.toml` の `[lints.rust]` の `unexpected_cfgs` の `check-cfg` に書き、知らない名前を build の警告 (`-D warnings` の下では誤り) にします。
故障を入れた build は別の target directory に作り、台本の言語の台本と `rustdut` の Go の台本を流して、その故障を捉えるはずの確かめが落ちることを求めます。
故障を核の crate に入れるか adapter の側で作るかは、核の公開の API で作れる故障の範囲を見て、T4 で決めます。

### 段階の関門

段階の関門では、git に入れない大きな記録の集まりを照らし、fuzz を長く流します。
回数と時間は、Rust の実行の速さを測ってから決めます。

## 8. 段階の計画

試験の担当の段は、wgstack の Rust 版の設計の計画の T1 から T4 と同じ区切りにし、それぞれを積んだ PR に分けます。
大きさは試験を含む行数の見込みです。
実装の段の番号 (2 から 8) は wgstack の Rust 版の設計の「積む PR」の番号です。

| 段 | PR | 中身 | 大きさ | 前提 |
| --- | --- | --- | --- | --- |
| | `docs(v2): design the test tooling for the Rust wgstack` | この文書 | 文書だけ | |
| T1a | `test(tcpharness): add the scenario script language and its Go runner` | 構文解析器、解釈器、組み込み、構文の fixture、台本の乱数の値の書き出し、handshake と close の族の台本、Go の関数との一致の確かめ | 約 2,000 行 | この文書 |
| T1b | `test(tcpharness): move the ICMP, UDP and RFC 2525 scenarios to scripts` | 残りの台本と (T1b) の文と関数、3 つの DUT での照らし、移した Go の関数と照らしの試験を消す | 約 +900、-1,300 行 | T1a |
| T2a | `test(tcpharness): add the DUT frames, a Go frame server and rustdut` | `internal/dutproto` と frame の付録、`internal/wgstack` の `dutserve` の形、`rustdut`、`wgstackdut` と `rustdut` で同じ結果になる確かめ | 約 1,500 行 | この文書 |
| T2b | `test(wgstack): record the frozen Go wgstack for replay` | `testNet` の記録の包み、記録の手順、2 回作って同じになる確かめ、git に入れる記録 | 約 600 行と記録 | T2a |
| T3a | `test(wgstack-rs): add the tcpharness crate` | 口の符号、packet の組み立て、台本の乱数の写し、`ProcessDut`、記録の読み込み | 約 1,500 行 | T2a |
| T3b | `test(wgstack-rs): run scenario scripts in Rust` | Rust の構文解析器と runner、`dutserve` に対する transcript の一致、CI の `harness-rust-go` | 約 2,000 行 | T1b、T3a |
| T3c | `test(wgstack-rs): add wgstack-dut and replay the Go recordings` | adapter、`wgstack-dut`、記録の照合と意図した違いの一覧、期待した差の一覧のファイル、関門の段 | 約 1,200 行 | T2b、T3b、実装の 4 |
| T4 | `test(wgstack-rs): fuzz targets and adversarial bounds` | `tools/fuzzseed`、`core`、`adversarial_sender`、`replay`、回帰の試験、敵対的な保持の試験、stream の一致の試験、故障を入れた build | 約 3,000 行。段ごとに分ける | 実装の 3 から。4 から 6 に合わせて足す |
| 8 の試験の側 | `test(wgstack-rs): qbench through wgstack-dut` | `--clock real`、socketpair の `tun.Device`、`wgstack-rs` の engine、判定の切り替え | 約 1,000 行 | 実装の 5 と 7 |

T1 と T2 は Go の側だけで完結するので、この文書の後すぐに並べて始められます。
T3a と T3b は Rust の wgstack を待ちません。
`dutserve` を相手に Rust の runner の意味を確かめられるためです。
Rust の wgstack を相手にするのは T3c からで、実装の 4 の API が固まった後です。
`parse` の fuzz の target は実装の 2 が持ちます。

## 9. 未決の点

- 口の往復の費用:1 往復を数 µs から数十 µs と見込んでいますが、測っていません。`rustdut` で 30 秒の待ちを持つ台本は、1 ms ごとに 2 往復します。遅すぎる場合は、`POLL` が空の時に時計を 1 ms 進めて次の packet を返す要求を足します
- `dutserve` の待たない操作:`FuzzCore` の確かめ (`readable`、`room`、待ち受けの列) が、公開の操作が待たずに戻る条件と一致することはコードから読みましたが、試験で確かめていません。T2a で、確かめが真の時に操作が待たないことを試験にします
- 記録の大きさ:git に入れる上限の 5 MiB は測る前の値です。T2b で測って直します
- 乱数の写し:Go の PCG と `IntN` の写しと、Go の `%q` と `%.0f` の丸めの写しは、Go の試験が書き出した値との照合で確かめます。照合の値の数は T3b で決めます
- 台本の観察の文字列:T1a で移した台本は、3 つの DUT の照らしの試験で Go の関数と同じ観察の文字列になることを確かめました。T1b で移す台本は、T1b の照らしの試験で確かめます
- 実時間の Rust の DUT:`--clock real` の外側の層が製品の層と同じものになるかは、Rust の wgstack の外側の層の設計で決まります
- qbench の Unix ソケットの 1 段:細い stream の遅れの p99 にどれだけ加わるかは未測定です
- fuzz の速さ:cargo-fuzz の 1 秒あたりの実行回数は未測定で、関門の回数はその後に決めます
- 関門の時間:7 節の時間はどれも推定です

## 10. wgstack の Rust 版の設計との対応

wgstack の Rust 版の設計 (`docs/design/v2/wgstack-rs.md`) の「検証」の節は、試験の道具の骨格を提案しています。
この文書はその骨格を引き継ぎ、細部を決めます。

### 合わせたもの

- crate:`wgft-wgstack` (核)、`wgft-wgstack-dut` (バイナリ `wgstack-dut`、配布しない)、`crates/wgft-wgstack/fuzz` の target `parse`、`core`、`adversarial_sender`、`replay`
- Go の adapter:`internal/tcpharness/rustdut` と、バイナリを指す環境変数 `WGFT_TEST_WGSTACK_DUT` (無ければ SKIP)
- engine の名前:`wgstack-rs`。期待した差の一覧は凍結した Go の wgstack の一覧の写しから始める
- frame:長さ (u32 の little endian)、種類 (u8)、中身。命令 1 つに応答 1 つ。同じ frame の列を記録の形式にも使う
- 記録:Go の wgstack を frame で動かす Go の道具で作り、Rust は命令を順に与えて応答を byte の単位で比べ、最初に違った frame で止める。相手の option と試験の選択で分けて段ごとに照らす。意図した違いの一覧を持つ
- `core`:`FuzzCore` の op の読み方と相手の模型を同じ byte の読み方で写し、Go の corpus をそのまま種にする
- 段の区切り:試験の担当の T1 から T4 と、qbench の 8

### 違う形を選んだもの

| 点 | wgstack の Rust 版の設計の提案 | この文書 | 理由 |
| --- | --- | --- | --- |
| 台本の形式 | JSON | 行を単位にした専用の形 (`.scn`) と、2 つの構文解析器の構文の fixture | 台本は RFC の根拠の注釈を要し、JSON は注釈を持てない。照合の述語と観察の文字列にはどちらの形式でも式の言語が要り、JSON に文字列で埋めても構文解析器を 2 つ書く費用は減らない |
| 台本の置き場所 | `testdata/tcpharness/` | `internal/tcpharness/scripts/` | Go の runner は台本を `go:embed` で試験のバイナリに入れる。`linuxdut` の試験はラボの VM で作り置きの試験のバイナリとして流れるので、実行の時に repo のパスを探さずに済む。`go:embed` は package の外の directory を読めない |
| 時刻の範囲の単位 | RTO の回数のような規格の単位 | 今の Go の台本と同じ時間の値 (遅延 ACK の 500 ms など) | 移す時に確かめと観察の文字列を Go の台本と同じに保ち、期待した差の一覧をそのまま使うため |
| Rust の runner の置き場所 | `wgft-wgstack` の試験 | `wgft-tcpharness` の lib と `wgft-wgstack-dut` の試験 | 試験の担当のコードを実装の担当の crate に置かず、核の crate の依存を空に保つ。runner を `ProcessDut` で `dutserve` にも向けられ、Rust の wgstack を待たずに runner の意味を確かめられる |
| runner どうしの照合 | 結果が同じ | 台本の言語の台本は、手で進める時計で要求と応答の列が byte の単位で同じ。goroutine を使う Go の台本は結果が同じ | 結果が同じでも、台本の意味のずれが DUT への呼び出しの違いとして隠れうる。呼び出しの列まで比べると、ずれた最初の文が分かる |
| qbench の口 | `wgstack-dut` の TUN の形と、制御の pipe でのアプリケーションの操作 | socketpair の packet と、Unix ソケットで中継するアプリケーションの byte | TUN の向こうはカーネルになり、qbench の Go の Link を packet の通り道に挟めない (5 節)。中継の形は製品の中継と同じで、`runBulk` と `runThin` を変えずに済む |
| `core` の書き手 | 試験の担当 | 同じ (合わせた) | |

wgstack の Rust 版の設計が「実装の時に決めること」に置いた試験の項目のうち、frame の形式、データの台本の語彙の線引き、関門の組み方、記録の分け方は、この文書の 3 節、1 節、7 節、4 節が決めます。
記録の量の上限は 4 節の仮の値で、T2b で測って決めます。
