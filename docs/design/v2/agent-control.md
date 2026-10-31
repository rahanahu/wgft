# Rust の agent の制御プレーン (試作)

この文書は、v2 の Rust の agent のうち制御プレーンの試作を定めます。
制御プレーンは、wire の版 1 の型、接続文字列と登録、認証情報 (`agent.json`)、stream、全体状態の適用、ハートビートを受け持ちます。
試作の目的は、変更していない Go の v1 の server に Rust の agent を登録し、トンネルを立て、ルールの TCP の接続を 1 本中継できることをラボで確かめることです。
wire と `agent.json` の契約は [agent と server の境目の仕様](../spec/README.md) に従います。
この文書は Rust の側の作りと、試作だけの扱いと、未確認の点を書きます。

## crate の分け方

| crate | 中身 |
| --- | --- |
| `crates/wgft-proto` | wire の版 1 の型。接続文字列の解釈、登録の要求と応答、stream のメッセージ、全体状態、close の符号、版の交渉、理由の整形 |
| `crates/wgft-agent` | agent の制御プレーン。登録、認証情報、stream、全体状態の適用、ハートビート、トンネルの監視、TCP の中継 |
| `crates/wgft` | コマンド。今は `wgft agent run` と `wgft version` だけを持ちます |

`wgft-proto` は I/O を持たず、serde と serde_json と time だけに依ります。
agent と、後で作る Rust の server の両方が使います。
`wgft-agent` は tokio の上の async で書きます。
所有者の決定のとおり、制御プレーンは通常の async で書き、データプレーンの核は sans-IO にします。
WireGuard の device の層 (`crates/wgft-wireguard`) と Linux の TUN の外殻 (`crates/wgft-wireguard-tun`) を扱うのは `wgft-agent` の `tunnel` の module だけで、残りは wgft の型だけを見ます。
device の層の作りは [WireGuard の device の層](wireguard-device.md) にあります。

## wire の型

型と JSON の形は Go の `proto` パッケージと `internal/agent/enroll` を写します。
Go の `encoding/json` に由来する細部のうち、次の点を Rust でも同じにします。

- 時刻:`GoTime` が Go の `time.Time` に当たります。
  Go の零の値と同じ瞬間を、どの作り方でも零の値に揃え、`0001-01-01T00:00:00Z` で書きます。
  ハートビートの `last_handshake` は `omitempty` でも常に書きます。
  Rust の agent は時刻を UTC の `Z` で書きます。
  Go の agent は自分のホストの時差で書きますが、どちらも RFC 3339 なので server は同じ瞬間に読みます
- 不在と空の配列:`capabilities` と `server_capabilities` は `Option<Vec<String>>` で持ち、不在の legacy v0 と空の配列を区別します
- `null`:Go のポインタと配列のフィールドに当たるものは、`null` を不在と同じに読みます。
  `Option` で持つのは、メッセージの `state`、`heartbeat`、`protocol_min`、`protocol_max`、`capabilities` と、全体状態の `server_protocol_version`、`server_capabilities` です。
  全体状態とハートビートの `rules` は `null` を空の列として読みます。
  時刻の `null` は零の値として読みます。
  Rust の agent が `agent.json` に書き戻すときと、ハートビートを送るときは、`rules` を `[]` で書きます
- フィールドの順:Go の構造体の宣言の順で書きます。
  登録の要求は Go が `map[string]string` を書くので、キーの辞書順の `name`、`token` で書きます
- 知らないキー:読み飛ばします
- 1 通の大きさ:stream の 1 通は 4 MiB (`STREAM_READ_LIMIT`)、登録の応答は 4096 byte (`REGISTER_RESPONSE_LIMIT`) までを読みます

### 接続文字列

接続文字列の解釈は、Go の `url.Parse` と `net.SplitHostPort` を、`ParseJoin` が見る結果の範囲で写します。
角括弧の host の IPv6 と zone、userinfo の文字、`%XX` の形と host の中で許す escape、制御文字、`?` と opaque の形を Go と同じに扱います。
誤りは Go と同じ固定の 7 つの文言で、入力のどの部分も引用しません。
トークンは秘密で、形の崩れた入力ではトークンがどの断片に入り込むか判別できないためです。
`Join` と登録の要求と応答の `Debug` の出力もトークンを伏せます。

Go と Rust の結果は、次の 1 点を除いて一致させます。
Go の文字列は不正な UTF-8 を持てるので、Go は `%FF` のような escape が作る不正な UTF-8 の host とトークンを受けます。
Rust の `String` は持てないので、Rust はその入力を scheme の誤りとして拒みます。
照合した入力の範囲で、Go が拒む入力を Rust が受けることはありません。

### 理由の整形

理由の整形は Go の `textsafe.SanitizeAndClip` を写します。
`unicode.IsGraphic` でない文字を `strconv.QuoteRune` の形に置き換え、512 byte を超える理由は文字の境目で切って `... truncated` を付けます。
一般カテゴリの表は `unicode-general-category` の crate から取ります。
crate の表の Unicode の版は `UNICODE_VERSION` で、Go の `unicode.Version` と違うことがあります。
2026-11 の時点で Go 1.27 は Unicode 17.0、crate は 16.0 です。
差は、片方の版だけで割り当てのある文字の扱いだけです。
割り当ての無い文字は表示できない文字なので、Go の版が新しい間は、新しく割り当てられた文字を Rust だけが置き換えます。
server は受け取った理由に同じ整形を自分でかけますが、置き換えた後の文言は元に戻らないので、その文字を含む理由は Go の agent が送った場合と違う文言で保存されます。

## 登録と TLS

登録は Go の agent と同じく `POST https://host:port/api/v1/agents/register` を呼び、本文は `{"name","token"}` です。
TLS の検証は rustls の独自の検証器で行い、leaf の証明書の DER の SHA-256 がピンと一致するときだけ通します。
CA、ホスト名、期限は検証しません。
ハンドシェイクの署名は rustls の ring の provider で検証するので、相手が証明書の秘密鍵を持つことは確かめます。
TLS は 1.2 と 1.3 を許し、ALPN を送らないので HTTP/1.1 で話します。
暗号の provider は ring にし、rustls の既定の aws-lc-rs を使いません。
aws-lc-rs は C と CMake の build を要し、クロスの build を重くするためです。

応答は 4096 byte までを読みます。
401、400、409 は送った値への判断で、再起動では直らないので、起動の拒否 (終了コード 3) にします。
文言は Go の agent と同じです。
それ以外の失敗は終了コード 1 です。

登録の結果は Go の `enroll.Record` と同じ項目を `agent.json` に書きます。
`used_join_token_sha256` はトークンの SHA-256 で、`compose` に残った使用済みの `WGFT_JOIN` を黙って無視するために使います。

## 認証情報

`agent.json` は Go の v1 の agent と同じファイルです。
Rust の agent は Go の v1 の agent が書いたファイルをそのまま読み、Go の v1 の agent は Rust の agent が書いたファイルを読めます。
フィールドの順と 2 文字の字下げは Go の `json.MarshalIndent` と同じにします。
カーネルモードの記録 (`previous_wg_private_key`、`ip_forward_enabled_at`、`kernel_publication`、`kernel_unconverged`) は形を持たずに保存し直し、知らないキーも捨てずに保存し直します。
Go の v1 の agent は知らないキーを捨てるので、ここは Go より保守的な扱いです。

保存は同じディレクトリの一時ファイルに書いて rename します。
一時ファイルの名前の接頭辞 `.wgft-credentials-` と、Unix で作った瞬間から 0600 にする扱いは Go と同じです。
二重起動は隣の `agent.json.lock` の排他ロックで防ぎます。
Rust の標準の `File::try_lock` は Unix で `flock`、Windows で `LockFileEx` を使い、Go の agent と同じ方式なので、Go の agent と Rust の agent は同じデータディレクトリで同時に動きません。

`mode` が `kernel` の記録を持つファイルは、試作が扱わないので起動の拒否にします。

## stream

stream は Go の agent と同じ順で動きます。

1. ピンで確かめた TLS の上で `GET /api/v1/agents/stream` の WebSocket に `Authorization: Bearer <恒久トークン>` で接続します
2. 最初に `pubkey` を送ります。`protocol_min` と `protocol_max` は 1、`capabilities` は空の配列です
3. 最初の `state` で server が選んだ版を確かめ、1 以上で agent の範囲に入らなければ接続を終えます
4. `state` を受けるたびに適用し、適用の直後にハートビートを送ります。
   古い世代は捨て、最後に適用したものと世代も中身も同じ全体状態は適用し直しません
5. ハートビートは 30 秒ごとにも送ります。
   適用の直後のハートビートがハンドシェイク待ちを報告したときは、済むまで 1 秒ごとに 10 秒まで送り直します
6. 30 秒ごとに WebSocket の ping を送り、20 秒以内に pong が無ければ接続を終えます。
   適用の間は読みが止まるので、適用の後に pong の期限を測り直します

1 通の大きさの上限は 4 MiB です。
接続が切れたら 1 秒から 5 分の指数の待ちで繋ぎ直し、1 分以上続いた接続の後は 1 秒から数え直します。
最終ハンドシェイクが 180 秒より新しい間は、待ちの上限を 10 秒にします。
Go と同じく、server が応答したうえで再試行では直らない食い違いを示した切断 (恒久トークンの拒否、置き換え、版の不一致、ピンの不一致、1008) には当てません。
HTTP 401 は登録のし直しに入り、未使用の `WGFT_JOIN` が無ければ起動の拒否で終わります。
ピンの不一致は、未使用でピンの違う `WGFT_JOIN` があるときだけ登録し直します。

読めないメッセージは `Message::decode` が拒み、ログに出して読み飛ばします (Go の writer が書かない形の扱いは下の節)。
ハートビートの理由は、送る前に server の受け口と同じ整形と 512 byte の上限にかけます。
JSON は HTML のための書き換えをしない形で書きます。
Go の agent の `SetEscapeHTML(false)` と同じ形です。

## 全体状態の適用

wg の設定が変わったときか、トンネルが無いときにトンネルを立て直し、ルールは変わったものだけを開閉します。
トンネルを立てられなければ世代も `agent.json` も進めず、30 秒ごとに立て直します。
トンネルが立った後はルールの一部が失敗しても世代を進めて `last_state` を保存します。
起動のときに `last_state` があれば、stream に繋ぐ前にその全体状態でトンネルとリスナーを立てます。
server のプロセスが止まっていても、server の側にピアが残っていれば転送が戻るようにするためです。

server のトンネルのアドレスは、全体状態の `wg.address` の帯の先頭の次 (`10.200.0.1`) です。
WireGuard のピアは server の 1 つで、AllowedIPs は server のアドレスの /32 です。
keepalive の秒が 1 から 65535 の外なら 25 秒を使います。

## トンネルと中継 (試作の形)

試作のトンネルは Linux の TUN とカーネルの TCP/IP を使います。
所有者の判断で、Rust の wgstack ができるまでの試作の形です。
`tunnel` の module は `wgft-wireguard-tun` の外殻で device を動かし、外殻が TUN を作り、全体状態の `wg.address` と MTU を付けて link を上げます。
カーネルは帯の経路を TUN に向けるので、server のアドレスへの packet は TUN を通ります。
TUN を作るには root か `CAP_NET_ADMIN` と `ip` のコマンドが要ります。
v1 のユーザー空間モードの agent は特権を要らないので、この点は製品の形と違います。

TUN の名前は `WGFT_WG_INTERFACE` (既定 `wgft0`) から取ります。
v1 ではカーネルモードの WireGuard のインタフェースの名前で、ユーザー空間モードでは使わない設定です。
試作だけの読み替えです。

エンドポイントの名前は起動のときに解決し、解決できなくてもトンネルを立てます。
keepalive ごとに、最終ハンドシェイクが keepalive の 5 倍より古ければ名前を引き直し、変わっていれば device に設定し直します。
続けて、server のトンネルのアドレスへ ICMP echo を 1 つ送ります。
Go の agent の `tunnel.Run` と同じで、server がセッションを失っていれば鍵の寿命を待たずに新しいハンドシェイクが始まります。
ping はカーネルの ICMP のデータグラムのソケットをトンネルのアドレスに bind して送り、答えの有無が変わったときだけ 1 行をログに出します。
ハートビートの最終ハンドシェイクは、device が返す単調な時計の値を壁時計に直して書きます。

中継はルールのポートごとに、トンネルのアドレスに bind したカーネルの TCP のソケットで待ち受けます。
受けた接続は、ルールの範囲の中の位置を足した宛先へ 10 秒の期限で接続し、両方向に複写します。
開けなかったリスナーはルールの状態を `error` にし、30 秒ごとに開き直します。

## コマンドと設定

`wgft agent run` は v1 と同じく `WGFT_*` の環境変数を受け、フラグはその別名です。
試作が持つのは `WGFT_DATA_DIR`、`WGFT_JOIN`、`WGFT_NAME` です。
`WGFT_MODE` は空か `userspace` だけを受けます。
`WGFT_AGENT_NETSTACK` は `gvisor` と `wgstack` を受けて使わない旨を 1 行出します。
所有者の決定の「`gvisor` は受け付けて wgstack で動かし 1 行出す」の試作の形です。
`WGFT_WG_INTERFACE` は TUN の名前に使います ([トンネルと中継](#トンネルと中継-試作の形))。
1 から 15 byte で、`/`、`%`、空白を含まない値だけを受けます。

次の設定は試作に無く、値があれば黙って無視せずに設定の誤り (終了コード 3) で止めます。
無視すると、許可一覧や上限のような守りを利用者の意図より緩めるためです。

- `WGFT_CONFIG` と既定の dotenv (`/etc/wgft/agent.env`):dotenv を読みません
- `WGFT_AGENT_ALLOW_TARGETS`:宛先の許可一覧
- `WGFT_MAX_TCP_FLOWS`、`WGFT_MAX_UDP_FLOWS`:同時のフローの上限
- `WGFT_AGENT_BATCH_MIB`:送信の向きのバッチ

`agent doctor`、`agent pubkey`、`agent rotate-key`、`agent teardown`、制御ソケット (`agent.json.sock`)、server と rule と status のコマンドもありません。
ログの 1 行の形は Go の `log` と同じ `2006/01/02 15:04:05 msg` です。

## Go の v1 との照合

照合の fixture はリポジトリの直下の `testdata/spec/` に置き、Go の試験が Go の v1 の実装から作ります。
Go の試験は `-update` で fixture を書き直し、`-update` が無ければ実装と fixture が離れたときに失敗します。

| fixture | 作る Go の試験 | 照らす Rust の試験 |
| --- | --- | --- |
| `testdata/spec/join/join-corpus.json` | `internal/agent/enroll` の `TestJoinCorpus` | `crates/wgft-proto/tests/join_corpus.rs` |
| `testdata/spec/text/non-graphic.json` | `internal/textsafe` の `TestNonGraphicRanges` | `crates/wgft-proto/tests/non_graphic.rs` |
| `testdata/spec/wire/` | 仕様の fixture。`proto` の `spec_test.go` が Go の型との往復を確かめる | `crates/wgft-proto/tests/spec_wire.rs` |
| `testdata/spec/join/join-strings.json` と登録の本文 | 仕様の fixture。`internal/agent/enroll` の `spec_test.go` が確かめる | `crates/wgft-proto/tests/spec_join.rs` |

`join-corpus.json` は、接続文字列の種の入力と、種から決まった手順で作った変異の入力に対する `ParseJoin` の結果です。
Rust の試験は、受理、`endpoint`、トークン、ピン、誤りの文言のすべてで Go と一致することを確かめます。
例外は上の不正な UTF-8 の入力だけで、fixture がその入力に印を付けます。
`non-graphic.json` は `unicode.IsGraphic` が偽の code point の範囲で、Rust の試験は差が割り当ての無い文字だけであることを確かめます。
仕様の wire の fixture では、Rust の試験は次を確かめます。

- `pubkey`、`state`、`heartbeat` のメッセージは、Rust で読んで書くと同じ byte 列に戻ること
- `quirks.json` の `must-accept` の例は Go と同じ値に読み、`may-reject` の例は拒むか Go と同じ値に読むこと。
  Go と同じ値かは、Go が読んで書き直した形を Rust で読んだ値と比べます。
  Go が誤りにする例は Rust も拒みます
- `reasons.json` の理由の整形が Go と同じ文言になること。
  不正な UTF-8 の入力の例は、Rust の文字列が持てないので照らしません
- `close.json` の符号が、Rust の知る符号と 1008、1011、close のフレームの無いことのどれかであること

## Go の writer が書かない形

仕様は、Go の v1 の writer が書く形をすべて受けることを求め、Go の writer が書かない形はメッセージごと拒んでよいとします。
Rust の型は前者を受け、後者の次の形を拒みます。
拒む経路は Go の v1 の読みの誤りと同じで、agent は読めない `state` をログに出して捨てます。

- 大文字か ASCII でない文字を含むキー:`Message::decode` はメッセージごと拒みます。
  Go はそのキーを Unicode の単純な case folding で既知のフィールドに当てるので、serde の既定のように知らないキーとして読み飛ばすと、Go と違う値になります。
  Go の writer のキーは小文字の ASCII なので、知らないキーとして受けるのは小文字の ASCII のキーだけです
- 重複したキー:既知のフィールドの重複は serde の構造体の誤りにします。
  知らないキーの重複は、Go と同じく読み飛ばします
- 時刻の小文字の `t` と `z`:Go と同じく誤りにします
- 数、文字列、真偽、`PortRange` への `null`:上に挙げた `Option`、`rules`、時刻のほかは誤りにします
- 欠けたフィールド:ルールの `id`、`proto`、`listen_port`、`target` と、ルールの状態の `id`、`state` が欠けたメッセージを誤りにします。
  Go の writer はこれらを省きません

書く側は、正規の小文字のキーを重複なく書きます。
HTML のための書き換えは byte 列だけの差です。
Go の server と `agent.json` の書き手は `<`、`>`、`&` を `\u003c` の形で書き、Go の agent の stream の書き手も U+2028 と U+2029 を書き換えます。
serde_json はどれも書き換えず、JSON の値は同じです。
接続文字列の差は上の不正な UTF-8 の扱いだけです。

## 試作だけの扱い

- 中継:TCP だけです。UDP のルールは状態を `error` にして報告します。
  宛先の許可一覧、ブロードキャストとマルチキャストの宛先の拒否、フローの数の上限、試し接続による宛先の確認がありません
- トンネルの立て直し:Go の agent の watchdog (ハンドシェイクが長く無いときのトンネルの作り直し) と、新しいハンドシェイクで stream の再接続の待ちを打ち切る扱いがありません
- 特権:TUN を作るので root か `CAP_NET_ADMIN` で動かします
- 一時ファイルの片付け:前の保存が残した一時ファイルを起動のときに消しません

## ラボでの確認

`lab/rust-agent.sh` は、使い捨てのラボの VM で、変更していない Go の v1 の server に対して Rust の agent を動かします。
手順は [lab/README.md](../../../lab/README.md#v2-の-rust-の-agent-の試作) にあります。
server のカーネルモードは Linux のカーネルの WireGuard と、ユーザー空間モードは wireguard-go と組む確認です。
次の点を両方のモードで確かめました。

- 登録:Rust の agent が接続文字列で自分を登録し、自分で作った鍵を送ること
- stream:server が版 1 を選び、全体状態の適用の後のハートビートで、トンネルとルールの状態が server に届くこと
- トンネル:TUN にトンネルのアドレスが付き、server が WireGuard のハンドシェイクを観測すること
- keepalive の ping:ユーザー空間モードの server は答えること。
  カーネルモードの server では、ping が server の `wgft0` に届き、nftables の `input` に落とされて答えが返らないこと
- 中継:server の公開の側からの TCP の接続で、ルールの宛先へ 8 MiB を送り、宛先から 8 MiB を受け、SHA-256 が一致すること
- 停止:止めると TUN が消えること
- Go の agent:同じ server に Go の v1 の agent を登録し、同じ確認で転送できること
- 認証情報の引き継ぎ:Go の agent が登録して書いた `agent.json` から、接続文字列なしで Rust の agent が起動し、同じ鍵でハンドシェイクして転送できること。
  逆に、Rust の agent が書いた `agent.json` から Go の agent が起動して転送できること

## 未確認の点

- UDP のルール、許可一覧、フローの数の上限は、試作に無いので確かめていません
- 長い時間の動作、鍵の更新 (120 秒ごとの再ハンドシェイク) を跨ぐ転送、server の再起動からの戻りを確かめていません
- Windows と macOS では build と単体の試験だけを CI で流し、動かしていません
