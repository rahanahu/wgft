# Rust の agent の制御プレーン (試作)

この文書は、v2 の Rust の agent のうち制御プレーンの試作を定めます。
制御プレーンは、wire の版 1 の型、接続文字列と登録、認証情報 (`agent.json`)、stream、全体状態の適用、ハートビートを受け持ちます。
試作の目的は、変更していない Go の v1 の server に Rust の agent を登録し、トンネルを立て、ルールの TCP の接続を 1 本中継できることをラボで確かめることです。
wire と `agent.json` の契約は、別に書く agent と server の境目の仕様 (`docs/design/spec/`) に従います。
この文書は Rust の側の作りと、試作だけの扱いと、未確認の点を書きます。

## crate の分け方

| crate | 中身 |
| --- | --- |
| `crates/wgft-proto` | wire の版 1 の型。接続文字列の解釈、登録の要求と応答、stream のメッセージ、全体状態、close の符号、版の交渉、理由の整形 |

`wgft-proto` は I/O を持たず、serde と serde_json と time だけに依ります。
agent と、後で作る Rust の server の両方が使います。

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
Go が拒む入力を Rust が受けることはありません。

### 理由の整形

理由の整形は Go の `textsafe.SanitizeAndClip` を写します。
`unicode.IsGraphic` でない文字を `strconv.QuoteRune` の形に置き換え、512 byte を超える理由は文字の境目で切って `... truncated` を付けます。
一般カテゴリの表は `unicode-general-category` の crate から取ります。
crate の表の Unicode の版は `UNICODE_VERSION` で、Go の `unicode.Version` と違うことがあります。
2026-11 の時点で Go 1.27 は Unicode 17.0、crate は 16.0 です。
差は、片方の版だけで割り当てのある文字の扱いだけです。
割り当ての無い文字は表示できない文字なので、Go の版が新しい間は、新しく割り当てられた文字を Rust だけが置き換えます。
server は受け取った理由に同じ整形を自分でかけますが、置き換えた後の文言は元に戻らないので、その文字を含む理由は Go の agent が送った場合と違う文言で保存されます。

## Go の v1 との照合

照合の fixture はリポジトリの直下の `testdata/spec/` に置き、Go の試験が Go の v1 の実装から作ります。
Go の試験は `-update` で fixture を書き直し、`-update` が無ければ実装と fixture が離れたときに失敗します。

| fixture | 作る Go の試験 | 照らす Rust の試験 |
| --- | --- | --- |
| `testdata/spec/join/join-corpus.json` | `internal/agent/enroll` の `TestJoinCorpus` | `crates/wgft-proto/tests/join_corpus.rs` |
| `testdata/spec/text/non-graphic.json` | `internal/textsafe` の `TestNonGraphicRanges` | `crates/wgft-proto/tests/non_graphic.rs` |

`join-corpus.json` は、接続文字列の種の入力と、種から決まった手順で作った変異の入力に対する `ParseJoin` の結果です。
Rust の試験は、受理、`endpoint`、トークン、ピン、誤りの文言のすべてで Go と一致することを確かめます。
例外は上の不正な UTF-8 の入力だけで、fixture がその入力に印を付けます。
`non-graphic.json` は `unicode.IsGraphic` が偽の code point の範囲で、Rust の試験は差が割り当ての無い文字だけであることを確かめます。
wire のメッセージの byte 列の fixture は、仕様の PR が `testdata/spec/wire/` に置くものを使います (未着手)。

## Go の writer が書かない形

仕様は、Go の v1 の writer が書く形をすべて受けることを求め、Go の writer が書かない形はメッセージごと拒んでよいとします。
Rust の型は前者を受け、後者の次の形を拒みます。
Go は受けるので、ここが Go の読み手と違う点です。

- 大文字と小文字だけが違うキーと、重複したキー:serde の既定のとおり、前者は知らないキーとして読み飛ばし、後者は構造体の誤りにします。
  Unicode の case folding と重複したキーの重ね合わせは写しません
- 数、文字列、真偽、`PortRange` への `null`:上に挙げた `Option`、`rules`、時刻のほかは誤りにします
- 欠けたフィールド:ルールの `id`、`proto`、`listen_port`、`target` と、ルールの状態の `id`、`state` が欠けたメッセージを誤りにします。
  Go の writer はこれらを省きません

書く側は、正規の小文字のキーを重複なく書きます。
HTML のための書き換えは byte 列だけの差です。
Go の server と `agent.json` の書き手は `<`、`>`、`&` を `\u003c` の形で書き、Go の agent の stream の書き手も U+2028 と U+2029 を書き換えます。
serde_json はどれも書き換えず、JSON の値は同じです。
接続文字列の差は上の不正な UTF-8 の扱いだけです。

## 未確認の点

- Go の v1 の server との登録、stream、トンネル、中継は、制御のクライアントのラボの確認で確かめます。
  型だけの単体の試験では、Go の v1 の server が実際に送る `state` を受けていません
