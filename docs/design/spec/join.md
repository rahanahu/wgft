# 接続文字列、登録、証明書のピン

agent は 1 回限りの接続文字列で server に登録し、恒久トークンを得ます。
登録の API と stream は、接続文字列が運ぶ証明書の SHA-256 で server を確かめる TLS の上にあります。
登録の流れと理由は[登録](../control/registration.md#51-登録)にあります。

## 接続文字列

形は `wgft://<host>:<port>/<token>#sha256:<hex>` です。

- host:エージェント用 API のホスト名か IP アドレスです。
  IPv6 のアドレスは `[` と `]` で囲みます
- port:エージェント用 API の TCP のポートで、1 から 65535 の 10 進の数字です
- token:1 回限りの登録トークンです。
  server は 16 byte の乱数を base64url の padding 無しで 22 文字にして発行します
- hex:エージェント用 API の証明書の SHA-256 で、64 桁の 16 進です。
  server は小文字で発行します

server は `fmt.Sprintf("wgft://%s/%s#sha256:%x", host, token, fingerprint)` の形で発行します。
`host` は `WGFT_AGENT_API_HOST` の値です。
無ければ `WGFT_WG_ENDPOINT` のホストと `WGFT_AGENT_API` のポートを合わせた値です。

### 解釈の手順

agent は次の順に確かめ、最初に当たった誤りを返します。
誤りの文言は固定で、接続文字列のどの部分も引用しません。
トークンは秘密で、形の崩れた入力ではトークンがどの部分に入るか分からないためです。

| 順 | 条件 | 誤りの文言 |
| --- | --- | --- |
| 1 | 前後の空白を除いた値を URL として読めない、または scheme が `wgft` でない | `join string must look like wgft://host:port/token#sha256:HASH` |
| 2 | authority を host と port に分けられない | `join string host has no port` |
| 3 | host が空 | `join string has no host` |
| 4 | port が 1 から 65535 の 10 進の数でない | `join string port must be a number from 1 to 65535` |
| 5 | path から先頭の `/` を 1 つ除いた値が空か `/` を含む | `join string has no token` |
| 6 | fragment を最初の `:` で分けられない、または前半が `sha256` でない | `join string has no #sha256 certificate hash` |
| 7 | 後半が 16 進として読めないか 32 byte でない | `join string certificate hash is invalid` |

成功したときの値は 3 つです。

- endpoint:authority の `host:port` を書かれたまま使います。
  IPv6 なら `[` と `]` を含みます
- token:path から先頭の `/` を除いた値です
- pin:fragment の後半を 16 進として読んだ 32 byte です

### Go の性質:URL の解釈

agent は Go の `net/url.Parse` と `net.SplitHostPort` で読みます。
Go 以外の実装は次の点を写します。
fixture の `testdata/spec/join/join-strings.json` が、正しい値と誤りの値と、Go の v1 の結果を持ちます。

- scheme:大文字と小文字を区別しません。
  `WGFT://` も受けます
- userinfo:`user:pass@` は読み飛ばし、endpoint に入れません
- query:`?` から `#` の前までは読み飛ばします
- percent-encoding:path と fragment は percent-decoding の後の値で判定します。
  `%2F` は `/` になるので、トークンの判定 (表の 5) で誤りになります。
  不正な percent-encoding は表の 1 の誤りです
- port:数字以外を含む port は URL の解釈の誤りで、表の 1 に当たります。
  数字だけの port は `strconv.ParseUint(port, 10, 32)` で読むので、先頭の 0 (`08443`) を受けます。
  endpoint には先頭の 0 を残したまま入り、接続のときに 8443 として扱います
- 16 進:大文字と小文字の両方を受けます
- 前後の空白:改行を含む前後の空白を除いてから読みます

## 登録の API

agent は `POST https://<endpoint>/api/v1/agents/register` を送ります。

- 要求の header:`Content-Type: application/json` を付けます
- 要求の本文:`{"name":"<名前>","token":"<トークン>"}` で、キーはこの順です。
  名前が無ければ `"name":""` を送ります。
  server は本文を 4096 byte まで読みます
- 名前の形:`^[a-z0-9]([a-z0-9-]{0,30}[a-z0-9])?$` です。
  server は空でない名前をこの形で確かめます
- 期限:1 回の要求は 15 秒で打ち切り、登録の全体は 30 秒で打ち切ります

### 応答

agent は応答の本文を最大 4096 byte 読みます。

| 状態 | server の本文 | agent の扱い |
| --- | --- | --- |
| 200 | `{"permanent_token":"...","address":"10.200.0.2","name":"home"}` と改行 | `permanent_token` と `name` が空でなければ成功です。どちらかが空か本文を読めなければ `registration API returned an invalid response` の誤りで、終了コードは 1 です |
| 400 | `bad request` と改行 | 名前の形の誤りとして、終了コード 3 の拒否にします。種別は config、対象は `WGFT_NAME` です。server は本文を読めない場合とトークンが空の場合にも 400 を返しますが、agent は区別しません |
| 401 | `invalid token` と改行 | 接続文字列が使用済みか期限切れか名前が違うとして、終了コード 3 の拒否にします。種別は conflict、対象は `WGFT_JOIN` です |
| 409 | `agent already registered` と改行 | その名前のエージェントが登録済みとして、終了コード 3 の拒否にします。種別は conflict、対象は `WGFT_JOIN` です |
| 429 | `too many attempts` と改行 | `registration API: HTTP 429: too many attempts` の誤りで、終了コードは 1 です |
| その他 | `internal error` など | `registration API: HTTP <状態>: <本文>` の誤りで、終了コードは 1 です |

- 200 の本文:server は `json.NewEncoder` で書くので、末尾に改行が付きます。
  `Content-Type` は `application/json` です。
  `address` はトンネルのアドレスで、帯の長さを付けずに書きます
- 誤りの本文:server は Go の `http.Error` で書くので、`Content-Type` は `text/plain; charset=utf-8` で、末尾に改行が付きます。
  agent は誤りの文言に、前後の空白を除いた本文を入れます
- 終了コード 3 の拒否:拒否の文言の形と終了コードは [cli-config.md](cli-config.md) にあります

server は登録と stream の要求を、送信元の IP アドレスごとに毎秒 1 回、溜めて 5 回までに制限し、超えた要求に 429 を返します。
IPv4 はアドレスで数え、IPv6 は /64 で数えます。
登録と stream は同じ枠を使います。

### 登録の結果の記録

agent は登録に成功した時点で `agent.json` を書き換えます。
失敗したときは既存の `agent.json` を残します。

| `agent.json` のキー | 値 |
| --- | --- |
| `name` | 応答の `name` |
| `endpoint` | 接続文字列の endpoint |
| `permanent_token` | 応答の `permanent_token` |
| `cert_sha256` | 接続文字列の pin を小文字の 16 進 64 桁にした値 |
| `used_join_token_sha256` | トークンの UTF-8 の byte の SHA-256 を小文字の 16 進 64 桁にした値 |
| `tunnel_address` | 応答の `address` が IPv4 のアドレスならその値、IPv4 の CIDR ならその値、どちらでもなければ空 |

各キーの意味は [credentials.md](credentials.md) にあります。

### 登録をするかどうかの判定

agent は起動のたびに次の順で判定します。

1. `agent.json` に `permanent_token` があれば登録しません。
   `WGFT_NAME` が記録の名前と違えば警告を 1 行出し、記録の名前を使います。
   `WGFT_JOIN` が未使用の接続文字列なら、使わない旨を 1 行出します
2. `WGFT_JOIN` が無ければ、終了コード 3 の拒否にします
3. `WGFT_JOIN` を上の手順で読めなければ、終了コード 3 の拒否にします。
   起動の入口では警告を 1 行出すだけで、拒否は登録の直前に判定します。
   登録済みの agent が compose に残った古い値で止まらないためです
4. トークンの SHA-256 が `used_join_token_sha256` と同じなら、終了コード 3 の拒否にします
5. 登録の API を呼びます

stream の認証が 401 で拒まれた場合と、証明書のピンが合わない場合の登録のし直しは [stream.md](stream.md#登録のし直し) にあります。

## TLS と証明書のピン

エージェント用 API の TLS は、CA と名前と期限の検証を使わず、leaf の証明書の SHA-256 だけで server を確かめます。
IP アドレスでも DNS の名前でも同じ接続文字列が使えるようにするためです。

- 最低の版:TLS 1.2 です
- ピン:server が送った証明書の列の先頭、つまり leaf の DER の SHA-256 が pin と一致しなければ、ハンドシェイクを失敗させます。
  証明書の列が空でも失敗です
- ハンドシェイクの署名:Go の性質として、`InsecureSkipVerify` でも TLS のハンドシェイクの署名は leaf の公開鍵で確かめます。
  Go 以外の実装でピンだけを比べる検証器を書くときも、ハンドシェイクの署名は確かめなければなりません。
  例えば rustls の独自の `ServerCertVerifier` では、`verify_tls12_signature` と `verify_tls13_signature` を既定の実装に任せます。
  署名を確かめないと、公開された証明書を持つだけの第三者が server に成りすませます
- ピンの不一致の誤り:`server certificate does not match the pinned hash: got sha256 <先頭 4 byte の 16 進>` です。
  agent はこの誤りを他の接続の失敗と区別します
- 名前:Go の性質として、host が DNS の名前なら SNI に入れ、IP アドレスなら SNI を送りません。
  server は SNI を見ません
- HTTP の版:HTTP/1.1 だけです。
  server は h2 を広告しません
- keep-alive:server は応答の後に接続を閉じます。
  agent は登録と stream の接続のたびに新しい接続を張ります

server の証明書は ECDSA の P-256 の自己署名で、CN は `wgft agent api`、有効期限は 10 年です。
agent は証明書の中身を見ないので、この形は保証の外です。
server は証明書を初回の起動で作り、`teardown --purge` で作り直すまで変えません。

[agent と server の境目の仕様](README.md)
