# agent の CLI と設定

agent のホストで使うコマンド、設定の受け取り方、終了コード、起動ログを定めます。
VPS の側のコマンドは、agent の手順が要る `wgft agent join-string` だけを扱います。
設定を決めた理由は [11a 節](../security/configuration.md#11a-設定の渡し方)に、終了コードを決めた理由は [11b 節](../security/startup.md#11b-起動の失敗の意味論)にあります。
fixture は `testdata/spec/config/` に置き、`cmd/wgft/spec_config_test.go` が Go の v1 と照らします。

## コマンド

| コマンド | 動かす場所 | 引数 | 常駐 | 読む設定 |
| --- | --- | --- | --- | --- |
| `wgft agent run` | agent のホスト | なし | する | 設定項目の一覧のすべて |
| `wgft agent pubkey` | agent のホスト | なし | しない | `WGFT_DATA_DIR` |
| `wgft agent rotate-key` | agent のホスト | なし | しない | `WGFT_DATA_DIR` |
| `wgft agent doctor` | agent のホスト | なし | しない | 設定項目の一覧のすべて。フラグは一部だけ |
| `wgft agent teardown` | agent のホスト | なし | しない | `WGFT_DATA_DIR`、`WGFT_WG_INTERFACE` |
| `wgft version` | どこでも | なし | しない | なし |
| `wgft agent join-string` | VPS | なし | しない | `WGFT_ADMIN` |

`wgft version` を除くどのコマンドも、`--config` で dotenv のファイルを指せます。
`wgft version` と `wgft --version` は設定を読みません。
フラグの名前と意味は [CLI の互換性](../compatibility/surfaces.md)が保証します。
`--help` の文面と `docs/cli.md` は保証の外です。

### wgft agent run

agent の常駐プロセスです。
フラグは次のとおりです。
型は `--max-udp-flows` と `--max-tcp-flows` が整数で、それ以外は文字列です。

- `--config`:dotenv のファイルで、既定は OS ごとの `agent.env` です
- `--data-dir`:`WGFT_DATA_DIR` の別名
- `--join`:`WGFT_JOIN` の別名
- `--name`:`WGFT_NAME` の別名
- `--mode`:`WGFT_MODE` の別名
- `--wg-interface`:`WGFT_WG_INTERFACE` の別名
- `--agent-netstack`:`WGFT_AGENT_NETSTACK` の別名
- `--agent-batch-mib`:`WGFT_AGENT_BATCH_MIB` の別名
- `--agent-allow-targets`:`WGFT_AGENT_ALLOW_TARGETS` の別名
- `--max-udp-flows`:`WGFT_MAX_UDP_FLOWS` の別名
- `--max-tcp-flows`:`WGFT_MAX_TCP_FLOWS` の別名

標準出力には何も書きません。
起動ログは標準エラーに書きます。
順序と書式は後述の起動ログの節に書きます。
SIGINT か SIGTERM を受けると `shutting down` をログに書き、終了コード 0 で終わります。

### wgft agent pubkey

認証情報ファイル `agent.json` の WireGuard の公開鍵を、標準出力に base64 の 1 行で書きます。
鍵が無く、agent が止まっていれば、鍵を作って保存してから書きます。
フラグは `--config` と `--data-dir` です。
ファイルの扱いは [agent.json と .lock と .sock](credentials.md) に従います。

`WGFT_DATA_DIR` が空でも拒否しません。
このとき認証情報ファイルのパスは、Linux では `/agent.json`、Windows と macOS では作業ディレクトリの `agent.json` になります。
これは `agent run` の入口の検査と食い違う挙動で、保証の外です。

### wgft agent rotate-key

WireGuard の鍵の対を作り直します。
agent が動いていれば制御ソケットで頼み、止まっていれば認証情報ファイルの鍵と `last_state` を消します。
フラグは `--config` と `--data-dir` です。
制御ソケットの要求と応答は [制御ソケットと agent doctor --json](control-socket.md) に従います。

成功すると標準出力に 1 行を書きます。

- 稼働中:`running agent regenerated its key; public key: <公開鍵>`
- 停止中:`agent stopped: cleared the key and last_state in the credentials file, agent.json; the next start regenerates the key and receives full state over the stream`
- 停止中でカーネルモードの記録がある場合:停止中の行の後ろに `; the old key is kept as the previous key, so the next start still recognises the kernel WireGuard interface that holds it and moves it to the new key` を続けます

この文面は保証の外です。
終了コード 0 は agent が自分の鍵を変えたことだけを表し、server が受け付けたことは表しません。
`WGFT_DATA_DIR` が空のときの扱いは `agent pubkey` と同じです。

### wgft agent doctor

agent のホストの状態を診断します。
報告の JSON の形と状態の語は [制御ソケットと agent doctor --json](control-socket.md) に、診断の意味は [10.2c 節](../diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor)にあります。
フラグは次のとおりです。

- `--json`:真偽値のフラグで、JSON の報告を書きます。
  終了コードは変えません
- `--config`:dotenv のファイル
- `--data-dir`:`WGFT_DATA_DIR` の別名
- `--max-udp-flows`、`--max-tcp-flows`:整数のフラグで、メモリのソフト上限の予測に使います

環境変数と dotenv からは `agent run` と同じ設定項目をすべて読みます。
フラグの別名を持つのは上の項目だけです。
`WGFT_WG_INTERFACE` は環境変数か dotenv で渡し、空なら `wgft0` として扱います。
`agent run` と違い、`WGFT_DATA_DIR` の空と同時フロー数の上限の範囲だけを検査し、他の値は検査しません。

dotenv を権限で読めない場合は拒否せず、診断の所見にします。
このとき設定はフラグ、環境変数、既定だけから決めます。
dotenv の構文の誤りは終了コード 3 の拒否です。
権限以外の理由で読めない場合、たとえばパスがディレクトリの場合は終了コード 1 です。

| 終了コード | 意味 |
| --- | --- |
| 0 | 判定に使う項目に FAILED が無い |
| 1 | 判定に使う項目に FAILED がある |
| 2 | 権限で証拠を読めず報告が決まらない。引数かフラグの誤り。JSON を書けなかった |
| 3 | 設定の誤り |

2 は 1 より優先します。
終了コード 2 と 3 では、報告を作る前に止まるので、標準出力に JSON を書きません。
誤りは標準エラーに書きます。

### wgft agent teardown

停止したカーネルモードの agent がカーネルに残したものと、`agent.json` のカーネルモードの記録を消します。
手順と出力は [10.3 節](../operations/setup.md#103-運用の流れ)にあります。
フラグは次のとおりです。

- `--config`:dotenv のファイル
- `--data-dir`:`WGFT_DATA_DIR` の別名
- `--wg-interface`:`WGFT_WG_INTERFACE` の別名
- `--dry-run`:真偽値のフラグで、消すものを書くだけで何も消しません。
  1 回限りの操作なので、環境変数と dotenv では受け取りません

Linux 以外では、設定を読む前に種別 `prerequisite`、対象 `operating system` で拒否します。
次に `WGFT_DATA_DIR` の空と `WGFT_WG_INTERFACE` の値を、`agent run` と同じ文面で検査します。

| 終了コード | 場合 |
| --- | --- |
| 0 | 消し終えた。消すものが無かった。`--dry-run` で書き終えた |
| 1 | agent が動いている。指したディレクトリに `agent.json` が無い。その他の失敗 |
| 3 | Linux でない。`CAP_NET_ADMIN` が足りない。`agent.json` が知らないモードを記録している。設定の誤り |

### wgft version と --version

`wgft version` は標準出力に 2 行を書きます。

```text
v1.5.0
protocol range: v1-v1
```

1 行目は版です。
リリースのバイナリでは、そのリリースのタグそのものです([配布物の互換性](../compatibility/surfaces.md))。
ビルドの時に版を埋めていない場合は Go のモジュールの版を使い、それも無ければ `dev` です。
2 行目は、このバイナリが扱う wire の版の範囲で、`v<最小>-v<最大>` の形です。
`wgft --version` と `wgft -v` は 1 行目だけを書きます。
引数を付けると終了コード 1 で止まります。

### wgft agent join-string

VPS で、新しい agent のための接続文字列を 1 回だけ発行します。
接続文字列の形は [接続文字列、登録、証明書のピン](join.md)にあります。
フラグは次のとおりです。

- `--name`:必須で、agent の名前です。
  検査は server が行います
- `--admin`:`WGFT_ADMIN` の別名で、管理用 API の場所です。
  既定は `unix:///run/wgft/admin.sock` です
- `--config`:dotenv のファイルで、既定は OS ごとの `server.env` です。
  Linux では `/etc/wgft/server.env` です

成功すると、標準出力に接続文字列を 1 行で書きます。
標準エラーには `expires <expires_at>. it contains a #, so write it into dotenv as-is without quotes` を 1 行で書きます。
`<expires_at>` は管理用 API の応答の値で、RFC 3339 の時刻です。
`--name` が無い場合と管理用 API の失敗は終了コード 1 です。
設定の誤りは終了コード 3 の拒否です。
接続文字列は秘密なので、agent には `--join` ではなく `WGFT_JOIN` で渡します。
フラグの値は `ps` で他の利用者に見え、シェルの履歴に残るためです。

## 設定の受け取り方

### 優先順位

1 つの設定項目は `WGFT_*` の環境変数で受け取ります。
dotenv はそのファイルでの書き方、フラグはその別名です([11a 節](../security/configuration.md#11a-設定の渡し方))。
優先順位はフラグ、環境変数、dotenv、既定の順です。
優先順位と名前の対応は互換性の保証に含まれます([設定の互換性](../compatibility/surfaces.md))。

- フラグ:コマンドラインに書いたフラグです。
  値が既定と同じでも、出所はフラグです
- 環境変数:プロセスの環境にある変数です。
  値が空でも、あれば dotenv と既定に優先します
- dotenv:ファイルにあるキーです。
  値が空でも、あれば既定に優先します
- 既定:どこにも無い場合の値です

文字列のフラグは書いた値をそのまま使います。
整数のフラグの値は、解釈した整数を 10 進で書き直したものです。
解釈の規則は後述の Go の性質に書きます。

設定を読むのは、コマンドの入口で 1 回だけです。
稼働中に dotenv を書き換えても、次の起動まで効きません。

### dotenv のファイルの場所

dotenv のパスは `--config`、`WGFT_CONFIG`、既定の順で決めます。
`WGFT_CONFIG` は環境変数でだけ受け取り、dotenv の中の `WGFT_CONFIG` は読みません。
`--config ""` と空の `WGFT_CONFIG` は空のパスを指し、存在しないファイルと同じに扱います。

| OS | agent の既定 | `WGFT_DATA_DIR` の既定 |
| --- | --- | --- |
| Linux と他の Unix | `/etc/wgft/agent.env` | `/var/lib/wgft` |
| macOS | `$HOME/Library/Application Support/wgft/agent.env` | `$HOME/Library/Application Support/wgft` |
| Windows | `%ProgramData%\wgft\agent.env` | `%ProgramData%\wgft` |

既定はプロセスの起動の時に 1 回だけ決め、`--help` の既定の表示にも同じ値を出します。
macOS で `HOME` が空なら、どちらも作業ディレクトリの `wgft` を基にします。
Windows で `ProgramData` が空なら、`C:\ProgramData` を使います。
server と CLI の既定の dotenv は、同じディレクトリの `server.env` です。

### 知らない名前

dotenv と環境変数にある `WGFT_*` のうち、そのコマンドが読まない名前は、誤りにも警告にもせず無視します([11a 節](../security/configuration.md#11a-設定の渡し方))。
知らない名前と、`WGFT_ADMIN` や `WGFT_WG_ADDRESS` のような他のプロセス向けの名前の両方が対象です。
dotenv のキーは大文字と小文字を区別するので、`wgft_mode` は `WGFT_MODE` ではありません。
`WGFT_MODE` と `WGFT_WG_INTERFACE` は、server と agent が同じ名前で読みます。
同じファイルを両方に渡すと、同じ値が両方に効きます。

## 設定項目

`agent run` が読む設定項目は次のとおりです。
「使うモード」に無いモードでも、値の検査は入口で行います。
モードを切り替えたときに、起動の後半で初めて失敗しないためです。

| 名前 | フラグ | 既定 | 秘密 | 使うモード |
| --- | --- | --- | --- | --- |
| `WGFT_DATA_DIR` | `--data-dir` | OS ごと(上の表) | いいえ | 両方 |
| `WGFT_JOIN` | `--join` | 空 | はい | 両方 |
| `WGFT_NAME` | `--name` | 空 | いいえ | 両方 |
| `WGFT_MODE` | `--mode` | 空。`userspace` を指す | いいえ | 両方 |
| `WGFT_WG_INTERFACE` | `--wg-interface` | `wgft0` | いいえ | kernel |
| `WGFT_AGENT_NETSTACK` | `--agent-netstack` | 空。`gvisor` を指す | いいえ | userspace |
| `WGFT_AGENT_BATCH_MIB` | `--agent-batch-mib` | 空。フロー数の上限から導く | いいえ | userspace で wgstack のとき |
| `WGFT_AGENT_ALLOW_TARGETS` | `--agent-allow-targets` | 空。制限しない | いいえ | 両方 |
| `WGFT_MAX_UDP_FLOWS` | `--max-udp-flows` | `8192` | いいえ | userspace |
| `WGFT_MAX_TCP_FLOWS` | `--max-tcp-flows` | `2048` | いいえ | userspace |

`WGFT_MAX_UDP_FLOWS_PER_SOURCE` と `WGFT_MAX_TCP_FLOWS_PER_SOURCE` は server だけの設定で、agent は読みません。
agent から見た接続元は常に server のトンネルのアドレスで、接続元ごとに数える意味が無いためです。

拒否の文面は `refusing to start [config <名前>]: <理由>` の形です。
下の各項の「誤り」には `<理由>` の部分を書きます。
`%q` は値を Go の引用の規則で囲んだものです(後述の Go の性質)。

### WGFT_DATA_DIR

認証情報ファイル `agent.json` と、その隣の `.lock` と `.sock` を置くディレクトリです([agent.json と .lock と .sock](credentials.md))。
`agent run` は無ければ作ります。
作れなければ `data dir: <理由>` の誤りで、終了コード 1 です。

- 誤り:前後の空白を除いて空なら `is empty; give the directory that holds agent.json`
- 空白の扱い:検査は前後の空白を除いて行い、パスには値をそのまま使います

### WGFT_JOIN

初回の登録と、恒久トークンが拒否された後の登録のし直しに使う接続文字列です。
構文は [接続文字列、登録、証明書のピン](join.md)にあります。
秘密です。

入口では構文を拒否しません。
登録済みの agent は compose に残った古い `WGFT_JOIN` を読まないので、入口で拒否すると、動いていた agent が値の誤りだけで止まるためです([11a 節](../security/configuration.md#11a-設定の渡し方))。
空でなく構文が誤っていれば、入口で警告を 1 行書いて起動を続けます。
構文の判定は登録の直前に行い、そこで誤っていれば拒否します。
拒否の一覧は終了コードの節にあります。

### WGFT_NAME

登録で送る agent の名前です。
接続文字列が名前に結び付いているので、ふつうは空のままにします。
agent は値を検査しません。
名前の規則は server が判定し、HTTP 400 の応答は対象 `WGFT_NAME` の `config` の拒否になります。
登録済みの名前と違う値なら、次の行をログに書いて登録済みの名前を使います。

```text
WGFT_NAME=<値> differs from the registered name <名前>; keeping <名前>
```

### WGFT_MODE

転送の方式です([11a 節](../security/configuration.md#11a-設定の渡し方))。
空は `userspace` を指します。
`kernel` は Linux だけで使えます。
値は大文字と小文字を区別し、前後の空白も値の一部です。

- 誤り:空、`kernel`、`userspace` 以外なら `must be kernel or userspace, not %q`
- Linux 以外の `kernel`:種別 `prerequisite` で、理由は `the agent's kernel mode needs Linux, and this is <OS>; leave WGFT_MODE unset or set it to userspace` です。
  `<OS>` は `windows` か `darwin` です

記録との照合と切り替えの関門は、認証情報ファイルを読んだ後に行います(終了コードの節)。

### WGFT_WG_INTERFACE

カーネルモードの WireGuard のインタフェースの名前です。
判定は Linux のカーネルの `dev_valid_name` に合わせ、名前をバイト列として調べます。

- 空:`is empty; give the WireGuard interface name, for example wgft0`
- 15 バイトを超える:`%q is longer than the 15 bytes the kernel allows for an interface name`
- `.` と `..`:`%q is not a usable interface name`
- 使えないバイト:`%q contains byte 0x<2 桁の小文字の 16 進>, which is not usable in an interface name; /, :, %, a NUL byte and whitespace including 0xa0 are not allowed`

使えないバイトは `/`、`:`、`%`、NUL、`0x09` から `0x0D`、`0x20`、`0xA0` です。
最初に見つかったバイトを示します。
`0xA0` は UTF-8 の文字の 2 バイト目にも現れるので、`wgà` も拒否します。

### WGFT_AGENT_NETSTACK

ユーザー空間モードの netstack の実装です([実装の選択](../userspace/wgstack.md#実装の選択))。
空は `gvisor` を指します。
`wgstack` は実験的で、起動時に警告を 1 行書きます。

- 誤り:空、`gvisor`、`wgstack` 以外なら `must be gvisor or wgstack, not %q`

カーネルモードでは使いません。
出所が既定でなければ、値が空でも使わない旨を 1 行書きます。

### WGFT_AGENT_BATCH_MIB

wgstack の送信の向きのバッチの予算を MiB で表します([P_max の決め方](../userspace/wgstack-batching.md#p_max-の決め方))。
空は既定の式、`0` はバッチを使わないことを表します。

- 受け付ける値:0 以上の 10 進の整数です。
  先頭の `+` と、先頭の 0 を受け付けます。
  `-0` は 0 です
- 大きすぎる値:int64 を超える正の値も受け付け、上限に丸めます
- 誤り:それ以外は `%q is not a whole number of MiB of at least 0; 0 turns send batching off`。
  前後の空白、小数、単位、int64 を超える負の値はここに入ります

- Go の性質:予算を buffer の数に直す式は、wireguard-go の buffer の大きさとキューの長さ、CPU の数から決まります。
  上限は CPU の数で決まるので、上限を超える値は誤りにせず丸めます。
  Go 以外の実装は、受け付ける値の集合と誤りの文面を同じにします。
  値から何を導くかは、その実装の送信の経路に合わせて決めます。

### WGFT_AGENT_ALLOW_TARGETS

server が agent に送らせてよい宛先の一覧です([11a 節](../security/configuration.md#11a-設定の渡し方))。
値の前後の空白を除いて空なら、制限しません。

- 区切り:コンマで区切ります。
  各項目の前後の空白は除き、空の項目は飛ばします
- 項目の形:`CIDR`、`CIDR:ポート`、`CIDR:下限-上限` のどれかです。
  アドレスだけの項目は IPv4 で `/32`、IPv6 で `/128` です
- IPv6 のポート:`[2001:db8::/32]:8080` のように角括弧で囲みます。
  ポートの無い IPv6 の項目は角括弧が無くても書けます
- ポート:10 進の 1 から 65535 です。
  先頭の 0 は受け付け、符号は受け付けません。
  下限は上限以下です
- 正規化:プレフィクスの host の部分を 0 にし、IPv6 は小文字の短い形にします。
  同じポートの範囲は 1 つのポートとして書きます。
  順序と重複はそのまま保ちます

次の挙動は Go の `net/netip` の性質から来ます。
v1 が受け付けた `agent.env` を Rust の agent が拒むと更新で止まるので、Go 以外の実装も同じ値を受け付け、同じ意味に読みます。
`testdata/spec/config/allow-targets.json` がこの例を持ちます。

- 空のポート:`10.0.0.1:` と `[2001:db8::1]:` はポートの無い項目として受け付けます
- 角括弧の IPv4:`[10.0.0.1]:80` を受け付けます
- 角括弧の無い IPv6 のポート:`2001:db8::1:80` は、`2001:db8::1:80/128` という 1 つのアドレスになります

誤りの文面は次のとおりです。
最初に誤った項目で止まります。

- 項目が 1 つも無い:`WGFT_AGENT_ALLOW_TARGETS: %q has no entries; leave it unset to allow every target`。
  `%q` は値の全体です
- アドレスの形:`WGFT_AGENT_ALLOW_TARGETS: entry %q is not a CIDR, CIDR:port or CIDR:lo-hi`
- ポート:`WGFT_AGENT_ALLOW_TARGETS: entry %q port is not an integer in 1-65535`
- ポートの順:`WGFT_AGENT_ALLOW_TARGETS: entry %q port range is not in lo-hi order`
- 角括弧:`... entry %q has no closing bracket` と `... entry %q has trailing text after the brackets`
- ゾーン:`... entry %q must not carry an IPv6 zone`
- IPv4 を写した IPv6:`... entry %q is an IPv4-mapped IPv6 address; write it as IPv4`

入口の拒否では、この文面の全体が理由になります。
設定の名前は `[config WGFT_AGENT_ALLOW_TARGETS]` と理由の先頭の両方に出ます。

- Go の性質:アドレスとプレフィクスの解釈は Go の `net/netip` に従います。
  IPv4 の各部の先頭の 0(`010.0.0.1`)とプレフィクス長の範囲外は誤りです。
  Go 以外の実装は、`testdata/spec/config/allow-targets.json` の入力に同じ結果を出すように解釈します。

### WGFT_MAX_UDP_FLOWS と WGFT_MAX_TCP_FLOWS

プロセス全体の同時フロー数の上限です([7 節](../agent-dataplane.md#7-データプレーン自宅側))。
メモリのソフト上限もこの 2 つから導きます。

- 受け付ける値:16 から 65535 の整数です。
  環境変数と dotenv では、先頭の `+` と先頭の 0 を受け付けます
- 誤り:`%q is not an integer between 16 and 65535`。
  前後の空白、空、`0x400` のような基数の接頭辞はここに入ります
- 検査の順:UDP を先に検査します

カーネルモードでは使いません。
どちらかの出所が既定でなければ、使わない旨を 1 行書きます。
フラグで渡す値の解釈は環境変数と違います(後述の Go の性質)。

### GOMEMLIMIT

- Go の性質:`GOMEMLIMIT` は Go のランタイムが読む環境変数で、wgft の設定項目ではありません。
  dotenv には書けず、優先順位の外にあります。
  値が誤っていると、Go のランタイムは wgft のコードより前に `fatal error: malformed GOMEMLIMIT; see ...` を書き、終了コード 2 で止まります。
  この 2 は wgft の終了コード 2 とは無関係です。

`agent run` は起動時に次のどちらかの行を書きます。

- `GOMEMLIMIT` が空でない:`memory soft limit: GOMEMLIMIT=<値>; set by the environment`。
  ランタイムの値を変えません
- それ以外:`memory soft limit: <N> MiB, derived from the flow caps; set GOMEMLIMIT to override`。
  ソフト上限を `32 MiB + 12 KiB × UDP の上限 + 44 KiB × TCP の上限` に設定します。
  `<N>` はバイト数を MiB で割った切り捨てで、既定の上限では 216 です

この上限は GC の目標で、メモリの上限ではありません([メモリのソフト上限との関係](../resource/integration.md))。
Go 以外の実装に、同じ値を設定する先はありません。
この行は保証の外なので、Go 以外の実装は書かなくてかまいません。
`agent doctor` の報告が予測を含む扱いは [制御ソケットと agent doctor --json](control-socket.md) に従います。

### 入口での検査の順

`agent run` は認証情報ファイル、トンネル、待ち受けに触れる前に、値だけから判定できる誤りをすべて拒否します([11b 節](../security/startup.md#11b-起動の失敗の意味論))。
複数の誤りがあれば、次の順で最初の 1 つだけを示します。

1. dotenv の読み取りと構文
2. `WGFT_DATA_DIR` の空
3. `WGFT_MODE` の値
4. Linux 以外での `WGFT_MODE=kernel`
5. `WGFT_WG_INTERFACE`
6. `WGFT_AGENT_NETSTACK`
7. `WGFT_MAX_UDP_FLOWS`、`WGFT_MAX_TCP_FLOWS`
8. `WGFT_AGENT_BATCH_MIB`
9. `WGFT_AGENT_ALLOW_TARGETS`
10. `WGFT_JOIN` の構文です。
    拒否せず警告だけを書きます

### 設定ファイルの権限の警告

Unix では、秘密の設定項目の空でない値を dotenv から読み、そのファイルを other が読める場合に、警告を 1 行書いて起動を続けます([11a 節](../security/configuration.md#11a-設定の渡し方))。
判定はパーミッションの `0o007` のビットだけで行い、group のビットは見ません。
agent の秘密の設定項目は `WGFT_JOIN` だけです。

```text
warning: <パス> is readable by other users on this host and holds a secret value, WGFT_JOIN; recommended mode is 0600, or 0640 owned by root and a dedicated group; see docs/design.md 11a
```

この判定は設定を読むたびに行います。
`WGFT_JOIN` を読む `agent run` と `agent doctor` で出ます。
`pubkey`、`rotate-key`、`teardown` は `WGFT_JOIN` を読まないので出しません。
Windows では判定しません。

## dotenv の構文

dotenv は、systemd、Docker の `--env-file`、compose の `env_file` の解釈が一致する範囲だけを受け付けます([11a 節](../security/configuration.md#11a-設定の渡し方))。
読む規則は次のとおりです。

- 行:ファイルを LF で行に分けます。
  行末の CR はすべて除きます。
  最後の行に LF が無くてもかまいません
- 空行:何も無い行は飛ばします。
  空白だけの行は空行ではなく、誤りです
- コメント:行頭の `#` で始まる行だけがコメントです。
  前に空白がある `#` はコメントではありません。
  値の中の `#` は値の一部です
- 形:最初の `=` で `KEY` と値に分けます。
  値の中の 2 つ目からの `=` は値の一部です
- キー:空は誤りです。
  前後に Unicode の空白があるか、空白かタブを含むと誤りです。
  それ以外の文字は受け付け、知らない名前は呼び出し側が無視します
- 値:空を受け付けます。
  `"` か `'` で始まると誤りです。
  空白かタブを含むと誤りです。
  途中の引用符と、CR、垂直タブ、`U+00A0` のような他の空白は値の一部です
- 重複:同じキーが複数あれば、最後の行が勝ちます
- 文字コード:バイト列を UTF-8 として扱い、BOM を特別に扱いません。
  先頭の BOM は最初のキーの一部になるので、その行はどの設定にも当たりません

`export KEY=value` は、キーが空白を含むので誤りです。

### 読み取りの誤り

- ファイルが無い:誤りにせず、空のファイルと同じに扱います
- 権限で読めない:種別 `config`、対象はパスの拒否です。
  理由は事実だけを並べ、どちらの側の原因かを断定しません
- その他:パスがディレクトリの場合などは普通の誤りで、終了コード 1 です

権限の拒否の理由は、Unix では次の形です。

```text
<OS の誤り>; this process runs as uid <実効 uid>, gid <実効 gid>, and the file is mode <4 桁の 8 進> with owner uid <uid> and group gid <gid>
```

ファイル自身を stat できない場合は、`and the file is mode ...` の代わりに `and the file's own owner and mode could not be read, so a directory above it refuses the way in: <stat の誤り>` を続けます。
Windows では `; who may read it is decided by the file's DACL, which this build does not evaluate` を続けます。
`<OS の誤り>` の末尾の句点と空白は除きます。

`agent run` と `agent teardown` は、この理由の後ろに直し方を足します。

```text
It may hold WGFT_JOIN, so let the agent's group read it rather than every local user; with the provided agent.service, which runs the agent as the wgft user: chown root:wgft <パス> && chmod 0640 <パス>. If the file already has that owner, group and mode, the user that read it here is not the one the agent runs as
```

`pubkey` と `rotate-key` は直し方を足しません。
`agent doctor` は拒否にせず、診断の所見にします。

- Go の性質:`<OS の誤り>` は Go の `*os.PathError` の文で、`open <パス>: permission denied` の形です。
  Unix では、ファイルが無いことの判定は `ENOENT` だけで、パスの途中がファイルである `ENOTDIR` は普通の誤りになります。
  Go 以外の実装が同じ文面を出すには、この形を自分で組み立てます。
  文面は保証の外です。

### 構文の誤り

構文の誤りは種別 `config` の拒否で、対象は `<パス>:<行番号>` です。
行番号は 1 から数え、CRLF の行も 1 行と数えます。
最初に誤った行で止まります。
文面には行の中身も値も出しません。
行が `WGFT_JOIN` の接続文字列のような秘密を含みうるためです([11a 節](../security/configuration.md#11a-設定の渡し方))。

| 誤り | 理由の文面 |
| --- | --- |
| `=` が無い、またはキーが空 | `not in KEY=value form; the line is not shown, since it may hold a secret` |
| キーに空白 | `key name may not contain whitespace; the line is not shown, since it may hold a secret` |
| 値が引用符で始まる | `do not quote the value of <キー>; Docker keeps quotes as part of the value` |
| 値に空白かタブ | `the value of <キー> may not contain whitespace` |

`<キー>` は、キーが ASCII の英数字と `_` だけでできていればそのキーで、それ以外は `this key` です。
行が壊れていると、`=` より前に値の一部が入りうるためです。
引用符の検査は空白の検査より先に行います。

## 終了コード

| 終了コード | 意味 | 使うコマンド |
| --- | --- | --- |
| 0 | 成功。`agent run` はシグナルで止まった場合 | すべて |
| 1 | 拒否でない失敗。再試行で直りうる | すべて |
| 2 | 求められた報告を作れなかった | `agent doctor` |
| 3 | 起動の拒否。人が手を入れなければ直らない | すべて |

拒否の判定は [11b 節](../security/startup.md#11b-起動の失敗の意味論)の非対称の規則に従います。
3 は、原因が設定された値そのものであるか、運用者の操作なしには消えないと示せる場合だけに使います。
示せない失敗は 1 です。
拒否を別の誤りが包んでも、終了コードは 3 のままです。

### 拒否の文面

拒否は標準エラーの 1 行で、次の形です。

```text
Error: refusing to start [<種別> <対象>]: <理由>. <直し方>
```

- 種別:`config`、`prerequisite`、`conflict`、`mode-gate` のどれかです
- 対象:`WGFT_*` の名前か、資源の名前です。
  空なら `[<種別>]` になります
- 直し方:無ければ `. <直し方>` を書きません
- 書き出し:常駐プロセスを起動する `agent run` だけが `refusing to start` です。
  他のコマンドは `cannot continue` です。
  終了コードはどちらも 3 です
- 包んだ誤り:外側の誤りの文が前に付きます。
  たとえば `re-register failed: refusing to start [...]: ...` です

`Error: ` の接頭辞は後述の Go の性質です。
書き出しと `[種別 対象]` の形は 11b 節の決定です。
理由と直し方の文面は保証の外です。

### agent の拒否

`agent run` が拒否する場合は次のとおりです。
入口の値の誤りは設定項目の節にあります。

| 場合 | 種別 | 対象 | 理由 |
| --- | --- | --- | --- |
| dotenv を権限で読めない | `config` | パス | 上の dotenv の節 |
| dotenv の構文 | `config` | `パス:行` | 上の dotenv の節 |
| Linux 以外での `kernel` | `prerequisite` | `WGFT_MODE` | 上の `WGFT_MODE` の節 |
| カーネルモードを持たないビルド | `prerequisite` | `WGFT_MODE` | `this build does not include the agent's kernel mode yet, so it cannot start in kernel mode; use a build that includes it` |
| `CAP_NET_ADMIN` が無い | `prerequisite` | `CAP_NET_ADMIN` | カーネルモードの前提の検査([7b.5 節](../kernel-agent/operations.md#7b5-権限と配置)) |
| カーネルの WireGuard が無い | `prerequisite` | `wireguard module` | 同上 |
| 記録したモードが `kernel` でも `userspace` でもない | `conflict` | `WGFT_MODE` | `the credentials file agent.json records the mode %q, which is neither kernel nor userspace; ...` |
| 記録が `kernel` で `WGFT_MODE` が空 | `mode-gate` | `WGFT_MODE` | `WGFT_MODE is unset, which means userspace, but the credentials file agent.json records kernel mode; ...` |
| 記録が `kernel` で `WGFT_MODE=userspace` | `mode-gate` | `WGFT_MODE` | `changing mode from kernel to userspace: ...` |
| 未登録で `WGFT_JOIN` が空 | `config` | `WGFT_JOIN` | `not registered and no join string; provide via WGFT_JOIN or --join` |
| 未登録で `WGFT_JOIN` の構文の誤り | `config` | `WGFT_JOIN` | 接続文字列の固定の誤りの文([join.md](join.md)) |
| 未登録で `WGFT_JOIN` が使用済み | `conflict` | `WGFT_JOIN` | `this join string is already used; issue a new join string` |
| 登録の応答が HTTP 401 | `conflict` | `WGFT_JOIN` | `registration rejected: join string already used or expired, or the name differs. Issue a new join string on the VPS with wgft agent join-string, and replace WGFT_JOIN` |
| 登録の応答が HTTP 400 | `config` | `WGFT_NAME` | `the registration API rejected the request: HTTP 400, <応答の本文>; an agent name may hold ...` |
| 登録の応答が HTTP 409 | `conflict` | `WGFT_JOIN` | `an agent is already registered under the name this join string carries: HTTP 409, <応答の本文>. ...` |

モードの照合と関門の意味は [11a 節](../security/configuration.md#11a-設定の渡し方)にあります。
関門と前提で止まる起動は、`agent.json` に何も書かず、接続文字列も使いません。
未登録で `WGFT_JOIN` が空の場合は、鍵を作って `agent.json` に保存した後に拒否します。

稼働中に stream の認証が拒否される(HTTP 401)と、登録のし直しを試みます([5.1 節](../control/registration.md#51-登録))。
次の場合はプロセスを終え、終了コード 3 で止まります。

| 場合 | 種別 | 理由 |
| --- | --- | --- |
| `WGFT_JOIN` が空 | `config` | `permanent token was revoked; provide a new join string via WGFT_JOIN and restart` |
| `WGFT_JOIN` の構文の誤り | `config` | 接続文字列の固定の誤りの文 |
| `WGFT_JOIN` が使用済み | `conflict` | `permanent token was revoked and the local join string is already used; issue a new join string and replace WGFT_JOIN` |
| 登録のし直しの応答が 401、400、409 | 上の表と同じ | `re-register failed: ` に続けて上の表の拒否の文 |

登録のし直しのその他の失敗は `re-register failed: <誤り>` で、終了コード 1 です。

### 拒否でない失敗

次の失敗は終了コード 1 です。
相手が資源を手放すか、時間が経てば、次の起動で直りうるためです。

- 二重起動:`credentials file is in use by another process`
- データディレクトリを作れない:`data dir: <誤り>`
- 登録の API に届かない:`cannot reach the registration API: <誤り>`
- 登録の API の 429 と 5xx:`registration API: HTTP <番号>: <応答の本文>`
- 登録の API の応答が壊れている:`registration API returned an invalid response`
- 同名の WireGuard のインタフェースが別の鍵を持つ:カーネルモードの所有の判定([11b 節](../security/startup.md#11b-起動の失敗の意味論))
- フラグと引数の誤り:後述の Go の性質

応答の本文は最大 4096 バイトまで読み、前後の空白を除いて文に入れます。

### 同梱の unit と終了コード

- `deploy/agent.service`:`Restart=on-failure`、`RestartSec=2`、`RestartPreventExitStatus=3` です。
  終了コード 3 では再起動しません
- `deploy/agent.compose.yaml`:`restart: unless-stopped` です。
  Docker は終了コードを区別せず、3 でも再起動を繰り返します
- `deploy/io.github.rahanahu.wgft.agent.plist`:`KeepAlive` の `SuccessfulExit` が偽で、`ThrottleInterval` は 10 秒です。
  launchd は 3 でも再起動を繰り返します
- `deploy/Dockerfile.agent`:`ENTRYPOINT` は `wgft agent run` です

unit のファイル名と `ExecStart`、`RestartPreventExitStatus=3` は互換性の保証に含まれます([配布物の互換性](../compatibility/surfaces.md))。

## 起動ログ

`agent run` は起動の時に標準エラーへ次の順で書きます。
`<ts>` の付いた行は、Go の `log` の既定の形の時刻で始まります(後述の Go の性質)。
`<ts>` の無い行は時刻を付けずに書きます。

1. 設定ファイルの権限の警告です。
   条件は上の節にあります
2. `<ts> warning: WGFT_JOIN is malformed: <固定の誤りの文>; it is used only for a first registration or after a revocation, so this agent starts if it is already registered` です。
   `WGFT_JOIN` が空でなく構文が誤っている場合だけです
3. `effective config:` の行と、有効な設定の行
4. メモリのソフト上限の行(`GOMEMLIMIT` の節)
5. 送信の向きのバッチの行(下の表)
6. カーネルモードで使わない設定の行(下の表)
7. `<ts> warning: WGFT_AGENT_NETSTACK=wgstack selects wgft's own TCP/IP stack for the userspace mode; it is experimental, and its transfer quality and resource behavior are not covered by the compatibility guarantee` です。
   ユーザー空間モードで `wgstack` の場合だけです
8. `<ts> changing mode from <旧> to <新>; recording it in the credentials file` です。
   `userspace` から `kernel` へ切り替える場合だけです
9. `<ts> wgft <版> agent starting: name <名前>, mode <モード>, data dir <ディレクトリ>` です。
   未登録なら `<名前>` は `not registered yet` です
10. 宛先の許可一覧の行(下の表)
11. `<ts> generated wg key pair; public key: <公開鍵>` です。
    鍵を作った場合だけです
12. 登録の行です。
    初回の登録では `<ts> registered as agent <名前>; assigned <アドレス>, API <host:port>` を書きます。
    登録済みで未使用の接続文字列が渡された場合は `<ts> already registered; ignoring the provided join string and using the existing permanent token` を書きます

拒否は、それまでに書いた行の後に 1 行で書きます。
入口の拒否では、3 より後の行を書きません。

### 有効な設定の行

`effective config:` の行の後に、設定項目ごとに 1 行を書きます。
順序は名前の昇順で、書式は次のとおりです。

```text
  %-22s = %-28s from %s
```

- 名前:左詰めで 22 文字に満たない分を空白で埋めます。
  長い名前は切りません
- 値:左詰めで 28 文字に満たない分を空白で埋めます。
  長い値は切りません。
  値は受け取ったとおりで、正規化しません
- 秘密:秘密の設定項目の値は、空でなければ `****` に置き換えます。
  空なら空のままです
- 出所:`flag`、`env`、`file`、`default` のどれかです

値の中の改行や制御文字は、そのまま書きます。
例を示します。

```text
effective config:
  WGFT_AGENT_ALLOW_TARGETS =                              from default
  WGFT_AGENT_BATCH_MIB   =                              from default
  WGFT_AGENT_NETSTACK    =                              from default
  WGFT_DATA_DIR          = /srv/wgft                    from env
  WGFT_JOIN              = ****                         from file
  WGFT_MAX_TCP_FLOWS     = 2048                         from default
  WGFT_MAX_UDP_FLOWS     = 8192                         from default
  WGFT_MODE              =                              from default
  WGFT_NAME              =                              from default
  WGFT_WG_INTERFACE      = wgft0                        from default
```

すべての設定を値と出所付きで書き、秘密を伏せることは 11a 節の要件です。
書式は保証の外です。
`testdata/spec/config/effective-config.json` が v1 の書式を固定し、Go の試験が照らします。

### 送信の向きのバッチの行

| 条件 | 行 |
| --- | --- |
| カーネルモードで値が空でない | `<ts> WGFT_AGENT_BATCH_MIB: unused in kernel mode, which runs no network stack in the process; the setting is kept so the same agent.env works in both modes` |
| `gvisor` で値が空でない | `<ts> WGFT_AGENT_BATCH_MIB: unused with the gvisor network stack, which sends one packet at a time; the setting is kept so the same agent.env works with both stacks` |
| カーネルモードか `gvisor` で値が空 | 書きません |
| `wgstack` で予算が 0 | `send batch budget: 0 MiB; WGFT_AGENT_BATCH_MIB=0 turns send batching off` |
| `wgstack` で予算が正 | `send batch budget: <%.1f> MiB, <buffer の数> buffers, <出所>` |

`<出所>` は次のどれかです。

- 上限に丸めた:`from WGFT_AGENT_BATCH_MIB lowered to the cap for this host's <CPU の数> CPUs`
- 値から:`from WGFT_AGENT_BATCH_MIB`
- 空で Windows:`the cap for this host's <CPU の数> CPUs; set WGFT_AGENT_BATCH_MIB to override`
- 空で Windows 以外:`derived from the flow caps; set WGFT_AGENT_BATCH_MIB to override`

予算がバッチを使える最小の数に満たない場合は、行の後ろに `; send batching is off because this host's <CPU の数> CPUs need at least <最小の数> buffers, <%.1f> MiB` を続けます。

### カーネルモードで使わない設定の行

カーネルモードでだけ、出所が既定でない設定について書きます。

- `WGFT_AGENT_NETSTACK`:`<ts> WGFT_AGENT_NETSTACK: unused in kernel mode, which runs no network stack in the process; the setting is kept so the same agent.env works in both modes`
- 同時フロー数の上限:`<ts> <名前>: unused in kernel mode, where the host's conntrack holds the flows; the setting is kept so the same agent.env works in both modes`。
  両方なら `<名前>` は `WGFT_MAX_UDP_FLOWS and WGFT_MAX_TCP_FLOWS` です

拒否にしないのは、モードを切り替えても同じ `agent.env` を使えるようにするためです([7b.1 節](../kernel-agent/installation.md#7b1-カーネルに置くもの))。

### 宛先の許可一覧の行

- 一覧が無い:`<ts> no target allowlist: WGFT_AGENT_ALLOW_TARGETS is not set; the server can direct this agent to any address it can reach`
- 一覧がある:`<ts> target allowlist WGFT_AGENT_ALLOW_TARGETS=<正規化した一覧>; the server can direct this agent only to these addresses`

### ログの保証

ログの行の書式、語順、語彙は保証の外です([ログ出力の互換性](../compatibility/surfaces.md))。
保証の外であっても、秘密をログに出さないことは [10.4 節](../operations/output.md#104-ログ)の約束です。
相手の実装と運用の道具は、上の行の文面に頼りません。

## 秘密を伏せる規則

agent の秘密の設定項目は `WGFT_JOIN` だけです。
恒久トークンと WireGuard の秘密鍵は `agent.json` にあり、設定項目ではありません。

- 有効な設定:`WGFT_JOIN` の値は空でなければ `****` で書きます
- dotenv の誤り:行の中身も値も出しません
- 接続文字列の誤り:固定の文だけを出し、接続文字列のどの部分も引用しません。
  ホストとポートの形が崩れた入力では、トークンがどの断片に入るかを判別できないためです([join.md](join.md))
- 権限の警告:`WGFT_JOIN` という名前だけを出し、値を出しません
- 登録の誤り:server の応答の本文を出しますが、送ったトークンは出しません
- 公開鍵:`generated wg key pair` の行と `pubkey` は公開鍵だけを出します

値を引用する誤りは、秘密でない設定項目だけにあります。
`WGFT_MODE`、`WGFT_WG_INTERFACE`、`WGFT_AGENT_NETSTACK`、`WGFT_AGENT_BATCH_MIB`、`WGFT_AGENT_ALLOW_TARGETS`、同時フロー数の上限が該当します。

`scripts/check-log-tokens.sh` は、ログの呼び出しのうちトークンに触れる行を人が確かめた一覧と照らす CI の検査です。
ログの形式を外部に約束するものではありません([ログ出力の互換性](../compatibility/surfaces.md))。

## Go の性質:コマンドラインの解釈

コマンドラインは Go の cobra と pflag が解釈します。
次の挙動は cobra と pflag だけで決まります。
Go 以外の実装は、ここに書いた挙動を再現すれば同じ結果になります。
保証の外と書いた項目は、再現しなくてかまいません。

- フラグの書き方:`--name value` と `--name=value` の両方を受け付けます。
  名前の省略形と、1 本のハイフンの長い名前は受け付けません。
  Go 以外の実装は両方の形を受け付け、他の形を拒みます
- 短い名前:`-h` はすべてのコマンドで `--help` です。
  `-v` はルートだけで `--version` です。
  他の短い名前はありません
- 真偽値のフラグ:`--json` と `--dry-run` は値を書かなければ真です。
  値は `--json=false` の形でだけ渡せます。
  `--json false` の `false` は引数になり、引数の誤りで止まります。
  受け付ける値は `1`、`t`、`T`、`TRUE`、`true`、`True`、`0`、`f`、`F`、`FALSE`、`false`、`False` です
- 整数のフラグ:Go の整数の書き方で解釈します。
  `0x`、`0o`、`0b` の接頭辞、先頭の 0 による 8 進、桁の間の `_` を受け付けます。
  `--max-udp-flows 016` は 14 で、範囲の誤りになります。
  同じ `016` を環境変数で渡すと 16 です。
  解釈した値を 10 進で書き直したものを、有効な設定の行と範囲の検査に使います
- 繰り返したフラグ:同じフラグを複数回書くと最後の値が勝ちます。
  agent のコマンドに、値を積み上げる一覧のフラグはありません。
  `--agent-allow-targets` を 2 回書いても一覧は合わさりません
- フラグの位置:フラグはサブコマンドの名前の前にも後にも書けます。
  `wgft agent --data-dir X pubkey` は `wgft agent pubkey --data-dir X` と同じです。
  `--` の後はすべて引数です
- 誤りの出力:誤りは標準エラーに `Error: <文>` の 1 行で書き、使い方は書きません。
  Go 以外の実装は同じ接頭辞を付けます
- 誤りの終了コード:フラグと引数の誤りは終了コード 1 です。
  `agent doctor` だけは 2 です
- 誤りの文:未知のフラグは `unknown flag: --x`、未知の短い名前は `unknown shorthand flag: 'd' in -d`、値の欠落は `flag needs an argument: --data-dir` です。
  値の解釈の誤りは `invalid argument "abc" for "--max-udp-flows" flag: strconv.ParseInt: parsing "abc": invalid syntax` です。
  余分な引数は `unknown command "extra" for "wgft agent pubkey"` です。
  必須のフラグの欠落は `required flag(s) "name" not set` です。
  文は保証の外です
- 未知のコマンド:`wgft foo` は `unknown command "foo" for "wgft"` と `Run 'wgft --help' for usage.` の 2 行で、終了コード 1 です。
  `wgft agent foo` は `wgft agent` の説明を標準出力に書き、終了コード 0 です。
  この違いは保証の外です
- ヘルプ:`-h`、`--help`、`wgft help <コマンド>` は説明を標準出力に書き、終了コード 0 です。
  余分な引数があっても説明を書きますが、未知のフラグがあれば誤りになります
- 付属のコマンド:cobra は `completion` を足し、シェルの補完のスクリプトを書きます。
  Go 以外の実装は持たなくてかまいません
- Windows のダブルクリック:エクスプローラーから起動されると、PowerShell から起動するよう案内する文を書き、Enter を待ちます。
  この挙動は保証の外です

出力と設定の値の扱いにも、Go の標準ライブラリの性質があります。

- 引用:誤りの文の `%q` は Go の `strconv.Quote` の規則です。
  ASCII の印字できる文字はそのまま書き、`"` と `\` の前に `\` を付けます。
  制御文字は `\t`、`\n`、`\x00` のように書きます。
  印字できる ASCII 以外の文字はそのまま書きます。
  Go 以外の実装が同じ文面を出すには、この規則で引用します
- 幅:有効な設定の行の `%-22s` と `%-28s` の幅は、バイトではなく Unicode のコードポイントで数えます
- 環境変数と dotenv の整数:`strconv.Atoi` は先頭の `+` と `-`、先頭の 0 を受け付け、空白、`_`、基数の接頭辞を受け付けません
- 時刻の形:`<ts>` は `2006/01/02 15:04:05` の形の地方時に空白を 1 つ続けたものです
- 環境変数の名前:Windows では大文字と小文字を区別せずに引けます。
  未確認です

## fixture

| ファイル | 中身 | Go の試験 |
| --- | --- | --- |
| `dotenv.json` | 読める dotenv と読み取った対応表、読めない dotenv と行番号と理由 | `TestSpecConfigDotenv` |
| `effective-config.json` | 決めた入力に対する有効な設定の行の全体 | `TestSpecConfigEffectiveConfig` |
| `values.json` | `agent run` の入口で拒否する値と文面、通る値 | `TestSpecConfigValuesAtTheDoor` |
| `allow-targets.json` | `WGFT_AGENT_ALLOW_TARGETS` の正規化と誤りの文 | `TestSpecConfigAllowTargets` |
| `refusals.json` | 拒否の文面の組み立てと、終了コードの振り分け | `TestSpecConfigRefusalsAndExitCodes` |

どれも `testdata/spec/config/` にあり、各ファイルの `description` が項目の意味を述べます。
入力のバイト列を正確に保つため、dotenv の中身も JSON の文字列として持ちます。
`values.json` の `goos` は、その場合を判定する OS の名前です。

## 未確認の点

- macOS と Windows の既定のパス:コードから写したもので、この文書のために実機で確かめていません
- Windows の環境変数の名前:大文字と小文字を区別しない引き方は Go と Windows の文書による推測で、確かめていません
- Windows の権限の拒否の文面:Windows の実機で確かめていません
- 稼働中の stream の認証の拒否からの拒否:コードから写したもので、この文書のために動かしていません
- 登録の応答ごとの拒否:HTTP 401、400、409 の扱いはコードから写したもので、この文書のために動かしていません
- シグナルで止めたときの終了コード 0:コードから写したもので、この文書のために動かしていません
- `rotate-key` の出力の行と `agent teardown` の終了コード:コードと `--help` から写したもので、この文書のために動かしていません
- カーネルモードの拒否の理由の全文:`CAP_NET_ADMIN` の場合だけを Linux で確かめ、他は確かめていません

[agent と server の境目の仕様](README.md)
