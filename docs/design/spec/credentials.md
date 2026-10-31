# agent.json と .lock と .sock

agent の認証情報は `agent.json` の 1 ファイルにあります。
登録の結果、WireGuard の秘密鍵、最後に適用した全体状態、カーネルモードの記録を持ちます。
同じディレクトリに、二重起動を防ぐ `agent.json.lock` と、稼働中の agent への指示を受ける `agent.json.sock` を置きます。
理由と運用の扱いは[状態の保存と再起動](../state.md#9-状態の保存と再起動)、[設定の渡し方](../security/configuration.md)、[互換性](../compatibility/surfaces.md)にあります。

Rust の agent は v1 の `agent.json` をそのまま読みます。
v1 と Rust の agent が同じデータディレクトリで同時に動かないことは、同じロックの方式で守ります。

## 置き場所

データディレクトリは `WGFT_DATA_DIR` で、既定は OS ごとに決まります ([cli-config.md](cli-config.md))。

| OS | 既定のデータディレクトリ |
| --- | --- |
| Linux とその他の Unix | `/var/lib/wgft` |
| macOS | `~/Library/Application Support/wgft` (Go の `os.UserConfigDir` に `wgft` を足した値。引けなければ相対の `wgft`) |
| Windows | `%ProgramData%\wgft` (`ProgramData` が空なら `C:\ProgramData\wgft`) |

ファイルの名前は固定です。

| ファイル | 名前 | 中身 |
| --- | --- | --- |
| 認証情報 | `<データディレクトリ>/agent.json` | 下の JSON |
| ロック | `agent.json.lock` | 空。ロックを取るためだけに使います |
| 制御ソケット | `agent.json.sock` | AF_UNIX のソケット。Windows でも AF_UNIX です ([control-socket.md](control-socket.md)) |
| 書き換えの一時ファイル | `.wgft-credentials-<乱数>` | 書き終えてから `agent.json` へ rename します |

- ディレクトリの作成:agent は起動のときにデータディレクトリが無ければ権限 0700 で作ります。
  既にあるディレクトリの権限は変えません。
  Windows では、新しく作ったディレクトリにだけ、下の DACL を継承付きで付けます
- 一時ファイルの片付け:agent はロックを取った後、データディレクトリにある `.wgft-credentials-` で始まる通常のファイルを消します。
  書き換えの途中で落ちた残りです

## agent.json のキー

`agent.json` は 1 つの JSON のオブジェクトです。
キーの順は表の順です。

| キー | 型 | 省略 | 意味 |
| --- | --- | --- | --- |
| `name` | 文字列 | 省きません | 登録で確定した agent の名前。未登録なら `""` |
| `endpoint` | 文字列 | 省きません | エージェント用 API の `host:port`。接続文字列の endpoint のまま |
| `cert_sha256` | 文字列 | 省きません | エージェント用 API の証明書の SHA-256。小文字の 16 進 64 桁 |
| `permanent_token` | 文字列 | 省きません | 恒久トークン。秘密です |
| `used_join_token_sha256` | 文字列 | 省きません | 最後に登録に使った登録トークンの SHA-256。小文字の 16 進 64 桁 |
| `wg_private_key` | 文字列 | 省きません | WireGuard の秘密鍵 (base64、44 文字)。秘密です。`agent rotate-key` の停止中の実行の後は `""` です |
| `last_state` | オブジェクトか `null` | 省きません | 最後に適用した全体状態。中身は [messages.md](messages.md#state) の `State` で、版のフィールドも server が送ったまま持ちます |
| `mode` | 文字列 | 空なら省きます | 転送の方式の記録。`kernel` か `userspace`。無ければ `userspace` とみなします |
| `previous_wg_private_key` | 文字列 | 空なら省きます | 1 つ前の WireGuard の秘密鍵。カーネルモードの記録を持つファイルでだけ書きます。秘密です |
| `ip_forward_enabled_at` | 時刻 | 無ければ省きます | カーネルモードの agent が `net.ipv4.ip_forward` を 0 から 1 にした時刻 |
| `kernel_publication` | 任意の JSON | 無ければ省きます | カーネルモードの直近の公開の記録 |
| `kernel_unconverged` | 任意の JSON | 無ければ省きます | conntrack の収束が済んでいない前の公開の記録の配列 |
| `tunnel_address` | 文字列 | 空なら省きます | 登録で割り当てられたトンネルのアドレス。`10.200.0.2/24` か `10.200.0.2` の形 |

- 未登録のファイル:初回の起動は、登録の前に鍵だけを作って保存します。
  そのファイルは `name`、`endpoint`、`cert_sha256`、`permanent_token`、`used_join_token_sha256` が `""` で、`last_state` が `null` です
- `mode` の書き方:ユーザー空間モードの agent は `mode` を書きません。
  ユーザー空間モードの記録のファイルでカーネルモードを指定して起動すると、`kernel` を書きます。
  カーネルモードからユーザー空間モードへの切り替えは、`agent teardown` が記録を消すまで終了コード 3 で拒みます。
  `kernel` と `userspace` のどちらでもない記録も終了コード 3 で拒みます
- `tunnel_address` の書き方:登録の応答のアドレスを帯の長さを付けずに書き、最初に適用した全体状態の `wg.address` で帯の長さを付けた形に置き換えます。
  記録と違う `wg.address` が届いたとき、ユーザー空間モードは警告を 1 行出して使い、カーネルモードは拒みます。
  記録を置き換えるのは登録のし直しだけです
- `kernel_publication` と `kernel_unconverged`:中身はカーネルモードの実装の内部の形で、この文書群では定めません。
  ユーザー空間モードの実装は中身を解釈せず、読んだまま書き戻します
- 秘密:`permanent_token`、`wg_private_key`、`previous_wg_private_key` は秘密です。
  agent はこの 3 つをログと誤りの文言に出しません

### 書き方

- 形:Go の `json.MarshalIndent` で 2 つの空白で字下げし、末尾に改行を付けません。
  HTML のための書き換えをします ([encoding.md](encoding.md#go-の性質html-のための書き換え))
- 置き換え:同じディレクトリに一時ファイルを作り、権限 0600 にしてから中身を書き、`fsync` してから `agent.json` へ rename します。
  途中で落ちても `agent.json` は前の中身か新しい中身のどちらかです
- 既存のファイルの種別:`agent.json` が既にあって通常のファイルでなければ、何も書かずに誤りにします。
  symbolic link も辿らずに誤りにします
- 持ち主:root のプロセスが他の利用者の持つ `agent.json` を書き換えるときは、一時ファイルの持ち主とグループを元のファイルに合わせます。
  合わせられなければ警告を出して保存を続けます
- 大きさの上限:書く中身が 512 MiB を超えるなら書かずに誤りにします

### 読み方

- 種別:最後の要素が symbolic link なら辿らずに誤りにし、通常のファイルでなければ誤りにします。
  種別と大きさは開いた記述子で確かめます
- 大きさの上限:512 MiB を超えるファイルは読まずに誤りにします
- 無いファイル:`agent run` は空の認証情報として扱い、鍵を作って保存します
- JSON の読み方:[encoding.md](encoding.md#読む側の規則) のとおりです。
  Go の性質として、v1 は知らないキーを読み飛ばし、次の書き換えで落とします。
  Rust の実装は知らないキーを書き戻しても構いません。
  v1 は書き戻したキーを読み飛ばすので、v1 に戻しても動きます

fixture は次のとおりです。
秘密の値は本物ではない値に置き換えてあります。

| fixture | 中身 |
| --- | --- |
| `testdata/spec/credentials/agent-userspace.json` | ラボで登録して全体状態を適用した、ユーザー空間モードの agent の `agent.json` |
| `testdata/spec/credentials/agent-kernel.json` | ラボのカーネルモードの agent の `agent.json`。`mode`、`kernel_publication` を持ちます |
| `testdata/spec/credentials/agent-rotated.json` | 停止中に `agent rotate-key` を実行した後の `agent.json` |
| `testdata/spec/credentials/agent-unregistered.json` | 登録の前に鍵だけを保存した `agent.json` |

`internal/agent/credentials` の `spec_test.go` が、Go の v1 がこれらを読み、同じ byte 列に書き戻すことを確かめます。

## ロック (agent.json.lock)

`agent run` は起動の最初に `agent.json.lock` の排他ロックを取り、終わるまで持ちます。
取れなければ `credentials file is in use by another process` の誤りで止まります。

- ファイルの開き方:無ければ権限 0600 で作り、symbolic link を辿らずに開き、通常のファイルでなければ誤りにします
- Unix のロック:`flock(LOCK_EX | LOCK_NB)` です。
  Linux のローカルのファイルシステムでは `fcntl` のロックと `flock` のロックは互いに見えないので、Go 以外の実装も `flock` を使わなければなりません。
  NFS のようなネットワークのファイルシステムでの振る舞いは未確認です
- Windows のロック:`LockFileEx(LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY)` で、範囲は offset 0 からの 1 byte です
- 差し替えの検出:ロックを取った後、開いたファイルとそのパスのファイルが同じかを確かめます。
  違えば開き直し、4 回試してだめなら誤りにします
- ロックの中身:ファイルは空のままで、PID などを書きません
- 停止中の操作:`agent rotate-key`、`agent pubkey`、`agent teardown` は、ロックファイルがあって誰も持っていなければロックを取ってから `agent.json` を書きます。
  ロックファイルが無ければ作らずに進みます。
  作ると呼び出した利用者の権限のファイルが残り、後から非特権で動く agent の起動を塞ぐためです

## Windows の DACL

Windows では、`agent.json`、`agent.json.lock`、`agent.json.sock`、書き換えの一時ファイルに、継承を切った DACL を付けます。
許すのは SYSTEM、BUILTIN\Administrators、実行中の利用者の 3 者で、どれもフルアクセスです。
SDDL では `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;<実行中の利用者の SID>)` です。

- 一時ファイル:作成の時点からこの DACL で作ります。
  作ってから締めると、締めるまでの間に他の利用者がハンドルを開けるためです
- 既存のファイル:`agent.json` を読むたびと、ロックを取るたびに、そのファイルにこの DACL を付け直します。
  緩い ACL の下で作られた古いファイルを締めるためです
- 制御ソケット:開いた直後にこの DACL を付けます。
  付けられなければソケットを閉じて、制御ソケットを使わずに動きます
- 新しく作ったデータディレクトリ:同じ 3 者に、子へ継承する `OICI` を添えた DACL を付けます。
  既にあるディレクトリには付けません
- Unix:`agent.json` と一時ファイルは権限 0600 です。
  既にある `agent.json` とロックファイルの権限は変えません。
  管理者が意図して締めた 0400 を緩めず、ボリュームのファイルを持たない構成で chmod が失敗しないためです。
  制御ソケットは 0600 にし、失敗は無視します

[agent と server の境目の仕様](README.md)
