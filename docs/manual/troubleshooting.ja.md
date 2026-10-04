# 転送が届かない場合の診断

[English](troubleshooting.md) | 日本語

VPS で `server doctor` を実行し、結果が agent 側を示す場合は agent のホストを調べます。
診断結果は現在の観測で、履歴を保持せず、外部クライアントからサービスを利用できることまでは証明しません。
server が起動していない場合は、先に [server check](../cli.md#wgft-server-check) と起動ログを確認します。

## 1. VPS で対象のルールを特定する

付属の Linux systemd 手順で導入した場合は、VPS で実行します。

```sh
sudo wgft server doctor
sudo wgft rule ls
```

最初のコマンドは server、agent、各ルールを一覧で診断します。
ルール一覧の ID を指定すると、公開側から転送先までをルールごとに診断できます。

```sh
sudo wgft server doctor r_01M2R009
```

`r_01M2R009` を対象のルールの ID に置き換えます。
コマンドは稼働中の server の管理 API を読み、既定の接続先は `/run/wgft/admin.sock` です。
接続先を変えた場合は、server と同じ `WGFT_ADMIN` を使います。
Docker では、[Docker 手順の CLI の実行方法](setup-docker.ja.md#vps-の-server)に従って server のコンテナ内で実行します。
Web UI からもルールごとに診断できます。

| 状態 | 意味と次の確認 |
| --- | --- |
| `OK` | 観測した検査に成功しました。観測時刻を確認してください。成功した観測も時間が経つと古くなります。 |
| `FAILED` | 検査で失敗を確認しました。理由と次の確認の案内に従います。 |
| `UNKNOWN` | 証拠が古い、矛盾する、または不足しています。現在の agent の報告や不足している証拠を確認します。 |
| `NOT TESTED` | コマンドが検査しない条件です。外部からの接続やアプリケーションで確認します。 |
| `SKIPPED` | 先行する失敗で検査できないか、設定で転送を無効にしています。先にその条件を確認します。 |

切断した agent の `last:` は保存した観測で、現在の状態ではありません。
無効にしたルールや agent は設定どおり転送を停止しているため、`server doctor` の失敗には数えません。
有効に戻す前に、停止が意図したものか確認します。

## 2. agent のホストを調べる

agent と同じ利用者、同じデータディレクトリで診断します。
付属の Linux systemd unit の場合は、次を実行します。

```sh
sudo runuser -u wgft -- wgft agent doctor
```

README のディレクトリでフォアグラウンド実行している場合は、次の指定を使います。

README のバイナリで `agent doctor` を呼び出し、`--data-dir ~/.wgft` を指定します。
[agent doctor のデータディレクトリの指定](../cli.md#wgft-agent-doctor)は、稼働中の agent と同じパスに合わせてください。
認証情報がないと表示された場合は、接続文字列を再発行したり agent を失効させたりする前にパスを確認します。
登録済みの名前での新規登録は拒否され、失効は既存の agent を切断します。
Windows と macOS では、[デスクトップの導入手順](setup-desktop.ja.md)と同じ利用者と認証情報の保存先を使います。
Docker のコンテナ内で診断するコマンドは [agent の導入手順](setup-docker.ja.md#自宅側の-agent)にあります。

`agent doctor` は認証情報、ホストの情報、稼働中の agent のローカル制御ソケットを読みます。
API と WireGuard の接続先の名前を解決しますが、転送先へは接続しません。
既存のロックファイルに対する短い共有ロックが起動と重なる場合があります。
その場合、付属の systemd unit はロックを取れなかった起動を再試行します。
root で診断すると agent の利用者のファイル権限の問題を確認できないため、`host.privileges` は `UNKNOWN` になります。

ユーザー空間モードでは、停止した agent は転送できず、プロセスの検査が失敗します。
カーネルモードではプロセスの停止後も設定済みの転送が継続するため、インタフェース、nftables のテーブル、転送設定で判定します。
停止したカーネルモードの agent を調べる場合は `sudo wgft agent doctor` を使います。
`CAP_NET_ADMIN` がなくカーネルの証拠を読めない場合、終了コードは 2 です。
転送先とサービスの条件は[カーネルモードのエージェント](agent-kernel.ja.md)にあります。

## 3. 診断で検査しない通信の確認

VPS 自身からは、外部から公開 DNAT ポートへ接続できることを確認できません。
TCP は別のホストから接続するか、実際のサービスのクライアントで確認します。
UDP は実際のクライアントを使い、サービスの応答を確認してください。
UDP を送るだけでは到達を確認できません。
そのため、UDP の転送先は待ち受けが開いていても `NOT TESTED` のままになる場合があります。
最後の応答の値は観測事実で、この判定を変えません。

TCP の場合は、server からトンネルと agent を通して転送先へ 1 回接続する診断もできます。

`--probe` は転送先に実際の接続を作り、TCP のルールを 1 つずつ指定します。
`--from` は指定したアドレスをルールの allow/deny リストと照合します。
外部クライアントとして接続したり公開側の firewall を検査したりする指定ではありません。
`--probe` を省くと `server doctor` は転送先へ接続しません。

## よくある診断結果

| 結果 | 確認と対応 |
| --- | --- |
| 公開側から届かない | VPS の firewall で UDP 51820 と TCP 8443 に加え、転送する TCP/UDP ポートも許可します。Docker のブリッジネットワークを使う server では、compose に転送ポートの公開も指定します。 |
| agent が転送先を拒否した | 稼働中の agent の `WGFT_AGENT_ALLOW_TARGETS` とルールを照合します。両モードでブロードキャストとマルチキャストを拒み、カーネルモードには LAN の転送先の条件もあります。[転送先の制限](operations.ja.md#エージェントの転送先を制限する)と[カーネルモードの転送先](agent-kernel.ja.md)を確認します。 |
| ユーザー空間モードで `bind failed` と `not active` | ポートを使っているプロセスを確認します。公開ポートがホストの一時ポートと重なる場合は、範囲外のポートを選ぶか `net.ipv4.ip_local_reserved_ports` で予約します。 |
| Linux のソケットバッファの警告 | [ソケットバッファの手順](socket-buffers.ja.md)でホストを設定し、agent または server を再起動してソケットを開き直します。Docker ではコンテナのホストを設定します。agent のバッファの検査は失敗しても終了コードを変えません。 |
| server のログに `startup hold` | 保存済みのルールを適用できず、管理 API を開いたまま再試行しています。`wgft rule rm` または `wgft rule disable` で原因のルールを修正します。カーネルモードではプロセスの再起動後も旧い転送が残る場合があるため、`wgft server nft` で確認します。 |
| `ip-flapping` | 直近 10 分以内に使ったネットワークへの復帰で警告が出ました。予定どおりの移動なら `sudo wgft agent dismiss-warning home ip-flapping` で削除します。それ以外は鍵や恒久トークンの複製を疑い、`wgft agent warnings --help` を確認します。 |

## ログと終了コード

付属の systemd unit のログは、次のコマンドで読みます。

```sh
sudo journalctl -u wgft -b
sudo journalctl -u wgft-agent -f
```

`server started` は転送と API の準備ができたことを示します。
問題が始まった時刻を調べる場合はログを確認します。

| コード | `server doctor` | `agent doctor` |
| --- | --- | --- |
| 0 | `FAILED` の検査がありません。 | モードの判定に使う項目に `FAILED` がありません。 |
| 1 | 少なくとも 1 つの検査が `FAILED` です。 | 少なくとも 1 つの判定項目が `FAILED` です。 |
| 2 | 管理 API に接続できない、ルールがないなどの理由で結果を作れませんでした。 | 権限不足で判定を完了できず、終了 1 より優先します。不正な引数も結果を作る前に終了 2 になります。 |
| 3 | 設定が不正です。 | 設定が不正です。 |

終了 0 でも、不明な条件、未検査の条件、意図した停止を含む場合があります。
サービスが動作している証拠として扱う前に、個別の検査を読んでください。
`--json` でも診断の終了コードは同じです。
全オプション、機械向けの項目、判定条件は [server doctor](../cli.md#wgft-server-doctor) と [agent doctor](../cli.md#wgft-agent-doctor) のリファレンスにあります。

[利用者向けの手順](README.ja.md) · [転送と運用](operations.ja.md)
