# 導入済みの wgft の更新

[English](upgrade.md) | 日本語

wgft の入れ替えでは、server のデータディレクトリと agent の認証情報を保持します。
登録済みの agent の `agent.json` がデータディレクトリにあれば、更新時の接続文字列の再発行は不要です。
更新前に、対象の版の[リリースノート](https://github.com/rahanahu/wgft/releases)を確認します。

## 保持するデータと設定

| 導入方法 | 永続データ | 設定 |
| --- | --- | --- |
| Linux systemd server | `/var/lib/wgft`。付属の `DynamicUser` unit では実体は `/var/lib/private/wgft` です。 | `/etc/wgft/server.env`、導入した unit、ローカルの drop-in |
| Linux systemd agent | `/var/lib/wgft/agent.json` とデータディレクトリ | `/etc/wgft/agent.env`、導入した unit、カーネルモードの drop-in |
| README の Linux フォアグラウンド agent | `~/.wgft` | 起動時のフラグと環境変数 |
| Windows agent | `%ProgramData%\wgft\agent.json` | 起動する利用者、フラグ、環境変数 |
| デスクトップ手順の macOS agent | `~/Library/Application Support/wgft` | LaunchDaemon の plist と起動設定 |
| Docker | `/var/lib/wgft` にマウントした名前付きボリューム | 編集した compose ファイル |

`WGFT_DATA_DIR` または `--data-dir` を指定した場合は、そのディレクトリを保持します。
server のデータベースは鍵と証明書を、agent の認証情報は秘密を含みます。
バックアップは非公開にし、所有者と権限を保持します。

更新前に server のデータディレクトリ全体、設定、agent のデータディレクトリをバックアップします。
SQLite のデータベースをファイルとしてコピーする場合は、コピー中にデータベースと WAL ファイルが変わらないよう server を停止します。
agent の認証情報をコピーする場合も agent を停止します。
バイナリを入れ替える前に、バックアップが存在し、読み取れることを確認します。
バックアップ後は既存のサービスを起動し、次のバイナリ交換を両側が稼働した状態から始めます。
付属の server unit のデータディレクトリはシンボリックリンクを使うため、リンクだけでなく実体の内容を保存する必要があります。

## Linux バイナリと systemd の更新

[Linux のセットアップ](setup.ja.md)で導入済みで、既存の service unit、モード、設定を保持する手順です。
[バイナリの導入コマンド](setup.ja.md#1-バイナリをインストールする)でバイナリとチェックサムを取得します。
特定の版に更新する場合は、`latest` ではなく対象のリリースを選びます。
アーキテクチャに合わせて `amd64` または `arm64` を選んでください。
登録と利用者の作成は繰り返しません。

バックアップ後、VPS で server のバイナリを入れ替え、service を再起動します。

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
sudo systemctl restart wgft
sudo wgft server check
sudo wgft agent ls
sudo wgft rule ls
```

起動ログを確認し、既存の agent が再接続した後に自宅側を更新します。
自宅の Linux マシンで agent のバイナリを入れ替えます。

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
sudo systemctl restart wgft-agent
sudo runuser -u wgft -- wgft agent doctor
```

VPS の外部から実際のサービスのクライアントでルールを確認します。
起動や転送が復旧しない場合は[診断手順](troubleshooting.ja.md)で調べます。
ユーザー空間モードの転送はプロセスとともに停止します。
カーネルモードではプロセスの再起動中も転送が残る場合がありますが、更新中のセッションの維持や一定時間での復旧は保証しません。

リリースノートで unit の更新が必要とされた場合は、セットアップ手順の unit の導入と `daemon-reload` を実行し、ローカルの設定を保持します。
バイナリだけの更新では unit とカーネルモードの drop-in は変わりません。
モードの変更は別の操作です。
カーネルモードの agent は[モードの変更手順](agent-kernel.ja.md#ユーザー空間モードへ戻す)に従います。

## デスクトップとコンテナの更新

Windows では、フォアグラウンドの agent を停止し、[デスクトップの導入手順](setup-desktop.ja.md#windows-で-agent-を実行する)と同じ方法で新しいバイナリのチェックサムを確認します。
実行ファイルを入れ替え、同じ利用者で起動します。
`%ProgramData%\wgft\agent.json` を保持するため、接続文字列の再発行は不要です。

macOS では、[デスクトップの導入手順](setup-desktop.ja.md#macos-で-agent-を実行する)で新しいバイナリを検証して導入します。
付属の LaunchDaemon は、入れ替え前に公開済みの `launchctl bootout` コマンドで停止し、入れ替え後に `launchctl bootstrap` コマンドで起動します。
認証情報のディレクトリと設定した `UserName` を保持します。
この更新方法は公開済みの導入と停止、起動の手順を組み合わせたもので、LaunchDaemon の更新としては未確認です。

Docker では、コンテナの交換や再作成時に両方の名前付き状態ボリュームを保持し、対象の版のイメージと compose の変更を確認します。
`docker compose ... down -v` はボリュームを削除するため、更新ではなく削除の操作です。
[Docker の導入手順](setup-docker.ja.md)は永続マウントとコンテナの起動を説明していますが、イメージの更新手順としては未確認です。

## 旧版へ戻す場合の制限

更新後に旧版へ戻すことは保証しません。
v1.2.0 以降の server のデータベースはスキーマの版 9 を使い、v1.1.x 以前の server は開きません。
バイナリだけを旧版に戻しても、データベースの移行は取り消されません。
復旧の検討に備えて更新前のバックアップと旧版のバイナリを保持します。
自動で旧版へ戻すコマンドやバックアップを復元するコマンドはありません。

カーネルモードの agent を v1.1.x へ戻す前には、v1.2 以降のバイナリで `agent teardown` を実行します。
[カーネルモードのエージェント](agent-kernel.ja.md#ユーザー空間モードへ戻す)の手順に従ってください。
agent の teardown は登録と鍵を保持します。
server の teardown に `--purge` を付けると登録と鍵を削除するため、更新には使いません。
互換性の保証の対象と除外は[互換性の規範](../design/compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)にあります。

[利用者向けの手順](README.ja.md) · [診断手順](troubleshooting.ja.md)
