# セットアップ

この文書には、README から分離した詳細なインストール・運用手順をまとめています。

## 動作環境

VPS 側は Linux で動作します。自宅側の agent は Windows amd64 でも動作し、Windows 11 で実機確認済みです。Apple シリコンの macOS でも動作し、macOS 27 で実機確認済みです。Intel Mac には対応していません。wgft は現在 IPv4 のみに対応しています。

自宅側のエージェントには root 権限も TUN デバイスも不要です。VPS 側の要件は動作モードで変わります。

| | カーネルモード `kernel` | ユーザー空間モード `userspace` |
|---|---|---|
| VPS の root 権限 | 必要 | 不要 |
| カーネル / nftables | Linux 6.1 以上、nftables 1.0.6 以上 | 不要 |
| 転送経路 | カーネル WireGuard + nftables DNAT | wireguard-go + ユーザー空間 netstack |
| wgft プロセス停止・クラッシュ時 | 設定済みの転送は継続 | 転送も停止 |
| レート制限の判定場所 | カーネル | wgft プロセス |
| `wgft server` のメモリ | 通常の DNAT ルールはほぼ一定。proxy モードの TCP は接続数に応じて増える | フロー数に応じて増え、同時フロー数の上限で抑える |

カーネルモードでは、wgft が WireGuard / nftables の実行時状態を作った後は、wgft プロセスがクラッシュまたは再起動しても、その状態がカーネルに残るため転送は継続します。一方、VPS 自体を再起動すると実行時状態は失われるため、wgft service が再び起動して状態を作り直す必要があります。通常運用では付属の systemd unit を有効にしておいてください。

VPS で root が使えるならカーネルモードを推奨します。ユーザー空間モードは、root が使えない環境、カーネルに WireGuard がない環境、コンテナだけで完結させたい場合向けです。

ユーザー空間モードでは、`wgft server` 自身がルールの listen port で待ち受けます。この listen port がホストのエフェメラルポートの範囲(Linux の既定は 32768-60999、`net.ipv4.ip_local_port_range`)に入っていると、VPS 上のどのプロセスの外向きの接続でも、その番号を送信元ポートとして使っているあいだや、切断後 60 秒の TIME_WAIT のあいだは、server の bind と衝突します。衝突すると bind は失敗し、ルールは宣言に残ったまま not active として報告されます。理由は `bind failed: listen tcp4 :<port>: bind: address already in use` で、server のログには `rule <id>: not active: bind failed: ...` の行が出て、Web UI のルールの状態にも同じ理由が表示されます。`wgft rule ls --json` の `rule_states` にも同じ理由が入ります。`wgft server` は 30 秒ごとに適用をやり直すため、ポートが空けば自然に回復します。`SO_REUSEADDR` はこの衝突を防ぎません。カーネルモードでは VPS 上で公開ポートを待ち受けるプロセスが無いため、この問題は起きません。衝突を避けるには、listen port をエフェメラルポートの範囲外から選ぶか、`sysctl net.ipv4.ip_local_reserved_ports=<ports>` で予約してください。

カーネルモードでは、ルール集合をカーネルへ 1 つの nftables バッチとして適用します。wgft はこのバッチに合わせて netlink ソケットのバッファの大きさを調整します([design.md](design.md) の 6.1 節)。付属の systemd unit でカーネルモードを動かしたラボでは、1 回の `rule import` によるバッチでも 1 本ずつの `rule add` による追加でも、2000 本までのルール集合を適用できました。2000 本を超える規模は確かめていません。文書にあるカーネルモードの配置には、`net.core.rmem_max` と `net.core.wmem_max` で制限されるものがありません。付属の systemd unit は、この 2 つの sysctl の値を超えてバッファを要求するための権限を wgft に与えます。Docker の配置はユーザー空間モードだけを対象にしており、カーネルモードを対象にしていません。

カーネルモードは、ホストの conntrack の表にも依存します。`wgft server check` と起動時のログは、`nf_conntrack_max` が wgft の推奨する下限 65536 を下回っている場合に警告し、上げるための `sysctl -w net.netfilter.nf_conntrack_max=65536` を提示します。

フローには、ルールごと、接続元アドレスごと、プロセス全体の 3 段の同時数の上限があります。agent は接続元アドレスを区別できないため、ルールごととプロセス全体の 2 段だけを適用します。`wgft server` は、ユーザー空間モードでは 3 段とも Go で適用します。カーネルモードでは、DNAT ルールの通信は nftables が転送し、`wgft server` を経由しません。そのため、DNAT ルールには接続元アドレスごとの上限だけを nftables の `ct count` で適用します。proxy モードのルールの TCP 接続は、カーネルモードでも `wgft server` が終端します。そのため、proxy モードのルールにはユーザー空間モードと同じく 3 段とも適用します。上限に達すると新しいフローだけを拒否し、既存のフローは切りません。カーネルモードでも、自宅側の agent は中継を行うため、agent の上限の対象です。

プロセス全体の上限は `WGFT_MAX_UDP_FLOWS` と `WGFT_MAX_TCP_FLOWS` で設定し、既定値はそれぞれ 8192 と 2048 です。server と agent は別プロセスなので、必要ならそれぞれに設定してください。wgft はこの 2 つの値から Go ランタイムのメモリのソフト上限を計算し、起動時に表示します。開発用ラボでは、ユーザー空間モードの server で既定値の上限を埋め、さらに大量の通信を送ったときの最大 RSS は 208 MiB でした。`WGFT_MAX_UDP_FLOWS=2048` と `WGFT_MAX_TCP_FLOWS=1024` では同じ負荷を 150 MiB の cgroup 制限内で動かせました。実際の 256 MiB VPS ではまだ確認していません。systemd では、必要なら付属 unit のコメント例を使って `MemoryMax=` を起動時に表示されるソフト上限より大きい値に設定できます。

1 つのルールが全体の容量を独占しないよう、wgft は内部でルールごとの上限も設けます。この上限は設定項目ではありません。新しいフローを受け付けているルールが 1 本だけなら、そのルールはプロセス全体の上限のすべてを保持できます。2 本以上あるときは、1 本のルールはプロセス全体の上限の半分(切り上げ)で止まり、残りの半分は他のルールのために予約されるので、1 本のルールへのフラッドの最中も他のルールが新しいフローを通せます。接続元アドレスごとの上限は `wgft server` だけの設定項目で、`WGFT_MAX_UDP_FLOWS_PER_SOURCE`(既定 256)と `WGFT_MAX_TCP_FLOWS_PER_SOURCE`(既定 128)を全ルールの合計に対して適用し、1 つの接続元アドレスがルールの上限を埋めて他の利用者を締め出すことを防ぎます。プロセス全体の上限と連動しないため、メモリに余裕がありプロセス全体の上限を上げた運用者も、この設定を明示して上げない限り接続元ごとの上限は既定値のままです。0 にするとそのプロトコルの上限を無効にできます。agent にはこの設定項目がありません。agent から見た相手は server だけなので、どのフローも同じアドレスから来ているように見えるためです。

## 1. バイナリをインストールする

同じバイナリに server、agent、CLI が含まれています。VPS のイメージや Proxmox の LXC テンプレートのような最小構成のイメージは、curl を含まないことがあります。あらかじめ `sudo apt install curl` のように導入してください。

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64.sha256
sha256sum -c wgft-linux-amd64.sha256
```

arm64 環境では `amd64` を `arm64` に置き換えてください。Windows と macOS での手順は、[Windows で agent を実行する](#windows-で-agent-を実行する)と[macOS で agent を実行する](#macos-で-agent-を実行する)で説明します。

Go 1.27 以上があれば次でもインストールできます。

```sh
go install github.com/rahanahu/wgft/cmd/wgft@latest
```

## 2. VPS を設定する

wgft は `WGFT_*` 環境変数で設定します。systemd 構成では `/etc/wgft/server.env` を読み込みます。全設定項目は [deploy/server.env.example](../deploy/server.env.example) にあります。

### カーネルモード

バイナリを配置し、最小限の設定を作ります。

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
sudo mkdir -p /etc/wgft
printf 'WGFT_MODE=kernel\nWGFT_WG_ENDPOINT=vps.example.com:51820\n' | sudo tee /etc/wgft/server.env
sudo chmod 0644 /etc/wgft/server.env
```

初回起動前に設定を確認します。

```sh
sudo wgft server check
```

`check` は、有効な設定、同じ server key を持つ WireGuard インタフェースの残骸、既存 firewall に必要な forwarding 許可を表示します。加えて、host 自身の input firewall が wgft 自身のポート(WireGuard と agent API)や、wgft が host 上で受けるルールの listen port(カーネルモードはプロキシモードのルール、ユーザー空間モードは全ルール)を塞いでいないかも検査し、追加する行を提示します。firewall 自体は変更しません。

wgft は既存の firewall 設定を変更しません。カーネルモードでは IPv4 forwarding が必要なため、必要に応じて `net.ipv4.ip_forward=1` を有効にします。`wgft server teardown` は、元に戻す必要がある設定も表示します。

WireGuard 用の UDP 51820 と agent API 用の TCP 8443 を開けます。ufw の例:

```sh
sudo ufw allow 51820/udp
sudo ufw allow 8443/tcp
```

firewalld の例:

```sh
sudo firewall-cmd --permanent --add-port=51820/udp --add-port=8443/tcp
sudo firewall-cmd --reload
```

付属の systemd unit を使う場合:

```sh
sudo install -m 0644 deploy/server.service /etc/systemd/system/wgft.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgft
```

`/etc/wgft/server.env` は秘密情報を含まず、付属の service は非特権の動的ユーザーで動作するため、意図的に 0644 にします。旧版のセットアップ手順でインストールした環境では 0600 のままになっている場合があるため、service の起動・再起動前に `sudo chmod 0644 /etc/wgft/server.env` を実行してください。root で動作する旧 unit から移行する場合も同様です。

手動で試す場合:

```sh
sudo wgft server run
```

### systemd でユーザー空間モードを使う

カーネルモードと同じ unit を使い、モードだけ変更します。

```sh
printf 'WGFT_MODE=userspace\nWGFT_WG_ENDPOINT=vps.example.com:51820\n' | sudo tee /etc/wgft/server.env
```

UDP 51820、TCP 8443、および転送する各ポートを VPS の firewall で開けてください。ユーザー空間モードでは `wgft server` が停止すると転送も停止します。

### root なしでユーザー空間モードを使う

設定とデータをホームディレクトリに置きます。

```sh
install -d -m 0700 ~/wgft
printf 'WGFT_MODE=userspace\nWGFT_WG_ENDPOINT=vps.example.com:51820\nWGFT_DATA_DIR=%s/wgft\nWGFT_ADMIN=unix://%s/wgft/admin.sock\n' "$HOME" "$HOME" > ~/wgft/server.env
chmod 0600 ~/wgft/server.env
wgft server run --config ~/wgft/server.env
```

通常ユーザーでは 1024 未満のポートを直接 bind できません。この構成では、以降の `sudo` の代わりに `--config ~/wgft/server.env` を付けて CLI を実行します。

### Docker でユーザー空間モードを使う

server コンテナはユーザー空間モードで動きます。リポジトリを clone し、[deploy/server.compose.yaml](../deploy/server.compose.yaml) の `WGFT_WG_ENDPOINT` を設定して起動します。

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
# deploy/server.compose.yaml の WGFT_WG_ENDPOINT を編集
docker compose -f deploy/server.compose.yaml up -d
```

転送するポートは compose の `ports:` に列挙する必要があります。`network_mode: host` を使えば列挙は不要ですが、非特権コンテナでは 1024 未満のポートを bind できません。

コンテナ利用時の CLI は次の形で実行します。

```sh
docker compose -f deploy/server.compose.yaml exec wgft-server wgft ...
```

## 3. 自宅側エージェントを登録する

VPS で一度だけ使える join string を発行します。

```sh
sudo wgft agent join-string --name home
```

join string は 1 回だけ使用でき、1 時間で期限切れになります。`#` を含むため shell から渡す場合は引用符で囲んでください。

join string は秘密の値です。持っている人は誰でもこのエージェントとして登録できます。以下の例は `WGFT_JOIN` を環境変数か dotenv ファイルに設定する形を使い、コマンドラインのフラグには渡しません。フラグの値は `ps` から他の利用者にも見え、shell の履歴にも残るためです。

### バイナリとして起動する

```sh
chmod +x wgft-linux-amd64
mkdir -p ~/.local/bin ~/.wgft
mv wgft-linux-amd64 ~/.local/bin/wgft
WGFT_JOIN='<join string>' ~/.local/bin/wgft agent run --data-dir ~/.wgft
```

初回登録に成功すると `~/.wgft/agent.json` が作成されます。2 回目以降は次だけで起動できます。

```sh
wgft agent run --data-dir ~/.wgft
```

### Windows で agent を実行する

[Releases ページ](https://github.com/rahanahu/wgft/releases) から `wgft-windows-amd64.exe` と `wgft-windows-amd64.exe.sha256` を取得します。ファイルを保存したフォルダで PowerShell を開きます。例えば Downloads フォルダです。次のコマンドでダウンロードを検証します。

```powershell
if ((Get-FileHash -Algorithm SHA256 .\wgft-windows-amd64.exe).Hash -ne (Get-Content .\wgft-windows-amd64.exe.sha256).Split(' ')[0]) {
    throw "SHA256 mismatch"
}
```

一致すれば何も表示されず、そのまま次に進めます。一致しなければ例外を投げてスクリプトを止めるため、ハッシュが合わないバイナリをそのまま実行することを防げます。`Get-FileHash` はハッシュを大文字で返し、公開されている `.sha256` ファイルは小文字であるため、PowerShell の `-ne` が大文字と小文字を区別せずに比較する点が重要です。続けて次を実行します。

```powershell
Rename-Item wgft-windows-amd64.exe wgft.exe
$env:WGFT_JOIN = '<join string>'
.\wgft.exe agent run
```

Explorer で .exe をダブルクリックすると、PowerShell から実行するよう促す文章を表示し、Return キーを押すまでウィンドウを閉じずに待ちます。

join string は `#` を含むため、PowerShell では単一引用符で囲みます。初回登録に成功すると `%ProgramData%\wgft\agent.json` が作成されます。既定のこの場所は管理者権限を必要としません。2 回目以降は次だけで起動できます。

```powershell
.\wgft.exe agent run
```

wireguard-go が UDP をすべてのインタフェースで待ち受けるため、初回起動時に Windows Defender Firewall が `wgft.exe` の受信を許可するかどうかのダイアログを出すことがあります。Windows 11 の実機で、このダイアログを許可してもキャンセルしても、WireGuard の鍵の再交換をまたいでトンネルと中継が動作し続けることを確認しました。agent は外向きの接続だけを使うためです。停止は Ctrl+C を押すか、コンソールのウィンドウを閉じます。次の起動では保存済みの認証情報を使って復帰します。

配布するバイナリはコード署名をしていません。確認に使用した Windows 11 環境では、Web ブラウザで取得したファイルを Explorer からダブルクリックで起動すると、Microsoft Defender SmartScreen の「Windows によって PC が保護されました」という警告が表示され、詳細情報を選んで実行を選ぶまでプログラムは起動しませんでした。Windows または組織のポリシーによっては、この警告を回避できない場合があります。同じ環境で、一度実行を選んだ同じファイルでは、この警告は再表示されませんでした。また、本書のとおり PowerShell から起動した場合、この警告は表示されませんでした。

wgft は Windows のサービスもタスクスケジューラも通知領域への常駐も持ちません。`agent run` は起動した利用者の権限で動作し、ゲーミング PC の多くのゲームサーバーと同じ動き方です。ログオンのたびに自動で起動させるかどうかは利用者に任されています。スタートアップフォルダへの登録はその一例ですが、未確認です。

### macOS で agent を実行する

macOS 版は Apple シリコン (arm64) 向けで、macOS 27 で実機確認済みです。Intel Mac には対応していません。ターミナルで `curl` を使って取得します。

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64.sha256
shasum -a 256 -c wgft-darwin-arm64.sha256
sudo mkdir -p /usr/local/bin
sudo install -m 0755 wgft-darwin-arm64 /usr/local/bin/wgft
```

`curl` で取得したファイルには quarantine 属性が付きません。Web ブラウザで取得するとこの属性が付き、Gatekeeper は、この属性が付いていて Apple の公証 (notarization) を受けていないバイナリの起動を止めます。wgft は公証を受けていません。Apple シリコンの Mac には `/usr/local/bin` が無い場合があるため、`mkdir -p` で作成します。

ターミナルから 1 回だけ登録します。

```sh
WGFT_JOIN='<join string>' /usr/local/bin/wgft agent run
```

初回登録に成功すると、`registered as agent <name>` が表示され、`~/Library/Application Support/wgft/agent.json` が作成されます。ディレクトリの権限は 0700、ファイルの権限は 0600 です。下の LaunchDaemon を登録する前に、Ctrl+C でこの agent を止めます。認証情報は `agent.json` に残ります。LaunchDaemon とターミナルの agent は同時に動かせません。後から起動した側が `credentials file is in use by another process` を表示して起動を止めるためです。

agent を常駐させる場合は、[deploy/io.github.rahanahu.wgft.agent.plist](../deploy/io.github.rahanahu.wgft.agent.plist) を LaunchDaemon として登録します。この LaunchDaemon は `UserName` により root ではなく利用者の権限で `wgft agent run` を実行し、`WGFT_DATA_DIR` で同じ `~/Library/Application Support/wgft` を指します。プレースホルダ `YOUR_USER` を利用者名とホームディレクトリに置き換えてから、インストールして読み込みます。

```sh
curl -LO https://raw.githubusercontent.com/rahanahu/wgft/main/deploy/io.github.rahanahu.wgft.agent.plist
sed -e "s|/Users/YOUR_USER|$HOME|g" -e "s|YOUR_USER|$(id -un)|g" io.github.rahanahu.wgft.agent.plist > wgft-agent.plist
plutil -lint wgft-agent.plist
sudo install -m 0644 -o root -g wheel wgft-agent.plist /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
```

plist はすべての利用者が読めるため、join string を書きません。このため、初回登録は上のとおりターミナルから行います。LaunchDaemon の動作とログは次で確認します。

```sh
sudo launchctl print system/io.github.rahanahu.wgft.agent | grep -E 'state|pid'
tail -f ~/Library/Logs/wgft-agent.log
```

トンネルが確立すると、VPS 側の `sudo wgft agent ls` の `TUNNEL` 列が `ok` になります。agent がエラーで終了した場合や強制終了された場合、launchd は agent を再起動します。再起動の間隔は最短で 10 秒 (`ThrottleInterval`) です。launchd には systemd の unit の `RestartPreventExitStatus=3` に当たる設定が無く、終了コード 3 で終わる設定の誤りでも同じ間隔で再起動を繰り返します。macOS 27 で確認しました。設定の誤りが残っている間、agent は 10 秒ごとに起動と失敗を繰り返し、`launchctl print` は `last exit code = 3` と `state = spawn scheduled` を示します。これ以外にデーモンの異常を示すものはありません。再起動を繰り返す場合はログを確認します。

LaunchDaemon は次で止めます。

```sh
sudo launchctl bootout system/io.github.rahanahu.wgft.agent
```

plist は `/Library/LaunchDaemons` に残るため、次の起動時に LaunchDaemon は再び起動します。登録を解除するには、続けて `sudo rm /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist` を実行します。

更新するには、上と同じ手順で新しい `wgft-darwin-arm64` を取得してから、次を実行します。

```sh
sudo launchctl bootout system/io.github.rahanahu.wgft.agent
sudo install -m 0755 wgft-darwin-arm64 /usr/local/bin/wgft
sudo launchctl bootstrap system /Library/LaunchDaemons/io.github.rahanahu.wgft.agent.plist
```

wgft は更新の経路を保証しますが、更新後に旧版へ戻すことは保証しません。戻す場合に備え、更新前に `~/Library/Application Support/wgft` のバックアップを取ってください。

この構成は、macOS の次の 2 つの挙動に合わせたものです。

- ローカルネットワークのプライバシー保護: `~/Library/LaunchAgents` の LaunchAgent として起動した agent は、デフォルトゲートウェイには接続できましたが、LAN 内の他のホストへの接続は `connect: no route to host` で失敗し、許可を求めるダイアログも表示されませんでした。同じバイナリをターミナルから起動した場合と、`UserName` に同じ利用者を指定した LaunchDaemon として起動した場合は、どちらも UDP と TCP でそのホストに接続できました。ターミナルから起動したプロセスは、ターミナル自身の許可を引き継ぎます。失敗の原因をローカルネットワークのプライバシー保護とする判断は症状からの推測で、裏付けるシステムログは見つかっていません。`brew services` も LaunchAgent を使うため同じ問題が起きる可能性がありますが、未確認です。macOS 27 では、インストール直後のバイナリが LAN 内の他のホストへ行う最初の接続だけが同じ `connect: no route to host` で失敗し、その後の接続はすべて成功しました。1 回だけ失敗した理由は分かっていません。
- FileVault: FileVault を有効にした Mac では、再起動後、LaunchDaemon は起動時ではなく利用者が最初にログインした時点で起動しました。その後、その Mac 自身のネットワークが使えるようになるまで `network is unreachable` を記録し、その後は自動で接続しました。この待ち時間は、ある Mac では約 15 秒、Wi-Fi の接続もログイン後に始まる Mac では約 60 秒でした。FileVault を無効にした Mac でログインせずに起動時から動くかどうかと、ログアウト後も動き続けるかどうかは未確認です。

### systemd で起動する

付属の unit は非特権の `wgft` ユーザーで動きます。

```sh
sudo install -m 0755 ~/.local/bin/wgft /usr/local/bin/wgft
sudo useradd --system --home-dir /var/lib/wgft --shell /usr/sbin/nologin wgft
sudo mkdir -p /etc/wgft
printf 'WGFT_JOIN=<join string>\n' | sudo tee /etc/wgft/agent.env >/dev/null
sudo chown root:wgft /etc/wgft/agent.env
sudo chmod 0640 /etc/wgft/agent.env
sudo install -m 0644 deploy/agent.service /etc/systemd/system/wgft-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now wgft-agent
```

認証情報は `/var/lib/wgft/agent.json` に保存されます。

### Docker で起動する

[deploy/agent.compose.yaml](../deploy/agent.compose.yaml) の `WGFT_JOIN` を設定して起動します。

```sh
git clone https://github.com/rahanahu/wgft.git && cd wgft
# deploy/agent.compose.yaml の WGFT_JOIN を編集
docker compose -f deploy/agent.compose.yaml up -d
```

コンテナから LAN 側の転送先に到達できない場合は、compose の `network_mode: host` を有効にしてください。

### 転送先のアドレスを必要な範囲に絞る

エージェントは server が配る転送先へそのまま接続します。VPS を奪った攻撃者は、転送先を LAN の任意のアドレスに書き換えられます。`WGFT_AGENT_ALLOW_TARGETS` は、エージェントが接続してよいアドレスの一覧です。

```sh
WGFT_AGENT_ALLOW_TARGETS=192.168.1.20:25565,192.168.1.21:2456-2458 wgft agent run --data-dir ~/.wgft
```

systemd では `/etc/wgft/agent.env` の `WGFT_JOIN` と並べて書きます。

```sh
printf 'WGFT_AGENT_ALLOW_TARGETS=192.168.1.20:25565,192.168.1.21:2456-2458\n' | sudo tee -a /etc/wgft/agent.env >/dev/null
```

項目はコンマ区切りで、各項目は `CIDR`、`CIDR:ポート`、`CIDR:下限-上限` のいずれかです。アドレスだけの項目は 1 台のホストを指し、ポートを書かない項目はそのアドレスの全ポートを許します。IPv6 のアドレスにポートを付ける項目は `[2001:db8::/32]:8080` のように角括弧で囲みます。判定は接続する直前のアドレスに対して行うので、ホスト名の転送先は名前解決の後に判定され、新しい接続と UDP のセッションごとに判定されます。転送先が IP アドレスで一覧の外にあるルールは待ち受けを開かず、理由付きの error として `wgft agent ls` と Web UI に出ます。ポートの範囲を持つルールでは、一覧の外のポートだけが閉じたままになります。設定を省略した場合は制限しません。値の構文が誤っている場合は、終了コード 3 で起動を止めます。コンマだけのように、値はあるのに項目が 1 つも無い場合も同じく起動を止めます。守りの設定が黙って無効になることを防ぐためです。

### ローミングと ip-flapping の警告

エージェントを動かすホストがネットワークを移動し、直近 10 分以内に使ったネットワークへ戻ると `ip-flapping` の警告が出ます。stream 側と WireGuard のエンドポイント側でそれぞれ 1 件です。自宅の Wi-Fi と携帯回線のテザリングの間を移動するノート PC や、2 つの事業所の間を移動する運用では、認証情報が 1 部のままでもこれが日常的に起こります。この場合の警告は、窃取の兆候ではありません。`wgft agent warnings` は次の形で表示します。

```
AGENT   KIND         DETAIL                                                         AT
laptop  ip-flapping  stream source alternated between 198.51.100.7 and 203.0.113.9  2026-01-01T09:00:00+09:00
laptop  ip-flapping  wg endpoint alternated between 198.51.100.7 and 203.0.113.9    2026-01-01T09:00:05+09:00
```

ローミングすると分かっているエージェントでは、警告を削除します。詳細の引数を付けなければ、そのエージェントの `ip-flapping` の警告をすべて削除します。

```sh
sudo wgft agent dismiss-warning laptop ip-flapping
```

移動しないエージェントに `ip-flapping` が出た場合は、鍵か恒久トークンの複製を疑います。対応は `wgft agent warnings --help` にあります。

## 4. 転送ルールを追加する

まずエージェントの接続を確認します。

```sh
sudo wgft agent ls
```

UDP のゲームサーバを公開する例:

```sh
sudo wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game
```

ポート範囲を指定した場合、`--to` は転送先の先頭ポートを示します。この例では VPS の UDP 2456 は `192.168.1.20:2456` へ、UDP 2457 は `192.168.1.20:2457` へ転送されます。

TCP で実クライアント IP を PROXY protocol v2 として渡す例:

```sh
sudo wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol
```

転送対象のポートは VPS の firewall 側でも開けてください。

エージェントは、新しいルールのために TCP の待ち受けを開くとき、転送先へ 1 回だけ試し接続してすぐ閉じます。接続を拒む転送先を、通信が来る前に報告するためです。転送先からは、データを運ばない接続 1 本に見えます。転送先が待ち受けていない間、`wgft agent ls` はそのルールを `RULES` 列に `cannot connect to target` として示します。この状態は、転送先が起動してから 30 秒以内、エージェントの次の報告で消えます。UDP のルールにこの確認はありません。データグラムは、送っても届いたかどうかが分からないためです。

ルールを追加・変更しても、無関係な既存セッションは切断されません。接続元 allow/deny やレート制限は CLI から設定できます。詳しくは [cli.md](cli.md) を参照してください。

## Web UI

管理 API は既定で `/run/wgft/admin.sock` だけで待ち受け、VPS のネットワークには公開されません。SSH でローカルポートへ転送します。

```sh
ssh -L 8686:/run/wgft/admin.sock root@vps
```

SSH 接続中に `http://localhost:8686` を開いてください。

root で SSH ログインできない場合は、次を設定します。

```text
WGFT_ADMIN=127.0.0.1:8686
```

その場合は VPS の loopback listener へ転送します。

```sh
ssh -L 8686:127.0.0.1:8686 vps
```

Tailscale 経由で管理画面にアクセスする場合は `WGFT_ADMIN_TAILSCALE=true` を設定します。追加の Host 名は `WGFT_ADMIN_HOST` で指定できます。

## HTTPS を公開する

wgft 自身は TLS を終端しません。VPS の 443 と 80 を自宅のリバースプロキシへ転送し、証明書と認証はリバースプロキシ側で管理します。

Caddy では 443 に PROXY protocol を使うことで、アクセスログに実クライアント IP を残せます。

```sh
sudo wgft rule add --agent home --tcp 443 --to 192.168.1.30:443 --proxy --proxy-protocol
sudo wgft rule add --agent home --tcp 80  --to 192.168.1.30:80
```

以下の listener wrapper を使うには Caddy 2.11 以上が必要です。

```text
{
    servers 192.168.1.30:443 {
        listener_wrappers {
            proxy_protocol {
                allow 192.168.1.30/32
            }
            tls
        }
    }
}

example.com {
    reverse_proxy 192.168.1.40:8080
}
```

`allow` には wgft agent が動いているホストのアドレスを指定します。Caddy から見た TCP peer はそのホストになるためです。

## ログを見る

server とエージェントは、ログを標準エラー出力に書き、独自のログファイルを持ちません。同梱の systemd の unit では、journald がログを保存します。

```sh
sudo journalctl -u wgft -b            # server、直近の起動以降
sudo journalctl -u wgft-agent -f      # エージェント、新しい行を追う
sudo journalctl -u wgft --since "1 hour ago"
```

Docker では `docker compose -f deploy/server.compose.yaml logs` か、コンテナに対する `docker logs` を使います。

server は、データプレーンの適用が済み、管理用 API とエージェント用 API の待ち受けを開けた時点で、版、モード、世代、ルールとエージェントの件数を `server started` の 1 行に出します。この行が無ければ起動は終わっていません。止まった箇所は、直前の行に出ます。ただし、起動を終わらせない失敗が 1 つあります。保存済みのルールがまったく適用できない場合、server は `startup hold` の 1 行を出し、管理用 API だけを待ち受けたまま 30 秒ごとに適用をやり直します。保留の間も `wgft rule rm` と `wgft rule disable` は届くので、適用できない宣言を小さくして直せます。適用が成功するまで、server は新しい宣言を反映済みとは扱いません。`server started` の行も適用の成功の後に出ます。保留が止めるのは公開であり、転送ではありません。初回の起動や VPS 自体の再起動の直後は、カーネルに何も残っていないため転送されません。プロセスだけの再起動をまたぐときは、前のプロセスがカーネルに残したものがそのまま残ります。どちらの宣言を転送しているかは適用がどこで失敗したかで変わり、ログからは分かりません。カーネルが差し替えを行わないまま失敗した場合は、テーブルは実際に旧いままなので、前回の宣言のまま転送を続けます。宣言の送信自体が失敗した場合と、カーネルがバッチを拒んだ場合が該当します。カーネルが差し替えを終えたのに vpsd が応答を受け取れなかった場合は、テーブルは既に差し替わっており、vpsd が失敗として報告した新しい宣言のほうを転送しています。プロキシモードの待ち受けは、いずれの場合もプロセスと一緒に消えます。実際のカーネルの内容は `wgft server nft` で読めます。ルールの変更が成功するたびに、`cli rule add` や `ui import` のような操作の出所、対象のルールの ID、結果の世代を 1 行に出します。ルールの変更だけを一覧にするコマンドは次のとおりです。

```sh
sudo journalctl -u wgft | grep 'rules: '
```

wgft は個々のパケットや成功したフローをログに出しません。接続文字列、トークン、秘密鍵もログに出しません。

## 削除する

サービスを停止し、まず削除内容を確認します。

```sh
sudo systemctl disable --now wgft
sudo wgft server teardown --dry-run
```

wgft が管理する状態を削除する場合:

```sh
sudo wgft server teardown --purge --yes
```

`--purge` を付けなければ key と証明書は残るため、再起動後も同じ server identity を使えます。`--purge` を付けると server key、ルール、agent 登録も削除されるため、agent の再登録が必要です。

Docker の agent を認証情報ごと削除する場合:

```sh
docker compose -f deploy/agent.compose.yaml down -v
```

## コマンドリファレンス

`wgft <command> --help` には各コマンドの例があります。生成済みの完全な一覧は [cli.md](cli.md) にあります。