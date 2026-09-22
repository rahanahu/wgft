# wgft - WireGuard Forwarding Tool

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/rahanahu/wgft/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![Status: v1.0](https://img.shields.io/badge/status-v1.0-blue.svg)](#開発状況)

[English](README.md) | 日本語

wgft は、VPS に届いた TCP/UDP 通信を WireGuard 経由で自宅ネットワーク上のサービスへ転送するツールです。自宅側の agent から VPS へ接続するため、自宅ルータのポート開放は不要で、CGNAT や二重 NAT の環境でも使えます。

```mermaid
flowchart LR
  c1[client] -->|UDP 2456| s
  c2[client] -->|TCP 443| s
  subgraph vps[VPS - 固定 IP]
    s[wgft server]
  end
  s <==>|WireGuard トンネル| a
  subgraph home[自宅 - ポート開放なし]
    a[wgft agent] --> g[ゲームサーバ<br>192.168.1.20:2456]
    a --> p[リバースプロキシ<br>192.168.1.30:443]
  end
```

wgft は、任意の TCP/UDP ポートをそのまま転送したい用途、特にゲームサーバの公開を主な用途にしています。HTTPS も転送できますが、TLS 終端や認証は行わず、自宅側のリバースプロキシに任せます。

## 特徴

- 1 つのバイナリに VPS 側 server、自宅側 agent、CLI を収録
- カーネルモードでは Linux の WireGuard と nftables DNAT を使うため、wgft プロセスを再起動しても既存の転送は継続
- ユーザー空間モードは root 不要で、コンテナ内だけでも動作
- TCP/UDP の単一ポート・ポート範囲を転送
- ルールごとの allow/deny とレート制限
- ルール変更時も無関係なセッションは切断しない
- TCP ルールでは PROXY protocol v2 により実クライアント IP を転送可能
- agent、ルール、警告、転送状態を確認できる Web ダッシュボード
- `wgft server teardown` は wgft が作成した状態だけを削除

## wgft を作った理由

wgft は Pangolin から着想を得ています。Pangolin を使って、VPS を入口に自宅ネットワークへトンネルする構成の便利さを知りました。一方、ゲームサーバなどの raw TCP/UDP 転送だけが目的なら、もっと小さく、ポート転送に特化したツールが欲しいと感じたのが wgft を作ったきっかけです。日本の IPv4 over IPv6 回線など、自宅側で任意の IPv4 ポートを外部公開できない環境も想定しています。

そのため wgft は、WireGuard によるトンネル、nftables によるカーネル転送、シンプルな TCP/UDP ルールに機能を絞っています。必要な WireGuard と wgft 用 nftables ルールは wgft が管理するため、手作業でトンネルや DNAT ルールを組む必要はありません。TLS 終端、SSO、証明書管理、Web アプリ公開は扱わず、リバースプロキシなど別のソフトウェアに任せます。

## 動作モード

| | カーネルモード `kernel` | ユーザー空間モード `userspace` |
|---|---|---|
| VPS の root 権限 | 必要 | 不要 |
| カーネル / nftables | Linux 6.1+、nftables 1.0.6+ | 不要 |
| 転送経路 | カーネル WireGuard + nftables DNAT | wireguard-go + ユーザー空間 netstack |
| wgft プロセス停止・クラッシュ時 | 設定済みの転送は継続 | 転送も停止 |
| レート制限の判定場所 | カーネル | wgft プロセス |

カーネルモードでは、起動後に wgft プロセスがクラッシュまたは再起動しても転送はカーネル側で継続します。ただし VPS 自体を再起動すると WireGuard / nftables の実行時状態が失われるため、wgft が再起動して転送状態を復旧する必要があります。通常運用では付属の systemd unit を有効にしておけば、VPS 再起動後も自動で復旧します。

VPS で root が使える場合はカーネルモードを使います。root やカーネル WireGuard が使えない場合、または server をコンテナ内だけで動かしたい場合はユーザー空間モードを使います。

VPS 側は Linux で動作します。自宅側の agent は Windows amd64 でも動作し、Windows 11 で実機確認済みです。Apple シリコンの macOS でも動作し、macOS 27 で実機確認済みです。Intel Mac には対応していません。wgft は IPv4 のみに対応しています。自宅側の agent には root 権限も TUN デバイスも不要で、Windows でも管理者権限は不要です。macOS の agent は利用者の権限で動作します。

## クイックスタート

ここでは最も一般的な構成として、Linux VPS 上のカーネルモードと、自宅側の通常バイナリ agent を使います。ユーザー空間モード、Docker、systemd の詳細、firewall、HTTPS、ログ、削除方法は [セットアップガイド](docs/setup.ja.md) を参照してください。

### 1. wgft を入手する

Linux では release バイナリを取得します。VPS のイメージや Proxmox の LXC テンプレートのような最小構成のイメージは、curl を含まないことがあります。あらかじめ `sudo apt install curl` のように導入してください。

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-linux-amd64
chmod +x wgft-linux-amd64
```

Linux の arm64 環境では `amd64` を `arm64` に置き換えてください。Windows と macOS での取得手順は手順 3 で説明します。

### 2. VPS 側 server を起動する

```sh
sudo install -m 0755 wgft-linux-amd64 /usr/local/bin/wgft
sudo mkdir -p /etc/wgft
printf 'WGFT_MODE=kernel\nWGFT_WG_ENDPOINT=vps.example.com:51820\n' | sudo tee /etc/wgft/server.env
sudo chmod 0644 /etc/wgft/server.env
sudo wgft server check
sudo wgft server run
```

`server.env` は、意図的に全員が読める権限にします。秘密の値を含まず、付属の systemd の service は非特権の動的な利用者で動くためです。

VPS の firewall で UDP 51820 と TCP 8443 を開けてください。`wgft server check` は、既存 firewall に追加で必要な forwarding 許可を表示するほか、host 自身の input firewall が wgft 自身のポートやルールの listen port を塞ぐ場合に警告します。

カーネルモードでは IPv4 forwarding が必要です。wgft は必要に応じて `net.ipv4.ip_forward=1` を設定し、`wgft server teardown` は元に戻す方法を表示します。

別の VPS shell で、一度だけ使える join string を発行します。

```sh
sudo wgft agent join-string --name home
```

### 3. 自宅側 agent を起動する

```sh
mkdir -p ~/.local/bin ~/.wgft
mv wgft-linux-amd64 ~/.local/bin/wgft
WGFT_JOIN='<join string>' ~/.local/bin/wgft agent run --data-dir ~/.wgft
```

認証情報は `~/.wgft/agent.json` に保存されます。join string が必要なのは初回登録時だけです。

Windows では、[Releases ページ](https://github.com/rahanahu/wgft/releases) から `wgft-windows-amd64.exe` を取得します。ファイルを保存したフォルダで PowerShell を開きます。例えば Downloads フォルダです。次を実行します。

```powershell
Rename-Item wgft-windows-amd64.exe wgft.exe
$env:WGFT_JOIN = '<join string>'
.\wgft.exe agent run
```

join string は `#` を含むため、単一引用符で囲みます。

2 回目以降は `.\wgft.exe agent run` だけで起動でき、保存済みの認証情報を使います。初回起動時、Windows Defender Firewall が `wgft.exe` の受信を許可するかどうかのダイアログを出すことがあります。agent は外向きの接続だけを使うため、許可してもキャンセルしてもトンネルは動作し続けます。停止は Ctrl+C を押すか、コンソールのウィンドウを閉じます。認証情報は `%ProgramData%\wgft\agent.json` に保存され、管理者権限は不要です。wgft は Windows のサービスを持たないため、ログオンのたびに自動で起動させるかどうかは利用者が決めます。スタートアップフォルダへの登録は未確認の選択肢の 1 つです。詳しくは[セットアップガイド](docs/setup.ja.md#windows-で-agent-を実行する)を参照してください。

macOS では、ターミナルで `curl` を使ってバイナリを取得し、インストールしてから 1 回だけ登録します。

```sh
curl -LO https://github.com/rahanahu/wgft/releases/latest/download/wgft-darwin-arm64
sudo mkdir -p /usr/local/bin
sudo install -m 0755 wgft-darwin-arm64 /usr/local/bin/wgft
WGFT_JOIN='<join string>' /usr/local/bin/wgft agent run
```

取得には Web ブラウザではなく `curl` を使います。ブラウザで取得したファイルには quarantine 属性が付き、Gatekeeper は、この属性が付いていて Apple の公証を受けていないバイナリの起動を止めるためです。wgft は公証を受けていません。Apple シリコンの Mac には `/usr/local/bin` が無い場合があるため、`mkdir` で作成します。認証情報は `~/Library/Application Support/wgft/agent.json` に保存されます。

agent を常駐させる場合は、`registered as agent` が表示された後に Ctrl+C で止め、[deploy/io.github.rahanahu.wgft.agent.plist](deploy/io.github.rahanahu.wgft.agent.plist) を使って LaunchDaemon として登録します。この LaunchDaemon は利用者の権限で動作し、同じ認証情報を使います。LaunchAgent は使いません。LaunchAgent として起動した agent は LAN 内の他のホストに接続できなかったためです。原因は macOS のローカルネットワークのプライバシー保護だと推測しています。FileVault を有効にした Mac では、再起動後に最初にログインした時点で LaunchDaemon が起動します。手順は[セットアップガイド](docs/setup.ja.md#macos-で-agent-を実行する)を参照してください。

### 4. 転送ルールを追加する

VPS 側で実行します。

```sh
sudo wgft agent ls
sudo wgft rule add --agent home --udp 2456-2457 --to 192.168.1.20:2456 --group game
```

ポート範囲を指定した場合、`--to` は転送先の先頭ポートを示します。この例では VPS の UDP 2456 は `192.168.1.20:2456` へ、UDP 2457 は `192.168.1.20:2457` へ転送されます。

転送対象のポートも VPS の firewall で開けてください。ルールが有効になると、VPS に届いた通信が WireGuard トンネルを通って自宅側の転送先へ届きます。

## Web UI

![wgft のダッシュボード](docs/images/dashboard.ja.png)

ダッシュボードでは agent の接続状態、ルール、drop カウンタ、警告、適用中の nftables 状態を確認できます。join string の発行や通常のルール操作も行えます。

管理 API は既定では外部公開されず、`/run/wgft/admin.sock` でのみ待ち受けます。SSH で手元へ転送します。

```sh
ssh -L 8686:/run/wgft/admin.sock root@vps
```

その状態で `http://localhost:8686` を開きます。その他の管理画面への接続方法は [セットアップガイド](docs/setup.ja.md#web-ui) を参照してください。

## ドキュメント

- [セットアップガイド](docs/setup.ja.md) - カーネル / ユーザー空間モード、root なし運用、Docker、systemd、HTTPS、Web UI、ログ、削除方法
- [CLI リファレンス](docs/cli.md) - 各コマンドと使用例
- [設計](docs/design.md) - プロトコル、セキュリティ、転送動作、設計判断
- [アーキテクチャ](docs/architecture.md) - package 構成と処理経路
- [CLAUDE.md](CLAUDE.md) - 開発上のルール、テスト環境

`wgft <command> --help` でも各コマンドの使用例を確認できます。

## 開発状況

v1.0.0。版番号は、互換性の保証が拘束を始める点を示すものであり、成熟度の段階ではありません。対象は Linux の server と Linux の agent だけです。Windows と macOS の agent は暫定とし、保証の対象に含めません。カーネルモードは作者の VPS / 自宅環境で UDP/TCP 転送、NAT 越え、再接続、VPS 再起動からの復旧、teardown を確認済みです。ユーザー空間モードは開発環境と VPS で確認済みです。`wgft server doctor` と `wgft status` は、カーネルモードの稼働中の server と登録済みの agent 1 台に対して、次の 3 つの場面で確認済みです。健全な配置、agent が宛先を拒む状態、制御の接続が切れた状態です。適用が毎回失敗するルール集合からの回復も開発環境で確認済みです。server は管理用 API を開いたまま起動の残りを保留するので、データディレクトリを削除せずにルールを小さくできます。暫定の扱いにしたことは、現在配っている Windows と macOS の agent のバイナリの配布を取りやめる決定ではありません。登録、トンネルの確立、再起動からの復帰などの一般的な動作は、Windows と macOS の実機で確認済みです。agent の再接続の契機を決める接続の生死の判定は新しく加えた仕組みで、Windows でも macOS でも実機で確認していません。この判定が実機で未確認であることが、Windows と macOS の agent を今回 v1.0 の保証に含めなかったおもな理由です。中継フローはルール単位、接続元単位、プロセス単位で上限を設け、負荷時のメモリ使用量を制限します。更新の経路は保証しますが、更新後に旧版へ戻すことは保証しません。戻す場合に備え、更新前にデータディレクトリのバックアップを取ってください。実装や構成の詳細は設計・セットアップ文書を参照してください。

## セキュリティ

付属の server 用 systemd unit では、wgft は転送に必要な capability だけを持つ非特権ユーザーとして動作します。外部へ公開されるのは WireGuard、agent API、明示的に転送したポートだけで、管理 API は既定ではローカル専用です。

agent は server が配る転送先へそのまま接続します。agent 側の `WGFT_AGENT_ALLOW_TARGETS` は接続先を列挙したアドレスだけに絞り、奪われた server を LAN の他のホストから遠ざけます。

脆弱性の報告方法は [SECURITY.md](SECURITY.md) を参照してください。

## ライセンス

[MIT](LICENSE)。バイナリに含まれる Go module のライセンスは `THIRD_PARTY_LICENSES.txt` にまとめ、release と container image にも含めています。
