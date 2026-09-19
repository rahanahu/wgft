# lab/caddy: 実 Caddy での HTTPS 経路の確認記録

HTTPS を出す手順を実リバースプロキシで確かめるために、ラボ VM の home ns で実 Caddy を動かして確かめた記録です。
`lab/caddy/Caddyfile` は本書の確認で使った設定そのもので、README の「HTTPS を出すには」の小節は本書の結果だけから書きます。

## 入れ方

Debian 12 (bookworm) の apt パッケージの Caddy は 2.6.2 で、`caddy list-modules` に
`caddy.listeners.proxy_protocol` が出てきません(モジュールが未登録)。当初の予定は「apt の
caddy (2.6 系)」でしたが、この版には PROXY protocol の listener wrapper 自体が入っておらず、
実 IP の伝達を確かめられません。Caddy 公式の apt リポジトリ (Cloudsmith 配信) を
追加し、同じく apt 経由で 2.11.4 に上げたところ `caddy.listeners.proxy_protocol` が使えるように
なりました。ラボはこの時点で IPv6 のみ外に出られる状態でしたが、`dl.cloudsmith.io` は IPv6 で
届きます。手順は次のとおりです。

```sh
# ラボの VM は時刻がずれていることがある。ずれていると InRelease の検証で apt update が失敗する
lab/lab exec vm date
lab/lab exec vm bash -c 'date -u -s "@$(date -u +%s)"'   # ホストの時刻に合わせる(ホストで date を先に見ておく)

lab/lab exec vm apt-get install -y --no-install-recommends caddy   # まず Debian 12 の版(2.6.2)を入れる

# Caddy 公式の apt リポジトリを追加して上げる(2.11.4。proxy_protocol あり)
lab/lab exec vm apt-get install -y --no-install-recommends debian-keyring debian-archive-keyring apt-transport-https gnupg
lab/lab exec vm bash -c "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg"
lab/lab exec vm bash -c "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list"
lab/lab exec vm apt-get update
lab/lab exec vm apt-get install -y caddy

lab/lab exec vm systemctl stop caddy
lab/lab exec vm systemctl disable caddy   # 常駐はさせない。以後は手動で `caddy run` する
```

`caddy version` は `v2.11.4`、`caddy list-modules | grep proxy_protocol` は
`caddy.listeners.proxy_protocol` を返します。パッケージは入れたままにしてあります
(`apt list --installed | grep caddy`)。

## 動かし方

ログの出力先ディレクトリを作ってから、home ns で foreground 起動します(`lab exec` はバック
グラウンド実行が要るので `setsid ... nohup ... &` を使います。詳しくは下のコマンド例)。

```sh
lab/lab exec vm mkdir -p /var/log/caddy-lab
lab/lab exec vm bash -c '
ip netns exec home setsid nohup caddy run --config /wgft/lab/caddy/Caddyfile --adapter caddyfile \
  > /tmp/caddy.log 2>&1 < /dev/null &
disown
'
```

`/wgft` はホストのリポジトリを読み取り専用で共有したものなので、`Caddyfile` はそのまま読めますが、
ログの出力先は `/wgft` 配下には書けません。`/var/log/caddy-lab/` など VM 側のパスにします。

## Caddyfile の要点

`Caddyfile` の中にも同じ内容のコメントを英語で書いていますが、確かめた事実を補足します。

- **Host ヘッダ / SNI によるルーティング**:ラボには DNS がないので、Caddy のサイトのアドレスに
  ラボの LAN アドレス (`192.168.50.2`) をそのまま書くと、外から VPS の公開 IP (`198.51.100.1`)
  宛に届いた `Host: 198.51.100.1` のリクエストとサイトのアドレスが一致せず、Caddy はどのハンドラ
  にもマッチさせずに `"msg":"NOP"` を返します(空の 200 ではなく、実際には何のハンドラも通って
  いない状態)。本番なら VPS を指す実ドメインが `Host` に入るので起きませんが、ラボでは実ドメイン
  の代わりに `home.wgft.lab` という架空の名前をサイトのアドレスにし、`bind 192.168.50.2` で
  実際に待ち受けるインタフェースだけを指定します。確認は client ns から
  `curl --resolve home.wgft.lab:443:198.51.100.1 ...` のように `--resolve` で名前とアドレスの
  対応を渡し、`Host` ヘッダと SNI を `home.wgft.lab` にしたまま VPS の公開 IP に TCP 接続します。
- **`listener_wrappers` のスコープ**:`servers 192.168.50.2:443 { listener_wrappers { ... } }` の
  ように listen アドレスを指定した `servers` ブロックにすることで、`proxy_protocol` を 443 の
  listener だけに掛けています。素通しの 80 にも掛けると、PROXY protocol ヘッダの来ない普通の
  HTTP 接続が壊れます(下の「allow の検討」とは別の理由で、80 に `listener_wrappers` を書かない
  必要があります)。
- **`auto_https disable_redirects`**:`tls internal` を使うサイトは既定で 80 番に自動リダイレクト
  サーバを立てますが、これは別に用意した 80 番のサイト(素通し用)と衝突するため、主要な
  4 点を確かめる設定では止めています。リダイレクト自体は別建てで確かめました(下の「(任意) リダ
  イレクト」)。

## allow の検討

当初の予定は「`allow` に `10.200.0.1/32`(vpsd の wg アドレス)を書く必要があるかも確かめる」
でしたが、実際に必要な CIDR は違いました。

- プロキシモードの中継 (`internal/vpsd/proxyrelay/proxyrelay.go`) は、vpsd から
  `10.200.0.2:443`(エージェントのリスナー、wg0 経由)へ TCP 接続して PROXY protocol v2 ヘッダを
  書き込みますが、それを受けたエージェント側の TCP リレー (`internal/agent/relay/tcp.go`) は
  受け取ったバイト列をそのまま**新しいローカルの TCP 接続**として `192.168.50.2:443`(Caddy)へ
  つなぎ直します(`net.Dial` の既定実装、home ns 内の自分自身への接続)。Caddy が実際に受け取る
  TCP の相手は、この最後の接続の送信元である home ns 自身のアドレス `192.168.50.2` です。
  `10.200.0.1`(vpsd の wg アドレス)は Caddy からは見えません。
- 実際に確かめると、`allow` を書かない場合(誰からでも PROXY protocol ヘッダを解釈する設定)でも
  ヘッダは解釈されず、アクセスログの `remote_ip` はエージェント自身のアドレス `192.168.50.2` の
  ままでした。`caddy.listeners.proxy_protocol` は `allow` が空だと既定で「誰も信頼しない」らしく、
  ヘッダを読まずに実際の TCP 接続元をそのまま使う(エラーにはならない)ようです。
  `allow 192.168.50.2/32` を書いたところ、`remote_ip` / `client_ip` が client の実 IP
  (`198.51.100.2`)になりました。結論として、**`allow` は必要で、書く値は vpsd の wg アドレス
  (`10.200.0.1/32`)ではなく、エージェントが動くホスト自身のアドレス(具体的には
  `192.168.50.2/32`)** です。

## 確認した 4 点

いずれも `lab/lab exec vm ...` で VM に入り、client ns からの `curl` は
`lab/lab exec client curl ...` で実行しました。ルールは次の 2 本です(`--admin
unix:///run/wgft/admin.sock`。`server run` は `--data-dir /tmp/wgftlab`、agent は
`--data-dir /tmp/wgftagent`)。

```sh
wgft rule add --agent home --tcp 443 --to 192.168.50.2:443 --proxy --proxy-protocol
wgft rule add --agent home --tcp 80  --to 192.168.50.2:80
```

| # | 項目 | 結果 | 根拠 |
|---|---|---|---|
| 1 | PROXY protocol で実 IP が届く | 確認済み | `curl -k --resolve home.wgft.lab:443:198.51.100.1 https://home.wgft.lab/` → `https ok remote=198.51.100.2`。`access-443.log` の `"remote_ip":"198.51.100.2","client_ip":"198.51.100.2"` |
| 2 | 80 の素通し(PROXY protocol 無し) | 確認済み | `curl --resolve home.wgft.lab:80:198.51.100.1 http://home.wgft.lab/` → `http ok remote=192.168.50.2`。`access-80.log` の `"remote_ip":"192.168.50.2","client_ip":"192.168.50.2"`(仕様 8 節のとおりエージェントのアドレス) |
| 3 | TLS の終端が自宅側 | 確認済み | vps ns の `tcpdump -i pub0 tcp port 443 -c 20 -A` に `GET ` や `HTTP/1.1 200` などの平文は 0 件(`grep -c` で確認)。ClientHello の SNI `home.wgft.lab` だけは TLS の仕様どおり平文で見える。`access-443.log` に `"tls":{"resumed":false,"version":772,...}` があり、Caddy 側で復号できている |
| 4 | 拒否の即時反映 | 確認済み | client ns で `openssl s_client -connect 198.51.100.1:443 -servername home.wgft.lab -quiet` を張ったまま(`ss -tn` で `ESTAB` を確認)、vps ns で `wgft rule deny add r_... 198.51.100.2/32` を実行。直後の `ss -tn` に該当の接続が残っておらず、同じ秒のうちに切れた |

deny を実行した直後に出る `applied; generation unchanged` は接続元制限の変更が状態の世代
(generation)を進めないことを表しており、`vpsd` 自身が進行中の中継を閉じる処理(仕様 6.2 節)は
配信とは別経路であることと一致します。

## (任意) HTTP → HTTPS リダイレクト

80 が素通し(カーネルモード)、443 がプロキシモードという非対称な構成でも、Caddy の既定のリダイ
レクトは自然に動きました。確認は `auto_https disable_redirects` を外し、80 番の専用サイトも外し
た一時的な Caddyfile (`home.wgft.lab { bind 192.168.50.2; tls internal; ... }` のみ) で行いました。

```sh
curl -sS --max-time 5 --resolve home.wgft.lab:80:198.51.100.1 http://home.wgft.lab/
# → HTTP/1.1 308 Permanent Redirect, Location: https://home.wgft.lab/

curl -sS -k -L --max-time 5 \
  --resolve home.wgft.lab:80:198.51.100.1 --resolve home.wgft.lab:443:198.51.100.1 \
  http://home.wgft.lab/
# → https ok remote=198.51.100.2 (リダイレクトを追って 443 まで到達)
```

`lab/caddy/Caddyfile` 本体はこのリダイレクトを止めたままにしてあります(80 番の素通しと 443 番の
プロキシモードを別々のサイトとして比べるための構成のため)。リダイレクトを使うだけなら、80 番の
専用サイトブロックと `auto_https disable_redirects` を削り、443 番のサイトブロックだけを残せば
足ります。

## 未確認

- **nginx**:任意項目のため試していません。`proxy_protocol` ディレクティブと
  `set_real_ip_from 10.200.0.1`(または上の allow の検討のとおり実際は home 側のアドレス)の設定
  例は、別途試すまで README には書きません。
- **ACME (Let's Encrypt の HTTP-01)**:ラボには公開 DNS も外からの到達性もないため試していません。
  README の ACME の説明は Caddy 公式のドキュメントに委ねます。

## 補足: ルールの入れ替え時に見えた挙動

本筋の確認には関係しませんが、同じ公開ポート (443) のプロキシモードのルールを一度削除してすぐに
作り直す(`--proxy-protocol` の有無を切り替えるためにやった)と、エージェント側のログに次が出て
一時的にリスナーが開けないことがありました。

```
listener tcp/443 closed
listener tcp/443: bind tcp 10.200.0.2:443: port is in use
```

エージェントの次の収束(30 秒おきのハートビートに乗る再試行)で自然に解消し、`rule ok` に戻りま
した。ルールを消してすぐ同じポートで作り直すという操作そのものが今回の確認の都合によるもので、
通常の運用(ルールを 1 回追加するだけ)では起きません。確認の結果には影響しませんが、
念のため記録します。
