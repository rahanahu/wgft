<a id="103-運用の流れ"></a>
### 運用の流れ

server とエージェントの初回配置では、転送のモードと接続文字列を明示して設定します。


初回セットアップ(VPS):

1. `/etc/wgft/server.env` に `WGFT_MODE=kernel` と `WGFT_WG_ENDPOINT` を書き、`wgft server check` で検査してから、systemd で `wgft server run` を起動します。
   root もカーネル WireGuard も使えない VPS では、代わりに `WGFT_MODE=userspace` を焼き込んだコンテナイメージを `WGFT_WG_ENDPOINT` とデータのボリュームだけ与えて起動する([6.3 節](../vps/userspace.md#63-ユーザー空間モード))。
   入れ方でモードが決まり、systemd ならカーネル、Docker ならユーザー空間です。
   初回起動で SQLite、自己署名証明書、wg0 のサーバ鍵を作り、モードとアドレス帯を記録する([9 節](../state.md#9-状態の保存と再起動))。
   対話は無く、初回に決めるのはモードだけです
2. VPS のファイアウォールで WireGuard とエージェント用 API のポートを開ける。
   これは手作業で、`vpsd` は行いません
3. 起動ログに [6.1 節](../vps/kernel.md#61-カーネルモード)の警告(forward の `policy drop` など)が出ていれば、提示された行を 1 回だけ足す

同梱の systemd の unit は `vpsd` を root では動かさない。
`DynamicUser=yes` で systemd がサービスの寿命だけ非特権の利用者を割り当て、`AmbientCapabilities` で `CAP_NET_ADMIN` と `CAP_NET_BIND_SERVICE` の 2 つだけを渡す。
前者はカーネルの WireGuard、nftables、conntrack の netlink と `net.ipv4.ip_forward` の書き込みに、後者はプロキシモードの 1024 未満の待ち受けに使います。
ネットワーク系の sysctl は `CAP_NET_ADMIN` があれば root でなくても書けるので、[6.1 節](../vps/kernel.md#61-カーネルモード)の「`vpsd` 自身が 1 にする」はそのまま成り立つ。
`ProtectKernelTunables` は `/proc/sys` を読み取り専用にして書き込みを妨げるので付けない。
root のままで `/proc/sys` を書き込み可にすると、侵害されたときに root 所有のほかの sysctl まで書き換えられるので、非 root にする意味はここにあります。
ファイルシステムは `ProtectSystem=strict` で読み取り専用にし、書けるのはデータの置き場と実行時ディレクトリだけにします。
システムコールは `@system-service` から `@privileged` と `@resources` を除いたものに絞る。
データの置き場の実体は `/var/lib/private/wgft` になり、`/var/lib/wgft` はそこへのシンボリックリンクになります。
root で動く旧い unit が作ったディレクトリは、最初の起動で systemd が移して所有者を付け替えるので、unit を差し替えて再起動するだけで更新でき、サーバ鍵も登録済みのエージェントも引き継がれる。
root からは従来どおり読めるので、CLI と `teardown` の使い方は変わりません。
設定ファイルの権限は [11a 節](../security/configuration.md#11a-設定の渡し方)による。
`systemd-analyze security` の値は 8.6 から 2.0 になった(systemd 252)。

メモリが尽きたときの扱いは次のとおり。
[7 節](../agent-dataplane.md#7-データプレーン自宅側)の同時フロー数の上限は、`vpsd` が保持するフローの数を抑えるが、プロセスのメモリの量を抑える上限ではありません。
OOM キラーに殺された場合は、unit の `Restart=on-failure` が 2 秒後に起動し直す(compose は `restart: unless-stopped`)。
ルール、サーバ鍵、エージェントの登録は SQLite にあるので失われない。
カーネルモードでは、`vpsd` が落ちている間も、プロキシモード([6.2 節](../vps/proxy.md#62-プロキシモード))以外のルールの転送は続く。
ホスト全体のメモリが尽きた場合にカーネルが選ぶプロセスは `vpsd` とは限らないので、unit には `MemoryMax=` の例をコメントで添える。
値はホストの大きさで変わるので既定では有効にせず、起動時に出るソフト上限より上に置くよう書きます。
ソフト上限はメモリの上限ではないので、この置き方だけで OOM を避けられるとは限らない。
ユーザー空間モードで最悪の場合に要るメモリの量は、[7 節](../agent-dataplane.md#7-データプレーン自宅側)の「プロセス全体のメモリの上界」の段落にホストの要件として書きます。

管理 UI と CLI への入り方([11 節](../security/admin-transport.md#11-セキュリティ))。
どの経路でもパスワードの入力は無い:

- VPS 上の CLI:`sudo wgft rule add ...` のように root で叩く。
  ソケットを開けるのは root と `vpsd` 自身だけなので、sudo がそのまま認証になります
- Tailscale を使う場合(推奨):`--admin-tailscale` を付けて起動し、tailnet 内の端末から `http://<VPS の tailnet 名>:8686/` を開きます
- Tailscale が無い、または tailnet が落ちたとき:SSH でソケットを手元に引く。
  `~/.ssh/config` の該当ホストに `LocalForward 8686 /run/wgft/admin.sock` を書いておけば、`ssh vps` を張るだけで `http://localhost:8686/` が開きます

エージェントの追加(自宅):

1. `wgft agent join-string --name home` で接続文字列を 1 本発行します
2. 自宅の LXC か Docker で、接続文字列を `WGFT_JOIN` に入れてエージェントを起動します。
   名前は接続文字列に紐付いているので入力しません。
   接続文字列には `#` が入るのでクォートします。
   状態ファイルの置き場所をボリュームにしておく
3. エージェント一覧に名前が現れ、最終ハンドシェイクが埋まれば完了。
   接続文字列はこの時点で使い切りになります

ルールの追加と監視:

1. `wgft rule add` で追加します。
   VPS の nftables に即反映され、エージェントに全体状態が配信され、ルール一覧に `ok` が出る
2. `error` なら理由(`target` に繋がらない、など)が一覧に出る
3. 拒否カウンタや新規フロー数はルール一覧で見る。
   荒らしには `wgft rule deny add` で対処し、通信中のフローも含めて即座に切れる

普段の運用で人が触るのは、ルールの追加と拒否リストの追加だけです。
エージェントは再起動しても状態ファイルから復旧し、VPS が再起動しても `vpsd` が同じ鍵で wg0 を作り直すので、どちらも手作業は要りません。

[操作の設計](README.md)
