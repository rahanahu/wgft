<a id="7b5-権限と配置"></a>
### 権限と配置

Linux の kernel エージェントは CAP_NET_ADMIN を要します。
モードは server へ通知せず、ハートビートの理由で故障を報告します。


- 権限:`CAP_NET_ADMIN` だけで足りる。
  WireGuard インタフェースの作成と設定、nftables、conntrack の削除、`ip_forward` の書き込みのすべてが、非 root のプロセスで `CAP_NET_ADMIN` だけを持てば通ることを、ラボで確かめた。
  systemd の `ProtectKernelTunables=yes` は `/proc/sys` を読み取り専用にして `ip_forward` の書き込みを止め、`RestrictAddressFamilies` から `AF_NETLINK` を外すとどの操作も失敗します
- unit:同梱の `deploy/agent.service` は変えません。
  ユーザー空間モードのエージェントに要らない権限を渡さないためです。
  カーネルモードに要る `CAP_NET_ADMIN` は、unit に重ねる systemd の drop-in の例 `deploy/agent.kernel.conf` として別に配る(2026-09-24、所有者の決定)。
  置き場所は `/etc/systemd/system/wgft-agent.service.d/kernel.conf` です。
  中身は `AmbientCapabilities=CAP_NET_ADMIN` と `CapabilityBoundingSet=CAP_NET_ADMIN` の 2 行だけであり、エージェントは `User=wgft` のまま動き、unit の他のサンドボックスの設定も変わりません。
  2 行目が要るのは、unit の空の `CapabilityBoundingSet=` が境界の集合を空にしており、境界の集合に無い権限はプロセスが ambient の集合に置けないためです。
  drop-in の空でない値は unit の値に加わるので、境界の集合は `CAP_NET_ADMIN` だけになります。
  drop-in には `ProtectKernelTunables=` を加えず、`RestrictAddressFamilies=` から `AF_NETLINK` を外さない。
  前項のとおり、前者は `ip_forward` の書き込みを止め、後者はどの操作も失敗させるためです。
  この drop-in は、配布物の VM 試験(docs/development/testing.md の B9)の Debian 12 の VM と、試験用の実機の Proxmox VE の非特権の LXC のコンテナ(Debian 13、nesting を有効、AppArmor のプロファイルは unconfined)で確かめた
- 非特権の LXC:動作の対象にします。
  `ip_forward`、WireGuard、nftables、conntrack の操作はどれもコンテナの network namespace の中で完結し、ホストの値を変えないことを、ラボの非特権の LXC で確かめた。
  conntrack の表の上限はコンテナから変えられないので、読むだけにします
- Docker:v1.2 ではカーネルモードの手順を書かない([13 節](../roadmap.md#制限と未実装の提案))
- Linux 以外:Windows と macOS で `WGFT_MODE=kernel` を指定すると、種別 `prerequisite` の拒否として終了コード 3 で止まる([11b 節](../security/startup.md#11b-起動の失敗の意味論))
- カーネルの前提:WireGuard のリンク種別を持たないカーネルと、権限が足りない配置は、[9 節](../state.md#9-状態の保存と再起動)の `vpsd` と同じく種別 `prerequisite` の拒否とし、ユーザー空間モードへの案内を添える
- 前提の検査の時点:エージェントは上の 2 つの前提を、モードを `agent.json` に記録するより前、つまり登録で接続文字列を使うより前に確かめる(2026-09-25、所有者の決定)。
  検査はカーネルに何も書きません。
  権限は、`CAP_NET_ADMIN` を要する読み出しである nftables のテーブルの一覧で確かめ、権限の誤りだけを拒否にします。
  プロセスの `CapEff` のビットで判定しないのは、後の書き込みと同じ判定をカーネルにさせるためです。
  WireGuard は、汎用 netlink の `wireguard` のファミリの問い合わせで確かめる。
  問い合わせに権限は要りません。
  カーネルは、知らないファミリを問われるとモジュールの読み込みを試すので、問い合わせの後もファミリが無ければ、リンクの作成も同じく失敗します。
  どちらの読み出しでも、それ以外の誤りでは起動を止めず、この検査が無い場合と同じく最初の収束([7b.4 節](lifecycle.md#7b4-収束と停止))に分類を任せる。
  前提で止まる起動は `agent.json` を書き換えず、接続文字列も使わないので、拒否の文面の案内どおり `WGFT_MODE=userspace` にすれば、そのまま登録して起動できます。
  記録の後に止まると、ユーザー空間モードへ戻す起動が [11a 節](../security/configuration.md#11a-設定の渡し方)の関門に止められ、関門が案内する撤去には `CAP_NET_ADMIN` が要る。
  カーネルには何も作られていないのに、案内どおりに戻す道が閉じるので、検査を記録より前に置く。
  最初の収束での同じ分類は残します。
  検査を通っても、書き込みだけが拒まれる配置がありうるためです

<a id="7b6-server-との関係"></a>
### server との関係

server にはエージェントのモードを知らせない(2026-09-24、所有者の決定)。
wire protocol、管理用 API、全体状態の形は変わらず、ハートビートの理由の文言だけがモードで変わる。
`server doctor` と Web UI の経路の図の節点の名前(`listener / target` など)も変えません。
モードを知らせるには、wire と管理用 API への加算と、[7a.6 節](../architecture/wire-compatibility.md#7a6-維持する外部仕様と互換性)の capability の検証が要るためです。
見直しは [13 節](../roadmap.md#制限と未実装の提案)に置く。

プロキシモードのルール([6.2 節](../vps/proxy.md#62-プロキシモード))と疎通確認([10.1 節](../interface.md#101-web-ui))では、`vpsd` がエージェントのトンネルアドレスの `listen_port` へ接続します。
カーネルモードではこの接続も wgft0 から入るので、同じ DNAT で宛先に届く見込みです。
この点は未確認です。

[kernel エージェント](README.md)
