# wgft 設計文書

wgft は、VPS を入口にして、自宅の TCP と UDP のサービスを WireGuard 経由で公開する L4 転送ツールです。
TLS 終端と L7 の認証は自宅側のサービスが担当します。


VPS で受けた TCP/UDP を WireGuard 経由で自宅のサービスへ届けるツール。
名前は WireGuard Forwarding Tool の略。

## 背景と全体像

自宅のサービス(ゲームサーバ、Web サービス)を、固定 IP を持つ VPS 経由でインターネットに公開したい。
自宅側は NAT 配下でポート開放を避けたいので、自宅から VPS へ WireGuard トンネルを張り、VPS に届いたパケットをトンネル経由で自宅へ転送します。
この構成は Pangolin から着想を得た。
Pangolin を使う中で VPS を入口にして自宅サービスを公開する構成の便利さを知った一方、ゲームサーバなどの raw TCP/UDP 転送だけが目的なら、より直接的で小さな構成が欲しくなった。
また、日本の IPv4 over IPv6 接続の一部では任意の受信 IPv4 ポートを使えない場合があり、VPS を入口にする構成はその制約を避ける用途にも合う。
そこで WireGuard と nftables を直接組み合わせ、その手作業をツールに置き換える。

置き換え後の全体像は次のとおりです。

- DNS:ワイルドカードレコードで VPS の IP を指す
- VPS:本ツールが、指定したポートを自宅へ素通しします。
  接続元 IP による制限もここで行います
- 自宅:本ツールのエージェントがトンネルを張り、届いたパケットを LAN 内のサービスへ中継します。
  HTTPS は自宅側のリバースプロキシ(Caddy)が TLS 終端とホスト名の振り分けを担う

本ツールは L4 の転送だけを担当し、TLS、証明書、認証は扱わない。

<a id="1-目的と範囲"></a>
## 目的と範囲

VPS から自宅へのポート転送に必要な nftables と WireGuard の手作業設定をなくすことが目的です。

やること:

- 任意の TCP/UDP ポートを VPS から自宅の任意ホストへ転送します
- 自宅側はエージェントを置くだけで繋がる(自宅側のポート開放は不要)
- 転送ルールごとに、接続元 IP による許可と拒否、レート制限を VPS 側で行います
- 転送ルールの追加削除を Web UI と CLI から行います
- 既存の nftables ルールを壊さない

やらないこと:

- TLS 終端、証明書取得、SNI やパスによる振り分け(自宅側の Caddy が担う)
- 認証ゲート、共有リンク
- L7 の解釈全般
- 接続元 IP を自宅側のサービスへ伝えること(TCP の PROXY protocol を除く)

<a id="2-全体構成"></a>
## 全体構成

| 部品 | 動作場所 | 役割 |
|---|---|---|
| `vpsd` | VPS | wg0 の管理、nftables の適用、conntrack の操作、API と Web UI、状態の保存 |
| `agent` | 自宅 | `vpsd` への登録、wg トンネルの維持、届いたパケットの LAN 内サービスへの転送(ユーザー空間モードは自分で中継し、カーネルモードはカーネルの DNAT を設定する) |
| `proto` | 両方 | 登録と全体状態配信の JSON スキーマを定める共有ライブラリ。実行されるプロセスではない |

実装言語は Go。
`vpsd` と `agent` は同一バイナリで、サブコマンド `server` と `agent` で切り替える(起動はそれぞれ `wgft server run`、`wgft agent run`)。
`vpsd` は本書と内部での呼び名で、利用者に見えるコマンド名は `server` です。
`vpsd` は wgctrl-go で WireGuard を、google/nftables で nftables を、ti-mo/conntrack で conntrack を直接操作し、Web UI はバイナリに埋め込む。
`agent` は 2 つのモードを持ちます。
既定のユーザー空間モードは、wireguard-go と gVisor の netstack でトンネルをユーザー空間に持ち、カーネルの設定を変更しない([7 節](agent-dataplane.md#7-データプレーン自宅側))。
Linux のエージェントだけが明示して選べるカーネルモードは、カーネルの WireGuard インタフェースと nftables の DNAT で転送し、`vpsd` と同じく wgctrl-go、google/nftables、ti-mo/conntrack でカーネルを直接操作する([7b 節](agent-kernel.md#7b-データプレーン自宅側カーネルモード))。

<a id="3-用語"></a>
## 用語

- **`vpsd`**:VPS 側で動くデーモン。
  `wgft server run` で起動するプロセスを本書と内部ではこう呼び、利用者に見える名前(コマンド、設定ファイル、unit)は `server` です
- **エージェント**:自宅側で動く `agent` の 1 インスタンス。
  1 拠点に 1 つ置く想定だが、複数登録できます
- **ルール**:「VPS の `<proto>/<port>` を、エージェント `<name>` 経由で `<host>:<port>` へ届ける」という 1 行の宣言
- **接続元制限**:ルールに付ける、接続元 IP の許可リスト、拒否リスト、レート制限
- **全体状態**:`vpsd` がエージェントに配る、そのエージェントに関わる wg 設定とルール集合の全体
- **世代**:全体状態の版を表す単調増加の整数。
  エージェントに配る内容が変わったときだけ `vpsd` が増やし、SQLite に保存します。
  管理用 API の 1 リクエストで上がる世代は最大 1 つ
- **リスナー**:エージェントが netstack 上に開く待ち受け。
  単一ポートごとに 1 つで、`(proto, port)` で同一性を取ります。
  状態として実効宛先(`host:port`)と所属ルール ID を持ちます
- **状態ファイル**:エージェントが恒久トークン、wg の秘密鍵、証明書のハッシュ、最後の全体状態を保存するファイル(`agent.json`。
  [9 節](state.md#9-状態の保存と再起動))。
  本書と内部では状態ファイルと呼び、利用者に見える文言(UI、CLI、README)では**認証情報**(英語は credentials)と呼ぶ。
  `vpsd` 側の SQLite は別物で、利用者向けにはサーバのデータベースと呼ぶ
- **stream**:エージェントが `vpsd` に張る常時接続(WebSocket)。
  全体状態の配信、公開鍵の宣言、ハートビートに使う([5.2 節](control/connection.md#52-全体状態の配信とハートビート))
- **エージェント用 API** と **管理用 API**:`vpsd` が持つ 2 つの HTTP リスナー。
  前者は公開でエージェントの登録と stream だけを受け、後者は Unix ソケット(既定)か Tailscale のアドレスで Web UI と CLI が使う([5 節](control/README.md#5-制御プレーン)、[11 節](security/admin-transport.md#11-セキュリティ))
- **カーネルモード** と **プロキシモード**:VPS 側の転送方式。
  前者は nftables の DNAT でカーネルが転送し、後者は `vpsd` 自身が TCP を受けて中継する([6 節](vps-dataplane.md#6-データプレーンvps-側))。
  ルールごとに `vps_mode` で選ぶ。
  内部の実装ではこの選択を `Forwarding` という型(`Transparent`/`Relay`)で表し、`proxy_protocol` は別の型 `SourceMetadata`(`None`/`ProxyV2`)で表します。
  どちらも server・agent 全体の転送方式(`DataplaneMode`。
  [11a 節](security/configuration.md#11a-設定の渡し方)の `WGFT_MODE`)とは区別する([7a 節](architecture/model.md#7a-内部アーキテクチャ))
- **疎通確認**:管理者が UI から、`vpsd` 経由で自宅の `target` に届くかを試す操作([10.1 節](interface.md#101-web-ui))
- **エージェントの無効化** と **有効化**:前者は、エージェントの登録を残したまま、そのエージェントのルールの転送を止める操作であり、後者はそれを戻す操作です。
  英語は disable と enable です。
  無効化したエージェントの状態を「無効」と呼ぶ。
  エージェントの無効は、ルールごとの `enabled`([5.3 節](control/rules.md#53-ルールのスキーマ))とは別の値であり、互いを書き換えない([5.1 節](control/registration.md#51-登録))
- **エージェントの削除**:エージェントの登録を取り消す操作。
  英語は revoke です。
  恒久トークンは使えなくなり、元に戻せない。
  同じ名前で使い直すには、新しい接続文字列で登録し直す([5.1 節](control/registration.md#51-登録))

## 関連する仕様

- [network.md](network.md)
- [制御プレーン](control/README.md)

<details>
<summary>旧見出しの参照先</summary>

- <a id="4-ネットワーク"></a> [4-ネットワーク](network.md#4-ネットワーク)
- <a id="5-制御プレーン"></a> [5-制御プレーン](control/README.md#5-制御プレーン)
- <a id="51-登録"></a> [51-登録](control/registration.md#51-登録)
- <a id="エージェントの無効化と有効化"></a> [エージェントの無効化と有効化](control/registration.md#エージェントの無効化と有効化)
- <a id="エージェントの削除とルール"></a> [エージェントの削除とルール](control/registration.md#エージェントの削除とルール)
- <a id="52-全体状態の配信とハートビート"></a> [52-全体状態の配信とハートビート](control/connection.md#52-全体状態の配信とハートビート)
- <a id="53-ルールのスキーマ"></a> [53-ルールのスキーマ](control/rules.md#53-ルールのスキーマ)
- <a id="54-ルールのバッチ操作"></a> [54-ルールのバッチ操作](control/batches.md#54-ルールのバッチ操作)
- <a id="55-複数サービスへの配り方"></a> [55-複数サービスへの配り方](control/targets.md#55-複数サービスへの配り方)

</details>
