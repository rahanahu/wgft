# wgft 設計文書

wgft は、自宅の TCP と UDP のサービスを VPS から WireGuard 経由で公開する L4 転送ツールです。
TLS 終端と L7 の認証は自宅側のサービスが担当します。
名前は WireGuard Forwarding Tool の略です。

## 背景と全体像

想定する用途は、自宅のサービス(ゲームサーバ、Web サービス)を、固定 IP を持つ VPS 経由でインターネットに公開することです。
自宅側は NAT 配下でポート開放を避けたいので、自宅から VPS へ WireGuard トンネルを張り、VPS に届いたパケットをトンネル経由で自宅へ転送します。

wgft の構成は Pangolin から着想を得ました。
Pangolin を使う中で、VPS 経由で自宅のサービスを公開する構成の便利さを知りました。
一方で、ゲームサーバなどの raw TCP/UDP 転送だけが目的なら、より直接的で小さな構成が欲しくなりました。
また、日本の IPv4 over IPv6 接続の一部では、任意の受信 IPv4 ポートを使えない場合があります。
VPS で受けて自宅へ転送する構成は、その制約を避ける用途にも合います。

そこで、WireGuard と nftables を直接組み合わせ、組み合わせに要る手作業をツールに置き換えます。
置き換え後の全体像は次のとおりです。

- DNS:ワイルドカードレコードで VPS の IP を指します
- VPS:本ツールが、指定したポートを自宅へそのまま転送します。
  接続元 IP による制限も VPS で行います
- 自宅:本ツールのエージェントがトンネルを張り、届いたパケットを LAN 内のサービスへ中継します。
  HTTPS は自宅側のリバースプロキシ(Caddy)が TLS 終端とホスト名の振り分けを担います

本ツールは L4 の転送だけを担当し、TLS、証明書、認証は扱いません。

<a id="1-目的と範囲"></a>
## 目的と範囲

VPS から自宅へのポート転送に必要な nftables と WireGuard の手作業設定をなくすことが目的です。

やること:

- 任意の TCP/UDP ポートを VPS から自宅の任意ホストへ転送します
- 自宅側はエージェントを置くだけで接続できます。自宅側のポート開放は要りません
- 転送ルールごとに、接続元 IP による許可と拒否、レート制限を VPS 側で行います
- 転送ルールの追加削除を Web UI と CLI から行います
- 既存の nftables ルールを壊しません

やらないこと:

- TLS 終端、証明書取得、SNI やパスによる振り分け(自宅側の Caddy が担います)
- 認証ゲート、共有リンク
- L7 の解釈全般
- 接続元 IP を自宅側のサービスへ伝えること(TCP の PROXY protocol を除く)

<a id="2-全体構成"></a>
## 全体構成

| 部品 | 動作場所 | 役割 |
|---|---|---|
| `vpsd` | VPS | wg0 の管理、nftables の適用、conntrack の操作、API と Web UI、状態の保存 |
| `agent` | 自宅 | `vpsd` への登録、wg トンネルの維持、届いたパケットの LAN 内サービスへの転送。ユーザー空間モードは自分で中継し、カーネルモードはカーネルの DNAT を設定します |
| `proto` | 両方 | 登録と全体状態配信の JSON スキーマを定める共有ライブラリです。実行されるプロセスではありません |

実装言語は Go です。
`vpsd` と `agent` は同一バイナリで、サブコマンド `server` と `agent` で切り替えます。
起動のコマンドはそれぞれ `wgft server run` と `wgft agent run` です。
`vpsd` は本書と内部での呼び名で、利用者に見えるコマンド名は `server` です。
`vpsd` は wgctrl-go で WireGuard を、google/nftables で nftables を、ti-mo/conntrack で conntrack を直接操作します。
Web UI はバイナリに埋め込みます。

`agent` は 2 つのモードを持ちます。
既定のユーザー空間モードは、wireguard-go と gVisor の netstack でトンネルをユーザー空間に持ち、カーネルの設定を変更しません([7 節](agent-dataplane.md#7-データプレーン自宅側))。
Linux のエージェントだけが明示して選べるカーネルモードは、カーネルの WireGuard インタフェースと nftables の DNAT で転送します。
カーネルモードは、`vpsd` と同じく wgctrl-go、google/nftables、ti-mo/conntrack でカーネルを直接操作します([7b 節](agent-kernel.md#7b-データプレーン自宅側カーネルモード))。
Linux のエージェントにはカーネルモードを推奨し、既定は互換性のためユーザー空間モードのままとします([モードの推奨と既定](userspace/mode-selection.md#モードの推奨と既定))。

<a id="3-用語"></a>
## 用語

- **`vpsd`**:VPS 側で動くデーモンです。
  `wgft server run` で起動するプロセスを本書と内部ではこう呼び、利用者に見える名前(コマンド、設定ファイル、unit)は `server` です
- **エージェント**:自宅側で動く `agent` の 1 インスタンスです。
  1 拠点に 1 つ置く想定ですが、複数登録できます
- **ルール**:「VPS の `<proto>/<port>` を、エージェント `<name>` 経由で `<host>:<port>` へ届ける」という 1 行の宣言です
- **接続元制限**:ルールに付ける、接続元 IP の許可リスト、拒否リスト、レート制限です
- **全体状態**:`vpsd` がエージェントに配る、そのエージェントに関わる wg 設定とルール集合の全体です
- **世代**:全体状態の版を表す単調増加の整数です。
  エージェントに配る内容が変わったときだけ `vpsd` が増やし、SQLite に保存します。
  管理用 API の 1 リクエストで増える世代は最大 1 つです
- **リスナー**:エージェントが netstack 上に開く待ち受けです。
  単一ポートごとに 1 つで、`(proto, port)` の組で識別します。
  状態として実効宛先(`host:port`)と所属ルール ID を持ちます
- **状態ファイル**:エージェントが恒久トークン、wg の秘密鍵、証明書のハッシュ、最後の全体状態を保存するファイル `agent.json` です([9 節](state.md#9-状態の保存と再起動))。
  本書と内部では状態ファイルと呼び、利用者に見える文言(UI、CLI、README)では**認証情報**(英語は credentials)と呼びます。
  `vpsd` 側の SQLite は別物で、利用者向けにはサーバのデータベースと呼びます
- **stream**:エージェントが `vpsd` に張る常時接続(WebSocket)です。
  全体状態の配信、公開鍵の宣言、ハートビートに使います([5.2 節](control/connection.md#52-全体状態の配信とハートビート))
- **エージェント用 API** と **管理用 API**:`vpsd` が持つ 2 つの HTTP リスナーです。
  前者は公開の待ち受けで、エージェントの登録と stream だけを受け付けます。
  後者は Web UI と CLI が Unix ソケット(既定)か Tailscale のアドレスで使います([5 節](control/README.md#5-制御プレーン)、[11 節](security/admin-transport.md#11-セキュリティ))
- **カーネルモード** と **プロキシモード**:VPS 側の転送方式です。
  前者は nftables の DNAT でカーネルが転送し、後者は `vpsd` 自身が TCP を受けて中継します([6 節](vps-dataplane.md#6-データプレーンvps-側))。
  ルールごとに `vps_mode` で選びます。
  内部の実装ではこの選択を `Forwarding` という型(`Transparent`/`Relay`)で表し、`proxy_protocol` は別の型 `SourceMetadata`(`None`/`ProxyV2`)で表します。
  どちらも、server と agent 全体の転送方式 `DataplaneMode` とは区別します([7a 節](architecture/model.md#7a-内部アーキテクチャ))。
  `DataplaneMode` は [11a 節](security/configuration.md#11a-設定の渡し方)の `WGFT_MODE` に当たります
- **疎通確認**:管理者が UI から、`vpsd` 経由で自宅の `target` に届くかを試す操作です([10.1 節](interface.md#101-web-ui))
- **エージェントの無効化** と **有効化**:前者は、エージェントの登録を残したまま、そのエージェントのルールの転送を止める操作であり、後者はそれを戻す操作です。
  英語は disable と enable です。
  無効化したエージェントの状態を「無効」と呼びます。
  エージェントの無効は、ルールごとの `enabled`([5.3 節](control/rules.md#53-ルールのスキーマ))とは別の値であり、互いを書き換えません([5.1 節](control/registration.md#51-登録))
- **エージェントの削除**:エージェントの登録を取り消す操作です。
  英語は revoke です。
  恒久トークンは使えなくなり、元に戻せません。
  同じ名前で使い直すには、新しい接続文字列で登録し直します([5.1 節](control/registration.md#51-登録))

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
