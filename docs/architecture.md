# wgft アーキテクチャ

wgft のコードは、設計文書([docs/design.md](design.md))の各節が扱う機能ごとに、パッケージが分かれています。以下は、そのパッケージと節の対応、代表的な操作がコードのどこを通るか、そして不具合の調査を始める場所です。

## 1. パッケージと設計文書の対応

| パッケージ | 実装する節 | 役割 |
| --- | --- | --- |
| `internal/dataplane` | 7a.2, 7a.7 | dataplane `Backend` の契約(`Prepare`/`Commit`/`Rollback`、`EnsureWG`、`Converge`、`ReadDrops`、`Dial`)だけを持つ、インタフェース専用のパッケージです |
| `internal/dataplane/linuxkernel` | 6.1, 7a.7 | kernel dataplane の `Backend` です。カーネルの WireGuard(`wg`)、nftables(`nft`)、conntrack 収束(`conntrack`)を束ね、`internal/vpsd` を import しません(将来の agent の kernel backend、7a.8 節 Phase 7 も同じ実装を使います) |
| `internal/dataplane/linuxkernel/nft` | 6.1 | `internal/planner` の `Plan` から `table inet wgft` を組み立て、1 トランザクションで適用します |
| `internal/dataplane/linuxkernel/conntrack` | 6.1(収束) | 外から入って DNAT されたフローを `Plan` の Transparent なルールに収束させます |
| `internal/dataplane/linuxkernel/wg` | 4, 9 | wg0 インタフェースを宣言に収束させます(所有判定、アドレス・MTU・鍵・ピアの突き合わせ) |
| `internal/platform/linux` | 6.1(起動時検査)、4 | Linux ホスト側の前段検査と sysctl です。bind 中のポートとの衝突、他テーブルの forward / input の遮断、他テーブルの同ポート DNAT の検査、`ip_forward` と conntrack テーブルの sysctl、conntrack の UDP タイムアウトの読み取りを持ちます。`internal/dataplane/linuxkernel` からも呼ばれ、`internal/vpsd` を import しません |
| `internal/vpsd/proxyrelay` | 6.2 | プロキシモードのルールについて、vpsd が受けた TCP をエージェントへ中継します |
| `internal/reconcile` | 7a.2 | frontend(プロキシモードの中継)と dataplane を固定の順序で適用する `Runtime` を持ちます |
| `internal/dataplane/userspace` | 6.3 | `vpsd` のユーザー空間モードの転送面です。wireguard-go と netstack のトンネル(`utun`)、中継(`relay`)を束ね、接続元制限とレート制限を `internal/policy/goengine` の評価器で判定し、`internal/planner` の `Plan` から待ち受けと評価器を組み立てます |
| `internal/policy/goengine` | 6.3, 7a.9 | Admission Policy の IR から作る Go の評価器です。userspace モードの中継が、新しいフローと成立済みの UDP セッションのデータグラムをこの評価器で判定します。送信元ごとの同時フロー数と drop カウンタもこの評価器が数えます |
| `internal/dataplane/userspace/relay` | 6.3, 7 | エージェントの netstack 上のリスナーと LAN 内 `target` への中継を持ちます。`vpsd` のユーザー空間モードも、公開ポートの待ち受けと netstack 越しのエージェントへの中継に同じパッケージを使います |
| `internal/dataplane/userspace/tunnel` | 7 | エージェント側が wireguard-go と gVisor の netstack でユーザー空間に持つトンネルです。`internal/dataplane/userspace/utun`(vpsd 側)と対になります |
| `internal/vpsd/stream` | 5.2 | エージェントごとの stream(WebSocket)を持ち、全体状態の配信とハートビートの記録を行います |
| `internal/vpsd/agentapi` | 5.1 | エージェント用 API(登録と stream の公開エンドポイント、自己署名証明書)を持ちます |
| `internal/vpsd/store` | 9 | vpsd の永続状態を SQLite 1 ファイルに保存します |
| `internal/agent/credentials` | 9 | エージェントの認証情報ファイル(`agent.json`)を扱います。設計文書では状態ファイルと呼びます |
| `internal/vpsd/admin` | 10, 11 | 管理用 API と Web UI を持ちます。既定は Unix ソケットで待ち受けます |
| `internal/vpsd/conncheck` | 10.1 | 管理者が UI から行う疎通確認(vpsd からエージェントのリスナーへの TCP 接続)を持ちます |
| `cmd/wgft` | 10.2 | 単一バイナリの CLI です。`server` / `agent` / `rule` のサブコマンドをここにまとめます |
| `internal/netpipe` | 6.2, 7 | 2 つの接続をハーフクローズ維持で双方向に中継します。`proxyrelay` と `internal/dataplane/userspace/relay` が共有します |
| `internal/flock` | 9 | 状態ファイルの隣の `.lock` への排他制御です。vpsd と agent の両方が二重起動の検出に使います |
| `internal/vpsd`(本体) | 2, 6, 9 | 上記の各パッケージを束ねる vpsd 本体(`Daemon`)です。管理 API の backend も実装します |
| `internal/agent`(本体) | 7, 9 | 上記の各パッケージを束ねるエージェント本体(`runtime`)です |
| `proto` | 3, 5.2, 5.3 | 登録・全体状態・ルールの JSON スキーマを定める共有ライブラリです |

## 2. 代表的な経路

### ルールの追加

CLI の `wgft rule add`(`cmd/wgft/rule.go` の `newRuleAddCmd`)は `proto.Rule` を組み立て、`admin.Client.Batch`(`internal/vpsd/admin/client.go`)で管理用 API の `POST /api/v1/rules/batch` を呼びます。

管理用 API の側では、`internal/vpsd/admin/admin.go` の `postBatch` がリクエストを受け取り、`backend.Batch` を呼びます。この `backend` の実体は `internal/vpsd/vpsd.go` の `Daemon.Batch` です。

`Daemon.Batch` は `internal/vpsd/store/rules.go` の `Store.ApplyBatch` を呼び、追加・変更・削除を 1 トランザクションで保存します。世代はこの保存で 1 つ進みます。

保存が成功すると、`Daemon.applyNFT`(`internal/vpsd/apply.go`)が `internal/planner` の `Plan` を組み立て、`internal/reconcile` の `Runtime` で適用します。`Runtime` は、プロキシモードの新しい待ち受けを先に開き、kernel dataplane の `Backend`(`internal/dataplane/linuxkernel`)の `Commit` が `internal/dataplane/linuxkernel/nft` の `Apply` で `table inet wgft` をまるごと差し替え、成功したら中継を始めます。差し替えが失敗したら、新しく開いた待ち受けを閉じます。

`applyNFT` はテーブルの差し替えの直後に `Daemon.converge` を呼び、`Backend.Converge` が `internal/dataplane/linuxkernel/conntrack` の `Converge` で、新しい宣言に合わない DNAT 済みフローを削除します。この順序は、先に conntrack を収束させると旧テーブルで許可されたフローが差し替えまでの間に入ってしまうために保たれています。

変更があった場合、`Daemon.Batch` は `internal/vpsd/stream` の `Hub.PushAll` を呼び、接続中の全エージェントへ新しい全体状態を配ります。

エージェント側では、stream 経由で全体状態を受け取ると `internal/agent` の `runtime.apply`(`agent.go`)が呼ばれ、`internal/dataplane/userspace/relay` の `Manager.Apply` が宣言された `(proto, port)` と現在のリスナーを突き合わせて開閉します。

### エージェントの起動

`internal/agent` の `Run`(`agent.go`)は、まず `credentials.Acquire` で認証情報ファイルの隣の `.lock` に排他をかけ、二重起動を検出します。続けて `credentials.LoadOrNew` で `agent.json` を読み、鍵が無ければ生成し、未登録であれば `ensureRegistered` が `WGFT_JOIN` を使って初回登録を行います。

認証情報ファイルに前回の全体状態(`LastState`)が残っていれば、`runtime.apply` が `internal/dataplane/userspace/tunnel` の `New` でトンネルを先に立て、`internal/dataplane/userspace/relay` の `Manager.Apply` でリスナーを開きます。これは、vpsd が停止中でも VPS 側に wg ピアが残っていれば転送が復旧するようにするための順序です。

並行して `internal/agent/stream.go` の `streamLoop` が vpsd の `/api/v1/agents/stream` に WebSocket で接続し、恒久トークンで認証したうえで自分の wg 公開鍵を宣言します。

vpsd 側では `internal/vpsd/stream` の `Hub.serve` が公開鍵を検証してピアを作り(または置き換え)、続けて全体状態を送ります。エージェントはこれを受け取ると `runtime.apply` を改めて呼びます。

wg 設定が保存済みの値と変わっていればトンネルを張り直し、`internal/dataplane/userspace/relay` の `Manager.Apply` が宣言と現在のリスナーを突き合わせて開閉したうえで、`runtime.apply` は最新の全体状態を認証情報ファイルに保存します。

## 3. 壊れたときに見る順番

- VPS 側の適用状態: `wgft server nft` で、いま適用されている `table inet wgft` をそのまま表示します。ルールが意図どおり入っているかをここで確かめます
- エージェント側の適用状態: `wgft rule ls` が表示するハートビートの `error` 状態です。リスナーが開けない、または TCP ルールで `target` への接続確認が失敗した場合に出ます
- トンネルを挟んだ到達性: Web UI の疎通確認(`internal/vpsd/conncheck`)です。vpsd から wg0 経由でエージェントのリスナーへ TCP 接続し、エージェントの中継を通して `target` に届くかを確かめます
- 窃取や二重稼働の兆候: `wgft agent ls` が表示する 2 つの IP(stream の接続元 IP と wg ピアのエンドポイント IP)です。両方が観測できて食い違っていれば、design.md の 5.2 節の警告の対象になります
