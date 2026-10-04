<a id="7a7-package-配置"></a>
### package 配置

モデルと計画は副作用から切り離し、kernel の操作は共通の部品へ集約します。
依存の向きは単体テストが検査します。


目標とする配置は次のとおりです。

```
internal/
  model/                 Rule、Forwarding、SourceMetadata、proto.Rule との写像(FromProto/ToProto)
  policy/                AdmissionPolicy(IR)
  policy/nftables/       IR から nftables の行の列へのコンパイラ(google/nftables を import しない。7a.9 節)
  policy/goengine/       IR から Go の評価器へのコンパイラ
  planner/               Planner、Plan
  resource/              Resource Guard(予算、カウンタ)
  lograte/               同じ理由で繰り返すログを間引く門(7a.10 節)と、名前の解決の誤りの文面をそろえる関数(5.2 節)
  startup/               起動の拒否の型と種別(11b 節)
  textsafe/              信頼できない文字列を端末向けに無害化する関数(11 節)
  reasontext/            ルールの理由の文言のうち、理由を書く側と server doctor が共有する断片(10.2a 節)
  reconcile/             Observe -> diff -> Prepare -> Commit の骨格(今は server が使う。agent は変更の通知の購読の張り直しと公開し直しの間隔だけを使い、移行は後の段階)
  dataplane/             Backend interface(Observe、Prepare、Commit、Rollback)
  dataplane/userspace/   wireguard-go + netstack + 中継
  dataplane/linuxkernel/ カーネルの WireGuard、nftables、conntrack、所有判定
  platform/linux/        sysctl、capability、他ファイアウォールとの衝突の検査
  vpsd/                  制御プレーン(登録、stream、SQLite、admin API)。proxyrelay が frontend の participant を実装する(下記)
  vpsd/servercheck/      `wgft server check`。internal/vpsd の下位の package のうち store だけを import する(下記)
  vpsd/teardown/         `wgft server teardown`。internal/vpsd の下位の package のうち store だけを import する(下記)
  vpsd/tailnet/          --admin-tailscale の待ち受け(11 節)。internal/vpsd のどの package も import しない(下記)
  agent/                 制御プレーン(認証情報、stream クライアント、rotate-key)と、2 つのモードの選択(下記)
  agent/credentials/     認証情報ファイル(agent.json)、そのロック、停止中に CLI が認証情報ファイルを書くための排他(9 節)
  agent/allowtargets/    エージェントが接続してよい宛先の一覧(7 節)
  agent/teardown/        wgft agent teardown の判定と順序、撤去のカーネル操作(10.3 節)。実行時の状態に依存しない
  agent/controlapi/      制御ソケットの wire の型と定数(proto と resource だけを import する葉。下記)
  agent/control/         制御ソケットのサーバと、エージェントのホストで動く CLI の側(rotate-key、agent pubkey)。実行時の状態は Backend の後ろに置き、internal/agent の下では controlapi と credentials だけを import する(下記)
  agent/agentdp/         エージェントの dataplane の境目(Dataplane と任意の interface、1 回の読み取りの型、起動の失敗の型)。internal/agent の下では controlapi だけを import する(下記)
  agent/usermode/        ユーザー空間モードの dataplane。wireguard-go と netstack のトンネルと中継を包む。internal/agent の下では agentdp と allowtargets だけを import する(下記)
  agent/kernelmode/      カーネルモードの dataplane と、停止中の agent doctor が使うカーネルの読み取り。internal/agent の下では agentdp、allowtargets、credentials、controlapi だけを import し、usermode を import しない(下記)
  agent/enroll/          登録のクライアントの側(接続文字列の解釈、ピン留めした登録 API の呼び出し、登録の結果の認証情報への記録)
proto/                   維持する外部仕様としての wire スキーマ(既存フィールドの意味は変えず、加算のみ許す)
```

`platform/windows/`、`platform/darwin/` は、Windows・macOS の agent([13 節](../roadmap.md#制限と未実装の提案))に着手するときに設ける。
今は `platform/linux/` だけがあり、目標の木には含めません。

依存の向きは一方向です。
`model`、`policy`、`planner`、`resource` は OS、nftables、gVisor を知らない純粋な Go の型と関数だけを持ち、`dataplane/*`、`platform/*` を一切 import しません。
`reconcile` は `planner` の `Plan` と、`Runtime` を組み立てる participant の interface(dataplane の `Backend`、frontend の `Frontend`/`FrontendPrepared`)だけを持ち、`dataplane/userspace`・`dataplane/linuxkernel` にも、frontend の実装にも依存しません。
`dataplane/*` は `model`、`policy`、`planner`、`resource`、`platform/*` を import できるが、互いには依存しません。
`planner` を含めるのは、`Backend` が収束先を `Plan` と実行時の入力(frontend が待ち受けているポートの集合など)だけから受け取り、設定やルール集合を別の経路から読まないためです。
`Relay` の listener 集合という frontend 側の資源には独立した package を置かない。
server では `internal/vpsd/proxyrelay` が `Prepare`/`Commit`/`Rollback` を持ち、`internal/vpsd` がそれを `reconcile.Frontend`/`FrontendPrepared` へ橋渡しする([7a.2 節](model.md#7a2-層と責務))。
`vpsd` と `agent` は上記すべてを import できる唯一の層です。
`vpsd` は起動時に dataplane と frontend の実装から `Runtime` を組み立て、`reconcile` に渡す。
この向きにより `internal/dataplane/linuxkernel` が `internal/vpsd` に依存しない構造になり、agent のカーネルモード([7b 節](../agent-kernel.md#7b-データプレーン自宅側カーネルモード))が server の kernel backend の共通の部品(WireGuard、host 側の検査、nftables と conntrack の基本操作)を再利用できます。
VPS 用の table(公開ポートから agent への DNAT)とその収束は server に固有で、agent には LAN の宛先への DNAT、MASQUERADE、agent 側の conntrack 収束という別の経路を同じ package に足す。

`internal/vpsd` の根には、実行時の状態を持つ `Daemon` と、下位の package が定める `Backend` の実装と、起動の配線を置く。
`Daemon` に依存しない機能は下位の package に置く。
`internal/vpsd/servercheck` は `wgft server check`([6.1 節](../vps/kernel.md#61-カーネルモード)、[10.3 節](../operations/setup.md#103-運用の流れ)、[11a 節](../security/configuration.md#11a-設定の渡し方))を持ちます。
このコマンドは server を起動せずにサーバのデータベースを読むだけなので、`internal/vpsd` の下位の package のうち `store` だけを import します。
`internal/dataplane/deps_test.go` の `TestVpsdServerCheckImportsOnlyTheStore` がこれを検査します。
`internal/vpsd/teardown` は `wgft server teardown`([10.3 節](../operations/setup.md#103-運用の流れ))と、その手掛かりを起動時に記録する関数を持ちます。
撤去は停止した server の後片付けとしてサーバのデータベースを読むので、`internal/vpsd` の下位の package のうち `store` だけを import します。
`internal/dataplane/deps_test.go` の `TestVpsdTeardownImportsOnlyTheStore` がこれを検査します。
`internal/vpsd/tailnet` は `--admin-tailscale` の待ち受け([11 節](../security/admin-transport.md#11-セキュリティ))を持ちます。
この package は管理用 API の応答と、Host の検査で許す名前の更新を関数の値として受け取るので、`internal/vpsd` のどの package も import しません。
`internal/dataplane/deps_test.go` の `TestVpsdTailnetImportsNoServerPackage` がこれを検査します。

agent は `reconcile.Runtime`、`dataplane.Backend`、`planner.Plan` をまだ使いません。
`internal/agent` は userspace のトンネル(`internal/dataplane/userspace/tunnel`)と中継(`internal/dataplane/userspace/relay`)を直接駆動し、全体状態(`proto.AgentRule` を含む)を自分で収束させる。
v1.2 はこの形を保ったまま、`internal/agent` の中に狭い dataplane の境目を切り、その後ろにユーザー空間モードとカーネルモードの 2 つの実装を置く(2026-09-24、所有者の決定)。
ユーザー空間モードの実装は今のトンネルと中継をそのまま包み、カーネルモードの実装は `internal/dataplane/linuxkernel` の部品から組み立てる。
agent 全体を `Runtime` へ移してからカーネルモードを足す案は採らなかった。
移行はトンネルの作り直し([7 節](../agent-dataplane.md#7-データプレーン自宅側))、全体状態の適用の試し直し、`agent doctor`([10.2c 節](../diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor))の経路を巻き込み、カーネルモードを加えるという目的より大きいためです。
agent を `Runtime` へ移すのは後の段階とします。

この境目は依存の向きの規則を変えません。
カーネルモードのために加える部品は `internal/dataplane/linuxkernel` の下に置き、`internal/agent` を import しません。
`internal/dataplane/deps_test.go` の `TestDependencyDirection`、`TestPureLayersStayPure`、`TestVpsdSubpackagesDoNotImportVpsd`、`TestPolicyNftablesDoesNotImportGoogleNftables` は変えずに、この配置を検査します。

境目は `internal/agent/agentdp` の interface `Dataplane` です。
ユーザー空間モードの実装は `internal/agent/usermode` の `Dataplane` であり、カーネルモードの実装は `internal/agent/kernelmode` の `Dataplane` です。
境目の後ろの実装が持つのは、トンネルを立てることと閉じること、ルールの宣言への収束、30 秒ごとの見直し、watchdog が読む最終ハンドシェイク、ハートビートと `agent doctor` が共有する 1 回の読み取りです。
処理済み世代と `last_state` の記録、トンネルの作成の試し直しの予定、トンネルを作り直すかどうかの判定は、境目の手前の実行時の状態に残します。
ルールの収束は、宣言をまとめて公開できなかった backend 全体の失敗([7b.3 節](../kernel-agent/targets.md#7b3-ルールの状態と失敗の種類)の 3 つ目の種類)を誤りとして返し、このとき処理済み世代は進まない。
ルール単位の失敗は誤りにせず、ルールごとの状態として読み取りに載せる。

カーネルモードの実装だけが持つ処理は、`internal/agent/agentdp` の任意の interface に置く。
全体状態の適用の前の名前の解決、wg 設定の検証、30 秒ごとの見直し、変更の通知の購読、起動時の所有の判定、`agent doctor` のためのカーネルの読み取りです。
実行時の状態は任意の interface を型アサーションで探し、満たさない実装ではその処理を飛ばす。
メソッドの形がずれても黙って飛ばされないよう、カーネルモードの実装がそれぞれの interface を満たすことをコンパイル時に検査します。
`agentdp` は実行時の状態と 2 つのモードの実装の両方から import されるので、それらより下に置く。
モジュールの中から直接 import するのは、`proto`、`internal/resource`、`internal/dataplane`、読み取りの型が載せる中継とソケットのバッファの型の package(`internal/dataplane/userspace/relay`、`internal/dataplane/userspace/sockbuf`)、カーネルの読み取りの型を持つ `internal/agent/controlapi` だけです。
`internal/agent` とその他の下位の package、`internal/dataplane/linuxkernel` には推移的にも依存しません。
`internal/dataplane/deps_test.go` の `TestAgentDataplaneBoundaryImports` がこの規則を検査します。

`internal/agent/usermode` はユーザー空間モードの実装を持ち、wireguard-go と netstack のトンネル(`internal/dataplane/userspace/tunnel`)と、その上の中継(`internal/dataplane/userspace/relay`)を包む。
`internal/agent` の下で import するのは `agentdp` と `allowtargets` だけです。
`internal/agent` 自身、`internal/agent/kernelmode`、`internal/dataplane/linuxkernel` には推移的にも依存しません。

`internal/agent/kernelmode` はカーネルモードの実装を持ち、`internal/dataplane/linuxkernel` の部品でカーネルの WireGuard インタフェースと `table inet wgft_agent` を宣言へ収束させる。
停止中の `agent doctor` が読むカーネルの読み取り(`ReadKernel`)も同じ package にあり、稼働中のエージェントの読み取りと同じ関数を使います。
`internal/agent` の下で import するのは `agentdp`、`allowtargets`、`credentials`、`controlapi` だけです。
`internal/agent` 自身、`internal/agent/usermode`、`internal/vpsd` とその下位の package には推移的にも依存しません。
`internal/dataplane/userspace` とその下位の package は直接 import しません。
読み取りの型が載せる中継とソケットのバッファの型の package には、`agentdp` を通して推移的に依存します。
`internal/agent` 自身は `internal/dataplane/linuxkernel` とその下位の package を直接 import しません。
この 2 つの規則の検査は直接の import だけを見る。
ほかの package を通した推移的な依存は検査の外です。
例えば、カーネルの層を import する `internal/agent/teardown` を `internal/agent` の本番のファイルが import しても、この検査は落ちない。

この節の 2 つのモードの規則は本番のファイルに当てはめ、テストのファイルには当てはめない。
カーネルモードのテストは、エージェントが書く理由の文言を server doctor に読ませて確かめるために、`internal/vpsd/doctor` などを import します。
`internal/dataplane/deps_test.go` の `TestAgentModesStayApart` が、2 つのモードの package と `internal/agent` 自身の import をテスト以外のファイルから読み、これらの規則を検査します。

Go には、package をまたいでテストにだけ名前を見せる仕組みがありません。
`internal/agent` のテストがユーザー空間モードの実装の中身を読み書きできるよう、`usermode` はトンネルと中継のフィールド、宛先の許可一覧とフロー予算のフィールド、トンネルの作成と状態の読み取りの差し替え口、ルールごとの状態の合成、中継の調整値の組み立てを公開します。
これらはテストのための口であり、本番のコードが `usermode` の外から使ってよいのは作成の関数 `New` だけです。
`kernelmode` も同じ理由で、dataplane の型とそのフィールドの一部、wgft0 の宣言を返すメソッド、カーネルと名前解決への操作の差し替え口とその型、カーネルの読み取りの操作の差し替え口とその型、収束が済んでいない前の公開を残す数の上限を公開します。
本番のコードが `kernelmode` の外から使ってよいのは、作成の関数 `New`、このビルドがカーネルモードを持つかどうか(`Built`)、ホストの前提の検査(`Prerequisites`)、このプロセスが `CAP_NET_ADMIN` を持つかどうかの読み取り(`ProcessNetAdmin`)、カーネルの読み取り(`ReadKernel`)だけです。
`internal/agent/control`(下記)も同じ理由で、接続を 1 つ処理する関数 `ServeConn` を `internal/agent` のテストのために公開します。
本番のコードが `control` の外から使ってよいのは、制御ソケットを開いて指示を受ける関数 `Serve`、実行時の状態の interface `Backend`、CLI の側の `RotateKey` と `PublicKey` だけです。
本番のコードが使ってよい名前とテストのための口は、`internal/dataplane/deps_test.go` の `modeSeams` と `modeTestSeams` に、モードの package と `control` の package ごとに列挙します。
これらの package が公開する名前は、`agentdp` の interface を満たすメソッドを除いて、どちらか一方だけに載せる。
公開した interface の型のメソッド(`Backend` のメソッド)は、どちらの一覧にも載せない。
`Backend` を満たすメソッドは実装の側の型が持つためです。
本番のコードが package の外から interface の型を通じてそのメソッドを使うことは許さず、同じ検査が、テストのための口とは別の文言で落ちる。
同じファイルの `TestAgentModeTestSeamsStayInTests` が、これらの package を import するモジュールの中の package の本番のファイルを型検査し、この規則を検査します。

`internal/agent` の下位の package は `internal/agent` を import しません。
実行時の状態を持つ `internal/agent` が下位の package を使う向きだけを許し、`wgft agent teardown` のような 1 回限りのコマンドを実行時の状態から切り離すためです。
`internal/vpsd` の下位の package と同じ規則であり、`internal/dataplane/deps_test.go` の `TestAgentSubpackagesDoNotImportAgent` が検査します。

制御ソケット([9 節](../state.md#9-状態の保存と再起動)、[10.2c 節](../diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor))の wire の型と定数は `internal/agent/controlapi` に置く。
`doctor` の要求と応答の型、応答に載せる 1 つの文字列の長さの上限、応答が載せるカーネルモードの読み取りの型と列挙の値、ソケットのパスの規則と長さの上限、応答の 1 行の読み取りとその大きさの上限、読み手が照らし合わせるトンネルの理由の文字列が含まれる。
応答を組み立てる処理は `internal/agent` に残り、制御ソケットのサーバと、エージェントのホストで動く CLI の側(`rotate-key` と `agent pubkey`)は `internal/agent/control` に置く。
サーバは実行時の状態を `control.Backend` を通じて呼び、`internal/agent` がそれを実装します。
`cmd/wgft` の `agent doctor` は、稼働中のエージェントの実装に依存せずに応答の形を読みます。
server の `internal/vpsd/adminapi`(管理用 API の読み取りの型。
[10.2d 節](../web-doctor.md#102d-web-ui-の診断の画面))と同じ位置づけの葉です。
モジュールの中から、`adminapi` は `proto` だけを、`controlapi` は `proto` と `internal/resource` だけを import します。
`controlapi` が `internal/resource` を import するのは、フロー予算の拒否の理由が `resource.Reason` の型を持つためです。
`internal/resource` 自身はモジュールの中を何も import しません。
`internal/dataplane/deps_test.go` の `TestWireShapesStayLeaf` がこの規則を検査します。

`internal/agent/control` が `internal/agent` の下で import するのは `controlapi` と `credentials` だけです。
`internal/agent` 自身、`internal/agent/agentdp`、`internal/agent/usermode`、`internal/agent/kernelmode`、`internal/dataplane` とその下位の package には推移的にも依存しません。
この規則も本番のファイルだけに当てはめる。
`internal/dataplane/deps_test.go` の `TestAgentControlImportsNoRuntimeOrMode` が、`control` の import をテスト以外のファイルから読み、この規則を検査します。

`internal/agent/enroll` は登録のクライアントの側を持ち、`internal/agent` の初回の登録と登録のし直しの両方が使います。
`cmd/wgft` も、`agent run` の起動時に接続文字列の形を確かめて警告するために `internal/agent/enroll` を直接使います。

`internal/startup` は、この向きの例外ではなく葉です。
モジュールの中の何も import せず、`cmd/wgft` から `internal/dataplane/linuxkernel/wg` までのどの層も import できます。
起動の拒否は、値を受け取る入口と、カーネルに書き込む層の両方が作るので、どちらからも見える場所に置く必要があります。
`internal/resource` と `internal/lograte` と同じ扱いであり、`internal/dataplane/deps_test.go` がモジュールの中を import しないことを検査します。
`internal/textsafe`(信頼できない文字列の無害化。
[11 節](../security/admin-transport.md#11-セキュリティ))も同じ理由で葉に置く。
`cmd/wgft`、`internal/agent`、`internal/vpsd/stream` のように、エージェントが選ぶ文字列を端末へ出す層すべてから見える必要があるためである(2026-09-25、所有者の決定)。

`internal/reasontext` も葉です。
ルールの理由の文言のうち、理由を書く側と、それを部分一致で読む `server doctor`([10.2a 節](../diagnosis/server-observations.md#102a-転送の診断-server-doctor))の両方が使う断片を持ちます。
書く側は、エージェント(`internal/agent`、`internal/dataplane/linuxkernel/nft`、`internal/dataplane/userspace/relay`)と、ルールを公開しなかった server(`internal/vpsd`、`internal/vpsd/proxyrelay`、中継の `Prepare`)です。
dataplane の実装と 2 つの制御プレーンのどこからも見える必要があるので、葉に置く。
エージェントの宛先の許可一覧の設定の名前も拒否の理由に入るので、この package に置き、`internal/agent/allowtargets` はその値を使います。
`internal/dataplane/deps_test.go` の `TestPureLayersStayPure` が、この package がモジュールの中を import しないことを検査します。

2 つの制御プレーンは互いを import しません。
`internal/vpsd` の下のどの package も `internal/agent` の下の package に依存せず、その逆もありません。
両側が共有するものは、`internal/reasontext` のような下の層に置く。
`internal/dataplane/deps_test.go` の `TestControlPlanesDoNotImportEachOther` がこれを検査します。

`internal/flowcap` は、Phase 6 の移行の手順 1 で `internal/resource` に改めた。
送信元ごとの上限を `internal/policy` の `AdmissionLimits` へ、上限で拒んだログを間引く門を `internal/lograte` へ移し、`internal/resource` には Resource Guard の予算だけを残した([7a.10 節](../resource/admission.md#7a10-resource-guard-の再設計))。

`frontend` の package の分け方([7a.9 節](../policy.md#7a9-admission-policy-のコンパイラ)の未決事項だった)は、分けないことで決着した。
kernel backend 側の `Transparent` は nftables の DNAT だけで完結して独立したコードを持たず、`Relay` の listener 集合は server に固有で(wg 越しに agent へ dial する)`internal/vpsd/proxyrelay` に残る。
agent 側の userspace の中継は `internal/dataplane/userspace/relay` に既にあります。
独立した `frontend` package を作っても、動かすコードがありません。

[内部構造](README.md)
