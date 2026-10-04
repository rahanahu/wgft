<a id="102d-web-ui-の診断の画面"></a>
### Web UI の診断の画面

Web UI の診断画面は、`server doctor` と同じ証拠とロジックで判定します。
ブラウザの表示は人向けのサーフェスで、CLI の機械向け出力とは別の保証に従います ([7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧))。


#### この節が固定する範囲

診断のロジックの置き場所、ラベルと群の名前の言語、疎通確認を呼ぶ契機は、次の各項に定めます。

画面の細かな構成、表示の文言、検査の並び、内部の package と型の名前は、Web UI の実装として変更できます ([7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧))。

境界をここに引く理由は [10.2c 節](diagnosis/agent-evidence.md#102c-エージェント側の診断-wgft-agent-doctor)と同じです。
実装もテストも無い段階で画面の細部まで決めると、規則どうしが実際の実行に当たったときに食い違わないことを確かめる手段がありません。
Web UI には [7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の保証が無いので、画面の構成と文言を設計文書で固定する利得も小さい。

#### 診断のロジックの置き場所

診断のロジックは、新しい姉妹 package に置く (2026-09-23、所有者の決定)。
`internal/vpsd` の下、`internal/vpsd/admin` の姉妹に置き、`internal/vpsd/admin` と `cmd/wgft` の両方が import します。
`internal/vpsd/admin` に足す案は採らない。

理由は再利用の境界にあります。
診断のロジックは admin の都合でも CLI の都合でもない共有の領域なので、姉妹 package に置くのが適切です。
export が少し増えても、admin を診断のロジックの所有者にすると、後で再利用の境界が悪くなる。

逆向き、つまり `internal/vpsd/admin` が `cmd/wgft` の報告を組み立てる部分を呼ぶ形は取れません。
`cmd/wgft` が既に `internal/vpsd/admin` を import しているので、逆向きは import の循環になります。
規約ではなく Go の言語の制約です。

[7a.7 節](architecture/packages.md#7a7-package-配置)の依存の向きには抵触しない。`internal/dataplane/deps_test.go` の検査は `cmd/wgft` と `internal/vpsd/admin` の関係に触れておらず、`internal/vpsd` の下の package どうしの import を禁じる規範も無い。

ただし、実装者が最初の一歩で当たる制約を先に挙げる。
第 1 に、姉妹 package は `internal/vpsd/admin` を import できません。
`internal/vpsd/admin` が姉妹 package を import する以上、逆向きは import の循環になります。
第 2 に、姉妹 package は `internal/vpsd` 自身も import できません。
`internal/dataplane/deps_test.go` の `TestVpsdSubpackagesDoNotImportVpsd` が、`internal/vpsd` の下の package から `internal/vpsd` への import を禁じています。
第 3 に、今の診断が入力として読む証拠の型は `admin.BatchResponse`、`admin.AgentInfo`、`admin.ConnCheck` であり、どれも `internal/vpsd/admin` の所有である (`cmd/wgft/doctor.go`)。

証拠の型をどこが所有するかは、この節では決めない (2026-09-23、所有者の決定)。
骨組みの実装で依存を確かめてから決める。
今の入力の型が admin の所有なので、姉妹 package を採ることだけを決めて型の移動まで同時に決めると、まだ骨組みで確かめていない依存の構造を文章だけで先取りすることになります。

姉妹 package は build tag を持ちません。
`server doctor` の実装は既に build tag を持たない `cmd/wgft/doctor.go` にあり、登録だけが `server` の一群にある ([10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor))。
この形を保つ。

証拠の読み方は呼び出し側で分かれる。
CLI は `admin.Client` 越しに管理用 API を呼び、Web UI は同じプロセスの中で `s.backend` を呼ぶ。
姉妹 package はこの違いを interface で受け取り、どちらの経路から呼ばれても同じ判定を返します。
`internal/vpsd/admin` が `server doctor` の読む証拠のすべてに同じプロセスの中で届くことと、CLI 経由と同じ値が取れることは、ラボで確かめた。
同じ形の前例として、Web UI の接続テストのボタンが `s.backend.CheckConnectivity(id)` を同じプロセスの中で呼んでいる。

#### ラベルと群の名前

検査の見出し、状態の語、群の名前は、日英で切り替えず英語のままにする (2026-09-23、所有者の決定)。
理由は、既存の診断の用語と機械可読性を優先することにあります。
状態の語と検査の `id` は `server doctor --json` の `checks[].status` と `checks[].id` に出る語でもあり、画面と機械向けの出力で語が分かれると、運用者が画面で見た語で機械向けの出力を引けなくなる。

経路の図の節点の名前 (`public port`、`WireGuard`、`agent`、`listener / target`) も、検査の見出しと同じく英語のままにする (2026-09-23、所有者の決定)。
止まった節点より後ろの節点に出す「届いていない」は状態の語ではなく画面の枠の語なので、日英で切り替える。
その節点の元の状態は、代替テキストと検査の一覧に残します。

所見の自由文が英語のままであることは、既存の書き分けと同じです。
Web UI は短いラベルを日英で切り替え、証拠になる自由文は英語のまま出す。
接続テストの結果とルールの状態表示が既にその形であり、日本語のロケールでも英語の自由文がそのまま出ることをラボで確かめた。
この節が既存の書き分けと違うのは、診断のラベルを切り替えの対象から外す点だけです。

#### 疎通の確認を呼ぶ契機

`--probe` に当たる疎通の確認は、画面を開いたときには呼びません。
運用者が明示的に操作したときだけ呼ぶ (2026-09-23、所有者の決定)。

理由は待ち時間にあります。
画面の表示だけで全部のルールに疎通の確認をかけると、server 側の dial の期限がルールの本数だけ積み上がり、運用者にとって待ち時間が長すぎる。
[10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor)が `--probe` を 1 本のルールにしか付けられないと定めた理由と同じものが、ブラウザにも当たる。
エージェントが落ちている状態で `POST /api/v1/rules/{id}/check` を呼ぶと応答に約 5 秒かかることは、ラボで確かめた。
既定の 5 秒という期限は [10.2 節](interface.md#102-cli)が既に書いています。

既存の接続テストのボタンが、まさに明示の操作です。
この画面の疎通の確認も同じ形にします。

<a id="7a11-節との関係"></a>
#### 節との関係

Web UI は [7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)が「保つものは無い」と定めるサーフェスであり、この画面も同じ扱いです。
URL 構成、HTML の構造、画面の文言は、テンプレートの都合で変わってよい。
自動化がこの画面の HTML を解析すべきでないことも変わりません。

診断のロジックを姉妹 package へ移すことは、`server doctor --json` が出力する JSON の形を変えないので、CLI の保証にも触れない。
[7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)が保証するのは出力の形であって、その型をどの package が持つかではありません。

#### UDP の応答の観測の注記

UDP のルールの `listener / target` の節点には、[10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor)「UDP の応答の観測」の観測を 2 つ目の注記として添える(2026-09-24、所有者の決定)。
注記は状態の色を持たない控えめな文字で描き、節点の状態は変えません。
応答を見ていないことを警告の色にしません。
文は日英で切り替え、代替テキストにも入れる。

#### ダッシュボードの診断の印

ダッシュボードのルール一覧は、1 本のルールの経路の図を 1 つの印に縮めて出す([10.1 節](interface.md#101-web-ui)。
2026-09-24、所有者の決定)。
印は経路の図を作る関数の出力から選び、判定を作り直さない。
形と記号はルールの総合判定から取り、FAILED の印に添える節点は、図が `StoppedAt` から決めた止まった節点を使います。
一覧の図と 1 本のルールの画面が止まった位置として描く節点と同じです。

画面が自ら決めることは 2 つあります。

第 1 は、UNKNOWN の印に添える節点です。
図を公開側から見て最初の UNKNOWN の節点を選ぶ。
節点の並びは検査の経路の順と同じなので、`StoppedAt` が経路の順で最初の FAILED の検査であるのと同じ向きの規則になります。

第 2 は、持ち主のエージェントが未登録のルールの扱いです。
そのルールの `agent.connection` の reason が `agent_not_registered` なら、総合判定が FAILED でも、印を灰色の「エージェント未登録」にし、ダッシュボードの error の数に含めません。
根拠は [5.1 節](control/registration.md#51-登録)の決定です。
削除の既定はルールを残すので、このルールは登録を待つ状態であり故障ではありません。
`server doctor` は [7a.11 節](compatibility.md#7a11-v10-の互換性の保証サーフェスごとの一覧)の保証のために FAILED を保ち、Web UI だけがこの扱いをします。
診断の画面は、この版ではこのルールを FAILED のまま描く。

#### 範囲外

`--report` と遠隔の診断は含めません。
[10.2a 節](diagnosis/server-observations.md#102a-転送の診断-server-doctor)が定めた順序のとおりです。

`agent doctor` の結果をこの画面に併せて出すことも含めません。
server がエージェントに診断を要求する経路、つまり遠隔の診断が要るためです。
